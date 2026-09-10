"""decompile -- java through jadx, smali through baksmali, outline with no deps.

Engines are resolved out loud: every result says which engine produced it, and
when the requested engine is missing the tool returns DECOMPILER_UNAVAILABLE
for ``format="java"`` instead of quietly handing back something weaker.  For
``format="smali"`` the fallback is the index outline -- it is labelled
``engine="index-outline"`` and ``authoritative=false`` so nobody mistakes it
for real disassembly.

Nothing here writes into the analysed artefact.  jadx/baksmali output goes to a
throwaway directory under CACHE_DIR and is deleted again.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from typing import Any

from . import envelope as env
from . import signature as sg
from .config import (ErrorCode, MAX_DECOMPILE_LINES, ApkIndexError, settings)
from .index import SessionDB

JADX_TIMEOUT = 180
SMALI_TIMEOUT = 120


# ------------------------------------------------------------ engine probes
def jadx_bin() -> str:
    cfg = settings()
    cands: list[str] = []
    if os.environ.get("JADX_CMD"):
        cands.append(os.environ["JADX_CMD"])
    if cfg.jadx_home:
        cands += [os.path.join(cfg.jadx_home, "bin", "jadx"),
                  os.path.join(cfg.jadx_home, "jadx")]
    found = shutil.which("jadx")
    if found:
        cands.append(found)
    for c in cands:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return ""


def java_bin() -> str:
    cfg = settings()
    jh = os.environ.get("JAVA_HOME")
    cands = ([os.path.join(jh, "bin", "java")] if jh else []) + (
        [cfg.baksmali_jar and (shutil.which("java") or "")] or [])
    found = shutil.which("java")
    if found:
        cands.append(found)
    for c in cands:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return ""


def baksmali_jar() -> str:
    jar = settings().baksmali_jar
    return jar if jar and os.path.isfile(jar) else ""


def engines() -> dict:
    return {"jadx": jadx_bin() or None, "java": java_bin() or None,
            "baksmali": baksmali_jar() or None}


# ------------------------------------------------------------------ helpers
def _class_source_row(s: SessionDB, desc: str) -> dict:
    row = s.q("SELECT * FROM classes WHERE session_id=? AND descriptor=?",
              (s.session_id, desc))
    if not row:
        raise ApkIndexError(ErrorCode.NOT_FOUND, f"类不在索引里: {desc}",
                            "searchClasses 先确认 descriptor（内部统一 Smali 形式）。")
    return row[0]


def _artifact_for(s: SessionDB, dex_idx: int) -> str:
    d = s.q("SELECT origin FROM dex WHERE idx=?", (dex_idx,))
    origin = d[0]["origin"] if d else ""
    for cand in [origin] + list(s.row.get("sources") or []):
        if cand and os.path.exists(cand):
            return cand
    raise ApkIndexError(
        ErrorCode.INDEX_STALE,
        f"索引还在，但源文件已不可读: {origin or '(未知 origin)'}",
        "把 APK 放回原路径，或重新 loadApk 建新会话。")


def _dex_member(s: SessionDB, dex_idx: int) -> str:
    d = s.q("SELECT name FROM dex WHERE idx=?", (dex_idx,))
    return d[0]["name"] if d else "classes.dex"


def _slice_method(text: str, name: str) -> tuple[str, int, int]:
    """Best-effort extraction of one member's source from a class body."""
    lines = text.splitlines()
    start = -1
    for i, ln in enumerate(lines):
        stripped = ln.strip()
        if re.search(r"(?<![\w.$])" + re.escape(name) + r"\s*\(", stripped) and not stripped.startswith("//"):
            start = i
            break
    if start < 0:
        return "", 0, 0
    depth = 0
    seen = False
    end = start
    for j in range(start, len(lines)):
        depth += lines[j].count("{") - lines[j].count("}")
        seen = seen or "{" in lines[j]
        end = j
        if seen and depth <= 0:
            break
    head = max(0, start - 2)
    return "\n".join(lines[head:end + 1]), head + 1, end + 1


# -------------------------------------------------------------------- java
def _via_jadx(s: SessionDB, desc: str, member: str, max_lines: int) -> dict:
    bin_ = jadx_bin()
    if not bin_:
        raise ApkIndexError(
            ErrorCode.DECOMPILER_UNAVAILABLE,
            "没找到 jadx：format=\"java\" 需要 jadx（JADX_HOME/bin/jadx 或 PATH 上的 jadx）",
            "装 jadx 后在 mcp.json 的 env 里给 JADX_HOME；或先用 format=\"smali\"。")
    row = _class_source_row(s, desc)
    artifact = _artifact_for(s, row["dex_idx"])
    fqcn = sg.binary_name(desc)
    out_dir = tempfile.mkdtemp(prefix="apkindex-jadx-", dir=settings().cache_dir)
    try:
        # --no-res matters: jadx aborts on a broken/unknown resources.arsc while
        # decoding resources, and we only ever want the *code*.  Second command is
        # the whole-project run, which also covers classes that jadx can only
        # resolve after full decompilation.
        cmds = [
            [bin_, "-q", "--no-res", "--no-debug-info", "--no-inline-anonymous",
             "--single-class", fqcn, "-d", out_dir, artifact],
            [bin_, "-q", "--no-res", "--no-debug-info", "-d", out_dir, artifact],
        ]
        err = ""
        for cmd in cmds:
            try:
                p = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=JADX_TIMEOUT)
            except subprocess.TimeoutExpired:
                raise ApkIndexError(ErrorCode.DECOMPILER_UNAVAILABLE,
                                    f"jadx 超时（{JADX_TIMEOUT}s）: {artifact}",
                                    "大 APK 建议只对目标 dex 建会话：loadDex(classesN.dex)。")
            err = (p.stderr or p.stdout or "")[-2000:]
            hits = []
            for root, _dirs, files in os.walk(out_dir):
                for f in files:
                    if f.endswith(".java") and os.path.splitext(f)[0] == fqcn.rsplit(".", 1)[-1]:
                        hits.append(os.path.join(root, f))
                if hits:
                    break
            if hits:
                text = open(hits[0], encoding="utf-8", errors="replace").read()
                lines_total = text.count("\n") + 1
                note = ""
                if member:
                    body, a, b = _slice_method(text, member)
                    if body:
                        text = body
                        note = f"只截取 {member} 的源码（第 {a}-{b} 行）；类级上下文用 target=类名。"
                shown = text.splitlines()[:max_lines]
                return {
                    "engine": "jadx", "authoritative": True, "path": artifact,
                    "file": hits[0], "lines": lines_total,
                    "returnedLines": len(shown),
                    "truncated": lines_total > len(shown),
                    "code": "\n".join(shown), "note": note,
                }
        raise ApkIndexError(ErrorCode.PARSE_FAILED,
                            f"jadx 未能导出 {fqcn}", (err or "")[:400])
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


# ------------------------------------------------------------------- smali
def _via_baksmali(s: SessionDB, desc: str, member: str, max_lines: int) -> dict:
    jar, jbin = baksmali_jar(), java_bin()
    if not (jar and jbin):
        return {}
    row = _class_source_row(s, desc)
    artifact = _artifact_for(s, row["dex_idx"])
    member_name = _dex_member(s, row["dex_idx"])
    work = tempfile.mkdtemp(prefix="apkindex-smali-", dir=settings().cache_dir)
    try:
        dex_path = artifact
        if zipfile.is_zipfile(artifact):
            with zipfile.ZipFile(artifact) as z:
                open(os.path.join(work, member_name), "wb").write(z.read(member_name))
            dex_path = os.path.join(work, member_name)
        out = os.path.join(work, "smali")
        p = subprocess.run([jbin, "-jar", jar, "disassemble", "-o", out, dex_path],
                           capture_output=True, text=True, timeout=SMALI_TIMEOUT)
        target = os.path.join(out, desc[1:-1] + ".smali")
        if os.path.exists(target):
            text = open(target, encoding="utf-8", errors="replace").read()
            lines_total = text.count("\n") + 1
            shown = text.splitlines()[:max_lines]
            return {"engine": "baksmali", "authoritative": True, "path": dex_path,
                    "file": target, "lines": lines_total,
                    "returnedLines": len(shown), "truncated": lines_total > len(shown),
                    "code": "\n".join(shown), "note": ""}
        return {"engine": "baksmali", "error": (p.stderr or p.stdout or "")[-800:]}
    except subprocess.TimeoutExpired:
        return {"engine": "baksmali", "error": "baksmali 超时"}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _outline(s: SessionDB, desc: str, member: str, max_lines: int) -> dict:
    """Dependency-free view assembled from the index itself."""
    row = _class_source_row(s, desc)
    acc = sg.__dict__  # noqa: F841  (kept for symmetry; flags via dex.flag_names)
    from .dex import flag_names, method_flag_names as dflag
    lines: list[str] = [
        f"# apk-index index-outline（由 SQLite 索引重建，不是指令流）",
        f".class {' '.join(flag_names(row['access_flags'] or 0, for_class=True))} {desc}",
    ]
    if row.get("super_descriptor"):
        lines.append(f".super {row['super_descriptor']}")
    ifaces = json.loads(row.get("interfaces_json") or "[]")
    if ifaces:
        lines.append(".implements " + " \n.implements ".join(ifaces))
    src = s.q("SELECT source_file FROM classes WHERE id=?", (row["id"],))
    if src and src[0]["source_file"]:
        lines.append(f".source {src[0]['source_file']}")
    for f in s.q("SELECT * FROM fields WHERE class_id=? ORDER BY name", (row["id"],)):
        lines.append(f"\n.field {' '.join(flag_names(f['access_flags']))} "
                     f"{f['name']}:{f['type_descriptor']}")
    mrows = s.q("SELECT * FROM methods WHERE class_id=? ORDER BY name, param_count",
                (row["id"],))
    for m in mrows:
        if member and m["name"] != member:
            continue
        lines.append("\n.method %s " % " ".join(
            dflag(m["access_flags"], m.get("name") or "")) +
                     f"{m['name']}{m['params_descriptor']}{m['return_descriptor']}")
        lines.append(f"    .registers {m['regs'] if m['regs'] is not None else '?'}"
                     f"  # ins={m['ins_size']} units={m['unit_count']}"
                     + ("  # partial-decode" if m["partial"] else ""))
        strs = s.q("""SELECT st.value v FROM string_refs sr JOIN strings st ON st.id=sr.string_id
                      WHERE sr.method_id=? LIMIT 12""", (m["id"],))
        for x in strs:
            lines.append(f"    const-string  # {x['v'][:120]}")
        refs = s.q("""SELECT r.descriptor d, r.kind k FROM xref_edges e JOIN refs r
                      ON r.id=e.callee_ref WHERE e.caller_method_id=? LIMIT 20""", (m["id"],))
        from .index import CODE_TO_KIND
        for x in refs:
            lines.append(f"    {CODE_TO_KIND.get(x['k'], '?')} {x['d']}")
        lines.append("    .end method")
    if member and len(mrows) and not any(l.startswith("\n.method") for l in lines):
        raise ApkIndexError(ErrorCode.NOT_FOUND, f"方法不存在: {desc}->{member}")
    total = len(lines)
    return {"engine": "index-outline", "authoritative": False,
            "path": s.db_path, "file": None, "lines": total,
            "returnedLines": min(total, max_lines), "truncated": total > max_lines,
            "code": "\n".join(lines[:max_lines]),
            "note": ("这是从索引重建的结构视图（签名 + 字符串/调用/字段引用清单），"
                     "不含完整指令流。要看真 smali：设 BAKSALI_JAR（+ JDK）；"
                     "要看 Java：设 JADX_HOME。")}


# ---------------------------------------------------------------------- api
def _auto(s: SessionDB, desc: str, member: str, max_lines: int) -> dict:
    """java -> smali -> outline：无论环境缺什么都一定带正文回来。

    只有 jadx 的产物算 authoritative；降级后的视图会带着整条尝试链回来，
    调用方能看到是哪一步、为什么退的，而不是拿到一份看起来像代码的东西。
    """
    chain: list[str] = []
    try:
        res = _via_jadx(s, desc, member, max_lines)
        if res.get("code"):
            chain.append("java:jadx")
            res["degraded"] = False
            res["chain"] = chain
            return res
        chain.append("java:jadx 无输出")
    except ApkIndexError as exc:
        chain.append("java:%s %s" % (getattr(exc, "code", "?"), str(exc)[:70]))
    except Exception as exc:                                    # noqa: BLE001
        chain.append("java:%s" % type(exc).__name__)
    res = _via_baksmali(s, desc, member, max_lines)
    if res.get("code"):
        chain.append("smali:baksmali")
        res["degraded"] = True
        res["chain"] = chain
        return res
    chain.append("smali:" + ((res.get("error") if res else "")
                             or "缺 baksmali/Java 环境")[:70])
    res = _outline(s, desc, member, max_lines)
    res["degraded"] = True
    res["chain"] = chain        # 单独成字段，不塞进 note —— 渲染层会分行显示
    return res


def decompile(s: SessionDB, target: str, format: str, max_lines: int = MAX_DECOMPILE_LINES) -> dict:
    """``target`` is a class or a member reference in any accepted spelling."""
    max_lines = min(max(max_lines, 20), 4000)
    member = ""
    desc = ""
    try:
        owner, name, pd, ret = sg.parse_method_ref(target)
        desc, member = owner, name
    except (sg.SignatureError, ValueError):
        row = _class_source_row(s, sg.normalize_desc(target))
        desc = row["descriptor"]
    if not desc:
        raise ApkIndexError(ErrorCode.BAD_ARGUMENT, f"无法解析 target: {target}")
    format = (format or "auto").strip().lower()
    if format in ("", "auto"):
        res = _auto(s, desc, member, max_lines)
    elif format == "java":
        res = _via_jadx(s, desc, member, max_lines)
    elif format == "smali":
        res = _via_baksmali(s, desc, member, max_lines) or _outline(s, desc, member, max_lines)
    elif format in ("outline", "index"):
        res = _outline(s, desc, member, max_lines)
    else:
        raise ApkIndexError(ErrorCode.BAD_ARGUMENT, f"format 不支持: {format}",
                            '只能是 "auto" | "java" | "smali" | "outline"')
    meta = {"engine": res.get("engine"), "authoritative": res.get("authoritative"),
            "target": sg.binary_name(desc) + (f"#{member}" if member else ""),
            "descriptor": desc, "member": member or None,
            "format": format, "lines": res.get("lines"),
            "returnedLines": res.get("returnedLines"), "file": res.get("file"),
            "path": res.get("path"), "note": res.get("note") or "",
            "degraded": bool(res.get("degraded")), "chain": res.get("chain") or []}
    # 反编译正文放 items[0].text；code 属于错误契约字段，混用会让客户端
    # 把 "PARSE_FAILED" 与代码文本当同一个键读。
    meta["text"] = res.get("code") or ""
    meta["engineCode"] = res.get("engineCode") or ""
    if res.get("error"):
        meta["engineError"] = res["error"]
    hint = (f"engine={meta['engine']} authoritative={meta['authoritative']}；"
            "签名一律用 getSignature 的四种写法，不要从反编译文本里手抄名字。")
    return env.ok([meta], session_id=s.session_id, total=1,
                  truncated=bool(res.get("truncated")), hint=hint, maxLines=max_lines)
