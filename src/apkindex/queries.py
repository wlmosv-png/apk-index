"""Query layer: the only reason this whole server exists.

A hook author must never guess a symbol name.  Every function here answers from
rows that were read out of the target's own dex -- and every member-level item
carries the four spellings (Smali descriptor / Java signature / LibXposed
Reflector string / ``Class.forName``) plus, where useful, a paste-ready
``helper-ktx`` block.

Naming note: function names mirror the MCP tool names one-to-one but in
snake_case, and the public tool names stay exactly ``searchClasses``,
``matchSignature``, ... (see :mod:`apkindex.server`).
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Iterable

from . import dsl as dslmod
from . import envelope as env
from . import signature as sg
from .config import (DEFAULT_LIMIT, ErrorCode, HARD_LIMIT, MAX_DECOMPILE_LINES,
                     ApkIndexError, settings)
from .dex import flag_names, method_flag_names as dflag
from .index import (CODE_TO_KIND, SessionDB, catalog)

# invoke-ish ref kinds, used for call-graph walking
INVOKE_KINDS = (1, 2, 3, 4, 5, 6, 7, 8)
FIELD_KINDS = (10, 11, 12, 13)
ACC_BITS = {
    "public": 0x1, "private": 0x2, "protected": 0x4, "static": 0x8,
    "final": 0x10, "synchronized": 0x20, "volatile": 0x40, "bridge": 0x40,
    "transient": 0x80, "varargs": 0x80, "native": 0x100, "interface": 0x200,
    "abstract": 0x400, "strict": 0x800, "synthetic": 0x1000,
    "annotation": 0x2000, "enum": 0x4000, "anonymous": 0x8000,
}

_SCAN_CAP = 400_000          # rows a python-side filter may touch
_REF_SAMPLES = 6             # how many evidence rows per item


# ---------------------------------------------------------------- sessions
def open_session(session_id: str) -> SessionDB:
    if not session_id:
        raise ApkIndexError(ErrorCode.SESSION_NOT_FOUND, "缺少 sessionId",
                            "先 loadApk/loadAar/loadDex，或 sessionList 看现有会话。")
    row = catalog().find_by_id(session_id)
    if row is None:
        sess = catalog().list()
        by_pkg = [x for x in sess if x.get("pkg") == session_id]
        by_sha = [x for x in sess if (x.get("sha256") or "").startswith(session_id)]
        cand = by_pkg or by_sha
        if len(cand) > 1:
            raise ApkIndexError(ErrorCode.BAD_ARGUMENT,
                                f"sessionId/pkg 有歧义: {session_id}",
                                "改用完整 sessionId：" + ", ".join(c["sessionId"] for c in cand[:6]))
        if len(cand) == 1:
            row = catalog().find_by_id(cand[0]["sessionId"])
    if row is None:
        raise ApkIndexError(ErrorCode.SESSION_NOT_FOUND, f"会话不存在: {session_id}")
    sid = row.get("session_id") or row.get("sessionId")
    s = SessionDB(sid, row)
    s.created_at = row.get("created_at") or row.get("createdAt")
    s.packed = bool(row.get("packed"))
    s.kind = row.get("kind")
    s.backend = row.get("backend")
    return s


def _scope_sql(scope: str) -> tuple[str, list]:
    scope = (scope or "all").lower()
    # the clause must carry its own placeholder, otherwise the arg count and
    # the ?-count drift apart as soon as a caller adds filter conditions.
    scope = scope or "all"
    if scope == "app":
        return " AND c.source = ?", ["app"]
    if scope in ("library", "lib"):
        return " AND c.source IN (?, ?)", ["library", "system"]
    if scope == "system":
        return " AND c.source = ?", ["system"]
    return "", []


def _like(text: str) -> str:
    return (text or "").replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


_M_COLS = ("c.descriptor AS descriptor, c.simple_name AS simple_name, "
           "c.package AS package, c.kind AS class_kind, c.source AS source, "
           "c.origin_file AS origin_file, c.dex_idx AS dex_idx, "
           "c.super_descriptor AS super_descriptor, c.interfaces_json AS interfaces_json, "
           "c.access_flags AS class_flags, c.id AS class_id, "
           "m.id AS method_id, m.name AS name, m.params_descriptor AS params_descriptor, "
           "m.return_descriptor AS return_descriptor, m.access_flags AS access_flags, "
           "m.is_static AS is_static, m.is_constructor AS is_constructor, "
           "m.param_count AS param_count, m.shorty AS shorty, m.unit_count AS unit_count, "
           "m.declares_string_refs AS has_refs, m.partial AS partial")

_F_COLS = ("c.descriptor AS descriptor, c.simple_name AS simple_name, "
           "c.package AS package, c.source AS source, c.origin_file AS origin_file, "
           "c.dex_idx AS dex_idx, c.super_descriptor AS super_descriptor, "
           "c.interfaces_json AS interfaces_json, c.kind AS class_kind, "
           "f.id AS field_id, f.name AS name, f.type_descriptor AS type_descriptor, "
           "f.access_flags AS access_flags, f.is_static AS is_static")


# ------------------------------------------------------------------ items
def _class_item(s: SessionDB, row: dict, *, with_counts: bool = True) -> dict:
    desc = row["descriptor"]
    item = {
        "descriptor": desc,
        "binaryName": sg.binary_name(desc),
        "javaName": sg.type_to_java(desc),
        "simpleName": row.get("simple_name"),
        "package": (row.get("package") or "").replace("/", "."),
        "kind": row.get("class_kind") or "class",
        "source": row.get("source"),
        "accessFlags": flag_names(row.get("access_flags") or 0, for_class=True),
        "superClass": sg.binary_name(row["super_descriptor"]) if row.get("super_descriptor") else None,
        "interfaces": [sg.binary_name(i) for i in json.loads(row.get("interfaces_json") or "[]")],
        "originFile": os.path.basename(row.get("origin_file") or ""),
        "dexIdx": row.get("dex_idx"),
        "reflector": sg.internal_name(desc),
        "classForName": sg.class_for_name(desc, loader=True),
    }
    if with_counts:
        item["methods"] = int(s.scalar(
            "SELECT COUNT(*) FROM methods WHERE class_id=?", (row["id"],)) or 0)
        item["fields"] = int(s.scalar(
            "SELECT COUNT(*) FROM fields WHERE class_id=?", (row["id"],)) or 0)
    return item


def _method_item(s: SessionDB, row: dict, *, with_strings: int = 0,
                 with_evidence: bool = False) -> dict:
    owner = row["descriptor"]
    forms = sg.method_forms(owner, row["name"], row["params_descriptor"],
                            row["return_descriptor"], row["access_flags"])
    item = {
        "class": sg.binary_name(owner),
        "classDescriptor": owner,
        "source": row.get("source"),
        "dexIdx": row.get("dex_idx"),
        "name": row["name"],
        "kind": forms["kind"],
        "modifiers": (dflag(row["access_flags"], row["name"])
                      if row.get("name") else flag_names(row["access_flags"])),
        "static": bool(row.get("is_static")),
        "constructor": bool(row.get("is_constructor")),
        "paramCount": row.get("param_count", len(forms["params"])),
        "smali": forms["smali"],
        "reflector": forms["reflector"],
        "java": forms["java"],
        "returnType": forms["returnType"],
        "params": [sg.type_to_java(p) for p in forms["params"]],
        "paramsDescriptor": forms["paramsDescriptor"],
        "returnDescriptor": forms["returnDescriptor"],
        "shorty": forms["shorty"],
        "classForName": sg.class_for_name(owner, loader=True),
    }
    if with_evidence:
        strs = s.q("SELECT st.value AS v FROM string_refs sr JOIN strings st ON st.id=sr.string_id"
                   " WHERE sr.method_id=? ORDER BY length(st.value) DESC LIMIT ?",
                   (row["method_id"], _REF_SAMPLES))
        if strs:
            item["referredStrings"] = [x["v"] for x in strs]
        calls = s.q("""SELECT r.descriptor AS d, r.kind AS k, r.owner AS o, r.name AS n
                       FROM xref_edges e JOIN refs r ON r.id=e.callee_ref
                       WHERE e.caller_method_id=? AND r.kind IN (1,2,3,4,5,6,7,8)
                       ORDER BY e.hits DESC LIMIT ?""", (row["method_id"], _REF_SAMPLES))
        if calls:
            item["invokedMethods"] = [{"smali": c["d"], "kind": CODE_TO_KIND.get(c["k"], "?")}
                                      for c in calls]
        flds = s.q("""SELECT r.descriptor AS d, r.kind AS k FROM xref_edges e
                      JOIN refs r ON r.id=e.callee_ref
                      WHERE e.caller_method_id=? AND r.kind IN (10,11,12,13) LIMIT ?""",
                   (row["method_id"], _REF_SAMPLES))
        if flds:
            item["accessedFields"] = [{"smali": f["d"],
                                       "kind": CODE_TO_KIND.get(f["k"], "?")} for f in flds]
        item["synthetic"] = bool("synthetic" in " ".join(item["modifiers"]))
    if with_strings:
        rows = s.q("SELECT st.value AS v FROM string_refs sr JOIN strings st ON st.id=sr.string_id"
                   " WHERE sr.method_id=? ORDER BY length(st.value) DESC LIMIT ?",
                   (row["method_id"], with_strings))
        item["strings"] = [r["v"] for r in rows]
    return item


def _field_item(s: SessionDB, row: dict) -> dict:
    forms = sg.field_forms(row["descriptor"], row["name"], row["type_descriptor"],
                           row["access_flags"])
    return {
        "class": sg.binary_name(row["descriptor"]),
        "classDescriptor": row["descriptor"],
        "source": row.get("source"),
        "dexIdx": row.get("dex_idx"),
        "name": row["name"],
        "kind": "field",
        "modifiers": flag_names(row["access_flags"], for_field=True),
        "static": bool(row.get("is_static")),
        "type": forms["type"],
        "typeDescriptor": forms["typeDescriptor"],
        "smali": forms["smali"],
        "reflector": forms["reflector"],
        "java": forms["java"],
        "classForName": sg.class_for_name(row["descriptor"], loader=True),
    }


# ------------------------------------------------------------ class lookup
def find_class_rows(s: SessionDB, ref: str, scope: str = "all", limit: int = 20) -> list[dict]:
    """Resolve any accepted spelling to concrete class rows (possibly several)."""
    if not ref:
        raise ApkIndexError(ErrorCode.BAD_ARGUMENT, "class 参数不能为空")
    desc = sg.normalize_desc(ref)
    where, params = _scope_sql(scope)
    rows = s.q(f"SELECT * FROM classes c WHERE c.session_id=? AND c.descriptor=?{where}",
               [s.session_id, desc] + params)
    if rows:
        return rows[:limit]
    # simple name / dotted suffix
    simple = (desc or "").lstrip("[L").rstrip(";").rsplit("/", 1)[-1] or ref
    like_pat = "%/" + _like(simple) + ";"
    rows = s.q(f"""SELECT * FROM classes c WHERE c.session_id=?
                   AND (c.simple_name=? OR c.descriptor LIKE ? ESCAPE '\\'){where}
                   ORDER BY (c.descriptor LIKE ? ESCAPE '\\') DESC, length(c.descriptor)
                   LIMIT ?""",
               [s.session_id, simple, like_pat] + params + [like_pat, limit])
    return rows


def _unique_class(s: SessionDB, ref: str, scope: str = "all") -> dict:
    rows = find_class_rows(s, ref, scope, limit=5)
    if not rows:
        raise ApkIndexError(ErrorCode.NOT_FOUND, f"索引里没有类 {ref}",
                            "searchClasses 用 prefix/regex 找相近名字；混淆类名请先 "
                            "searchByString 从字符串入口反查。")
    if len(rows) > 1 and sg.normalize_desc(ref) not in {r["descriptor"] for r in rows}:
        raise ApkIndexError(ErrorCode.BAD_ARGUMENT,
                            f"{ref} 匹配到 {len(rows)} 个类",
                            "用全限定名：" + ", ".join(sg.binary_name(r["descriptor"]) for r in rows[:5]))
    return rows[0]


# ------------------------------------------------------------------- tools
# ------------------------------------------------------ 注解（读路径）
# dex annotation_item 的 visibility：0=BUILD 1=RUNTIME 2=SYSTEM。
# SYSTEM/BUILD 只是"运行期不保留"，dex 里照样在——混淆包里 @Metadata、
# @MemberClasses、@Signature 全是 2，它们恰恰是"这是不是 Kotlin 类"的线索。
ANNO_VISIBILITY = {0: "build", 1: "runtime", 2: "system"}


def _anno_payload(raw):
    """args_json 入库时已经夹过长度；_blob 说明该字段换成了 sha1 摘要。"""
    try:
        vals = json.loads(raw or "{}")
    except ValueError:
        return {"_unparsed": True}, False
    clipped = "_truncated" in vals or any(
        isinstance(v, dict) and "_blob" in v for v in vals.values())
    return vals, clipped


def _annos_of(s, where, arg, limit=40):
    out = []
    for r in s.q("SELECT descriptor, visibility, args_json FROM annotations"
                 " WHERE " + where + " ORDER BY visibility DESC, descriptor LIMIT ?",
                 (arg, limit)):
        vals, clipped = _anno_payload(r["args_json"])
        item = {"descriptor": r["descriptor"],
                "javaName": sg.type_to_java(r["descriptor"]),
                "visibility": ANNO_VISIBILITY.get(r["visibility"], "build")}
        if vals:
            item["values"] = vals
        if clipped:
            item["valuesClipped"] = True
        out.append(item)
    return out


def class_annotations(s, class_id, limit=40):
    """类级注解。字段上的注解索引时就没单列，故不在此。"""
    return _annos_of(s, "class_id=? AND method_id IS NULL", class_id, limit)


def member_annotations(s, method_id, limit=12):
    return _annos_of(s, "method_id=?", method_id, limit)


def _anno_match(ref):
    """@Keep / dalvik.annotation.Keep / Ldalvik/annotation/Keep; 归一成
    (等值 descriptor 列表, 简单名后缀 LIKE 列表)。"""
    txt = (ref or "").strip().lstrip("@")
    if not txt:
        raise ApkIndexError(ErrorCode.BAD_ARGUMENT, "annotatedWith 不能为空",
                            '例：annotatedWith="dalvik.annotation.Keep" 或 "Keep"')
    if txt.startswith("L") and txt.endswith(";"):
        return [txt], []
    slash = txt.replace(".", "/")
    if "/" in slash:
        return ["L" + slash + ";"], []
    if "%" in slash or "_" in slash:
        raise ApkIndexError(ErrorCode.BAD_ARGUMENT, "annotatedWith 的简单名不能带 % 或 _",
                            "要按模式匹配，先 searchClasses 拿全限定名。")
    return [], ["%/" + slash + ";"]


def search_classes(session_id: str, query: str = "", kind: str = "prefix",
                   scope: str = "all", limit: int = DEFAULT_LIMIT,
                   packageFilter: str = "", annotatedWith: str = "", **_: Any) -> dict:
    t0 = time.time()
    s = open_session(session_id)
    _v = (kind or "").lower()
    if _v not in ('exact', 'prefix', 'regex', 'scope'):
        raise ApkIndexError(ErrorCode.BAD_ARGUMENT,
                            f"kind 不支持: " + str(kind),
                            "取值只能是 exact / prefix / regex / scope。")
    try:
        limit = env.clamp_limit(limit)
        kind = (kind or "prefix").lower()
        scope_clause, wparams = _scope_sql(scope)
        # annotatedWith 只筛"注解打在类上"的；方法级注解看 getSignature
        anno_sql, anno_params = "", []
        if annotatedWith:
            eq, likes = _anno_match(annotatedWith)
            conds, aargs = [], []
            for d in eq:
                conds.append("a.descriptor=?")
                aargs.append(d)
            for pat in likes:
                conds.append("a.descriptor LIKE ?")
                aargs.append(pat)
            anno_sql = (" AND EXISTS (SELECT 1 FROM annotations a WHERE a.class_id=c.id AND ("
                        + " OR ".join(conds) + "))")
            anno_params = aargs
        q = (query or "").strip()
        if not q:
            raise ApkIndexError(ErrorCode.BAD_ARGUMENT, "query 不能为空")
        rows: list[dict]
        total: int
        if kind == "exact":
            desc = sg.normalize_desc(q)
            simple = desc.lstrip("[L").rstrip(";").rsplit("/", 1)[-1]
            rows = s.q(f"""SELECT * FROM classes c WHERE c.session_id=?
                           AND (c.descriptor=? OR c.simple_name=?){scope_clause}{anno_sql}""",
                       [s.session_id, desc, simple] + wparams + anno_params)
            total = len(rows)
            rows = rows[:limit]
        elif kind == "prefix":
            # classes.package is stored in dex form (slashes); descriptor carries
            # the leading L and trailing ; -- build both prefixes from the query.
            raw = q[1:-1] if (q.startswith("L") and q.endswith(";")) else q
            slash = raw.replace(".", "/")
            desc_prefix = "L" + slash
            pkg_prefix = slash.rstrip("/")
            simple_prefix = q.rsplit(".", 1)[-1].rsplit("/", 1)[-1]
            args = [s.session_id] + wparams
            if packageFilter:
                conds = ["(c.package LIKE ? ESCAPE '\\')"]
                args.append(_like(packageFilter.replace(".", "/").rstrip("/")) + "%")
            else:
                conds = ["(c.descriptor LIKE ? ESCAPE '\\')",
                         "(c.package LIKE ? ESCAPE '\\')",
                         "(c.simple_name LIKE ? ESCAPE '\\')"]
                args += [_like(desc_prefix) + "%", _like(pkg_prefix) + "%",
                         _like(simple_prefix) + "%"]
            args += anno_params
            sql = (f"SELECT * FROM classes c WHERE c.session_id=?{scope_clause}"
                   " AND (" + " OR ".join(conds) + ")" + anno_sql)
            total = int(s.scalar(f"SELECT COUNT(*) FROM ({sql})", tuple(args)) or 0)
            rows = s.q(sql + " ORDER BY length(c.descriptor) LIMIT ?",
                       tuple(args) + (limit,))
        elif kind == "regex":
            rx = re.compile(q)
            rows = []
            total = 0
            cur = s.conn.execute(
                f"SELECT * FROM classes c WHERE c.session_id=?{scope_clause}{anno_sql}",
                tuple([s.session_id] + wparams + anno_params))
            scanned = 0
            for r in cur:
                d = dict(zip([c[0] for c in cur.description], r))
                scanned += 1
                bn = sg.binary_name(d["descriptor"])
                if rx.search(bn) or rx.search(d["simple_name"] or ""):
                    total += 1
                    if len(rows) < limit:
                        rows.append(d)
                if scanned >= _SCAN_CAP:
                    break
            cur.close()
        else:
            raise ApkIndexError(ErrorCode.BAD_ARGUMENT, f"kind 不支持: {kind}",
                                'kind 只能是 "exact" | "prefix" | "regex"')
        items = [_class_item(s, r) for r in rows]
        hint = (f"耗时 {time.time() - t0:.2f}s；exact/prefix/regex 都吃 (session_id,descriptor) "
                "与 simple_name/package 索引。选中目标后用 listMembers/getSignature 取可粘贴签名。")
        if packageFilter:
            hint += " packageFilter 已覆盖 query 前缀条件。"
        if annotatedWith:
            hint += (f" annotatedWith={annotatedWith} 只统计类级注解；方法上的看 getSignature。")
            if total == 0:
                hint += " 0 命中通常是注解只打在方法上，或名字写错——先对已知类调一次 getSignature 看 annotations。"
        return env.ok(items, session_id=s.session_id, total=total,
                      truncated=total > len(items), hint=hint, limit=limit,
                      elapsedMs=round((time.time() - t0) * 1000, 1),
                      query=query, kind=kind, scope=scope)
    finally:
        s.close()


def list_members(session_id: str, cls: str = "", include: str = "both",
                 scope: str = "all", limit: int = DEFAULT_LIMIT,
                 namePattern: str = "", withStrings: int = 0, **_: Any) -> dict:
    t0 = time.time()
    s = open_session(session_id)
    try:
        limit = env.clamp_limit(limit)
        row = _unique_class(s, cls, scope)
        cid = row["id"]
        rx = re.compile(namePattern) if namePattern else None
        include = (include or "both").lower()
        items: list[dict] = []
        mtotal = ftotal = 0
        if include in ("methods", "both"):
            rows = s.q("""SELECT * FROM methods m WHERE m.class_id=?
                          ORDER BY m.is_static DESC, m.name, m.param_count""", (cid,))
            for m in rows:
                if rx and not rx.search(m["name"]):
                    continue
                mtotal += 1
                if len(items) < limit:
                    mrow = dict(m)
                    mrow.update({k: row[k] for k in
                                 ("descriptor", "simple_name", "package", "source",
                                  "dex_idx", "super_descriptor", "interfaces_json")})
                    mrow["method_id"] = m["id"]
                    items.append(_method_item(s, mrow, with_strings=int(withStrings or 0),
                                              with_evidence=True))
        if include in ("fields", "both"):
            rows = s.q("SELECT * FROM fields f WHERE f.class_id=? ORDER BY f.is_static DESC, f.name",
                       (cid,))
            for f in rows:
                if rx and not rx.search(f["name"]):
                    continue
                ftotal += 1
                if len(items) < limit:
                    frow = dict(f)
                    frow.update({k: row[k] for k in
                                 ("descriptor", "simple_name", "package", "source",
                                  "dex_idx", "super_descriptor", "interfaces_json")})
                    items.append(_field_item(s, frow))
        total = mtotal + ftotal
        cls = _class_item(s, row, with_counts=False)
        hint = (f"{cls['binaryName']}: {mtotal} 方法 / {ftotal} 字段，返回前 {len(items)} 条。"
                "reflector 字段可直接贴进 Reflector.loadMethod/loadField。"
                "Kotlin 合成类（$1、$initData$1）在这里就是真实存在的类，不要当成幻觉。")
        return env.ok(items, session_id=s.session_id, total=total,
                      truncated=total > len(items), hint=hint, limit=limit,
                      elapsedMs=round((time.time() - t0) * 1000, 1),
                      target=cls)
    finally:
        s.close()


def get_signature(session_id: str, cls: str = "", member: str = "",
                  scope: str = "all", **_: Any) -> dict:
    """One class/member -> every spelling a hook needs, plus the DSL starter."""
    s = open_session(session_id)
    try:
        row = _unique_class(s, cls, scope)
        desc = row["descriptor"]
        bin_name = sg.binary_name(desc)
        out: dict[str, Any] = {
            "class": {
                "descriptor": desc,
                "binaryName": bin_name,
                "javaName": sg.type_to_java(desc),
                "smali": desc,
                "reflector": bin_name,
                "classForName": sg.class_for_name(desc),
                "classForNameWithLoader": sg.class_for_name(desc, loader=True),
                "reflectorLoadClass": f'reflector.loadClass("{bin_name}")',
                "helperKtx": f'name = "{bin_name}".exactClass',
                "kotlinDsl": dslmod.class_snippet(bin_name),
                "annotations": class_annotations(s, row["id"]),
            },
            "parent": {"superClass": sg.binary_name(row["super_descriptor"])
                       if row.get("super_descriptor") else None,
                       "superClassDescriptor": row.get("super_descriptor"),
                       "interfaces": json.loads(row.get("interfaces_json") or "[]"),
                       "interfaceNames": [sg.binary_name(i)
                                          for i in json.loads(row.get("interfaces_json") or "[]")]},
            "source": row.get("source"),
            "dexIdx": row.get("dex_idx"),
            "originFile": os.path.basename(row.get("origin_file") or ""),
            "accessFlags": flag_names(row["access_flags"] or 0, for_class=True),
        }
        items: list[dict] = []
        if member:
            mr = (member or "").strip()
            parsed = None
            try:
                parsed = sg.parse_method_ref(mr)
            except sg.SignatureError:
                parsed = None
            if parsed and parsed[1]:
                owner, name, pd, ret = parsed
                sql = ("SELECT * FROM methods m WHERE m.class_id=? AND m.name=?"
                       + (" AND m.params_descriptor=?" if pd != "()" else "")
                       + (" AND m.return_descriptor=?" if ret else ""))
                args = [row["id"], name]
                if pd != "()":
                    args.append(pd)
                if ret:
                    args.append(ret)
                rows = s.q(sql, tuple(args))
            else:
                frows = s.q("SELECT * FROM fields f WHERE f.class_id=? AND f.name=?",
                            (row["id"], mr.split(":")[0].strip()))
                mrows = s.q("SELECT * FROM methods m WHERE m.class_id=? AND m.name LIKE ?",
                            (row["id"], mr + "%"))
                rows = mrows + frows
            for r in rows:
                if "params_descriptor" in r:
                    forms = sg.method_forms(desc, r["name"], r["params_descriptor"],
                                            r["return_descriptor"], r["access_flags"])
                    params = forms["params"]
                    item = {
                        "kind": "method", "name": r["name"], "forms": forms,
                        "modifiers": dflag(r["access_flags"], r["name"]),
                        "overloadCount": int(s.scalar(
                            "SELECT COUNT(*) FROM methods WHERE class_id=? AND name=?",
                            (row["id"], r["name"])) or 0),
                        "reflectorSnippet": dslmod.reflector_snippet(forms),
                        "hookDsl": dslmod.match_dsl(bin_name, r["name"], params,
                                                    r["return_descriptor"],
                                                    access=r["access_flags"],
                                                    is_constructor=r["name"] == "<init>",
                                                    verbose_header=False),
                    }
                    # 方法上的注解决定能不能/该不该 hook（@Keep 是名字稳定的强信号）
                    pann = member_annotations(s, r["id"])
                    if pann:
                        item["annotations"] = pann
                    items.append(item)
                else:
                    forms = sg.field_forms(desc, r["name"], r["type_descriptor"],
                                           r["access_flags"])
                    items.append({
                        "kind": "field", "name": r["name"], "forms": forms,
                        "modifiers": flag_names(r["access_flags"]),
                        "reflectorSnippet": dslmod.reflector_snippet(forms),
                        "hookDsl": dslmod.field_dsl(bin_name, r["name"],
                                                    r["type_descriptor"],
                                                    static=bool(r.get("is_static"))),
                    })
            out["member"] = member
            if not items:
                # 以前这里静默回"0 个匹配"，看着像工具坏了
                out["hint"] = ((out.get("hint") or "") + " member=%r 在 %s 上没有同名成员；"
                        "listMembers 看真名（构造方法是 <init>，静态块是 <clinit>）。"
                        % (member, bin_name)).strip()
        else:
            out["member"] = None
            hint = "member 为空 → 只给类级签名；带 member（方法名或完整引用）才出方法级四种写法。"
        hint = out.get("hint") or ""
        hint += (" 用法：未混淆目标走 reflectorSnippet；混淆目标把 hookDsl 交给 "
                 "matchSignature 生成的结构匹配块替换 name 条件。")
        return env.ok(items, session_id=s.session_id, total=len(items),
                      truncated=False, hint=hint, signature=out)
    finally:
        s.close()


def search_by_string(session_id: str, text: str = "", match: str = "contains",
                     scope: str = "all", limit: int = DEFAULT_LIMIT,
                     methodLimit: int = 8, minLen: int = 0, **_: Any) -> dict:
    """Reverse lookup: string constant -> the methods that reference it.

    This is the single most productive hook-entry search (UI copy, log TAG,
    SharedPreferences key, HTTP path).  Results are ordered by *fewest*
    referencing methods first: a string used by one method is a far better
    anchor than one used by two hundred.
    """
    t0 = time.time()
    s = open_session(session_id)
    _v = (match or "").lower()
    if _v not in ('contains', 'exact', 'regex', 'prefix'):
        raise ApkIndexError(ErrorCode.BAD_ARGUMENT,
                            f"match 不支持: " + str(match),
                            "取值只能是 contains / exact / regex。")
    try:
        limit = env.clamp_limit(limit)
        if not text:
            raise ApkIndexError(ErrorCode.BAD_ARGUMENT, "text 不能为空")
        match = (match or "contains").lower()
        args = [s.session_id]
        if match == "contains":
            if len(text) < 2 and not minLen:
                raise ApkIndexError(ErrorCode.BAD_ARGUMENT,
                                    "contains 至少要 2 个字符（否则命中过散）",
                                    "短串请用 match=\"exact\"，或加 minLen。")
            clause = "lc LIKE ? ESCAPE '\\'"
            args.append("%" + _like(text.lower()) + "%")
        elif match == "exact":
            clause = "value = ?"
            args.append(text)
        elif match == "regex":
            clause = None       # python side, see below
        else:
            raise ApkIndexError(ErrorCode.BAD_ARGUMENT, f"match 不支持: {match}",
                                '只能是 "contains" | "exact" | "regex"')
        method_where, method_params = _scope_sql(scope)
        hits: list[dict] = []
        total = 0
        if clause:
            if minLen:
                clause += " AND len >= ?"
                args.append(int(minLen))
            cur = s.conn.execute(
                f"""SELECT id, value, len FROM strings
                    WHERE session_id=? AND {clause}
                    ORDER BY len LIMIT ?""", tuple(args) + (_SCAN_CAP,))
            cols = [c[0] for c in cur.description]
            cand = [dict(zip(cols, r)) for r in cur.fetchall()]
            cur.close()
        else:
            rx = re.compile(text)
            cur = s.conn.execute(
                "SELECT id, value, len FROM strings WHERE session_id=? LIMIT ?",
                (s.session_id, _SCAN_CAP))
            cols = [c[0] for c in cur.description]
            cand = [dict(zip(cols, r)) for r in cur.fetchall() if rx.search(r[1])]
            cur.close()
        for cand_row in cand:
            mc = int(s.scalar(
                f"""SELECT COUNT(*) FROM string_refs sr JOIN methods m ON m.id=sr.method_id
                    JOIN classes c ON c.id=m.class_id
                    WHERE sr.string_id=? {method_where}""",
                tuple([cand_row["id"]] + method_params)) or 0)
            total += 1
            if len(hits) >= limit or mc == 0:
                continue
            mrows = s.q(f"""SELECT {_M_COLS.replace('c.', 'c.').replace('m.', 'm.')}
                            FROM string_refs sr JOIN methods m ON m.id=sr.method_id
                            JOIN classes c ON c.id=m.class_id
                            WHERE sr.string_id=? {method_where}
                            ORDER BY c.descriptor LIMIT ?""",
                        tuple([cand_row["id"]] + method_params + [int(methodLimit or 8)]))
            entry = {
                "string": cand_row["value"],
                "stringId": cand_row["id"],
                "length": cand_row["len"],
                "methodCount": mc,
                "methods": [_method_item(s, r) for r in mrows],
            }
            if mc > len(mrows):
                entry["moreMethods"] = mc - len(mrows)
            hits.append(entry)
        hint = (f"{time.time() - t0:.2f}s；命中 {total} 个字符串常量，"
                "按“引用它的方法数”升序排：越少越适合作为 hook 锚点。"
                "拿 methods[].reflector 写代码，或把该串塞进 matchSignature 的 referredStrings。")
        return env.ok(hits, session_id=s.session_id, total=total,
                      truncated=total > len(hits), hint=hint, limit=limit,
                      elapsedMs=round((time.time() - t0) * 1000, 1),
                      query=text, match=match, scope=scope)
    finally:
        s.close()


def find_implementations(session_id: str, interface: str = "", superClass: str = "",
                         method: str = "", scope: str = "all",
                         limit: int = DEFAULT_LIMIT, transitive: bool = True,
                         includeAbstract: bool = True, **_: Any) -> dict:
    t0 = time.time()
    s = open_session(session_id)
    try:
        limit = env.clamp_limit(limit)
        if not (interface or superClass or method):
            raise ApkIndexError(ErrorCode.BAD_ARGUMENT,
                                "interface / superClass / method 至少要一个")
        where, wparams = _scope_sql(scope)
        conds = ["c.session_id=?"]
        args: list[Any] = [s.session_id]
        anchor_desc = ""

        def _anchor(ref):
            """索引里没有的框架父类（android.app.Activity）也要能查。

            旧实现直接 _unique_class 抛 NOT_FOUND，等于"父类递归"只对
            已索引的父类生效——真实目标几乎总是继承框架类。
            """
            try:
                return _unique_class(s, ref, "all")["descriptor"]
            except ApkIndexError:
                d = sg.normalize_desc(ref)
                if not d.startswith("L"):
                    raise
                return d

        if interface:
            anchor_desc = _anchor(interface)
            conds.append("EXISTS (SELECT 1 FROM json_each(c.interfaces_json) WHERE value = ?)")
            args.append(anchor_desc)
        if superClass:
            anchor_desc = _anchor(superClass)
            if transitive:
                conds.append("""c.super_descriptor IN (
                    WITH RECURSIVE chain(d) AS (
                      SELECT ? UNION ALL
                      SELECT c2.descriptor FROM classes c2
                      JOIN chain ON c2.super_descriptor = chain.d WHERE c2.session_id=?)
                    SELECT d FROM chain)""")
                args += [anchor_desc, s.session_id]
            else:
                conds.append("c.super_descriptor = ?")
                args.append(anchor_desc)
        if method:
            if "->" not in method and "(" not in method:
                # 裸方法名（"greet"）才是常态：问的是"谁实现了这个名字"，
                # 逼调用方写全 smali 签名等于逼他先去查参数表。
                mname, mpd = method.strip(), "()ANY"
            else:
                try:
                    _, mname, mpd, _ = sg.parse_method_ref(method)
                except sg.SignatureError as e:
                    raise ApkIndexError(ErrorCode.BAD_ARGUMENT, f"method 解析失败: {e}",
                                        "给方法名（greet）、Java 写法（类.方法）或完整 smali 引用。")
            conds.append("""EXISTS (SELECT 1 FROM methods m2 WHERE m2.class_id=c.id
                              AND m2.name=? """ + ("AND m2.params_descriptor=?" if mpd not in ("()", "()ANY") else "") + ")")
            args.append(mname)
            if mpd not in ("()", "()ANY"):
                args.append(mpd)
        if not includeAbstract:
            conds.append("(c.access_flags & 0x400) = 0 AND (c.access_flags & 0x200) = 0")
        sql = (f"SELECT * FROM classes c WHERE {' AND '.join(conds)}{where} "
               "ORDER BY c.source DESC, c.descriptor LIMIT ?")
        bound = tuple(args + wparams) + (limit,)
        rows = s.q(sql, bound)
        total = len(rows) + int(s.scalar(
            f"SELECT COUNT(*) FROM classes c WHERE {' AND '.join(conds)}{where}",
            tuple(args + wparams)) or 0)
        total = max(total, len(rows))
        items = []
        for r in rows:
            it = _class_item(s, r, with_counts=False)
            if anchor_desc:
                over = s.q("""SELECT m.name AS name, m.params_descriptor AS pd,
                                     m.return_descriptor AS rd, m.access_flags AS af,
                                     m.is_static AS st, m.is_constructor AS ctor
                              FROM methods m WHERE m.class_id=? AND m.is_constructor=0
                              ORDER BY m.name LIMIT 6""", (r["id"],))
                it["members"] = [
                    {"name": o["name"],
                     "smali": sg.smali_method(r["descriptor"], o["name"], o["pd"], o["rd"]),
                     "reflector": sg.reflector_method(sg.internal_name(r["descriptor"]),
                                                      o["name"], o["pd"], o["rd"]),
                     "java": sg.java_method(r["descriptor"], o["name"], o["pd"], o["rd"],
                                            modifiers=" ".join(
                                                f for f in flag_names(o["af"])
                                                if f in ("public", "protected", "private", "static", "final"))),
                     "static": bool(o["st"])} for o in over]
            items.append(it)
        hint = ("接口实现用于确定 hook 的“唯一入口”（例如所有 IResult.a() 的实现）；"
                "transitive=true 时用递归 CTE 走完整父类链。")
        return env.ok(items, session_id=s.session_id, total=total,
                      truncated=total > len(items), hint=hint, limit=limit,
                      elapsedMs=round((time.time() - t0) * 1000, 1),
                      anchor=sg.binary_name(anchor_desc) if anchor_desc else None)
    finally:
        s.close()


def xref(session_id: str, method: str = "", clazz: str = "", direction: str = "callers",
         depth: int = 1, limit: int = DEFAULT_LIMIT, scope: str = "all", **_: Any) -> dict:
    """Call graph walk, 1..3 hops, both directions.

    ``method`` accepts a Reflector/smali/Java reference (targets one overload
    set) or a bare class name (every method of that class becomes a frontier
    node).  ``direction=callers`` answers "who reaches this code", which is how
    you find the place to hook instead of the place that breaks.
    """
    t0 = time.time()
    s = open_session(session_id)
    try:
        limit = env.clamp_limit(limit)
        depth = max(1, min(3, int(depth or 1)))
        direction = (direction or "callers").lower()
        if direction not in ("callers", "callees"):
            raise ApkIndexError(ErrorCode.BAD_ARGUMENT, f"direction 不支持: {direction}")
        if not method:
            raise ApkIndexError(ErrorCode.BAD_ARGUMENT, "method 不能为空")
        # 只给裸方法名 + class= 时补全 owner，避免 "找不到方法: greet" 这种假阴。
        if clazz and not any(tok in method for tok in ("(", ";", "->", ".")):
            crows = find_class_rows(s, clazz, "all", limit=1)
            if crows:
                method = f"{crows[0]['descriptor']}->{method}"
        frontier: set[int] = set()
        target_desc: list[str] = []
        rows = find_class_rows(s, method, "all", limit=1)
        parsed = None
        try:
            parsed = sg.parse_method_ref(method)
        except sg.SignatureError:
            parsed = None
        if parsed and parsed[1]:
            owner, name, pd, ret = parsed
            mrows = s.q(f"""SELECT m.id AS id FROM methods m JOIN classes c ON c.id=m.class_id
                            WHERE c.descriptor=? AND m.name=?
                              {'AND m.params_descriptor=?' if pd != '()' else ''}
                              {'AND m.return_descriptor=?' if ret else ''}""",
                        tuple([owner, name] + ([pd] if pd != "()" else [])
                              + ([ret] if ret else [])))
            frontier = {r["id"] for r in mrows}
            target_desc = [sg.smali_method(owner, name, pd, ret)] if ret else []
            if not frontier:
                # fall back to name-only match across the session
                mrows = s.q("SELECT m.id AS id FROM methods m WHERE m.name=?", (name,))
                frontier = {r["id"] for r in mrows}
        elif rows:
            mrows = s.q("SELECT m.id AS id FROM methods m WHERE m.class_id=?", (rows[0]["id"],))
            frontier = {r["id"] for r in mrows}
        if not frontier:
            raise ApkIndexError(ErrorCode.NOT_FOUND, f"找不到方法: {method}",
                                "先 searchClasses/listMembers 确认签名，或去掉重载参数只给方法名。")
        items: list[dict] = []
        seen: set[tuple] = set()
        level_frontier = set(frontier)
        levels: list[int] = []
        for hop in range(1, depth + 1):
            if not level_frontier:
                break
            nxt: set[int] = set()
            ids = list(level_frontier)
            placeholders = ",".join("?" * len(ids))
            if direction == "callees":
                got = s.q(f"""SELECT m.id AS caller_id, r.id AS ref_id, r.kind AS kind,
                                     r.descriptor AS descriptor, r.owner AS owner, r.name AS name,
                                     r.params AS params, r.ret AS ret, SUM(e.hits) AS hits
                              FROM xref_edges e
                              JOIN methods m ON m.id=e.caller_method_id
                              JOIN refs r ON r.id=e.callee_ref
                              WHERE e.caller_method_id IN ({placeholders})
                                AND r.kind IN ({",".join(str(k) for k in INVOKE_KINDS)})
                              GROUP BY r.id, m.id
                              ORDER BY hits DESC LIMIT ?""", tuple(ids) + (limit * 4,))
            else:
                got = s.q(f"""SELECT m.id AS caller_id, r.id AS ref_id, r.kind AS kind,
                                     r.descriptor AS descriptor, r.owner AS owner, r.name AS name,
                                     r.params AS params, r.ret AS ret, SUM(e.hits) AS hits
                              FROM xref_edges e JOIN refs r ON r.id=e.callee_ref
                              JOIN methods m ON m.id=e.caller_method_id
                              WHERE r.descriptor IN (
                                  SELECT smali FROM (
                                      SELECT c.descriptor || '->' || m2.name || m2.params_descriptor
                                             || m2.return_descriptor AS smali
                                      FROM methods m2 JOIN classes c ON c.id=m2.class_id
                                      WHERE m2.id IN ({placeholders})))
                                AND r.kind IN ({",".join(str(k) for k in INVOKE_KINDS)})
                              GROUP BY m.id, r.id
                              ORDER BY hits DESC LIMIT ?""", tuple(ids) + (limit * 4,))
            for g in got:
                key = (g["caller_id"], g["ref_id"])
                if key in seen:
                    continue
                seen.add(key)
                caller = s.q("""SELECT c.descriptor AS descriptor, c.source AS source,
                                       c.dex_idx AS dex_idx, m.name AS name,
                                       m.params_descriptor AS params_descriptor,
                                       m.return_descriptor AS return_descriptor,
                                       m.access_flags AS access_flags, m.id AS method_id
                                FROM methods m JOIN classes c ON c.id=m.class_id WHERE m.id=?""",
                             (g["caller_id"],))
                entry: dict[str, Any] = {"depth": hop,
                                         "kind": CODE_TO_KIND.get(g["kind"], "invoke"),
                                         "hits": g["hits"]}
                if direction == "callees":
                    entry["from"] = _method_item(s, dict(caller[0])) if caller else None
                    entry["callee"] = _callee_forms(g)
                    if g["owner"] and g["name"]:
                        m2 = s.q("""SELECT m.id AS method_id, c.descriptor AS descriptor,
                                       c.source AS source, c.dex_idx AS dex_idx, m.name AS name,
                                       m.params_descriptor AS params_descriptor,
                                       m.return_descriptor AS return_descriptor,
                                       m.access_flags AS access_flags
                                    FROM methods m JOIN classes c ON c.id=m.class_id
                                    WHERE c.descriptor=? AND m.name=? AND m.params_descriptor=?""",
                                 (g["owner"], g["name"], g["params"] or "()"))
                        nxt |= {r["method_id"] for r in m2}
                else:
                    entry["to"] = _callee_forms(g)
                    if caller:
                        entry["caller"] = _method_item(s, dict(caller[0]))
                        nxt.add(caller[0]["method_id"])
                if len(items) < limit:
                    items.append(entry)
            levels.append(len(got))
            level_frontier = nxt - frontier
            frontier |= nxt
        total = sum(levels)
        hint = (f"{time.time() - t0:.2f}s；逐层 {levels}（depth={depth}）。"
                "callers 用来找“调用者”以便 hook 在最外层；callees 用来看该方法依赖什么。")
        return env.ok(items, session_id=s.session_id, total=total,
                      truncated=total > len(items), hint=hint, limit=limit,
                      elapsedMs=round((time.time() - t0) * 1000, 1),
                      direction=direction, depth=depth, levels=levels)
    finally:
        s.close()


def _callee_forms(g: dict) -> dict:
    """Turn a refs row into the same four-spelling shape as a method item."""
    kind = CODE_TO_KIND.get(g["kind"], "invoke")
    owner = g.get("owner") or ""
    name = g.get("name")
    if kind == "const-class":
        return {"kind": "type", "descriptor": owner, "binaryName": sg.binary_name(owner)}
    if name and ":" in (g.get("descriptor") or ""):
        return {"kind": "field", "smali": g["descriptor"],
                "reflector": sg.reflector_field(owner, name, g.get("ret") or "")}
    pd = g.get("params") or "()"
    ret = g.get("ret") or "V"
    return {"kind": "method", "smali": g["descriptor"],
            "reflector": sg.reflector_method(owner, name or "", pd, ret),
            "java": sg.java_method(owner, name or "", pd, ret),
            "binaryName": sg.binary_name(owner), "name": name,
            "paramsDescriptor": pd, "returnDescriptor": ret,
            "paramCount": len(sg.split_params(pd))}


# ------------------------------------------------------------- matchSignature
def match_signature(session_id: str, params: list | str | None = None,
                    returnType: str = "", modifiers: list | str | None = None,
                    referredStrings: list | str | None = None,
                    accessedFields: list | str | None = None,
                    invokedMethods: list | str | None = None,
                    namePattern: str = "", scope: str = "all",
                    packagePrefix: str = "", limit: int = DEFAULT_LIMIT,
                    requireConstructor: bool = False, **_: Any) -> dict:
    """Structural search: find the hook point by *shape*, not by name.

    Every condition is AND-ed.  Each hit comes back with a ready-made
    ``helper-ktx`` matcher block, so the answer is code, not a name to go and
    double-check.
    """
    t0 = time.time()
    s = open_session(session_id)
    try:
        limit = env.clamp_limit(limit)
        plist = _as_list(params)
        pdescs: list[str] = []
        wildcard_count = None
        for p in plist:
            if p.strip() in ("*", "any", "Any", ""):
                wildcard_count = (wildcard_count or 0) + 1
                pdescs.append(None)
            else:
                pdescs.append(sg.normalize_desc(p))
        rwhere, rparams = _scope_sql(scope)
        conds = ["c.session_id=?"]
        args: list[Any] = [s.session_id]
        if pdescs and wildcard_count is None:
            conds.append("m.params_descriptor = ?")
            args.append("(" + "".join(pdescs) + ")")
        elif plist:
            conds.append("m.param_count = ?")
            args.append(len(pdescs))
        if returnType and returnType.strip() not in ("*", "any", "void?"):
            conds.append("m.return_descriptor = ?")
            args.append(sg.normalize_desc(returnType))
        elif returnType.strip() == "any":
            pass
        elif returnType.strip() == "*":
            pass
        for mod in _as_list(modifiers):
            if mod.strip().lower() == "constructor":
                # 位判会把 <clinit> 也捞进来（d8 给它打同一个位）
                conds.append("m.name = '<init>'")
                continue
            bit = ACC_BITS.get(mod.strip().lower())
            if bit is None:
                raise ApkIndexError(ErrorCode.BAD_ARGUMENT, f"未知 modifier: {mod}",
                                    "可用: " + ", ".join(sorted(ACC_BITS)))
            conds.append(f"(m.access_flags & {bit}) = {bit}")
        if requireConstructor:
            conds.append("m.name = '<init>'")
        if packagePrefix:
            # 包名在库里可能是 com/example/demo 也可能是 com.example.demo，
            # 只按一种写法 LIKE 会让"看着对"的前缀静默返回 0 条。
            conds.append("(REPLACE(c.package, '/', '.') LIKE ? ESCAPE '\\'"
                         " OR c.package LIKE ? ESCAPE '\\')")
            args.append(_like(packagePrefix.replace("/", ".")) + "%")
            args.append(_like(packagePrefix) + "%")
        strings = [x for x in _as_list(referredStrings) if x]
        for sstr in strings[:6]:
            conds.append("""EXISTS (SELECT 1 FROM string_refs sr JOIN strings st ON st.id=sr.string_id
                                WHERE sr.method_id=m.id AND st.value=?)""")
            args.append(sstr)
        fields = [x for x in _as_list(accessedFields) if x]
        for f in fields[:6]:
            try:
                owner, fname, ftype = sg.parse_field_ref(f)
            except sg.SignatureError:
                owner, fname, ftype = sg.normalize_desc(f.split("->")[0]), \
                    f.split("->")[1].split(":")[0], \
                    sg.normalize_desc(f.split(":", 1)[1] if ":" in f else "Ljava/lang/Object;")
            desc = sg.smali_field(owner, fname, ftype)
            conds.append("""EXISTS (SELECT 1 FROM xref_edges e JOIN refs r ON r.id=e.callee_ref
                                WHERE e.caller_method_id=m.id AND r.descriptor=? AND r.kind IN (10,11,12,13))""")
            args.append(desc)
        calls = [x for x in _as_list(invokedMethods) if x]
        for c in calls[:6]:
            owner, cname, cpd, cret = sg.parse_method_ref(c)
            desc = sg.smali_method(owner, cname, cpd, cret)
            conds.append("""EXISTS (SELECT 1 FROM xref_edges e JOIN refs r ON r.id=e.callee_ref
                                WHERE e.caller_method_id=m.id AND r.descriptor=?
                                  AND r.kind IN (1,2,3,4,5,6,7,8))""")
            args.append(desc)
        rx = re.compile(namePattern) if namePattern else None
        sql = (f"""SELECT {_M_COLS} FROM methods m JOIN classes c ON c.id=m.class_id
                  WHERE {' AND '.join(conds)}{rwhere}
                  ORDER BY c.source DESC, m.name LIMIT ?""")
        rows = s.q(sql, tuple(args + rparams) + (limit * (4 if rx else 1),))
        items: list[dict] = []
        total = 0
        for r in rows:
            if rx and not rx.search(r["name"] or ""):
                continue
            total += 1
            if len(items) >= limit:
                continue
            forms = sg.method_forms(r["descriptor"], r["name"], r["params_descriptor"],
                                    r["return_descriptor"], r["access_flags"])
            bin_name = sg.binary_name(r["descriptor"])
            item = _method_item(s, r, with_evidence=True)
            item["forms"] = forms
            item["matched"] = {
                "params": forms["params"], "return": forms["returnDescriptor"],
                "modifiers": forms["java"].rsplit(" ", 2)[0] if " " in forms["java"] else "",
                "referredStrings": strings, "accessedFields": fields, "invokedMethods": calls,
            }
            item["dsl"] = dslmod.match_dsl(
                bin_name, r["name"], forms["params"], r["return_descriptor"],
                access=r["access_flags"],
                super_binary=sg.binary_name(r["super_descriptor"]) if r.get("super_descriptor") else None,
                referred_strings=strings,
                is_constructor=(r.get("name") == "<init>"))
            item["reflectorSnippet"] = dslmod.reflector_snippet(forms)
            items.append(item)
        dsl_check = [p for it in items for p in dslmod.check_kotlin(it.get("dsl", ""))]
        hint = ("所有条件是 AND。referredStrings/accessedFields/invokedMethods 走的是"
                "已建好的 string_refs / xref_edges，不是现场扫 dex。"
                + (" 生成块结构检查通过。" if not dsl_check else " 生成块结构异常: " + "; ".join(dsl_check)))
        for _it in items:
            _it["constructor"] = _it.get("name") == "<init>"
        return env.ok(items, session_id=s.session_id, total=total,
                      truncated=total > len(items), hint=hint, limit=limit,
                      elapsedMs=round((time.time() - t0) * 1000, 1),
                      conditions={"params": plist, "returnType": returnType,
                                  "modifiers": _as_list(modifiers),
                                  "referredStrings": strings, "accessedFields": fields,
                                  "invokedMethods": calls, "namePattern": namePattern})
    finally:
        s.close()


def _as_list(v: Any) -> list[str]:
    if v is None or v == "":
        return []
    if isinstance(v, list):
        return [str(x) for x in v]
    if isinstance(v, tuple):
        return [str(x) for x in v]
    return [x.strip() for x in re.split(r"[,;|]", str(v)) if x.strip()]


# ---------------------------------------------------------------- decompile
def decompile(session_id: str, target: str = "", format: str = "auto",
              maxLines: int = MAX_DECOMPILE_LINES, **_: Any) -> dict:
    from . import decomp
    s = open_session(session_id)
    try:
        if not target:
            raise ApkIndexError(ErrorCode.BAD_ARGUMENT, "target 不能为空")
        return decomp.decompile(s, target, (format or "auto").lower(),
                                max(int(maxLines or MAX_DECOMPILE_LINES), 20))
    finally:
        s.close()


# ------------------------------------------------------------- diffSessions
def diff_sessions(session_a: str = "", session_b: str = "", limit: int = DEFAULT_LIMIT,
                  minScore: float = 0.45, scope: str = "app", **_: Any) -> dict:
    """Cross-version drift report: which obfuscated names moved where.

    Pairing is structural (super class + interface set + method signature set +
    referenced string set), because obfuscated names carry no information
    across releases.  Exact structural matches come first, then a Jaccard pass
    inside same-super buckets.
    """
    for key, val in (("sessionA", session_a), ("sessionB", session_b)):
        if not (val or "").strip():
            raise ApkIndexError(ErrorCode.BAD_ARGUMENT, f"diffSessions 缺少必填参数 {key}",
                                "两个会话都要给：sessionA=旧版 sessionId, sessionB=新版；"
                                "忘了 id 先调 sessionList。")
    t0 = time.time()
    sa = open_session(session_a)
    sb = open_session(session_b)
    try:
        limit = env.clamp_limit(limit)
        fa = _feature_map(sa, scope)
        fb = _feature_map(sb, scope)
        exact_a = {}
        for desc, f in fa.items():
            exact_a.setdefault(f["sig_hash"], []).append(desc)
        renamed: list[dict] = []
        matched_a: set[str] = set()
        matched_b: set[str] = set()
        for desc, f in fb.items():
            if desc in fa:
                matched_a.add(desc)
                matched_b.add(desc)
                continue
            cands = exact_a.get(f["sig_hash"], [])
            cands = [c for c in cands if c not in matched_a]
            if len(cands) == 1:
                renamed.append(_diff_pair(sa, sb, fa[cands[0]], f, 1.0, "exact-structure"))
                matched_a.add(cands[0])
                matched_b.add(desc)
        # fuzzy: bucket by super, compare method-signature + string Jaccard
        buckets: dict[str, list[str]] = {}
        for desc, f in fa.items():
            if desc in matched_a:
                continue
            buckets.setdefault(f["super"], []).append(desc)
        for desc, f in fb.items():
            if desc in matched_b:
                continue
            pool = [x for x in buckets.get(f["super"], []) if x not in matched_a][:64]
            best, best_score = None, 0.0
            for cand in pool:
                score = _jaccard_pair(fa[cand], f)
                if score > best_score:
                    best, best_score = cand, score
            if best and best_score >= float(minScore):
                renamed.append(_diff_pair(sa, sb, fa[best], f, round(best_score, 3),
                                          "structural-similarity"))
                matched_a.add(best)
                matched_b.add(desc)
        removed = [fa[d] for d in fa if d not in matched_a]
        added = [fb[d] for d in fb if d not in matched_b]
        items = [{"kind": "renamed", **r} for r in renamed[:limit]]
        items += [{"kind": "removed", **_brief_feat(x)} for x in removed[:limit]]
        items += [{"kind": "added", **_brief_feat(x)} for x in added[:limit]]
        hint = (f"{time.time() - t0:.2f}s；renamed={len(renamed)} added={len(added)} "
                f"removed={len(removed)}。exact-structure=签名集合完全一致（可信）；"
                "structural-similarity=按 Jaccard 猜的（写进模块前先 decompile 复核）。")
        return env.ok(items, session_id=sa.session_id, total=len(items),
                      truncated=len(items) >= limit, hint=hint, limit=limit,
                      elapsedMs=round((time.time() - t0) * 1000, 1),
                      summary={"sessionA": sa.session_id, "sessionB": sb.session_id,
                               "classesA": len(fa), "classesB": len(fb),
                               "renamed": len(renamed), "added": len(added),
                               "removed": len(removed),
                               "unchanged": len(set(fa) & set(fb))},
                      pairA=_pair_note(renamed))
    finally:
        sa.close()
        sb.close()


def _pair_note(renamed: list[dict]) -> str:
    if not renamed:
        return "两版结构完全一致，旧模块大概率不用改。"
    return f"最高相似度 {max(r['score'] for r in renamed):.2f}，见 items[].from/to。"


def _feature_map(s: SessionDB, scope: str) -> dict:
    where, wparams = _scope_sql(scope)
    out: dict[str, dict] = {}
    cur = s.conn.execute(
        f"""SELECT c.id, c.descriptor, c.super_descriptor, c.interfaces_json,
                   c.package, c.source, c.kind, c.access_flags
            FROM classes c WHERE c.session_id=?{where}""",
        tuple([s.session_id] + wparams))
    cols = [c[0] for c in cur.description]
    crows = [dict(zip(cols, r)) for r in cur.fetchall()]
    cur.close()
    for c in crows:
        ms = s.q("SELECT name, params_descriptor, return_descriptor FROM methods WHERE class_id=?",
                 (c["id"],))
        sigs = sorted(f"{m['name']}{m['params_descriptor']}{m['return_descriptor']}" for m in ms)
        fs = s.q("SELECT name, type_descriptor FROM fields WHERE class_id=?", (c["id"],))
        flds = sorted(f"{f['name']}:{f['type_descriptor']}" for f in fs)
        strs = s.q("""SELECT DISTINCT st.value AS v FROM string_refs sr
                      JOIN methods m2 ON m2.id=sr.method_id JOIN strings st ON st.id=sr.string_id
                      WHERE m2.class_id=? LIMIT 200""", (c["id"],))
        import hashlib
        h = hashlib.sha1(
            ("|".join(sigs) + "#" + "|".join(flds) + "#" + (c["super_descriptor"] or "")).encode()
        ).hexdigest()[:16]
        out[c["descriptor"]] = {
            "descriptor": c["descriptor"], "binaryName": sg.binary_name(c["descriptor"]),
            "super": c["super_descriptor"] or "", "source": c["source"],
            "interfaces": json.loads(c["interfaces_json"] or "[]"),
            "methods": sigs, "fields": flds, "strings": [x["v"] for x in strs],
            "sig_hash": h, "classKind": c["kind"],
        }
    return out


def _jaccard_pair(a: dict, b: dict) -> float:
    def jac(x: set, y: set) -> float:
        if not x and not y:
            return 0.0
        inter = len(x & y)
        union = len(x | y) or 1
        return inter / union
    # 混淆器改类名也改成员名，但改不掉方法外形（参数表+返回类型）和字符串常量。
    # 旧实现把成员名算进 methods 集合，改名后交集归零，a.b.e ↔ JavaGreeter 这种一眼
    # 同构的配对被 minScore 掉，整张差分表只剩一对假阳。
    def shape(f):
        return sorted(f"{m.split(')')[0]}){m.split(')')[-1]}" for m in f["methods"])

    def names(f):
        return sorted({m.split("(")[0] for m in f["methods"]})

    sh = jac(set(shape(a)), set(shape(b)))
    ms = jac(set(names(a)), set(names(b)))
    ss = jac(set(a["strings"]), set(b["strings"]))
    fs = jac(set(f.split(":", 1)[0] for f in a["fields"]),
             set(f.split(":", 1)[0] for f in b["fields"]))
    iface = 1.0 if (len(a["interfaces"]) == len(b["interfaces"])
                    and a["classKind"] == b["classKind"]) else 0.3
    return 0.30 * sh + 0.33 * ss + 0.15 * fs + 0.12 * ms + 0.10 * iface


def _diff_pair(sa: SessionDB, sb: SessionDB, a: dict, b: dict, score: float,
               how: str) -> dict:
    am, bm = set(a["methods"]), set(b["methods"])
    return {
        "score": score, "how": how,
        "from": a["binaryName"], "to": b["binaryName"],
        "fromDescriptor": a["descriptor"], "toDescriptor": b["descriptor"],
        "packageFrom": sg.binary_name(a["descriptor"]).rsplit(".", 1)[0],
        "packageTo": sg.binary_name(b["descriptor"]).rsplit(".", 1)[0],
        "methodsOnlyInA": sorted(am - bm)[:10],
        "methodsOnlyInB": sorted(bm - am)[:10],
        "methodCount": {"a": len(am), "b": len(bm)},
        "reflectorTo": sg.internal_name(b["descriptor"]),
        "classForNameTo": sg.class_for_name(b["descriptor"], loader=True),
        "kept": a["binaryName"] == b["binaryName"],
    }


def _brief_feat(f: dict) -> dict:
    return {"from" if f.get("_gone") else "class": f["binaryName"],
            "descriptor": f["descriptor"], "superClass": sg.binary_name(f["super"]) if f["super"] else None,
            "source": f["source"], "methodCount": len(f["methods"]),
            "sampleMethods": f["methods"][:6],
            "sampleStrings": f["strings"][:4]}


# -------------------------------------------------------------------- probe
_QUESTION_WORDS = re.compile(r"[A-Za-z][A-Za-z0-9_.]{2,}")
_CJK = re.compile(r"[\u4e00-\u9fff]{2,}")
_QUOTES = re.compile(r"[\"'“”「『《]([^\"'“”」』》]{2,80})[\"'“”」』》]")
_PATH = re.compile(r"[\w./-]{4,}")


def probe(session_id: str, question: str = "", limit: int = 12,
          target: str = "", max_depth: int = 2, **_: Any) -> dict:
    """One call = the usual recon sweep, so the caller stops burning tokens.

    Recognises: quoted literals (→ string search), dotted identifiers and Camel
    names (→ class search), CJK phrases (→ UI copy search), and falls back to a
    package/corpus overview so the caller knows what it is looking at.
    """
    t0 = time.time()
    s = open_session(session_id)
    try:
        limit = env.clamp_limit(limit, default=12)
        q = question or ""
        quoted = [x.strip() for x in _QUOTES.findall(q) if x.strip()]
        dotted = [x for x in _QUESTION_WORDS.findall(q)
                  if "." in x or (x[0].isupper() and len(x) > 5)]
        cjk = [x for x in _CJK.findall(q)]
        keywords = list(dict.fromkeys(quoted + cjk + dotted))[:6]
        sections: dict[str, Any] = {}
        sections["target"] = {
            "sessionId": s.session_id, "kind": s.kind, "backend": s.backend,
            "counts": s.counts(), "packed": s.packed,
        }
        pack = s.row.get("meta_json")
        sections["keywords"] = keywords
        string_hits: list[dict] = []
        for kw in keywords:
            r = search_by_string(s.session_id, kw, "contains", limit=3,
                                 methodLimit=4)
            for it in r.get("items", []):
                string_hits.append(it)
            if len(string_hits) >= limit:
                break
        sections["stringHits"] = string_hits[:limit]
        class_hits: list[dict] = []
        for kw in dotted[:4]:
            r = search_classes(s.session_id, kw, "regex" if "$" in kw else "prefix",
                               scope="app", limit=max(3, limit // 2))
            class_hits.extend(r.get("items", [])[:max(3, limit // 2)])
            if len(class_hits) >= limit:
                break
        sections["classHits"] = class_hits[:limit]
        candidates: list[dict] = []
        for hit in string_hits[:4]:
            for m in hit.get("methods", [])[:2]:
                candidates.append({
                    "anchor": hit["string"], "class": m["class"], "name": m["name"],
                    "reflector": m["reflector"], "java": m["java"],
                    "paramCount": m["paramCount"], "returnType": m["returnType"],
                })
        if not candidates and class_hits:
            # 问句里只有类名（没有字符串锚点）时也要给出起点，否则 probe 在这种
            # 最常见的问法下返回空建议，等于没用。
            for ch in class_hits[:3]:
                chd = sg.normalize_desc(str(ch.get("descriptor") or ch.get("binaryName")
                                              or ch.get("class") or ""))
                if not chd:
                    continue
                for mr in s.q("""SELECT m.name, m.params_descriptor, m.return_descriptor
                                 FROM methods m JOIN classes c ON c.id=m.class_id
                                 WHERE c.descriptor=? ORDER BY m.name LIMIT 5""", (chd,)):
                    bn = sg.binary_name(chd)
                    candidates.append({
                        "class": bn, "name": mr["name"],
                        "reflector": (f"{bn}->{mr['name']}"
                                      f"{mr['params_descriptor']}{mr['return_descriptor']}"),
                        "anchor": "",
                        "evidence": "类命中（无字符串锚点）：该类成员是候选 hook 点，"
                                    "用 getSignature 核对形态后再决定",
                    })
        sections["hookCandidates"] = candidates[:limit]
        if candidates:
            c0 = candidates[0]
            owner = sg.normalize_desc(c0["class"])
            pd = re.search(r"\(([^()]*)\)", c0["reflector"])
            ret = c0["reflector"].rsplit(")", 1)[-1]
            sections["suggestedDsl"] = dslmod.match_dsl(
                c0["class"], c0["name"], sg.split_params("(" + (pd.group(1) if pd else "") + ")"),
                ret, referred_strings=[c0["anchor"]])
        # 显式给了 target 就必须深挖：schema 上写着 target/maxDepth 却什么都不做，
        # 是最坏的一种"能用"。类目标先取其成员再逐个取调用者；出错单独放
        # xrefErrors，不把整次 probe 打死，也不静默吞掉。
        # 问"有哪些实现类 / 谁实现了 X / X 的子类"→ 直接跑实现查找。
        # 这个分节一度在别处丢失，导致 probe 对这类问法只给候选不给答案。
        if re.search(r"实现|子类|派生|implements|subclass", q, re.I) and "implementations" not in sections:
            _iface = ""
            for _kw in dotted + [k for k in keywords if k not in dotted]:
                _k = str(_kw).strip()
                if _k and not re.search(r"[\u4e00-\u9fff]", _k):
                    _iface = _k.split(".")[-1] if "#" not in _k else _k
                    break
            if _iface:
                try:
                    _fi = find_implementations(session_id, interface=_iface, limit=limit)
                    sections["implementations"] = {
                        "interface": _iface, "items": _fi.get("items", [])[:limit],
                        "total": _fi.get("total")}
                except Exception as _exc:  # noqa: BLE001
                    sections["implementations"] = {
                        "interface": _iface, "items": [],
                        "message": str(_exc)[:180]}

        tgt = str(target or "").strip()
        if tgt:
            # 成员引用有两种常见写法（A#b(sig) 与 A->b(sig)），不同后端认的不同；
            # 类名直接交给 xref 的"整类全部成员"语义，不去枚举拼畸形引用。
            forms = [tgt]
            if "#" in tgt:
                forms.append(tgt.replace("#", "->", 1))
            elif "->" in tgt:
                forms.append(tgt.replace("->", "#", 1))
            agg: list[dict] = []
            errs: list[dict] = []
            for _r in forms:
                try:
                    try:
                        _x = xref(session_id, method=_r, direction="callers",
                                  depth=max_depth)
                    except TypeError:
                        _x = xref(session_id, method=_r, direction="callers")
                    _items = _x.get("items", [])
                except Exception as exc:  # noqa: BLE001
                    _items = []
                    errs.append({"target": _r, "error": str(getattr(exc, "code", "ERROR")),
                                 "message": str(exc)[:160]})
                if _items:
                    for _it in _items[:limit]:
                        _it = dict(_it)
                        _it.setdefault("via", _r)
                        agg.append(_it)
                    break
            sections["xref"] = agg[:limit]
            if errs and not agg:
                sections["xrefErrors"] = errs[:4]
            if "#" not in tgt and "->" not in tgt:
                try:
                    sections["signature"] = get_signature(session_id, cls=tgt)
                except Exception as exc:  # noqa: BLE001
                    sections["signature"] = {"message": str(exc)[:180]}
            try:
                dc = decompile(session_id, target=tgt, maxLines=80)
            except TypeError:
                try:
                    dc = decompile(session_id, target=tgt)
                except Exception as exc:  # noqa: BLE001
                    dc = {"error": str(getattr(exc, "code", "ERROR")),
                          "message": str(exc)[:200]}
            except Exception as exc:  # noqa: BLE001
                dc = {"error": str(getattr(exc, "code", "ERROR")), "message": str(exc)[:200]}
            src = dc.get("source") or dc.get("code") or dc.get("java") or ""
            sections["decompile"] = {
                "format": dc.get("format"), "backend": dc.get("backend"),
                "truncated": dc.get("truncated"), "error": dc.get("error"),
                "message": dc.get("message"), "source": str(src)[:4000]}
            _hint = (f"probe 已按 target 深挖调用链（{len(agg)} 条）；"
                     "要更全的链就用 xref 带 direction/depth。") if agg else \
                (f"target {tgt} 没查到调用者；先 getSignature 核对成员写法。")
            NEXT_HINT = _hint

        next_steps = []
        if locals().get("NEXT_HINT"):
            next_steps.append(NEXT_HINT)
        if locals().get("NEXT_HINT"):
            next_steps.append(NEXT_HINT)
        if s.packed:
            next_steps.append("目标是加固包：静态 dex 只有壳类，先脱壳再 loadDex，或改走运行期 hook。")
        if not string_hits:
            next_steps.append("没有字符串命中：换 searchClasses(kind=regex) 或提供 UI 上真实可见的文案。")
        if not class_hits:
            next_steps.append("没有类命中：目标符号可能是混淆名，先用 matchSignature 按结构找。")
        if not next_steps:
            next_steps.append("用 getSignature 取四种写法，再 decompile(format=\"smali\") 复核方法体。")
        hint = (f"{time.time() - t0:.2f}s；一次侦察含 "
                f"{len(keywords)} 个关键词 / {len(string_hits)} 个字符串命中 / "
                f"{len(class_hits)} 个类命中。证据不足时不要写 hook。")
        return env.ok([{"section": k, "data": v} for k, v in sections.items()],
                      session_id=s.session_id, total=len(sections),
                      truncated=False, hint=hint, sections=sections,
                      nextSteps=next_steps,
                      elapsedMs=round((time.time() - t0) * 1000, 1))
    finally:
        s.close()


def session_health(session_id: str) -> dict:
    """Internal helper used by server selftest: can this session answer queries?"""
    s = open_session(session_id)
    try:
        return {"sessionId": s.session_id, "counts": s.counts(), "dbPath": s.db_path}
    finally:
        s.close()
