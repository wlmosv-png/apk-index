"""Loader layer: turn an artifact into a queryable Session.

``loadApk`` / ``loadAar`` / ``loadDex`` are the only tools that write anything,
and what they write is exclusively the SQLite index under CACHE_DIR.  Input
artifacts are opened read-only and never repacked.
"""
from __future__ import annotations

import io
import json
import os
import re
import time
import zipfile

from . import apkio, backends
from . import packer as packer_mod
from .config import (ApkIndexError, DEFAULT_LIMIT, ErrorCode, HARD_LIMIT,
                     iso, resolve_input_path, settings)
from .dex import ACC_STATIC, ClassInfo, CodeInfo, DexFileData, FieldInfo, MethodInfo
from .index import (SCHEMA_VERSION, IndexWriter, SessionDB, catalog, connect,
                    meta_get)
from .signature import normalize_desc

DEX_NAME_RE = re.compile(r"(^|/)classes\d*\.dex$")  # classes.dex / classes2.dex
PROGUARD_KEEP_RE = re.compile(
    r"^-(?:keep|keepclassmembers|keepclasseswithmembers|keepdirectories)\b(.*)$")


def session_id_for(sha: str) -> str:
    return "ses_" + sha[:12]


def combined_sha(per_file: list[tuple[str, str]]) -> str:
    import hashlib
    if len(per_file) == 1:
        return per_file[0][1]
    h = hashlib.sha256()
    for name, digest in sorted(per_file):
        h.update(name.encode("utf-8", "replace"))
        h.update(digest.encode("utf-8", "replace"))
    return h.hexdigest()


def _limit(v, default=DEFAULT_LIMIT):
    try:
        v = int(v) if v is not None else default
    except Exception:
        v = default
    return max(1, min(HARD_LIMIT, v))


def _params_of(pd: str) -> list[str]:
    return backends._params(pd)


# ------------------------------------------------- class-file -> DexFileData
def classes_to_dexfile(entries: list[tuple[str, bytes]], label: str) -> DexFileData:
    """Index a jar's .class stream through the same record shape as dex."""
    from . import classfile
    classes: list[ClassInfo] = []
    strings: list[str] = []
    seen: set[str] = set()
    notes: list[str] = []
    for name, data in entries:
        try:
            pc = classfile.parse(data)
        except Exception as e:
            notes.append(f"{name}: {e}")
            continue
        fields = []
        for f in pc.fields:
            desc = f["descriptor"]
            fields.append(FieldInfo(f["name"], normalize_desc(desc), f["access"],
                                    bool(f["access"] & ACC_STATIC)))
        methods = []
        for m in pc.methods:
            desc = m["descriptor"]
            if ")" in desc:
                pd, ret = desc.split(")")[0] + ")", desc.split(")")[-1]
            else:
                pd, ret = "()", "V"
            code = None
            if any(k in m for k in ("code_strings", "code_methods", "code_fields")):
                code = CodeInfo()
                for s in m.get("code_strings") or []:
                    code.strings.append(s)
                    if s not in seen:
                        seen.add(s)
                        strings.append(s)
                for ref in m.get("code_methods") or []:
                    _kind, owner, nm, d = ref[0], ref[1], ref[2], ref[3]
                    if ")" in d:
                        opd, oret = d.split(")")[0] + ")", d.split(")")[-1]
                    else:
                        opd, oret = "()", "V"
                    code.calls.append(("invoke-direct" if nm == "<init>"
                                       else "invoke-virtual",
                                       normalize_desc(owner), nm,
                                       _params_of(opd), normalize_desc(oret)))
                for ref in m.get("code_fields") or []:
                    code.reads.append((normalize_desc(ref[1]), ref[2],
                                       normalize_desc(ref[3])))
            methods.append(MethodInfo(m["name"], _params_of(pd), normalize_desc(ret),
                                      "", m["access"], code))
        for s in pc.class_strings or []:
            if s not in seen:
                seen.add(s)
                strings.append(s)
        classes.append(ClassInfo(
            descriptor=normalize_desc(pc.descriptor), access=pc.access,
            super_descriptor=normalize_desc(pc.super_descriptor)
            if pc.super_descriptor else None,
            interfaces=[normalize_desc(i) for i in pc.interfaces or []],
            source_file=None, fields=fields, methods=methods, annotations=[]))
    counts = {"string_ids": len(strings), "type_ids": 0, "proto_ids": 0,
              "field_ids": sum(len(c.fields) for c in classes),
              "method_ids": sum(len(c.methods) for c in classes),
              "class_defs": len(classes), "method_handles": 0, "call_sites": 0,
              "code_items": sum(1 for c in classes for m in c.methods if m.code)}
    return DexFileData(name=label, size_bytes=sum(len(d) for _n, d in entries),
                       version="class", counts=counts, classes=classes,
                       strings=strings, parse_notes=notes[:20])


def _jar_entries(blob: bytes, limit: int = 20000) -> list[tuple[str, bytes]]:
    out = []
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        for n in zf.namelist():
            if n.endswith(".class") and "module-info" not in n:
                out.append((n, zf.read(n)))
                if len(out) >= limit:
                    break
    return out


# ---------------------------------------------------------------- session io
def _read_summary(db_path: str) -> dict:
    conn = connect(db_path, readonly=True)
    try:
        return meta_get(conn, "summary", {}) or {}
    finally:
        conn.close()


def _index_usable(row: dict) -> bool:
    p = row.get("dbPath") or ""
    if not p or not os.path.exists(p):
        return False
    try:
        summary = _read_summary(p)
    except Exception:
        return False
    if not summary:
        return False
    if int(summary.get("schemaVersion") or 0) != SCHEMA_VERSION:
        raise ApkIndexError(
            ErrorCode.INDEX_STALE,
            f"索引 schema v{summary.get('schemaVersion')} 与当前 v{SCHEMA_VERSION} 不符",
            f"unload({row['session_id']}) 后重新 loadApk 重建。")
    return True


def _counts_of(db_path: str) -> dict:
    conn = connect(db_path, readonly=True)
    try:
        out = {}
        for key, table in [("dex", "dex"), ("classes", "classes"),
                           ("methods", "methods"), ("fields", "fields"),
                           ("strings", "strings"), ("stringRefs", "string_refs"),
                           ("xrefEdges", "xref_edges"), ("refs", "refs"),
                           ("annotations", "annotations")]:
            out[key] = int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        return out
    finally:
        conn.close()


def _result(row: dict, summary: dict, already_loaded: bool,
            elapsed_ms: float) -> dict:
    sid = row["session_id"]
    counts = summary.get("counts") or _counts_of(row["dbPath"])
    dexes = summary.get("dexes") or []
    pack = summary.get("packed") or {}
    items = []
    for d in dexes[:12]:
        items.append({k: v for k, v in d.items()
                      if k in ("dex", "dexIdx", "version", "sizeBytes", "sha256",
                               "counts", "skipped", "notes")})
    hint = ("索引命中缓存（sha256 幂等复用），未重建。" if already_loaded
            else "首次索引完成。写 hook 前先用 searchByString/matchSignature 定位 hook 点，"
                 "再用 getSignature 取 Reflector 字符串。")
    if pack.get("packed"):
        hint = "注意：判定为加固包，dex 里可能只有壳类。" + hint
    return {
        "ok": True,
        "sessionId": sid,
        "alreadyLoaded": already_loaded,
        "kind": summary.get("kind", row.get("kind")),
        "fingerprint": {
            "sha256": summary.get("sha256", row.get("sha256")),
            "pkg": summary.get("pkg") or row.get("pkg"),
            "versionName": summary.get("versionName") or row.get("version_name"),
            "versionCode": summary.get("versionCode") if summary.get("versionCode")
            is not None else row.get("version_code"),
            "dexCount": counts.get("dex", len(dexes)),
            "totalClasses": counts.get("classes", 0),
        },
        "packed": {
            "packed": bool(pack.get("packed")),
            "evidence": pack.get("evidence", [])[:12],
            "vendors": pack.get("vendors", []),
            "confidence": pack.get("confidence", "none"),
            "stringEntropy": pack.get("stringEntropy"),
            "recommendation": pack.get("recommendation", ""),
        },
        "total": counts.get("classes", 0),
        "items": items,
        "truncated": len(dexes) > 12,
        "hint": hint,
        "index": {"path": row["dbPath"],
                  "sizeBytes": os.path.getsize(row["dbPath"])
                  if os.path.exists(row["dbPath"]) else 0,
                  "indexMs": round(elapsed_ms, 1) if not already_loaded
                  else summary.get("indexMs"),
                  "backend": row.get("backend"), "counts": counts},
        "splits": summary.get("splits", []),
        "paths": summary.get("paths", []),
        "manifestBrief": summary.get("manifest", {}),
        "components": summary.get("components", {}),
        "deps": summary.get("deps", {}),
        "keepRules": summary.get("keepRules", []),
        "declaredPackages": summary.get("declaredPackages", []),
        "classesTotal": summary.get("classesTotal", counts.get("classes", 0)),
        "schemaVersion": summary.get("schemaVersion"),
        "createdAt": summary.get("createdAt"),
    }


def _register(sid: str, summary: dict, db_path: str, kind: str, backend_name: str,
              index_ms: float, sources: list[str], packed: bool):
    catalog().upsert(
        session_id=sid, sha256=summary["sha256"], kind=kind,
        label=summary.get("pkg") or (sources[0] if sources else sid),
        pkg=summary.get("pkg") or "", version_name=summary.get("versionName"),
        version_code=summary.get("versionCode"), db_path=db_path,
        index_ms=round(index_ms, 1), backend=backend_name,
        packed=1 if packed else 0, sources_json=json.dumps(sources),
        meta_json=json.dumps({"counts": summary.get("counts", {}),
                              "dexCount": len(summary.get("dexes", []))},
                             ensure_ascii=False))


# ------------------------------------------------------------------- loadApk
def _size_gate(path: str, max_apk_bytes: int = 0, force: bool = False) -> None:
    """体积门槛：默认 200MB（settings），单次调用可用 maxApkBytes 覆盖。

    force=True 才放行——不是静默降级，索引大包的代价（时间/磁盘）由客户端显式承担。
    """
    cap = int(max_apk_bytes or 0) or int(os.environ.get("APK_INDEX_MAX_BYTES",
                                     200 * 1024 * 1024))
    if cap <= 0:
        return
    try:
        size = os.path.getsize(path)
    except OSError:
        return
    if size > cap and not force:
        from .config import ApkIndexError, ErrorCode  # 局部导入，避免与旧 import 结构冲突
        raise ApkIndexError(
            ErrorCode.APK_TOO_LARGE,
            f"文件 {size / 1048576:.1f}MB 超过上限 {cap / 1048576:.1f}MB",
            "确认要付索引代价就带 force=true；或只索引目标 dex：loadDex(path=内部 classes.dex)。")


def load_apk(path: str, from_device: bool = False, package_name: str = "",
             splits=True, backend: str = "", maxApkBytes: int = 0,
             force: bool = False, **_kw) -> dict:
    t0 = time.time()
    _size_gate(path, maxApkBytes, force)
    bke = backends.backend(backend)
    pull_info = None
    if from_device:
        pkg = package_name or _pkg_from_path(path)
        remote = apkio.adb_device_apks(pkg)
        meta_dev = apkio.adb_package_meta(pkg)
        dest = os.path.join(settings().staging_dir(),
                            "%s-%s" % (pkg, time.strftime("%Y%m%d%H%M%S")))
        local = apkio.adb_pull(remote, dest)
        base, sp = local[:1], local[1:]
        pull_info = {"package": pkg, "remotePaths": remote, "staging": dest,
                     "dumpsys": meta_dev}
    else:
        primary = resolve_input_path(path)
        if os.path.isdir(primary) and not os.path.isfile(os.path.join(primary,
                                                                      "AndroidManifest.xml")):
            base, sp = apkio.expand_apk_paths(primary, want_splits=bool(splits))
        elif not primary.endswith((".apk", ".apks")) and os.path.isdir(primary):
            base, sp = apkio.expand_apk_paths(primary, want_splits=bool(splits))
        else:
            base, sp = apkio.expand_apk_paths(primary, want_splits=bool(splits))
    all_paths = base + sp
    if not all_paths:
        raise ApkIndexError(ErrorCode.INVALID_PATH, f"找不到 APK: {path}")
    per_file = [(os.path.basename(p), apkio.sha256_file(p)) for p in all_paths]
    fp = combined_sha(per_file)

    hit = None if force else catalog().find_by_sha(fp)
    if hit:
        row = catalog().find_by_id(hit)
        if row and _index_usable(row):
            summary = _read_summary(row["dbPath"])
            return _result(row, summary, already_loaded=True,
                           elapsed_ms=(time.time() - t0) * 1000.0)
        if row and force:
            # 重建前把旧会话（连同可能几百 MB 的过期索引文件）清掉，不然缓存只涨不消
            try:
                unload(row["session_id"], keep_files=False)
            except Exception:
                pass

    manifest = apkio.read_manifest_dict(all_paths)
    services, versions, natives, _mf, flags = apkio.zip_infos(all_paths)
    dex_entries = apkio.bundle_dexes(all_paths)
    if not dex_entries:
        raise ApkIndexError(ErrorCode.UNSUPPORTED_FORMAT,
                            "APK 内没有 classes*.dex",
                            "确认是真实安装包；若是运行期解密注入的壳包，请脱壳后用 loadDex。")
    sid = session_id_for(fp)
    w = IndexWriter(sid, backend=bke.name)
    seen_dex: dict[str, str] = {}
    dex_summaries = []
    idx = int(w.conn.execute("SELECT COALESCE(MAX(idx),-1)+1 FROM dex").fetchone()[0])
    total_dex_bytes = 0
    entropy_strings: list[str] = []
    for de in dex_entries:
        data = apkio.read_dex_entry(de)
        ds = apkio.sha256_bytes(data)
        if ds in seen_dex:
            dex_summaries.append({"dex": de.label, "sizeBytes": len(data),
                                  "skipped": "duplicate-of:" + seen_dex[ds],
                                  "counts": {}, "added": {}})
            idx += 1
            continue
        seen_dex[ds] = de.label
        dd = bke.parse(data, os.path.basename(de.member))
        total_dex_bytes += len(data)
        added = w.add_dex(idx, dd, source="app", origin=de.origin)
        if len(entropy_strings) < 40000:
            entropy_strings.extend(dd.strings[:8000])
        dex_summaries.append({"dex": de.label, "dexIdx": idx, "version": dd.version,
                              "sizeBytes": len(data), "sha256": ds[:16],
                              "counts": dd.counts, "added": added,
                              "notes": list(dd.parse_notes[:4])})
        idx += 1
    counts = _counts_from_conn(w.conn)
    descs = packer_mod.scan_classes(
        [d for (d,) in w.conn.execute("SELECT descriptor FROM classes")])
    pack = packer_mod.detect(
        native_libs=natives, class_descs=[d["detail"] for d in descs],
        asset_names=_asset_names(all_paths),
        total_classes=counts["classes"], dex_bytes=total_dex_bytes,
        strings=entropy_strings, application_class=manifest.get("application"))
    compose = bool(w.conn.execute(
        "SELECT 1 FROM classes WHERE descriptor LIKE 'Landroidx/compose/runtime/%'"
        " LIMIT 1").fetchone())
    kotlin_meta = bool(flags.get("kotlin_metadata")) or bool(w.conn.execute(
        "SELECT 1 FROM classes WHERE descriptor='Lkotlin/Metadata;' LIMIT 1").fetchone())
    index_ms = (time.time() - t0) * 1000.0
    pkg = (pull_info or {}).get("dumpsys", {}).get("pkg") or manifest.get("package") \
        or package_name or ""
    vcode = manifest.get("versionCode")
    if pull_info and pull_info["dumpsys"].get("versionCode") is not None:
        vcode = pull_info["dumpsys"]["versionCode"]
    vname = manifest.get("versionName") or (pull_info or {}).get(
        "dumpsys", {}).get("versionName")
    summary = {
        "kind": "apk", "sessionId": sid, "sha256": fp, "pkg": pkg,
        "versionName": vname, "versionCode": vcode,
        "manifest": {k: manifest.get(k) for k in
                     ("package", "versionName", "versionCode", "minSdk", "targetSdk",
                      "application", "usesPermissions", "metaData")},
        "components": {k: (manifest.get(k) or [])[:60] for k in
                       ("activities", "services", "receivers", "providers")},
        "counts": counts, "packed": pack, "backend": bke.name,
        "schemaVersion": SCHEMA_VERSION, "indexMs": round(index_ms, 1),
        "dexes": dex_summaries, "splits": [os.path.basename(p) for p in sp],
        "baseApks": [os.path.basename(p) for p in base],
        "files": [{"name": n, "sha256": d} for n, d in per_file],
        "paths": all_paths, "nativeLibs": natives[:80],
        "services": sorted(services)[:40], "versions": sorted(versions)[:40],
        "deps": {"kotlinMetadata": kotlin_meta, "compose": compose,
                 "coroutines": bool(flags.get("coroutines")),
                 "kotlinModules": flags.get("kotlin_modules", [])[:8],
                 "signingBlocks": flags.get("signing_blocks", []),
                 "resourceTable": bool(flags.get("resource_table"))},
        "device": pull_info, "createdAt": iso(),
        "classesTotal": counts["classes"],
    }
    w.set_meta({"summary": summary, "packed": pack, "counts": counts,
                "schemaVersion": SCHEMA_VERSION, "sha256": fp, "pkg": pkg,
                "indexMs": round(index_ms, 1)})
    w.vacuum_light()
    db_path = w.db_path
    w.close()
    _register(sid, summary, db_path, "apk", bke.name, index_ms, all_paths,
              pack["packed"])
    row = catalog().find_by_id(sid)
    return _result(row, summary, already_loaded=False, elapsed_ms=index_ms)


def _counts_from_conn(conn) -> dict:
    out = {}
    for key, table in [("dex", "dex"), ("classes", "classes"), ("methods", "methods"),
                       ("fields", "fields"), ("strings", "strings"),
                       ("stringRefs", "string_refs"), ("xrefEdges", "xref_edges"),
                       ("refs", "refs"), ("annotations", "annotations")]:
        out[key] = int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
    return out


def _asset_names(paths) -> list[str]:
    out: list[str] = []
    for ap in paths:
        try:
            with zipfile.ZipFile(ap) as zf:
                out += [n for n in zf.namelist()
                        if n.startswith("assets/") or n.startswith("res/raw/")]
        except Exception:
            continue
        if len(out) > 4000:
            break
    return out[:4000]


def _pkg_from_path(path: str) -> str:
    for p in reversed([x for x in path.replace("\\", "/").split("/") if x]):
        m = re.match(r"^([A-Za-z][\w]*(?:\.[\w]+)+)", p)
        if m:
            return m.group(1)
    raise ApkIndexError(ErrorCode.BAD_ARGUMENT,
                        "fromDevice=true 且无法从 path 推导包名，请显式给 packageName")


# ------------------------------------------------------------------- loadAar
def load_aar(path: str, merge_into: str = "", backend: str = "", maxApkBytes: int = 0, force: bool = False, **_kw) -> dict:
    t0 = time.time()
    bke = backends.backend(backend)
    p = resolve_input_path(path)
    if not zipfile.is_zipfile(p):
        raise ApkIndexError(ErrorCode.UNSUPPORTED_FORMAT, f"{p} 不是 zip 容器（aar/jar）")
    sha = apkio.sha256_file(p)
    keep_meta: dict = {"keepRules": [], "hardcodable": []}
    with zipfile.ZipFile(p) as zf:
        names = zf.namelist()
        manifest_txt = zf.read("AndroidManifest.xml") if "AndroidManifest.xml" in names \
            else b""
        consumer = b""
        for cand in ("consumer-rules.pro", "proguard.txt", "proguard-rules.pro"):
            if cand in names:
                consumer = zf.read(cand)
                keep_meta["consumerFile"] = cand
                break
        r_txt = zf.read("R.txt").decode("utf-8", "replace") if "R.txt" in names else ""
        jars = [(n, zf.read(n)) for n in names
                if n == "classes.jar" or (n.startswith("libs/") and n.endswith(".jar"))]
        natives = [{"abi": n.split("/")[1], "name": n.split("/")[-1],
                    "size": zf.getinfo(n).file_size, "origin": os.path.basename(p)}
                   for n in names if n.startswith("jni/") and n.endswith(".so")]
        extras = {"prefab": sum(1 for n in names if n.startswith("prefab/")),
                  "headers": sum(1 for n in names if n.startswith(("headers/", "include/"))),
                  "res": sum(1 for n in names if n.startswith("res/")),
                  "assets": sum(1 for n in names if n.startswith("assets/")),
                  "other": [n for n in names if n.endswith((".png", ".xml"))][:0]}
        dexes_in_jars = []
        for n, blob in jars:
            try:
                with zipfile.ZipFile(io.BytesIO(blob)) as jf:
                    for jn in jf.namelist():
                        if DEX_NAME_RE.match(jn):
                            dexes_in_jars.append((f"{n}::{jn}", jf.read(jn)))
            except Exception:
                continue

    manifest = {}
    if manifest_txt:
        manifest = apkio._manifest_from_text(manifest_txt) \
            if manifest_txt[:1] == b"<" else _safe_axml(manifest_txt)
    keep_rules = parse_keep_rules(consumer.decode("utf-8", "replace")) if consumer else []

    if merge_into:
        row = catalog().find_by_id(merge_into) or _resolve_by_label(merge_into)
        sid = row["session_id"]
        w = IndexWriter(sid, backend=bke.name)
    else:
        row = None
        sid = session_id_for(sha)
        w = IndexWriter(sid, backend=bke.name)
    idx = int(w.conn.execute("SELECT COALESCE(MAX(idx),-1)+1 FROM dex").fetchone()[0])
    dex_summaries = []
    for label, blob in dexes_in_jars:
        dd = bke.parse(blob, os.path.basename(label))
        added = w.add_dex(idx, dd, source="library", origin=os.path.basename(p))
        dex_summaries.append({"dex": f"{os.path.basename(p)}::{label}", "dexIdx": idx,
                              "version": dd.version, "sizeBytes": len(blob),
                              "counts": dd.counts, "added": added, "origin": "dex"})
        idx += 1
    for n, blob in jars:
        entries = _jar_entries(blob)
        if not entries:
            continue
        dd = classes_to_dexfile(entries, os.path.basename(n))
        added = w.add_dex(idx, dd, source="library", origin=os.path.basename(p))
        dex_summaries.append({"dex": f"{os.path.basename(p)}::{n}", "dexIdx": idx,
                              "version": "class", "sizeBytes": len(blob),
                              "counts": dd.counts, "added": added,
                              "origin": "classes.jar", "classFiles": len(entries)})
        idx += 1
    counts = _counts_from_conn(w.conn)
    own = [x["dexIdx"] for x in dex_summaries]
    declared = sorted({d[1:-1].rsplit("/", 1)[0].replace("/", ".")
                       for d in _aar_own_descriptors(w.conn, own)
                       if d.startswith("L")})
    hard = hardcodable_keep(keep_rules, set(declared))
    index_ms = (time.time() - t0) * 1000.0
    pkg = manifest.get("package") or (os.path.basename(p).rsplit(".", 1)[0])
    summary = {
        "kind": "aar", "sessionId": sid, "sha256": sha, "pkg": pkg,
        "versionName": manifest.get("versionName"), "versionCode": manifest.get("versionCode"),
        "manifest": {"package": pkg, "application": manifest.get("application"),
                     "minSdk": manifest.get("minSdk"), "targetSdk": manifest.get("targetSdk")},
        "components": {}, "counts": counts,
        "packed": {"packed": False, "evidence": [], "vendors": [],
                   "confidence": "none", "recommendation": "库产物，无壳检测需求。"},
        "backend": bke.name, "schemaVersion": SCHEMA_VERSION,
        "indexMs": round(index_ms, 1), "dexes": dex_summaries,
        "splits": [], "files": [{"name": os.path.basename(p), "sha256": sha}],
        "paths": [p], "nativeLibs": natives,
        "declaredPackages": declared[:40],
        "keepRules": keep_rules[:60], "hardcodable": hard[:60],
        "rTxt": {"entries": len(r_txt.splitlines()) if r_txt else 0,
                 "sample": r_txt.splitlines()[:5] if r_txt else []},
        "extras": extras, "createdAt": iso(),
        "classesTotal": counts["classes"], "mergedInto": merge_into or None,
    }
    prev = w.meta("summary", {}) or {}
    if merge_into and prev:
        prev.setdefault("aarMerges", []).append(
            {"path": p, "sha256": sha, "declaredPackages": declared[:20],
             "keepRules": keep_rules[:20], "dexes": [d["dex"] for d in dex_summaries]})
        summary["aarMerges"] = prev.get("aarMerges", [])
        summary["pkg"] = prev.get("pkg") or pkg
        summary["counts"] = counts
    w.set_meta({"summary": summary, "schemaVersion": SCHEMA_VERSION,
                "sha256": summary.get("sha256"), "counts": counts})
    db_path = w.db_path
    w.vacuum_light()
    w.close()
    if not merge_into:
        _register(sid, summary, db_path, "aar", bke.name, index_ms, [p], False)
    else:
        row = catalog().find_by_id(sid)
        catalog().upsert(session_id=sid, sha256=row["sha256"], kind=row["kind"],
                         label=row["label"], pkg=row["pkg"],
                         version_name=row["version_name"],
                         version_code=row["version_code"], db_path=db_path,
                         index_ms=round((row.get("index_ms") or 0) + index_ms, 1),
                         backend=row["backend"], packed=row["packed"],
                         sources_json=json.dumps(
                             json.loads(row["sources_json"] or "[]") + [p]),
                         meta_json=json.dumps({"counts": counts}, ensure_ascii=False))
    row = catalog().find_by_id(sid)
    out = _result(row, summary, already_loaded=False, elapsed_ms=index_ms)
    out.update({
        "kind": "aar",
        "declaredPackages": declared[:40],
        "keepRules": keep_rules[:60],
        "hardcodable": hard[:60],
        "nativeLibs": natives,
        "classesTotal": counts["classes"],
        "mergedInto": merge_into or None,
        "hint": ("库代码已并入目标 Session，source=library。查询时用 scope=app 排除库代码，"
                 "scope=all 才能同时看到两边。" if merge_into else
                 "库产物已单独建会话；写模块时用 loadAar(mergeInto=<sessionId>) 并入目标 App 会话。"),
    })
    return out


def _safe_axml(blob: bytes) -> dict:
    from . import axml
    try:
        return axml.manifest_of(blob)
    except Exception as e:
        raise ApkIndexError(ErrorCode.PARSE_FAILED, f"AndroidManifest.xml 解析失败: {e}")


def _aar_own_descriptors(conn, dex_idxs: list[int]) -> list[str]:
    if not dex_idxs:
        return []
    q = ",".join("?" * len(dex_idxs))
    return [d for (d,) in conn.execute(
        f"SELECT descriptor FROM classes WHERE dex_idx IN ({q})", tuple(dex_idxs))]


def parse_keep_rules(text: str) -> list[dict]:
    """Pull -keep* directives out of consumer-rules.pro / proguard.txt."""
    out: list[dict] = []
    lines = [l.strip() for l in (text or "").splitlines()]
    i = 0
    while i < len(lines):
        l = lines[i]
        if not l or l.startswith("#"):
            i += 1
            continue
        m = PROGUARD_KEEP_RE.match(l)
        if not m:
            i += 1
            continue
        directive = l.split()[0]
        body = l[len(directive):].strip()
        # rules can span lines until the closing brace
        depth = body.count("{") - body.count("}")
        j = i
        while depth > 0 and j + 1 < len(lines):
            j += 1
            body += " " + lines[j]
            depth = body.count("{") - body.count("}")
        out.append({"directive": directive, "raw": " ".join(body.split())[:220],
                    "members": "{}" in body or "*;" in body})
        i = j + 1
    return out


def hardcodable_keep(rules: list[dict], known: set) -> list[dict]:
    """Which kept symbols are literal class names present in the index.

    A class named verbatim in a -keep rule survives R8, so hook code may hardcode
    it; wildcard rules are reported as not hardcodable.
    """
    out = []
    for r in rules:
        body = r["raw"]
        for tok in re.findall(r"[A-Za-z_][\w.]*(?:\.[A-Za-z_][\w]*)+", body):
            if "*" in tok or "$" in tok or tok in ("<clinit>",):
                continue
            dotted = tok
            if known and dotted.replace(".", "/") in {k[1:-1] for k in known
                                                      if k.startswith("L")}:
                out.append({"class": dotted, "directive": r["directive"],
                            "hardcodable": True, "via": "consumer-rule"})
    dedup = []
    seen = set()
    for x in out:
        if x["class"] not in seen:
            seen.add(x["class"])
            dedup.append(x)
    return dedup


# ------------------------------------------------------------------- loadDex
def load_dex(path: str, session_id: str = "", format: str = "auto",
             source: str = "app", backend: str = "", maxApkBytes: int = 0, force: bool = False, **_kw) -> dict:
    t0 = time.time()
    _size_gate(path, maxApkBytes, force)
    bke = backends.backend(backend)
    p = resolve_input_path(path)
    fmt = (format or "auto").lower()
    if fmt == "auto":
        fmt = apkio.sniff(p)
    allowed = {"dex", "jar", "aar", "odex", "vdex", "apk"}
    if fmt not in allowed:
        raise ApkIndexError(
            ErrorCode.UNSUPPORTED_FORMAT,
            f"不支持的格式: {fmt} ({os.path.basename(p)})",
            "支持 dex/jar/aar/odex/vdex；odex/vdex 需内嵌完整 dex，"
            "compact-dex(cdx) 请先用外部工具预提取。")
    blob = open(p, "rb").read()
    payloads: list[tuple[str, bytes]] = []
    notes = []
    if fmt == "dex":
        payloads = [(os.path.basename(p), blob)]
    elif fmt in ("jar", "aar", "apk"):
        with zipfile.ZipFile(p) as zf:
            for n in zf.namelist():
                if DEX_NAME_RE.match(n):
                    payloads.append((n, zf.read(n)))
            if not payloads and fmt != "apk":
                for n in zf.namelist():
                    if n.endswith(".jar"):
                        inner = _jar_entries(zf.read(n))
                        if inner:
                            payloads.append((n + "(class)",
                                             classes_to_dexfile(inner,
                                                                os.path.basename(n))))
                            notes.append("%s 走 class 常量池解析（无 d8 时不生成临时 dex）"
                                         % n)
        if fmt == "aar":
            return load_aar(path, merge_into=session_id, backend=backend)
    elif fmt in ("odex", "vdex"):
        carved = apkio.carve_dexes(blob)
        if not carved:
            ver = apkio.vdex_version(blob) if fmt == "vdex" else "?"
            raise ApkIndexError(
                ErrorCode.UNSUPPORTED_FORMAT,
                f"{fmt.upper()}（version={ver}）内找不到完整 dex；ART 的 compact dex "
                f"(cdx) 增量无法离线还原",
                "用 vdexExtractor / unrar 预提取内嵌 classes.dex 后再 loadDex；"
                "或在设备上用 `cmd package compile -m verify -f <pkg>` 后再取。")
        payloads = [(f"{os.path.basename(p)}::carved{i}.dex", c)
                    for i, c in enumerate(carved)]
        notes.append(f"carved {len(carved)} 个完整 dex；"
                     "若原文件含 cdx 增量，索引可能不完整")
    if not payloads:
        raise ApkIndexError(ErrorCode.UNSUPPORTED_FORMAT, "没有可索引的 dex 内容")

    if session_id:
        row = catalog().find_by_id(session_id) or _resolve_by_label(session_id)
        sid = row["session_id"]
        w = IndexWriter(sid, backend=bke.name)
        incremental = True
    else:
        first = payloads[0][1] if isinstance(payloads[0][1], bytes) else None
        base_sha = apkio.sha256_bytes(first) if first else apkio.sha256_file(p)
        sid = session_id_for(base_sha)
        w = IndexWriter(sid, backend=bke.name)
        incremental = False
    idx = int(w.conn.execute("SELECT COALESCE(MAX(idx),-1)+1 FROM dex").fetchone()[0])
    added = []
    for name, data in payloads:
        if isinstance(data, DexFileData):
            dd = data
        else:
            dd = bke.parse(data, os.path.basename(name))
        res = w.add_dex(idx, dd, source=source or "app", origin=p)
        added.append({"dexName": name, "dexIdx": idx, "classes": len(dd.classes),
                      "methods": sum(len(c.methods) for c in dd.classes),
                      "fields": sum(len(c.fields) for c in dd.classes),
                      "strings": len(dd.strings), "counts": dd.counts,
                      "added": res, "notes": list(dd.parse_notes[:4])})
        idx += 1
    counts = _counts_from_conn(w.conn)
    summary = w.meta("summary", {}) or {}
    summary.update({
        "kind": summary.get("kind") or "dex", "sessionId": sid,
        "sha256": summary.get("sha256") or apkio.sha256_file(p),
        "pkg": summary.get("pkg") or "", "counts": counts,
        "schemaVersion": SCHEMA_VERSION, "backend": bke.name,
        "dexes": (summary.get("dexes") or []) + added,
        "paths": sorted(set((summary.get("paths") or []) + [p])),
        "createdAt": summary.get("createdAt") or iso(),
        "loadDexNotes": (summary.get("loadDexNotes") or []) + notes,
        "indexMs": round((summary.get("indexMs") or 0) + (time.time() - t0) * 1000.0, 1),
    })
    w.set_meta({"summary": summary, "counts": counts,
                "schemaVersion": SCHEMA_VERSION})
    db_path = w.db_path
    w.vacuum_light()
    w.close()
    if not incremental:
        summary.setdefault("versionName", None)
        summary.setdefault("versionCode", None)
        _register(sid, summary, db_path, "dex", bke.name,
                  (time.time() - t0) * 1000.0, [p], False)
    else:
        row = catalog().find_by_id(sid)
        catalog().upsert(session_id=sid, sha256=row["sha256"], kind=row["kind"],
                         label=row["label"], pkg=row["pkg"],
                         version_name=row["version_name"],
                         version_code=row["version_code"], db_path=db_path,
                         index_ms=summary["indexMs"], backend=row["backend"],
                         packed=row["packed"], sources_json=row["sources_json"],
                         meta_json=json.dumps({"counts": counts}, ensure_ascii=False))
    a0 = added[0]
    return {
        "ok": True, "sessionId": sid, "incremental": incremental,
        "dexName": a0["dexName"], "classes": a0["classes"],
        "methods": a0["methods"], "fields": a0["fields"], "strings": a0["strings"],
        "fingerprint": {"sha256": summary["sha256"], "pkg": summary.get("pkg"),
                        "versionName": summary.get("versionName"),
                        "versionCode": summary.get("versionCode"),
                        "dexCount": counts["dex"], "totalClasses": counts["classes"]},
        "total": counts["classes"], "items": added[:12],
        "truncated": len(added) > 12,
        "hint": (f"已{'追加' if incremental else '新建'}索引 {len(added)} 个 dex；"
                 f"session={sid}。counts 是本次新增量，session 总量看 stats。") +
                (("；" + "；".join(notes)) if notes else ""),
        "index": {"path": db_path, "counts": counts, "backend": bke.name,
                  "sizeBytes": os.path.getsize(db_path)},
    }


def _resolve_by_label(label: str) -> dict:
    rows = [r for r in catalog().list()
            if r["sessionId"] == label or (r.get("pkg") or "") == label
            or (r.get("sha256") or "").startswith(label)]
    if len(rows) == 1:
        return catalog().find_by_id(rows[0]["sessionId"])
    if not rows:
        raise ApkIndexError(ErrorCode.SESSION_NOT_FOUND, f"没有这个会话: {label}",
                            "sessionList 看现有会话。")
    raise ApkIndexError(ErrorCode.BAD_ARGUMENT,
                        f"sessionId 有歧义: {label}",
                        "用完整 sessionId: " + ", ".join(r["sessionId"] for r in rows))


# ------------------------------------------------------- list/unload/stats
def session_list(**_kw) -> dict:
    rows = catalog().list()
    items = []
    for r in rows:
        db_ok = bool(r["dbPath"]) and os.path.exists(r["dbPath"])
        items.append({"sessionId": r["sessionId"], "kind": r["kind"],
                      "label": r["label"], "pkg": r["pkg"],
                      "versionName": r["versionName"], "versionCode": r["versionCode"],
                      "sha256": (r["sha256"] or "")[:16], "dbPath": r["dbPath"],
                      "indexAvailable": db_ok, "indexMs": r["indexMs"],
                      "backend": r["backend"], "packed": r["packed"],
                      "sources": r["sources"], "createdAt": r["createdAt"]})
    return {"ok": True, "sessionId": None, "total": len(items), "items": items,
            "truncated": False,
            "hint": f"cache={settings().cache_dir}；用 stats(sessionId) 看细节。"}


def unload(session_id: str, keep_files: bool = False, **_kw) -> dict:
    row = catalog().find_by_id(session_id) or _resolve_by_label(session_id)
    sid = row["session_id"]
    db_path = row["dbPath"]
    removed = []
    if not keep_files and db_path:
        real = os.path.realpath(db_path)
        base = os.path.realpath(settings().index_dir())
        if not real.startswith(base + os.sep):
            raise ApkIndexError(ErrorCode.INVALID_PATH,
                                f"索引路径越界，拒绝删除: {real}")
        for suffix in ("", "-wal", "-shm"):
            f = real + suffix
            if os.path.exists(f):
                os.remove(f)
                removed.append(f)
    catalog().delete(sid)
    return {"ok": True, "sessionId": sid, "total": len(removed),
            "items": [{"deleted": f} for f in removed],
            "truncated": False,
            "hint": "会话与索引已删除（源文件从未被修改）。重新 loadApk 会重建索引。"}


def stats(session_id: str = "", **_kw) -> dict:
    if not session_id:
        rows = catalog().list()
        items = []
        for r in rows:
            try:
                c = _counts_of(r["dbPath"])
            except Exception:
                c = {}
            items.append({"sessionId": r["sessionId"], "kind": r["kind"],
                          "pkg": r["pkg"], "counts": c,
                          "indexMs": r["indexMs"], "backend": r["backend"],
                          "packed": r["packed"],
                          "sizeBytes": os.path.getsize(r["dbPath"])
                          if os.path.exists(r["dbPath"]) else 0})
        return {"ok": True, "sessionId": None, "total": len(items), "items": items,
                "truncated": False, "hint": "stats 需要 sessionId 才有细节。"}
    row = catalog().find_by_id(session_id) or _resolve_by_label(session_id)
    sid = row["session_id"]
    summary = _read_summary(row["dbPath"])
    counts = _counts_of(row["dbPath"])
    dexes = [{"dexIdx": d[0], "name": d[1], "origin": d[2], "size": d[3],
              "version": d[4], "source": d[5], "counts": json.loads(d[6] or "{}")}
             for d in connect(row["dbPath"], readonly=True).execute(
                 "SELECT idx,name,origin,size,version,source,counts_json FROM dex "
                 "ORDER BY idx")]
    src_break = {r[0]: r[1] for r in connect(row["dbPath"], readonly=True).execute(
        "SELECT source, COUNT(*) FROM classes GROUP BY source")}
    pack = summary.get("packed") or {}
    return {
        "ok": True, "sessionId": sid, "total": counts["classes"],
        "items": dexes[:24], "truncated": len(dexes) > 24,
        "fingerprint": {"sha256": summary.get("sha256"), "pkg": summary.get("pkg"),
                        "versionName": summary.get("versionName"),
                        "versionCode": summary.get("versionCode"),
                        "dexCount": counts["dex"], "totalClasses": counts["classes"]},
        "counts": counts, "classSourceBreakdown": src_break,
        "index": {"path": row["dbPath"],
                  "sizeBytes": os.path.getsize(row["dbPath"]),
                  "indexMs": summary.get("indexMs"),
                  "backend": row["backend"],
                  "schemaVersion": summary.get("schemaVersion"),
                  "cacheDir": settings().cache_dir},
        "packed": bool(pack.get("packed")), "packerEvidence": pack.get("evidence", [])[:8],
        "deps": summary.get("deps"), "splits": summary.get("splits"),
        "paths": summary.get("paths"), "createdAt": summary.get("createdAt"),
        "hint": "索引耗时 %sms；同 sha256 再 loadApk 走幂等命中。" % summary.get("indexMs"),
    }


def check_packer(session_id: str, **_kw) -> dict:
    row = catalog().find_by_id(session_id) or _resolve_by_label(session_id)
    sid = row["session_id"]
    summary = _read_summary(row["dbPath"])
    pack = summary.get("packed") or {}
    conn = connect(row["dbPath"], readonly=True)
    stub_hits = packer_mod.scan_classes(
        [d for (d,) in conn.execute("SELECT descriptor FROM classes")])
    conn.close()
    merged = {"packed": bool(pack.get("packed")) or bool(stub_hits),
              "evidence": (pack.get("evidence") or []) + [
                  e for e in stub_hits if e["detail"] not in
                  {x.get("detail") for x in (pack.get("evidence") or [])}][:12],
              "vendors": sorted(set((pack.get("vendors") or []) +
                                    [e["vendor"] for e in stub_hits])),
              "confidence": pack.get("confidence"),
              "stringEntropy": pack.get("stringEntropy"),
              "recommendation": pack.get("recommendation")}
    if merged["packed"] and not pack:
        merged["recommendation"] = packer_mod._recommendation(
            True, merged["vendors"], merged["evidence"])
    out = {"ok": True, "sessionId": sid, "total": len(merged["evidence"]),
           "items": merged["evidence"], "truncated": False,
           "packed": merged["packed"], "vendors": merged["vendors"],
           "confidence": merged["confidence"], "recommendation": merged["recommendation"],
           "hint": ("PACKED_TARGET：静态 hook 点只能在壳类里找，业务类需脱壳。"
                    if merged["packed"] else "非加固，可直接静态索引。")}
    if merged["packed"]:
        out["code"] = ErrorCode.PACKED_TARGET
    return out
