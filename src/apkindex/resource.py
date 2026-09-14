"""Resource / manifest / cache-doctor layer for apk-index.

New tools:
* listManifest       -- full manifest/component/permission summary from the APK
* findComponent      -- fuzzy component lookup across the four component kinds
* searchResources    -- enumerate resources.arsc entries (best-effort parser)
* resourceRefs       -- DEX string / const-class refs that mention a resource
* resourceSecurity   -- security surface: exported components, permissions, native libs
* doctor             -- read-only cache health check

All access is read-only.  resources.arsc parsing is intentionally capped and
best-effort; it reports ``available=false`` plus notes instead of pretending.
"""
from __future__ import annotations

import os
import re
import struct
import time
import zipfile
from collections import defaultdict

from . import envelope as env, signature as sg
from .config import (ApkIndexError, DEFAULT_LIMIT, ErrorCode, settings)
from .index import SessionDB, catalog, connect, meta_get
from .queries import _like

# method columns reused by resource_refs.  The ``value`` alias is the DEX
# string literal; for const-class rows it is NULL.
_RES_METHOD_COLS = (
    "c.descriptor AS descriptor, c.simple_name AS simple_name, c.package AS package,"
    " m.id AS method_id, m.name AS name, m.params_descriptor AS params_descriptor,"
    " m.return_descriptor AS return_descriptor, m.access_flags AS access_flags,"
    " m.is_static AS is_static, m.is_constructor AS is_constructor, "
    "coalesce(st.value, r.owner) AS value, st.len AS string_len"
)


_COMP_TYPE = {"activities": "activity", "services": "service",
              "receivers": "receiver", "providers": "provider"}

_TRUEISH = (True, "true", 1)
_FALSEISH = (False, "false", 0)


def _exported_match(val, want) -> bool:
    """Strict filter: exported=True keeps only explicitly true components.

    ``None`` means the manifest never said — Android's default rules decide,
    and that is NOT the same as an explicit ``android:exported="false"``.
    Silently folding None into False would turn "no explicit false" into a
    security-cleared list, which is exactly the kind of false negative an
    auditor should never get.
    """
    if want is None:
        return True
    if want is True:
        return val in _TRUEISH
    return val in _FALSEISH


def _method_item_brief(row: dict) -> dict:
    out = dict(row)
    out.setdefault("class", sg.binary_name(row.get("descriptor") or ""))
    out.setdefault("smali", sg.smali_method(
        row.get("descriptor"), row.get("name"),
        row.get("params_descriptor"), row.get("return_descriptor")))
    out.setdefault("reflector", sg.reflector_method(
        sg.internal_name(row.get("descriptor") or ""), row.get("name"),
        row.get("params_descriptor"), row.get("return_descriptor")))
    out.setdefault("java", sg.java_method(
        row.get("descriptor"), row.get("name"), row.get("params_descriptor"),
        row.get("return_descriptor")))
    out.setdefault("kind", "string-const")
    return out


# ------------------------------------------------------------------ session helper
class _ResourceSession(SessionDB):
    """Read-side session with manifest/resource data attached."""

    def __init__(self, session_id: str, row: dict):
        super().__init__(session_id, row)
        self.manifest: dict = {}
        self.components: dict = {}
        self.resource_table: dict = {}
        self.native_libs: list = []
        summary = meta_get(self.conn, "summary", {}) or {}
        self.manifest = summary.get("manifest") or {}
        self.components = summary.get("components") or {}
        self.native_libs = summary.get("nativeLibs") or []
        paths = summary.get("paths") or []
        # resource table: pick the first apk path containing resources.arsc
        for p in paths:
            if p and os.path.exists(p) and p.endswith(".apk"):
                try:
                    with zipfile.ZipFile(p) as zf:
                        if "resources.arsc" in zf.namelist():
                            self.resource_table = read_arsc(zf.read("resources.arsc"),
                                                            limit=512)
                            break
                except Exception:
                    continue
        self._res_cache: dict[str, list] = {}

    def query_resource_strings(self, needle: str, limit: int) -> list[dict]:
        if needle in self._res_cache:
            return self._res_cache[needle][:limit]
        esc = _like(needle)
        sql = f"""SELECT {_RES_METHOD_COLS}
                  FROM string_refs sr
                  JOIN methods m ON m.id = sr.method_id
                  JOIN classes c ON c.id = m.class_id
                  JOIN strings st ON st.id = sr.string_id
                  LEFT JOIN refs r ON r.id = -1
                  WHERE st.value LIKE ? ESCAPE '\\'
                  LIMIT ?"""
        out = self.q(sql, (f"%{esc}%", limit))
        items = [_method_item_brief(r) for r in out]
        for it in items:
            it["string"] = it.get("value")
            it["kind"] = "string-const"
        self._res_cache[needle] = items
        return items[:limit]

    def query_resource_classes(self, resource_type: str, limit: int) -> list[dict]:
        if not resource_type:
            return []
        key = f"cls:{resource_type}"
        if key in self._res_cache:
            return self._res_cache[key][:limit]
        # const-class refs whose target is an R / BuildConfig class for this type.
        # owner is stored in refs.owner; for kind=9 (const-class) owner == type descriptor.
        patterns = ["L%R$" + resource_type + ";",
                    "L%R$" + resource_type + ";",
                    "L%R;" + resource_type,
                    "L%BuildConfig;"]
        patterns = list(dict.fromkeys(patterns))
        out: list[dict] = []
        for pat in patterns:
            esc = _like(pat)
            sql = f"""SELECT {_RES_METHOD_COLS}
                      FROM xref_edges e
                      JOIN methods m ON m.id = e.caller_method_id
                      JOIN classes c ON c.id = m.class_id
                      JOIN refs r ON r.id = e.callee_ref
                      LEFT JOIN strings st ON st.id = -1
                      WHERE r.kind = 9 AND r.owner LIKE ? ESCAPE '\\'
                      LIMIT ?"""
            rows = self.q(sql, (esc, limit))
            for r in rows:
                item = _method_item_brief(r)
                item["class"] = r.get("value")
                item["kind"] = "class-const"
                out.append(item)
            if len(out) >= limit:
                break
        self._res_cache[key] = out
        return out[:limit]


def _open_session_for_resources(session_id: str) -> _ResourceSession:
    row = catalog().find_by_id(session_id)
    if row is None:
        raise ApkIndexError(ErrorCode.SESSION_NOT_FOUND,
                            f"会话不存在: {session_id}",
                            "先 sessionList 看现有会话。")
    return _ResourceSession(row["session_id"], row)


# ------------------------------------------------------------------ resources.arsc
_RES_STRING_POOL = 0x0001
_RES_TABLE = 0x0002
_RES_PACKAGE = 0x0200
_RES_TYPE_SPEC = 0x0201
_RES_TYPE = 0x0202
_RES_PKG_OFFSETS = 0x0218
_UTF8_FLAG = 1 << 8
_SPARSE_FLAG = 1 << 0
_NO_ENTRY = 0xFFFFFFFF
_MAX_SAMPLE = 512


def _uleb128(buf: bytes, off: int) -> tuple[int, int]:
    v = shift = 0
    while True:
        b = buf[off]
        off += 1
        v |= (b & 0x7F) << shift
        if not b & 0x80:
            return v, off
        shift += 7
        if shift > 35:
            raise ValueError("uleb128 超长")


def _read_string_pool(data: bytes, off: int) -> tuple[int, list[str]]:
    """Parse a ResStringPool chunk.  Returns (next_offset, strings)."""
    n = len(data)
    if off + 28 > n:
        raise ValueError("字符串池越界")
    ctype, hdr, size = struct.unpack_from("<HHI", data, off)
    if ctype != _RES_STRING_POOL or size < hdr or off + size > n:
        raise ValueError("不是合法的 ResStringPool (type=0x%04x)" % ctype)
    str_count, style_count, flags, str_start, _style_start = struct.unpack_from(
        "<IIIII", data, off + 8)
    base = off + hdr
    offs = struct.unpack_from("<%dI" % str_count, data, base) if str_count else ()
    dp = off + str_start
    utf8 = bool(flags & _UTF8_FLAG)
    out: list[str] = []
    for o in offs:
        pos = dp + o
        if pos + 1 > n:
            out.append("")
            continue
        if utf8:
            try:
                _nch, pos = _uleb128(data, pos)       # char count (not needed)
                nby, pos = _uleb128(data, pos)        # byte count (authoritative)
            except (IndexError, ValueError):
                out.append("")
                continue
            out.append(data[pos:pos + nby].decode("utf-8", "replace"))
        else:
            ln = struct.unpack_from("<H", data, pos)[0]
            pos += 2
            if ln & 0x8000:
                ln = ((ln & 0x7FFF) << 16) | struct.unpack_from("<H", data, pos)[0]
                pos += 2
            out.append(data[pos:pos + 2 * ln].decode("utf-16-le", "replace"))
    return off + size, out


def _parse_type_chunk(data: bytes, q: int, pkg: str, pkg_id: int,
                      key_strings: list[str], type_strings: list[str]) -> dict:
    """One ResTable_type chunk -> {typeId,type,entryCount,flags,entries[]}."""
    end = q + struct.unpack_from("<I", data, q + 4)[0]
    tid = data[q + 8]
    tflags = data[q + 9]
    entry_count, entries_start = struct.unpack_from("<II", data, q + 12)
    tname = ""
    if 0 < tid - 1 < len(type_strings):
        tname = type_strings[tid - 1] or ("type_%d" % tid)
    else:
        tname = "type_%d" % tid
    # config: starts at q+20 and begins with its own uint32 size
    cfg_size = struct.unpack_from("<I", data, q + 20)[0] if q + 24 <= end else 0
    r = q + 20 + cfg_size
    if r + 8 <= end:
        ct, _ch, csz = struct.unpack_from("<HHI", data, r)
        if ct == _RES_STRING_POOL and csz >= 8:
            r += csz
    offs_pos = q + entries_start - 4 * entry_count
    entries: list[dict] = []
    if offs_pos >= r:
        for i in range(min(entry_count, _MAX_SAMPLE)):
            try:
                o = struct.unpack_from("<I", data, offs_pos + i * 4)[0]
            except struct.error:
                break
            if o == _NO_ENTRY:
                continue
            e = q + entries_start + o
            if e + 8 > end:
                continue
            key_idx = struct.unpack_from("<I", data, e + 4)[0]
            name = key_strings[key_idx] if key_idx < len(key_strings) else "?"
            entries.append({"pkg": pkg, "type": tname, "name": name,
                            "typeId": tid, "entryId": i,
                            "id": "0x%08x" % ((pkg_id << 16) | (tid << 8) | i)})
    return {"pkg": pkg, "type": tname, "typeId": tid,
            "entryCount": entry_count, "flags": tflags,
            "sparse": bool(tflags & _SPARSE_FLAG), "entries": entries}


def _parse_package(data: bytes, pos: int) -> dict:
    """One ResTable_package chunk -> {pkg, types, entries}."""
    size = struct.unpack_from("<I", data, pos + 4)[0]
    end = pos + size
    pkg_id = struct.unpack_from("<I", data, pos + 8)[0]
    raw = data[pos + 12:pos + 12 + 256]
    pkg = raw.decode("utf-16-le", "replace").split("\x00", 1)[0]
    hdr = struct.unpack_from("<H", data, pos + 2)[0]
    p = pos + (hdr if hdr >= 276 else 276)
    try:
        p, type_strings = _read_string_pool(data, p)
        p, key_strings = _read_string_pool(data, p)
    except ValueError:
        return {}
    types: dict[int, dict] = {}
    counts: dict[int, int] = {}
    q = p
    while q + 12 <= end:
        ctype, chdr, csz = struct.unpack_from("<HHI", data, q)
        if csz < chdr or csz < 8 or q + csz > end:
            break
        if ctype == _RES_TYPE_SPEC:
            tid = data[q + 8]
            counts[tid] = struct.unpack_from("<I", data, q + 12)[0]
        elif ctype == _RES_TYPE:
            rec = _parse_type_chunk(data, q, pkg, pkg_id, key_strings, type_strings)
            prev = types.get(rec["typeId"])
            # multiple configs of the same type repeat entries; keep the first
            # (default config usually comes first) so the sample stays readable.
            if prev is None:
                types[rec["typeId"]] = rec
            elif rec["type"] and not prev["type"]:
                prev["type"] = rec["type"]
            if len(types) > 2000:
                break
        q += csz
    body = {"pkg": pkg, "pkgId": pkg_id, "types": [], "entriesSample": []}
    for tid in sorted(types):
        rec = types[tid]
        body["types"].append({"pkg": pkg, "type": rec["type"], "typeId": tid,
                              "entryCount": rec["entryCount"],
                              "sparse": rec["sparse"]})
        body["entriesSample"].extend(rec["entries"])
    if len(body["entriesSample"]) > _MAX_SAMPLE:
        body["entriesSample"] = body["entriesSample"][:_MAX_SAMPLE]
    # typeSpec entryCount is authoritative when a type chunk was missing
    for t in body["types"]:
        if not t["entryCount"]:
            t["entryCount"] = counts.get(t["typeId"], 0)
    return body


def _walk_arsc(data: bytes) -> dict:
    """Parse resources.arsc into {pkgName: body}.  Best effort, never guesses."""
    n = len(data)
    if n < 12:
        return {}
    rtype, rheader, rsize, pkg_count = struct.unpack_from("<HHII", data, 0)
    if rtype != _RES_TABLE:
        return {}
    out: dict[str, dict] = {}
    pos = rheader if rheader >= 12 else 12
    while pos + 8 <= n and len(out) < max(1, min(pkg_count, 64)):
        ctype, chdr, csz = struct.unpack_from("<HHI", data, pos)
        if csz < chdr or csz < 8 or pos + csz > n:
            break
        if ctype == _RES_PACKAGE:
            body = _parse_package(data, pos)
            if body and body.get("pkg"):
                out.setdefault(body["pkg"], body)
        pos += csz
    return out


def read_arsc(path_or_blob, name: str = "resources.arsc", limit: int = _MAX_SAMPLE) -> dict:
    """Read a resources.arsc into a capped, serialisable summary.

    ``available=false`` plus notes is an honest outcome; it is NOT reported as
    "this APK has no resources".
    """
    if isinstance(path_or_blob, bytes):
        data = path_or_blob
        source = name
    else:
        with open(path_or_blob, "rb") as f:
            data = f.read()
        source = os.path.basename(path_or_blob)
    res = _walk_arsc(data)
    summary: dict = {
        "available": bool(res),
        "source": source,
        "sizeBytes": len(data),
        "packages": list(res.keys()),
        "types": [],
        "entriesSample": [],
        "notes": [],
    }
    for _pkg, body in res.items():
        summary["types"].extend(body["types"])
        summary["entriesSample"].extend(body["entriesSample"])
    summary["types"] = summary["types"][:2000]
    summary["entriesSample"] = summary["entriesSample"][:limit]
    if not res:
        summary["notes"].append(
            "resources.arsc 头/包结构未按 AOSP ResTable 布局解析成功；"
            "这只说明解析器没读懂，不能当成'包里没有资源'。")
    elif len(summary["entriesSample"]) >= _MAX_SAMPLE:
        summary["notes"].append("条目样本按 %d 上限截断；全量类型统计见 types。"
                                % _MAX_SAMPLE)
    return summary


# ------------------------------------------------------------------ public tools
def list_manifest(session_id: str, componentType: str = "", query: str = "",
                  exported: bool | None = None, limit: int = DEFAULT_LIMIT,
                  **_: object) -> dict:
    """Return the manifest-level summary stored at load time.

    This is the ``listManifest`` tool: package / version / sdk levels /
    permissions / application class / all four component kinds / native libs /
    deps flags.  The caller can filter the component lists by ``componentType``
    and ``query``.
    """
    t0 = time.time()
    limit = env.clamp_limit(limit)
    s = _open_session_for_resources(session_id)
    try:
        man = s.manifest
        comps = s.components
        if not man and not comps:
            raise ApkIndexError(
                ErrorCode.NOT_FOUND, "该会话没有 manifest 数据",
                "用 loadApk 索引带 AndroidManifest.xml 的 APK；裸 dex / AAR 不带 manifest。")
        wanted = (componentType or "").lower()
        if wanted and wanted not in ("activity", "service", "receiver", "provider",
                                     "component"):
            raise ApkIndexError(
                ErrorCode.BAD_ARGUMENT, f"componentType 不支持: {componentType}",
                "可选值: activity / service / receiver / provider / component。")
        if wanted == "component" or not wanted:
            keys = ["activities", "services", "receivers", "providers"]
        else:
            keys = [wanted + "s"]
        filtered: dict[str, list] = {}
        total = 0
        for k in keys:
            src = comps.get(k) or []
            keep = []
            for c in src:
                cname = c.get("name") or ""
                if query and query.lower() not in cname.lower():
                    continue
                if not _exported_match(c.get("exported"), exported):
                    continue
                keep.append(c)
            filtered[k] = keep
            total += len(keep)
        items: list[dict] = []
        for k in keys:
            for c in filtered.get(k, [])[:limit]:
                c2 = dict(c)
                c2.setdefault("type", _COMP_TYPE.get(k, k))
                items.append(c2)
        out = {
            "package": man.get("package"),
            "versionName": man.get("versionName"),
            "versionCode": man.get("versionCode"),
            "minSdk": man.get("minSdk"), "targetSdk": man.get("targetSdk"),
            "application": man.get("application"),
            "usesPermissions": man.get("usesPermissions") or [],
            "permissions": man.get("permissions") or [],
            "features": man.get("features") or [],
            "nativeLibs": s.native_libs,
            "components": filtered,
            "totalComponents": total,
        }
        hint = (f"{total} 个组件（已按 componentType / query / exported 过滤）。"
                " 完整权限列表看 usesPermissions；exported=None 表示清单未显式声明，"
                " 按 Android 默认规则。")
        return env.ok(items, session_id=session_id, total=total,
                      truncated=total > len(items), limit=limit,
                      elapsedMs=round((time.time() - t0) * 1000, 1),
                      hint=hint, manifest=out)
    finally:
        s.close()


def find_component(session_id: str, name: str = "", componentType: str = "",
                   exported: bool | None = None, limit: int = DEFAULT_LIMIT,
                   **_: object) -> dict:
    """Fuzzy-lookup a component by name across activity/service/receiver/provider.

    ``name`` matches the manifest's ``android:name`` (suffix match when only
    a short name is given).  ``exported`` filters on the explicit value when
    the manifest sets it.
    """
    t0 = time.time()
    limit = env.clamp_limit(limit)
    s = _open_session_for_resources(session_id)
    try:
        comps = s.components
        if not comps:
            raise ApkIndexError(
                ErrorCode.NOT_FOUND, "该会话没有 manifest 组件数据",
                "用 loadApk 重新索引，或确认是带 AndroidManifest.xml 的 APK。")
        if not name and not componentType and exported is None:
            raise ApkIndexError(
                ErrorCode.BAD_ARGUMENT,
                "至少给 name、componentType 或 exported 之一",
                '例：name="MainActivity" 或 componentType="activity" 或 exported=true')
        wanted = (componentType or "").lower()
        if wanted and wanted not in ("activity", "service", "receiver", "provider"):
            raise ApkIndexError(
                ErrorCode.BAD_ARGUMENT, f"componentType 不支持: {componentType}",
                "可选值: activity / service / receiver / provider。")
        keys = [wanted + "s"] if wanted else ["activities", "services",
                                              "receivers", "providers"]
        items: list[dict] = []
        total = 0
        for k in keys:
            for c in comps.get(k, []):
                total += 1
                cname = c.get("name") or ""
                if name:
                    low = name.lower()
                    # suffix match: ".MainActivity" or "MainActivity" both work
                    if not (cname.lower().endswith(low) or
                            low in cname.lower()):
                        continue
                if not _exported_match(c.get("exported"), exported):
                    continue
                c2 = dict(c)
                c2["type"] = _COMP_TYPE.get(k, k)
                if len(items) < limit:
                    items.append(c2)
        hint = (f"命中 {total} 个组件，返回前 {len(items)} 条。"
                " permission 字段为空表示组件没有 permission 保护；"
                " 要看实际安全面，用 resourceSecurity。")
        return env.ok(items, session_id=session_id, total=total,
                      truncated=total > len(items), limit=limit,
                      elapsedMs=round((time.time() - t0) * 1000, 1),
                      hint=hint)
    finally:
        s.close()


def search_resources(session_id: str, query: str = "", match: str = "contains",
                    resourceType: str = "", limit: int = DEFAULT_LIMIT,
                    **_: object) -> dict:
    """Enumerate resources.arsc entries (type / name / typeId).

    Best-effort parser.  ``resourceType`` narrows to a single type; ``query``
    filters entry names.  When the table cannot be parsed the tool returns
    ``available=false`` plus notes instead of an empty result.
    """
    t0 = time.time()
    limit = env.clamp_limit(limit)
    match = (match or "contains").lower()
    if match not in ("contains", "prefix", "regex"):
        raise ApkIndexError(ErrorCode.BAD_ARGUMENT, f"match 不支持: {match}",
                            "只能是 contains / prefix / regex。")
    s = _open_session_for_resources(session_id)
    try:
        res = s.resource_table or {}
        if not res.get("available"):
            raise ApkIndexError(
                ErrorCode.NOT_FOUND,
                "该会话没有可读的 resources.arsc（解析失败或非 APK 会话）",
                "用 loadApk 索引带 resources.arsc 的 APK；解析结果见 notes 字段。")
        entries = res.get("entriesSample") or []
        if resourceType:
            entries = [e for e in entries if e.get("type") == resourceType]
        rx = re.compile(query) if (query and match == "regex") else None
        items: list[dict] = []
        total = 0
        for e in entries:
            name = e.get("name") or ""
            if not query:
                total += 1
                if len(items) < limit:
                    items.append(e)
                continue
            ok = ((match == "contains" and query.lower() in name.lower()) or
                  (match == "prefix" and name.startswith(query)) or
                  (match == "regex" and rx and rx.search(name)))
            if ok:
                total += 1
                if len(items) < limit:
                    items.append(e)
        hint = (f"resources.arsc 解析 {res.get('available')}；"
                f"返回 {total} 条（entriesSample 上限 512）。"
                " 要定位代码里的引用，用 resourceRefs。")
        return env.ok(items, session_id=session_id, total=total,
                      truncated=total > len(items), limit=limit,
                      elapsedMs=round((time.time() - t0) * 1000, 1),
                      hint=hint, resourceTable=res)
    finally:
        s.close()


def resource_refs(session_id: str, resource: str = "", resourceType: str = "",
                  limit: int = DEFAULT_LIMIT, **_: object) -> dict:
    """Find DEX code that mentions a resource by name or type.

    Two passes:
      1. string constants containing the resource name / ``R.type.name``.
      2. const-class references to ``R$type`` / ``BuildConfig`` classes.

    The returned methods are real DEX xrefs, not guesses.  ``kind`` tells
    which evidence produced the hit.
    """
    t0 = time.time()
    limit = env.clamp_limit(limit)
    if not resource and not resourceType:
        raise ApkIndexError(
            ErrorCode.BAD_ARGUMENT, "至少给 resource 或 resourceType 之一",
            '例：resource="string/app_name" 或 resourceType="layout"')
    s = _open_session_for_resources(session_id)
    try:
        needle = (resource or "").strip().lstrip("@")
        t = resourceType or ""
        if "/" in needle:
            t, _, n = needle.partition("/")
            if not n:
                raise ApkIndexError(ErrorCode.BAD_ARGUMENT,
                                    "resource 必须写完整 @type/name",
                                    '例：resource="string/app_name"')
        else:
            n = needle
        cands: set[str] = set()
        if n:
            cands.add(n)
            if t:
                cands.add(f"{t}.{n}")
                cands.add(f"R.{t}.{n}")
            else:
                cands.add(f"R.{n}")
        if t and not n:
            cands.add(t)
        hits: list[dict] = []
        total = 0
        for cand in sorted(cands):
            for m in s.query_resource_strings(cand, limit=limit):
                total += 1
                m["candidate"] = cand
                m["string"] = cand
                m["kind"] = "string-const"
                if len(hits) < limit:
                    hits.append(m)
        if not hits and t:
            for m in s.query_resource_classes(t, limit=limit):
                total += 1
                m["via"] = "class-const"
                if len(hits) < limit:
                    hits.append(m)
        hint = (f"命中 {total} 条代码引用。"
                " string-const 通常是资源名的字面量（日志、调试）；"
                " class-const 是代码里出现过 R$type / BuildConfig 类。"
                " 要确认是否真的读了该资源，把方法交给 decompile(format=smali)。"
                " 0 命中不代表没用到：getIdentifier、XML 直接引用、插件化动态加载"
                " 都不会留下这两种痕迹。")
        return env.ok(hits, session_id=session_id, total=total,
                      truncated=total > len(hits), limit=limit,
                      elapsedMs=round((time.time() - t0) * 1000, 1),
                      hint=hint)
    finally:
        s.close()


def resource_security(session_id: str, limit: int = DEFAULT_LIMIT,
                      **_: object) -> dict:
    """Security-relevant resource / manifest surface.

    Aggregates exported components, dangerous permissions, native libs and
    resource-table availability.  The output is a single item so the caller
    can diff it across versions.
    """
    t0 = time.time()
    limit = env.clamp_limit(limit)
    s = _open_session_for_resources(session_id)
    try:
        man = s.manifest
        comps = s.components
        perms = man.get("usesPermissions") or []
        dangerous = [p for p in perms
                     if any(k in p.upper() for k in
                            ("INTERNET", "LOCATION", "CAMERA", "RECORD_AUDIO",
                             "STORAGE", "READ_PHONE", "SEND_SMS", "CALL_PHONE",
                             "READ_CONTACTS", "WRITE_CONTACTS", "READ_SMS",
                             "ACCESS_FINE", "ACCESS_COARSE"))]
        exported: list[dict] = []
        for ctype in ("activities", "services", "receivers", "providers"):
            for c in comps.get(ctype, []):
                if c.get("exported") in _TRUEISH:
                    exported.append({**c, "type": _COMP_TYPE.get(ctype, ctype)})
        out = {
            "available": bool(s.resource_table),
            "manifestPackage": man.get("package"),
            "minSdk": man.get("minSdk"), "targetSdk": man.get("targetSdk"),
            "application": man.get("application"),
            "usesPermissions": perms[:80],
            "dangerousPermissions": dangerous[:50],
            "exportedComponents": exported[:80],
            "nativeLibs": s.native_libs[:30],
            "resourceTable": bool(s.resource_table),
            "resourceTypes": [t.get("type") for t in
                              (s.resource_table or {}).get("types", [])][:60],
            "notes": (s.resource_table or {}).get("notes", []),
        }
        hint = ("exportedComponents 是安全面清单。 "
                "permission 字段为空表示组件自身没有 permission 保护，"
                " 不代表不可被外部调用。")
        return env.ok([out], session_id=session_id, total=1, truncated=False,
                      limit=limit, elapsedMs=round((time.time() - t0) * 1000, 1),
                      hint=hint)
    finally:
        s.close()


def doctor(**_: object) -> dict:
    """Read-only cache health check.

    Inspects every registered session:
      * db file exists and passes ``PRAGMA quick_check``
      * schema version
      * cache size
      * unregistered ``*.db`` files in the cache dir

    Never mutates the cache.  For remediation, ``unload`` + ``loadApk`` is
    the supported path.
    """
    t0 = time.time()
    base = settings().cache_dir
    catalog_db = os.path.join(base, "catalog.db")
    out: dict = {
        "ok": True,
        "cacheDir": base,
        "sessions": [],
        "issues": [],
        "notes": [],
    }
    total = 0
    if os.path.isdir(base):
        for root, _dirs, files in os.walk(base):
            for f in files:
                p = os.path.join(root, f)
                try:
                    total += os.path.getsize(p)
                except OSError:
                    pass
        out["cacheBytes"] = total
        out["cacheHuman"] = f"{total / 1048576:.1f}MB"
    if not os.path.exists(catalog_db):
        out["issues"].append("catalog.db 不存在（还没有索引过任何会话）")
        out["ok"] = False
        out["elapsedMs"] = round((time.time() - t0) * 1000, 1)
        out["hint"] = "缓存目录是空的。loadApk 一次即可。"
        return out
    cat = catalog()
    for r in cat.list():
        sid = r["sessionId"]
        dbp = r.get("dbPath") or ""
        entry: dict = {
            "sessionId": sid, "pkg": r.get("pkg"), "kind": r.get("kind"),
            "dbPath": dbp, "exists": bool(dbp and os.path.exists(dbp)),
            "sizeBytes": os.path.getsize(dbp) if dbp and os.path.exists(dbp) else 0,
            "backend": r.get("backend"), "packed": bool(r.get("packed")),
            "createdAt": r.get("createdAt"),
        }
        if entry["exists"]:
            try:
                conn = connect(dbp, readonly=True)
                try:
                    sv = conn.execute("PRAGMA user_version").fetchone()
                    entry["schemaVersion"] = sv[0] if sv else None
                    quick = conn.execute("PRAGMA quick_check").fetchone()
                    entry["quickCheck"] = str(quick[0]).strip().lower() if quick else "?"
                finally:
                    conn.close()
                if entry.get("quickCheck") != "ok":
                    entry["issue"] = f"quick_check={entry['quickCheck']}"
                    out["issues"].append(f"{sid}: {entry['issue']}")
                    out["ok"] = False
                if entry.get("schemaVersion") is None:
                    entry["issue"] = "schemaVersion 缺失"
                    out["issues"].append(f"{sid}: schemaVersion 缺失")
                    out["ok"] = False
            except Exception as e:  # noqa: BLE001
                entry["issue"] = f"不可读: {e}"
                out["issues"].append(f"{sid}: 不可读 ({e})")
                out["ok"] = False
        else:
            entry["issue"] = "索引文件缺失"
            out["issues"].append(f"{sid}: 索引文件缺失 {dbp}")
            out["ok"] = False
        out["sessions"].append(entry)
    registered = {s.get("dbPath") for s in out["sessions"] if s.get("dbPath")}
    for root, _dirs, files in os.walk(base):
        for f in files:
            if f.endswith(".db"):
                p = os.path.join(root, f)
                if p not in registered:
                    out["notes"].append(f"未登记索引文件: {p}")
    out["elapsedMs"] = round((time.time() - t0) * 1000, 1)
    out["hint"] = ("缓存体检完成。 "
                   "issues 里的会话需要 unload 后重新 load；"
                   " 未登记文件可以安全删除（先确认没有进程在使用）。")
    return out
