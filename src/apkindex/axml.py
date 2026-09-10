"""Binary AndroidManifest.xml (AXML) reader + minimal writer.

Reader decodes: string pool, resource id map, element tree with attribute
values (string / int / bool / reference / float).  No external dependency and
no framework requirement -- enough to recover package, versions, sdk levels,
application class, the four component kinds, permissions and meta-data.

The writer exists only so tests can build a real APK without aapt2; the bytes
it emits are read back by the reader in this same module.
"""
from __future__ import annotations

import struct

RES_XML_TYPE = 0x0003
CHUNK_STRING_POOL = 0x0001
CHUNK_RESOURCE_ID = 0x0180
CHUNK_START_NS = 0x0104
CHUNK_END_NS = 0x0105
CHUNK_START_TAG = 0x0102
CHUNK_END_TAG = 0x0103
UTF8_FLAG = 1 << 8

TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# a tiny, honest subset -- unknown names keep index 0 and are matched by string
ANDROID_ATTR_IDS = {
    "name": 0x01010003,
    "label": 0x01010001,
    "icon": 0x01010002,
    "versionCode": 0x0101021b,
    "versionName": 0x0101021c,
    "minSdkVersion": 0x01010209,
    "targetSdkVersion": 0x0101021d,
    "value": 0x01010024,
    "resource": 0x01010025,
    "authorities": 0x01010027,
    "exported": 0x01010010,
    "enabled": 0x0101000e,
    "permission": 0x01010006,
    "process": 0x01010011,
    "theme": 0x01010000,
}


class AxmlError(Exception):
    pass


def _decode_utf8(buf: bytes, off: int) -> str:
    def _len(o: int):
        n = buf[o]
        if n & 0x80:
            n = ((n & 0x7F) << 8) | buf[o + 1]
            o += 2
        else:
            o += 1
        return o

    o = _len(off)
    nbytes = buf[o]
    if nbytes & 0x80:
        nbytes = ((nbytes & 0x7F) << 8) | buf[o + 1]
        o += 2
    else:
        o += 1
    return buf[o:o + nbytes].decode("utf-8", "replace")


def _decode_utf16(buf: bytes, off: int) -> str:
    n = struct.unpack_from("<H", buf, off)[0]
    if n & 0x8000:
        n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", buf, off + 2)[0]
        off += 4
    else:
        off += 2
    return buf[off:off + 2 * n].decode("utf-16-le", "replace")


class Element:
    __slots__ = ("tag", "ns", "attrs", "children", "line")

    def __init__(self, tag, ns=None, attrs=None, line=0):
        self.tag = tag
        self.ns = ns
        self.attrs = list(attrs or [])   # (prefix_or_None, uri, name, value)
        self.children: list[Element] = []
        self.line = line

    def attr(self, name, uri=ANDROID_NS, default=None):
        for _pfx, auri, nm, val in self.attrs:
            if nm == name and (auri in (uri, "android", None, "")):
                return val
        return default

    def plain(self, name, default=None):
        for _pfx, _uri, nm, val in self.attrs:
            if nm == name:
                return val
        return default

    def find_all(self, tag):
        return [c for c in self.children if c.tag == tag]

    def walk(self):
        yield self
        for c in self.children:
            yield from c.walk()

    def __repr__(self):
        return f"<{self.tag} attrs={len(self.attrs)} kids={len(self.children)}>"


class StringPool:
    def __init__(self, buf: bytes, off: int):
        (self.ctype, self.hdr, self.size, self.count, self.styles,
         self.flags, self.strings_start, self.styles_start) = struct.unpack_from(
            "<HHIIIIII", buf, off)
        self.base = off
        self.buf = buf
        self.utf8 = bool(self.flags & UTF8_FLAG)
        self._start = off + self.strings_start
        self._offs = struct.unpack_from(f"<{self.count}I", buf,
                                        off + self.hdr) if self.count else ()
        self._cache: dict[int, str | None] = {}

    def __len__(self):
        return self.count

    def s(self, idx):
        if idx is None or idx < 0 or idx >= self.count:
            return None
        if idx in self._cache:
            return self._cache[idx]
        try:
            p = self._start + self._offs[idx]
            val = _decode_utf8(self.buf, p) if self.utf8 else _decode_utf16(self.buf, p)
        except Exception:
            val = None
        self._cache[idx] = val
        return val


def parse(data: bytes) -> Element:
    if len(data) < 8 or struct.unpack_from("<H", data, 0)[0] != RES_XML_TYPE:
        raise AxmlError("not an AXML binary manifest")
    pool: StringPool | None = None
    root: Element | None = None
    stack: list[Element] = []
    pos, n = 8, len(data)
    while pos + 8 <= n:
        ctype, hdr, csize = struct.unpack_from("<HHI", data, pos)
        if csize < 8 or pos + csize > n:
            break
        if ctype == CHUNK_STRING_POOL:
            pool = StringPool(data, pos)
        elif ctype == CHUNK_START_TAG and pool is not None:
            el = _read_tag(data, pos, pool)
            if stack:
                stack[-1].children.append(el)
            elif root is None:
                root = el
            stack.append(el)
        elif ctype == CHUNK_END_TAG:
            if stack:
                stack.pop()
        pos += max(csize, 8)
    if root is None:
        raise AxmlError("AXML 无根节点")
    return root


def _read_tag(buf: bytes, off: int, pool: StringPool) -> Element:
    line = struct.unpack_from("<I", buf, off + 8)[0]
    ns_i, name_i, attr_start, attr_size, attr_count = struct.unpack_from(
        "<IIHHH", buf, off + 16)
    base = off + 16 + attr_start
    attrs = []
    step = attr_size if attr_size >= 20 else 20
    for i in range(attr_count):
        p = base + i * step
        ans, aname, araw = struct.unpack_from("<III", buf, p)
        dsize = struct.unpack_from("<H", buf, p + 12)[0]
        dtype = buf[p + 15]             # Res_value: size(2) res0(1) dataType(1)
        ddata = struct.unpack_from("<i", buf, p + 16)[0]
        name = pool.s(aname) or f"attr{i}"
        uri = pool.s(ans) if ans not in (0, 0xFFFFFFFF) else None
        attrs.append((None, uri, name, _value(pool, dtype, araw, ddata)))
    ns = pool.s(ns_i) if ns_i not in (0, 0xFFFFFFFF) else None
    return Element(pool.s(name_i) or "?", ns, attrs, line)


def _value(pool, dtype, raw_i, data):
    if dtype == TYPE_STRING and raw_i != 0xFFFFFFFF:
        return pool.s(raw_i)
    if dtype == TYPE_INT_DEC:
        return data
    if dtype == TYPE_INT_HEX:
        return f"0x{data & 0xFFFFFFFF:08x}"
    if dtype == TYPE_INT_BOOLEAN:
        return data != 0
    if dtype == TYPE_REFERENCE:
        return f"@0x{data & 0xFFFFFFFF:08x}"
    if dtype == TYPE_FLOAT:
        return struct.unpack("<f", struct.pack("<i", data))[0]
    if raw_i not in (0, 0xFFFFFFFF):
        s = pool.s(raw_i)
        if s is not None:
            return s
    return data


# ---------------------------------------------------------------- decoding
def manifest_of(data: bytes) -> dict:
    """High level summary used by the loader."""
    root = parse(data)
    out: dict = {
        "package": root.plain("package"),
        "versionCode": _as_int(root.attr("versionCode")),
        "versionName": root.attr("versionName"),
        "minSdk": None, "targetSdk": None, "maxSdk": None,
        "compileSdkVersion": root.plain("compileSdkVersion"),
        "compileSdkCodename": root.plain("compileSdkCodename"),
        "split": root.plain("split"),
        "installLocation": root.attr("installLocation"),
        "application": None,
        "activities": [], "services": [], "receivers": [], "providers": [],
        "permissions": [], "usesPermissions": [], "libraries": [],
        "metaData": {}, "features": [],
    }
    for el in root.walk():
        if el.tag == "uses-sdk":
            out["minSdk"] = _as_int(el.attr("minSdkVersion"))
            out["targetSdk"] = _as_int(el.attr("targetSdkVersion"))
            out["maxSdk"] = _as_int(el.attr("maxSdkVersion"))
        elif el.tag == "application":
            out["application"] = el.attr("name")
            for c in el.children:
                if c.tag == "activity":
                    out["activities"].append(_comp(c))
                elif c.tag == "service":
                    out["services"].append(_comp(c))
                elif c.tag == "receiver":
                    out["receivers"].append(_comp(c))
                elif c.tag == "provider":
                    out["providers"].append(_comp(c))
                elif c.tag == "meta-data":
                    _meta(out["metaData"], c)
                elif c.tag == "uses-library":
                    out["libraries"].append(c.attr("name") or c.plain("name"))
        elif el.tag == "uses-permission":
            name = el.attr("name") or el.plain("name")
            if name:
                out["usesPermissions"].append(name)
        elif el.tag == "permission":
            name = el.attr("name") or el.plain("name")
            if name:
                out["permissions"].append(name)
        elif el.tag == "uses-library":
            out["libraries"].append(el.attr("name") or el.plain("name"))
        elif el.tag == "meta-data" and out["application"] is None:
            _meta(out["metaData"], el)
        elif el.tag == "uses-feature":
            f = el.attr("name")
            if f:
                out["features"].append(f)
    out["activities"] += _collect_orphans(root, "activity-alias")
    return out


def _meta(dst: dict, el: Element):
    name = el.attr("name") or el.plain("name")
    if not name:
        return
    dst[name] = el.attr("value") if el.attr("value") is not None else el.attr("resource")


def _comp(el: Element) -> dict:
    return {
        "name": el.attr("name"),
        "exported": el.attr("exported"),
        "permission": el.attr("permission"),
        "process": el.attr("process"),
        "enabled": el.attr("enabled"),
    }


def _collect_orphans(root: Element, tag: str) -> list:
    return [_comp(e) for e in root.walk() if e.tag == tag]


def _as_int(v):
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v, 0)
        except ValueError:
            return None
    return None


# ---------------------------------------------------------------- encoding
def _enc_utf16(s: str) -> bytes:
    n = len(s)
    if n > 0x7FFF:
        head = struct.pack("<HH", 0x8000 | (n >> 16), n & 0xFFFF)
    else:
        head = struct.pack("<H", n)
    return head + s.encode("utf-16-le") + b"\x00\x00"


class Writer:
    """Builds an AXML document from an Element tree (UTF-16 pool).

    Two passes on purpose: every chunk is serialised first -- which is what
    registers the strings it still needs -- and only then is the string pool
    frozen and emitted.  Emitting the pool up front and patching indices
    afterwards is how a manifest ended up with attribute names pointing past
    the end of the pool.
    """

    def __init__(self, root: Element):
        self.root = root
        self.strings: list[str] = []
        self.ids: dict[str, int] = {}
        self.attr_names: list[str] = []
        self.namespaces = ["android", ANDROID_NS]
        self._seed()

    def _seed(self):
        for st in self.namespaces:
            self._sid(st)
        for el in self.root.walk():
            self._sid(el.tag)
            for _p, uri, name, val in el.attrs:
                if uri:
                    self._sid(uri)
                self._sid(name)
                if name != "xmlns" and name not in self.attr_names:
                    self.attr_names.append(name)
                if isinstance(val, str):
                    self._sid(val)

    def _sid(self, st: str) -> int:
        i = self.ids.get(st)
        if i is None:
            i = len(self.strings)
            self.ids[st] = i
            self.strings.append(st)
        return i

    @staticmethod
    def _node(ctype: int, size: int, line: int = 1) -> bytes:
        """ResXMLTree_node header: ResChunk_header(8) + line(4) + comment(4)."""
        return struct.pack("<HHIII", ctype, 16, size, line, 0xFFFFFFFF)

    def build(self) -> bytes:
        chunks = [self._ns(CHUNK_START_NS),
                  self._tag(self.root, True),
                  self._tag(self.root, False),
                  self._ns(CHUNK_END_NS)]
        body = self._pool() + self._resmap() + b"".join(chunks)
        return struct.pack("<HHI", RES_XML_TYPE, 8, 8 + len(body)) + body

    def _pool(self) -> bytes:
        offs, data = [], b""
        for st in self.strings:
            offs.append(len(data))
            data += _enc_utf16(st)
        while len(data) % 4:
            data += b"\x00"
        hdr = 28 + 4 * len(self.strings)
        out = struct.pack("<HHIIIIII", CHUNK_STRING_POOL, 28, hdr + len(data),
                          len(self.strings), 0, 0, hdr, 0)
        out += b"".join(struct.pack("<I", o) for o in offs)
        return out + data

    def _resmap(self) -> bytes:
        """ResXMLTree_id: header(8) + count(4) + ids (aapt writes headerSize 8)."""
        ids = [ANDROID_ATTR_IDS.get(n, 0x01010000) for n in self.attr_names]
        body = b"".join(struct.pack("<I", i) for i in ids)
        return struct.pack("<HHII", CHUNK_RESOURCE_ID, 8,
                           12 + len(body), len(ids)) + body

    def _ns(self, ctype: int) -> bytes:
        pfx, uri = self.namespaces
        ext = struct.pack("<II", self._sid(pfx), self._sid(uri))
        return self._node(ctype, 16 + 8) + ext

    def _tag(self, el: Element, start: bool) -> bytes:
        ns_i = 0xFFFFFFFF if el.ns is None else self._sid(el.ns)
        if not start:
            return self._node(CHUNK_END_TAG, 24) + struct.pack(
                "<II", ns_i, self._sid(el.tag))
        blob = b""
        for _p, uri, name, val in el.attrs:
            ans = self._sid(uri) if uri else 0xFFFFFFFF
            aname = self._sid(name)
            if val is None:
                dtype, raw, data = TYPE_NULL, 0xFFFFFFFF, 0
            elif isinstance(val, bool):
                dtype, raw, data = TYPE_INT_BOOLEAN, 0xFFFFFFFF, (0xFFFFFFFF if val else 0)
            elif isinstance(val, int):
                dtype, raw, data = TYPE_INT_DEC, 0xFFFFFFFF, val
            else:
                idx = self._sid(str(val))
                dtype, raw, data = TYPE_STRING, idx, idx
            blob += struct.pack("<III", ans, aname, raw)   # ns, name, rawValue
            blob += struct.pack("<HBB", 8, 0, dtype)       # size, res0, dataType
            blob += struct.pack("<I", data & 0xFFFFFFFF)
        ext = struct.pack("<II", ns_i, self._sid(el.tag))
        ext += struct.pack("<HHHHHH", 20, 20, len(el.attrs), 0, 0, 0)
        out = self._node(CHUNK_START_TAG, 16 + len(ext) + len(blob)) + ext + blob
        for c in el.children:
            out += self._tag(c, True)
            out += self._tag(c, False)
        return out
