"""apk-index builtin DEX parser: classes*.dex -> structured records.

Pure stdlib, read-only.  Produces the same record shape as the optional
androguard / dexlib2 backends (see backends.py) so the indexer is agnostic.
"""
from __future__ import annotations

import struct
import sys
import traceback
from dataclasses import dataclass, field as _f

ENDIAN_TAG = 0x12345678
HEADER_SIZE = 0x70

ACC_PUBLIC, ACC_PRIVATE, ACC_PROTECTED, ACC_STATIC = 0x1, 0x2, 0x4, 0x8
ACC_FINAL, ACC_SYNCHRONIZED, ACC_BRIDGE, ACC_VARARGS = 0x10, 0x20, 0x40, 0x80
ACC_NATIVE, ACC_INTERFACE, ACC_ABSTRACT = 0x100, 0x200, 0x400
ACC_ANNOTATION, ACC_ENUM = 0x2000, 0x4000
ACC_CONSTRUCTOR, ACC_DECLARED_SYNCHRONIZED = 0x10000, 0x20000


class DexError(Exception):
    pass


def flag_names(flags: int, for_class: bool = False, for_field: bool = False) -> list[str]:
    """Access flags -> modifier words, in the right *context*.

    The same bit means different things per member kind (0x40 is volatile on a
    field and bridge on a method; 0x20 is the deprecated ACC_SUPER on a class
    and synchronized on a method), so labelling them with one shared table is
    how a tool invents a modifier that no compiler would ever accept.
    """
    common = [(ACC_PUBLIC, "public"), (ACC_PRIVATE, "private"),
              (ACC_PROTECTED, "protected"), (ACC_STATIC, "static"),
              (ACC_FINAL, "final")]
    if for_class:
        pairs = common + [
            (ACC_INTERFACE, "interface"), (ACC_ABSTRACT, "abstract"),
            (ACC_ANNOTATION, "annotation"), (ACC_ENUM, "enum"),
            (ACC_SYNCHRONIZED, "super-deprecated")]
    elif for_field:
        # 0x40/0x80 are bridge/varargs on methods but volatile/transient on
        # fields -- same bits, different vocabulary.  Report the field reading.
        pairs = common + [(0x40, "volatile"), (0x80, "transient"), (ACC_ENUM, "enum")]
    else:
        pairs = common + [
            (ACC_SYNCHRONIZED, "synchronized"), (ACC_BRIDGE, "bridge"),
            (ACC_VARARGS, "varargs"), (ACC_NATIVE, "native"),
            (ACC_ABSTRACT, "abstract"), (0x800, "strictfp"),
            (ACC_CONSTRUCTOR, "constructor"),
            (ACC_DECLARED_SYNCHRONIZED, "declared-synchronized")]
    return [n for b, n in pairs if flags & b]


# ------------------------------------------------------------------ leb128
def method_flag_names(flags: int, name: str = "") -> list[str]:
    """方法修饰符词表，按方法名校正 0x10000 的读法。

    <init> → constructor；<clinit> → static-initializer（d8 也给它打 0x10000）；
    其它方法带上这个位属编译器残留，不写成 constructor，免得下游照着生成错的 matcher。
    """
    out = flag_names(flags)
    if ACC_CONSTRUCTOR and (flags & ACC_CONSTRUCTOR) and "constructor" in out:
        if name == "<clinit>":
            out = [x for x in out if x != "constructor"] + ["static-initializer"]
        elif name not in ("", "<init>"):
            out = [x for x in out if x != "constructor"]
    return out


def uleb(buf: bytes, off: int):
    result = shift = 0
    while True:
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, off
        shift += 7
        if shift > 35:
            raise DexError("uleb128 超长")


def u32(buf: bytes, off: int):
    """定长 uint：DexFormat 里 *_off / *_idx / set size 用它，不是 ULEB128。"""
    return struct.unpack_from("<I", buf, off)[0], off + 4


def uleb_enc(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | 0x80 if v else b)
        if not v:
            return bytes(out)


def mutf8(buf: bytes, off: int):
    out = []
    i, n = off, len(buf)
    while i < n:
        c = buf[i]
        if c == 0:
            i += 1
            break
        if c < 0x80:
            out.append(chr(c))
            i += 1
        elif c & 0xE0 == 0xC0 and i + 1 < n:
            v = ((c & 0x1F) << 6) | (buf[i + 1] & 0x3F)
            out.append("\u0000" if v == 0 else chr(v))
            i += 2
        elif c & 0xF0 == 0xE0 and i + 2 < n:
            v = ((c & 0x0F) << 12) | ((buf[i + 1] & 0x3F) << 6) | (buf[i + 2] & 0x3F)
            out.append(chr(v))
            i += 3
        else:
            out.append("\ufffd")
            i += 1
    return "".join(out), i


def mutf8_enc(s: str) -> bytes:
    out = bytearray()
    for ch in s:
        cp = ord(ch)
        if cp == 0:
            out += b"\xc0\x80"
        elif cp < 0x80:
            out.append(cp)
        elif cp < 0x800:
            out += bytes([0xC0 | (cp >> 6), 0x80 | (cp & 0x3F)])
        else:
            out += bytes([0xE0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3F),
                          0x80 | (cp & 0x3F)])
    out.append(0)
    return bytes(out)


# ------------------------------------------------- instruction length table
def _insn_table():
    T: dict[int, tuple[int, str]] = {}
    for op in range(0x00, 0x12):
        T[op] = (1, "")                     # nop..return-object  (0x11), const/4
    T[0x12] = (1, "")                       # const/4
    T[0x13] = (2, "")                       # const/16
    T[0x14] = (2, "")                       # const/high16
    T[0x15] = (2, "")                       # const-wide/16
    T[0x16] = (3, "")                       # const-wide/32
    T[0x17] = (3, "")                       # const-wide
    T[0x18] = (2, "")                       # const-wide/high16
    T[0x19] = (2, "")                       # reserved
    T[0x1A] = (2, "string")                 # const-string
    T[0x1B] = (3, "string")                 # const-string/jumbo
    T[0x1C] = (2, "type")                   # const-class
    T[0x1D] = (1, "")                       # monitorenter
    T[0x1E] = (1, "")                       # monitorexit
    T[0x1F] = (2, "type")                   # check-cast
    T[0x20] = (2, "type")                   # instance-of
    T[0x21] = (1, "")                       # array-length
    T[0x22] = (2, "type")                   # new-instance
    T[0x23] = (2, "type")                   # new-array
    T[0x24] = (3, "type")                   # filled-new-array
    T[0x25] = (2, "type")                   # filled-new-array/range
    T[0x26] = (3, "")                       # fill-array-data
    T[0x27] = (1, "")                       # throw
    T[0x28] = (1, "")                       # goto
    T[0x29] = (2, "")                       # goto/16
    T[0x2A] = (3, "")                       # goto/32
    T[0x2B] = (3, "")                       # packed-switch
    T[0x2C] = (3, "")                       # sparse-switch
    for op in range(0x2D, 0x52):
        T[op] = (1, "")                     # cmp/binop/if-* (all 1 unit, 23x/12x/21c? )
    for op in range(0x52, 0x5F):
        T[op] = (2, "field")                # iget* / iput*  (0x52..0x5e)
    T[0x5F] = (2, "field")
    for op in range(0x60, 0x6E):
        T[op] = (2, "field")                # sget*/sput*
    for op in range(0x6E, 0x74):
        T[op] = (3, "method")               # invoke-*  (35c) + invoke-dynamic
    for op in range(0x74, 0x78):
        T[op] = (2, "method")               # invoke-*/range (3rc)
    T[0x78] = (1, "")
    T[0x79] = (1, "")
    T[0x7A] = (2, "")                       # const-method-handle
    T[0x7B] = (2, "")                       # const-method-type
    for op in range(0x7C, 0x8F):
        T[op] = (1, "")                     # arithmetic tail
    for op in range(0x8F, 0x9B):
        T[op] = (2, "field")                # volatile iget/iput/sget/sput
    for op in range(0x9B, 0xF0):
        T[op] = (1, "")                     # reserved / application / array-ext
    T[0xFA] = (4, "")                       # const (extended range)
    T[0xFB] = (5, "")                       # const-wide (extended)
    T[0xFC] = (3, "type")                   # const-class/jumbo
    T[0xFD] = (5, "")                       # reserved
    T[0xFE] = (3, "method")                 # invoke-polymorphic
    T[0xFF] = (3, "method")                 # invoke-custom
    T[0x12] = (1, "")
    return T


INSN = _insn_table()

_FIELD_READ = set(range(0x52, 0x59)) | set(range(0x60, 0x67)) | \
    set(range(0x8F, 0x92)) | set(range(0x95, 0x98))
_FIELD_WRITE = set(range(0x59, 0x60)) | set(range(0x67, 0x6E)) | \
    set(range(0x92, 0x95)) | set(range(0x98, 0x9B))
_INVOKE_OPS = {0x6E: "invoke-virtual", 0x6F: "invoke-super",
               0x70: "invoke-direct", 0x71: "invoke-static",
               0x72: "invoke-interface", 0x73: "invoke-dynamic",
               0x74: "invoke-interface", 0x75: "invoke-virtual",
               0x76: "invoke-super", 0x77: "invoke-direct",
               0xFE: "invoke-polymorphic", 0xFF: "invoke-custom"}


# ---------------------------------------------------------------- records
@dataclass
class CodeInfo:
    strings: list[str] = _f(default_factory=list)
    const_classes: list[str] = _f(default_factory=list)
    reads: list[tuple] = _f(default_factory=list)     # (owner_desc,name,type)
    writes: list[tuple] = _f(default_factory=list)
    calls: list[tuple] = _f(default_factory=list)     # (kind,owner,name,params,ret)
    registers: int = 0
    ins_size: int = 0
    outs_size: int = 0
    tries: int = 0
    partial: bool = False
    unit_count: int = 0
    raw: bytes = b""


@dataclass
class MethodInfo:
    name: str
    params: list[str]
    returns: str
    shorty: str
    access: int
    code: CodeInfo | None = None

    @property
    def params_descriptor(self) -> str:
        return "(" + "".join(self.params) + ")"

    @property
    def is_static(self) -> bool:
        return bool(self.access & ACC_STATIC)

    @property
    def is_constructor(self) -> bool:
        # d8/R8 把 kAccConstructor(0x10000) 同时打在 <clinit> 上（它也是"初始化器"），
        # 所以位不能单独当判据：按位判会把静态初始化器说成构造方法，
        # 生成的 DSL 会去 constructors{} 里找一个根本不在那里的 hook 点。
        return self.name == "<init>"

    @property
    def is_static_initializer(self) -> bool:
        return self.name == "<clinit>"


@dataclass
class FieldInfo:
    name: str
    type: str
    access: int
    static: bool


@dataclass
class AnnotationInfo:
    descriptor: str
    visibility: int
    values: dict
    on_method: str | None = None
    on_field: str | None = None


@dataclass
class ClassInfo:
    descriptor: str
    access: int
    super_descriptor: str | None
    interfaces: list[str]
    source_file: str | None
    fields: list[FieldInfo]
    methods: list[MethodInfo]
    annotations: list[AnnotationInfo]

    @property
    def simple_name(self) -> str:
        n = self.descriptor[1:-1] if self.descriptor.startswith("L") else self.descriptor
        return n.rsplit("/", 1)[-1].replace("/", "$")

    @property
    def package(self) -> str:
        n = self.descriptor[1:-1] if self.descriptor.startswith("L") else self.descriptor
        return n.rsplit("/", 1)[0] if "/" in n else ""

    @property
    def kind(self) -> str:
        if self.access & ACC_INTERFACE:
            return "interface"
        if self.access & ACC_ANNOTATION:
            return "annotation"
        if self.access & ACC_ENUM:
            return "enum"
        if self.access & ACC_ABSTRACT:
            return "abstract"
        return "class"


@dataclass
class DexFileData:
    name: str
    size_bytes: int
    version: str
    counts: dict
    classes: list[ClassInfo]
    strings: list[str]
    parse_notes: list[str] = _f(default_factory=list)


def usable_annotation(desc, vis) -> bool:
    """encoded_annotation 的 type_idx 只能指向 reference type，visibility 只有 0/1/2。
    任一不满足就是读歪了（偏移错位的典型症状）——丢掉，别让垃圾进索引。"""
    if not isinstance(desc, str) or not desc:
        return False
    if not (desc.startswith("L") or desc.startswith("[")):
        return False
    return vis in (0, 1, 2)


# ---------------------------------------------------------------- parser
class Dex:
    def __init__(self, data: bytes, name: str = "classes.dex"):
        self.b = data
        self.name = name
        if len(data) < HEADER_SIZE:
            raise DexError(f"{name}: 文件小于 dex header")
        magic = data[:8]
        if not magic.startswith(b"dex\n"):
            raise DexError(f"{name}: 非 dex 文件 magic={magic!r}")
        self.version = magic[4:7].decode("ascii", "replace")
        (self.checksum, self.signature, self.file_size, self.header_size,
         self.endian) = struct.unpack_from("<I20sIII", data, 8)
        if self.endian != ENDIAN_TAG:
            raise DexError(f"{name}: endian_tag=0x{self.endian:08x} 不支持")
        if self.file_size > len(data) + 4:
            raise DexError(f"{name}: file_size={self.file_size} 超出实际 {len(data)}")
        (self.link_size, self.link_off, self.map_off) = struct.unpack_from(
            "<3I", data, 44)
        (self.string_ids_size, self.string_ids_off, self.type_ids_size,
         self.type_ids_off, self.proto_ids_size, self.proto_ids_off,
         self.field_ids_size, self.field_ids_off, self.method_ids_size,
         self.method_ids_off, self.class_defs_size, self.class_defs_off,
         self.data_size, self.data_off) = struct.unpack_from("<14I", data, 56)

    # ---- section readers
    def strings(self) -> list[str | None]:
        out: list[str | None] = []
        for i in range(self.string_ids_size):
            off = struct.unpack_from("<I", self.b, self.string_ids_off + i * 4)[0]
            try:
                _n, p = uleb(self.b, off)
                s, _ = mutf8(self.b, p)
            except Exception:
                s = None
            out.append(s)
        return out

    def type_str_idx(self) -> list[int]:
        if not self.type_ids_size:
            return []
        return list(struct.unpack_from(f"<{self.type_ids_size}I", self.b,
                                       self.type_ids_off))

    def protos(self):
        out = []
        for i in range(self.proto_ids_size):
            si, ri, po = struct.unpack_from("<III", self.b, self.proto_ids_off + i * 12)
            params: list[int] = []
            if po and po + 4 <= len(self.b):
                n = struct.unpack_from("<I", self.b, po)[0]
                if n * 2 <= len(self.b) - po - 4:
                    params = list(struct.unpack_from(f"<{n}H", self.b, po + 4))
            out.append((si, ri, params))
        return out

    def field_ids(self):
        out = []
        for i in range(self.field_ids_size):
            c, t = struct.unpack_from("<HH", self.b, self.field_ids_off + i * 8)
            n = struct.unpack_from("<I", self.b, self.field_ids_off + i * 8 + 4)[0]
            out.append((c, t, n))
        return out

    def method_ids(self):
        out = []
        for i in range(self.method_ids_size):
            c, p = struct.unpack_from("<HH", self.b, self.method_ids_off + i * 8)
            n = struct.unpack_from("<I", self.b, self.method_ids_off + i * 8 + 4)[0]
            out.append((c, p, n))
        return out

    def class_def_items(self):
        out = []
        for i in range(self.class_defs_size):
            base = self.class_defs_off + i * 32
            if base + 32 > len(self.b):
                break
            ci, acc, sup, ifc, src, ann, cd, sv = struct.unpack_from("<8I", self.b, base)
            out.append(dict(class_idx=ci, access=acc, super_idx=sup, ifaces_off=ifc,
                            source_off=src, ann_off=ann, class_data_off=cd,
                            static_values_off=sv))
        return out

    def map_counts(self) -> dict:
        """Only meaningful when link_size>0 (odex / map-bearing dex)."""
        res: dict[str, int] = {}
        moff = self.map_off or (self.link_off if self.link_size else 0)
        if not moff or moff + 4 > len(self.b):
            return res
        names = {0x0000: "header", 0x0001: "string_ids", 0x0002: "type_ids",
                 0x0003: "proto_ids", 0x0004: "field_ids", 0x0005: "method_ids",
                 0x0006: "class_defs", 0x1000: "map_list", 0x2000: "type_list",
                 0x2001: "class_data", 0x2002: "code", 0x2003: "string_data",
                 0x2004: "debug_info", 0x2005: "annotation", 0x2006: "annotation_set",
                 0x2007: "annotations_directory", 0x2008: "annotation_set_list",
                 0x2009: "encoded_array", 0x200a: "method_handles",
                 0x200b: "call_sites", 0x200c: "call_site_ids",
                 0x200d: "method_handle_items", 0x2011: "hidden_class"}
        try:
            size = struct.unpack_from("<I", self.b, moff)[0]
            for i in range(min(size, 64)):
                p = moff + 4 + i * 12
                if p + 12 > len(self.b):
                    break
                t, _u, sz, _off = struct.unpack_from("<HHII", self.b, p)
                res[names.get(t, f"map_0x{t:04x}")] = sz
        except Exception:
            return {}
        return res

    # ---- code_item
    def decode_code(self, off: int, strs, types, protos, fids, mids) -> CodeInfo:
        b = self.b
        ci = CodeInfo()
        if off + 16 > len(b):
            ci.partial = True
            return ci
        regs, ins, outs, tries, _dbg, units = struct.unpack_from("<HHHHII", b, off)
        ci.registers, ci.ins_size, ci.outs_size = regs, ins, outs
        ci.tries = tries
        base = off + 16
        end = base + units * 2
        if end > len(b):
            ci.partial = True
            end = len(b)
        ci.unit_count = units
        ci.raw = b[base:end]
        i = base
        while i + 2 <= end:
            word = struct.unpack_from("<H", b, i)[0]
            lo = word & 0xFF
            spec = INSN.get(lo)
            if spec is None:
                ci.partial = True
                break
            width, kind = spec
            if i + width * 2 > end:
                ci.partial = True
                break
            if kind:
                if kind == "string":
                    sidx = (struct.unpack_from("<I", b, i + 2)[0] if lo == 0x1B
                            else struct.unpack_from("<H", b, i + 2)[0])
                    if sidx < len(strs) and strs[sidx] is not None:
                        ci.strings.append(strs[sidx])
                elif kind == "type":
                    tidx = struct.unpack_from("<H", b, i + 2)[0]
                    if tidx < len(types) and types[tidx]:
                        ci.const_classes.append(types[tidx])
                elif kind == "field":
                    fidx = struct.unpack_from("<H", b, i + 2)[0]
                    if fidx < len(fids):
                        c, t, n = fids[fidx]
                        owner, typ = types[c], types[t]
                        nm = strs[n]
                        if owner is not None and nm is not None:
                            dst = ci.writes if lo in _FIELD_WRITE else ci.reads
                            dst.append((owner, nm, typ))
                elif kind == "method":
                    midx = struct.unpack_from("<H", b, i + 2)[0]
                    if midx < len(mids):
                        c, pi, n = mids[midx]
                        owner = types[c]
                        params, ret = self._proto_of(protos, pi, types)
                        if owner is not None and strs[n] is not None:
                            ci.calls.append((_INVOKE_OPS.get(lo, "invoke-virtual"),
                                             owner, strs[n], params, ret))
            i += width * 2
            if lo in (0x2B, 0x2C):
                # switch payload: optional filler nop, ident u16, elem size, size
                j = i
                if j + 2 <= end and struct.unpack_from("<H", b, j)[0] == 0x0000:
                    j += 2
                if j + 8 <= end:
                    ident, esz, cnt = struct.unpack_from("<HHI", b, j)
                    if ident == 0x0100:
                        jump = 16 + cnt * 2
                    elif ident == 0x0200:
                        jump = 16 + cnt * 4
                    else:
                        jump = 0
                    if jump:
                        i = max(i, j + jump)
        return ci

    @staticmethod
    def _proto_of(protos, pi, types):
        if pi >= len(protos):
            return [], "V"
        _si, ri, params = protos[pi]
        return [types[p] for p in params], types[ri]

    # ---- annotations
    def read_annotation(self, off: int, strs, types):
        """annotation_item = ubyte visibility + encoded_annotation{type_idx, size, elements}。
        现行 DexFormat 把 visibility 提到 annotation_item 头上；早年 spec 写在
        encoded_annotation 里面（tidx, vis, size）。两种都认：先按现行布局读，
        校验不过再退回旧布局——只按一种读会把 code 区字节当成元素值收进来。"""
        b = self.b
        tidx, vis, size, p = self._ann_header(b, off)
        vals = {}
        for _ in range(size):
            name_i, p = uleb(b, p)
            v, p = self.read_encoded_value(b, p, strs, types, depth=0)
            if name_i < len(strs) and strs[name_i] is not None:
                vals[strs[name_i]] = v
        desc = types[tidx] if tidx < len(types) and types[tidx] is not None else "?"
        return desc, vis, vals, p

    @staticmethod
    def _ann_header(b, off):
        """解出 (type_idx, visibility, size, 元素起始位置)，现行布局优先。"""
        try:
            vis = b[off]
            tidx, q = uleb(b, off + 1)
            size, r = uleb(b, q)
            if vis in (0, 1, 2) and 0 <= size <= 4096:
                return tidx, vis, size, r
        except (IndexError, DexError):
            pass
        tidx, q = uleb(b, off)                       # 旧布局回退
        vis = b[q] if q < len(b) else -1
        size, r = uleb(b, q + 1)
        return tidx, vis, min(size, 4096), r

    @staticmethod
    def read_encoded_value(b, p, strs, types, depth=0):
        """encoded_value_item -- canonical VALUE_* tags (DexFormat 3.5.71)."""
        if depth >= 6:                                     # 元素套元素也有上限，别把整类注解炸掉
            return {"_depth": True}, p
        bt = b[p]
        p += 1
        vt = bt & 0x1F
        size = ((bt >> 5) & 7) + 1
        if vt == 0x1E:                                     # null
            return None, p
        if vt == 0x00:                                     # byte
            raw = b[p:p + size]; p += size
            v = int.from_bytes(raw, "little", signed=True)
            return v, p
        if vt == 0x02:                                     # short
            raw = b[p:p + size]; p += size
            return int.from_bytes(raw, "little", signed=True), p
        if vt == 0x03:                                     # char
            raw = b[p:p + size]; p += size
            n = int.from_bytes(raw, "little")
            return (chr(n) if 0 <= n < 0x110000 else n), p
        if vt == 0x04:                                     # int
            raw = b[p:p + size]; p += size
            return int.from_bytes(raw, "little", signed=True), p
        if vt == 0x06:                                     # long
            raw = b[p:p + size]; p += size
            return int.from_bytes(raw, "little", signed=True), p
        if vt == 0x10:                                     # float：合法宽度 2..4 字节
            raw = b[p:p + min(size, 4)]
            p += size                                      # 但仍按 size 前进，别错位
            raw = raw + b"\x00" * (4 - len(raw))
            bits = int.from_bytes(raw, "little", signed=False) & 0xFFFFFFFF
            return struct.unpack("<f", struct.pack("<I", bits))[0], p
        if vt == 0x11:                                     # double：合法宽度 3..8 字节
            raw = b[p:p + min(size, 8)]
            p += size
            raw = raw + b"\x00" * (8 - len(raw))
            bits = int.from_bytes(raw, "little", signed=False) & 0xFFFFFFFFFFFFFFFF
            return struct.unpack("<d", struct.pack("<Q", bits))[0], p
        if vt == 0x17:                                     # string index
            raw = b[p:p + size]; p += size
            n = int.from_bytes(raw, "little")
            return (strs[n] if n < len(strs) else n), p
        if vt == 0x18:                                     # type index
            raw = b[p:p + size]; p += size
            n = int.from_bytes(raw, "little")
            return (types[n] if n < len(types) else n), p
        if vt in (0x19, 0x1A):                             # field / method index
            raw = b[p:p + size]; p += size
            return {"ref_kind": "field" if vt == 0x19 else "method",
                    "index": int.from_bytes(raw, "little")}, p
        if vt == 0x1B:                                     # enum
            tidx, p = uleb(b, p)
            fidx, p = uleb(b, p)
            return {"enum": fidx, "type": types[tidx] if tidx < len(types) else "?"}, p
        if vt == 0x1C:                                     # array
            n, p = uleb(b, p)
            if n > 4096:                                   # 异常表头不放大读
                return {"_array": n}, p
            arr = []
            for _ in range(n):
                v, p = Dex.read_encoded_value(b, p, strs, types, depth + 1)
                arr.append(v)
            return arr, p
        if vt == 0x1D:                                     # nested annotation
            if depth >= 4:
                return None, p
            tidx, p = uleb(b, p)
            p += 1                                         # visibility byte
            n, p = uleb(b, p)
            inner = {}
            for _ in range(n):
                ni, p = uleb(b, p)
                v, p = Dex.read_encoded_value(b, p, strs, types, depth + 1)
                inner[strs[ni] if ni < len(strs) else str(ni)] = v
            owner = types[tidx] if tidx < len(types) else "?"
            return {"annotation": owner, "values": inner}, p
        if vt == 0x1F:                                     # boolean
            raw = b[p:p + size]; p += size
            return ("true" if int.from_bytes(raw, "little") else "false"), p
        p += size
        return None, p


# ---------------------------------------------------------------- main entry
def parse_dex(data: bytes, name: str = "classes.dex") -> DexFileData:
    d = Dex(data, name)
    strs = d.strings()
    tidxs = d.type_str_idx()
    types = [(strs[i] if i < len(strs) and strs[i] is not None else "?")
             for i in tidxs]
    protos = d.protos()
    fids = d.field_ids()
    mids = d.method_ids()
    notes: list[str] = []

    def as_desc(s):
        if s is None:
            return "?"
        if s.startswith("L") and s.endswith(";"):
            return s
        if s.startswith("["):
            return s
        if s in ("V", "Z", "B", "S", "I", "J", "F", "D"):
            return s
        return "L" + s + ";"

    type_desc = [as_desc(t) for t in types]

    def proto_of(pi):
        if pi >= len(protos):
            return [], "V", "?"
        si, ri, params = protos[pi]
        return ([type_desc[p] for p in params if p < len(type_desc)],
                type_desc[ri] if ri < len(type_desc) else "V",
                strs[si] if si < len(strs) and strs[si] is not None else "?")

    classes: list[ClassInfo] = []
    for cd in d.class_def_items():
        desc = type_desc[cd["class_idx"]] if cd["class_idx"] < len(type_desc) else "?"
        sup = (None if cd["super_idx"] == 0xFFFFFFFF or
               cd["super_idx"] >= len(type_desc) else type_desc[cd["super_idx"]])
        ifaces: list[str] = []
        if cd["ifaces_off"]:
            try:
                n = struct.unpack_from("<I", d.b, cd["ifaces_off"])[0]
                raw = struct.unpack_from(f"<{n}H", d.b, cd["ifaces_off"] + 4)
                ifaces = [type_desc[i] for i in raw if i < len(type_desc)]
            except Exception:
                notes.append(f"{desc}: interfaces 解析失败")
        src = None
        if cd["source_off"]:
            try:
                _n, q = uleb(d.b, cd["source_off"])
                src, _ = mutf8(d.b, q)
            except Exception:
                src = None
        flds: list[FieldInfo] = []
        meths: list[MethodInfo] = []
        if cd["class_data_off"]:
            p = cd["class_data_off"]
            ns, p = uleb(d.b, p)
            ni, p = uleb(d.b, p)
            nd, p = uleb(d.b, p)
            nv, p = uleb(d.b, p)

            def read_fields(count, static, p):
                out = []
                idx = acc = 0
                for _ in range(count):
                    di, p = uleb(d.b, p)
                    da, p = uleb(d.b, p)
                    idx += di
                    acc = da
                    if idx < len(fids):
                        c, t, n = fids[idx]
                        nm = strs[n] if n < len(strs) else "?"
                        out.append(FieldInfo(nm or "?",
                                             type_desc[t] if t < len(type_desc) else "?",
                                             acc, static))
                    else:
                        notes.append(f"{desc}: field_idx {idx} 越界")
                return out, p

            def read_methods(count, p):
                out = []
                idx = acc = 0
                for _ in range(count):
                    di, p = uleb(d.b, p)
                    da, p = uleb(d.b, p)
                    coff, p = uleb(d.b, p)
                    idx += di
                    acc = da
                    if idx >= len(mids):
                        notes.append(f"{desc}: method_idx {idx} 越界")
                        continue
                    c, pi, n = mids[idx]
                    params, ret, shorty = proto_of(pi)
                    code = None
                    if coff:
                        try:
                            code = d.decode_code(coff, strs, type_desc, protos,
                                                 fids, mids)
                        except Exception as e:                     # never fatal
                            code = CodeInfo(partial=True)
                            notes.append(f"{desc}#{strs[n]}: code 解码异常 {e}")
                    nm = strs[n] if n < len(strs) else "?"
                    out.append((MethodInfo(nm or "?", params, ret, shorty, acc, code),
                                idx, coff))
                return out, p

            flds_static, p = read_fields(ns, True, p)
            flds_inst, p = read_fields(ni, False, p)
            flds = flds_static + flds_inst
            dm, p = read_methods(nd, p)
            vm, p = read_methods(nv, p)
            meths = [m for m, _i, _c in dm + vm]
        # annotations directory
        annos: list[AnnotationInfo] = []
        bad = [0]            # 本类里读失败的注解条数
        if cd["ann_off"]:
            try:
                coff, _nf, _nm, _np = struct.unpack_from("<IIII", d.b, cd["ann_off"])
                q = cd["ann_off"] + 16

                def set_items(off_a: int):
                    """annotation_set_item：uint size + size 个 uint annotation_off。"""
                    if not off_a or off_a + 4 > len(d.b):
                        return []
                    cnt = struct.unpack_from("<I", d.b, off_a)[0]
                    if cnt > 4096:                        # 表头异常就不放大读
                        return []
                    out_a, rr = [], off_a + 4
                    for _ in range(cnt):
                        o2, rr = u32(d.b, rr)
                        if o2:
                            out_a.append(o2)
                    return out_a

                for ao in set_items(coff):                # 类级注解
                    try:
                        da, vis, vals, _ = d.read_annotation(ao, strs, type_desc)
                    except Exception:
                        bad[0] += 1                       # 一条读歪不拖垮整类
                        continue
                    if usable_annotation(da, vis):
                        annos.append(AnnotationInfo(da, vis, vals))
                q += _nf * 8                              # field_annotation: uint+uint
                for _ in range(_nm):                      # method_annotation
                    mi, q = u32(d.b, q)
                    ao, q = u32(d.b, q)
                    if not ao or mi >= len(mids):
                        continue
                    ni = mids[mi][2]
                    nm = strs[ni] if ni < len(strs) else "?"
                    for ao2 in set_items(ao):
                        try:
                            da, vis, vals, _ = d.read_annotation(ao2, strs, type_desc)
                        except Exception:
                            bad[0] += 1
                            continue
                        if usable_annotation(da, vis):
                            annos.append(AnnotationInfo(da, vis, vals, on_method=nm))
            except Exception as e:
                # 带上出错位置：这段是 try 包住整类注解，静默降级过一次就别再哑了
                if bad[0]:
                    notes.append(f"{desc}: 跳过 {bad[0]} 条读不出的注解")
                else:
                    tb = traceback.extract_tb(sys.exc_info()[2])[-1]
                    notes.append(f"{desc}: annotations 目录解析失败 {type(e).__name__}: {e}"
                                 f" @dex.py:{tb.lineno}")
        if bad[0]:
            notes.append(f"{desc}: 跳过 {bad[0]} 条读不出的注解")
        classes.append(ClassInfo(descriptor=desc, access=cd["access"],
                                 super_descriptor=sup, interfaces=ifaces,
                                 source_file=src, fields=flds, methods=meths,
                                 annotations=annos))
    counts = {
        "string_ids": d.string_ids_size, "type_ids": d.type_ids_size,
        "proto_ids": d.proto_ids_size, "field_ids": d.field_ids_size,
        "method_ids": d.method_ids_size, "class_defs": d.class_defs_size,
        "method_handles": d.map_counts().get("method_handles", 0),
        "call_sites": d.map_counts().get("call_sites", 0),
        "code_items": sum(1 for c in classes for m in c.methods if m.code),
    }
    return DexFileData(name=name, size_bytes=len(data), version=d.version,
                       counts=counts, classes=classes,
                       strings=[s for s in strs if s is not None],
                       parse_notes=notes[:20])
