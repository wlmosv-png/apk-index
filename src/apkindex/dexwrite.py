"""dexwrite — build a valid classes.dex from scratch (test fixtures only).

Deferred instruction encoding: fixture code refers to strings/types/fields/
methods symbolically, and indices are patched in after the id sections are
ordered -- which is the only way to satisfy the dex ordering rules by hand.
Pure stdlib; nothing here is used at query time.
"""
from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass, field as _f

from .dex import (ACC_PUBLIC, ACC_STATIC, ACC_PRIVATE, ACC_CONSTRUCTOR,
                  uleb_enc, mutf8_enc, DexError)

HEADER_SIZE = 0x70
ENDIAN_TAG = 0x12345678
_WIDE = {"J", "D"}


def _sc(t: str) -> str:
    if t.startswith("[") or t.startswith("L"):
        return "L"
    return t if t in "VZBSIJFD" else "L"


# ------------------------------------------------------------------ refs
@dataclass(frozen=True)
class Proto:
    ret: str
    params: tuple

    @property
    def shorty(self) -> str:
        return "".join([_sc(self.ret)] + [_sc(p) for p in self.params])


@dataclass(frozen=True)
class FieldRef:
    owner: str
    name: str
    type: str


@dataclass(frozen=True)
class MethodRef:
    owner: str
    name: str
    proto: Proto


class S:      # string reference
    __slots__ = ("v",)

    def __init__(self, v):
        self.v = v


class T:      # type reference
    __slots__ = ("v",)

    def __init__(self, v):
        self.v = v


# ------------------------------------------------- deferred dalvik insns
class DI:
    """Instruction factories producing (format, opcode, operands...) tuples."""

    @staticmethod
    def ret_void():
        return ("10x", 0x0E)

    @staticmethod
    def ret_obj(v=0):
        return ("10x?", 0x11, v)

    @staticmethod
    def ret_int(v=0):
        return ("10x?", 0x0F, v)

    @staticmethod
    def move_obj(dst, src):
        return ("12x", 0x07, dst, src)

    @staticmethod
    def move_res_obj(v=0):
        return ("10x?", 0x0C, v)

    @staticmethod
    def move_res(v=0):
        return ("10x?", 0x0A, v)

    @staticmethod
    def const4(v, lit):
        return ("11n", 0x12, v, lit)

    @staticmethod
    def const16(v, lit):
        return ("21s", 0x13, v, lit)

    @staticmethod
    def const_string(v, s):
        return ("21c", 0x1A, v, s if isinstance(s, S) else S(s))

    @staticmethod
    def const_class(v, t):
        return ("21c", 0x1C, v, t if isinstance(t, T) else T(t))

    @staticmethod
    def new_instance(v, t):
        return ("21c", 0x22, v, t if isinstance(t, T) else T(t))

    @staticmethod
    def check_cast(v, t):
        return ("21c", 0x1F, v, t if isinstance(t, T) else T(t))

    @staticmethod
    def iget(dst, obj, fr):
        return ("22c", 0x54, dst, obj, fr)

    @staticmethod
    def iget_int(dst, obj, fr):
        return ("22c", 0x52, dst, obj, fr)

    @staticmethod
    def iput(val, obj, fr):
        return ("22c", 0x5B, val, obj, fr)

    @staticmethod
    def sget(dst, fr):
        return ("21c", 0x62, dst, fr)

    @staticmethod
    def sput(src, fr):
        return ("21c", 0x69, src, fr)

    @staticmethod
    def invoke(kind, regs, mr):
        op = {"virtual": 0x6E, "super": 0x6F, "direct": 0x70,
              "static": 0x71, "interface": 0x72}[kind]
        return ("35c", op, list(regs), mr)

    @staticmethod
    def invoke_range(kind, first, count, mr):
        op = {"virtual": 0x75, "super": 0x76, "direct": 0x77,
              "static": 0x71, "interface": 0x74}[kind]
        return ("3rc", op, first, count, mr)

    @staticmethod
    def if_eqz(v, off=0):
        return ("21t", 0x38, v, off)

    @staticmethod
    def goto(off=0):
        return ("10t", 0x28, off)

    @staticmethod
    def throw(v=0):
        return ("10x?", 0x27, v)


def _encode(ins, M, sh=0):
    """Encode one deferred instruction into code units.  ``sh`` re-bases every
    register operand, so fixture code may reference parameters as v0..vN no
    matter how large the final register window turns out to be."""
    fmt, op = ins[0], ins[1]

    def R(v):
        return (v + sh) & 0xFF

    if fmt == "10x":
        return [op]
    if fmt == "10x?":                       # 11x
        return [op | (R(ins[2]) << 8)]
    if fmt == "12x":
        return [op | (R(ins[2]) << 8) | (R(ins[3]) << 4)]
    if fmt == "11n":
        return [op | (R(ins[2]) << 8) | ((ins[3] & 0xF) << 4)]
    if fmt == "21s":
        return [op | (R(ins[2]) << 8), ins[3] & 0xFFFF]
    if fmt == "21t":
        return [op | (R(ins[2]) << 8), ins[3] & 0xFFFF]
    if fmt == "10t":
        return [op | (ins[2] & 0xFF)]
    if fmt == "21c":
        return [op | (R(ins[2]) << 8), M.idx_of(ins[3]) & 0xFFFF]
    if fmt == "22c":
        return [op | (R(ins[3]) << 8) | (R(ins[2]) << 12),
                M.idx_of(ins[4]) & 0xFFFF]
    if fmt == "35c":
        regs = ins[2]
        if len(regs) > 5:
            raise DexError("35c 最多 5 个寄存器")
        w2 = 0
        for i, r in enumerate(regs):
            w2 |= (R(r) & 0xF) << (i * 4)
        return [op | (len(regs) << 12), M.idx_of(ins[3]) & 0xFFFF, w2]
    if fmt == "3rc":
        return [op | ((R(ins[2]) & 0xFF) << 8), M.idx_of(ins[4]) & 0xFFFF, ins[3]]
    raise DexError(f"未知指令格式 {fmt}")


@dataclass
class EncMethod:
    ref: MethodRef
    access: int
    insns: list = _f(default_factory=list)
    locals: int = 0
    outs: int = 3
    annotations: list = _f(default_factory=list)
    code_off: int = 0
    idx: int = -1

    @property
    def ins_size(self):
        n = sum(2 if t in _WIDE else 1 for t in self.ref.proto.params)
        return n + (0 if self.access & ACC_STATIC else 1)

    def reg_operands(self):
        out = []
        for ins in self.insns:
            fmt = ins[0]
            if fmt in ("10x?", "11n", "21s", "21t", "21c"):
                out.append(ins[2])
            elif fmt in ("12x", "22c"):
                out.extend((ins[2], ins[3]))
            elif fmt == "35c":
                out.extend(ins[2])
            elif fmt == "3rc":
                out.extend(range(ins[2], ins[2] + ins[3]))
        return [x for x in out if isinstance(x, int)]

    @property
    def total_registers(self):
        hi = max(self.reg_operands(), default=-1)
        return max(self.ins_size, self.outs, hi + 1, self.ins_size + self.locals)

    @property
    def shift(self):
        return self.total_registers - self.ins_size

    @property
    def registers(self):
        return self.total_registers


@dataclass
class EncField:
    ref: FieldRef
    access: int
    idx: int = -1


@dataclass
class ClassDef:
    desc: str
    access: int
    super_: str | None
    ifaces: tuple
    source: str | None
    fields: list = _f(default_factory=list)
    methods: list = _f(default_factory=list)
    annotations: list = _f(default_factory=list)


class _Maps:
    def __init__(self, sid, tid, fid, mid):
        self.sid, self.tid, self.fid, self.mid = sid, tid, fid, mid

    def idx_of(self, ref):
        if not isinstance(ref, (S, T, FieldRef, MethodRef)):
            ref = getattr(ref, "ref", ref)      # EncField / EncMethod wrappers
        if isinstance(ref, S):
            return self.sid[ref.v]
        if isinstance(ref, T):
            return self.tid[ref.v]
        if isinstance(ref, FieldRef):
            return self.fid[(ref.owner, ref.name, ref.type)]
        if isinstance(ref, MethodRef):
            return self.mid[(ref.owner, ref.name, ref.proto.ret, ref.proto.params)]
        raise DexError(f"无法解析引用 {ref!r}")


class DexBuilder:
    """Small dex assembler used by tests/make_fixture.py."""

    def __init__(self):
        self.classes: list[ClassDef] = []
        self._strings: set[str] = set()
        self._types: set[str] = set()
        self._protos: dict[tuple, Proto] = {}
        self._fields: dict[tuple, FieldRef] = {}
        self._methods: dict[tuple, MethodRef] = {}

    # ------------------------------------------------------------ interning
    def string(self, s: str) -> str:
        self._strings.add(s)
        return s

    def type(self, desc: str) -> str:
        self._types.add(desc)
        return desc

    def proto(self, ret: str, params=()) -> Proto:
        p = Proto(ret, tuple(params))
        self._protos.setdefault((p.ret, p.params), p)
        return self._protos[(p.ret, p.params)]

    def field(self, owner: str, name: str, type_: str) -> FieldRef:
        fr = FieldRef(owner, name, type_)
        self._fields.setdefault((owner, name, type_), fr)
        return self._fields[(owner, name, type_)]

    def method(self, owner: str, name: str, ret: str, params=()) -> MethodRef:
        mr = MethodRef(owner, name, self.proto(ret, params))
        self._methods.setdefault((owner, name, mr.proto.ret, mr.proto.params), mr)
        return self._methods[(owner, name, mr.proto.ret, mr.proto.params)]

    # ------------------------------------------------------------ structure
    def add_class(self, desc, access=ACC_PUBLIC, super_="Ljava/lang/Object;",
                  ifaces=(), source=None) -> ClassDef:
        c = ClassDef(desc, access, super_, tuple(ifaces), source)
        self.classes.append(c)
        return c

    def add_field(self, c: ClassDef, name, type_, access=0, static=False) -> EncField:
        ef = EncField(self.field(c.desc, name, type_),
                      access | (ACC_STATIC if static else 0))
        c.fields.append(ef)
        return ef

    def add_method(self, c: ClassDef, name, ret="V", params=(), access=0,
                   insns=None, locals_=0, outs=3, ctor=False) -> EncMethod:
        if ctor:
            access |= ACC_CONSTRUCTOR
        em = EncMethod(self.method(c.desc, name, ret, params), access,
                       list(insns or []), locals_, outs)
        c.methods.append(em)
        return em

    def add_annotation(self, target, desc, values=None):
        vals = dict(values or {})
        self.type(desc)
        for k, v in vals.items():
            self.string(k)
            if isinstance(v, str):
                self.string(v)
        target.annotations.append((desc, vals))
        return target

    # ------------------------------------------------------------ assembly
    def build(self) -> bytes:
        for c in self.classes:
            self._types.add(c.desc)
            if c.super_:
                self._types.add(c.super_)
            for i in c.ifaces:
                self._types.add(i)
            if c.source:
                self._strings.add(c.source)
            for f in c.fields:
                f.ref = FieldRef(c.desc, f.ref.name, f.ref.type)
                self._fields[(f.ref.owner, f.ref.name, f.ref.type)] = f.ref
                self._types.add(f.ref.type)
                self._strings.add(f.ref.name)
            for m in c.methods:
                m.ref = MethodRef(c.desc, m.ref.name, m.ref.proto)
                self._methods[(m.ref.owner, m.ref.name, m.ref.proto.ret,
                               m.ref.proto.params)] = m.ref
                self._strings.add(m.ref.name)
                self._strings.add(m.ref.proto.shorty)
                for p in (m.ref.proto.ret,) + m.ref.proto.params:
                    self._types.add(p)
            for _d, v in c.annotations:
                self._strings.update(v.keys())
                self._strings.update(x for x in v.values() if isinstance(x, str))
        self._collect_refs()
        # every referenced proto needs its shorty + types interned, including
        # protos of external methods that are never declared as a ClassDef.
        for pr in list(self._protos.values()):
            self._strings.add(pr.shorty)
            self._types.add(pr.ret)
            for x in pr.params:
                self._types.add(x)
        for mr in list(self._methods.values()):
            self._strings.add(mr.name)
            self._types.add(mr.owner)
        for fr in list(self._fields.values()):
            self._strings.add(fr.name)
            self._types.add(fr.owner)
            self._types.add(fr.type)
        for d, v in [(a[0], a[1]) for c in self.classes for a in c.annotations]:
            self._types.add(d)
        for c in self.classes:
            for m in c.methods:
                for d, v in m.annotations:
                    self._types.add(d)
                    self._strings.update(v.keys())
                    self._strings.update(x for x in v.values() if isinstance(x, str))

        sid = self._order_strings()
        tid = self._order_types(sid)
        pid = self._order_protos(sid, tid)
        fid = self._order_fields(sid, tid)
        mid = self._order_methods(sid, tid, pid)
        M = _Maps(sid, tid, fid, mid)
        for c in self.classes:
            for f in c.fields:
                f.idx = fid[(f.ref.owner, f.ref.name, f.ref.type)]
            for m in c.methods:
                p = m.ref.proto
                m.idx = mid[(m.ref.owner, m.ref.name, p.ret, p.params)]

        n_str, n_typ, n_pro = len(sid), len(tid), len(pid)
        n_fld, n_met, n_cls = len(fid), len(mid), len(self.classes)
        so, to, po = HEADER_SIZE, HEADER_SIZE + 4 * n_str, 0
        to = so + 4 * n_str
        po = to + 4 * n_typ
        fo = po + 12 * n_pro
        mo = fo + 8 * n_fld
        co = mo + 8 * n_met
        d_base = co + 32 * n_cls

        data = bytearray()

        def pad(n=4):
            data.extend(b"\x00" * ((-len(data)) % n))

        def AB(o):
            return d_base + o

        str_off = {}
        for s, i in sorted(sid.items(), key=lambda kv: kv[1]):
            str_off[i] = len(data)
            data += uleb_enc(len(s)) + mutf8_enc(s)

        proto_param_off = {}
        for key, pi in sorted(pid.items(), key=lambda kv: kv[1]):
            p = self._protos[key]
            if not p.params:
                continue
            pad()
            proto_param_off[pi] = len(data)
            data += struct.pack("<I", len(p.params))
            for x in p.params:
                data += struct.pack("<H", tid[x])

        iface_off = {}
        for c in sorted(self.classes, key=lambda x: tid[x.desc]):
            if not c.ifaces:
                continue
            pad()
            iface_off[c.desc] = len(data)
            data += struct.pack("<I", len(c.ifaces))
            for i in c.ifaces:
                data += struct.pack("<H", tid[i])

        for c in self.classes:
            for m in c.methods:
                units = []
                for ins in m.insns:
                    units.extend(_encode(ins, M, m.shift))
                if not units:
                    continue
                if len(units) % 2:
                    units.append(0)
                pad()
                m.code_off = AB(len(data))
                data += struct.pack("<HHHHII", m.registers, m.ins_size,
                                    min(m.outs, m.total_registers), 0, 0, len(units))
                for u in units:
                    data += struct.pack("<H", u & 0xFFFF)

        def vis_of(_desc, _vals):
            """默认 RUNTIME(0x01)：写模块时最关心的就是运行期还在的注解。"""
            return 0x01

        def emit_annotation(desc, vals):
            pad()
            off = len(data)
            # 现行 DexFormat：annotation_item = ubyte visibility + encoded_annotation
            # （visibility 在 encoded_annotation 里是早年 spec 的写法，d8 不这么发）
            body = bytes([vis_of(desc, vals)]) + uleb_enc(tid[desc]) + uleb_enc(len(vals))
            for k, v in vals.items():
                body += uleb_enc(sid[k])
                if isinstance(v, str):
                    idx = sid[v]
                    nb = max(1, (idx.bit_length() + 7) // 8)
                    body += bytes([((nb - 1) << 5) | 0x17]) + idx.to_bytes(nb, "little")
                elif isinstance(v, bool):
                    body += bytes([(0 << 5) | 0x1F, 1 if v else 0])
                elif isinstance(v, int):
                    nb = 4
                    body += bytes([((nb - 1) << 5) | 0x04]) + \
                        (v & 0xFFFFFFFF).to_bytes(nb, "little")
                elif isinstance(v, float):
                    body += bytes([((4 - 1) << 5) | 0x10]) + \
                        struct.pack("<f", v)
                else:
                    continue
            data.extend(body)
            return AB(off)

        def emit_set(offs):
            pad()
            off = len(data)
            # annotation_set_item = uint size + uint offset[size]
            # （早先写的是 uleb，读端按 uint 走 → 偏移错位，整条注解解析失败）
            data.extend(struct.pack("<I", len(offs)))
            for o in offs:
                data.extend(struct.pack("<I", o))
            pad()
            return AB(off)

        dir_off = {}
        for c in self.classes:
            meth_entries = []
            for m in c.methods:
                if m.annotations:
                    items = [emit_annotation(d, v) for d, v in m.annotations]
                    meth_entries.append((m.idx, emit_set(items)))
            if not c.annotations and not meth_entries:
                continue
            class_set = emit_set([emit_annotation(d, v)
                                  for d, v in c.annotations]) if c.annotations else 0
            # annotations_directory_item: class_annotations_off, fields_size,
            # annotated_methods_size, annotated_parameters_size
            blob = bytearray(struct.pack("<IIII", class_set, 0, len(meth_entries), 0))
            for i, o in sorted(meth_entries):
                blob += uleb_enc(i) + uleb_enc(o)
            pad()
            dir_off[c.desc] = AB(len(data))
            data += blob

        cd_off = {}
        for c in self.classes:
            st = sorted([f for f in c.fields if f.access & ACC_STATIC], key=lambda x: x.idx)
            ins_f = sorted([f for f in c.fields if not f.access & ACC_STATIC],
                           key=lambda x: x.idx)
            dm = sorted([m for m in c.methods if (m.access & ACC_STATIC) or
                         (m.access & ACC_PRIVATE) or m.ref.name == "<init>"],
                        key=lambda x: x.idx)
            dm_ids = {id(m) for m in dm}
            vm = sorted([m for m in c.methods if id(m) not in dm_ids],
                        key=lambda x: x.idx)
            blob = bytearray(uleb_enc(len(st)) + uleb_enc(len(ins_f)) +
                             uleb_enc(len(dm)) + uleb_enc(len(vm)))
            for lst in (st, ins_f):
                prev = 0
                for f in lst:
                    blob += uleb_enc(f.idx - prev) + uleb_enc(f.access)
                    prev = f.idx
            for lst in (dm, vm):
                prev = 0
                for m in lst:
                    blob += uleb_enc(m.idx - prev) + uleb_enc(m.access) + \
                        uleb_enc(m.code_off)
                    prev = m.idx
            cd_off[c.desc] = AB(len(data))
            data += blob

        pad()
        map_local = len(data)
        n_code = sum(1 for c in self.classes for m in c.methods if m.code_off)
        n_tlist = sum(1 for pr in self._protos.values() if pr.params)
        # real d8 emits the HEADER_ITEM map entry with offset 0
        sections = [(0x0000, 1, 0), (0x0001, n_str, so),
                    (0x0002, n_typ, to), (0x0003, n_pro, po),
                    (0x0004, n_fld, fo), (0x0005, n_met, mo),
                    (0x0006, n_cls, co)]
        if n_tlist:
            sections.append((0x2000, n_tlist,
                             min(AB(o) for o in proto_param_off.values())))
        if n_code:
            sections.append((0x2002, n_code,
                             min(m.code_off for c in self.classes
                                 for m in c.methods if m.code_off)))
        sections.append((0x1000, 1, AB(map_local)))
        sections.sort(key=lambda t: t[2])
        mblob = bytearray(struct.pack("<I", len(sections)))
        for t, n, off in sections:
            mblob += struct.pack("<HHII", t, 0, n, off)
        data += mblob
        map_size = len(data) - map_local

        ids = bytearray()
        for i in range(n_str):
            ids += struct.pack("<I", AB(str_off[i]))
        for d, i in sorted(tid.items(), key=lambda kv: kv[1]):
            ids += struct.pack("<I", sid[d[1:-1] if d.startswith("L") else d])
        for key, pi in sorted(pid.items(), key=lambda kv: kv[1]):
            p = self._protos[key]
            ids += struct.pack("<III", sid[p.shorty], tid[p.ret],
                               AB(proto_param_off[pi]) if pi in proto_param_off else 0)
        for key, i in sorted(fid.items(), key=lambda kv: kv[1]):
            owner, name, type_ = key
            ids += struct.pack("<HHI", tid[owner], tid[type_], sid[name])
        for key, i in sorted(mid.items(), key=lambda kv: kv[1]):
            owner, name, ret, prm = key
            ids += struct.pack("<HHI", tid[owner], pid[(ret, prm)], sid[name])
        for c in sorted(self.classes, key=lambda x: tid[x.desc]):
            ids += struct.pack("<8I", tid[c.desc], c.access,
                               0xFFFFFFFF if not c.super_ else tid[c.super_],
                               AB(iface_off[c.desc]) if c.desc in iface_off else 0,
                               AB(str_off[sid[c.source]]) if c.source else 0,
                               dir_off.get(c.desc, 0), cd_off[c.desc], 0)

        hdr = struct.pack(
            "<8sI20s20I", b"dex\n035\x00", 0, b"\x00" * 20,
            0, HEADER_SIZE, ENDIAN_TAG, 0, 0, AB(map_local),
            n_str, so, n_typ, to, n_pro, po, n_fld, fo, n_met, mo,
            n_cls, co, len(data), d_base)
        out = bytearray(hdr) + ids + bytes(data)
        if len(out) % 4:
            out += b"\x00" * (4 - len(out) % 4)
        struct.pack_into("<I", out, 32, len(out))
        out[12:32] = hashlib.sha1(bytes(out[32:])).digest()
        struct.pack_into("<I", out, 8, zlib.adler32(bytes(out[12:]), 1))
        return bytes(out)

    # ------------------------------------------------------------ ref sweep
    def _collect_refs(self):
        """Walk every deferred instruction so nothing referenced only from
        code is missing from the id sections."""
        for c in self.classes:
            for m in c.methods:
                for ins in m.insns:
                    for operand in ins[1:] if len(ins) > 1 else ():
                        if isinstance(operand, (S, T)):
                            if isinstance(operand, S):
                                self._strings.add(operand.v)
                            else:
                                self._types.add(operand.v)
                        elif isinstance(operand, MethodRef):
                            self._methods.setdefault(
                                (operand.owner, operand.name, operand.proto.ret,
                                 operand.proto.params), operand)
                            self._strings.add(operand.name)
                            self._strings.add(operand.proto.shorty)
                            self._types.add(operand.owner)
                            for p in (operand.proto.ret,) + operand.proto.params:
                                self._types.add(p)
                        elif isinstance(operand, FieldRef):
                            self._fields.setdefault(
                                (operand.owner, operand.name, operand.type), operand)
                            self._strings.add(operand.name)
                            self._types.add(operand.owner)
                            self._types.add(operand.type)
                        elif isinstance(operand, (list, tuple)):
                            for x in operand:
                                if isinstance(x, T):
                                    self._types.add(x.v)

    # ------------------------------------------------------------ orderings
    def _order_strings(self):
        vals = set(self._strings)
        for t in self._types:
            vals.add(t[1:-1] if t.startswith("L") else t)
        ordered = sorted(vals, key=lambda s: [ord(ch) for ch in s])
        return {s: i for i, s in enumerate(ordered)}

    def _order_types(self, sid):
        ordered = sorted(self._types,
                         key=lambda t: sid[t[1:-1] if t.startswith("L") else t])
        return {t: i for i, t in enumerate(ordered)}

    def _order_protos(self, sid, tid):
        items = sorted(self._protos.values(),
                       key=lambda p: (sid[p.shorty], tid[p.ret],
                                      tuple(tid[x] for x in p.params)))
        return {(p.ret, p.params): i for i, p in enumerate(items)}

    def _order_fields(self, sid, tid):
        items = sorted(self._fields.values(),
                       key=lambda f: (tid[f.owner], sid[f.name], tid[f.type]))
        return {(f.owner, f.name, f.type): i for i, f in enumerate(items)}

    def _order_methods(self, sid, tid, pid):
        items = sorted(self._methods.values(),
                       key=lambda m: (tid[m.owner], sid[m.name],
                                      pid[(m.proto.ret, m.proto.params)]))
        return {(m.owner, m.name, m.proto.ret, m.proto.params): i
                for i, m in enumerate(items)}
