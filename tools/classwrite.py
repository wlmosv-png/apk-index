"""Minimal Java .class emitter (constant pool + one Code attribute per method).

Only what the fixture needs: public classes/interfaces, String constants in
method bodies, method/field refs.  Written so that apkindex.classfile can be
round-trip tested without a JVM.
"""
from __future__ import annotations

import struct

U1, U2, U4 = 1, 2, 4

OP_NOP = 0x00
OP_LDC = 0x12
OP_LDC_W = 0x13
OP_INVOKEVIRTUAL = 0xB6
OP_INVOKESPECIAL = 0xB7
OP_INVOKESTATIC = 0xB8
OP_INVOKEINTERFACE = 0xB9
OP_ALOAD_0 = 0x2A
OP_ARETURN = 0xB0
OP_RETURN = 0xB1
OP_GETFIELD = 0xB4
OP_PUTFIELD = 0xB5
OP_GETSTATIC = 0xB2
OP_BIPUSH = 0x10
OP_IRETURN = 0xAC


class Cp:
    def __init__(self):
        self.items: list[tuple] = []
        self.index: dict[tuple, int] = {}

    def add(self, key, encoded):
        if key in self.index:
            return self.index[key]
        i = len(self.items) + 1
        self.items.append(encoded)
        self.index[key] = i
        if encoded[0] in ("Long", "Double"):
            self.items.append(None)
        return i

    def utf8(self, s):
        b = s.encode("utf-8")
        return self.add(("Utf8", s), ("Utf8", b))

    def cls(self, name):
        return self.add(("Class", name), ("Class", self.utf8(name)))

    def string(self, s):
        return self.add(("String", s), ("String", self.utf8(s)))

    def name_and_type(self, name, desc):
        return self.add(("NameAndType", name, desc),
                        ("NameAndType", self.utf8(name), self.utf8(desc)))

    def methodref(self, owner, name, desc, iface=False):
        key = ("InterfaceMethodref" if iface else "Methodref", owner, name, desc)
        kind = "InterfaceMethodref" if iface else "Methodref"
        return self.add(key, (kind, self.cls(owner.replace(".", "/")),
                              self.name_and_type(name, desc)))

    def fieldref(self, owner, name, desc):
        return self.add(("Fieldref", owner, name, desc),
                        ("Fieldref", self.cls(owner.replace(".", "/")),
                         self.name_and_type(name, desc)))

    def serialize(self) -> bytes:
        out = bytearray()
        for it in self.items:
            if it is None:
                continue
            tag = it[0]
            if tag == "Utf8":
                out += b"\x01" + struct.pack("!H", len(it[1])) + it[1]
            elif tag == "Class":
                out += b"\x07" + struct.pack("!H", it[1])
            elif tag == "String":
                out += b"\x08" + struct.pack("!H", it[1])
            elif tag == "Fieldref":
                out += b"\x09" + struct.pack("!HH", it[1], it[2])
            elif tag == "Methodref":
                out += b"\x0a" + struct.pack("!HH", it[1], it[2])
            elif tag == "InterfaceMethodref":
                out += b"\x0b" + struct.pack("!HH", it[1], it[2])
            elif tag == "NameAndType":
                out += b"\x0c" + struct.pack("!HH", it[1], it[2])
            elif tag == "Integer":
                out += b"\x03" + struct.pack("!i", it[1])
            else:
                raise ValueError("unsupported cp entry " + tag)
        return bytes(out)


def _code(body: bytes, stack=2, locals_=2) -> bytes:
    return (struct.pack("!Hhh", stack, locals_, len(body)) + body
            + struct.pack("!H", 0) + struct.pack("!H", 0))


def _method(cp: Cp, name: str, desc: str, flags: int, body: bytes) -> bytes:
    attrs = b""
    if body is not None:
        code = _code(body)
        attrs = (struct.pack("!H", cp.utf8("Code"))
                 + struct.pack("!I", len(code)) + code)
    return struct.pack("!HHH", flags, cp.utf8(name), cp.utf8(desc)) \
        + struct.pack("!H", len(attrs and [1] or [])) + attrs


def _field(cp: Cp, name: str, desc: str, flags: int) -> bytes:
    return struct.pack("!HHH", flags, cp.utf8(name), cp.utf8(desc)) \
        + struct.pack("!H", 0)


def build_class(binary_name: str, super_name: str = "java/lang/Object",
                interfaces=(), flags: int = 0x0021, fields=(),
                methods=()) -> bytes:
    """fields: (name, desc, flags) ; methods: (name, desc, flags, body).

    ``body`` is raw bytecode, ``None`` (abstract/native), or a callable
    ``f(cp) -> bytes`` that interns constants into the class constant pool --
    the only safe way to emit ldc/invoke* references.
    """
    cp = Cp()
    methods = [(n, d, f, (b(cp) if callable(b) else b)) for n, d, f, b in methods]
    this_i = cp.cls(binary_name)
    sup_i = cp.cls(super_name)
    ifc_i = [cp.cls(i) for i in interfaces]
    iface_flag = 0x0200 if interfaces and "Marker" in super_name else 0
    body_out = bytearray()
    for name, desc, fl, body in methods:
        body_out += _method(cp, name, desc, fl, body)
    field_out = bytearray()
    for name, desc, fl in fields:
        field_out += _field(cp, name, desc, fl)
    attrs = b""
    if fields or methods:
        pass
    n_attrs = 1
    src = b""
    srcname = "%s.java" % binary_name.rsplit("/", 1)[-1]
    payload = struct.pack("!H", cp.utf8(srcname))   # 索引是 u2，不是 u4
    src = struct.pack("!H", cp.utf8("SourceFile")) + struct.pack("!I", 2) + payload
    out = struct.pack("!I", 0xCAFEBABE) + struct.pack("!HH", 0, 52)
    out += struct.pack("!H", len(cp.items) + 1) + cp.serialize()
    out += struct.pack("!HHH", flags | iface_flag, this_i, sup_i)
    out += struct.pack("!H", len(ifc_i)) + b"".join(struct.pack("!H", i) for i in ifc_i)
    out += struct.pack("!H", len(fields)) + bytes(field_out)
    out += struct.pack("!H", len(methods)) + bytes(body_out)
    out += struct.pack("!H", n_attrs) + src
    return out


# convenience bodies ------------------------------------------------------
def body_return_this(cp, field_owner=None):
    return bytes([OP_ALOAD_0, OP_ARETURN])


def body_ldc_areturn(cp, s: str):
    idx = cp.string(s)
    if idx < 256:
        return bytes([OP_LDC]) + struct.pack("!B", idx) + bytes([OP_ARETURN])
    return bytes([OP_LDC_W]) + struct.pack("!H", idx) + bytes([OP_ARETURN])


def body_void(cp):
    return bytes([OP_RETURN])


def body_return_static(cp, owner, name, desc):
    """ldc-like helper: invokestatic + areturn (used by fixtures)."""
    mi = cp.methodref(owner, name, desc)
    return (bytes([OP_INVOKESTATIC]) + struct.pack("!H", mi) + bytes([OP_ARETURN]))
