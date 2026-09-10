"""Java .class reader for AAR indexing (constant pool + members + Code refs).

Only reads. Records: class descriptor, super, interfaces, fields, methods and,
per method, the String constants referenced by ldc/ldc_w plus the
field/method references from getstatic/putstatic/invoke* -- exactly the shape
the SQLite index needs.  A method whose bytecode cannot be walked completely is
flagged decode='partial' so the index never silently pretends coverage.
"""
from __future__ import annotations

import struct

# constant pool: tag -> (name, fmt) with '@' = native size, no alignment padding
_CP = {
    1: ("Utf8", None), 3: ("Integer", ">i"), 4: ("Float", ">f"), 5: ("Long", ">q"),
    6: ("Double", ">d"), 7: ("Class", ">H"), 8: ("String", ">H"),
    9: ("Fieldref", ">HH"), 10: ("Methodref", ">HH"),
    11: ("InterfaceMethodref", ">HH"), 12: ("NameAndType", ">HH"),
    15: ("MethodHandle", ">BH"), 16: ("MethodType", ">H"),
    17: ("Dynamic", ">HH"), 18: ("InvokeDynamic", ">HH"),
    19: ("Module", ">H"), 20: ("Package", ">H"),
}


def _lens():
    L = {}
    for o in range(0x00, 0x10):        # nop..dconst_1
        L[o] = 1
    L[0x10] = 2                        # bipush
    L[0x11] = 3                        # sipush
    L[0x12] = 2                        # ldc
    L[0x13] = 3                        # ldc_w
    L[0x14] = 3                        # ldc2_w
    for o in range(0x15, 0x1a):        # iload..aload
        L[o] = 2
    for o in range(0x1a, 0x36):        # iload_0 .. saload
        L[o] = 1
    for o in range(0x36, 0x3b):        # istore..astore
        L[o] = 2
    for o in range(0x3b, 0x57):        # istore_0 .. sastore
        L[o] = 1
    for o in range(0x57, 0x84):        # pop .. lxor
        L[o] = 1
    L[0x84] = 3                        # iinc
    for o in range(0x85, 0x94):        # i2l .. i2s
        L[o] = 1
    L[0x94] = 1                        # lcmp
    for o in range(0x99, 0xa8):        # ifeq .. if_acmpne
        L[o] = 3
    L[0xa8] = 3                        # goto
    L[0xa9] = 5                        # goto_w
    L[0xaa] = 3                        # jsr
    L[0xab] = 5                        # jsr_w
    L[0xac] = 1                        # ireturn
    for o in range(0xad, 0xb2):        # lreturn .. return
        L[o] = 1
    for o in range(0xb2, 0xbb):        # getstatic .. invokestatic
        L[o] = 3
    L[0xb9] = 5                        # invokeinterface
    L[0xba] = 5                        # invokedynamic
    L[0xbb] = 3                        # new
    L[0xbc] = 2                        # newarray
    L[0xbd] = 3                        # anewarray
    L[0xbe] = 1                        # arraylength
    L[0xbf] = 1                        # athrow
    L[0xc0] = 3                        # checkcast
    L[0xc1] = 3                        # instanceof
    L[0xc2] = 1                        # monitorenter
    L[0xc3] = 1                        # monitorexit
    L[0xc4] = 0                        # wide: variable
    L[0xc5] = 4                        # multianewarray
    L[0xc6] = 3                        # ifnull
    L[0xc7] = 3                        # ifnonnull
    L[0xc8] = 5                        # goto_w
    L[0xc9] = 5                        # jsr_w
    return L


_LEN = _lens()
_INVOKE_KIND = {0xb6: "invoke-virtual", 0xb7: "invoke-direct",
                0xb8: "invoke-static", 0xb9: "invoke-interface",
                0xba: "invoke-interface"}


class ClassParseError(Exception):
    pass


class ParsedClass:
    __slots__ = ("descriptor", "access", "super_descriptor", "interfaces",
                 "fields", "methods", "class_strings", "annotations",
                 "generic_signature", "partial_code")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))
        self.fields = self.fields or []
        self.methods = self.methods or []
        self.interfaces = self.interfaces or []
        self.class_strings = self.class_strings or []
        self.annotations = self.annotations or []


def jtype_to_descriptor(t: str) -> str:
    """Jvm 'Ljava/lang/String;[I' style already in descriptor form; helper for
    the generic-signature fallback only."""
    return t


def _u1(b, p):
    return b[p], p + 1


def parse(data: bytes) -> ParsedClass:
    if len(data) < 10:
        raise ClassParseError(f"class file 太短: {len(data)} 字节")
    if struct.unpack_from(">I", data, 0)[0] != 0xCAFEBABE:
        raise ClassParseError(
            f"不是 class 文件（magic={data[:4].hex()}，期望 cafebabe）")
    minor, major, cpc = struct.unpack_from(">HHH", data, 4)
    p = 10
    cp: list = [None] * cpc
    i = 1
    while i < cpc:
        tag, p = _u1(data, p)
        spec = _CP.get(tag)
        if spec is None:
            raise ClassParseError(f"bad cp tag {tag} #{i}")
        name, fmt = spec
        if name == "Utf8":
            ln = struct.unpack_from(">H", data, p)[0]
            p += 2
            cp[i] = ("Utf8", data[p:p + ln].decode("utf-8", "replace"))
            p += ln
        else:
            size = struct.calcsize(fmt)
            vals = struct.unpack_from(fmt, data, p)
            p += size
            cp[i] = (name, vals[0] if len(vals) == 1 else vals)
        if name in ("Long", "Double"):
            i += 2
        else:
            i += 1

    def utf(idx):
        e = cp[idx] if 0 < idx < cpc else None
        return e[1] if e and e[0] == "Utf8" else None

    def cls(idx):
        e = cp[idx] if 0 < idx < cpc else None
        if e and e[0] == "Class":
            return utf(e[1])
        return None

    access, this_i, super_i, n_if = struct.unpack_from(">HHHH", data, p)
    p += 8
    interfaces = []
    for _ in range(n_if):
        ci = struct.unpack_from(">H", data, p)[0]
        p += 2
        c = cls(ci)
        if c:
            interfaces.append("L" + c + ";")
    fields, p = _members(cp, data, p, code=False)
    methods, p = _members(cp, data, p, code=True)
    # class-level attributes come last (SourceFile / InnerClasses / NestMembers...)
    p, class_attrs = _attrs(cp, data, p)

    strings = []
    for e in cp:
        if e and e[0] == "String":
            s = utf(e[1])
            if s is not None:
                strings.append(s)

    return ParsedClass(
        descriptor="L" + (cls(this_i) or "?") + ";",
        access=access,
        super_descriptor=("L" + cls(super_i) + ";") if super_i else None,
        interfaces=interfaces,
        fields=fields,
        methods=methods,
        class_strings=strings,
        annotations=[],
        generic_signature=None,
        partial_code=any(m.get("partial") for m in methods),
    )


def _attrs(cp, data, p):
    n = struct.unpack_from(">H", data, p)[0]
    p += 2
    info = {}
    for _ in range(n):
        an = cp[struct.unpack_from(">H", data, p)[0]]
        aname = an[1] if an else "?"
        alen = struct.unpack_from(">I", data, p + 2)[0]
        info[aname] = data[p + 6:p + 6 + alen]
        p += 6 + alen
    return p, info


def _members(cp, data, p, code: bool):
    n = struct.unpack_from(">H", data, p)[0]
    p += 2
    out = []
    for _ in range(n):
        acc, ni, di = struct.unpack_from(">HHH", data, p)
        p += 6
        p, attrs = _attrs(cp, data, p)
        name = cp[ni][1] if cp[ni] else "?"
        desc = cp[di][1] if cp[di] else "()V"
        item = {"name": name, "descriptor": desc, "access": acc}
        if code:
            codeb = attrs.get("Code")
            if codeb:
                refs, partial = _decode_code(cp, codeb)
                item.update(refs)
                if partial:
                    item["partial"] = True
        out.append(item)
    return out, p


def _resolve_ref(cp, idx):
    """Return ('method'|'field', owner, name, descriptor) for a cp index."""
    e = cp[idx] if 0 < idx < len(cp) else None
    if not e:
        return None
    kind, val = e
    if kind not in ("Methodref", "InterfaceMethodref", "Fieldref"):
        return None
    cpi, nti = val
    owner = None
    ce = cp[cpi] if cpi and cpi < len(cp) else None
    if ce and ce[0] == "Class":
        owner = cp[ce[1]][1] if cp[ce[1]] else None
    ne = cp[nti] if nti and nti < len(cp) else None
    if not ne or ne[0] != "NameAndType" or owner is None:
        return None
    name_i, desc_i = ne[1]
    name = cp[name_i][1] if cp[name_i] else "?"
    desc = cp[desc_i][1] if cp[desc_i] else "?"
    return ("method" if kind != "Fieldref" else "field", owner, name, desc)


def _decode_code(cp, codeb: bytes):
    """Scan a Code attribute for string / method / field references."""
    codelen = struct.unpack_from(">I", codeb, 0)[0]
    off = 8 + codelen
    strings, methods, fields = [], [], []
    partial = False
    if off >= len(codeb):
        return {"code_strings": strings, "code_methods": methods,
                "code_fields": fields}, False
    # linear walk of the bytecode array (the exception table is not needed)
    ln = struct.unpack_from(">I", codeb, 4)[0]
    body = codeb[8:8 + ln]
    i = 0
    while i < len(body):
        op = body[i]
        size = _LEN.get(op)
        if size is None:
            partial = True
            break
        if size == 0:                       # wide
            if i + 2 >= len(body):
                partial = True
                break
            wop = body[i + 1]
            size = 6 if wop == 0x84 else 4
        elif op in (0x12, 0x13, 0x14):
            idx = body[i + 1] if op == 0x12 else struct.unpack_from(
                ">H", body, i + 1)[0]
            e = cp[idx] if 0 < idx < len(cp) else None
            if e and e[0] == "String":
                s = cp[e[1]][1] if cp[e[1]] else None
                if s is not None:
                    strings.append(s)
            elif e and e[0] == "Class":
                c = cp[e[1]][1] if cp[e[1]] else None
                if c:
                    methods.append(("const-class", "L" + c + ";", None, None))
        elif op in _INVOKE_KIND or op in (0xb2, 0xb3, 0xb4, 0xb5):
            idx = struct.unpack_from(">H", body, i + 1)[0]
            r = _resolve_ref(cp, idx)
            if r:
                if r[0] == "method":
                    _k, owner, name, desc = r
                    methods.append((_INVOKE_KIND.get(op, "invoke-virtual"),
                                    "L" + owner + ";", name, desc))
                else:
                    _k, owner, name, desc = r
                    fields.append(("L" + owner + ";", name, desc))
        i += size
    return {"code_strings": strings, "code_methods": methods,
            "code_fields": fields}, partial
