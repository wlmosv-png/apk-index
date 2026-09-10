"""Descriptor <-> Java <-> LibXposed Reflector conversions.

Internal storage form is always the Smali/JVM descriptor (``Lcom/example/User;``).
Every query result additionally carries the Java form, the Reflector string used
by ``io.github.libxposed:helper-ktx`` and a ``Class.forName`` expression, so the
downstream author can paste straight into Kotlin without guessing names.
"""
from __future__ import annotations

import re

PRIM_TO_JAVA = {
    "V": "void", "Z": "boolean", "B": "byte", "S": "short",
    "I": "int", "J": "long", "F": "float", "D": "double",
}
JAVA_TO_PRIM = {v: k for k, v in PRIM_TO_JAVA.items()}
_PRIM_SET = set(PRIM_TO_JAVA)


class SignatureError(ValueError):
    pass


# ------------------------------------------------------------------ normalize
_PRIM = {"void": "V", "boolean": "Z", "byte": "B", "short": "S", "int": "I",
         "long": "J", "float": "F", "double": "D", "char": "C",
         "java.lang.Object": "Ljava/lang/Object;"}


def normalize_desc(name: str) -> str:
    """任意写法 → JVM 类型描述符；无法判定返回原串。

    坑：早期实现只按 "含 ." 猜类名，把 java.lang.String 压成 LString;（丢掉包名），
    于是 matchSignature(params=["java.lang.String"]) 永远 0 命中。这里显式区分
    描述符 / 数组 / 原始类型 / 二进制类名四种输入。
    """
    s = (name or "").strip()
    if not s:
        return ""
    if len(s) == 1 and s in "VZBSIIFDC":
        return s                       # 已是原始类型描述符
    if s in _PRIM:
        return _PRIM[s]
    if s.startswith("L") and s.endswith(";") and "." not in s and " " not in s:
        return s                       # 已是描述符 Ljava/lang/String;
    if s.startswith("["):              # 描述符数组 [[I 等
        return s
    dims = 0
    while s.endswith("[]"):
        dims += 1
        s = s[:-2].strip()
    base = s
    if base in _PRIM:
        d = _PRIM[base]
    elif base.startswith("L") and base.endswith(";") and "." not in base:
        d = base
    else:
        d = "L" + base.replace(".", "/").replace("/", "/") + ";"
    return "[" * dims + d



def is_class_desc(desc: str) -> bool:
    return bool(desc) and desc.startswith("L") and desc.endswith(";")


def binary_name(desc: str) -> str:
    """``Lcom/example/User;`` -> ``com.example.User`` ; ``[Lcom/x/Y;`` -> array form."""
    d = desc or ""
    if d.startswith("["):
        return binary_name(d[1:]) + "[]"
    if is_class_desc(d):
        return d[1:-1].replace("/", ".")
    return PRIM_TO_JAVA.get(d, d)


def internal_name(desc: str) -> str:
    """Reflector/Xposed style owner name: ``com.example.User`` (arrays keep slashes)."""
    d = desc or ""
    if d.startswith("["):
        return d.replace("/", ".")
    if is_class_desc(d):
        return d[1:-1].replace("/", ".")
    return d


def type_to_java(desc: str, simple: bool = False) -> str:
    """``Ljava/lang/String;`` -> ``java.lang.String`` (or ``String`` when simple)."""
    d = desc or ""
    if d.startswith("["):
        return type_to_java(d[1:], simple) + "[]"
    if is_class_desc(d):
        name = binary_name(d)
        return name.rsplit(".", 1)[-1] if simple else name
    return PRIM_TO_JAVA.get(d, d)


def split_params(params_descriptor: str) -> list[str]:
    """``(ILjava/lang/String;[J)`` -> [``I``, ``Ljava/lang/String;``, ``[J``]."""
    s = params_descriptor or "()"
    if s.startswith("("):
        s = s[1:]
    if s.endswith(")"):
        s = s[:-1]
    out: list[str] = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "[":
            j = i
            while j < len(s) and s[j] == "[":
                j += 1
            if j < len(s) and s[j] == "L":
                k = s.index(";", j)
                out.append(s[i:k + 1])
                i = k + 1
            else:
                out.append(s[i:j + 1])
                i = j + 1
        elif c == "L":
            k = s.find(";", i)
            if k < 0:
                raise SignatureError(f"params 解析失败: {params_descriptor}")
            out.append(s[i:k + 1])
            i = k + 1
        else:
            out.append(c)
            i += 1
    return out


def join_params(params) -> str:
    return "(" + "".join(params) + ")"


def shorty(params, ret) -> str:
    def sc(t):
        if t.startswith("[") or is_class_desc(t):
            return "L"
        return t if t in _PRIM_SET else "L"
    return sc(ret) + "".join(sc(p) for p in params)


# ------------------------------------------------------------------ renderers
def smali_method(owner_desc: str, name: str, params_descriptor: str,
                 return_descriptor: str) -> str:
    return f"{owner_desc}->{name}{params_descriptor}{return_descriptor}"


def smali_field(owner_desc: str, name: str, type_descriptor: str) -> str:
    return f"{owner_desc}->{name}:{type_descriptor}"


def reflector_method(owner_desc: str, name: str, params_descriptor: str,
                     return_descriptor: str) -> str:
    """``com.example.User->getName()Ljava/lang/String;``"""
    return (f"{internal_name(owner_desc)}->{name}{params_descriptor}"
            f"{return_descriptor}")


def reflector_field(owner_desc: str, name: str, type_descriptor: str) -> str:
    """``com.example.User->mToken:Ljava/lang/String;``"""
    return f"{internal_name(owner_desc)}->{name}:{type_descriptor}"


def java_method(owner_desc: str, name: str, params_descriptor: str,
                return_descriptor: str, simple: bool = False,
                modifiers: str = "", qualified_owner: bool = True) -> str:
    ps = split_params(params_descriptor)
    # ``qualified_owner`` only ever added a Smali descriptor in front of the
    # return type, which is not valid Java.  The owner is already reachable via
    # ``forms["owner"]``; keep the signature as it appears in a .java file.
    pre = ""
    if name == "<init>":
        head = f"{pre}{type_to_java(owner_desc, simple)}"
        body = ", ".join(type_to_java(p, simple) for p in ps)
        sig = f"{head}({body})"
    else:
        head = f"{pre}{type_to_java(name and return_descriptor, simple)}" if False else \
               f"{pre}{type_to_java(return_descriptor, simple)}"
        body = ", ".join(type_to_java(p, simple) for p in ps)
        nm = type_to_java(owner_desc, True).rsplit(".", 1)[-1] if simple else name
        sig = f"{head} {nm}({body})" if not qualified_owner else f"{head} {name}({body})"
    return (modifiers + " " + sig).strip()


def java_field(owner_desc: str, name: str, type_descriptor: str,
               simple: bool = False, modifiers: str = "") -> str:
    sig = f"{type_to_java(type_descriptor, simple)} {name}"
    return (modifiers + " " + sig).strip()


def class_for_name(desc: str, loader: bool = False) -> str:
    if loader:
        return f'Class.forName("{binary_name(desc)}", true, classLoader)'
    return f'Class.forName("{binary_name(desc)}")'


def helpers_for_class(desc: str) -> dict:
    return {
        "descriptor": desc,
        "binaryName": binary_name(desc),
        "className": type_to_java(desc),
        "classForName": class_for_name(desc),
        "classForNameWithLoader": class_for_name(desc, loader=True),
    }


def method_forms(owner_desc: str, name: str, params_descriptor: str,
                 return_descriptor: str, access: int = 0,
                 modifiers: str = "") -> dict:
    """The four spellings getSignature() must return, plus smali/XposedBridge id."""
    from .dex import flag_names  # local import avoids cycle
    mods = modifiers or " ".join(
        f for f in flag_names(access)
        if f in ("public", "protected", "private", "static", "final"))
    return {
        "kind": "method",
        "owner": binary_name(owner_desc),
        "name": name,
        "smali": smali_method(owner_desc, name, params_descriptor, return_descriptor),
        "reflector": reflector_method(owner_desc, name, params_descriptor,
                                      return_descriptor),
        "java": java_method(owner_desc, name, params_descriptor, return_descriptor,
                            modifiers=mods),
        "javaSimple": java_method(owner_desc, name, params_descriptor,
                                  return_descriptor, simple=True, modifiers=mods),
        "params": split_params(params_descriptor),
        "paramsDescriptor": params_descriptor,
        "returnDescriptor": return_descriptor,
        "returnType": type_to_java(return_descriptor),
        "paramCount": len(split_params(params_descriptor)),
        "shorty": shorty(split_params(params_descriptor), return_descriptor),
    }


def field_forms(owner_desc: str, name: str, type_descriptor: str,
                access: int = 0, modifiers: str = "") -> dict:
    from .dex import flag_names
    mods = modifiers or " ".join(
        f for f in flag_names(access)
        if f in ("public", "protected", "private", "static", "final"))
    return {
        "kind": "field",
        "owner": binary_name(owner_desc),
        "name": name,
        "smali": smali_field(owner_desc, name, type_descriptor),
        "reflector": reflector_field(owner_desc, name, type_descriptor),
        "java": java_field(owner_desc, name, type_descriptor, modifiers=mods),
        "javaSimple": java_field(owner_desc, name, type_descriptor, simple=True,
                                 modifiers=mods),
        "typeDescriptor": type_descriptor,
        "type": type_to_java(type_descriptor),
    }


# ------------------------------------------------------------------- parsing
_METHOD_RE = re.compile(
    r"^(?P<owner>\S+?)\s*(?:->|\.)\s*(?P<name><init>|<clinit>|[\w$]+)\s*"
    r"\((?P<params>[^()]*)\)\s*(?P<ret>[\w$\[\]/;.]+)$")


def parse_method_ref(text: str):
    """Accept any of the accepted spellings and return
    ``(owner_desc, name, params_descriptor, return_descriptor)``.

    * ``com.example.User->getName()Ljava/lang/String;``   (Reflector)
    * ``Lcom/example/User;->getName()Ljava/lang/String;`` (smali)
    * ``com.example.User.getName(java.lang.String, int)`` (Java-ish)
    * ``com.example.User#getName(String)``
    """
    if not text:
        raise SignatureError("空的方法引用")
    s = text.strip()
    m = _METHOD_RE.match(s)
    if not m:
        raise SignatureError(f"无法解析方法引用: {text}")
    owner = normalize_desc(m.group("owner"))
    name = m.group("name")
    ret = _type_token(m.group("ret"))
    pd = join_params([_type_token(p) for p in _param_split(m.group("params")) if p.strip()])
    return owner, name, pd, ret


def _param_split(s: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return out


def _type_token(t: str) -> str:
    t = (t or "").strip()
    if not t:
        raise SignatureError("缺少类型")
    if "<" in t:                                  # strip generics
        t = t.split("<", 1)[0].strip()
    if "." in t and t.startswith("java.lang."):
        t = t[len("java.lang."):]
    if t in PRIM_TO_JAVA.values():
        return JAVA_TO_PRIM[t]
    if t in _PRIM_SET:
        return t
    if t.startswith("L") and t.endswith(";"):
        return t
    if t.endswith("[]"):
        return "[" + _type_token(t[:-2])
    if "/" in t:
        return "L" + t + ";"
    return "L" + t.replace(".", "/") + ";"


def parse_field_ref(text: str):
    """``com.example.User->mToken:Ljava/lang/String;`` / ``...User.mToken``"""
    s = text.strip()
    m = re.match(r"^(?P<owner>\S+?)\s*(?:->|#|\.)\s*(?P<name>[\w$]+)\s*:\s*(?P<type>.+)$", s)
    if not m:
        raise SignatureError(f"无法解析字段引用: {text}")
    return (normalize_desc(m.group("owner")), m.group("name"),
            _type_token(m.group("type")))
