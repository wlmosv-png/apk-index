"""Kotlin snippet generation for ``io.github.libxposed:helper`` / ``helper-ktx``.

Two flavours, both paste-ready:

1. ``dsl``      -- the structural matcher DSL (``buildHooks { classes { methods {
                   ... }.first().onMatch { hook(it).intercept { ... } } } }``).
                   Use it when the target is obfuscated: match on shape and on
                   string/field/call evidence instead of on a name.
2. ``reflector`` -- the fast ``Reflector.loadMethod("a.b.C->m(...)Z")`` path.
                   Use it when ``getSignature`` proved the name survives
                   obfuscation (kept by -keep rules, or simply never renamed).

Every generated block passes :func:`check_kotlin` (bracket/quote balance)
before it leaves the process: a snippet pasted into a module must at least be
well-formed, otherwise the caller wastes a build cycle on our output.
"""
from __future__ import annotations

import re

from .dex import flag_names
from .signature import binary_name, is_class_desc, split_params

PRIM_CLASS_EXPR = {
    "Z": "Boolean::class.javaPrimitiveType!!",
    "B": "Byte::class.javaPrimitiveType!!",
    "S": "Short::class.javaPrimitiveType!!",
    "I": "Int::class.javaPrimitiveType!!",
    "J": "Long::class.javaPrimitiveType!!",
    "F": "Float::class.javaPrimitiveType!!",
    "D": "Double::class.javaPrimitiveType!!",
}


def kotlin_string(value: str) -> str:
    """Escape for a Kotlin double-quoted literal (``$`` would start a template)."""
    out = []
    for ch in value or "":
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "$":
            out.append("\\$")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def regex_string(pattern: str) -> str:
    """Regex source as a Kotlin literal (backslashes must survive escaping)."""
    return kotlin_string((pattern or "").replace("\\", "\\\\"))


def type_expr(desc: str) -> str:
    """Smali descriptor -> Kotlin ``Class`` expression for matcher properties."""
    d = desc or "V"
    if d.startswith("["):
        # arrays: Reflector accepts both "com.x.Y[]" and "[Lcom/x/Y;"
        return kotlin_string(binary_name(d)) + ".exactClass"
    if d in PRIM_CLASS_EXPR:
        return PRIM_CLASS_EXPR[d] + ".exactClass"
    if d == "V":
        return "Void.TYPE.exactClass"
    return kotlin_string(binary_name(d) if is_class_desc(d) else d) + ".exactClass"


def type_for_conjunction(desc: str) -> str:
    """Bare ``Class`` expression for ``parameters = conjunction(...)``."""
    d = desc or "V"
    if d.startswith("["):
        return kotlin_string(binary_name(d)) + ".exactClass"
    if d in PRIM_CLASS_EXPR:
        return PRIM_CLASS_EXPR[d]
    if d == "V":
        return "Void.TYPE"
    return kotlin_string(binary_name(d) if is_class_desc(d) else d) + ".exactClass"


_MOD_FLAGS = ("public", "private", "protected", "static", "final", "abstract",
              "synchronized", "native")


def _modifier_lines(access: int, only: tuple = _MOD_FLAGS) -> list[str]:
    seen = set(flag_names(access))
    return [f"is{f[0].upper()}{f[1:]} = true" for f in only if f in seen]


def method_matcher_body(name, params, ret, access: int = 0, referred_strings=(),
                        assigned_fields=(), invoked_methods=(),
                        name_pattern=None, is_constructor: bool = False,
                        indent: str = "            ") -> tuple[str, bool]:
    """(block body, needs @OptIn(DexAnalysis)) for a methods/constructors block."""
    needs = bool(referred_strings or assigned_fields or invoked_methods)
    lines: list[str] = []
    if name_pattern:
        lines.append(f"name = {regex_string(name_pattern)}.regex")
    elif name and name not in ("<init>", "<clinit>"):
        lines.append(f"name = {kotlin_string(name)}.exact")
    lines.append(f"parameterCounts = {len(params)}")
    lines.append("parameters = conjunction("
                 + ", ".join(type_for_conjunction(p) for p in params) + ")")
    if ret and not is_constructor:
        lines.append(f"returnType = {type_expr(ret)}")
    lines.extend(_modifier_lines(access))
    if referred_strings:
        joined = " or ".join("+" + kotlin_string(s)
                             for s in list(referred_strings)[:8])
        lines.append(f"referredStrings = {joined}")
    if assigned_fields:
        parts = []
        for owner, fname, ftype in list(assigned_fields)[:4]:
            parts.append("+" + "firstField {\n"
                         f"{indent}    name = {kotlin_string(fname)}.exact\n"
                         f"{indent}    type = {type_expr(ftype)}\n"
                         f"{indent}}}")
        lines.append("assignedFields = " + " and ".join(parts))
    if invoked_methods:
        parts = []
        for owner, mname, mparams in list(invoked_methods)[:4]:
            parts.append("+" + "firstMethod {\n"
                         f"{indent}    name = {kotlin_string(mname)}.exact\n"
                         f"{indent}    parameterCounts = {len(mparams)}\n"
                         f"{indent}}}")
        lines.append("invokedMethods = " + " and ".join(parts))
    return "\n".join(indent + ln for ln in lines), needs


DSL_HEADER = (
    "// requires: compileOnly(\"io.github.libxposed:api:102.0.0\")\n"
    "//            implementation(\"io.github.libxposed:helper:100.0.1\")\n"
    "//            implementation(\"io.github.libxposed:helper-ktx:100.0.1\")\n"
    "// put this inside XposedModule.onPackageReady(param) and set the target's\n"
    "// own symbol in the matcher: apk-index proved it exists in the loaded dex.\n"
)


def match_dsl(class_binary: str, member_name: str, params, ret: str, *,
              access: int = 0, super_binary: str | None = None,
              interfaces=(), referred_strings=(), assigned_fields=(),
              invoked_methods=(), name_pattern=None, is_constructor: bool = False,
              match_all: bool = False, comment: str = "",
              verbose_header: bool = True) -> str:
    """A complete ``buildHooks { ... }`` block describing exactly one hook point."""
    if member_name == "<clinit>":
        # matcher 只按方法表匹配，hook 不到静态初始化器；这里若照 <init> 或
        # methods{} 空名生成，给出的是一份看起来能编译、实际 hook 错位置的代码。
        return ("// apk-index：<clinit>（静态初始化器）不是构造方法，不能作为 hook 点生成 matcher。\n"
                f"// 目标：{class_binary}#<clinit>（d8 给它打了 kAccConstructor 位，别照着位生成 constructors{{}}）\n"
                "// 两条可行路子：\n"
                f"//   1) 在合适的时机 XposedHelpers.findClass(\"{class_binary}\", param.classLoader)"
                " 触发类初始化，再 hook 你真正关心的用法点；\n"
                "//   2) 换 matchSignature 的 namePattern（例如 on* / get*）选一个真能被方法表匹配到的成员。\n"
                "// 只取句柄可以这样：\n"
                f"//   reflector.loadMethod(\"{class_binary.replace('.', '/')}-><clinit>()V\")\n")
    inner, needs = method_matcher_body(
        member_name, list(params or []), ret, access, referred_strings,
        assigned_fields, invoked_methods, name_pattern, is_constructor)
    cls_lines: list[str] = [f"        name = {kotlin_string(class_binary)}.exactClass"]
    if super_binary:
        cls_lines.append(f"        superClass = {kotlin_string(super_binary)}.exactClass")
    for iface in list(interfaces or [])[:2]:
        cls_lines.append(f"        containsInterfaces = +{kotlin_string(iface)}.exactClass")
    for ln in _modifier_lines(access, only=("public", "static")):
        cls_lines.append("        " + ln)
    sel = ".all()" if match_all else ".first()"
    block = "constructors" if is_constructor else "methods"
    label = "<init>" if is_constructor else (member_name or (name_pattern or "?"))
    miss = kotlin_string(f"apk-index 预测的 hook 点未命中: {class_binary}#{label}")
    optin = ("@OptIn(io.github.libxposed.helper.matcher.DexAnalysis::class)\n"
             if needs else "")
    header = (f"// apk-index matchSignature -> {class_binary}#{label}"
              + (f"  {comment}" if comment else "") + "\n"
              + (DSL_HEADER if verbose_header else ""))
    body = (header
        + optin
        + "buildHooks(param.classLoader as dalvik.system.BaseDexClassLoader,\n"
        "           param.applicationInfo.sourceDir) {\n"
        "    classes {\n"
        + "\n".join(cls_lines) + "\n"
        + f"        {block} {{\n{inner}\n        }}{sel}.onMatch {{ target ->\n"
        "            hook(target).intercept { chain ->\n"
        "                // chain.args[i] 只读；改写请 chain.proceed(arrayOf(...))\n"
        "                // 构造函数里改写后必须 return null / Unit\n"
        "                chain.proceed()\n"
        "            }\n"
        f"        }}.onMiss {{ log(Log.WARN, TAG, {miss}) }}\n"
        "    }\n"
        "}\n"
    )
    problems = check_kotlin(body)
    if problems:
        return "// apk-index 生成失败: " + "; ".join(problems) + "\n"
    return body


def field_dsl(class_binary: str, field_name: str, type_descriptor: str,
              *, static: bool = False, final: bool = False) -> str:
    """Field access block: Reflector first (exact, no dex scan), matcher second."""
    mods = "\n".join(f"            is{name[0].upper()}{name[1:]} = true"
                      for name, on in (("static", static), ("final", final)) if on)
    ident = re.sub(r"\W+", "", field_name) or "field"
    body = (
        "// apk-index getSignature -> 字段：优先 Reflector 直取（零歧义、零 dex 扫描）\n"
        "val " + ident + ": java.lang.reflect.Field =\n"
        "    reflector.loadField("
        + kotlin_string(field_reflector(class_binary, field_name, type_descriptor)) + ")\n"
        "\n"
        "// 需要跨版本适配时再让 matcher 按结构找同名字段\n"
        "buildHooks(param.classLoader as dalvik.system.BaseDexClassLoader,\n"
        "           param.applicationInfo.sourceDir) {\n"
        "    classes {\n"
        "        name = " + kotlin_string(class_binary) + ".exactClass\n"
        "        fields {\n"
        "            name = " + kotlin_string(field_name) + ".exact\n"
        "            type = " + type_expr(type_descriptor) + "\n"
        + mods + "\n"
        "        }.first().onMatch { target ->\n"
        "            target.isAccessible = true\n"
        "            val value = target.get(this)\n"
        "            log(Log.INFO, TAG, \"field value = $value\")\n"
        "        }.onMiss { log(Log.WARN, TAG, "
        + kotlin_string("字段未找到: " + class_binary + "." + field_name) + ") }\n"
        "    }\n"
        "}\n"
    )
    problems = check_kotlin(body)
    if problems:
        return "// apk-index 生成失败: " + "; ".join(problems) + "\n"
    return body


def field_reflector(owner_binary: str, name: str, type_descriptor: str) -> str:
    return f"{owner_binary}->{name}:{type_descriptor}"


def method_reflector(owner_binary: str, name: str, params_descriptor: str,
                     return_descriptor: str) -> str:
    return f"{owner_binary}->{name}{params_descriptor}{return_descriptor}"


def reflector_snippet(forms: dict) -> str:
    """Fast-path code for a symbol that is known not to be renamed."""
    name = forms.get("name") or "target"
    ident = re.sub(r"\W+", "", name) or "member"
    if forms.get("kind") == "field":
        return (f"// Reflector 快路径（名字未被混淆时最稳，冷启动也最快）\n"
                f"val {ident}: java.lang.reflect.Field =\n"
                f"    reflector.loadField({kotlin_string(forms['reflector'])})\n")
    if name == "<init>":
        return (f"// Reflector 快路径\n"
                f"val ctor{ident if ident != 'ctor' else ''}: java.lang.reflect.Constructor<*> =\n"
                f"    reflector.loadConstructor({kotlin_string(forms['reflector'])})\n")
    return (f"// Reflector 快路径\n"
            f"val {ident}: java.lang.reflect.Method =\n"
            f"    reflector.loadMethod({kotlin_string(forms['reflector'])})\n"
            f"// hook 时先 deoptimize({ident}) 以对抗 ART 内联\n")


def class_snippet(class_binary: str) -> str:
    return (f"val clazz: Class<*> = reflector.loadClass({kotlin_string(class_binary)})\n"
            f"// 等价: Class.forName({kotlin_string(class_binary)}, true, param.classLoader)\n")


_STRING_RE = re.compile(r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'")
_COMMENT_RE = re.compile(r"//[^\n]*")


def check_kotlin(text: str) -> list[str]:
    """Structural sanity check. Returns problems; empty means paste-safe by shape."""
    problems: list[str] = []
    stripped = _STRING_RE.sub('"S"', _COMMENT_RE.sub("", text))
    for open_c, close_c in (("{", "}"), ("(", ")"), ("[", "]")):
        if stripped.count(open_c) != stripped.count(close_c):
            problems.append(f"{open_c}{close_c} 不平衡 "
                            f"({stripped.count(open_c)}/{stripped.count(close_c)})")
    if stripped.count('"') % 2:
        problems.append("未闭合的双引号")
    for m in re.finditer(r"\$\{([^}]*)\}", stripped):
        if not m.group(1).strip():
            problems.append("空的字符串模板 ${}")
    return problems


def member_forms_for_method(class_binary: str, name: str, params_descriptor: str,
                            return_descriptor: str, access: int = 0) -> dict:
    from . import signature as sg
    return sg.method_forms("L" + class_binary.replace(".", "/") + ";", name,
                           params_descriptor, return_descriptor, access)


def params_of(forms: dict) -> list[str]:
    return split_params(forms.get("paramsDescriptor") or "()")
