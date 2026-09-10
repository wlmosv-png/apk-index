"""Pluggable dex backends.

The indexer never talks to a parser directly -- it asks for a backend that
yields ``apkindex.dex.DexFileData`` records.  Three backends ship:

* ``builtin``     -- zero dependency, pure stdlib parser (default, fastest here)
* ``androguard``  -- requires ``pip install androguard``
* ``dexlib2``     -- requires a JVM plus ``DEXLIB2_JAR``/``APK_INDEX_DEXLIB2_CMD``

Selection is explicit: ``APK_INDEX_BACKEND`` (or the ``backend`` argument of the
loaders).  A missing backend raises ``BACKEND_UNAVAILABLE`` -- it never silently
falls back, because a silently different parser means silently different counts.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time

from .config import ApkIndexError, ErrorCode, settings
from .dex import (ACC_CONSTRUCTOR, ACC_STATIC, ClassInfo, CodeInfo, DexError,
                  DexFileData, FieldInfo, MethodInfo, parse_dex)

AG_METHOD_TAG = 256      # 0x100 operand kind: method reference
AG_STRING_TAG = 257      # 0x101 operand kind: string reference
AG_FIELD_TAG = 258       # 0x102 operand kind: field reference
AG_TYPE_TAG = 259        # 0x103 operand kind: type reference


class Backend:
    name = "abstract"

    def status(self) -> dict:
        raise NotImplementedError

    def parse(self, data: bytes, name: str) -> DexFileData:
        raise NotImplementedError


class BuiltinBackend(Backend):
    name = "builtin"

    def status(self):
        return {"name": "builtin", "available": True,
                "note": "纯 stdlib dex 解析器，无外部依赖"}

    def parse(self, data: bytes, name: str) -> DexFileData:
        return parse_dex(data, name)


class AndroguardBackend(Backend):
    name = "androguard"

    def __init__(self):
        self._mod = None

    def _load(self):
        if self._mod is None:
            try:
                from androguard.core.dex import DEX          # noqa: WPS433
                import androguard
                self._mod = DEX
            except Exception as e:
                raise ApkIndexError(
                    ErrorCode.BACKEND_UNAVAILABLE,
                    f"androguard 后端不可用: {e}",
                    "pip install androguard，或改用 APK_INDEX_BACKEND=builtin。")
        return self._mod

    def status(self):
        try:
            self._load()
            import importlib.metadata as md
            return {"name": self.name, "available": True,
                    "version": md.version("androguard")}
        except Exception as e:
            return {"name": self.name, "available": False, "reason": str(e)[:200]}

    # ---------------------------------------------------------------- parse
    def parse(self, data: bytes, name: str) -> DexFileData:
        DEX = self._load()
        try:
            d = DEX(data)
        except Exception as e:
            raise ApkIndexError(ErrorCode.PARSE_FAILED,
                                f"androguard 无法解析 {name}: {e}")
        strings = []
        for s in d.get_strings() or []:
            v = getattr(s, "get_value", None)
            strings.append(v() if callable(v) else str(s))
        classes: list[ClassInfo] = []
        notes: list[str] = []
        for c in d.get_classes() or []:
            desc = _norm_desc(c.get_name())
            sup = c.get_superclassname()
            try:
                ifaces = [_norm_desc(x) for x in (c.get_interfaces() or [])]
            except Exception:
                ifaces = []
            fields = []
            for f in (c.get_fields() or []):
                fields.append(FieldInfo(f.get_name(), _norm_desc(f.get_descriptor()),
                                        f.get_access_flags(),
                                        bool(f.get_access_flags() & ACC_STATIC)))
            methods = []
            for m in (c.get_methods() or []):
                desc_p = m.get_descriptor() or "()"
                pd, ret = desc_p.split(")")[0] + ")", desc_p.split(")")[-1]
                code = None
                try:
                    code = self._code_of(m, strings)
                except Exception as e:
                    code = CodeInfo(partial=True)
                    notes.append(f"{desc}#{m.get_name()}: {e}")
                methods.append(MethodInfo(
                    m.get_name(), _params(pd), ret, _shorty(_params(pd), ret),
                    m.get_access_flags(), code))
            src = None
            try:
                src = c.get_source_file_idx()
                src = strings[src] if isinstance(src, int) and src < len(strings) else None
            except Exception:
                src = None
            classes.append(ClassInfo(descriptor=desc, access=c.get_access_flags(),
                                     super_descriptor=_norm_desc(sup) if sup else None,
                                     interfaces=ifaces, source_file=None,
                                     fields=fields, methods=methods, annotations=[]))
        counts = {"string_ids": len(strings),
                  "type_ids": len(list(d.get_types())) if hasattr(d, "get_types") else 0,
                  "proto_ids": 0,
                  "field_ids": sum(len(c.fields) for c in classes),
                  "method_ids": sum(len(c.methods) for c in classes),
                  "class_defs": len(classes),
                  "method_handles": 0, "call_sites": 0,
                  "code_items": sum(1 for c in classes for m in c.methods if m.code)}
        return DexFileData(name=name, size_bytes=len(data),
                           version=getattr(d, "version", "?"),
                           counts=counts, classes=classes, strings=strings,
                           parse_notes=notes[:20])

    @staticmethod
    def _code_of(m, strings) -> CodeInfo:
        ci = CodeInfo()
        ci.registers = m.get_locals() or 0
        for i in m.get_instructions() or []:
            name = i.get_name()
            try:
                ops = i.get_operands() or []
            except Exception:
                continue
            for o in ops:
                if not isinstance(o, tuple):
                    continue
                tag = o[0]
                if tag == AG_STRING_TAG and len(o) > 2:
                    ci.strings.append(_as_text(o[2], strings))
                elif tag == AG_METHOD_TAG and len(o) > 2:
                    owner, nm, pd, ret = _split_method_text(str(o[2]))
                    ci.calls.append((_INVOKE_KINDS.get(name, "invoke-virtual"),
                                     owner, nm, _params(pd), ret))
                elif tag == AG_FIELD_TAG and len(o) > 2:
                    owner, nm, ty = _split_field_text(str(o[2]))
                    (ci.writes if name.startswith("iput") or name.startswith("sput")
                     else ci.reads).append((owner, nm, ty))
                elif tag == AG_TYPE_TAG and len(o) > 2:
                    ci.const_classes.append(_norm_desc(str(o[2])))
        return ci


_INVOKE_KINDS = {"invoke-virtual": "invoke-virtual", "invoke-virtual/range": "invoke-virtual",
                 "invoke-super": "invoke-super", "invoke-super/range": "invoke-super",
                 "invoke-direct": "invoke-direct", "invoke-direct/range": "invoke-direct",
                 "invoke-static": "invoke-static", "invoke-static/range": "invoke-static",
                 "invoke-interface": "invoke-interface",
                 "invoke-interface/range": "invoke-interface",
                 "invoke-dynamic": "invoke-dynamic",
                 "invoke-polymorphic": "invoke-polymorphic",
                 "invoke-custom": "invoke-custom"}


class Dexlib2Backend(Backend):
    """dexlib2 (baksmali family) over a JVM helper.

    The helper source ships at ``jvm/Dexlib2Dump.java``; build it once, then
    point ``APK_INDEX_DEXLIB2_CMD`` at a command that reads a dex file on
    argv[1] and prints one JSON object per line in DexFileData shape.
    """

    name = "dexlib2"

    def status(self):
        java = shutil.which(settings().adb_bin.replace("adb", "java")) or \
            shutil.which("java")
        cmd = os.environ.get("APK_INDEX_DEXLIB2_CMD", "")
        jar = settings().dexlib2_jar
        ok = bool(cmd) or bool(java and jar)
        return {"name": self.name, "available": ok,
                "reason": "" if ok else "需要 java + DEXLIB2_JAR 或 APK_INDEX_DEXLIB2_CMD"}

    def parse(self, data: bytes, name: str) -> DexFileData:
        st = self.status()
        if not st["available"]:
            raise ApkIndexError(
                ErrorCode.BACKEND_UNAVAILABLE,
                f"dexlib2 后端不可用: {st['reason']}",
                "编译 jvm/Dexlib2Dump.java 后设 APK_INDEX_DEXLIB2_CMD='java -cp ... Dexlib2Dump'，"
                "或改用 APK_INDEX_BACKEND=builtin。")
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".dex", delete=False) as f:
            f.write(data)
            tmp = f.name
        try:
            cmd = os.environ.get("APK_INDEX_DEXLIB2_CMD")
            argv = (cmd.split() if cmd else
                    ["java", "-cp", settings().dexlib2_jar, "Dexlib2Dump"]) + [tmp]
            out = subprocess.run(argv, capture_output=True, text=True, timeout=600)
            if out.returncode != 0:
                raise ApkIndexError(ErrorCode.PARSE_FAILED,
                                    f"dexlib2 helper 失败: {out.stderr[:400]}")
            return _records_from_jsonl(out.stdout, name, len(data))
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _records_from_jsonl(text: str, name: str, size: int) -> DexFileData:
    classes: list[ClassInfo] = []
    strings: list[str] = []
    counts: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        if obj.get("t") == "counts":
            counts = obj["v"]
        elif obj.get("t") == "string":
            strings.append(obj["v"])
        elif obj.get("t") == "class":
            ci = CodeInfo()
            for r in obj.get("refs", []):
                if r[0] == "s":
                    ci.strings.append(r[1])
                elif r[0] == "t":
                    ci.const_classes.append(r[1])
                elif r[0] == "f":
                    (ci.writes if r[4] == "w" else ci.reads).append(tuple(r[1:4]))
                elif r[0] == "c":
                    ci.calls.append((r[1], r[2], r[3], _params(r[4]), r[5]))
            classes.append(ClassInfo(
                descriptor=obj["d"], access=obj["a"],
                super_descriptor=obj.get("s"), interfaces=obj.get("i", []),
                source_file=obj.get("sf"),
                fields=[FieldInfo(x[0], x[1], x[2], bool(x[2] & ACC_STATIC))
                        for x in obj.get("f", [])],
                methods=[MethodInfo(x[0], _params(x[2]), x[3],
                                    _shorty(_params(x[2]), x[3]), x[1],
                                    ci if x[4] else None) for x in obj.get("m", [])],
                annotations=[]))
    return DexFileData(name=name, size_bytes=size, version="dexlib2",
                       counts=counts, classes=classes, strings=strings)


# ----------------------------------------------------------------- helpers
def _norm_desc(d):
    if d is None:
        return None
    s = str(d).strip()
    if s.startswith("L") and s.endswith(";"):
        return s
    if s.startswith("[") or s in "VZBSIJFD":
        return s
    if s.startswith("L"):                       # androguard field types: 'Laa7;'
        return s if s.endswith(";") else s + ";"
    return "L" + s.replace(".", "/") + ";"


def _split_method_text(t: str):
    owner, rest = t.split("->", 1)
    name, tail = rest.split("(", 1)
    pd, ret = tail.split(")", 1)
    return _norm_desc(owner), name, "(" + pd + ")", _norm_desc(ret or "V")


def _split_field_text(t: str):
    owner, rest = t.split("->", 1)
    nm, ty = rest.split(" ", 1) if " " in rest else (rest, "V")
    return _norm_desc(owner), nm.strip(), _norm_desc(ty.strip())


def _params(pd: str) -> list[str]:
    s = (pd or "()")[1:-1] if pd and pd.endswith(")") else (pd or "")
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == "[":
            j = i
            while j < len(s) and s[j] == "[":
                j += 1
            if j < len(s) and s[j] == "L":
                k = s.index(";", j)
                out.append(s[i:k + 1]); i = k + 1
            else:
                out.append(s[i:j + 1]); i = j + 1
        elif c == "L":
            k = s.index(";", i)
            out.append(s[i:k + 1]); i = k + 1
        else:
            out.append(c); i += 1
    return out


def _as_text(v, strings):
    if isinstance(v, int) and 0 <= v < len(strings):
        return strings[v]
    return str(v)


def _shorty(params, ret) -> str:
    from .signature import shorty
    return shorty(params, ret)


_REGISTRY: dict[str, Backend] = {}


def backend(name: str = "") -> Backend:
    name = (name or settings().force_backend or "builtin").lower()
    if name in ("auto", "default"):        # schema 里 advertised 的"auto"，别让它变成陷阱
        fb = (settings().force_backend or "").lower()
        # force_backend 自己也可能被写成 auto，必须落到具体后端，否则下面判非法
        name = fb if fb in ("builtin", "androguard", "dexlib2") else "builtin"
    if name not in ("builtin", "androguard", "dexlib2"):
        raise ApkIndexError(
            ErrorCode.BAD_ARGUMENT, f"未知后端: {name}",
            "可选: builtin | androguard | dexlib2")
    if name not in _REGISTRY:
        _REGISTRY[name] = {"builtin": BuiltinBackend,
                           "androguard": AndroguardBackend,
                           "dexlib2": Dexlib2Backend}[name]()
    return _REGISTRY[name]


def available_backends() -> list[dict]:
    out = []
    for cls in (BuiltinBackend, AndroguardBackend, Dexlib2Backend):
        b = cls()
        out.append(b.status())
    return out
