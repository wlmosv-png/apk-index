"""apk-index -- MCP server over stdio (newline-delimited JSON-RPC 2.0).

Transport notes: MCP's stdio transport is one JSON-RPC message per line; stdout
is reserved for those messages and every diagnostic goes to stderr, so a client
can never receive a log line that breaks its parser.

Run modes
  apk-index serve                 the MCP server (default when no subcommand)
  apk-index tools                 dump the tool table (name + inputSchema)
  apk-index call <tool> '<json>'  one-shot call, result printed as JSON
  apk-index selftest              in-process protocol handshake + smoke calls
  apk-index version               print name/version
"""
from __future__ import annotations

import argparse
import inspect
import json
import os
import re
import sys
import time
import traceback
from typing import Any, Callable

from . import backends
from . import decomp
from . import envelope as env
from . import loaders
from . import queries
from .config import (DEFAULT_LIMIT, ErrorCode, MAX_RESPONSE_BYTES, NAME,
                     PROTOCOL_VERSIONS, VERSION, settings)
from .render import render

VERBOSE = bool(os.environ.get("APK_INDEX_VERBOSE"))


def _log(*parts: Any) -> None:
    if VERBOSE:
        print("[apk-index]", *parts, file=sys.stderr, flush=True)


# ----------------------------------------------------------------- schemas
def _obj(props: dict, required: list | None = None) -> dict:
    out = {"type": "object", "properties": props,
           "additionalProperties": False}
    if required:
        out["required"] = required
    return out


def _p(type_: str, desc: str, **extra) -> dict:
    d = {"type": type_, "description": desc}
    d.update(extra)
    return d


_S_ID = _p("string", "loadApk/loadAar/loadDex 返回的 sessionId（也接受唯一前缀或包名）")
_S_SCOPE = _p("string", "app=目标自身代码 / library=注入进来的库代码 / all=全部",
              enum=["app", "library", "system", "all"], default="all")
_S_LIMIT = _p("integer", "返回条数，默认 50，硬上限 200", minimum=1, maximum=200)


def _tool(name: str, desc: str, props: dict, required: list, fn: Callable) -> dict:
    return {"name": name, "description": desc, "inputSchema": _obj(props, required),
            "_fn": fn}


TOOLS: list[dict] = [
    _tool("loadApk",
          "索引一个 APK（自动合并 base+config.*+split_*），解 AXML manifest、逐 dex 计数、"
          "识别加固壳。返回 sessionId 与 fingerprint。同 sha256 二次调用直接命中缓存（alreadyLoaded=true，不重建）。"
          "写任何 hook 之前必须先调它。",
          {"path": _p("string", "APK 路径，或 split 目录（内含 base.apk）"),
           "fromDevice": _p("boolean", "true=用 adb 从设备 pull（需先 dumpsys package 取版本）", default=False),
           "packageName": _p("string", "fromDevice 时的包名；path 可留空"),
           "splits": _p("boolean", "是否合并 split APK", default=True),
           "maxApkBytes": _p("integer", "体积上限字节数，超过直接报 APK_TOO_LARGE；0=不限", default=0),
           "force": _p("boolean", "true=即使按 dex 内容命中去重也强制重建索引", default=False),
           "backend": _p("string", "auto(默认，按 APK_INDEX_BACKEND 选) | builtin | androguard | dexlib2",
                         enum=["auto", "builtin", "androguard", "dexlib2"],
                         default="auto")},
          [], loaders.load_apk),
    _tool("loadAar",
          "解包 AAR：classes.jar/libs/*.jar 走 .class 常量池索引（source=library），"
          "解析 R.txt 与 consumer-rules.pro（被 keep 的符号名不会被混淆，可直接硬编码），"
          "列出 jni/<abi>/*.so 与 prefab/headers。mergeInto 可并入已有 Session 并保留库归属。",
          {"path": _p("string", ".aar 路径"),
           "mergeInto": _p("string", "已有 sessionId；留空则新建独立会话"),
           "backend": _p("string", "索引后端", enum=["builtin", "androguard", "dexlib2"])},
          ["path"], loaders.load_aar),
    _tool("loadDex",
          "索引裸 classes*.dex / jar 内嵌 dex / odex、vdex（无法解析时返回 UNSUPPORTED_FORMAT 并提示预提取）。"
          "带 sessionId 为增量追加，不重建索引。",
          {"path": _p("string", "dex/jar/aar/odex/vdex 路径"),
           "sessionId": _p("string", "追加进已有会话"),
           "format": _p("string", "auto 时按魔数嗅探",
                        enum=["dex", "jar", "aar", "odex", "vdex", "auto"]),
           "source": _p("string", "app|library|system 归属标记", default="app")},
          ["path"], loaders.load_dex),
    _tool("sessionList",
          "列出所有已索引会话：sessionId、包名、sha256、kind、类数、索引体积、是否可用。"
          "忘了 sessionId、或想确认目标 APK（含 split/AAR/dex 会话）是否已经索引过时先调它，"
          "再决定 loadApk 还是直接查询。",
          {"limit": _S_LIMIT}, [], loaders.session_list),
    _tool("unload", "卸载会话。默认连索引文件一起删（keepFiles=false），同 sha256 再 load 会重建。",
          {"sessionId": _S_ID, "keepFiles": _p("boolean", "只删登记、保留 .db", default=False)},
          ["sessionId"], loaders.unload),
    _tool("stats", "会话体检：dex 数、类/方法/字段/字符串总量、索引耗时、缓存路径、加固状态、来源分布。",
          {"sessionId": _S_ID}, ["sessionId"], loaders.stats),
    _tool("checkPacker", "只看加固判定：壳特征库、stub 入口类、类数/字符串熵证据链与建议（PACKED_TARGET 时静态 hook 无意义）。",
          {"sessionId": _S_ID}, ["sessionId"], loaders.check_packer),
    _tool("searchClasses",
          "按 exact/prefix/regex 找类。返回 descriptor(Smali)、binaryName、reflector、Class.forName、"
          "父类/接口/方法数字段数、来源与 dex 归属。scope=app 可把库代码排除掉。",
          {"sessionId": _S_ID, "query": _p("string", "类名：com.a.b、User、Lcom/a/b/User;、^a\\..*Login.*"),
           "kind": _p("string", "类名匹配方式", enum=["exact", "prefix", "regex"], default="prefix"),
           "scope": _S_SCOPE, "limit": _S_LIMIT,
           "packageFilter": _p("string", "按包名前缀过滤（如 com.example.net）"),
           "annotatedWith": _p("string", "只要类上带这个注解的：@Keep / dalvik.annotation.Keep / Ldalvik/annotation/Keep;",
                                default="")},
          ["sessionId", "query"], queries.search_classes),
    _tool("listMembers",
          "列出一个类的方法/字段，每条自带 smali+reflector+java 三种写法、修饰符、是否 static/构造器、"
          "体内引用的字符串与调用（withStrings>0 附带字符串）。",
          {"sessionId": _S_ID, "class": _p("string", "类名（任意写法，内部归一化）"),
           "include": _p("string", "返回成员类型", enum=["methods", "fields", "both"], default="both"),
           "namePattern": _p("string", "成员名正则，例如 ^get.*Token"),
           "withStrings": _p("integer", "每个方法附带的字符串常量数，默认 0"),
           "scope": _S_SCOPE, "limit": _S_LIMIT},
          ["sessionId", "class"], queries.list_members),
    _tool("getSignature",
          "一个类/成员 -> 四种可粘贴写法（Smali descriptor、Java 签名、LibXposed Reflector 字符串、"
          "Class.forName）+ helper-ktx 起手块 + Reflector 快路径代码，并给出类上与方法上的注解（descriptor、visibility、元素值）。混淆目标也照抄这里，不要自己拼名字。",
          {"sessionId": _S_ID, "class": _p("string", "类名"),
           "member": _p("string", "方法/字段名或完整引用；留空只给类级签名"),
           "scope": _S_SCOPE},
          ["sessionId", "class"], queries.get_signature),
    _tool("searchByString",
          "字符串常量反查方法：UI 文案、日志 TAG、SharedPreferences key、接口路径 —— 定位 hook 点最有效的入口。"
          "结果按“引用该方法数”升序，越少越适合当锚点。",
          {"sessionId": _S_ID, "text": _p("string", "要找的字符串"),
           "match": _p("string", "字符串匹配方式", enum=["contains", "exact", "regex"], default="contains"),
           "scope": _S_SCOPE, "limit": _S_LIMIT,
           "methodLimit": _p("integer", "每个字符串最多带几条方法，默认 8"),
           "minLen": _p("integer", "只看不短于该长度的字符串，0=不限")},
          ["sessionId", "text"], queries.search_by_string),
    _tool("findImplementations",
          "接口实现 / 父类子类（递归 CTE 走完整继承链），可按方法签名再筛一遍。"
          "用来确定「hook 接口方法还是 hook 唯一实现」。",
          {"sessionId": _S_ID, "interface": _p("string", "接口名"),
           "superClass": _p("string", "父类名"),
           "method": _p("string", "要求实现该方法：a.b.C#doIt(Ljava/lang/String;)V"),
           "transitive": _p("boolean", "是否走完整继承链", default=True),
           "includeAbstract": _p("boolean", "是否包含抽象类/接口本身", default=True),
           "scope": _S_SCOPE, "limit": _S_LIMIT},
          ["sessionId"], queries.find_implementations),
    _tool("xref",
          "调用图 1..3 层。callers=谁调用了它（找最外层 hook 点）；callees=它调用了什么（判断依赖与副作用）。",
          {"sessionId": _S_ID,
           "method": _p("string", "方法引用（Reflector/smali/Java 任意写法），或类名=该类全部方法"),
           "direction": _p("string", "callers=谁调用它，callees=它调用谁", enum=["callers", "callees"], default="callers"),
           "depth": _p("integer", "1..3", minimum=1, maximum=3, default=1),
           "scope": _S_SCOPE, "limit": _S_LIMIT},
          ["sessionId", "method"], queries.xref),
    _tool("decompile",
          "java 走 jadx（需 JADX_HOME/PATH），smali 优先 baksmali、否则退回索引 outline"
          "（engine/authoritative 字段会写清楚）。最多 400 行，超出标 truncated。",
          {"sessionId": _S_ID, "target": _p("string", "类或方法引用"),
           "format": _p("string", "auto=java→smali→outline 逐级降级（默认，绝不空手）；"
                        "java=jadx；smali=baksmali 或退回 outline；outline=只用索引重建",
                        enum=["auto", "java", "smali", "outline"], default="auto"),
           "maxLines": _p("integer", "默认 400", minimum=20, maximum=4000)},
          ["sessionId", "target"], queries.decompile),
    _tool("matchSignature",
          "按结构找 hook 点：参数表/返回类型/修饰符 + 体内引用的字符串 + 读写字段 + 调用方法（全部 AND）。"
          "命中直接给出 helper-ktx DSL 块与 Reflector 快路径代码。",
          {"sessionId": _S_ID,
           "params": _p(["array", "string"], "参数 descriptor 列表，位置通配用 \"any\"",
                        items={"type": "string"}),
           "returnType": _p("string", "返回 descriptor，any=不限"),
           "modifiers": _p(["array", "string"], "static/public/private/protected/final/synchronized/native/abstract",
                           items={"type": "string"}),
           "referredStrings": _p(["array", "string"], "方法体内必须出现的字符串常量", items={"type": "string"}),
           "accessedFields": _p(["array", "string"], "字段引用 Lcom/a/B;->f:I", items={"type": "string"}),
           "invokedMethods": _p(["array", "string"], "被调用方法引用", items={"type": "string"}),
           "namePattern": _p("string", "方法名正则"),
           "packagePrefix": _p("string", "包名前缀收窄"),
           "requireConstructor": _p("boolean", "只匹配构造器", default=False),
           "scope": _S_SCOPE, "limit": _S_LIMIT},
          ["sessionId"], queries.match_signature),
    _tool("diffSessions",
          "两个版本会话之间的混淆名漂移报告：结构完全一致=exact-structure，Jaccard 相似度=structural-similarity，"
          "外加 added/removed。跨版本适配就靠它。",
          {"sessionA": _S_ID, "sessionB": _S_ID,
           "minScore": _p("number", "结构相似度阈值，默认 0.55"),
           "scope": _S_SCOPE, "limit": _S_LIMIT},
          ["sessionA", "sessionB"], queries.diff_sessions),
    _tool("probe",
          "一次常用侦察：自动从问题里抽引号字面量/中文文案/类名关键词，串起 checkPacker+stats+"
          "searchByString+searchClasses+hook 候选+建议 DSL，返回结构化证据包（省往返、省 token）。",
          {"sessionId": _S_ID, "question": _p("string", "例如：想拦截“登录中...”这个按钮的回调"),
           "target": _p("string", "类或成员引用（A#m(sig) / A->m(sig) / 裸类名）；给了就连带 xref+getSignature+decompile 一起深挖"),
           "maxDepth": _p("integer", "target 调用链深度，默认 2"),
           "limit": _S_LIMIT},
          ["sessionId", "question"], queries.probe),
]

BY_NAME = {t["name"]: t for t in TOOLS}


# ------------------------------------------------------------------ dispatch
def _snake(name: str) -> str:
    """sessionId -> session_id, maxLines -> max_lines (handlers are snake_case)."""
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


# The public contract uses JSON-ish tool arg names that Python cannot spell as
# parameters (``class``) or spells differently (``sessionId``).
ARG_ALIASES = {"class": "cls", "sessionId": "session_id", "sessionA": "session_a",
               "sessionB": "session_b", "maxLines": "max_lines",
               "minScore": "min_score"}


def bind(fn: Callable, args: dict) -> dict:
    """Map camelCase tool arguments onto the python handler's parameters."""
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return {}
    accepts_all = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
    named = {p.name for p in sig.parameters.values()
             if p.kind in (p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY)}
    out: dict[str, Any] = {}
    dropped: list[str] = []
    for key, val in (args or {}).items():
        cand = [ARG_ALIASES.get(key, key), key, _snake(key)]
        chosen = next((c for c in cand if c in named), None)
        if chosen is not None:
            out[chosen] = val
        elif accepts_all:
            out[key] = val
        else:
            dropped.append(key)
    if dropped:
        # 以前这里静默丢参数：把 searchClasses 的 kind 写成 match，regex 没生效，
        # 返回 total=0，看着就像"这个 APK 里没有"。假空结果比崩溃更害人，直接拒收。
        raise backends.ApkIndexError(
            backends.ErrorCode.BAD_ARGUMENT,
            f"该工具不接受参数: {', '.join(sorted(dropped))}",
            "有效参数: " + ", ".join(sorted(named)) +
            "（参数名写错会导致空的假结果，别当成'不存在'）")
    return out


def _check_arg_names(name: str, tool: dict, args: dict) -> None:
    """按 tools/list 的 inputSchema 校验参数名。

    只按签名校验有个漏洞：带 **kwargs 的 handler 会把任何拼错的名字照单收下再扔掉
    （searchClasses 把 kind 写成 match 就是这么变成假的 total=0 的）。schema 才是
    对外契约，所以以 schema 为准；camel/snake 两种写法都认。
    """
    props = ((tool.get("inputSchema") or {}).get("properties")) or {}
    if not props:
        return
    allowed = set(props) | {_snake(k) for k in props}
    bad = []
    for k in args:
        if k in allowed or ARG_ALIASES.get(k, k) in allowed or _snake(k) in allowed:
            continue
        bad.append(k)
    if bad:
        raise backends.ApkIndexError(
            backends.ErrorCode.BAD_ARGUMENT,
            f"{name} 不接受参数: {', '.join(sorted(bad))}",
            "有效参数: " + ", ".join(sorted(props)) +
            "。参数名写错曾会导致空的假结果，别把空结果当成'包里不存在'。")


def call_tool(name: str, args: dict | None = None) -> dict:
    """Execute one tool and guarantee the documented return contract."""
    tool = BY_NAME.get(name)
    if tool is None:
        return env.fail(ErrorCode.BAD_ARGUMENT, f"未知工具: {name}",
                        "tools/list 里有全部工具名。")
    args = args or {}
    try:
        _check_arg_names(name, tool, args)
    except backends.ApkIndexError as exc:
        # 参数名写错属于调用方错误：必须回 ok:false，抛穿边界客户端只看到
        # JSON-RPC fault，拿不到"哪个参数、可选哪些"。手机上的 MCP 客户端会直接判服务挂了。
        _log("bad argument", name, repr(exc))
        return env.from_error(exc)
    try:
        result = tool["_fn"](**bind(tool["_fn"], args))
    except (ValueError, re.error) as exc:
        # 正则/枚举/类型不合法属于调用方错误（如 query="((x"），报 INTERNAL
        # 会把人引去翻服务端日志。
        _log("bad argument", name, repr(exc))
        return env.fail(ErrorCode.BAD_ARGUMENT, f"参数不合法: {exc}",
                        "修正 query/regex/枚举取值后重试；见 tools/list 的参数说明。")
    except Exception as exc:                      # noqa: BLE001
        _log("tool error", name, repr(exc))
        result = env.from_error(exc)
    if not isinstance(result, dict):
        result = {"ok": True, "sessionId": args.get("sessionId"),
                  "total": 1, "items": [result], "truncated": False, "hint": ""}
    if "ok" not in result:
        result = env.fail(ErrorCode.INTERNAL, f"{name} 未返回 ok 字段")
    if result.get("ok"):
        result.setdefault("sessionId", args.get("sessionId"))
        result.setdefault("total", len(result.get("items", [])))
        result.setdefault("items", [])
        result.setdefault("truncated", False)
        result.setdefault("hint", "")
        result["tool"] = name
        result = env.enforce_budget(result)
    else:
        result.setdefault("tool", name)
    return result


# 响应契约：所有工具都返回同一个信封（envelope.py 的 ok/fail）。
# 声明 outputSchema 之后，客户端可以校验 structuredContent，而不是靠猜字段。
_ENVELOPE_SCHEMA = {
    "type": "object",
    "properties": {
        "ok": {"type": "boolean"},
        "tool": {"type": "string"},
        "sessionId": {"type": "string"},
        "total": {"type": "integer"},
        "items": {"type": "array"},
        "truncated": {"type": "boolean"},
        "limit": {"type": "integer"},
        "maxBytes": {"type": "integer"},
        "hint": {"type": "string"},
        "elapsedMs": {"type": "number"},
        "code": {"type": "string"},
        "message": {"type": "string"},
        "suggestion": {"type": "string"},
    },
    "required": ["ok"],
    "additionalProperties": True,
}

# 注解是给客户端做自动放行用的：本服务全部只读被分析的包，唯一会删东西的
# 是 unload（删的是自己的索引缓存），所以只有它标 destructive。
_ANNOTATIONS_READ = {"readOnlyHint": True, "destructiveHint": False,
                     "idempotentHint": True, "openWorldHint": False}
_ANNOTATIONS_BUILD = {"readOnlyHint": False, "destructiveHint": False,
                      "idempotentHint": True, "openWorldHint": False}
_ANNOTATIONS_DROP = {"readOnlyHint": False, "destructiveHint": True,
                     "idempotentHint": True, "openWorldHint": False}
_BUILD_TOOLS = {"loadApk", "loadAar", "loadDex"}


def _annotations(name: str) -> dict:
    if name in ("unload", "unloadSession"):
        return _ANNOTATIONS_DROP
    if name in _BUILD_TOOLS:
        return _ANNOTATIONS_BUILD
    return _ANNOTATIONS_READ


def tool_specs() -> list[dict]:
    """MCP tools/list 的条目。annotations 缺省会按 readOnlyHint=true 处理，
    但那是"猜"，明确写出来才能让客户端区分只读查询与建/删索引。"""
    return [{"name": t["name"], "description": t["description"],
             "inputSchema": t["inputSchema"],
             "outputSchema": _ENVELOPE_SCHEMA,
             "annotations": _annotations(t["name"])} for t in TOOLS]


# ------------------------------------------------------------- json-rpc bits
JSONRPC_PROTOCOL_VERSION = "2.0"      # 协议字面量只留这一处
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


def _reply(mid, result=None, error=None, exc=None) -> dict | None:
    """JSON-RPC 回复的唯一出口。

    * ``jsonrpc`` 必须是 "2.0"，不能拿 MCP 协议版本去填；
    * 通知（id 为 None）不回复；
    * ``exc`` 把 code/httpStatus/retryable/hint 放进 error.data，客户端拿到
      非 0 HTTP 时不用去解析正文。
    """
    if mid is None:
        return None
    out: dict = {"jsonrpc": JSONRPC_PROTOCOL_VERSION, "id": mid}
    if error:
        out["error"] = error
        if exc is not None:
            out["error"]["data"] = exc.to_payload()
    else:
        out["result"] = result if result is not None else {}
    return out


class Server:
    def __init__(self) -> None:
        self.initialized = False
        self.protocol = PROTOCOL_VERSIONS[0]

    def server_info(self) -> dict:
        cfg = settings()
        return {"name": NAME, "version": VERSION,
                "instructions": ("apk-index：只读索引目标 App。写 hook 的正确顺序 —— "
                                 "loadApk → searchByString/matchSignature 定位 hook 点 → "
                                 "getSignature 取 Reflector 字符串 → diffSessions 做跨版本适配。"
                                 "禁止凭混淆类名猜测。"),
                "capabilities": {"title": "apk-index",
                                 "environment": {
                                     "allowedRoots": list(cfg.allowed_roots),
                                     "cacheDir": cfg.cache_dir}}}

    def handle(self, msg: dict) -> dict | None:
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
            return _reply(msg.get("id") if isinstance(msg, dict) else None,
                          error={"code": INVALID_REQUEST, "message": "not a JSON-RPC 2.0 object"})
        method = msg.get("method")
        mid = msg.get("id")
        params = msg.get("params") or {}
        if method is None:                       # a response to us -> ignore
            return None
        if method.startswith("notifications/"):
            if method == "notifications/initialized":
                self.initialized = True
            return None
        try:
            if method == "initialize":
                want = params.get("protocolVersion")
                self.protocol = want if want in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]
                return _reply(mid, {
                    "protocolVersion": self.protocol,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": NAME, "version": VERSION,
                                   "title": "apk-index",
                                   "description": ("Read-only APK/AAR/DEX index server for "
                                                   "LSPosed / LibXposed module authors.")},
                    "instructions": self.server_info()["instructions"]})
            if method == "ping":
                return _reply(mid, {})
            if method == "tools/list":
                return _reply(mid, {"tools": tool_specs()})
            if method == "tools/call":
                name = params.get("name") or ""
                args = params.get("arguments") or {}
                if not isinstance(args, dict):
                    return _reply(mid, error={"code": INVALID_PARAMS,
                                              "message": "arguments 必须是 object"})
                t0 = time.time()
                result = call_tool(name, args)
                raw = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
                # text 给人读（也仍可喂模型），structuredContent 给机器，别再重复同一坨 JSON
                text = render(name, result)
                _log("call", name, f"{(time.time() - t0) * 1000:.0f}ms",
                     f"{len(raw)}B", "ok" if result.get("ok") else result.get("code"))
                return _reply(mid, {
                    "content": [{"type": "text", "text": text}],
                    "structuredContent": result,
                    "isError": not bool(result.get("ok"))})
            if method in ("resources/list", "resources/templates/list", "prompts/list"):
                return _reply(mid, {("resources" if method.startswith("resources") else "prompts"): []})
            if method == "logging/setLevel":
                global VERBOSE
                VERBOSE = (params.get("level") or "") in ("debug", "info")
                return _reply(mid, {})
            return _reply(mid, error={"code": METHOD_NOT_FOUND,
                                      "message": f"unknown method: {method}"})
        except Exception as exc:                                  # noqa: BLE001
            traceback.print_exc(file=sys.stderr)
            return _reply(mid, error={"code": INTERNAL_ERROR,
                                      "message": f"{type(exc).__name__}: {exc}"})


def serve(stdin=None, stdout=None) -> int:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    srv = Server()
    for raw in stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as e:
            out = {"jsonrpc": "2.0", "id": None,
                   "error": {"code": PARSE_ERROR, "message": f"invalid JSON: {e}"}}
            stdout.write(json.dumps(out, ensure_ascii=False) + "\n")
            stdout.flush()
            continue
        msgs = msg if isinstance(msg, list) else [msg]
        replies = [srv.handle(m) for m in msgs]
        for rep in replies:
            if rep is not None:
                stdout.write(json.dumps(rep, ensure_ascii=False) + "\n")
        stdout.flush()
    return 0


# ---------------------------------------------------------------- CLI modes
def _one_shot(name: str, args: dict) -> int:
    print(json.dumps(call_tool(name, args), ensure_ascii=False, indent=2))
    return 0


def selftest() -> int:
    """In-process protocol check: handshake, tool table, three real calls."""
    srv = Server()
    problems: list[str] = []
    init = srv.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": PROTOCOL_VERSIONS[0],
                                  "capabilities": {}, "clientInfo": {"name": "selftest",
                                                                     "version": "0"}}})
    if not init or init.get("result", {}).get("serverInfo", {}).get("name") != NAME:
        problems.append("initialize 未返回 serverInfo")
    lst = srv.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    tools = lst["result"]["tools"] if lst else []
    if len(tools) != len(TOOLS):
        problems.append(f"tools/list 少了工具: {len(tools)}/{len(TOOLS)}")
    for t in tools:
        if not t.get("inputSchema", {}).get("properties"):
            problems.append(f"{t['name']} 缺 inputSchema.properties")
        blob = len(json.dumps(t, ensure_ascii=False).encode())
        if blob > 4000:
            problems.append(f"{t['name']} schema 过大 {blob}B")
    unknown = srv.handle({"jsonrpc": "2.0", "id": 3, "method": "bogus/method"})
    if not unknown or unknown.get("error", {}).get("code") != METHOD_NOT_FOUND:
        problems.append("未知方法未返回 -32601")
    bad = call_tool("searchClasses", {"sessionId": "ses_nope", "query": "a"})
    if bad.get("code") != ErrorCode.SESSION_NOT_FOUND:
        problems.append(f"SESSION_NOT_FOUND 契约不成立: {bad}")
    size = len(json.dumps(bad, ensure_ascii=False).encode())
    if size > MAX_RESPONSE_BYTES:
        problems.append(f"错误响应超预算 {size}B")
    print(json.dumps({"protocol": srv.protocol, "tools": len(tools),
                      "problems": problems}, ensure_ascii=False, indent=2))
    return 1 if problems else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog=NAME, description=NAME + " MCP server")
    ap.add_argument("mode", nargs="?", default="serve",
                    choices=["serve", "tools", "call", "selftest", "version", "env"])
    ap.add_argument("rest", nargs="*")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args(argv)
    global VERBOSE
    VERBOSE = VERBOSE or a.verbose
    if a.mode == "version":
        print(f"{NAME} {VERSION} (protocol {PROTOCOL_VERSIONS[0]})")
        return 0
    if a.mode == "env":
        cfg = settings()
        print(json.dumps({"allowedRoots": list(cfg.allowed_roots),
                          "cacheDir": cfg.cache_dir, "jadxHome": cfg.jadx_home,
                          "baksmaliJar": cfg.baksmali_jar,
                          "engines": decomp.engines(),
                          "backends": backends.available_backends()},
                         ensure_ascii=False, indent=2))
        return 0
    if a.mode == "tools":
        print(json.dumps(tool_specs(), ensure_ascii=False, indent=2))
        return 0
    if a.mode == "selftest":
        return selftest()
    if a.mode == "call":
        if not a.rest:
            print("用法: apk-index call <tool> '<json>'", file=sys.stderr)
            return 2
        args = json.loads(a.rest[1]) if len(a.rest) > 1 else {}
        return _one_shot(a.rest[0], args)
    return serve()


if __name__ == "__main__":
    raise SystemExit(main())
