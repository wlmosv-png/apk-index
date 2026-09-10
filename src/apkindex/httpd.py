"""Streamable HTTP 传输 —— 给只能填 URL 的 MCP 客户端（手机 App 内的客户端就是这种）。

只依赖标准库。协议行为与 stdio 版完全一致，共用 server.Server.handle()：

  POST /mcp    一条 JSON-RPC 请求      -> 200 + JSON 应答（客户端 Accept 里写了
               text/event-stream 就改成 SSE 单帧；有的 SDK 只认 SSE）
               通知（没有 id）         -> 202 空 body
               批量数组                -> 200 + JSON 数组
  GET  /mcp    Accept 要 event-stream -> 常驻 SSE 流（只发注释帧保活）
               否则                    -> 200 + {ok,name,version,tools} 健康检查
  DELETE /mcp  客户端结束会话          -> 200（回 501 会被当成服务故障）
  OPTIONS      CORS 预检               -> 204

initialize 的应答带 Mcp-Session-Id / MCP-Protocol-Version 头。这里**只发不校验**：
严格拒绝未知会话 id 会让实现松一点的客户端直接卡死，而本服务无状态可泄漏。

默认只绑 127.0.0.1：本机 App 能连，同网段别人连不上。
真要从局域网连自己加 --host 0.0.0.0；索引只读，但里面是别人 App 的代码结构。
"""
from __future__ import annotations

import hmac
import json
import os
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .server import (INTERNAL_ERROR, INVALID_PARAMS, INVALID_REQUEST,
                     JSONRPC_PROTOCOL_VERSION, METHOD_NOT_FOUND, PARSE_ERROR,
                     Server, VERSION, tool_specs)

JSONRPC_VERSION = JSONRPC_PROTOCOL_VERSION
MAX_BODY_BYTES = int(os.environ.get("APK_INDEX_MAX_BODY_BYTES") or 4194304)
# 规范没规定业务错误用哪个状态码，这里把映射集中一处，客户端好判断。
_HTTP_OF_RPC = {PARSE_ERROR: 400, INVALID_REQUEST: 400, METHOD_NOT_FOUND: 404,
                INVALID_PARAMS: 400, INTERNAL_ERROR: 500}

MCP_PATH = "/mcp"
# JSON-RPC 保留区 -32000..-32099 留给实现自定义，鉴权失败放这里。
UNAUTHORIZED = -32002
# 两个环境变量名都收：APK_INDEX_MCP_TOKEN 是文档写法，APK_INDEX_TOKEN 是短别名。
TOKEN_ENV = ("APK_INDEX_MCP_TOKEN", "APK_INDEX_TOKEN")


def env_token() -> str:
    for k in TOKEN_ENV:
        v = (os.environ.get(k) or "").strip()
        if v:
            return v
    return ""


def _authorized(token: str, headers) -> bool:
    """token 为空 = 没开鉴权（默认只绑 127.0.0.1，本机自用）。"""
    if not token:
        return True
    got = ""
    auth = headers.get("Authorization") or ""
    if auth[:7].lower() == "bearer ":
        got = auth[7:].strip()
    if not got:
        got = (headers.get("X-Apk-Index-Token") or "").strip()
    return bool(got) and hmac.compare_digest(got, token)

_LOCK = threading.Lock()   # sqlite 连接 check_same_thread=False 是共享的，串行最稳
SSE = "text/event-stream"
# 常见 MCP 客户端会带的头，--verbose 时打出来，出问题时一眼能对上
PROBE_HEADERS = ("Accept", "Content-Type", "MCP-Protocol-Version",
                 "MCP-Session-Id", "Last-Event-ID", "User-Agent")


def _wants_sse(accept: str) -> bool:
    """只在客户端**不**接受 application/json 时才用 SSE 帧。

    单条响应用裸 JSON 是合规且更省事的写法。有的 Kotlin/ktor 客户端一进
    text/event-stream 就切到"等流结束"的读法，白等一个 request_timeout；
    实测 ktor-client 系客户端 就是这个行为。所以：两边都接受 → JSON。
    """
    a = (accept or "").lower()
    if "application/json" in a or a.strip() in ("*/*", ""):
        return False
    return SSE in a or "text/*" in a


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "apk-index/" + VERSION

    # ------------------------------------------------------------ helpers
    def _cors(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers",
                         "Content-Type, Accept, MCP-Protocol-Version, "
                         "MCP-Session-Id, Last-Event-ID")
        self.send_header("Access-Control-Expose-Headers",
                         "Mcp-Session-Id, MCP-Protocol-Version")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, DELETE, OPTIONS")

    def _send(self, code: int, body: bytes = b"", ctype: str = "application/json",
              extra: dict | None = None, close: bool = False) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if not close:
            self.send_header("Content-Length", str(len(body)))
        self._cors()
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        if close:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, code: int, obj, extra: dict | None = None) -> None:
        """按客户端的 Accept 选 JSON 或 SSE 单帧，协议内容完全一样。"""
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        if _wants_sse(self.headers.get("Accept", "")):
            self._send(code, b"event: message\ndata: " + body + b"\n\n",
                       ctype="text/event-stream", extra=extra)
        else:
            self._send(code, body, extra=extra)

    def _err(self, code: int, rpc_code: int, message: str, mid=None) -> None:
        """传输层错误。id 取自请求信封 —— 回 null id 等于让客户端一直等回复。"""
        self._status(code, {"jsonrpc": JSONRPC_VERSION, "id": mid,
                           "error": {"code": rpc_code, "message": message}})

    def _status(self, code: int, obj, extra: dict | None = None) -> None:
        """带契约头的响应。code=0 表示按 JSON-RPC 错误码推导 HTTP 状态。

        MCP 流式 HTTP 只规定了几种状态码；全回 200 会让只看状态码的客户端
        （网关、curl -f、健康检查）把失败当成成功。
        """
        if not code:
            # 批量里只要有一条成功就 overall 200，逐条状态在各自信封里
            parts = obj if isinstance(obj, list) else [obj]
            errs = [p.get("error") for p in parts if isinstance(p, dict) and p.get("error")]
            if not errs:
                code = 200
            elif len(errs) < len(parts):
                code = 200
            else:
                code = _HTTP_OF_RPC.get(errs[0].get("code"), 500)
        extra = dict(extra or {})
        extra.setdefault("Content-Type", "application/json")
        extra.setdefault("Cache-Control", "no-store")
        extra.setdefault("X-Apk-Index-Max-Size", str(MAX_BODY_BYTES))
        self._send_json(code, obj, extra=extra)

    def _is_mcp(self) -> bool:
        return self.path.split("?")[0].rstrip("/") in (MCP_PATH, "")

    def _note(self, text: str) -> None:
        if getattr(self.server, "verbose", False):
            sys.stderr.write("http %s %s\n" % (self.address_string(), text))
            sys.stderr.flush()

    # ------------------------------------------------------------ methods
    def do_OPTIONS(self) -> None:                                    # noqa: N802
        self._send(204)

    def do_GET(self) -> None:                                        # noqa: N802
        if not self._is_mcp():
            return self._err(404, INVALID_REQUEST, f"只有 {MCP_PATH} 提供 MCP")
        srv = self.server.mcp                                        # type: ignore[attr-defined]
        if _wants_sse(self.headers.get("Accept", "")):
            # 真 SSE 流：本服务不主动推东西，所以只发注释帧保活，等客户端断开。
            # 不给 Content-Length，靠关连接收尾（HTTP/1.1 允许）。
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self._cors()
            self.send_header("Connection", "close")
            self.close_connection = True
            self.end_headers()
            try:
                while True:
                    self.wfile.write(b": apk-index\n\n")
                    self.wfile.flush()
                    time.sleep(15)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            self._note("GET stream closed")
            return
        info = srv.server_info()
        self._status(200, {"ok": True, "name": info["name"], "version": info["version"],
                           "transport": "streamable-http", "endpoint": MCP_PATH,
                           "tools": len(tool_specs()),
                           "maxRequestBytes": MAX_BODY_BYTES,
                           "sessionMode": "stateless",
                           # 健康检查不要 token：启动器要靠它探活。它不含任何包内容。
                           "auth": "token" if getattr(self.server, "token", "")
                                   else "none"},
                     extra={"Accept": "application/json",
                            "Cache-Control": "no-store, max-age=0",
                            "Vary": "Accept, Origin"})

    def _unauth(self) -> None:
        # 用 401 而不是 403：MCP 客户端一般把 401 读成"要凭据"，会提示去填 token。
        # 回 200 + 业务错误会让只看状态码的东西（curl -f、网关、健康检查）把失败当成功。
        self._send(401, json.dumps({
            "jsonrpc": JSONRPC_VERSION, "id": getattr(self, "_rpc_id", None),
            "error": {"code": UNAUTHORIZED,
                      "message": "缺 token：带 Authorization: Bearer <token> 或 "
                                 "X-Apk-Index-Token 头",
                      "data": {"hint": "服务端设了 APK_INDEX_MCP_TOKEN"}}},
            ensure_ascii=False).encode("utf-8"),
            extra={"WWW-Authenticate": 'Bearer realm="apk-index"'})

    def do_DELETE(self) -> None:                                     # noqa: N802
        if not self._is_mcp():
            return self._err(404, INVALID_REQUEST, f"只有 {MCP_PATH} 提供 MCP")
        if not _authorized(getattr(self.server, "token", ""), self.headers):
            return self._unauth()
        self._send(200, b"")

    def do_POST(self) -> None:                                       # noqa: N802
        try:
            self._post()
        except Exception as exc:                                  # noqa: BLE001
            # 意外异常必须回东西：直接断连 + 空响应是最难查的故障形态
            # （客户端只看到 connection reset），500 至少能看见原因。
            self._note("POST 内部异常 %s: %s" % (type(exc).__name__, exc))
            try:
                self._err(500, INTERNAL_ERROR, f"{type(exc).__name__}: {exc}",
                          mid=getattr(self, "_rpc_id", None))
            except Exception:                                     # noqa: BLE001
                self._note("500 都没发出去：连接已经断了")

    def _post(self) -> None:
        if not self._is_mcp():
            return self._err(404, INVALID_REQUEST, f"只有 {MCP_PATH} 提供 MCP")
        if not _authorized(getattr(self.server, "token", ""), self.headers):
            return self._unauth()
        hdr = " | ".join("%s=%s" % (h, self.headers.get(h)) for h in PROBE_HEADERS
                         if self.headers.get(h))
        self._note("POST " + hdr)
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n > MAX_BODY_BYTES:
            # 超限：不解析、不建索引，但要把正文读干净再回 413 —— 直接回话就关
            # 连接会把客户端的写端打断，它只能看到 broken pipe 而不是 413。
            left = n
            while left > 0:
                chunk = self.rfile.read(min(left, 65536))
                if not chunk:
                    break
                left -= len(chunk)
            return self._err(413, INVALID_REQUEST,
                             "请求体 %dB 超过上限 %dB" % (n, MAX_BODY_BYTES))
        raw = self.rfile.read(n) if n > 0 else b""
        if not raw:
            return self._err(400, INVALID_REQUEST,
                             "空 body：MCP 请求要 POST 一个 JSON-RPC 对象")
        try:
            msg = json.loads(raw.decode("utf-8"))
        except Exception as exc:                                     # noqa: BLE001
            return self._err(400, PARSE_ERROR, f"JSON 解析失败: {exc}")
        batch = isinstance(msg, list)
        items = msg if batch else [msg]
        # 留给 500 兜底用：异常发生时至少还能把 id 还给客户端
        self._rpc_id = None if batch else msg.get("id")
        if not all(isinstance(m, dict) for m in items):
            return self._err(400, INVALID_REQUEST, "JSON-RPC 每条必须是 object",
                             mid=items[0].get("id")
                             if items and isinstance(items[0], dict) else None)
        # 标签：tools/call 带工具名，别的带方法名 —— 慢请求/卡住请求的定位全靠它
        tag = ",".join(("tools/call:%s" % ((m.get("params") or {}).get("name")
                                           if m.get("method") == "tools/call" else "?"))
                       if m.get("method") == "tools/call" else str(m.get("method"))
                       for m in items)
        self._note("POST -> %s (%d bytes body)" % (tag, len(raw)))
        srv = self.server.mcp                                        # type: ignore[attr-defined]
        t0 = time.perf_counter()
        with _LOCK:
            replies = [r for r in (srv.handle(m) for m in items) if r is not None]
        dt_ms = (time.perf_counter() - t0) * 1000.0
        if dt_ms > 500.0:
            self._note("SLOW %.0fms %s（这段时间里其他请求都在排全局锁）" % (dt_ms, tag))
        if not replies:                       # 纯通知：202，不给 body
            return self._send(202)
        def _fix(r):
            """回复必须自证协议；丢了 id 就按同名请求补回来。"""
            if not isinstance(r, dict):
                return r
            r = dict(r)
            r.setdefault("jsonrpc", JSONRPC_VERSION)
            if r.get("id") is None:
                for m in items:
                    if (isinstance(m, dict) and m.get("method") == r.get("method")
                            and "id" in m):
                        r["id"] = m["id"]
                        break
            return r

        body = [_fix(r) for r in replies] if batch else _fix(replies[0])
        extra = {}
        if not batch and isinstance(body, dict) and \
                body.get("result", {}).get("protocolVersion"):
            # initialize 成功：给个会话 id 与协商到的协议版本（只发不校验）
            extra["Mcp-Session-Id"] = uuid.uuid4().hex[:16]
            extra["MCP-Protocol-Version"] = body["result"]["protocolVersion"]
        self._status(0, body, extra=extra)

class HttpServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, host: str = "127.0.0.1", port: int = 8732,
                 verbose: bool = False, token: str | None = None) -> None:
        super().__init__((host, port), Handler)
        self.mcp = Server()
        self.verbose = verbose
        # None = 读环境变量；"" = 明确关鉴权
        self.token = env_token() if token is None else (token or "").strip()


_LOOPBACK = ("127.0.0.1", "localhost", "::1")


def serve(host: str = "127.0.0.1", port: int = 8732,
          verbose: bool = False, token: str | None = None) -> int:
    httpd = HttpServer(host, port, verbose, token)
    if host not in _LOOPBACK and not httpd.token:
        # 索引本身只读，但里面装的是别人 App 的代码结构；
        # 无鉴权暴露到局域网等于把整套结构图公开。宁可不起。
        sys.stderr.write(
            f"拒绝启动：host={host} 不是回环地址，且没设 token。\n"
            "要么绑 127.0.0.1（默认），要么设 APK_INDEX_MCP_TOKEN 后重试。\n")
        return 2
    sys.stderr.write(f"apk-index {VERSION} streamable-http 监听 "
                     f"http://{host}:{port}{MCP_PATH}"
                     f"{'，token 鉴权已开' if httpd.token else '，无鉴权(仅本机)'}\n")
    sys.stderr.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0
