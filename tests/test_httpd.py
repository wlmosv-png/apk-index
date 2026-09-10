"""HTTP 传输层的契约测试：协议字段、状态码映射、体积上限、异常兜底。

进程内起一个真服务器（随机端口），走真 urllib，所以这些断言就是客户端
会看到的行为。
"""
import json
import socket
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, "src")
from apkindex import httpd, server  # noqa: E402


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TokenAuthTest(unittest.TestCase):
    """设了 APK_INDEX_MCP_TOKEN 之后：读代码的口子必须锁，探活的口子必须留。"""

    TOKEN = "test-token-9f3a"

    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        cls.httpd = httpd.HttpServer("127.0.0.1", cls.port, verbose=False,
                                     token=cls.TOKEN)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)

    def _raw(self, method, body=b"", headers=None, path="/mcp"):
        req = urllib.request.Request("http://127.0.0.1:%d%s" % (self.port, path),
                                     data=body, method=method, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), dict(exc.headers)

    def _ping(self, headers=None):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list",
                           "params": {}}).encode()
        h = {"Content-Type": "application/json"}
        h.update(headers or {})
        return self._raw("POST", body, h)

    def test_没带token_应当401并给WWWAuthenticate(self):
        code, body, hdr = self._ping()
        self.assertEqual(401, code)
        obj = json.loads(body.decode())
        self.assertEqual(httpd.UNAUTHORIZED, obj["error"]["code"])
        self.assertIn("Bearer", hdr.get("WWW-Authenticate", ""))

    def test_错token_同样401(self):
        code, _b, _h = self._ping({"Authorization": "Bearer wrong-value"})
        self.assertEqual(401, code)

    def test_Bearer与自定义头都能放行(self):
        for h in ({"Authorization": "Bearer " + self.TOKEN},
                  {"X-Apk-Index-Token": self.TOKEN}):
            code, body, _ = self._ping(h)
            self.assertEqual(200, code, h)
            self.assertIn("tools", json.loads(body.decode())["result"])

    def test_健康检查不要token(self):
        code, body, _ = self._raw("GET", path="/mcp")
        self.assertEqual(200, code)
        self.assertEqual("token", json.loads(body.decode())["auth"])

    def test_DELETE也要token(self):
        self.assertEqual(401, self._raw("DELETE")[0])
        self.assertEqual(200, self._raw(
            "DELETE", headers={"X-Apk-Index-Token": self.TOKEN})[0])

    def test_不设token时完全无鉴权(self):
        port = _free_port()
        srv = httpd.HttpServer("127.0.0.1", port, verbose=False, token="")
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        try:
            req = urllib.request.Request(
                "http://127.0.0.1:%d/mcp" % port,
                data=json.dumps({"jsonrpc": "2.0", "id": 1,
                                 "method": "tools/list", "params": {}}).encode(),
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as r:
                self.assertEqual(200, r.status)
            with urllib.request.urlopen(
                    "http://127.0.0.1:%d/mcp" % port, timeout=10) as g:
                self.assertEqual(200, g.status)
                body = json.loads(g.read().decode())
            self.assertEqual("none", body["auth"])
        finally:
            srv.shutdown()
            srv.server_close()
            th.join(timeout=5)


class GuardTest(unittest.TestCase):
    def test_非回环地址且无token_拒绝启动(self):
        # 不能只警告：无鉴权暴露到局域网等于把别人 App 的代码结构图公开。
        self.assertEqual(2, httpd.serve(host="0.0.0.0", port=_free_port(), token=""))

    def test_回环地址无token_仍然允许(self):
        # 本机自用是默认场景，不能把 stdio 之外唯一常用形态也锁死。
        port = _free_port()
        th = threading.Thread(target=lambda: httpd.serve(host="127.0.0.1",
                                                        port=port, token=""),
                              daemon=True)
        th.start()
        try:
            deadline = time.time() + 5
            while time.time() < deadline:
                try:
                    with urllib.request.urlopen(
                            "http://127.0.0.1:%d/mcp" % port, timeout=2) as r:
                        self.assertEqual("none", json.loads(r.read().decode())["auth"])
                    break
                except OSError:
                    time.sleep(0.05)
            else:
                self.fail("回环 + 无 token 应该正常起")
        finally:
            pass   # serve() 起来的线程是 daemon，进程退出即回收


class HttpContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        cls.httpd = httpd.HttpServer("127.0.0.1", cls.port, verbose=False)
        cls.httpd.mcp = server.Server()
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)

    # ------------------------------------------------------------- helpers
    def _raw(self, method, path, body=b"", headers=None):
        req = urllib.request.Request("http://127.0.0.1:%d%s" % (self.port, path),
                                     data=body, method=method,
                                     headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), dict(exc.headers)

    def _post(self, msg):
        return self._raw("POST", "/mcp",
                         json.dumps(msg).encode("utf-8"),
                         {"Content-Type": "application/json"})

    def _call(self, msg):
        code, body, _hdr = self._post(msg)
        return code, json.loads(body.decode("utf-8"))

    # --------------------------------------------------------------- tests
    def test_get_mcp_给出契约信息(self):
        code, body, hdr = self._raw("GET", "/mcp")
        self.assertEqual(200, code)
        info = json.loads(body.decode())
        self.assertEqual("/mcp", info["endpoint"])
        self.assertGreater(info["tools"], 0)
        self.assertIn("maxRequestBytes", info)
        self.assertIn("application/json", hdr.get("Content-Type", ""))
        self.assertEqual("no-store, max-age=0", hdr.get("Cache-Control"))

    def test_initialize_回显协商版本且_jsonrpc_为_20(self):
        code, reply = self._call({"jsonrpc": "2.0", "id": 7, "method": "initialize",
                                  "params": {"protocolVersion": "2025-03-26",
                                             "capabilities": {},
                                             "clientInfo": {"name": "t", "version": "0"}}})
        self.assertEqual(200, code)
        self.assertEqual("2.0", reply["jsonrpc"])
        self.assertEqual(7, reply["id"])
        self.assertEqual("2025-03-26", reply["result"]["protocolVersion"])

    def test_未知方法映射_404(self):
        code, reply = self._call({"jsonrpc": "2.0", "id": 8, "method": "nope/x"})
        self.assertEqual(404, code)
        self.assertEqual(-32601, reply["error"]["code"])
        self.assertEqual(8, reply["id"])

    def test_坏_json_是_parse_error_且带_id_为_null(self):
        code, body, _hdr = self._raw("POST", "/mcp", b"{not json",
                                     {"Content-Type": "application/json"})
        self.assertEqual(400, code)
        reply = json.loads(body.decode())
        self.assertEqual(-32700, reply["error"]["code"])
        self.assertIsNone(reply["id"])

    def test_非_mcp_路径_404(self):
        code, _body, _hdr = self._raw("GET", "/other")
        self.assertEqual(404, code)

    def test_空_body_400(self):
        code, body, _hdr = self._raw("POST", "/mcp", b"",
                                     {"Content-Type": "application/json"})
        reply = json.loads(body.decode())
        self.assertEqual(400, code)
        self.assertEqual(-32600, reply["error"]["code"])

    def test_超过体积上限_413(self):
        big = json.dumps({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                          "params": {"name": "stats",
                                     "arguments": {"pad": "x" * (httpd.MAX_BODY_BYTES + 10)}}})
        code, body, hdr = self._raw("POST", "/mcp", big.encode("utf-8"),
                                    {"Content-Type": "application/json"})
        self.assertEqual(413, code)
        self.assertEqual(str(httpd.MAX_BODY_BYTES), hdr.get("X-Apk-Index-Max-Size"))
        self.assertEqual(-32600, json.loads(body.decode())["error"]["code"])

    def test_batch_每条都带_id(self):
        code, reply = self._call([{"jsonrpc": "2.0", "id": 1, "method": "ping"},
                                  {"jsonrpc": "2.0", "id": 2, "method": "ping"}])
        self.assertEqual(200, code)
        self.assertEqual([1, 2], [r["id"] for r in reply])

    def test_通知不回_body(self):
        code, body, _hdr = self._post({"jsonrpc": "2.0",
                                       "method": "notifications/initialized"})
        self.assertEqual(202, code)
        self.assertEqual(b"", body)

    def test_内部异常回_500_而不是断连(self):
        class Boom(server.Server):
            def handle(self, msg):
                raise RuntimeError("故意炸")
        saved = self.httpd.mcp
        try:
            self.httpd.mcp = Boom()
            code, reply = self._call({"jsonrpc": "2.0", "id": 11, "method": "tools/list"})
        finally:
            self.httpd.mcp = saved
        self.assertEqual(500, code)
        self.assertEqual(-32603, reply["error"]["code"])
        self.assertEqual(11, reply["id"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
