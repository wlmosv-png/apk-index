"""渲染层与体积契约的四条硬约束：不撒谎、不静默丢弃、不超预算、每个工具都有版式。

这些测试不需要真实 APK —— 直接喂 envelope dict，因此能在毫秒级跑完，
也保证 tool_specs() 改名时立刻在这里爆。
"""
import json
import sys
import unittest

sys.path.insert(0, "src")
from apkindex import envelope, render, server  # noqa: E402


def env(tool, **kw):
    base = {"ok": True, "tool": tool, "items": [], "total": 0, "truncated": False,
            "hint": "", "elapsedMs": 3, "sessionId": "s"}
    base.update(kw)
    return base


class RenderTest(unittest.TestCase):
    def test_错误信封给出码与建议(self):
        res = {"ok": False, "tool": "searchClasses", "code": "INVALID_PATH",
               "message": "文件不存在", "suggestion": "先 loadApk"}
        text = render.render("searchClasses", res)
        self.assertIn("INVALID_PATH", text)
        self.assertIn("文件不存在", text)
        self.assertIn("先 loadApk", text)

    def test_真实字段进其他(self):
        text = render.render("stats", env("stats", summary={"a": 1}, backend="builtin"))
        self.assertIn("其他", text)
        self.assertIn("summary", text)

    def test_框架字段不算噪声(self):
        text = render.render("searchClasses", env("searchClasses"))
        for noise in ("elapsedMs", "'truncated'", "structuredContent", "None"):
            self.assertNotIn(noise, text)

    def test_getSignature_类级结果与注解必须印出来(self):
        """不带 member 时以前只印"0 个匹配"，四种写法和注解全在 signature 里丢了。"""
        cls = {"descriptor": "Ldemo/User;", "binaryName": "demo.User",
               "javaName": "demo.User", "smali": "Ldemo/User;",
               "reflector": "demo.User", "classForName": '\"demo.User\"',
               "kotlinDsl": 'clazz("demo.User")',
               "annotations": [{"descriptor": "Ldemo/Keep;", "javaName": "demo.Keep",
                                "visibility": "runtime", "values": {"value": "x"},
                                "valuesClipped": True}]}
        res = env("getSignature", total=0, signature={
            "class": cls,
            "parent": {"superClass": "java.lang.Object", "interfaceNames": ["demo.I"]},
            "member": None})
        text = render.render("getSignature", res)
        self.assertIn("demo.User", text)
        self.assertIn("reflector", text)
        self.assertIn("demo.Keep(runtime)", text)
        self.assertIn("parent", text)
        self.assertNotIn("0 个匹配", text)
        self.assertIn("没带 member", text)

        res2 = env("getSignature", total=1, signature={"class": cls, "member": "signIn"},
                   items=[{"kind": "method", "name": "signIn",
                           "forms": {"owner": "demo.User", "name": "signIn",
                                     "java": "void signIn()",
                                     "smali": "Ldemo/User;->signIn()V",
                                     "reflector": "demo.User#signIn",
                                     "paramsDescriptor": "()",
                                     "returnDescriptor": "V"},
                           "annotations": [{"descriptor": "Ldemo/Hook;",
                                            "javaName": "demo.Hook",
                                            "visibility": "build"}]}])
        t2 = render.render("getSignature", res2)
        self.assertIn("signIn", t2)
        self.assertIn("demo.Hook(build)", t2)
        self.assertIn("1 个成员", t2)

    def test_长列表被压缩(self):
        items = [{"descriptor": "Lcom/a/%d;" % i, "className": "C%d" % i,
                  "packageName": "com.a", "kind": "class", "match": "prefix"}
                 for i in range(1200)]
        text = render.render("searchClasses",
                             env("searchClasses", items=items, total=len(items)))
        self.assertLess(len(text), 6000)
        self.assertIn("…", text)

    def test_每个工具都有专属版式(self):
        missing = sorted(set(server.BY_NAME) - set(render.RENDERERS))
        self.assertEqual([], missing, "这些工具还在走兜底打印: %s" % missing)

    def test_坏输入不抛异常(self):
        for bad in (None, [], {"items": [{"x": (i,)} for i in range(50)]},
                    {"ok": True, "items": "not-a-list"}, env("stats", items=[None, 3])):
            self.assertIsInstance(render.render("stats", bad), str)


class BudgetTest(unittest.TestCase):
    def _size(self, res):
        return len(json.dumps(res, ensure_ascii=False).encode("utf-8"))

    def test_maxBytes_生效(self):
        items = [{"descriptor": "L%08d;" % i, "className": "c" * 40}
                 for i in range(2000)]
        res = envelope.ok(items, session_id="s", total=len(items), maxBytes=4000)
        self.assertLessEqual(self._size(res), 4000)
        self.assertTrue(res["truncated"])

    def test_默认仍受全局上限约束(self):
        res = envelope.ok([{"x": "y" * 100}] * 500, session_id="s")
        self.assertLessEqual(self._size(res), envelope.MAX_RESPONSE_BYTES)

    def test_maxBytes_过小不会被压成空壳(self):
        res = envelope.ok([{"a": 1}] * 300, session_id="s", maxBytes=2048)
        self.assertIn("sessionId", res)
        self.assertLessEqual(self._size(res), envelope.MAX_RESPONSE_BYTES)


if __name__ == "__main__":
    unittest.main(verbosity=2)
