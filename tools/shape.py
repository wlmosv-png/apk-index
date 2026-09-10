"""打印每个工具返回值的结构（键名+类型），用于校准测试断言。"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
os.environ["APK_INDEX_CACHE_DIR"] = os.environ.get(
    "APK_INDEX_CACHE_DIR", os.path.join(ROOT, ".smoketmp", "cache"))
os.environ["APK_INDEX_ALLOWED_ROOTS"] = ROOT + ":/data/local/tmp"
from apkindex import loaders, server  # noqa: E402


def shape(v, depth=0):
    if isinstance(v, dict):
        if depth >= 3:
            return "{...%d}" % len(v)
        return {k: shape(val, depth + 1) for k, val in v.items()}
    if isinstance(v, list):
        return [shape(x, depth + 1) for x in v[:1]] + (["...%d" % len(v)] if len(v) > 1 else [])
    if isinstance(v, str):
        return v if len(v) <= 46 else v[:43] + "..."
    return v


fx = os.path.join(ROOT, "fixtures")
s1 = loaders.load_apk(os.path.join(fx, "demo-v1.apk"))["sessionId"]
s2 = loaders.load_apk(os.path.join(fx, "demo-v2.apk"))["sessionId"]
CASES = [
    ("probe", {"sessionId": s1, "question": '哪里用到了 "Hello, "'}),
    ("decompile", {"sessionId": s1, "target": "com.example.demo.User", "format": "outline"}),
    ("matchSignature", {"sessionId": s1, "referredStrings": ["Hello, "]}),
    ("diffSessions", {"sessionA": s1, "sessionB": s2, "limit": 40}),
    ("xref", {"sessionId": s1, "method": "Lcom/example/demo/User;->getName()Ljava/lang/String;",
              "direction": "callers", "depth": 2}),
    ("findImplementations", {"sessionId": s1, "interface": "com.example.demo.Greeter"}),
    ("searchByString", {"sessionId": s1, "text": "Hello", "match": "contains"}),
    ("getSignature", {"sessionId": s1, "class": "com.example.demo.User", "member": "describe"}),
    ("listMembers", {"sessionId": s1, "class": "com.example.demo.Strings"}),
    ("checkPacker", {"sessionId": loaders.load_apk(os.path.join(fx, "packed.apk"))["sessionId"]}),
    ("stats", {"sessionId": s1}),
]
for name, args in CASES:
    out = server.call_tool(name, args)
    txt = json.dumps(shape(out), ensure_ascii=False, indent=None)
    print("#### %s ok=%s total=%s\n%s\n" % (name, out.get("ok"), out.get("total"),
                                            txt[:1500]))
