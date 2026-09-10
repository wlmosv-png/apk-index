"""校准：打印 loaders 各入口与几个工具的顶层键，供测试断言使用。"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
os.environ["APK_INDEX_CACHE_DIR"] = os.path.join(ROOT, ".calib", "cache")
os.environ["APK_INDEX_SHARED_DIR"] = os.path.join(ROOT, ".calib", "share")
os.environ["APK_INDEX_ALLOWED_ROOTS"] = ROOT
from apkindex import loaders, server, config  # noqa: E402

print("settings.cache_dir =", config.settings().cache_dir)
fx = os.path.join(ROOT, "fixtures")


def keys(label, d, depth=0):
    if not isinstance(d, dict):
        print("  " * depth + f"{label}: {type(d).__name__}")
        return
    print("  " * depth + f"{label}: " + ", ".join(sorted(d.keys()))[:400])


a = loaders.load_apk(os.path.join(fx, "demo-v1.apk"))
keys("load_apk", a)
keys("  fingerprint", a.get("fingerprint"))
keys("  index", a.get("index"))
keys("  manifest", a.get("manifest"))
keys("    application", (a.get("manifest") or {}).get("application", {}))
print("   dexCount=%s totalClasses=%s alreadyLoaded=%s status=%s" % (
    a["fingerprint"].get("dexCount"), a["fingerprint"].get("totalClasses"),
    a["index"].get("alreadyLoaded"), json.dumps(a["index"].get("status"), ensure_ascii=False)[:200]))
sid = a["sessionId"]
b = loaders.load_apk(os.path.join(fx, "demo-v2.apk"))
sid2 = b["sessionId"]
print("   v2 classes=%s dex=%s" % (b["fingerprint"]["totalClasses"], b["fingerprint"]["dexCount"]))
d = loaders.load_apk(os.path.join(fx, "split-demo", "com.example.demo"))
print("   split: sid=%s dex=%s classes=%s splits=%s" % (
    d["sessionId"], d["fingerprint"]["dexCount"], d["fingerprint"]["totalClasses"],
    d["fingerprint"]["splits"]))
p = loaders.load_apk(os.path.join(fx, "packed.apk"))
print("   packed: ok=%s code=%s packed=%s sid=%s" % (
    p.get("ok"), p.get("code"), p.get("packed"), p.get("sessionId")))
keys("load_aar", loaders.load_aar(os.path.join(fx, "lib-http-1.4.0.aar")))
keys("load_dex", loaders.load_dex(os.path.join(fx, "bare.dex")))
keys("  counts", loaders.load_dex(os.path.join(fx, "bare.dex")).get("counts", {}))
vd = loaders.load_dex(os.path.join(fx, "payload.vdex"))
keys("load_vdex", vd)
print("   vdex ok=%s code=%s container=%s" % (vd.get("ok"), vd.get("code"), json.dumps(vd.get("container"), ensure_ascii=False)[:150]))
print("   cdx:", json.dumps({k: v for k, v in loaders.load_dex(os.path.join(fx, "cdx.vdex")).items()
                             if k in ("ok", "code", "message", "suggestion")}, ensure_ascii=False)[:300])
sl = loaders.session_list()
keys("session_list item", sl["items"][0] if sl["items"] else {})
g1 = server.call_tool("getSignature", {"sessionId": sid, "class": "com.example.demo.Strings"})
print("getSignature no member: total=%s item0=%s" % (g1["total"], json.dumps(g1["items"][0], ensure_ascii=False)[:200]))
g2 = server.call_tool("getSignature", {"sessionId": sid, "class": "com.example.demo.User", "member": "mName"})
print("getSignature field:", json.dumps(g2["items"][0], ensure_ascii=False)[:260])
lm = server.call_tool("listMembers", {"sessionId": sid, "class": "com.example.demo.User"})
print("listMembers User:", lm["total"], [i["name"] for i in lm["items"]])
lm2 = server.call_tool("listMembers", {"sessionId": sid, "class": "com.example.demo.Strings"})
print("listMembers Strings:", lm2["total"], [i["name"] for i in lm2["items"]])
sc = server.call_tool("searchClasses", {"sessionId": sid, "query": "com.example", "kind": "prefix", "limit": 20})
print("searchClasses prefix total:", sc["total"], names := [i["simpleName"] for i in sc["items"]])
fi = server.call_tool("findImplementations", {"sessionId": sid, "interface": "com.example.demo.Greeter"})
print("findImpl:", fi["total"], fi.get("anchor"), len(fi["items"]), "truncated=", fi["truncated"])
xr = server.call_tool("xref", {"sessionId": sid, "method": "Lcom/example/demo/User;->getName()Ljava/lang/String;", "direction": "callers", "depth": 2})
print("xref:", xr["total"], json.dumps(xr["items"][0], ensure_ascii=False)[:230])
dc = server.call_tool("decompile", {"sessionId": sid, "target": "com.example.demo.User", "format": "outline", "maxLines": 20})
print("decompile keys:", sorted(dc.keys()), "| code head:", repr(dc.get("code", "")[:70]))
ms = server.call_tool("matchSignature", {"sessionId": sid, "referredStrings": ["Hello, "]})
print("matchSig item keys:", sorted(ms["items"][0].keys()))
pr = server.call_tool("probe", {"sessionId": sid, "question": '哪里用到了 "Hello, "'})
print("probe sections:", list(pr.get("sections", {}).keys()), "items0:", json.dumps(pr["items"][0], ensure_ascii=False)[:120])
df = server.call_tool("diffSessions", {"sessionA": sid, "sessionB": sid2, "limit": 40})
print("diff summary:", json.dumps(df.get("summary"), ensure_ascii=False)[:220])
print("diff kinds:", {k: sum(1 for i in df["items"] if i.get("kind") == k) for k in ("renamed", "added", "removed", "unchanged", "changed")})
print("diff renamed pairs:", [(i["from"], i["to"], i["how"], i.get("score")) for i in df["items"] if i["kind"] == "renamed"])
