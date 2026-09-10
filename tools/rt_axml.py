import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from apkindex import axml
A = axml.ANDROID_NS
def at(n, v): return (None, A, n, v)
root = axml.Element("manifest", None, [at("package", "com.example.demo"),
                                       at("versionCode", 7), at("versionName", "1.2.3")])
uses = axml.Element("uses-sdk", None, [at("minSdkVersion", 26), at("targetSdkVersion", 36)])
act = axml.Element("activity", None, [at("name", "com.example.demo.MainActivity"),
                                      at("exported", True)])
app = axml.Element("application", None, [at("name", "com.example.demo.App")])
app.children = [act]
root.children = [uses, app]
b = axml.Writer(root).build()
r = axml.parse(b)
m = axml.manifest_of(b)
print("bytes", len(b), "root", r.tag, "kids", [c.tag for c in r.children],
      "appkids", [c.tag for c in r.children[-1].children])
keys = ("package", "versionCode", "versionName", "minSdk", "targetSdk",
        "application", "activities", "usesPermissions")
for k in keys:
    print(" ", k, "=", m.get(k))
ok = (m["package"] == "com.example.demo" and m["versionCode"] == 7
      and m["versionName"] == "1.2.3" and m["minSdk"] == 26 and m["targetSdk"] == 36
      and m["application"] == "com.example.demo.App"
      and len(m["activities"]) == 1 and m["activities"][0]["name"] == "com.example.demo.MainActivity")
print("ROUNDTRIP", "OK" if ok else "FAIL")
sys.exit(0 if ok else 1)
