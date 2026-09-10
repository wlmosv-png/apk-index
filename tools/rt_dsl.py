import sys, os, textwrap
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from apkindex import dsl
b = dsl.match_dsl("com.example.net.TokenManager", "verify",
                  ["Ljava/lang/String;", "I"], "Z", access=0x0001 | 0x0002,
                  super_binary="java.lang.Object",
                  referred_strings=["AUTH_SECRET_KEY", "api/v1/登录"])
print(b)
print("problems(match):", dsl.check_kotlin(b))
f = dsl.field_dsl("com.example.User", "mToken", "Ljava/lang/String;", static=True, final=False)
print(f)
print("problems(field):", dsl.check_kotlin(f))
print("reflector:", repr(dsl.method_reflector("com.example.User", "getName", "()".replace("()", ""), "Ljava/lang/String;")))
print("kstr:", dsl.kotlin_string("价格$10 \"quoted\" \\back"))
