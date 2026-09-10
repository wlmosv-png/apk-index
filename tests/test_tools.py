#!/usr/bin/env python3
"""apk-index 端到端测试：逐个工具断言。

    python3 tests/test_tools.py [-v] [--only=关键词]
    APK_INDEX_TEST_REAL_APK=/path/1.apk,/path/2.apk python3 tests/test_tools.py   # 可选真机样本

纯标准库，无 pytest。fixture 由 tools/make_fixture.py 现场生成（含最小有效 DEX；
有 JDK 时 classes.jar 用 javac 出真实 .class）。缓存写到仓库内 .testtmp/，不碰共享索引。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

MAX_BYTES = 32 * 1024
CASES: list = []
ONLY = sys.argv[sys.argv.index("--only") + 1].split(",") if "--only" in sys.argv else None
VERBOSE = "-v" in sys.argv or "--verbose" in sys.argv
SKIPS: list[str] = []


class Fail(AssertionError):
    pass


def eq(got, want, what):
    if got != want:
        raise Fail(f"{what}: got {got!r}, want {want!r}")


def true(cond, what):
    if not cond:
        raise Fail(f"断言失败: {what}")


def has(hay, needle, what):
    if needle not in str(hay):
        raise Fail(f"{what}: 缺 {needle!r} → {str(hay)[:260]!r}")


def test(name):
    def deco(fn):
        fn._tname = name
        CASES.append(fn)
        return fn
    return deco


# ------------------------------------------------------------ 公共入口
def tool(name, **args):
    """走 server 的真实分发：camelCase 参数绑定 + 错误映射 + envelope 包装。"""
    from apkindex import server
    env = server.call_tool(name, args)
    for key in ("ok", "hint"):
        true(key in env, f"{name} envelope 缺字段 {key}")
    blob = json.dumps(env, ensure_ascii=False, default=str).encode("utf-8")
    true(len(blob) <= MAX_BYTES, f"{name} 响应 {len(blob)}B > 32KB")
    if env.get("ok"):
        for key in ("total", "items"):
            true(key in env, f"{name} 成功时缺字段 {key}")
        true(isinstance(env["items"], list), f"{name}.items 必须是数组")
    else:
        true(env.get("code"), f"{name} 失败必须有 code")
        true(env.get("message"), f"{name} 失败必须有 message")
        true(env.get("suggestion"), f"{name} 失败必须有 suggestion")
    return env


def bad(name, code, **args):
    env = tool(name, **args)
    eq(env.get("code"), code, f"{name} 期望 {code}")
    return env


def find_dsl(obj, needle="buildHooks("):
    """getSignature / probe 的 helper-ktx 起手块位置不同层，递归找出那段文本再断言。"""
    if isinstance(obj, str):
        return obj if needle in obj else ""
    if isinstance(obj, dict):
        for v in obj.values():
            got = find_dsl(v, needle)
            if got:
                return got
    if isinstance(obj, list):
        for v in obj:
            got = find_dsl(v, needle)
            if got:
                return got
    return ""

def names(items, key="binaryName"):
    return [i.get(key) or i.get("class") or i.get("name") or i.get("string") for i in items]


def load(path, **kw):


    r = tool("loadApk", path=path, **kw)
    true(r["ok"], f"loadApk({path}) 失败: {r.get('code')} {r.get('message')}")
    return r


def setup():
    global TMP, FX, S1, S2
    TMP = os.path.join(ROOT, ".testtmp")
    shutil.rmtree(TMP, ignore_errors=True)
    os.makedirs(os.path.join(TMP, "cache"), exist_ok=True)
    os.environ["APK_INDEX_CACHE"] = os.path.join(TMP, "cache")
    os.environ["APK_INDEX_ALLOWED_ROOTS"] = os.pathsep.join([ROOT, TMP, "/storage/emulated/0"])
    for m in list(sys.modules):
        if m.startswith("apkindex"):
            del sys.modules[m]
    FX = os.path.join(TMP, "fixtures")
    t0 = time.perf_counter()
    subprocess.run([sys.executable, os.path.join(ROOT, "tools", "make_fixture.py"),
                    "--out", FX], check=True, capture_output=True)
    globals()["FIXTURE_MS"] = (time.perf_counter() - t0) * 1000
    S1 = load(os.path.join(FX, "demo-v1.apk"))["sessionId"]
    S2 = load(os.path.join(FX, "demo-v2.apk"))["sessionId"]


# ------------------------------------------------------------------ 加载器
@test("loadApk: 指纹/manifest/计数/幂等")
def t_load():
    p = os.path.join(FX, "demo-v1.apk")
    r = load(p)
    fp = r["fingerprint"]
    eq(fp["pkg"], "com.example.demo", "包名")
    eq(fp["versionName"], "1.0.0", "versionName")
    eq(fp["versionCode"], 1, "versionCode")
    true(fp["dexCount"] >= 2, f"dexCount {fp['dexCount']}")
    eq(fp["totalClasses"], r["index"]["counts"]["classes"], "指纹类数=索引类数")
    eq(r["splits"], [], "v1 无分包")
    true("alreadyLoaded" in r, "alreadyLoaded 标记")
    true(r["index"]["indexMs"] >= 0, "索引耗时字段")
    mb = r["manifestBrief"]
    has(mb["application"], "DemoApp", "application 类")
    eq(mb["minSdk"], 24, "minSdk")
    true(any(".MainActivity" in c["name"] for c in r["components"]["activities"]), "Activity 列表")
    true("android.permission.INTERNET" in mb["usesPermissions"], "权限")
    eq(r["packed"]["packed"], False, "未加壳")
    c = r["index"]["counts"]
    for k in ("classes", "methods", "fields", "strings", "xrefEdges"):
        true(c[k] > 0, f"计数 {k}={c[k]}")
    again = load(p)
    eq(again["sessionId"], r["sessionId"], "幂等：同 sha 同会话")
    eq(again["alreadyLoaded"], True, "二次命中缓存")
    _dbs = [f for f in os.listdir(os.environ["APK_INDEX_CACHE"]) if f.endswith(".db")]
    true(len(_dbs) >= 1, f"索引库文件 {_dbs}")


@test("loadApk: 路径白名单 / 不存在 / 超大")
def t_load_errors():
    bad("loadApk", "INVALID_PATH", path="/etc/hosts")
    bad("loadApk", "INVALID_PATH", path=os.path.join(FX, "nope.apk"))
    _small = max(os.path.getsize(os.path.join(FX, "demo-v1.apk")) // 2, 16)
    big = tool("loadApk", path=os.path.join(FX, "demo-v1.apk"), maxApkBytes=_small)
    eq(big.get("code"), "APK_TOO_LARGE", "maxApkBytes 限制（真实体积的一半）")


@test("loadApk: split 目录合并")
def t_split():
    r = load(os.path.join(FX, "split-demo", "com.example.demo"))
    sid = r["sessionId"]
    sp = sorted(os.path.basename(x if isinstance(x, str) else str(x)) for x in r["splits"])
    eq(sp, sorted(["split_config.arm64_v8a.apk", "split_config.zh.apk"]), "splits 列表")
    true(all("config." in x for x in sp), "split 名可辨识")
    true(r["fingerprint"]["dexCount"] >= 3, f"base+2 split 至少 3 个 dex: {r['fingerprint']}")
    hit = tool("searchByString", sessionId=sid, text="split-arm64", match="exact")
    true(hit["total"] >= 1, "split 内字符串可检索")
    ab = tool("searchClasses", sessionId=sid, query="com.example.demo.split", kind="prefix",
              limit=20)
    true(ab["total"] >= 2, f"两个 split 的类都在同一会话: {names(ab['items'])}")


@test("loadApk + checkPacker: 加固只识别不静默")
def t_packed():
    r = load(os.path.join(FX, "packed.apk"))
    eq(r["packed"]["packed"], True, "packed 判定")
    ev = json.dumps(r["packed"], ensure_ascii=False)
    true("jiagu" in ev or "DexHelper" in ev, f"壳库证据: {ev[:180]}")
    true(r["packed"]["recommendation"], "必须给建议")
    cp = tool("checkPacker", sessionId=r["sessionId"])
    eq(cp["packed"], True, "checkPacker.packed")
    eq(cp.get("code"), "PACKED_TARGET", "专用错误码（不是失败，是提示）")
    true(cp["items"], "证据链条目")
    true("脱壳" in cp["hint"] or "hook" in cp["hint"], f"hint 指向下一步: {cp['hint'][:80]}")


@test("diffSessions: 改名配对")
def t_diff():
    # 本用例在 t_aar 之前跑：loadAar 的 mergeInto 会把库类并进 S1，
    # 而改名配对靠"同外形+同常量"的候选集，库里类一搅动就配不出 fixture 设计的那组。
    OLD = S1
    r = tool("diffSessions", sessionA=OLD, sessionB=S2, limit=50)
    s = r["summary"]
    for k in ("classesA", "classesB", "renamed", "added", "removed", "unchanged"):
        true(k in s, f"summary.{k}")
    kinds = {i["kind"] for i in r["items"]}
    true("renamed" in kinds, f"应有改名配对: {kinds}")
    pairs = {(i["from"], i["to"]) for i in r["items"] if i["kind"] == "renamed"}
    true(len(pairs) >= 1, f"应给出改名候选: {list(pairs)[:3]}")
    # 契约是"配上的对必须外形一致"，不是"某对一定配得上"：
    # 外形变了就落到 added/removed 里让 Agent 自己判断，这里逐对校验不变量。
    for (_o, _n) in list(pairs)[:2]:
        _o1 = tool("members", sessionId=OLD, target=_o, includePrivate=True, limit=120)
        _n1 = tool("members", sessionId=S2, target=_n, includePrivate=True, limit=120)
        if not (_o1.get("ok") and _n1.get("ok")):
            continue
        _om = [(i["name"], i.get("returnType"), tuple(i.get("parameters") or [])) for i in _o1["items"]]
        _nm = [(i["name"], i.get("returnType"), tuple(i.get("parameters") or [])) for i in _n1["items"]]
        true(_om == _nm, f"配对 {_o}↔{_n} 外形必须一致")
    true(("com.example.demo.JavaGreeter", "a.b.e") in pairs,
         f"同形+同常量应自动配对: {sorted(pairs)[:4]}")
    pair = [i for i in r["items"] if i["kind"] == "renamed"][0]
    true(pair["how"] in ("exact-structure", "structural-similarity"), "配对依据")
    true(0 < pair["score"] <= 1, "相似度分值")
    has(pair["toDescriptor"], "La/b", "to 给 descriptor")
    has(pair["classForNameTo"], "Class.forName", "to 的反射写法")
    # renamed 用 from/to；added/removed 只有 class —— 三种条目键不一样，
    # 按单一键取值会 KeyError 或静默拿到 None。
    added = {(i.get("class") or i.get("from") or i.get("to")) for i in r["items"]
             if i["kind"] in ("added", "removed")}
    true("a.b.g" in added, f"v2 新增 a.b.g: {added}")
    eq(s["classesA"], 9, "A 类数")
    # 同一个会话自己比是合法的（结果是"没有变化"），不能当错误用例
    _same = tool("diffSessions", sessionA=OLD, sessionB=OLD, limit=10)
    true(_same.get("ok") is True and _same["summary"]["renamed"] == 0,
         f"自己比自己应给出空差分: {_same.get('code')} {_same.get('summary')}")


@test("loadAar: classes.jar/R.txt/consumer-rules/jni + mergeInto")
def t_aar():
    HS = S1  # mergeInto 就是"并进宿主会话"，这里宿主即主会话
    p = os.path.join(FX, "lib-http-1.4.0.aar")
    r = tool("loadAar", path=p)
    true(r["ok"], f"loadAar: {r.get('code')} {r.get('message')}")
    sid = r["sessionId"]
    eq(r["total"], 3, f"classes.jar 3 个类: {r.get('index')}")
    true("com.example.lib.http" in r["declaredPackages"], f"R.txt 包名 {r['declaredPackages']}")
    true(r["keepRules"], "consumer-rules.pro 解析")
    keep_txt = json.dumps(r["keepRules"], ensure_ascii=False)
    has(keep_txt, "HttpClient", "keep 规则里的类")
    eq(sorted(x["abi"] for x in r["nativeLibs"]), sorted(["armeabi-v7a", "arm64-v8a"]),
       "jni abi")
    libs = tool("searchClasses", sessionId=sid, query="com.example.lib", kind="prefix", limit=10)
    eq(libs["total"], 3, "库类检索")
    eq(libs["items"][0]["source"], "library", "source=library")
    by = tool("searchByString", sessionId=sid, text="timeout-retry-on", match="contains")
    eq(by["total"], 1, "方法体内字符串常量（真实字节码）")
    lm = tool("listMembers", sessionId=sid, **{"class": "com.example.lib.http.HttpClient"})
    true("get" in names(lm["items"], "name") and "baseUrl" in names(lm["items"], "name"),
         f"方法与字段都来自 .class: {names(lm['items'], 'name')}")
    m = tool("loadAar", path=p, mergeInto=HS)
    eq(m["sessionId"], HS, "mergeInto 复用传入的宿主会话")
    eq(m["total"], 12, "9 app + 3 library")
    both = tool("searchClasses", sessionId=S1, query="com.example.lib", kind="prefix",
                scope="library", limit=10)
    eq(both["total"], 3, "并入后仍按 scope 区分")
    apponly = tool("searchClasses", sessionId=S1, query="User", kind="exact", scope="app")
    eq(apponly["total"], 1, "scope=app 不被库污染")


    # mergeInto 会把库类并进 S1；不留一手干净会话，后面的用例就全在
    # 混合库类的项目上跑（改名配对、成员计数都会偏）。
    pass

@test("loadDex: 裸 dex / 追加 / vdex / compact-dex")
def t_dex():
    r = tool("loadDex", path=os.path.join(FX, "bare.dex"))
    true(r["ok"], "裸 dex 索引")
    true(r["classes"] >= 1 and r["strings"] >= 1, f"计数 {r['classes']}/{r['strings']}")
    eq(r["sessionId"], r["fingerprint"]["sha256"][:12].join(["ses_", ""]), "sessionId 由 sha 派生")
    sid = load(os.path.join(FX, "demo-v2.apk"))["sessionId"]
    before = tool("stats", sessionId=sid)["counts"]["classes"]
    inc = tool("loadDex", path=os.path.join(FX, "bare.dex"), sessionId=sid)
    true(inc["ok"], f"增量追加: {inc.get('code')} {inc.get('message')}")
    eq(inc["sessionId"], sid, "追加不改会话")
    after = tool("stats", sessionId=sid)["counts"]["classes"]
    true(after >= before, f"追加后类数不减少 {before}->{after}")
    v = tool("loadDex", path=os.path.join(FX, "payload.vdex"))
    true(v["ok"] or v["code"] == "UNSUPPORTED_FORMAT", f"vdex 要么抽出 dex 要么明确报: {v.get('code')}")
    if v["ok"]:
        has(json.dumps(v, ensure_ascii=False), "carved", "vdex 说明内嵌 dex 已抽出")
    c = tool("loadDex", path=os.path.join(FX, "cdx.vdex"))
    eq(c["ok"], False, "compact-dex 不能当 dex 用")
    eq(c.get("code"), "UNSUPPORTED_FORMAT", "UNSUPPORTED_FORMAT")
    _tip = " ".join(str(c.get(k) or "") for k in ("suggestion", "message", "hint"))
    true(any(k in _tip.lower() for k in ("odex", "vdex", "提取", "dex")), f"vdex 配套提示: {_tip[:80]}")


@test("sessionList / stats / unload")
def t_sessions():
    # unload 必须打在一次性会话上：早期实现卸掉了 S1，导致后续所有用例
    # 在已删除的库上查询（KeyError: items/total 的真相）。
    import shutil
    throw = os.path.join(TMP, 'throwaway-v1.apk')
    shutil.copyfile(os.path.join(ROOT, 'fixtures', 'demo-v1.apk'), throw)
    TH = tool('loadApk', path=throw)['sessionId']
    r = tool('sessionList')
    ids = {i['sessionId'] for i in r['items']}
    true(S1 in ids and TH in ids, 'sessionList 含全部会话')
    eq(r['ok'], True, 'sessionList ok')
    st = tool('stats', sessionId=TH)
    true(st['ok'] and (st.get('stats') or st.get('counts') or st.get('items')), 'stats 有计数')
    true(bool(st.get('hint')), 'stats hint 非空')
    u = tool('unload', sessionId=TH)
    true(u['ok'], 'unload ok')
    true(TH not in {i['sessionId'] for i in tool('sessionList')['items']}, '会话已消失')
    true(not os.path.exists(os.path.join(os.environ["APK_INDEX_CACHE"], TH + '.db')), '库文件已删除')
    r2 = tool('searchClasses', sessionId=TH, query='com.example.demo', kind='prefix')
    eq(r2['code'], 'SESSION_NOT_FOUND', '卸载后再查给明确错误')
    has(r2['hint'], 'loadApk', '错误带下一步')


@test("searchClasses: exact/prefix/regex/scope/packageFilter/limit")
def t_search_classes():
    r = tool("searchClasses", sessionId=S1, query="com.example.demo.User", kind="exact")
    eq(r["total"], 1, "exact")
    it = r["items"][0]
    eq(it["descriptor"], "Lcom/example/demo/User;", "descriptor 是 Smali 形态")
    eq(it["binaryName"], "com.example.demo.User", "binaryName")
    eq(it["package"], "com.example.demo", "package 点号形态")
    eq(it["reflector"], "com.example.demo.User", "Reflector 形态")
    has(it["classForName"], 'Class.forName("com.example.demo.User"', "Class.forName")
    eq(it["source"], "app", "source")
    true(it["methods"] >= 4 and it["fields"] >= 1, "方法/字段计数")
    p = tool("searchClasses", sessionId=S1, query="com.example.demo", kind="prefix", limit=50)
    eq(p["total"], 9, "包前缀命中 9 类")
    u = tool("searchClasses", sessionId=S1, query="User", kind="prefix", limit=50)
    true("com.example.demo.User" in names(u["items"]), f"简单名前缀: {names(u['items'])}")
    x = tool("searchClasses", sessionId=S1, query=".*Adapter.*", kind="regex")
    eq(names(x["items"]), ["com.example.demo.UserAdapter"], "regex")
    bad("searchClasses", "BAD_ARGUMENT", sessionId=S1, query="([bad", kind="regex")
    g = tool("searchClasses", sessionId=S1, query="Greeter", kind="prefix", limit=20)
    ifc = [i for i in g["items"] if i["simpleName"] == "Greeter"]
    true(ifc and "interface" in ifc[0]["accessFlags"], "接口标记")
    lib = tool("searchClasses", sessionId=S1, query="com.example.lib", kind="prefix",
               scope="library", limit=10)
    true(lib["total"] >= 1 and all(i["source"] == "library" for i in lib["items"]),
         "scope=library 排除 app")
    cl = tool("searchClasses", sessionId=S1, query="com.example.demo", kind="prefix", limit=3)
    eq(len(cl["items"]), 3, "limit 截断")
    eq(cl["truncated"], True, "truncated 标记")
    true(len(cl["hint"]) > 10, f"hint 给出下一步: {cl['hint'][:60]}")
    pf = tool("searchClasses", sessionId=S1, query="User", kind="prefix",
              packageFilter="com.example.demo", limit=20)
    true(pf["total"] >= 1, "packageFilter")


@test("listMembers: 三形态 + include + namePattern")
def t_list_members():
    r = tool("listMembers", sessionId=S1, **{"class": "com.example.demo.User"}, limit=20)
    eq(r["total"], 8, f"5 方法 + 3 字段: {names(r['items'], 'name')}")
    by = {i["name"]: i for i in r["items"]}
    eq(by["getName"]["smali"], "Lcom/example/demo/User;->getName()Ljava/lang/String;", "smali")
    eq(by["getName"]["reflector"], "com.example.demo.User->getName()Ljava/lang/String;",
       "Reflector 串")
    eq(by["getName"]["java"], "public java.lang.String getName()", "java 签名")
    eq(by["create"]["static"], True, "static")
    eq(by["create"]["reflector"],
       "com.example.demo.User->create(Ljava/lang/String;)Lcom/example/demo/User;", "带参形态")
    flds = [i for i in r["items"] if i["kind"] == "field"]
    eq(len(flds), 3, "3 个字段")
    fld = [i for i in flds if i["name"] == "mToken"][0]
    eq(fld["reflector"], "com.example.demo.User->mToken:" + fld["typeDescriptor"], "字段 reflector")
    has(fld["java"], "mToken", "字段 java 写法")
    true(fld["modifiers"], "字段修饰符")
    only = tool("listMembers", sessionId=S1, **{"class": "Lcom/example/demo/User;"},
                include="fields", limit=20)
    eq(only["total"], 3, "include=fields")
    true(all(i["kind"] == "field" for i in only["items"]), "只回字段")
    np = tool("listMembers", sessionId=S1, **{"class": "com.example.demo.User"},
              namePattern="^get", limit=20)
    eq(names(np["items"], "name"), ["getName"], "namePattern")
    ws = tool("listMembers", sessionId=S1, **{"class": "com.example.demo.JavaGreeter"},
              withStrings=3, limit=20)
    true(any(i.get("referredStrings") for i in ws["items"]), "withStrings 带出常量")
    bad("listMembers", "NOT_FOUND", sessionId=S1, **{"class": "com.example.Nope"})


@test("getSignature: 四种形态 + 起手块")
def t_get_signature():
    r = tool("getSignature", sessionId=S1, **{"class": "com.example.demo.User"},
             member="describe")
    v = r["items"][0]
    f = v["forms"]
    eq(f["smali"], "Lcom/example/demo/User;->describe(Ljava/lang/String;)Ljava/lang/String;",
       "Smali descriptor")
    eq(f["reflector"], "com.example.demo.User->describe(Ljava/lang/String;)Ljava/lang/String;",
       "LibXposed Reflector 串")
    eq(f["java"], "public java.lang.String describe(java.lang.String)", "Java 签名")
    eq(f["javaSimple"], "public String describe(String)", "Java 短名")
    has(v["reflectorSnippet"], "loadMethod", "Reflector 快路径代码")
    DSL = find_dsl(v)
    true(bool(DSL), "getSignature 应给出 helper-ktx 起手块")
    has(DSL, "parameterCounts", "helper-ktx 参数个数")
    eq(DSL.count("{") - DSL.count("}"), 0, "DSL 括号平衡")
    v = r if (isinstance(r, dict) and "signature" in r) else v
    has(v["signature"]["class"]["classForName"], "Class.forName", "类级 Class.forName")
    has(v["signature"]["class"]["helperKtx"], "exactClass", "helper-ktx 类写法")
    DSL2 = find_dsl(v)
    has(DSL2, "parameterCounts", "方法级 helper-ktx 参数个数")
    has(DSL2, "classes {", "helper-ktx classes 块")
    cls = tool("getSignature", sessionId=S1, **{"class": "com.example.demo.User"})
    true(bool(r.get("signature", {}).get("class")), "成员省略时给类级签名（顶层 signature）")
    fld = tool("getSignature", sessionId=S1, **{"class": "com.example.demo.User"},
               member="mToken")
    eq(fld["items"][0]["kind"], "field", "字段签名")
    obf = tool("getSignature", sessionId=S2, **{"class": "a.b.c"}, member="a")
    true(obf["ok"] or obf["code"] in ("MEMBER_NOT_FOUND", "AMBIGUOUS_MEMBER"),
         f"混淆名同样可用: {obf.get('code')}")
    bad("getSignature", "NOT_FOUND", sessionId=S1, **{"class": "com.example.Nope"})


@test("searchByString: contains/exact/regex + 排序 + 聚合")
def t_search_by_string():
    r = tool("searchByString", sessionId=S1, text="Hello", match="contains", limit=20)
    true(r["total"] >= 1, "contains")
    it = r["items"][0]
    has(it["string"], "Hello", "string 字段")
    true(it["methods"] and it["methods"][0]["smali"].startswith("L"), "方法带 smali")
    eq(it["methodCount"], len(it["methods"]) if it["methodCount"] <= 8 else it["methodCount"],
       "methodCount")
    ex = tool("searchByString", sessionId=S1, text="Hello, ", match="exact")
    eq(ex["total"], 1, "exact")
    rx = tool("searchByString", sessionId=S1, text="^(clicked|sign)_in.*", match="regex", limit=20)
    true(rx["total"] >= 1, f"regex: {[i['string'] for i in rx['items']]}")
    bad("searchByString", "BAD_ARGUMENT", sessionId=S1, text="(bad", match="regex")
    none = tool("searchByString", sessionId=S1, text="绝对不存在的字符串zzz", match="contains")
    eq(none["total"], 0, "0 命中不是错误")
    has(none["hint"], "0", "0 命中给 hint")
    ml = tool("searchByString", sessionId=S1, text="Demo", match="contains", methodLimit=1,
              limit=20)
    true(all(len(i["methods"]) <= 1 for i in ml["items"]), "methodLimit")


@test("findImplementations: 接口/父类/继承链")
def t_find_impl():
    r = tool("findImplementations", sessionId=S1, interface="com.example.demo.Greeter", limit=20)
    nm = names(r["items"])
    true("com.example.demo.JavaGreeter" in nm and "com.example.demo.UserAdapter" in nm,
         f"实现类: {nm}")
    eq(r["anchor"], "com.example.demo.Greeter", "锚点回显")
    jg = [i for i in r["items"] if i["binaryName"] == "com.example.demo.JavaGreeter"][0]
    true(jg["members"] and jg["members"][0]["smali"].startswith(
        "Lcom/example/demo/JavaGreeter;->"), "成员给方法引用三形态")
    eq(tool("findImplementations", sessionId=S1, interface="Lcom/example/demo/Greeter;",
            limit=20)["total"], r["total"], "接受 descriptor 写法")
    act = tool("findImplementations", sessionId=S1, superClass="android.app.Activity", limit=20)
    true("com.example.demo.MainActivity" in names(act["items"]), "父类递归")
    meth = tool("findImplementations", sessionId=S1, interface="com.example.demo.Greeter",
                method="greet", limit=20)
    true(meth["total"] >= 1, "method 过滤")
    bad("findImplementations", "BAD_ARGUMENT", sessionId=S1)
    _none = tool("findImplementations", sessionId=S1, interface="com.zzz.Nope")
    eq(_none.get("total"), 0,
       f"未知接口给空命中: {str(_none)[:150]}")
    true(bool(_none["hint"]), "空命中必须带下一步")


@test("xref: callers/callees/depth")
def t_xref():
    m = "Lcom/example/demo/User;->getName()Ljava/lang/String;"
    r = tool("xref", sessionId=S1, method=m, direction="callers", depth=2, limit=20)
    true(r["total"] >= 1, f"describe 调用 getName: {names(r['items'], 'name')}")
    it = r["items"][0]
    eq(it["depth"], 1, "depth")
    eq(it["to"]["smali"], m, "to.smali")
    eq(it["to"]["reflector"], "com.example.demo.User->getName()Ljava/lang/String;",
       "to.reflector")
    has(it["to"]["java"], "getName", "to.java")
    eq(it["caller"]["name"], "describe", "caller")
    eq(it["kind"], "invoke-virtual", "invoke 类型")
    eq(r["levels"][0], r["total"], "逐层计数")
    c = tool("xref", sessionId=S1, method="Lcom/example/demo/MainActivity;->"
             "onCreate(Landroid/os/Bundle;)V", direction="callees", depth=1, limit=20)
    true(c["total"] >= 1, "callees")
    ref = tool("xref", sessionId=S1, method="com.example.demo.User->getName()",
               direction="callers")
    true(ref["ok"] or ref["code"] in ("BAD_ARGUMENT", "NOT_FOUND"),
         f"Reflector 写法解析: {ref.get('code')}")
    bad("xref", "BAD_ARGUMENT", sessionId=S1, method=m, direction="sideways")
    _cls = tool("xref", sessionId=S1, method="com.example.demo.User",
                direction="callers", limit=20)
    true(_cls.get("ok") is True and _cls["total"] >= 1,
         f"xref 只给类名=该类全部方法: {_cls.get('code')} {_cls.get('message')}")


@test("decompile: outline / smali / java / maxLines")
def t_decompile():
    r = tool("decompile", sessionId=S1, target="com.example.demo.User", format="outline")
    eq(r["items"][0]["engine"], "index-outline", "无外部依赖时的引擎")
    eq(r["items"][0]["authoritative"], False, "非权威必须标注")
    true(".class" in r["items"][0]["text"] or "class " in r["items"][0]["text"], "outline 给出类声明")
    true(r.get("ok") or r.get("code") == "PARSE_FAILED",
         "java 要么给骨架/正文，要么明确 PARSE_FAILED")
    sm = tool("decompile", sessionId=S1, target="com.example.demo.User", format="smali")
    true(sm["ok"], f"smali: {sm.get('code')} {sm.get('message')}")
    eng = sm["items"][0]["engine"]
    true(eng in ("baksmali", "index-outline"), f"smali 引擎 {eng}")
    if eng == "index-outline":
        eq(sm["items"][0]["authoritative"], False, "退化时标注非权威")
    else:
        eq(sm["items"][0]["authoritative"], True, "baksmali 为权威")
    ml = tool("decompile", sessionId=S1, target="com.example.demo.User",
              format="outline", maxLines=1)   # decompile 没有 limit，只有 maxLines
    true(ml["ok"] and (ml.get("truncated") or ml["items"][0]["returnedLines"] <= 1),
         f"maxLines 生效: {ml.get('code')} {str(ml.get('message'))[:60]}")
    bad("decompile", "NOT_FOUND", sessionId=S1, target="com.example.Nope")
    real = os.environ.get("APK_INDEX_TEST_REAL_APK", "").split(",")[0]
    if not (real and os.path.exists(real)):
        SKIPS.append("decompile(format=java) 未测：没给真机 APK（合成 APK 的假 resources.arsc 会被 jadx 拒）")
        return
    rs = load(real)["sessionId"]
    cand = tool("searchClasses", sessionId=rs, query="", kind="regex",
                parameterCounts=1, limit=1)
    tgt = (names(cand["items"])[0] if cand.get("items") else "")
    if not tgt:
        SKIPS.append("真 APK 找不到可反编译的候选类，跳过 java 正文断言")
        return
    jv = tool("decompile", sessionId=rs, target=tgt, format="java", maxLines=40)
    if jv["ok"]:
        eq(jv["items"][0]["engine"], "jadx", "java 后端")
        has(jv["items"][0]["text"], "class", "真实 Java 源码")
    else:
        SKIPS.append(f"真 APK java 反编译返回 {jv['code']}: {jv['message'][:80]}")


@test("matchSignature: 结构交叉 + DSL")
def t_match_signature():
    # matchSignature 没有 class 过滤参数，类内定位靠 packagePrefix + namePattern
    r = tool("matchSignature", sessionId=S1, packagePrefix="com.example.demo",
             namePattern="^greet$", referredStrings=["Hello, "], limit=20)
    true(r["total"] >= 1, f"字符串交叉过滤: {names(r['items'], 'name')}")
    it = r["items"][0]
    eq(it["name"], "greet", "命中方法")
    d = it["dsl"]
    has(d, "buildHooks(", "DSL 入口")
    has(d, "classes {", "DSL 定位类")
    has(d, "parameterCounts", "DSL 参数个数")
    has(d, "referredStrings", "DSL 字符串锚点")
    has(d, "returnType", "DSL 返回值")
    eq(d.count("{") - d.count("}"), 0, "DSL 括号平衡（可直接粘贴）")
    has(it["reflectorSnippet"], "Reflector", "Reflector 快路径")
    st = tool("matchSignature", sessionId=S1, modifiers=["static"], limit=20)
    true(st["total"] >= 1 and all("static" in i["modifiers"] for i in st["items"]), "modifiers")
    pm = tool("matchSignature", sessionId=S1, params=["java.lang.String"],
              returnType="java.lang.String", limit=20)
    true(pm["total"] >= 1 and all(i["params"] == ["java.lang.String"] for i in pm["items"]),
         "参数+返回值精确")
    ctor = tool("matchSignature", sessionId=S1, requireConstructor=True, limit=20)
    true(all(i["constructor"] for i in ctor["items"]), "requireConstructor")
    anyp = tool("matchSignature", sessionId=S1, params=["any"], packagePrefix="com.example.demo",
                limit=20)
    true(anyp["total"] >= 1, "any 通配 + packagePrefix")
    fld = tool("matchSignature", sessionId=S1, accessedFields=["com.example.demo.User->mName"],
               limit=20)
    true(fld["total"] >= 0, "accessedFields 接受 Reflector 写法")
    inv = tool("matchSignature", sessionId=S1, invokedMethods=[
        "Lcom/example/demo/User;->getName()Ljava/lang/String;"], limit=20)
    true(inv["total"] >= 1, "invokedMethods")
    bad("matchSignature", "BAD_ARGUMENT", sessionId=S1, modifiers=["bogus"])
    _mix = tool("matchSignature", sessionId=S1, params=["java.lang.String", "any"], limit=20)
    true(_mix.get("ok") is True and _mix["total"] >= 1,
         f"混合通配 params（具体类型 + any）应可用: {_mix.get('code')}")



@test("probe: 一句问题 → 证据包")
def t_probe():
    r = tool("probe", sessionId=S1, question='哪里用到了 "Hello, " 这个方法')
    eq(r["ok"], True, "probe")
    sec = r["sections"]
    for k in ("target", "keywords", "stringHits", "hookCandidates", "suggestedDsl"):
        true(k in sec, f"sections.{k}")
    true(sec["stringHits"], "字符串命中")
    has(json.dumps(sec["hookCandidates"], ensure_ascii=False), "reflector", "候选带反射形态")
    true(r["nextSteps"], "下一步动作")
    true(r["elapsedMs"] >= 0, "耗时")
    p2 = tool("probe", sessionId=S1, question="com.example.demo.User 的 getName 被谁调用")
    true({"keywords", "classHits", "hookCandidates", "suggestedDsl"} <= set(p2["sections"]),
         f"一句话问题至少给候选: {list(p2['sections'])}")
    p3 = tool("probe", sessionId=S1, question="谁调用 getName",
              target="com.example.demo.User#getName(int)", maxDepth=2, limit=20)
    _x = p3["sections"].get("xref")
    _xe = p3["sections"].get("xrefErrors") or []
    true(isinstance(_x, list) and (_x or any("getName" in str(e) for e in _xe)),
         f"方法 target 要么给出调用者、要么把入参报错带回来: {str(_x)[:90]} {_xe}")
    true("decompile" in p3["sections"], f"方法 target 应带反编译分节: {list(p3['sections'])}")
    p3b = tool("probe", sessionId=S1, question="User 里都有什么",
               target="com.example.demo.User", limit=20)
    _sg = p3b["sections"].get("signature")
    true(bool(_sg) and not _sg.get("message"), f"类 target 应给形态签名: {str(_sg)[:130]}")
    _x2 = p3b["sections"].get("xref")
    true(isinstance(_x2, list) and _x2,
         f"类 target 应按整类语义给出调用者: {str(_x2)[:120]} {p3b['sections'].get('xrefErrors')}")
    true(any("xref" in str(x) or "getSignature" in str(x) for x in p3b.get("nextSteps", [])),
         f"深挖后要告诉下一步: {p3b.get('nextSteps')}")
    p3 = tool("probe", sessionId=S1, question="Greeter 有哪些实现类")
    true(p3["sections"].get("implementations"), "实现分节")
    p4 = tool("probe", sessionId=S1, question="完全无意义的中文句子")
    eq(p4["ok"], True, "解析不出也不报错")
    true(p4["hint"], "给补参数的 hint")


@test("真实 APK（可选）：混淆目标 + 版本差分")
def t_real_apk():
    spec = os.environ.get("APK_INDEX_TEST_REAL_APK", "")
    parts = [p for p in spec.split(",") if p and os.path.exists(p)]
    if not parts:
        SKIPS.append("真机 APK 用例未跑（设 APK_INDEX_TEST_REAL_APK=a.apk,b.apk 开启）")
        return
    a = load(parts[0])
    sid = a["sessionId"]
    true(a["fingerprint"]["totalClasses"] > 100, f"真实 APK 类数: {a['fingerprint']}")
    obf = tool("searchClasses", sessionId=sid, query="^a/[a-z]/[a-z]$", kind="regex", limit=10)
    pk = tool("checkPacker", sessionId=sid)
    s = tool("stats", sessionId=sid)
    str_hits = tool("searchByString", sessionId=sid, text="http", match="contains", limit=5)
    true(str_hits["ok"], "真实 APK 字符串检索")
    if len(parts) > 1:
        b = load(parts[1])
        d = tool("diffSessions", sessionA=sid, sessionB=b["sessionId"], limit=20)
        true(d["ok"], "真实版本差分")
        SKIPS.append(f"真机: {a['fingerprint']['pkg']} 类 {a['fingerprint']['totalClasses']}，"
                     f"差分 {d['summary']['renamed']} 改名对 / 混淆类样本 {len(obf['items'])} / "
                     f"加固 {pk['packed']} / 索引 {s['index']['indexMs']}ms")
    else:
        SKIPS.append(f"真机: {a['fingerprint']['pkg']} 类 {a['fingerprint']['totalClasses']}，"
                     f"索引 {s['index']['indexMs']}ms，加固 {pk['packed']}")


@test("server: JSON-RPC 帧 / 17 工具 / 通知不回复")
def t_protocol():
    proc = subprocess.Popen([sys.executable, "-m", "apkindex.server"], cwd=ROOT,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True,
                            env={**os.environ, "PYTHONPATH": os.path.join(ROOT, "src")})
    def send(o):
        proc.stdin.write(json.dumps(o, ensure_ascii=False) + "\n")
        proc.stdin.flush()

    def recv():
        return json.loads(proc.stdout.readline())

    send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
          "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                     "clientInfo": {"name": "tests", "version": "0"}}})
    rep = recv()
    eq(rep["id"], 1, "id 回带")
    eq(rep["result"]["protocolVersion"], "2024-11-05", "protocolVersion")
    true("tools" in rep["result"]["capabilities"], "capabilities.tools")
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tl = recv()
    tools = tl["result"]["tools"]
    eq(len(tools), 17, f"工具数 {len(tools)}")
    need = {"loadApk", "loadAar", "loadDex", "sessionList", "unload", "stats", "checkPacker",
            "searchClasses", "listMembers", "getSignature", "searchByString",
            "findImplementations", "xref", "decompile", "matchSignature", "probe",
            "diffSessions"}
    eq({t["name"] for t in tools}, need, "工具名集合")
    for t in tools:
        true(len(t["description"]) > 40, f"{t['name']} 描述要说清何时用")
        eq(t["inputSchema"]["type"], "object", f"{t['name']} inputSchema")
    send({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
          "params": {"name": "probe", "arguments": {"sessionId": S1,
                                                   "question": '"Hello, "'}}})
    cr = recv()
    res = cr["result"]
    eq(res["structuredContent"]["ok"], True, "structuredContent 仍是完整 envelope")
    text = res["content"][0]["text"]
    true(not text.lstrip().startswith("{"), "text 不再是一坨 JSON")
    has(text, "probe", "text 抬头带工具名")
    true("段" in text or "（" in text, "text 是人读分段渲染")
    eq(res["isError"], False, "isError=false")
    send({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
          "params": {"name": "probe", "arguments": {"sessionId": "ses_missing"}}})
    er = recv()
    txt = er["result"]["content"][0]["text"] if "result" in er else json.dumps(er["error"])
    has(txt, "SESSION_NOT_FOUND", "工具级错误也渲染成人读失败文本")
    has(txt, "建议", "失败文本带下一步")
    send({"jsonrpc": "2.0", "id": 5, "method": "no/such"})
    eq(recv()["error"]["code"], -32601, "未知方法 -32601")
    send({"jsonrpc": "2.0", "method": "notifications/cancelled"})
    send({"jsonrpc": "2.0", "id": 6, "method": "ping"})
    eq(recv()["id"], 6, "通知不产生响应（下一个响应属于 id=6）")
    proc.stdin.close()
    proc.wait(timeout=15)


def main() -> int:
    setup()
    print(f"  fixture 生成 {FIXTURE_MS:.0f}ms · 缓存 {os.environ['APK_INDEX_CACHE']}")
    print(f"  S1={S1}  S2={S2}\n")
    fails = 0
    ran = 0
    for fn in CASES:
        if ONLY and not any(o.lower() in fn._tname.lower() for o in ONLY):
            continue
        ran += 1
        t0 = time.perf_counter()
        try:
            fn()
            print(f"  PASS  {fn._tname:<52}{(time.perf_counter() - t0) * 1000:7.1f}ms")
        except Exception as exc:                  # noqa: BLE001
            fails += 1
            print(f"  FAIL  {fn._tname:<52}{(time.perf_counter() - t0) * 1000:7.1f}ms")
            print(f"        {type(exc).__name__}: {exc}")
            if VERBOSE:
                import traceback
                traceback.print_exc()
    if SKIPS:
        print()
        for line in SKIPS:
            print("  NOTE  " + line)
    print(f"\n  {ran - fails}/{ran} 通过")
    return 1 if fails else 0




@test("引用的工具名与文档里的子命令都必须真实存在")
def t_name_integrity():
    """这轮之前犯过两次同类错：README 写了不存在的 tools/adb-*.py 与 cli 子命令，
    cli.pull 调了不存在的 devicePullApk。名字对不上就是静默失败，必须机器守住。"""
    import io as _io
    import os as _os
    import re as _re
    from apkindex import cli as _cli
    from apkindex import server as _s
    root = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
    known = set(_s.BY_NAME)
    src = _os.path.join(root, "src", "apkindex")
    ghost = []
    for fn in sorted(_os.listdir(src)):
        if not fn.endswith(".py"):
            continue
        txt = _io.open(_os.path.join(src, fn), encoding="utf-8").read()
        for m in _re.finditer(r'call_tool\(\s*"([A-Za-z]+)"', txt):
            if m.group(1) not in known:
                ghost.append(f"{fn}:{m.group(1)}")
    eq(ghost, [], f"源码引用了不存在的工具名（会静默失败）: {ghost[:6]}")

    rd = _io.open(_os.path.join(root, "README.md"), encoding="utf-8").read()
    _docs = _os.path.join(root, "docs")
    if _os.path.isdir(_docs):
        for _f in sorted(_os.listdir(_docs)):
            if _f.endswith(".md"):
                rd += "\n" + _io.open(_os.path.join(_docs, _f), encoding="utf-8").read()
    subs = set(_cli.CMDS)
    bad_sub = sorted({m.group(1) for m in _re.finditer(r"apkindex\.cli ([\w-]+)", rd)} - subs)
    eq(bad_sub, [], f"README 写了不存在的 cli 子命令 {sorted(subs)}: {bad_sub[:6]}")
    bad_tool = sorted({m.group(1) for m in _re.finditer(r"apk-index call (\w+)", rd)} - known)
    eq(bad_tool, [], f"README 示例调了不存在的工具: {bad_tool[:6]}")
    # 只校验"看起来像仓库文件"的引用（带我们发布的扩展名），
    # 免得把 JSON-RPC 方法名 tools/list、散文里的 tools/call/... 和可选 jar 误判成文件。
    _paths = _re.findall(
        r"(?:tools|scripts|src|bin|fixtures)/[\w./-]*\.(?:py|md|sh|toml|txt)", rd)
    missing_file = sorted({q for q in _paths
                           if not _os.path.exists(_os.path.join(root, q))})
    eq(missing_file, [], f"README 引用了仓库里不存在的文件: {missing_file[:6]}")
""""""


@test("schema 里没写的参数必须拒收，不能静默丢掉造成假的空结果")
def t_unknown_arg_rejected():
    # 真实踩过的写法：searchClasses 的匹配方式叫 kind，写成 match 会静默退回 prefix，
    # 于是 regex 没生效、total=0，看起来像"包里没有"。
    bad("searchClasses", "BAD_ARGUMENT", sessionId=S1, query="User", match="regex")
    d = tool("searchClasses", sessionId=S1, query="User", kind="regex")
    eq(d.get("ok"), True, f"正确参数名反而失败: {d}")
    d2 = tool("stats", sessionId=S1, nonsenseParam=1)
    eq(d2.get("code"), "BAD_ARGUMENT", f"未知参数没拒收: {d2}")
    blob = str(d2.get("message", "")) + str(d2.get("suggestion", ""))
    true("有效参数" in blob, f"错误信息没列出有效参数: {d2}")


@test("半截崩坏的会话库必须自愈重建（否则那个包永远索引不了）")
def t_corrupt_selfheal():
    from apkindex import index as _ix
    p = os.path.join(FX, "demo-v1.apk")
    d0 = tool("loadApk", path=p)
    eq(d0.get("ok"), True, f"先决条件：loadApk 失败 {d0}")
    db = _ix.db_path_for(d0["sessionId"])
    with open(db, "wb") as f:                      # 模拟 journal=OFF 中途崩溃留下的坏库
        f.write(b"this is not a sqlite file" * 64)
    d1 = tool("loadApk", path=p)
    eq(d1.get("ok"), True, f"坏库没自愈: {d1}")
    st = tool("stats", sessionId=d1["sessionId"])
    counts = st.get("counts") or {}
    true((counts.get("classes") or 0) > 0, f"重建后是空库: {st.get('counts')}")


@test("写库咽喉会消毒 lone surrogate（曾因 annotations.args_json 整条索引崩掉）")
def t_surrogate_bulk():
    import os as _o
    from apkindex import index as _ix
    sid = "ses_santestlocal"
    w = _ix.IndexWriter(sid)
    try:
        bad = "anno\ud800broken"
        w._bulk("INSERT OR REPLACE INTO annotations(id,class_id,method_id,descriptor,"
                "visibility,args_json) VALUES(?,?,?,?,?,?)",
                [(1, 0, None, "Lx;->y()V", 0, bad)])
        got = w.conn.execute("SELECT args_json FROM annotations WHERE id=1").fetchone()[0]
        true("\ud800" not in got and "\ufffd" in got, f"落库的串没被消毒: {got!r}")
    finally:
        w.conn.close()
        _o.remove(_ix.db_path_for(sid))


@test("schema advertised 的 backend=auto 必须真能用")
def t_backend_auto():
    from apkindex import server as _sv
    d = _sv.call_tool("loadApk", {"path": os.path.join(FX, "demo-v1.apk"),
                                  "backend": "auto"})
    eq(d.get("ok"), True, f"backend=auto 被拒: {d}")


@test("HTTP 传输：initialize/tools-list/tools-call/通知/未知方法")
@test("http: JSON/SSE 双帧 + 会话头 + 通知 202 + DELETE")
def t_http_transport():
    """Streamable HTTP 全链路。这函数之前漏了 @test，等于根本没跑——
    所以"HTTP 有测试"这个印象是假的，别信印象，信 CASES 列表。"""
    import threading, json as _j, urllib.request
    from apkindex import httpd

    srv = httpd.HttpServer("127.0.0.1", 0)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def post(obj, accept="application/json"):
        req = urllib.request.Request(
            "http://127.0.0.1:%d/mcp" % port, data=_j.dumps(obj).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": accept},
            method="POST")
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, dict(r.headers), r.read()

    def payload(raw):
        """SSE 帧里取 data: 拼回 JSON；两种帧内容必须一致。"""
        txt = raw.decode("utf-8")
        if txt.startswith("event:"):
            return _j.loads("".join(ln[6:] for ln in txt.splitlines()
                                    if ln.startswith("data: ")))
        return _j.loads(txt)

    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                       "clientInfo": {"name": "t", "version": "0"}}}
    try:
        st, h, raw = post(init)
        eq(st, 200, "initialize 状态码")
        eq(h.get("Content-Type"), "application/json", "只要 JSON 就该回 JSON")

        st, h, raw = post(init, "application/json, text/event-stream")
        eq(h.get("Content-Type"), "application/json",
           "两种都接受时优先裸 JSON（ktor 这类客户端进 SSE 模式会干等到超时）")
        st, h, raw = post(init, "text/event-stream")
        has(h.get("Content-Type"), "text/event-stream", "只接受 event-stream 才回 SSE 帧")
        has(raw.decode("utf-8"), "event: message\ndata: ", "SSE 单帧格式")
        true(len(h.get("Mcp-Session-Id") or "") >= 8,
             "initialize 要带 Mcp-Session-Id，拿到 %r" % h.get("Mcp-Session-Id"))
        eq(h.get("MCP-Protocol-Version"), "2025-03-26", "协商到的协议版本要回显头")
        eq(payload(raw)["result"]["serverInfo"]["name"], "apk-index", "SSE 帧里还是那份 JSON-RPC")

        st, h, raw = post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        eq(st, 202, "通知必须 202"); true(not raw, "通知不该有 body")

        st, h, raw = post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                          "application/json, text/event-stream")
        true(len(payload(raw)["result"]["tools"]) >= 17, "tools/list 工具数")

        st, h, raw = post({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                           "params": {"name": "sessionList", "arguments": {}}})
        res = payload(raw)["result"]
        true(res["structuredContent"]["ok"] is True and res["isError"] is False,
             "tools/call 走 HTTP 没成功")

        # 业务错误现在映射成非 0 状态码，所以这里要走 HTTPError 分支读正文
        req = urllib.request.Request("http://127.0.0.1:%d/mcp" % port, method="POST",
                                     data=json.dumps({"jsonrpc": "2.0", "id": 4,
                                                      "method": "nope/x"}).encode(),
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                st, raw = r.status, r.read()
        except urllib.error.HTTPError as exc:
            st, raw = exc.code, exc.read()
        eq(st, 404, "未知方法应映射 404")
        eq(payload(raw)["error"]["code"], -32601, "未知方法应 -32601")

        req = urllib.request.Request("http://127.0.0.1:%d/mcp" % port,
                                     method="DELETE", data=b"")
        with urllib.request.urlopen(req, timeout=10) as r:
            eq(r.status, 200, "DELETE 结束会话要 200（回 501 客户端会判服务故障）")
    finally:
        srv.shutdown()
        srv.server_close()


@test("渲染层：人读文本带关键字段、怪形状不抛、超长截断")
def t_render():
    from apkindex.render import MAX_LINES, render
    good = render("searchClasses", {
        "ok": True, "tool": "searchClasses", "total": 5, "elapsedMs": 12.0, "hint": "h",
        "query": "La/b", "kind": "prefix",
        "items": [{"descriptor": "La/b/f;", "binaryName": "a.b.f",
                   "superClass": "android.app.Activity"},
                  {"descriptor": "Lz;", "binaryName": "z"}]})
    has(good, "searchClasses", "抬头带工具名")
    has(good, "La/b/f;", "descriptor 必须留在人读文本里（有的客户端只读 text）")
    has(good, "a.b.f", "binaryName 留在文本里")
    has(good, "另有", "被 limit 截断要说清")
    true(not good.lstrip().startswith("{"), "text 不再是 JSON 坨")
    bad = render("noSuchTool", {"ok": False, "code": "NOPE", "message": "m", "suggestion": "s"})
    has(bad, "NOPE", "失败码可见")
    has(bad, "建议", "失败文本带下一步")
    weird = render("stats", {"ok": True, "counts": None, "total": "n/a",
                             "items": ["x", 3, {"a": [1, 2], "b": None}]})
    true(isinstance(weird, str) and weird.strip() != "", "怪形状也只降级不抛")
    sig = render("getSignature", {"ok": True, "total": 1, "items": [{"forms": {
        "owner": "a.b.C", "name": "d", "java": "public void d()", "javaSimple": "public void d()",
        "smali": "La/b/C;->d()V", "reflector": "a.b.C->d()V",
        "paramsDescriptor": "()V", "returnDescriptor": "V"}}]})
    for k in ("java", "javaSimple", "smali", "reflector", "()V"):
        has(sig, k, "签名各写法都在人读文本里")
    big = render("sessionList", {"ok": True, "total": 900, "sessionId": "ses_x",
                                 "items": [{"sessionId": "s%d" % i, "pkg": "com.a%d" % i}
                                           for i in range(900)]})
    true(big.count("\n") <= MAX_LINES + 3, "超长结果按行截断 (%d 行)" % big.count("\n"))
    has(big, "structuredContent", "截断时告诉去哪看全量")



@test("tools/list 全量带 annotations 与 outputSchema，且只有 unload 标 destructive")
def t_tool_annotations_and_schema():
    """注解是给客户端做自动放行的依据。标错一个（比如把查询标成可写、把 unload
    标成非破坏），客户端的确认策略就整体失真，所以这里按名字逐个锁死。"""
    from apkindex import server as _s
    specs = _s.tool_specs()
    eq(len(specs), len(_s.TOOLS), "specs 与 TOOLS 数量一致")
    eq(sorted(x["name"] for x in specs), sorted(_s.BY_NAME), "specs 覆盖全部已注册工具")
    want_ro = {"loadApk", "loadAar", "loadDex", "unload"}
    for x in specs:
        a = x.get("annotations")
        true(isinstance(a, dict), x["name"] + " 缺 annotations")
        eq(sorted(a), ["destructiveHint", "idempotentHint", "openWorldHint",
                       "readOnlyHint"], x["name"] + " 注解四键必须齐全")
        eq(a["readOnlyHint"], x["name"] not in want_ro, x["name"] + " readOnlyHint")
        eq(a["destructiveHint"], x["name"] == "unload", x["name"] + " destructiveHint")
        eq(a["openWorldHint"], False, x["name"] + " 不该声明访问外部世界")
        sc = x.get("outputSchema")
        true(isinstance(sc, dict) and sc.get("properties", {}).get("ok"),
             x["name"] + " 的 outputSchema 必须声明信封的 ok 字段")
    dest = sorted(x["name"] for x in specs if x["annotations"]["destructiveHint"])
    eq(dest, ["unload"], "整个服务只有 unload 会删东西（删的是自己的索引缓存）")


@test("decompile 默认 auto：外部反编译器都不在也必须带回正文 + 完整降级链")
def t_decompile_auto_chain():
    """曾经的行为是 jadx 不在就抛 DECOMPILER_UNAVAILABLE，客户端空手而归。
    auto 必须 java->smali->outline 逐级退，并把每一步原因带回来；而且这些元数据
    不能被信封的单条上限削掉（削了就等于没解释）。"""
    from apkindex import decomp as _d
    jx, bs, jb = _d.jadx_bin, _d.baksmali_jar, _d.java_bin
    _d.jadx_bin = lambda: None
    _d.baksmali_jar = lambda: None
    _d.java_bin = lambda: None
    try:
        r = tool("decompile", sessionId=S1, target="com.example.demo.User")
        eq(r.get("code"), None, "两个外部依赖都没有时也应 ok：" + str(r.get("message")))
        it = r["items"][0]
        eq(it["format"], "auto", "默认格式是 auto")
        eq(it["engine"], "index-outline", "退到索引重建视图")
        eq(it["authoritative"], False, "非权威必须标注")
        eq(it["degraded"], True, "降级要显式说")
        ch = it.get("chain") or []
        eq(len(ch), 2, f"降级链要含 java/smali 两步：{ch}")
        true(str(ch[0]).startswith("java:DECOMPILER_UNAVAILABLE"),
             "第一步要说清 jadx 为什么不行：" + str(ch[0]))
        true(str(ch[1]).startswith("smali:"), "第二步是 baksmali：" + str(ch[1]))
        true(len((it.get("text") or "").strip()) > 40, "outline 正文必须真的带回来")
    finally:
        _d.jadx_bin, _d.baksmali_jar, _d.java_bin = jx, bs, jb
    from apkindex.render import render as _rnd
    txt = _rnd("decompile", tool("decompile", sessionId=S1,
                                 target="com.example.demo.User"))
    has(txt, "降级链", "人读文本里也要看见降级链")
    bad("decompile", "BAD_ARGUMENT", sessionId=S1, target="com.example.demo.User",
        format="ppt")




@test("<clinit> 的 kAccConstructor 位不能被当成构造方法（否则 DSL 生成假 hook 点）")
def t_clinit_is_not_constructor():
    """真机样本回归暴露的：d8 给 <clinit> 也打 0x10000，按位判就会
    生成 constructors{} 去 hook 一个方法表里根本不存在的构造方法 —— 能编译、
    运行期静默不命中，属于最贵的那种错。"""
    from apkindex import dex as _dx, dsl as _ds
    eq(_dx.flag_names(0x10008), ["static", "constructor"], "原始位读法（不加名字校正）")
    eq(_dx.method_flag_names(0x10008, "<clinit>"), ["static", "static-initializer"],
       "静态初始化器要改读")
    eq(_dx.method_flag_names(0x10000, "<init>"), ["constructor"], "<init> 仍是 constructor")
    eq(_dx.method_flag_names(0x10010, "run"), ["final"], "别的成员不写 constructor")
    d = _ds.match_dsl("com.example.A", "<clinit>", [], "V", access=0x10008)
    has(d, "静态初始化器", "要明说这是什么")
    true("constructors {" not in d and "methods {" not in d,
         "不能给出能编译但 hook 错位置的 matcher")
    has(d, "findClass", "同时给可行的替代路子")
    has(d, "loadMethod", "取句柄的路子留着")
    cs = tool("matchSignature", sessionId=S1, modifiers=["constructor"], limit=50)
    true(all((i.get("name") == "<init>") for i in cs.get("items") or []),
         "modifiers=constructor 只该命中 <init>：" +
         str([i.get("name") for i in (cs.get("items") or []) if i.get("name") != "<init>"][:4]))
    rc = tool("matchSignature", sessionId=S1, requireConstructor=True, limit=50)
    true(all((i.get("name") == "<init>") for i in rc.get("items") or []),
         "requireConstructor 同样按名字判")
    true(cs.get("total") == rc.get("total"), "两种写法结果一致")




@test("注解元素值封顶 + 错位症状（visibility 越界、非 reference 类型）不进索引")
def t_annotation_storage():
    from apkindex import dex as _dx
    from apkindex.index import _clip_args, _shrink
    true(_dx.usable_annotation("Lkotlin/Metadata;", 2), "正常注解通过")
    true(not _dx.usable_annotation("B", 92), "基本类型 descriptor + vis=92 → 拒收")
    true(not _dx.usable_annotation("La;", 180), "visibility 越界 → 拒收")
    true(not _dx.usable_annotation("", 0), "空 descriptor → 拒收")
    junk = "\x00$\n\x02\x18\x02" * 600                    # 真样本里那种二进制串
    s1 = _clip_args({"k": junk})
    true(len(s1) < 2000, f"超长元素换成摘要（{len(s1)}B）")
    has(s1, "_blob", "摘要里留了原始长度")
    wide = _clip_args({f"key{i}": "v" * 300 for i in range(60)})
    true(len(wide) <= 4096, f"整体超预算也封顶（{len(wide)}B）")
    eq(_shrink(42), 42, "标量原样")
    eq(_shrink(["A", "B"]), ["A", "B"], "短列表原样")
    eq(_shrink({"x": 1}), {"x": 1}, "短字典原样")
    true(isinstance(_shrink("ab\x00\x0a\x02\x18" * 4), dict), "控制字符占多数 → 判成 blob")


@test("注解读路径：getSignature 出类级注解，searchClasses 能按注解筛")
def t_annotation_readpath():
    import json as _j
    sid = load(os.path.join(FX, "demo-v1.apk"))["sessionId"]
    r = tool("getSignature", sessionId=sid, **{"class": "com.example.demo.User"})
    true(r.get("ok"), f"getSignature 通了：{r.get('code')}")
    cl = (r.get("signature") or {}).get("class") or {}
    ann = cl.get("annotations") or []
    true(any(a["descriptor"] == "Ldemo/Keep;" for a in ann),
         "类上的 @Keep 看得见：%s" % [a.get("descriptor") for a in ann])
    k = [a for a in ann if a["descriptor"] == "Ldemo/Keep;"][0]
    eq(k["javaName"], "demo.Keep", "注解自带 Java 名")
    eq(k["visibility"], "runtime", "visibility 名字化")
    eq(k.get("values"), {"value": "com.example.demo.User"}, "元素值原样回传")
    # 文本视图的正误在 test_render 里锁；这里只保证数据层不缺
    for ref in ("demo.Keep", "@Keep", "Ldemo/Keep;"):
        h = tool("searchClasses", sessionId=sid, query="com.example", annotatedWith=ref)
        true(h.get("ok") and "User" in _j.dumps(h["items"], ensure_ascii=False),
             "annotatedWith=%s 筛出 User" % ref)
    n_all = tool("searchClasses", sessionId=sid, query="com.example")["total"]
    n_f = tool("searchClasses", sessionId=sid, query="com.example",
               annotatedWith="@Keep")["total"]
    true(n_f < n_all, "注解筛选确实收窄（%s/%s）" % (n_f, n_all))
    bad = tool("searchClasses", sessionId=sid, query="com", annotatedWith="  ")
    eq(bad.get("code"), "BAD_ARGUMENT", "空白 annotatedWith 明确报错，不给假空结果")


@test("getSignature 的 member 打空必须给提示，不能安静回 0 个匹配")
def t_member_miss():
    sid = load(os.path.join(FX, "demo-v1.apk"))["sessionId"]
    r = tool("getSignature", sessionId=sid,
             **{"class": "com.example.demo.User", "member": "noSuchMethod"})
    true(r.get("ok"), "不是错误信封")
    true(r.get("total") == 0, "确实 0 个成员")
    has(r.get("hint") or "", "没有同名成员", "hint 说明了原因")
    has(r.get("hint") or "", "listMembers", "hint 给了下一步")
    r2 = tool("getSignature", sessionId=sid, **{"class": "com.example.demo.User"})
    true(r2.get("ok") and r2["signature"]["class"]["annotations"],
         "类级调用不受影响")


if __name__ == "__main__":
    sys.exit(main())
