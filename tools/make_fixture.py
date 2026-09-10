"""Generate every fixture used by tests/ -- no network, no JVM.

Outputs under ``--out`` (default ``fixtures/``):

  demo-v1.apk                 clean 2-dex APK (Activity + interface impl + strings)
  demo-v2.apk                 same app, R8-style renamed, +added -removed classes
  split-demo/                 base.apk + split_config.*.apk (merge test)
  packed.apk                  hardened-looking APK (jiagu libs + stub classes)
  lib-http-1.4.0.aar          library AAR (classes.jar via .class emitter, R.txt,
                              consumer-rules.pro, jni/*.so, prefab/headers)
  bare.dex, embedded.jar      loadDex inputs
  payload.vdex, cdx.vdex      vdex carving / explicit UNSUPPORTED_FORMAT
"""
from __future__ import annotations

import argparse
import io
import os
import random
import struct
import sys
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from apkindex import axml                                        # noqa: E402
from apkindex.dex import (ACC_ABSTRACT, ACC_CONSTRUCTOR,          # noqa: E402
                          ACC_FINAL, ACC_INTERFACE, ACC_PRIVATE,
                          ACC_PUBLIC, ACC_STATIC)
from apkindex.dexwrite import DI, DexBuilder, S, T                # noqa: E402

import classwrite as cw                                          # noqa: E402

ACC_SUPER = 0x20

A = "http://schemas.android.com/apk/res/android"
R = random.Random(20260909)


def an(name, value):
    return ("android", A, name, value)


def manifest_xml(package, vname, vcode, app_class=None, activity=".MainActivity",
                 extra_permissions=("android.permission.INTERNET",),
                 split=None):
    attrs = [an("versionCode", int(vcode)), an("versionName", str(vname))]
    if split:
        attrs.append(an("split", split))
    root = axml.Element("manifest", None,
                        [("xmlns", None, "xmlns", A)] + attrs
                        + [(None, None, "package", package)])
    sdk = axml.Element("uses-sdk", None, [an("minSdkVersion", 24),
                                          an("targetSdkVersion", 34)])
    root.children.append(sdk)
    for p in extra_permissions:
        u = axml.Element("uses-permission", None, [an("name", p)])
        root.children.append(u)
    app = axml.Element("application", None,
                       ([an("name", app_class)] if app_class else [])
                       + [an("label", "ApkIndexDemo"), an("debuggable", True)])
    root.children.append(app)
    if activity:
        act = axml.Element("activity", None, [an("name", activity),
                                              an("exported", True)])
        intent = axml.Element("intent-filter", None, [])
        intent.children.append(axml.Element("action", None, [an("name", "android.intent.action.MAIN")]))
        intent.children.append(axml.Element("category", None, [an("name", "android.intent.category.LAUNCHER")]))
        act.children.append(intent)
        app.children.append(act)
    svc = axml.Element("service", None, [an("name", ".DemoService")])
    app.children.append(svc)
    app.children.append(axml.Element("provider", None,
                                     [an("name", ".DemoProvider"),
                                      an("authorities", package + ".provider")]))
    app.children.append(axml.Element("meta-data", None,
                                     [an("name", "demo.channel"), an("value", "mcp")]))
    return axml.Writer(root).build()


def _java_lib_types(b: DexBuilder):
    """Type/method prototypes used across the demo classes."""
    return dict(
        object=b.method("Ljava/lang/Object;", "<init>", "V"),
        log_d=b.method("Landroid/util/Log;", "d", "I",
                       ("Ljava/lang/String;", "Ljava/lang/String;")),
        log_e=b.method("Landroid/util/Log;", "e", "I",
                       ("Ljava/lang/String;", "Ljava/lang/String;")),
        load_lib=b.method("Ljava/lang/System;", "loadLibrary", "V",
                          ("Ljava/lang/String;",)),
        bundle="Landroid/os/Bundle;",
    )


def demo_classes_v1():
    """(dex_name, DexBuilder) pairs -> two dexes, cross-dex references on purpose."""
    b1 = DexBuilder()
    L = _java_lib_types(b1)

    user = b1.add_class("Lcom/example/demo/User;", ACC_PUBLIC | ACC_SUPER,
                        source="User.java")
    f_tok = b1.add_field(user, "mToken", "Ljava/lang/String;", ACC_PRIVATE)
    b1.add_field(user, "sTag", "Ljava/lang/String;", ACC_STATIC | ACC_FINAL)
    b1.add_field(user, "age", "I", ACC_PUBLIC)
    b1.add_method(user, "<init>", "V", (), ACC_PUBLIC, ctor=True, insns=[
        DI.invoke("direct", [1], L["object"]), DI.ret_void()], locals_=2)
    b1.add_method(user, "getName", "Ljava/lang/String;", (), ACC_PUBLIC, insns=[
        DI.iget(1, 0, f_tok), DI.ret_obj(1)], locals_=2)
    b1.add_method(user, "setToken", "V", ("Ljava/lang/String;",), ACC_PUBLIC, insns=[
        DI.iput(1, 0, f_tok), DI.ret_void()], locals_=2, outs=1)
    b1.add_method(user, "describe", "Ljava/lang/String;", ("Ljava/lang/String;",),
                  ACC_PUBLIC, insns=[
        DI.const_string(1, S("user-describe:")),
        DI.invoke("static", [0, 1], b1.method("Lcom/example/demo/User;", "create",
                                            "Lcom/example/demo/User;",
                                            ("Ljava/lang/String;",))),
        DI.move_res_obj(1),
        DI.invoke("virtual", [1], b1.method("Lcom/example/demo/User;", "getName",
                                          "Ljava/lang/String;")),
        DI.move_res_obj(1), DI.ret_obj(1)], locals_=3, outs=2)
    b1.add_method(user, "create", "Lcom/example/demo/User;", ("Ljava/lang/String;",),
                  ACC_PUBLIC | ACC_STATIC, insns=[
        DI.new_instance(1, T("Lcom/example/demo/User;")),
        DI.invoke("direct", [1], L["object"]), DI.ret_obj(1)], locals_=2, outs=1)
    b1.add_annotation(user, "Ldemo/Keep;", {"value": "com.example.demo.User"})

    greeter = b1.add_class("Lcom/example/demo/Greeter;",
                           ACC_PUBLIC | ACC_INTERFACE | ACC_ABSTRACT, super_=None,
                           source="Greeter.java")
    b1.add_method(greeter, "greet", "Ljava/lang/String;", ("Ljava/lang/String;",),
                  ACC_PUBLIC | ACC_ABSTRACT)
    b1.add_method(greeter, "name", "Ljava/lang/String;", (),
                  ACC_PUBLIC | ACC_ABSTRACT)

    jg = b1.add_class("Lcom/example/demo/JavaGreeter;", ACC_PUBLIC | ACC_SUPER,
                      ifaces=["Lcom/example/demo/Greeter;"], source="JavaGreeter.java")
    b1.add_method(jg, "<init>", "V", (), ACC_PUBLIC, ctor=True, insns=[
        DI.invoke("direct", [1], L["object"]), DI.ret_void()], locals_=2)
    b1.add_method(jg, "greet", "Ljava/lang/String;", ("Ljava/lang/String;",),
                  ACC_PUBLIC, insns=[
        DI.const_string(1, S("Hello, ")),
        DI.invoke("static", [1, 2], b1.method("Lcom/example/demo/Strings;", "concat",
                                            "Ljava/lang/String;",
                                            ("Ljava/lang/String;",
                                             "Ljava/lang/String;"))),
        DI.move_res_obj(1), DI.ret_obj(1)], locals_=3, outs=2)
    b1.add_method(jg, "name", "Ljava/lang/String;", (), ACC_PUBLIC, insns=[
        DI.const_string(1, S("java-greeter")), DI.ret_obj(1)], locals_=2)

    strings = b1.add_class("Lcom/example/demo/Strings;", ACC_PUBLIC, source="Strings.java")
    b1.add_method(strings, "concat", "Ljava/lang/String;",
                  ("Ljava/lang/String;", "Ljava/lang/String;"),
                  ACC_PUBLIC | ACC_STATIC, insns=[
        DI.invoke("static", [0, 1], b1.method("Lcom/example/demo/Strings;", "concat",
                                            "Ljava/lang/String;",
                                            ("Ljava/lang/String;",
                                             "Ljava/lang/String;"))),
        DI.move_res_obj(0), DI.ret_obj(0)], locals_=2, outs=2)

    bc = b1.add_class("Lcom/example/demo/BuildConfig;", ACC_PUBLIC,
                      source="BuildConfig.java")
    b1.add_field(bc, "APPLICATION_ID", "Ljava/lang/String;",
                 ACC_PUBLIC | ACC_STATIC | ACC_FINAL)
    b1.add_field(bc, "VERSION_CODE", "I", ACC_PUBLIC | ACC_STATIC | ACC_FINAL)

    adapter = b1.add_class("Lcom/example/demo/UserAdapter;", ACC_PUBLIC,
                           ifaces=["Lcom/example/demo/Greeter;"],
                           source="UserAdapter.java")
    f_u = b1.add_field(adapter, "user", "Lcom/example/demo/User;", ACC_PRIVATE)
    b1.add_method(adapter, "<init>", "V", (), ACC_PUBLIC, ctor=True, insns=[
        DI.invoke("direct", [1], L["object"]), DI.ret_void()], locals_=2)
    b1.add_method(adapter, "bind", "V", ("Lcom/example/demo/User;",), ACC_PUBLIC,
                  insns=[DI.iput(1, 0, f_u),
                         DI.const_string(1, S("adapter-bind")),
                         DI.invoke("static", [1], b1.method(
                             "Lcom/example/demo/Trace;", "beginSection",
                             "V", ("Ljava/lang/String;",))),
                         DI.ret_void()], locals_=2, outs=1)
    b1.add_method(adapter, "greet", "Ljava/lang/String;", ("Ljava/lang/String;",),
                  ACC_PUBLIC, insns=[
        DI.iget(1, 0, f_u),
        DI.invoke("virtual", [1], b1.method("Lcom/example/demo/User;", "getName",
                                          "Ljava/lang/String;")),
        DI.move_res_obj(1), DI.ret_obj(1)], locals_=3, outs=1)
    b1.add_method(adapter, "name", "Ljava/lang/String;", (), ACC_PUBLIC, insns=[
        DI.const_string(1, S("adapter")), DI.ret_obj(1)], locals_=2)

    # ---- dex 2: the Activity references classes defined in dex 1
    b2 = DexBuilder()
    L2 = _java_lib_types(b2)
    act = b2.add_class("Lcom/example/demo/MainActivity;", ACC_PUBLIC | ACC_SUPER,
                       super_="Landroid/app/Activity;", source="MainActivity.java")
    f_ad = b2.add_field(act, "adapter", "Lcom/example/demo/UserAdapter;", ACC_PRIVATE)
    f_tok = b2.add_field(act, "token", "Ljava/lang/String;", ACC_PRIVATE)
    b2.add_method(act, "<init>", "V", (), ACC_PUBLIC, ctor=True, insns=[
        DI.invoke("direct", [1], b2.method("Landroid/app/Activity;", "<init>", "V")),
        DI.ret_void()], locals_=2)
    b2.add_method(act, "onCreate", "V", ("Landroid/os/Bundle;",), ACC_PUBLIC, insns=[
        DI.invoke("super", [0, 1], b2.method("Landroid/app/Activity;", "onCreate",
                                           "V", ("Landroid/os/Bundle;",))),
        DI.const_string(1, S("DemoTag")),
        DI.const_string(2, S("sign_in_clicked")),
        DI.invoke("static", [1, 2], L2["log_d"]),
        DI.new_instance(1, T("Lcom/example/demo/User;")),
        DI.invoke("direct", [1], b2.method("Lcom/example/demo/User;", "<init>", "V")),
        DI.iput(1, 0, f_ad),
        DI.invoke("virtual", [1], b2.method("Lcom/example/demo/User;", "getName",
                                          "Ljava/lang/String;")),
        DI.move_res_obj(1),
        DI.iput(1, 0, f_tok),
        DI.const_string(1, S("shared_prefs_demo")),
        DI.invoke("static", [1], b2.method("Lcom/example/demo/Prefs;", "key",
                                         "V", ("Ljava/lang/String;",))),
        DI.ret_void()], locals_=4, outs=2)
    b2.add_method(act, "onClick", "V", ("Landroid/view/View;",), ACC_PUBLIC, insns=[
        DI.const_string(1, S("clicked-user")),
        DI.invoke("virtual", [0], b2.method("Lcom/example/demo/MainActivity;",
                                          "getNameForLog", "Ljava/lang/String;")),
        DI.move_res_obj(2),
        DI.invoke("static", [1, 2], L2["log_e"]),
        DI.ret_void()], locals_=3, outs=2)
    b2.add_method(act, "getNameForLog", "Ljava/lang/String;", (), ACC_PUBLIC, insns=[
        DI.const_string(1, S("MainActivity")), DI.ret_obj(1)], locals_=2)
    lam = b2.add_class("Lcom/example/demo/MainActivity$$ExternalSyntheticLambda0;",
                       ACC_PUBLIC | ACC_FINAL,
                       ifaces=["Lcom/example/demo/Greeter;"], source="MainActivity.java")
    b2.add_method(lam, "<init>", "V", (), ACC_PUBLIC, ctor=True, insns=[
        DI.invoke("direct", [1], L2["object"]), DI.ret_void()], locals_=2)
    b2.add_method(lam, "greet", "Ljava/lang/String;", ("Ljava/lang/String;",),
                  ACC_PUBLIC, insns=[DI.const_string(1, S("lambda")), DI.ret_obj(1)],
                  locals_=2)
    b2.add_method(lam, "name", "Ljava/lang/String;", (), ACC_PUBLIC, insns=[
        DI.const_string(1, S("lambda-name")), DI.ret_obj(1)], locals_=2)
    return [("classes.dex", b1), ("classes2.dex", b2)]


DEMO_APP_CLASS = "com.example.demo.DemoApp"


def demo_app_dex():
    b = DexBuilder()
    L = _java_lib_types(b)
    app = b.add_class("Lcom/example/demo/DemoApp;", ACC_PUBLIC,
                      super_="Landroid/app/Application;", source="DemoApp.java")
    b.add_method(app, "<init>", "V", (), ACC_PUBLIC, ctor=True, insns=[
        DI.invoke("direct", [1], b.method("Landroid/app/Application;", "<init>", "V")),
        DI.ret_void()], locals_=2)
    return b


def split_config_dex(tag: str, abi_cls: str, extra_strings=()):
    b = DexBuilder()
    L = _java_lib_types(b)
    c = b.add_class("Lcom/example/demo/split/%s;" % abi_cls, ACC_PUBLIC,
                    source="Split.java")
    b.add_method(c, "id", "Ljava/lang/String;", (), ACC_PUBLIC,
                 insns=[DI.const_string(1, S("split-%s" % tag))] +
                 [DI.const_string(1, S(x)) for x in extra_strings] +
                 [DI.ret_obj(1)], locals_=2)
    return b


def packed_dexes():
    b1 = DexBuilder()
    L = _java_lib_types(b1)
    stub = b1.add_class("Lcom/stub/StubApp;", ACC_PUBLIC,
                        super_="Landroid/app/Application;", source="StubApp.java")
    b1.add_method(stub, "<init>", "V", (), ACC_PUBLIC, ctor=True, insns=[
        DI.invoke("direct", [1], b1.method("Landroid/app/Application;", "<init>", "V")),
        DI.ret_void()], locals_=2)
    b1.add_method(stub, "attachBaseContext", "V", ("Landroid/content/Context;",),
                  ACC_PUBLIC, insns=[
        DI.const_string(1, S("jiagu")),
        DI.invoke("static", [1], L["load_lib"]),
        DI.invoke("static", [0], b1.method("Lcom/qihoo/util/NSU;",
                                         "loadDex", "V",
                                         ("Landroid/content/Context;",))),
        DI.ret_void()], locals_=2, outs=1)
    q = b1.add_class("Lcom/qihoo/util/NSU;", ACC_PUBLIC, source="NSU.java")
    b1.add_method(q, "loadDex", "V", ("Landroid/content/Context;",),
                  ACC_PUBLIC | ACC_STATIC, insns=[
        DI.const_string(1, S("classes.dex")), DI.ret_void()], locals_=2)
    ent = b1.add_class("Lcom/example/shelled/RealApp;", ACC_PUBLIC,
                       super_="Lcom/stub/StubApp;", source="RealApp.java")
    b1.add_method(ent, "<init>", "V", (), ACC_PUBLIC, ctor=True, insns=[
        DI.invoke("direct", [1], b1.method("Lcom/stub/StubApp;", "<init>", "V")),
        DI.ret_void()], locals_=2)
    # noise classes with random names + random strings (packed-looking dex)
    for i in range(40):
        nm = "L%s/%s;" % ("".join(R.choice("abcdefg") for _ in range(3)),
                          "".join(R.choice("ABCDabcdefgh") for _ in range(4)))
        c = b1.add_class(nm, ACC_PUBLIC, source=None)
        b1.add_method(c, "".join(R.choice("abcdefgh") for _ in range(3)),
                      "Ljava/lang/String;", (), ACC_PUBLIC, insns=[
            DI.const_string(1, S(_rand_str(28))), DI.ret_obj(1)], locals_=2)
    return [("classes.dex", b1)]


def _rand_str(n):
    al = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
    return "".join(R.choice(al) for _ in range(n))


# ------------------------------------------------------------------ packaging
def build_dexes(pairs):
    return [(name, b.build()) for name, b in pairs]


def write_apk(out_path, dex_blobs, manifest_bytes, extras=None,
              app_class=None, compress=zipfile.ZIP_DEFLATED):
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with zipfile.ZipFile(out_path, "w", compress) as z:
        z.writestr("AndroidManifest.xml", manifest_bytes)
        for name, blob in dex_blobs:
            z.writestr(name, blob)
        for name, blob in (extras or {}).items():
            z.writestr(name, blob)
        resources = _resources_arsc()
        z.writestr("resources.arsc", resources)
        z.writestr("META-INF/CERT.SF", b"Manifest-Version: 1.0\r\nCreated-By: apk-index fixture\r\n")
        z.writestr("META-INF/CERT.RSA", b"\x30\x82\x00\x00fake-pkcs7")
        z.writestr("META-INF/com/android/build/gradle/app-metadata.properties",
                   b"appMetadataVersion=1.1\r\nandroidGradlePluginVersion=8.5.0\r\n")
        z.writestr("META-INF/androidx.compose.runtime_runtime.version", b"1.6.0\r\n")
        z.writestr("META-INF/kotlin-application.kotlin_module", b"\x00\x00\x00\x00")
        z.writestr("kotlin/kotlin.kotlin_builtins", b"\x00\x01\x02")


def _resources_arsc():
    return b"RES0" + struct.pack("<I", 8) + b"\x00" * 32


def build_vdex(dex_blob, magic_version=b"010"):
    """A container that *embeds* a complete dex -- exactly what apkio.carve_dexes
    is allowed to recover (as opposed to compact-dex deltas)."""
    pad = b"\x00" * 32
    ver = b"vdex" + magic_version + b"\x00" * 4
    sections = struct.pack("<II", 1, 40 + len(ver) + len(pad))
    blob = ver + sections + pad + b"\x00" * 4
    while len(blob) % 8:
        blob += b"\x00"
    blob += dex_blob
    return blob + b"\x00" * 64


def build_cdx_only_vdex():
    ver = b"vdex" + b"019" + b"\x00" * 4
    return ver + struct.pack("<II", 2, 48) + b"cdx\x00" + struct.pack(
        "<I", 64) + os.urandom(4096)


def build_aar(out_path):
    """Library AAR fixture —— 见 tools/libfixture.py（有 JDK 就用 javac 出真实 .class）。"""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import libfixture
    return libfixture.build_aar(out_path)


def cw_flags_interface():
    return 0x0601


def make_all(out_dir: str) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    paths = {}
    # ---------------- demo v1 (two dexes, no splits)
    blobs = build_dexes(demo_classes_v1() + [("classes3.dex", demo_app_dex())])
    p = os.path.join(out_dir, "demo-v1.apk")
    write_apk(p, blobs, manifest_xml("com.example.demo", "1.0.0", 1,
                                     app_class=DEMO_APP_CLASS))
    paths["demoV1"] = p
    # ---------------- split demo (dir with base + 2 config splits)
    sd = os.path.join(out_dir, "split-demo", "com.example.demo")
    os.makedirs(sd, exist_ok=True)
    write_apk(os.path.join(sd, "base.apk"),
              build_dexes(demo_classes_v1()),
              manifest_xml("com.example.demo", "1.0.0", 1, app_class=DEMO_APP_CLASS))
    write_apk(os.path.join(sd, "split_config.arm64_v8a.apk"),
              build_dexes([("classes.dex",
                            split_config_dex("arm64", "Abi64",
                                             ("arm64-v8a-only-string",)))]),
              manifest_xml("com.example.demo", "1.0.0", 1, activity=None,
                           extra_permissions=(), split="config.arm64_v8a"),
              extras={"lib/arm64-v8a/libdemo.so": b"\x7fELF" + b"\x00" * 120,
                      "lib/arm64-v8a/libjiagu_helper.so": b"\x7fELF" + b"\x00" * 40})
    write_apk(os.path.join(sd, "split_config.zh.apk"),
              build_dexes([("classes.dex",
                            split_config_dex("zh", "LocaleZh",
                                             ("zh-locale-only-string",)))]),
              manifest_xml("com.example.demo", "1.0.0", 1, activity=None,
                           extra_permissions=(), split="config.zh"))
    paths["splitDir"] = sd
    # ---------------- demo v2 (renamed / R8 style)
    p = os.path.join(out_dir, "demo-v2.apk")
    write_apk(p, build_dexes(demo_classes_v2()),
              manifest_xml("com.example.demo", "2.0.0", 2, app_class=DEMO_APP_CLASS))
    paths["demoV2"] = p
    # ---------------- packed demo
    p = os.path.join(out_dir, "packed.apk")
    write_apk(p, build_dexes(packed_dexes()),
              manifest_xml("com.example.shelled", "5.1.0", 510,
                           app_class="com.stub.StubApp", activity=None),
              extras={"lib/armeabi-v7a/libjiagu.so": b"\x7fELF" + b"\x00" * 96,
                      "lib/arm64-v8a/libjiagu_64.so": b"\x7fELF" + b"\x00" * 96,
                      "assets/ijiami.ajm": os.urandom(2048),
                      "assets/libexec.so": b"\x7fELF" + b"\x00" * 32})
    paths["packed"] = p
    # ---------------- bare dex + embedded jar + vdex
    blobs = build_dexes(demo_classes_v1())
    p = os.path.join(out_dir, "bare.dex")
    open(p, "wb").write(blobs[0][1])
    paths["bareDex"] = p
    p = os.path.join(out_dir, "embedded.jar")
    with zipfile.ZipFile(p, "w", zipfile.ZIP_STORED) as z:
        z.writestr("classes.dex", blobs[1][1])
        z.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\n\r\n")
    paths["embeddedJar"] = p
    p = os.path.join(out_dir, "payload.vdex")
    open(p, "wb").write(build_vdex(blobs[0][1]))
    paths["vdex"] = p
    p = os.path.join(out_dir, "cdx.vdex")
    open(p, "wb").write(build_cdx_only_vdex())
    paths["cdxVdex"] = p
    # ---------------- aar
    p = os.path.join(out_dir, "lib-http-1.4.0.aar")
    paths["aar"] = build_aar(p)
    manifest = os.path.join(out_dir, "FIXTURES.txt")
    with open(manifest, "w") as f:
        for k, v in sorted(paths.items()):
            f.write("%s\t%s\t%d\n" % (k, v, os.path.getsize(v)
                                      if os.path.isfile(v) else -1))
    paths["manifest"] = manifest
    return paths


# ------------------------------------------------------------------ v2 (R8-ish)
def demo_classes_v2():
    """Same structure as v1, renamed classes/methods, +1 class, -2 classes."""
    b1 = DexBuilder()
    L = _java_lib_types(b1)
    user = b1.add_class("La/b/c;", ACC_PUBLIC, source="a.java")
    f_tok = b1.add_field(user, "a", "Ljava/lang/String;", ACC_PRIVATE)
    b1.add_field(user, "b", "Ljava/lang/String;", ACC_STATIC | ACC_FINAL)
    b1.add_field(user, "c", "I", ACC_PUBLIC)
    b1.add_method(user, "<init>", "V", (), ACC_PUBLIC, ctor=True, insns=[
        DI.invoke("direct", [1], L["object"]), DI.ret_void()], locals_=2)
    b1.add_method(user, "a", "Ljava/lang/String;", (), ACC_PUBLIC, insns=[
        DI.iget(1, 0, f_tok), DI.ret_obj(1)], locals_=2)
    b1.add_method(user, "b", "V", ("Ljava/lang/String;",), ACC_PUBLIC, insns=[
        DI.iput(1, 0, f_tok), DI.ret_void()], locals_=2, outs=1)
    b1.add_method(user, "c", "Ljava/lang/String;", ("Ljava/lang/String;",),
                  ACC_PUBLIC, insns=[
        DI.const_string(1, S("user-describe:")),
        DI.invoke("static", [0, 1], b1.method("La/b/c;", "d", "La/b/c;",
                                            ("Ljava/lang/String;",))),
        DI.move_res_obj(1),
        DI.invoke("virtual", [1], b1.method("La/b/c;", "a", "Ljava/lang/String;")),
        DI.move_res_obj(1), DI.ret_obj(1)], locals_=3, outs=2)
    b1.add_method(user, "d", "La/b/c;", ("Ljava/lang/String;",),
                  ACC_PUBLIC | ACC_STATIC, insns=[
        DI.new_instance(1, T("La/b/c;")),
        DI.invoke("direct", [1], L["object"]), DI.ret_obj(1)], locals_=2, outs=1)
    ifc = b1.add_class("La/b/d;", ACC_PUBLIC | ACC_INTERFACE | ACC_ABSTRACT,
                       super_=None, source="d.java")
    b1.add_method(ifc, "a", "Ljava/lang/String;", ("Ljava/lang/String;",),
                  ACC_PUBLIC | ACC_ABSTRACT)
    b1.add_method(ifc, "name", "Ljava/lang/String;", (), ACC_PUBLIC | ACC_ABSTRACT)
    impl = b1.add_class("La/b/e;", ACC_PUBLIC, ifaces=["La/b/d;"], source="e.java")
    b1.add_method(impl, "<init>", "V", (), ACC_PUBLIC, ctor=True, insns=[
        DI.invoke("direct", [1], L["object"]), DI.ret_void()], locals_=2)
    b1.add_method(impl, "a", "Ljava/lang/String;", ("Ljava/lang/String;",),
                  ACC_PUBLIC, insns=[
        DI.const_string(1, S("Hello, ")),
        DI.invoke("static", [1, 2], b1.method("Lcom/example/demo/Strings;", "concat",
                                            "Ljava/lang/String;",
                                            ("Ljava/lang/String;",
                                             "Ljava/lang/String;"))),
        DI.move_res_obj(1), DI.ret_obj(1)], locals_=3, outs=2)
    b1.add_method(impl, "name", "Ljava/lang/String;", (), ACC_PUBLIC, insns=[
        DI.const_string(1, S("java-greeter")), DI.ret_obj(1)], locals_=2)
    added = b1.add_class("La/b/g;", ACC_PUBLIC, source="g.java")
    b1.add_method(added, "a", "V", (), ACC_PUBLIC, insns=[
        DI.const_string(1, S("brand-new-in-v2")), DI.ret_void()], locals_=2)
    strings = b1.add_class("Lcom/example/demo/Strings;", ACC_PUBLIC, source="Strings.java")
    b1.add_method(strings, "concat", "Ljava/lang/String;",
                  ("Ljava/lang/String;", "Ljava/lang/String;"),
                  ACC_PUBLIC | ACC_STATIC, insns=[
        DI.move_res_obj(0), DI.ret_obj(0)], locals_=2, outs=2)
    b2 = DexBuilder()
    L2 = _java_lib_types(b2)
    act = b2.add_class("La/b/f;", ACC_PUBLIC, super_="Landroid/app/Activity;",
                       source="f.java")
    f_ad = b2.add_field(act, "a", "Lcom/example/demo/UserAdapter;", ACC_PRIVATE)
    b2.add_method(act, "<init>", "V", (), ACC_PUBLIC, ctor=True, insns=[
        DI.invoke("direct", [1], b2.method("Landroid/app/Activity;", "<init>", "V")),
        DI.ret_void()], locals_=2)
    b2.add_method(act, "onCreate", "V", ("Landroid/os/Bundle;",), ACC_PUBLIC, insns=[
        DI.invoke("super", [0, 1], b2.method("Landroid/app/Activity;", "onCreate",
                                           "V", ("Landroid/os/Bundle;",))),
        DI.const_string(1, S("DemoTag")),
        DI.const_string(2, S("sign_in_clicked")),
        DI.invoke("static", [1, 2], L2["log_d"]),
        DI.new_instance(1, T("La/b/c;")),
        DI.invoke("direct", [1], b2.method("La/b/c;", "<init>", "V")),
        DI.iput(1, 0, f_ad),
        DI.invoke("virtual", [1], b2.method("La/b/c;", "a", "Ljava/lang/String;")),
        DI.move_res_obj(1), DI.ret_void()], locals_=4, outs=2)
    b2.add_method(act, "onClick", "V", ("Landroid/view/View;",), ACC_PUBLIC, insns=[
        DI.const_string(1, S("clicked-user")),
        DI.invoke("static", [1, 1], L2["log_e"]), DI.ret_void()], locals_=3, outs=2)
    return [("classes.dex", b1), ("classes2.dex", b2)]


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="fixtures")
    a = ap.parse_args()
    made = make_all(a.out)
    for k, v in sorted(made.items()):
        print("%-12s %s" % (k, v))
