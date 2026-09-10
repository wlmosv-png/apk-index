"""Library-AAR fixture builder.

classes.jar is produced by a real ``javac`` whenever a JDK is on PATH, so the
.class stream that ``apkindex.classfile`` parses is authoritative (javap agrees).
Without a JVM we fall back to :mod:`tools.classwrite`, which keeps the repository
usable on a machine that has only Python.
"""
from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import classwrite as cw  # noqa: E402

LIB_JAVA_SOURCES = {
    "com/example/lib/http/HttpCallback.java": """
package com.example.lib.http;
public interface HttpCallback {
    void onResult(String var1);
}
""",
    "com/example/lib/http/HttpClient.java": """
package com.example.lib.http;
public class HttpClient implements HttpCallback {
    private String baseUrl;

    public HttpClient() {
        this.baseUrl = "https://api.example.invalid";
    }

    public String get(String path) {
        return request("GET ", path);
    }

    public String post(String path) {
        return request("POST ", path);
    }

    private String request(String verb, String path) {
        System.out.println("timeout-retry-on:" + baseUrl + verb + path);
        return baseUrl + verb + path;
    }

    @Override
    public void onResult(String s) {
        this.baseUrl = s;
    }
}
""",
    "com/example/lib/http/RetryPolicy.java": """
package com.example.lib.http;
public class RetryPolicy {
    public int maxRetries() {
        return 3;
    }

    public long backoffMillis() {
        return 2500L;
    }
}
""",
}


def _classwrite_fallback():
    """Hand-rolled .class stream (no JVM available)."""
    def get_body(cp):
        return cw.body_ldc_areturn(cp, "GET")

    def post_body(cp):
        return cw.body_ldc_areturn(cp, "POST")

    ifc = cw.build_class("com/example/lib/http/HttpCallback",
                         interfaces=(), flags=0x0601, fields=(),
                         methods=[("onResult", "(Ljava/lang/String;)V", 0x0601, None)])
    http = cw.build_class("com/example/lib/http/HttpClient",
                          interfaces=("com/example/lib/http/HttpCallback",), flags=0x0021,
                          fields=[("baseUrl", "Ljava/lang/String;", 0x0002)],
                          methods=[("get", "(Ljava/lang/String;)Ljava/lang/String;", 0x0001, get_body),
                                   ("post", "(Ljava/lang/String;)Ljava/lang/String;", 0x0001, post_body),
                                   ("<init>", "()V", 0x0001, bytes([cw.OP_RETURN]))])
    util = cw.build_class("com/example/lib/http/RetryPolicy", flags=0x0021, fields=[],
                          methods=[("maxRetries", "()I", 0x0001,
                                    bytes([cw.OP_BIPUSH, 3, cw.OP_IRETURN]))])
    return [("com/example/lib/http/HttpClient.class", http),
            ("com/example/lib/http/HttpCallback.class", ifc),
            ("com/example/lib/http/RetryPolicy.class", util)], "classwrite"


def compile_lib_classes():
    """-> ([(entry_name, bytes)], how).  javac first, classwrite as fallback."""
    javac = shutil.which("javac")
    if not javac:
        return _classwrite_fallback()
    src = tempfile.mkdtemp(prefix="fixture-src-")
    cls = tempfile.mkdtemp(prefix="fixture-cls-")
    try:
        paths = []
        for rel, text in LIB_JAVA_SOURCES.items():
            p = os.path.join(src, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            io.open(p, "w", encoding="utf-8").write(text)
            paths.append(p)
        r = subprocess.run([javac, "-nowarn", "-d", cls] + paths,
                           capture_output=True, text=True)
        if r.returncode != 0:
            print("  javac 失败，退回 classwrite:", (r.stderr or "")[:200])
            return _classwrite_fallback()
        out = []
        for root, _dirs, files in os.walk(cls):
            for f in files:
                if f.endswith(".class"):
                    full = os.path.join(root, f)
                    out.append((os.path.relpath(full, cls).replace(os.sep, "/"),
                                io.open(full, "rb").read()))
        return sorted(out), "javac"
    finally:
        shutil.rmtree(src, ignore_errors=True)
        shutil.rmtree(cls, ignore_errors=True)


def build_aar(out_path: str) -> str:
    entries, how = compile_lib_classes()
    print(f"  classes.jar: {len(entries)} 个 class（{how}）")
    jars = {}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as j:
        for name, blob in entries:
            j.writestr(name, blob)
        j.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\n\r\n")
    jars["classes.jar"] = buf.getvalue()
    dep = io.BytesIO()
    with zipfile.ZipFile(dep, "w", zipfile.ZIP_DEFLATED) as j:
        j.writestr("com/example/lib/http/RetryPolicy.class",
                   dict(entries)["com/example/lib/http/RetryPolicy.class"])
        j.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\n\r\n")
    jars["libs/http-deps.jar"] = dep.getvalue()

    manifest = (b'<?xml version="1.0" encoding="utf-8"?>\n'
                b'<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
                b'    package="com.example.lib.http"\n'
                b'    android:versionCode="140" android:versionName="1.4.0">\n'
                b'  <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="34"/>\n'
                b'  <application/>\n'
                b'</manifest>\n')
    consumer = (b"# consumer-rules.pro\n"
                b"-keep class com.example.lib.http.HttpClient { *; }\n"
                b"-keep public class * implements com.example.lib.http.HttpCallback { public *; }\n"
                b"-keep interface com.example.lib.http.HttpCallback { *; }\n"
                b"-dontwarn com.example.lib.http.**\n")
    rtxt = (b"int id button_login 0x7f0b0001\n"
            b"int string http_error_timeout 0x7f130002\n"
            b"int layout http_activity_main 0x7f040003\n")
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", manifest)
        for name, blob in jars.items():
            z.writestr(name, blob)
        z.writestr("R.txt", rtxt)
        z.writestr("consumer-rules.pro", consumer)
        z.writestr("jni/arm64-v8a/libhttpcore.so", b"\x7fELF" + b"\x00" * 64)
        z.writestr("jni/armeabi-v7a/libhttpcore.so", b"\x7fELF" + b"\x00" * 48)
        z.writestr("prefab/prefab.json", b'{"name":"http","version":"1.4.0"}')
        z.writestr("headers/http/core.h", b"int http_init(void);\n")
        z.writestr("res/values/values.xml", b"<resources/>")
    return out_path
