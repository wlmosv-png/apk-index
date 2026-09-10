"""apk-index 手机本地命令行。

MCP 走 stdio 长连接，适合客户端；但在手机 shell 里手查一个类，
不该逼人现写 python3 -c 拼 JSON。这里提供一次性调用：

    apk-index tools
    apk-index call searchClasses '{"keyword":"Hook","limit":5}'
    apk-index pull com.tencent.mm               # adb 拉包并索引（loadApk fromDevice）
    apk-index doctor [some.apk]                 # 自检引擎依赖

环境变量与 bin/apk-index 启动器一致：APK_INDEX_ALLOWED_ROOTS、
APK_INDEX_CACHE。stdout 永远是 JSON 信封，方便 | jq。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time

from . import config as cfg
from . import server as srv


def _out(obj) -> int:
    json.dump(obj, sys.stdout, ensure_ascii=False, default=str)
    sys.stdout.write("\n")
    return 0 if not (isinstance(obj, dict) and obj.get("ok") is False) else 1


def _root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def cmd_tools(_: list[str]) -> int:
    names = []
    for attr in ("TOOLS", "TOOL_SPECS", "TOOL_SCHEMAS"):
        specs = getattr(srv, attr, None)
        if isinstance(specs, list) and specs:
            names = [s.get("name") for s in specs if isinstance(s, dict)]
            break
    if not names:
        names = sorted(getattr(srv, "HANDLERS", {}) or {})
    return _out({"ok": True, "count": len(names), "tools": names})


def cmd_call(argv: list[str]) -> int:
    if not argv:
        return _out({"ok": False, "code": "BAD_ARGUMENT",
                     "message": "用法: apk-index call <tool> ['{json}']"})
    name = argv[0]
    raw = argv[1] if len(argv) > 1 else "{}"
    try:
        args = json.loads(raw)
        if not isinstance(args, dict):
            raise TypeError("参数必须是 JSON 对象")
    except Exception as e:                                    # noqa: BLE001
        return _out({"ok": False, "code": "BAD_ARGUMENT",
                     "message": f"参数不是合法 JSON 对象: {e}",
                     "suggestion": "整体用单引号包住，例如 '{\"keyword\":\"Hook\"}'。"})
    return _out(srv.call_tool(name, args))


def cmd_pull(argv: list[str]) -> int:
    """设备里已装的包 -> 直接索引好 -> 给 sessionId + 类数。

    真实入口是 loadApk(fromDevice=true, packageName=...)：内部走
    `adb shell pm path` 找到 base.apk/分包并拉取入库。没有独立的
    devicePullApk 工具，别再凭想象调它。
    """
    if not argv:
        return _out({"ok": False, "code": "BAD_ARGUMENT",
                     "message": "用法: apk-index pull <包名> [--splits]"})
    pkg = argv[0]
    args = {"fromDevice": True, "packageName": pkg}
    if "--splits" in argv[1:]:
        args["splits"] = True
    ld = srv.call_tool("loadApk", args)
    if not ld.get("ok"):
        return _out(ld)
    sid = ld.get("sessionId") or ""
    st = srv.call_tool("stats", {"sessionId": sid})
    classes = st.get("classes") or (st.get("items") or [{}])[0].get("classes")
    return _out({"ok": True, "package": pkg, "sessionId": sid,
                 "classes": classes, "elapsedMs": ld.get("elapsedMs"),
                 "packed": ld.get("packed"), "sources": ld.get("sources"),
                 "hint": "接着: apk-index call stats '{\"sessionId\":\"%s\"}' "
                         "或 searchClasses '{\"sessionId\":\"%s\",\"query\":\"Hook\"}'"
                         % (sid, sid)})


def cmd_doctor(argv: list[str]) -> int:
    root = _root()
    rep: dict = {"ok": True, "python": sys.version.split()[0],
                 "abiRoot": root,
                 "cacheDir": getattr(cfg, "CACHE_DIR",
                                     os.path.expanduser("~/.cache/apk-index")),
                 "allowedRoots": list(getattr(cfg, "ALLOWED_ROOTS", ()) or
                                      getattr(cfg, "ALLOWED_ROOTS_LIST", ()) or
                                      os.environ.get("APK_INDEX_ALLOWED_ROOTS", "").split(":"))}
    for name in ("java", "jadx", "unzip", "aapt2", "sqlite3"):
        rep[name] = shutil.which(name) or "缺失"
    for rel in ("tools/dexlib.jar", "tools/baksmali.jar", "tools/apktool.jar",
                "jadx/bin/jadx"):
        p = os.path.join(root, rel)
        rep[rel] = os.path.getsize(p) if os.path.exists(p) else "缺失"
    try:
        cdir = getattr(cfg, "CACHE_DIR", os.path.expanduser("~/.cache/apk-index"))
        os.makedirs(cdir, exist_ok=True)
        probe = os.path.join(cdir, ".write-test")
        with open(probe, "w", encoding="utf-8") as f:
            f.write("ok")
        os.remove(probe)
        rep["cacheWritable"] = True
    except Exception as e:                                    # noqa: BLE001
        rep["cacheWritable"] = f"不可写: {e}"
    apk = next((a for a in argv if os.path.exists(a)), "")
    if apk:
        t0 = time.time()
        ld = srv.call_tool("loadApk", {"path": apk})
        rep["smoke"] = {"ok": ld.get("ok"), "code": ld.get("code"),
                        "classes": ld.get("total"), "elapsedMs": ld.get("elapsedMs"),
                        "wallMs": round((time.time() - t0) * 1000, 1),
                        "sessionId": ld.get("sessionId")}
        if ld.get("ok"):
            # 17 个工具里没有 closeSession，清场用 unload；失败不影响体检结论
            srv.call_tool("unload", {"sessionId": ld["sessionId"]})
    else:
        rep["smoke"] = "未给 APK 路径，跳过端到端冒烟"
    bad = [k for k, v in rep.items() if v == "缺失" or (isinstance(v, str) and v.startswith("不可写"))]
    rep["ok"] = not bad
    rep["hint"] = ("全部就绪，可以直接 call/pull。" if not bad else
                   "缺这些依赖: " + ", ".join(bad) + " —— 反编译/解析会走降级路径。")
    return _out(rep)


def cmd_sessions(_: list[str]) -> int:
    return _out(srv.call_tool("sessionList", {}))




def cmd_serve_http(argv: list[str]) -> int:
    """起 Streamable HTTP 版 MCP，给手机上只能填 URL 的客户端用。"""
    host, port, verbose = "127.0.0.1", 8732, False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--host" and i + 1 < len(argv):
            host = argv[i + 1]; i += 2
        elif a == "--port" and i + 1 < len(argv):
            try:
                port = int(argv[i + 1])
            except ValueError:
                return _out({"ok": False, "code": "BAD_ARGUMENT",
                             "message": "--port 要数字: " + argv[i + 1]})
            i += 2
        elif a == "--verbose":
            verbose = True; i += 1
        else:
            return _out({"ok": False, "code": "BAD_ARGUMENT",
                         "message": "未知参数: " + a,
                         "suggestion": "apk-index serve-http [--host 127.0.0.1] [--port 8732] [--verbose]"})
    from . import httpd
    return httpd.serve(host, port, verbose)

CMDS = {"tools": cmd_tools, "call": cmd_call, "pull": cmd_pull,
        "doctor": cmd_doctor, "sessions": cmd_sessions, "serve-http": cmd_serve_http}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        sys.stderr.write(
            "apk-index <tools|call <tool> <json>|pull <包名>|sessions|doctor [apk]|serve-http [--host H] [--port P]>\n"
            "  给手机 shell 用的一次性调用口；MCP 长连接仍用 bin/apk-index 直接起服务。\n")
        return 0
    fn = CMDS.get(argv[0])
    if not fn:
        return _out({"ok": False, "code": "BAD_ARGUMENT",
                     "message": f"未知子命令: {argv[0]}",
                     "suggestion": "可选: " + ", ".join(CMDS)})
    return fn(argv[1:])


if __name__ == "__main__":
    sys.exit(main())
