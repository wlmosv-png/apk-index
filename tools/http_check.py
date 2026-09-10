#!/usr/bin/env python3
"""apk-index HTTP 传输的自检客户端（纯标准库，不依赖 MCP SDK）。

用途：
  http_check.py health                     # GET /mcp 看版本/工具数/鉴权模式
  http_check.py list                       # tools/list，并校验注解齐不齐
  http_check.py call <tool> '<json>'       # 单条 tools/call，人读文本 + 关键字段
  http_check.py demo <apk路径>             # 一条完整链路 + 逐步计时（真机样本回归用）

服务端默认 http://127.0.0.1:8732/mcp；设了 APK_INDEX_MCP_TOKEN 时用同名环境变量带上。
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

URL = os.environ.get("APK_INDEX_URL", "http://127.0.0.1:8732/mcp").rstrip("/")
TOKEN = (os.environ.get("APK_INDEX_MCP_TOKEN")
         or os.environ.get("APK_INDEX_TOKEN") or "").strip()
PROTOCOL = "2025-06-18"
_id = [0]
_sid = [None]


def rpc(method: str, params: dict | None = None, notify: bool = False):
    _id[0] += 1
    body = {"jsonrpc": "2.0", "method": method, "params": params or {}}
    if not notify:
        body["id"] = _id[0]
    hdr = {"Content-Type": "application/json",
           "Accept": "application/json, text/event-stream",
           "MCP-Protocol-Version": PROTOCOL}
    if TOKEN:
        hdr["Authorization"] = "Bearer " + TOKEN
    if _sid[0]:
        hdr["Mcp-Session-Id"] = _sid[0]
    req = urllib.request.Request(URL, data=json.dumps(body).encode(), headers=hdr,
                                method="POST")
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            raw, code = r.read(), r.status
            if notify:
                return code, None
            _sid[0] = r.headers.get("Mcp-Session-Id") or _sid[0]
    except urllib.error.HTTPError as e:
        raw, code = e.read(), e.code
        if notify:
            return code, None
    dt = (time.perf_counter() - t0) * 1000
    txt = raw.decode("utf-8", "replace")
    if txt.lstrip().startswith("event:") or "data: " in txt[:40]:
        txt = "".join(l[6:] for l in txt.splitlines() if l.startswith("data: "))
    try:
        obj = json.loads(txt)
    except json.JSONDecodeError:
        obj = {"_raw": txt[:400]}
    return (code, obj), dt


def get_health() -> int:
    with urllib.request.urlopen(URL, timeout=15) as r:
        print(r.status, r.read().decode("utf-8", "replace"))
    return 0


def check_list() -> int:
    rpc("initialize", {"protocolVersion": PROTOCOL,
                       "clientInfo": {"name": "http_check", "version": "1"},
                       "capabilities": {}})
    (_c, obj), _dt = rpc("tools/list")
    tools = obj["result"]["tools"]
    miss_ann = [t["name"] for t in tools if not t.get("annotations")]
    miss_sch = [t["name"] for t in tools if not t.get("outputSchema")]
    dest = sorted(t["name"] for t in tools
                  if (t.get("annotations") or {}).get("destructiveHint"))
    print(f"tools={len(tools)}  缺注解={miss_ann}  缺 outputSchema={miss_sch}")
    print(f"destructive={dest}  （应当只有 unload）")
    return 1 if (miss_ann or miss_sch or dest != ["unload"]) else 0


def show(name: str, env: dict) -> None:
    ok = env.get("ok")
    ms = env.get("elapsedMs")
    head = f"{name:<16} ok={str(ok):<5} total={env.get('total')}"
    if ms is not None:
        head += f" {float(ms):.0f}ms"
    print(head + ("" if ok else "  code=%s %s" % (env.get("code"),
                                                   str(env.get("message"))[:90])))
    if not ok:
        print("                 建议:", str(env.get("suggestion"))[:110])


def call(name: str, args: dict, *, quiet: bool = True) -> dict:
    (code, obj), dt = rpc("tools/call", {"name": name, "arguments": args})
    if "error" in (obj or {}):
        print(f"{name:<16} HTTP {code} JSON-RPC {obj['error']}")
        return {"ok": False}
    res = obj["result"]
    env = res.get("structuredContent") or {}
    show(name, {**env, "elapsedMs": env.get("elapsedMs") or round(dt, 1)})
    if not quiet:
        for c in res.get("content") or []:
            if c.get("type") == "text":
                print("\n".join("                 " + l for l in
                                (c.get("text") or "").splitlines()[:14]))
    return env


def demo(path: str) -> int:
    rpc("initialize", {"protocolVersion": PROTOCOL,
                       "clientInfo": {"name": "http_check", "version": "1"},
                       "capabilities": {}})
    env = call("loadApk", {"path": path, "force": True})
    items = env.get("items") or [{}]
    sid = env.get("sessionId")
    pkg = ((env.get("manifestBrief") or {}).get("packageName")
           or items[0].get("packageName") or "")
    if not sid:
        return 1
    print("                 包=%s 类=%s 体积=%s" % (items[0].get("packageName"),
                                                   items[0].get("classes"),
                                               items[0].get("indexBytes")))
    call("stats", {"sessionId": sid})
    call("checkPacker", {"sessionId": sid})
    sc = call("searchClasses", {"sessionId": sid, "query": "Activity",
                                "kind": "regex", "limit": 5})
    cands = [i.get("binaryName") or i.get("className") or "" for i in sc.get("items") or []]
    tgt = next((c for c in cands if c), "")
    print("                 候选:", cands[:3])
    if tgt:
        call("listMembers", {"sessionId": sid, "class": tgt, "limit": 8})
        dc = call("decompile", {"sessionId": sid, "target": tgt})
        it = (dc.get("items") or [{}])[0]
        print("                 引擎=%s 权威=%s 降级=%s 行数=%s"
              % (it.get("engine"), it.get("authoritative"), it.get("degraded"),
                 it.get("lines")))
        for c in it.get("chain") or []:
            print("                 降级原因:", str(c)[:120])
        ms = call("matchSignature", {"sessionId": sid, "packagePrefix": pkg or "",
                                      "namePattern": "get.*|on.*", "limit": 3})
        for m in (ms.get("items") or [])[:3]:
            print("                 命中:", (m.get("smali") or m.get("name") or "")[:100])
        xr = call("xref", {"sessionId": sid, "method": tgt, "direction": "callers",
                           "depth": 1, "limit": 5})
        for x in (xr.get("items") or [])[:5]:
            print("                 caller:", str(x)[:110])
    call("unload", {"sessionId": sid})
    return 0


def main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else "health"
    if cmd == "health":
        return get_health()
    if cmd == "list":
        return check_list()
    if cmd == "call":
        rpc("initialize", {"protocolVersion": PROTOCOL,
                           "clientInfo": {"name": "http_check", "version": "1"},
                           "capabilities": {}})
        args = json.loads(argv[3]) if len(argv) > 3 else {}
        call(argv[2], args, quiet=False)
        return 0
    if cmd == "demo":
        return demo(argv[2] if len(argv) > 2 else "fixtures/demo-v1.apk")
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
