"""人读文本渲染 —— tools/call 的 content[].text 走这里。

分工：structuredContent 给机器（完整 envelope）；这里的文本给人看：
一行结论 + 对齐条目 + 一句下一步。

约束（别破坏）：
1. 只加不减：descriptor / smali / reflector 这类"丢了就没法干活"的字段必须出现在
   文本里 —— 有的 MCP 客户端只把 text 喂给模型，不读 structuredContent。
2. 纯 ASCII 分隔 + 中文标签；不用颜色、不用表情。
3. 渲染器绝不抛异常，形状不对就退回通用渲染。
4. 行数与字节都有上限，超了写明"另有 N 条"以及怎么取全量。
"""
from __future__ import annotations

from typing import Any, Callable

MAX_LINES = 220
MAX_BYTES = 24000
IND = " " * 7          # 二级缩进，对齐 "  1  " 这类行号前缀
WIDE = 96


def _dur(res: dict) -> str:
    ms = res.get("elapsedMs")
    if isinstance(ms, (int, float)):
        return "%.0fms" % ms if ms < 1000 else "%.1fs" % (ms / 1000.0)
    return ""


def _sess(res: dict) -> str:
    return res.get("sessionId") or "跨会话"


def _hint(res: dict) -> str:
    h = (res.get("hint") or "").strip()
    if h.startswith("耗时 "):
        h = h.split("；", 1)[-1]
    return h if not h.startswith("0.") else ""


def _head(tool: str, res: dict, summary: str) -> str:
    bits = [tool, _sess(res), summary] + [x for x in (_dur(res),) if x]
    out = "  ".join(b for b in bits if b)
    if res.get("truncated"):
        out += "  ·按 limit 截断"
    return out


def _tail(res: dict) -> list:
    h = _hint(res)
    return ["提示  " + h] if h else []


def _fail(tool: str, res: dict) -> str:
    lines = ["%s 失败  [%s]" % (tool, res.get("code") or "?")]
    if res.get("message"):
        lines.append("  " + str(res["message"]))
    if res.get("suggestion"):
        lines.append("  建议  " + str(res["suggestion"]))
    return "\n".join(lines)


def _clip(text: str) -> str:
    lines = text.split("\n")
    if len(lines) > MAX_LINES:
        lines = lines[:MAX_LINES] + ["…… 文本只留 %d 行（共 %d 行）；全量看 structuredContent。"
                                     % (MAX_LINES, len(lines))]
    out = "\n".join(lines)
    if len(out.encode("utf-8")) > MAX_BYTES:
        out = out.encode("utf-8")[:MAX_BYTES].decode("utf-8", "ignore") + \
            "\n…… 文本按 %dKB 截断；全量看 structuredContent。" % (MAX_BYTES // 1024)
    return out


def _wlen(s: str) -> int:
    """中文标签占两格，按显示宽度补空格才不会错位。"""
    return sum(2 if ord(c) > 0x2E80 else 1 for c in s)


def _pad(s: Any, w: int) -> str:
    s = "" if s is None else str(s)
    gap = w - _wlen(s)
    return s + " " * gap if gap > 0 else s


MAX_ROWS = 60           # 文本视图的行数上限：全量在 structuredContent 里


def _numed(items: list, one: Callable, max_rows: int = MAX_ROWS) -> list:
    """编号渲染，超过 max_rows 行就停下并说明还剩多少。

    没有这层上限时 1200 条命中会把文本视图撑到十几 KB —— 那份文本和
    structuredContent 是同一个响应里的两路输出，谁都不该无限膨胀。
    """
    out = []
    for i, it in enumerate(items[:max_rows], 1):
        out += one(i, it)
    if len(items) > max_rows:
        out.append("…… 文本只列 %d 行，共 %d 条；全量看 structuredContent。"
                   % (max_rows, len(items)))
    return out


def _rest(total: int, shown: int, how: str = "调大 limit") -> str:
    if total > shown:
        return "…… 另有 %d 条未列（共 %d）；%s。" % (total - shown, total, how)
    return ""


def _flat(v: Any, limit: int = 160) -> str:
    if isinstance(v, dict):
        s = "  ".join("%s=%s" % (k, _flat(x, 44)) for k, x in list(v.items())[:8])
    elif isinstance(v, (list, tuple)):
        s = ", ".join(_flat(x, 44) for x in list(v)[:6]) + (" ……" if len(v) > 6 else "")
    else:
        s = str(v)
    s = s.replace("\n", " ")
    return s if len(s) <= limit else s[:limit - 3] + "..."


def _pick(d: dict, keys) -> str:
    for k in keys:
        v = d.get(k)
        if isinstance(v, str) and v:
            return v
    return ""


def _unknown(res: dict, extra=(), limit: int = 6) -> list:
    """把没有专属版式的真实字段收进"其他" —— 不静默丢弃，也不放噪声。

    extra 由调用方补齐自己已经渲染过的键；框架字段（ok/items/hint…）永远不进来。
    """
    skip = {"ok", "tool", "items", "total", "truncated", "hint", "suggestion",
            "sessionId", "sessionIds", "elapsedMs", "code", "message", "maxBytes",
            "warnings"} | set(extra)
    vals = [(k, v) for k, v in res.items() if k not in skip
            and v not in (None, "", [], {}, 0, False)]
    lines = ["  其他"] if vals else []
    for k, v in vals[:limit]:
        lines.append("    " + _pad(k, 17) + _flat(v, 150))
    if len(vals) > limit:
        lines.append("    …另 %d 个字段，见 structuredContent" % (len(vals) - limit))
    return lines


def _member_line(idx: int, m: Any) -> list:
    if not isinstance(m, dict):
        return ["%3d  %s" % (idx, _flat(m, WIDE - 6))]
    # java 形态里已经带修饰符，再拼一次就成了 "public public void ..."
    label = (m.get("java") or m.get("javaSimple") or m.get("name")
             or m.get("descriptor") or "-")
    tag = {"method": "方法", "field": "字段", "constructor": "构造"}.get(str(m.get("kind")), "条目")
    out = ["%3d  [%s] %s" % (idx, tag, label)]
    sm = m.get("smali") or m.get("descriptor") or ""
    if sm:
        out.append(IND + "smali     " + str(sm))
    ref = m.get("reflector")
    if ref and str(ref) != str(sm):
        out.append(IND + "Reflector " + str(ref))
    return [l.rstrip() for l in out]


def _class_line(idx: int, c: Any) -> list:
    if not isinstance(c, dict):
        return ["%3d  %s" % (idx, _flat(c, WIDE - 6))]
    desc = c.get("descriptor") or c.get("classDescriptor") or c.get("binaryName") or ""
    bn = c.get("binaryName") or c.get("javaName") or c.get("simpleName") or "-"
    if len(bn) <= 34:
        lines = ["%3d  %s%s" % (idx, _pad(bn, 36), desc)]
    else:                                   # 名字太长就不硬对齐，描述符换行避免粘连
        lines = ["%3d  %s" % (idx, bn), IND + desc]
    extras = []
    if c.get("superClass"):
        extras.append("父类 " + str(c["superClass"]))
    if c.get("interfaces"):
        extras.append("实现 " + ", ".join(str(x) for x in list(c["interfaces"])[:3]))
    if c.get("kind") and c["kind"] != "class":
        extras.append(str(c["kind"]))
    if c.get("source"):
        extras.append(str(c["source"]))
    if extras:
        lines.append(IND + " · ".join(extras))
    mem = c.get("members") or []
    for m in list(mem)[:3]:
        sm = _pick(m, ("smali", "reflector", "name")) if isinstance(m, dict) else str(m)
        if sm:
            lines.append(IND + "-> " + str(sm))
    if len(mem) > 3:
        lines.append(IND + "-> …… 还有 %d 个成员，listMembers 看全" % (len(mem) - 3))
    return [l.rstrip() for l in lines]


def _r_classes(res: dict) -> str:
    items = res.get("items") or []
    total = res.get("total") or 0
    q = '%s "%s"' % (res.get("kind") or "prefix", res.get("query") or "")
    if res.get("packageFilter"):
        q += "  限包 " + str(res["packageFilter"])
    lines = [_head("searchClasses", res, "命中 %d   %s" % (total, q))]
    if not items:
        lines.append("  这个条件一条都没有。descriptor 前缀要带 L（如 Lcom/a/b）；"
                     "只记得短名就用 kind=regex 自己写 .*。")
    else:
        lines += _numed(items, _class_line)
        r = _rest(total, len(items), "searchClasses 调大 limit")
        if r:
            lines.append(r)
    return "\n".join(lines + _tail(res))


def _r_findimpl(res: dict) -> str:
    items = res.get("items") or []
    a = res.get("anchor") or {}
    lines = [_head("findImplementations", res,
                   "命中 %d   锚点 %s" % (res.get("total") or 0,
                                        a.get("binaryName") or a.get("descriptor") or "-"))]
    lines += _numed(items, _class_line)
    r = _rest(res.get("total") or 0, len(items))
    return "\n".join(lines + ([r] if r else []) + _tail(res))


def _r_members(res: dict) -> str:
    items = res.get("items") or []
    t = res.get("target") or {}
    lines = [_head("listMembers", res, "%s  %s   成员 %d"
                   % (t.get("binaryName") or "-", t.get("descriptor") or "",
                      res.get("total") or 0))]
    if t.get("superClass"):
        s = "  父类 " + str(t["superClass"])
        if t.get("interfaces"):
            s += "  实现 " + ", ".join(str(x) for x in list(t["interfaces"])[:4])
        lines.append(s)
    if not items:
        lines.append("  include/namePattern 下没有任何成员。")
    else:
        lines += _numed(items, _member_line)
    r = _rest(res.get("total") or 0, len(items), "listMembers 调大 limit 或 include=both")
    return "\n".join(lines + ([r] if r else []) + _tail(res))


def _anno_line(annos) -> str:
    return "、".join("%s(%s)" % (a.get("javaName") or a.get("descriptor"),
                                 a.get("visibility") or "?")
                    for a in annos[:8]) + (" …共%d" % len(annos) if len(annos) > 8 else "")


def _r_sig(res: dict) -> str:
    items = res.get("items") or []
    sig = res.get("signature") or {}
    cl = sig.get("class") or {}
    n_mem = res.get("total") or 0
    # 以前只印 items：getSignature 不带 member 时 items 是空的，
    # 文本视图就只剩"0 个匹配"，类级四种写法与注解全在 signature 里没出来。
    head = ("%d 个成员" % n_mem) if (cl and sig.get("member")) else (
        "类级签名" if cl else "%d 个匹配" % n_mem)
    lines = [_head(str(res.get("tool") or "getSignature"), res, head)]
    if cl:
        par = sig.get("parent") or {}
        lines.append(IND + _pad("class", 13) + _flat(str(cl.get("javaName") or cl.get("binaryName") or "-"), 130))
        for key in ("reflector", "classForName", "smali"):
            if cl.get(key):
                lines.append(IND + _pad(key, 13) + _flat(str(cl[key]), 170))
        if par:
            ifs = ", ".join(par.get("interfaceNames") or [])
            lines.append(IND + _pad("parent", 13) + _flat(
                "%s  实现 %s" % (par.get("superClass") or "-", ifs or "无"), 170))
        ann = cl.get("annotations") or []
        lines.append(IND + _pad("注解", 13) + (_flat(_anno_line(ann), 200) if ann else "类上无注解（dex 里确实没有）"))
        lines.append(IND + _pad("kotlinDsl", 13) + _flat(str(cl.get("kotlinDsl") or ""), 170))
        lines.append("")
    for m in items:
        f = m.get("forms") if isinstance(m.get("forms"), dict) else m
        lines.append("  %s#%s" % (f.get("owner") or m.get("class") or "-",
                                  f.get("name") or m.get("name") or "-"))
        for key in ("java", "javaSimple", "smali", "reflector"):
            if f.get(key):
                lines.append(IND + _pad(key, 13) + str(f[key]))
        if f.get("paramsDescriptor") is not None or f.get("returnDescriptor"):
            lines.append(IND + _pad("descriptor", 13) + str(f.get("paramsDescriptor") or "")
                         + " -> " + str(f.get("returnDescriptor") or f.get("returnType") or ""))
        mann = m.get("annotations") or []
        if mann:
            lines.append(IND + _pad("注解", 13) + _flat(_anno_line(mann), 200))
        lines.append("")
    if cl and not items and not sig.get("member"):
        lines.append("  没带 member：只回类级。列成员用 listMembers；要方法级四种写法再带 member 调一次。")
    if len(lines) > 60:
        lines = [l for l in lines if l]
    return "\n".join(lines + _tail(res))


def _r_match(res: dict) -> str:
    items = res.get("items") or []
    cond = res.get("conditions") or {}
    active = "  ".join("%s=%s" % (k, v) for k, v in cond.items() if v not in (None, "", [], {}))
    lines = [_head("matchSignature", res, "命中 %d" % (res.get("total") or 0))]
    if active:
        lines.append("  条件(AND)  " + _flat(active, 200))
    if not items:
        lines.append("  没有同时满足全部条件的成员；条件可以减，先只留 namePattern 试试。")
    else:
        lines += _numed(items, _member_line)
    return "\n".join(lines + _tail(res))


def _r_strings(res: dict) -> str:
    items = res.get("items") or []
    lines = [_head("searchByString", res, '字符串 %d 条   %s "%s"'
                   % (res.get("total") or 0, res.get("match") or "contains",
                      res.get("query") or ""))]
    if not items:
        lines.append("  没有这条字符串。注意大小写；模糊匹配可换 match=regex。")
    for i, it in enumerate(items, 1):
        raw = str(it.get("string", ""))
        s = raw if len(raw) <= 72 else raw[:69] + "..."
        lines.append('%3d  "%s"      %s 字符 · %s 个方法引用'
                     % (i, s.replace('"', "'"), it.get("length", len(raw)),
                        it.get("methodCount", len(it.get("methods") or []))))
        mem = it.get("methods") or []
        for m in list(mem)[:3]:
            lines.append(IND + "-> " + str(_pick(m, ("smali", "reflector"))))
        if len(mem) > 3:
            lines.append(IND + "-> …… 还有 %d 个引用方法" % (len(mem) - 3))
    r = _rest(res.get("total") or 0, len(items))
    return "\n".join(lines + ([r] if r else []) + _tail(res))


def _r_xref(res: dict) -> str:
    items = res.get("items") or []
    lines = [_head("xref", res, "%s %d 条" % (res.get("direction") or "callers",
                                              res.get("total") or 0))]
    if not items:
        lines.append("  没有引用边。方法可能只被反射/字符串调用；也可以把 direction 反过来查。")
    for i, it in enumerate(items, 1):
        if not isinstance(it, dict):
            lines.append("%3d  %s" % (i, _flat(it, WIDE - 6)))
            continue
        who = _pick(it, ("caller", "callee", "smali", "reflector", "java", "binaryName", "name"))
        at = it.get("at") if it.get("at") is not None else it.get("offset")
        rest = _flat({k: v for k, v in it.items()
                      if k not in ("caller", "callee", "smali", "reflector", "java",
                                   "name", "binaryName", "at", "offset")}, 70)
        lines.append("%3d  %s%s%s" % (i, who or "-",
                                      ("   @%s" % at) if at is not None else "",
                                      ("      " + rest) if rest else ""))
    r = _rest(res.get("total") or 0, len(items), "xref 调大 limit 或改 depth")
    return "\n".join(lines + ([r] if r else []) + _tail(res))


def _r_decompile(res: dict) -> str:
    # decompile 的正文与引擎信息在 items[0]（envelope 顶层只有 sessionId/hint）；
    # 早先按顶层字段读，结果真实调用永远显示"没有代码正文"。
    it = dict((res.get("items") or [{}])[0]) if isinstance(res.get("items"), list) \
        and res.get("items") else {}
    for k, v in res.items():
        it.setdefault(k, v)
    body = _pick(it, ("code", "text", "source", "output", "java", "smali", "body"))
    lines = [_head("decompile", res, "%s · %s · %s 行"
                   % (it.get("target") or it.get("class") or "-",
                      it.get("format") or "?",
                      it.get("lines") or len(body.split("\n"))))]
    if it.get("engine"):
        lines.append("  引擎      %s%s" % (it["engine"],
                                    "" if it.get("authoritative") else "（非权威，别当反编译结果用）"))
    if it.get("chain"):
        lines.append("  降级链    " + "  ->  ".join(str(x) for x in it["chain"]))
    if it.get("note"):
        lines.append("  说明      " + str(it["note"])[:200])
    if res.get("truncated") or res.get("maxLines"):
        lines.append("  （文本按 maxLines 截；全量在 structuredContent）")
    lines += ["", body.rstrip()] if body else ["  （没有代码正文，看 structuredContent）"]
    return "\n".join(lines)


def _r_stats(res: dict) -> str:
    fp = res.get("fingerprint") or {}
    lines = [_head("stats", res, "包 %s" % (res.get("label") or res.get("pkg")
                                           or fp.get("pkg") or "-"))]
    if res.get("counts"):
        lines.append("  计数    " + _flat(res["counts"], 460))   # 300 会把注解数挤掉
    if res.get("packed") is not None:
        s = "  加固    " + ("是" if res["packed"] else "否")
        if res.get("packerEvidence"):
            s += "   证据 " + _flat(res["packerEvidence"], 120)
        lines.append(s)
    if res.get("index"):
        lines.append("  索引    " + _flat(res["index"], 300))
    for it in res.get("items") or []:
        if isinstance(it, dict):
            lines.append("  dex%-2s  %s  %sB  版本 %s  来源 %s"
                         % (it.get("dexIdx"), _pad(it.get("name"), 16), it.get("size"),
                            it.get("version"), it.get("source") or "-"))
    zh = {"paths": "路径", "deps": "依赖", "splits": "分包",
          "fingerprint": "指纹", "classSourceBreakdown": "类来源"}
    for key in ("paths", "deps", "splits", "fingerprint", "classSourceBreakdown"):
        v = res.get(key)
        if v:
            lines.append("  " + _pad(zh.get(key, key), 13) + _flat(v, 240))
    lines += _unknown(res, tuple(zh) + ("counts", "packed", "packerEvidence",
                                    "index", "label", "pkg"))
    return "\n".join(lines + _tail(res))


def _r_packer(res: dict) -> str:
    lines = [_head("checkPacker", res, "加固 %s   置信 %s"
                   % ("是" if res.get("packed") else "否", res.get("confidence") or "-"))]
    if res.get("vendors"):
        lines.append("  疑似厂商  " + _flat(res["vendors"], 200))
    for it in res.get("items") or []:
        lines.append("  证据      " + _flat(it, 200))
    if res.get("recommendation"):
        lines.append("  建议      " + str(res["recommendation"]))
    lines += _unknown(res, ("vendors", "recommendation", "packed", "confidence"))
    return "\n".join(lines + _tail(res))


def _r_sessions(res: dict) -> str:
    items = res.get("items") or []
    lines = [_head("sessionList", res, "%d 个会话" % (res.get("total") or len(items)))]

    def one(i: int, s: dict) -> list:
        ver = " ".join(x for x in (str(s.get("versionName") or ""),
                                   "(%s)" % s.get("versionCode") if s.get("versionCode") else "") if x)
        src = ", ".join(str(p).rsplit("/", 1)[-1] for p in (s.get("sources") or [])[:2])
        flag = []
        if s.get("packed"):
            flag.append("加固")
        if not s.get("indexAvailable", True):
            flag.append("无索引")
        return ["%3d  %s  %s %s %s %s  索引%sms%s"
                % (i, _pad(s.get("sessionId"), 17), _pad(s.get("kind"), 4),
                   _pad(s.get("pkg") or s.get("label"), 32), _pad(ver, 13),
                   _pad(src, 24), s.get("indexMs"),
                   ("   [" + " ".join(flag) + "]") if flag else "")]
    lines += _numed(items, one)
    return "\n".join(lines + _tail(res))


def _r_diff(res: dict) -> str:
    items = res.get("items") or []
    zh = {"renamed": "改名/漂移", "added": "只在 B", "removed": "只在 A",
          "changed": "成员变化", "same": "相同"}
    lines = [_head("diffSessions", res, "%d 处差异" % (res.get("total") or 0))]
    buckets: dict = {}
    for it in items:
        buckets.setdefault(str(it.get("kind") if isinstance(it, dict) else "?"), []).append(it)
    for kind, its in sorted(buckets.items()):
        lines.append("  %s（%d）" % (zh.get(kind, kind), len(its)))
        for it in its:
            if not isinstance(it, dict):
                lines.append("     " + _flat(it, 100))
                continue
            if kind == "renamed":
                lines.append("     %-42s -> %-42s 相似度 %s"
                             % (it.get("from"), it.get("to"), it.get("score")))
            else:
                lines.append("     " + _flat(it.get("class") or it.get("descriptor") or it, 110))
            for key, lab in (("methodsOnlyInA", "A 独有方法"), ("methodsOnlyInB", "B 独有方法"),
                             ("fieldsOnlyInA", "A 独有字段"), ("fieldsOnlyInB", "B 独有字段")):
                v = it.get(key)
                if v:
                    lines.append("        %s(%d)  %s"
                                 % (lab, len(v), ", ".join(str(x) for x in list(v)[:4])
                                    + (" ……" if len(v) > 4 else "")))
    r = _rest(res.get("total") or 0, len(items))
    return "\n".join(lines + ([r] if r else []) + _tail(res))


def _r_probe(res: dict) -> str:
    items = res.get("items") or []
    lines = [_head("probe", res, "%d 段" % len(items))]
    for it in items:
        if not isinstance(it, dict):
            lines.append("  " + _flat(it, 120))
            continue
        sec, data = it.get("section"), it.get("data")
        if isinstance(data, list):
            lines.append("  %s（%d）" % (sec, len(data)))
            for d in list(data)[:6]:
                lines.append(IND + _flat(d, 110))
            if len(data) > 6:
                lines.append(IND + "…… 另有 %d 条" % (len(data) - 6))
        else:
            lines.append("  " + _pad(str(sec), 16) + _flat(data, 200))
    for s in res.get("nextSteps") or []:
        lines.append("  下一步    " + str(s))
    return "\n".join(lines + _tail(res))


def _r_load(res: dict) -> str:
    tool = str(res.get("tool") or "load")
    lines = [_head(tool, res, "会话 %s   后端 %s" % (res.get("sessionId") or "-",
                                                    res.get("backend") or "-"))]
    if res.get("indexMs") is not None:
        try:
            ms = "%.1fms" % float(res["indexMs"])
        except (TypeError, ValueError):
            ms = str(res["indexMs"])
        lines.append("  索引      %s%s" % (ms, "（命中缓存）" if res.get("cached") else ""))
    if res.get("counts"):
        lines.append("  内容      " + _flat(res["counts"], 300))
    if res.get("packed"):
        lines.append("  加固      是 —— 静态结果可能只是壳，先看 checkPacker 的建议")
    if res.get("sources"):
        lines.append("  来源      " + _flat(res["sources"], 200))
    for key in ("removed", "unloaded", "kept"):
        if res.get(key):
            lines.append("  " + _pad(key, 10) + _flat(res[key], 200))
    lines += _unknown(res, ("backend", "indexMs", "cached", "counts", "packed",
                            "sources", "removed", "unloaded", "kept", "sessionId"))
    return "\n".join(lines + _tail(res))


def _r_generic(res: dict) -> str:
    items = res.get("items")
    lines = [_head(str(res.get("tool") or "result"), res,
                   "%d 条" % (res.get("total") or 0) if isinstance(items, list) else "完成")]
    lines += _unknown(res, limit=12)
    if isinstance(items, list):
        lines += _numed(items, lambda i, it: ["%3d  %s" % (i, _flat(it, WIDE - 6))])
        r = _rest(res.get("total") or 0, len(items))
        if r:
            lines.append(r)
    return "\n".join(lines + _tail(res))


RENDERERS: dict = {
    "searchClasses": _r_classes,
    "findImplementations": _r_findimpl,
    "listMembers": _r_members,
    "getSignature": _r_sig,
    "matchSignature": _r_match,
    "searchByString": _r_strings,
    "xref": _r_xref,
    "decompile": _r_decompile,
    "stats": _r_stats,
    "checkPacker": _r_packer,
    "sessionList": _r_sessions,
    "diffSessions": _r_diff,
    "probe": _r_probe,
    "loadApk": _r_load, "loadAar": _r_load, "loadDex": _r_load, "unload": _r_load,
}


def render(name: str, res: Any) -> str:
    """envelope -> 人读文本。永不抛异常，宁可朴素。"""
    tool = str(name or (res.get("tool") if isinstance(res, dict) else "") or "?")
    if not isinstance(res, dict):
        return _clip(_flat(res, 4000))
    try:
        if not res.get("ok"):
            return _clip(_fail(tool, res))
        return _clip(RENDERERS.get(tool, _r_generic)(res))
    except Exception as exc:                                  # noqa: BLE001
        try:
            return _clip(_r_generic(res) + "\n（渲染降级 %s，数据以 structuredContent 为准）"
                         % type(exc).__name__)
        except Exception:                                     # noqa: BLE001
            return "结果渲染失败，请读 structuredContent。"
