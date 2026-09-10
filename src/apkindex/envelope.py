"""Return contract: every tool answers with the same envelope.

Success  { ok: true, sessionId, total, items: [...], truncated, hint }
Failure  { ok: false, code, message, suggestion, hint }

Two hard caps are enforced here so no tool can ever flood the caller:
* a single item above MAX_ITEMS_BYTES is replaced by a summary that points at
  the tool which can fetch the full body (usually ``decompile``);
* the serialised response above MAX_RESPONSE_BYTES is trimmed item-by-item and
  flagged ``truncated`` -- the caller must never see a 300KB JSON blob.
"""
from __future__ import annotations

import json
from typing import Any, Iterable

from .config import (DEFAULT_LIMIT, ErrorCode, MAX_ITEMS_BYTES, MAX_RESPONSE_BYTES,
                     SUGGESTIONS, ApkIndexError, HARD_LIMIT)


def clamp_limit(limit: Any, default: int = DEFAULT_LIMIT) -> int:
    """Public limit policy: default 50, hard ceiling 200."""
    if limit is None or limit == "":
        return default
    try:
        n = int(limit)
    except (TypeError, ValueError):
        raise ApkIndexError(ErrorCode.BAD_ARGUMENT, f"limit 不是整数: {limit!r}")
    if n <= 0:
        return default
    return min(n, HARD_LIMIT)


# Losing the signature is never acceptable: that is the whole payload of this
# server.  So oversized items get trimmed by *field* (biggest, least essential
# first) and only then, if still too fat, are they summarised.
PROTECTED_KEYS = ("descriptor", "class", "classDescriptor", "binaryName", "name",
                  "smali", "reflector", "java", "paramsDescriptor",
                  "returnDescriptor", "returnType", "params", "paramCount",
                  "type", "typeDescriptor", "forms", "kind", "string", "score",
                  "from", "to", "how", "sessionId", "target", "signature",
                  "dsl", "hookDsl", "reflectorSnippet", "code", "classText",
                  "members", "modifiers", "matchedOn", "matchedValues",
                 "constructor", "text", "engine", "authoritative",
                 "lines", "returnedLines", "format")


def _summarise(item: Any) -> Any:
    """Shrink an oversized item without dropping its paste-ready signature."""
    if not isinstance(item, dict):
        text = json.dumps(item, ensure_ascii=False, default=str)
        if len(text.encode("utf-8", "replace")) <= MAX_ITEMS_BYTES:
            return item
        return {"_summary": text[:600], "_truncatedItem": True,
                "_howToGet": "decompile(sessionId, target=..., format=\"smali\")"}
    blob = json.dumps(item, ensure_ascii=False, default=str)
    if len(blob.encode("utf-8", "replace")) <= MAX_ITEMS_BYTES:
        return item
    out = dict(item)
    # 先削正文再删别的：元数据（engine/note/chain/authoritative）比正文小得多，
    # 但正文超限时把它们一起丢掉，客户端就只剩下代码、不知道代码是哪来的。
    for key in ("text", "code", "body", "smali", "java", "source"):
        v = out.get(key)
        if isinstance(v, str) and len(v.encode("utf-8", "replace")) > MAX_ITEMS_BYTES:
            keep = max(0, MAX_ITEMS_BYTES - 200)
            out[key] = v[:keep] + "\n…（正文超单条上限已截；调大 maxBytes 或缩小 target）"
    droppable = sorted([k for k in out if k not in PROTECTED_KEYS
                        and not isinstance(out[k], (int, float, bool))],
                       key=lambda k: -len(json.dumps(out[k], ensure_ascii=False,
                                                     default=str)))
    dropped = []
    for key in droppable:
        if len(json.dumps(out, ensure_ascii=False, default=str).encode("utf-8", "replace")) <= MAX_ITEMS_BYTES:
            break
        val = out[key]
        if isinstance(val, str) and len(val) > 160:
            out[key] = val[:160] + "...(截断)"
            dropped.append(key)
        elif isinstance(val, list) and val:
            out[key] = val[:2]
            out[key + "_count"] = len(val)
            dropped.append(key + "[]")
        else:
            out.pop(key, None)
            dropped.append(key)
    text = json.dumps(out, ensure_ascii=False, default=str)
    if len(text.encode("utf-8", "replace")) > MAX_ITEMS_BYTES:      # protected core is huge
        keep = {k: out[k] for k in PROTECTED_KEYS if k in out}
        keep["_omitted"] = f"{len(text.encode('utf-8'))}B -> 保留标识与签名字段"
        keep["_howToGet"] = ("listMembers(namePattern=...) 或 getSignature(member=...) "
                             "逐条取；正文用 decompile(target=..., format=\"smali\")")
        out = keep
    out["_trimmedFields"] = dropped
    return out


def _item_bytes(item: Any) -> int:
    return len(json.dumps(item, ensure_ascii=False, default=str).encode("utf-8", "replace"))


def ok(items: list, *, session_id: str | None = None, total: int | None = None,
       truncated: bool = False, hint: str = "", limit: int | None = None,
       maxBytes: int | None = None, **extra: Any) -> dict:
    """Build a success envelope, clamped to the documented size contract."""
    cleaned = []
    # 单条响应不套"每条上限"：decompile 一次就一条，上限会把 note/chain 这些
    # 解释"代码从哪来"的元数据削掉；整体上限仍由 enforce_budget 兜。
    single = len(items) <= 1
    for it in items:
        if not single and _item_bytes(it) > MAX_ITEMS_BYTES:
            it = _summarise(it)
        cleaned.append(it)
    out: dict[str, Any] = {"ok": True}
    if session_id is not None:
        out["sessionId"] = session_id
    out["total"] = int(total if total is not None else len(cleaned))
    out["items"] = cleaned
    out["truncated"] = bool(truncated or (limit is not None and out["total"] > len(cleaned)))
    if limit is not None:
        out["limit"] = limit
    out["hint"] = hint
    if maxBytes:
        out["maxBytes"] = int(maxBytes)
    for key, val in extra.items():
        if val is not None and val != "" and val != [] and val != {}:
            out[key] = val
    cap = MAX_RESPONSE_BYTES
    mb = out.get("maxBytes")
    if mb:
        try:
            cap = min(cap, max(2048, int(mb)))
        except (TypeError, ValueError):
            pass
    return enforce_budget(out, cap)


_GENERIC_SUGGESTION = "对照 tools/list 里该工具的参数名与取值修正后重试；仍失败请带上 sessionId 与本次入参复现。"


def fail(code: str, message: str, suggestion: str = "", **extra: Any) -> dict:
    # 契约：失败必带下一步。没写建议的分支（枚举、空参）在这里兜底建议。
    # 兜底建议必须真正落到信封里：曾经只赋值给 suggestion，字典读的却是 sug。
    sug = suggestion or SUGGESTIONS.get(code, "") or _GENERIC_SUGGESTION
    out = {"ok": False, "code": code, "message": message, "suggestion": sug,
           # hint 在两种 envelope 里都恒存在，客户端只读一个字段也能拿到下一步动作。
           "hint": sug or message}
    out.update({k: v for k, v in extra.items() if v not in (None, "", [], {})})
    return out


def from_error(exc: Exception) -> dict:
    if isinstance(exc, ApkIndexError):
        return fail(exc.code, exc.message, exc.suggestion, **exc.extra)
    return fail(ErrorCode.INTERNAL, f"{type(exc).__name__}: {exc}",
                "把这一步的入参重发一次（去掉可疑字段），或用 sessionList 确认会话存在。")


def enforce_budget(payload: dict, cap: int = MAX_RESPONSE_BYTES) -> dict:
    """Guarantee the serialised envelope never exceeds ``cap`` bytes."""
    if _json_bytes(payload) <= cap:
        return payload
    items = payload.get("items")
    if not isinstance(items, list):
        # single-blob payloads (decompile text) get sliced instead of dropped
        for key in ("code", "text", "body", "smali", "java"):
            if isinstance(payload.get(key), str):
                room = cap - _json_bytes({k: v for k, v in payload.items()
                                          if k != key}) - 512
                keep = max(0, min(len(payload[key]), room // 4))
                payload[key] = payload[key][:keep]
                payload["truncated"] = True
                payload["hint"] = (payload.get("hint") or "") + \
                    f" [响应超过 {cap}B，正文已截断；decompile 支持按方法/类缩小 target]"
                return payload
        keep_list: list = []
        payload["items"] = keep_list
        payload["truncated"] = True
        return payload
    head = dict(payload)
    head["items"] = []
    base = _json_bytes(head)
    kept: list = []
    used = base
    for it in items:
        cost = _json_bytes(it) + 2
        # 留 400B 给下面那句 [响应上限…] 提示，否则总长会刚好超预算
        if used + cost > cap - 400:
            break
        kept.append(it)
        used += cost
    payload["items"] = kept
    payload["truncated"] = True
    payload["hint"] = (payload.get("hint") or "") + \
        (f" [响应上限 {cap // 1024}KB：只保留前 {len(kept)} 条，"
         f"共 {payload.get('total')} 条命中；缩小 query/limit 或加 scope 再查]")
    if not kept:
        payload["items"] = [fail(ErrorCode.BAD_ARGUMENT, "命中项过大，无法在响应预算内返回",
                                 "缩小 limit 或换更精确的 query。")]
    return payload


def _json_bytes(obj: Any) -> int:
    return len(json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8", "replace"))


def iter_or_items(rows: Iterable) -> list:
    return list(rows)
