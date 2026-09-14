"""Per-connection tenant context.

apk-index used to keep a single global session registry: every client (HTTP
connection, stdio process, one-shot CLI call) saw and could unload everyone
else's sessions, and two concurrent clients indexing different packages would
race on the same SQLite files.  Fix: every client is now an *owner*, and the
catalog keeps per-owner references to the shared index files.

Owner resolution rules
  * HTTP  : the MCP-Session-Id request header.  The server issues one on
            ``initialize`` (only for well-behaved SDKs that echo it back);
            clients that never send one fall back to ``default``.
  * stdio : one random owner per process (APK_INDEX_OWNER env overrides).
  * CLI   : APK_INDEX_OWNER env, else ``cli``.

Same-package sessions are shared by reference: loading an already-indexed APK
registers the current owner against the existing session instead of building a
second index.  Unload only revokes the current owner's reference; the index
file is deleted only when the last owner lets go.
"""
from __future__ import annotations

import contextvars
import os
import uuid

DEFAULT_OWNER = "default"

_owner: contextvars.ContextVar[str] = contextvars.ContextVar(
    "apk_index_owner", default=DEFAULT_OWNER)


def current_owner() -> str:
    return _owner.get() or DEFAULT_OWNER


def set_owner(owner: str | None) -> str:
    """Bind this thread/context to an owner.  Empty -> default."""
    o = (owner or "").strip() or DEFAULT_OWNER
    _owner.set(o)
    return o


def process_owner() -> str:
    """Stable owner for this process (stdio servers, one-shot CLI)."""
    o = os.environ.get("APK_INDEX_OWNER", "").strip()
    if o:
        return o
    return "proc-" + uuid.uuid4().hex[:8]
