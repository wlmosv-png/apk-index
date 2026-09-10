"""apk-index: configuration, error codes, limits, path whitelist.

Everything is read-only with respect to the analysed artefacts. The only thing
this process ever writes is its own SQLite cache under CACHE_DIR.
"""
from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field

NAME = "apk-index"
VERSION = "0.4.4"
PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")

DEFAULT_LIMIT = 50
HARD_LIMIT = 200
MAX_ITEMS_BYTES = 2048          # a single item above this gets summarised
MAX_RESPONSE_BYTES = 32 * 1024  # hard contract cap
MAX_DECOMPILE_LINES = 400


class ErrorCode:
    SESSION_NOT_FOUND = "SESSION_NOT_FOUND"
    PACKED_TARGET = "PACKED_TARGET"
    UNSUPPORTED_FORMAT = "UNSUPPORTED_FORMAT"
    INVALID_PATH = "INVALID_PATH"
    INDEX_STALE = "INDEX_STALE"
    # operational extras (explicit, never silently degraded)
    ADB_UNAVAILABLE = "ADB_UNAVAILABLE"
    DECOMPILER_UNAVAILABLE = "DECOMPILER_UNAVAILABLE"
    BACKEND_UNAVAILABLE = "BACKEND_UNAVAILABLE"
    APK_TOO_LARGE = "APK_TOO_LARGE"
    NOT_FOUND = "NOT_FOUND"
    BAD_ARGUMENT = "BAD_ARGUMENT"
    PARSE_FAILED = "PARSE_FAILED"
    INTERNAL = "INTERNAL"


class ApkIndexError(Exception):
    """Tool-level failure carrying the documented error contract."""

    def __init__(self, code: str, message: str, suggestion: str = "", **extra):
        super().__init__(message)
        self.code = code
        self.message = message
        self.suggestion = suggestion
        self.extra = extra


SUGGESTIONS = {
    ErrorCode.SESSION_NOT_FOUND: "先调用 loadApk/loadAar/loadDex 取得 sessionId，或 sessionList 查看现有会话。",
    ErrorCode.PACKED_TARGET: "目标是加固/壳包。dex 里的类是壳自己的，真实类运行期解密注入。建议运行期 hook 入口类后用 probe 的 runtime 建议，或先用脱壳产物再 loadDex。",
    ErrorCode.UNSUPPORTED_FORMAT: "用 apktool/uncompress_dex/vdexExtract 预提取内嵌 classes.dex 后再 loadDex。",
    ErrorCode.INVALID_PATH: "把目标放到 ALLOWED_ROOTS 声明的目录内，或扩充 ALLOWED_ROOTS（冒号分隔）。",
    ErrorCode.INDEX_STALE: "索引与源文件 sha256 不一致，源文件已被替换。删除会话后重新 load。",
    ErrorCode.ADB_UNAVAILABLE: "安装 platform-tools 或在已 root 的手机上直接给出 /data/app/.../base.apk 路径。",
    ErrorCode.DECOMPILER_UNAVAILABLE: "安装 jadx 并设置 JADX_HOME，或使用 format=smali（内置后端）。",
    ErrorCode.BACKEND_UNAVAILABLE: "pip install androguard 或放置 dexlib2 jar 后重试；默认 builtin 后端通常已足够。",
}


@dataclass
class Settings:
    allowed_roots: tuple
    cache_dir: str
    jadx_home: str
    baksmali_jar: str
    dexlib2_jar: str
    adb_bin: str
    force_backend: str
    keep_going: bool = True

    @staticmethod
    def from_env() -> "Settings":
        # documented names are APK_INDEX_*; the short forms stay accepted so an
        # existing mcp.json keeps working.
        roots = (os.environ.get("APK_INDEX_ALLOWED_ROOTS")
                 or os.environ.get("ALLOWED_ROOTS") or "")
        if not roots:
            roots = os.pathsep.join(
                [
                    os.path.expanduser("~"),
                    "/data/local/tmp",
                    "/sdcard",
                    "/tmp",
                    os.getcwd(),
                ]
            )
        allowed = tuple(
            os.path.realpath(r) for r in roots.split(os.pathsep) if r.strip()
        )
        cache = (os.environ.get("APK_INDEX_CACHE")
                 or os.environ.get("APK_INDEX_CACHE_DIR")
                 or os.environ.get("CACHE_DIR")
                 or os.path.join(os.path.expanduser("~"), ".cache", "apk-index"))
        return Settings(
            allowed_roots=allowed,
            cache_dir=os.path.realpath(os.path.expanduser(cache)),
            jadx_home=(os.environ.get("APK_INDEX_JADX_HOME") or os.environ.get("JADX_HOME", "")),
            baksmali_jar=(os.environ.get("APK_INDEX_BAKSMALI_JAR")
                        or os.environ.get("BAKSMALI_JAR", "")),
            dexlib2_jar=(os.environ.get("APK_INDEX_DEXLIB2_JAR") or os.environ.get("DEXLIB2_JAR", "")),
            adb_bin=os.environ.get("ADB", "adb"),
            force_backend=os.environ.get("APK_INDEX_BACKEND", "").lower(),
        )

    def index_dir(self) -> str:
        p = os.path.join(self.cache_dir, "index")
        os.makedirs(p, exist_ok=True)
        return p

    def staging_dir(self) -> str:
        p = os.path.join(self.cache_dir, "staging")
        os.makedirs(p, exist_ok=True)
        return p


_CFG: Settings | None = None


def settings() -> Settings:
    global _CFG
    if _CFG is None:
        _CFG = Settings.from_env()
    return _CFG


def reset_settings() -> None:
    global _CFG
    _CFG = None


# --------------------------------------------------------------------------
# path whitelist
# --------------------------------------------------------------------------
_WIN = re.compile(r"^[A-Za-z]:[\\/]")


def resolve_input_path(path: str, must_exist: bool = True) -> str:
    """Return a realpath guaranteed to live under ALLOWED_ROOTS."""
    if not path or not isinstance(path, str):
        raise ApkIndexError(ErrorCode.INVALID_PATH, "path 不能为空")
    raw = os.path.expanduser(path.strip())
    roots = settings().allowed_roots
    # device-relative path such as /data/app/~~x==/pkg==/base.apk is fine as-is
    cand = os.path.realpath(raw)
    if not _inside_any(cand, roots):
        # tolerate relative input resolved against each allowed root
        for r in roots:
            alt = os.path.realpath(os.path.join(r, raw.lstrip("/")))
            if (not must_exist or os.path.exists(alt)) and _inside_any(alt, roots):
                cand = alt
                break
    if not _inside_any(cand, roots):
        raise ApkIndexError(
            ErrorCode.INVALID_PATH,
            f"path 超出 ALLOWED_ROOTS: {raw}",
            f"当前白名单: {os.pathsep.join(roots)}",
            path=raw,
        )
    if must_exist and not os.path.exists(cand):
        raise ApkIndexError(ErrorCode.INVALID_PATH, f"路径不存在: {cand}")
    return cand


def _inside_any(cand: str, roots) -> bool:
    if not os.path.isabs(cand):
        return False
    for r in roots:
        if cand == r or cand.startswith(r.rstrip("/") + "/"):
            return True
    return False


def _safe_index_path(self, name: str) -> str:
        base = self.index_dir()
        p = os.path.realpath(os.path.join(base, name))
        if not (p == base or p.startswith(base + os.sep)):
            raise ApkIndexError(ErrorCode.INVALID_PATH, "非法缓存名 %s" % name)
        return p


Settings.safe_index_path = _safe_index_path  # type: ignore[attr-defined]


def safe_cache_path(name: str) -> str:
    p = os.path.join(settings().index_dir(), name)
    if not _inside_any(os.path.realpath(p), (settings().index_dir(),)):
        raise ApkIndexError(ErrorCode.INVALID_PATH, f"非法缓存名 {name}")
    return p


def now_ms() -> float:
    return time.time() * 1000.0


def iso(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts or time.time()))
