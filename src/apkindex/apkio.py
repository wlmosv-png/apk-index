"""apk-index artifact I/O: format sniffing, split-APK merging, manifest,
META-INF/Kotlin metadata, native libs, vdex/odex carving.  Read-only.

Nothing in this module ever writes to the input file.  The only writes in the
whole product go to CACHE_DIR (SQLite index + device pull staging).
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import zipfile
from collections import Counter
from dataclasses import dataclass, field

from .config import ApkIndexError, ErrorCode, settings

DEX_RE = re.compile(r"^classes(\d*)\.dex$")
SPLIT_NAME_RE = re.compile(r"^(base|config\.[\w.]+|split_[\w.]+)\.apk$")
VDEX_MAGIC = b"vdex"
ODEX_MAGIC = b"dey\n"
CDX_MAGIC = b"cdx\x00"

KOTLIN_METADATA_RE = re.compile(r"^META-INF/([^/]+)\.kotlin_module$")


# ------------------------------------------------------------------ basics
def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sniff(path: str) -> str:
    """Return apk|aar|jar|dex|odex|vdex|unknown from magic + extension."""
    try:
        with open(path, "rb") as f:
            head = f.read(16)
    except OSError as e:
        raise ApkIndexError(ErrorCode.INVALID_PATH, f"无法读取 {path}: {e}")
    if head[:4] == b"PK\x03\x04":
        ext = os.path.splitext(path)[1].lower()
        if ext == ".aar":
            return "aar"
        if ext in (".apk", ".apks"):
            return "apk"
        if ext == ".jar":
            return "jar"
        # zip without a helpful extension: decide by contents
        try:
            names = set(zipfile.ZipFile(path).namelist())
        except Exception:
            return "unknown"
        if "AndroidManifest.xml" in names and any(DEX_RE.match(n) for n in names):
            return "apk"
        if "classes.jar" in names:
            return "aar"
        return "jar"
    if head[:3] == b"dex":
        return "dex"
    if head[:4] == ODEX_MAGIC:
        return "odex"
    if head[:4] == VDEX_MAGIC:
        return "vdex"
    return "unknown"


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


# ------------------------------------------------------------------- apks
@dataclass
class DexEntry:
    """One dex inside one artifact (zip member or bare file)."""
    origin: str                 # absolute file that carried it
    member: str                 # zip member name, or basename for bare dex
    size: int
    offset_hint: int = 0

    @property
    def label(self) -> str:
        return f"{os.path.basename(self.origin)}::{self.member}"


@dataclass
class ApkBundle:
    """A base APK plus every split that belongs to it."""
    primary: str
    members: list = field(default_factory=list)        # absolute apk paths
    splits: list = field(default_factory=list)
    kind: str = "apk"

    @property
    def all_paths(self) -> list[str]:
        return self.members


def _apk_sibling_split_paths(path: str) -> list[str]:
    d = os.path.dirname(os.path.abspath(path))
    out = []
    try:
        names = sorted(os.listdir(d))
    except OSError:
        return out
    for n in names:
        p = os.path.join(d, n)
        if not os.path.isfile(p) or os.path.realpath(p) == os.path.realpath(path):
            continue
        if SPLIT_NAME_RE.match(n) or n.endswith(".apk"):
            out.append(p)
    return out


def expand_apk_paths(path: str, want_splits: bool = True) -> tuple[list[str], list[str]]:
    """Return ``(base_paths, split_paths)``.

    ``path`` may be a single apk, a directory holding base+split apks, or a
    colon/comma separated list of apks.  Sibling merging only happens for the
    install-layout naming convention (base.apk / config.*.apk / split_*.apk),
    so an unrelated demo.apk never absorbs its neighbours.
    """
    p = os.path.abspath(path)
    if os.path.isdir(p):
        bases, splits = [], []
        for n in sorted(os.listdir(p)):
            if not n.endswith(".apk"):
                continue
            q = os.path.join(p, n)
            (bases if n == "base.apk" else splits).append(q)
        if not bases:                       # un-named dir: first apk is base
            bases, splits = splits[:1], splits[1:]
        return bases, (splits if want_splits else [])
    if re.search(r"[,:]", path):
        parts = [x.strip() for x in re.split(r"[,:]", path) if x.strip()]
        if len(parts) > 1 and all(os.path.isfile(x) for x in parts):
            return parts[:1], parts[1:]
    name = os.path.basename(p)
    if want_splits and SPLIT_NAME_RE.match(name):
        sibs = [q for q in _apk_sibling_split_paths(p)
                if SPLIT_NAME_RE.match(os.path.basename(q))]
        if name == "base.apk":
            return [p], [q for q in sibs if q != p]
        bases = [q for q in sibs if os.path.basename(q) == "base.apk"]
        others = [q for q in sibs if q not in bases and q != p]
        if bases:
            return bases, [p] + others
        return [p], others
    return [p], []


def bundle_dexes(paths: list[str]) -> list[DexEntry]:
    out: list[DexEntry] = []
    for ap in paths:
        try:
            zf = zipfile.ZipFile(ap)
        except zipfile.BadZipFile:
            raise ApkIndexError(ErrorCode.UNSUPPORTED_FORMAT,
                                f"{ap} 不是合法 zip/APK")
        with zf:
            dexes = [(n, zf.getinfo(n).file_size) for n in zf.namelist()
                     if DEX_RE.match(n)]
            dexes.sort(key=lambda kv: (int(kv[0][7:-4] or 1), kv[0]))
            for n, sz in dexes:
                out.append(DexEntry(origin=ap, member=n, size=sz))
    return out


def read_dex_entry(entry: DexEntry) -> bytes:
    with zipfile.ZipFile(entry.origin) as zf:
        return zf.read(entry.member)


# ---------------------------------------------------------- manifest etc
def read_manifest_dict(paths: list[str]) -> dict:
    """Decode the binary AndroidManifest.xml of the base APK (AXML)."""
    from . import axml
    for ap in paths:
        try:
            zf = zipfile.ZipFile(ap)
        except zipfile.BadZipFile:
            continue
        with zf:
            if "AndroidManifest.xml" not in zf.namelist():
                continue
            data = zf.read("AndroidManifest.xml")
            if data[:4] == b"PK\x03\x04":
                continue
            try:
                if data[:2] == b"<?" or data[:1] == b"<":
                    return _manifest_from_text(data)
                return axml.manifest_of(data)
            except Exception as e:
                raise ApkIndexError(ErrorCode.PARSE_FAILED,
                                    f"{ap} AndroidManifest.xml 解析失败: {e}")
    return {}


def _manifest_from_text(data: bytes) -> dict:
    from xml.etree import ElementTree as ET
    root = ET.fromstring(data.decode("utf-8", "replace"))
    A = "{http://schemas.android.com/apk/res/android}"
    out = {"package": root.get("package"), "versionCode": root.get(A + "versionCode"),
           "versionName": root.get(A + "versionName"), "minSdk": None,
           "targetSdk": None, "application": None, "activities": [],
           "services": [], "receivers": [], "providers": [], "permissions": [],
           "usesPermissions": [], "libraries": [], "metaData": {}, "features": []}
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]
        if tag == "uses-sdk":
            out["minSdk"] = el.get(A + "minSdkVersion")
            out["targetSdk"] = el.get(A + "targetSdkVersion")
        elif tag == "application":
            out["application"] = el.get(A + "name")
        elif tag in ("activity", "service", "receiver", "provider"):
            out[tag + "s"].append({"name": el.get(A + "name"), "exported": None,
                                   "permission": None, "process": None,
                                   "enabled": None})
        elif tag == "uses-permission":
            out["usesPermissions"].append(el.get(A + "name"))
        elif tag == "meta-data":
            out["metaData"][el.get(A + "name") or "?"] = el.get(A + "value")
    return out


def zip_infos(paths: list[str]) -> tuple[Counter, Counter, list, list, dict]:
    """One pass over the zips: service files, version files, native libs,
    META-INF entries, kotlin/compose flags."""
    services: Counter = Counter()
    versions: Counter = Counter()
    natives: list = []
    meta_files: list = []
    flags = {"kotlin_metadata": False, "kotlin_modules": [], "compose": False,
             "coroutines": False, "signing_blocks": [], "resource_table": False}
    total_entries = 0
    for ap in paths:
        try:
            zf = zipfile.ZipFile(ap)
        except zipfile.BadZipFile:
            continue
        with zf:
            total_entries += len(zf.namelist())
            for n in zf.namelist():
                if n.startswith("META-INF/services/"):
                    services[n[len("META-INF/services/"):]] += 1
                elif n.startswith("META-INF/") and n.endswith(".version"):
                    versions[n.split("/")[-1]] += 1
                elif KOTLIN_METADATA_RE.match(n):
                    flags["kotlin_metadata"] = True
                    flags["kotlin_modules"].append(KOTLIN_METADATA_RE.match(n).group(1))
                elif n.startswith("META-INF/") and n.endswith((".SF", ".RSA", ".DSA", ".EC")):
                    flags["signing_blocks"].append(n)
                elif n.startswith("lib/") and n.endswith(".so"):
                    parts = n.split("/")
                    abi = parts[1] if len(parts) > 2 else "?"
                    natives.append({"abi": abi, "name": parts[-1],
                                    "size": zf.getinfo(n).file_size,
                                    "origin": os.path.basename(ap)})
                elif "kotlinx/coroutines" in n or n.endswith("DebugProbesKt.bin"):
                    flags["coroutines"] = True
                elif n == "resources.arsc":
                    flags["resource_table"] = True
                elif n.startswith("assets/") and total_entries < 0:      # pragma: no cover
                    pass
    flags["kotlin_modules"] = sorted(set(flags["kotlin_modules"]))[:12]
    flags["signing_blocks"] = sorted(set(flags["signing_blocks"]))[:8]
    return services, versions, natives, meta_files, flags


def compose_detected(paths: list[str], dex_texts: list[bytes] | None = None) -> bool:
    """Compose runtime is a strong hint that $1 / initData$ synthetic classes appear."""
    markers = (b"Landroidx/compose/runtime/Composable;", b"androidx/compose/runtime")
    for blob in dex_texts or []:
        for m in markers:
            if m in blob:
                return True
    return False


# ------------------------------------------------------- odex / vdex / jar
def validate_embedded_dex(data: bytes, at: int) -> bool:
    """Check whether a plausible dex header starts at ``at``."""
    if at + 0x70 > len(data) or data[at:at + 3] != b"dex":
        return False
    try:
        import struct
        (cksum, sig, file_size, hdr_size, endian) = struct.unpack_from("<I20sIII", data, at + 8)
    except Exception:
        return False
    return hdr_size == 0x70 and endian == 0x12345678 and 0x70 < file_size <= (len(data) - at)


def carve_dexes(data: bytes, alignment: int = 4) -> list[bytes]:
    """Best-effort extraction of *full* dex blobs out of a vdex/blob.

    Compact dex (cdx) deltas are NOT reconstructed -- callers that find none
    must surface UNSUPPORTED_FORMAT instead of pretending.
    """
    out: list[bytes] = []
    start = 0
    seen = set()
    while True:
        i = data.find(b"dex\n", start)
        if i < 0:
            break
        if (i % alignment == 0 or True) and validate_embedded_dex(data, i):
            import struct
            fs = struct.unpack_from("<I", data, i + 32)[0]
            blob = data[i:i + fs]
            if sha256_bytes(blob) not in seen:
                seen.add(sha256_bytes(blob))
                out.append(blob)
            start = i + fs
        else:
            start = i + 4
    return out


def vdex_version(data: bytes) -> str:
    try:
        return data[4:8].decode("ascii", "replace").strip("\x00")
    except Exception:
        return "?"


# ------------------------------------------------------------ adb (device)
def adb_bin() -> str:
    return settings().adb_bin or "adb"


def adb(args: list[str], timeout: int = 120) -> str:
    import subprocess
    cmd = [adb_bin()] + args
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise ApkIndexError(
            ErrorCode.ADB_UNAVAILABLE,
            f"找不到 adb（{adb_bin()}）；fromDevice=true 需要 platform-tools。",
            "在已 root 的手机上直接给 /data/app/.../base.apk 路径，或设 ADB=/path/to/adb。")
    except subprocess.TimeoutExpired:
        raise ApkIndexError(ErrorCode.ADB_UNAVAILABLE, f"adb 超时: {' '.join(args)}")
    if p.returncode != 0:
        msg = (p.stderr or p.stdout or "").strip()[:400]
        raise ApkIndexError(ErrorCode.ADB_UNAVAILABLE,
                            f"adb {' '.join(args)} 失败 (rc={p.returncode}): {msg}",
                            "确认设备已连接且授权调试。")
    return p.stdout


def adb_device_apks(package: str) -> list[str]:
    out = adb(["shell", "pm", "path", package])
    paths = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            paths.append(line[len("package:"):])
    if not paths:
        raise ApkIndexError(ErrorCode.NOT_FOUND, f"设备上找不到包 {package} 的 apk 路径")
    return paths


_DUMP_VERSION = re.compile(r"versionName=(\S+)")
_DUMP_CODE = re.compile(r"versionCode=(\d+)")
_DUMP_MIN = re.compile(r"minSdk=(\d+)")
_DUMP_TARGET = re.compile(r"targetSdk=(\d+)")


def adb_package_meta(package: str) -> dict:
    out = adb(["shell", "dumpsys", "package", package], timeout=60)
    head = out[:200000]
    def one(rx):
        m = rx.search(head)
        return m.group(1) if m else None
    return {"pkg": package, "versionName": one(_DUMP_VERSION),
            "versionCode": int(one(_DUMP_CODE)) if one(_DUMP_CODE) else None,
            "minSdk": one(_DUMP_MIN), "targetSdk": one(_DUMP_TARGET)}


def adb_pull(remote_paths: list[str], dest_dir: str) -> list[str]:
    os.makedirs(dest_dir, exist_ok=True)
    got = []
    for r in remote_paths:
        name = r.replace("/", "_").strip("_")
        local = os.path.join(dest_dir, name)
        adb(["pull", r, local], timeout=600)
        if os.path.exists(local):
            got.append(local)
    if not got:
        raise ApkIndexError(ErrorCode.ADB_UNAVAILABLE, "adb pull 没有取回任何文件")
    return got
