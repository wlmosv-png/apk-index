"""apk-index packer / shell detection (加固识别).

Evidence classes, in decreasing reliability:

1. known stub *native* library names inside ``lib/<abi>/``
2. known stub *entry* classes present in the dexes
3. encrypted payloads in assets/ (high-entropy .jar/.dex/.bin names)
4. structural heuristics: the "real" dex carries almost no classes while its
   string pool is abnormally random (typical of a stub + packed payload)

Detection is advisory: ``packed=true`` never blocks indexing, the loaders
still build the index and ``checkPacker`` reports the evidence chain.
"""
from __future__ import annotations

import math
import re
from collections import Counter

NATIVE_SHELLS = {
    "libjiagu": ("360 加固 (jiagu)", "com.stub.StubApp"),
    "libDexHelper": ("爱加密 Ijiami", "com.secneo.apkwrapper.ApplicationWrapper"),
    "libdexjni": ("爱加密 Ijiami", None),
    "libSecShell": ("腾讯乐固 Legu/TBS", "com.tencent.tbs.TBSShell"),
    "libshell": ("腾讯乐固 Legu", None),
    "libshellx": ("腾讯乐固 Legu (64bit)", None),
    "libmobisec": ("梆梆 BangCle", "com.stub.STUB.Application"),
    "libnetmobsec": ("网御 NetMobSec", None),
    "libnesec": ("网御 NetMobSec", None),
    "libsh_shell": ("360 加固", None),
    "libprotect": ("ProtectMyApp", None),
    "libpmp": ("ProtectMyApp", None),
    "libdexguard": ("DexGuard (Collapsar)", None),
    "libTPCore-lib": ("Naga 加固", None),
    "libnaga": ("Naga 加固", None),
    "libexec": ("通用壳 loader", None),
    "libalisec": ("阿里云壳", None),
    "libcrashsdk": ("腾讯 Bugly 壳（常与乐固同现）", None),
    "libstub": ("通用 stub", None),
    "libSXCli": ("深信服", None),
    "libvbox": ("VBox 虚拟化壳", None),
    "libdatatran": ("通用壳 loader", None),
    "libsecneo": ("爱加密 secneo", None),
    "libijiami": ("爱加密 Ijiami", None),
    "libtuprotector": ("图盟 TUProtector", None),
    "libpxrt": ("Pxrt 壳", None),
    "libcryptex": ("Cryptex 壳", None),
}

CLASS_SHELLS = [
    (re.compile(r"^Lcom/stub/StubApp;?$"), "360 加固 com.stub.StubApp"),
    (re.compile(r"^Lcom/stub/STUB/"), "梆梆 com.stub.STUB.*"),
    (re.compile(r"^Lcom/tencent/bugly/stub"), "腾讯 bugly.stub"),
    (re.compile(r"^Lcom/qihoo/util/"), "360 com.qihoo.util"),
    (re.compile(r"^Lcom/qihoo/"), "360 壳相关"),
    (re.compile(r"^Lcom/s/h/e/l/l"), "字面 com.s.h.e.l.l 壳入口"),
    (re.compile(r"^Lcom/billy/android"), "com.billy.android 动态加载"),
    (re.compile(r"^Lcom/secneo/apkwrapper"), "爱加密 secneo.apkwrapper"),
    (re.compile(r"^Lcom/ijiami/"), "爱加密 com.ijiami.*"),
    (re.compile(r"^Lcom/tencent/SecShell"), "腾讯乐固 SecShell"),
    (re.compile(r"^Lcom/tbs/"), "腾讯 TBS 壳"),
    (re.compile(r"^Lcom/bangcle/"), "梆梆"),
    (re.compile(r"^Lcom/naga/"), "Naga"),
    (re.compile(r"^Lcom/google/and/"), "通用 DexHelper 壳"),
    (re.compile(r"^Lcom/wrapper/Stub"), "通用 wrapper stub"),
    (re.compile(r"^Lme/pya/", ), "ProtectYourApp"),
    (re.compile(r"^Lcom/ptrvsapp/"), "PtrvsApp"),
    (re.compile(r"^Lcom/mobilelinux/"), "娜迦 mobilelinux"),
    (re.compile(r"^Lcom/virtualapp/"), "VirtualApp 型壳"),
]

PAYLOAD_NAME_RE = re.compile(
    r"\.(dat|bin|jar|dex|so|enc|b|1|tmp|app|c|d|yag|ajm|kk|ss|res)$", re.I)
SUSPICIOUS_ASSET_RE = re.compile(
    r"(^assets/(?:\(?\d|libexec|dexj|ijiami|sec\.|shell|data\.|lic|tup|nags))"
    r"|(^assets/.{0,16}\.(ajm|yag|kk|tup|nags|dat|bin)$)", re.I)


def _nat_name(name: str) -> str:
    n = name.lower()
    if n.startswith("lib/"):
        n = n.split("/", 2)[-1]
    return n[:-3] if n.endswith(".so") else n


def scan_native_libs(native_libs) -> list[dict]:
    ev = []
    for lib in native_libs or []:
        nm = _nat_name(lib["name"] if isinstance(lib, dict) else str(lib))
        for pat, (vendor, entry) in NATIVE_SHELLS.items():
            if nm.startswith(pat.lower()):
                ev.append({"type": "native", "vendor": vendor,
                           "detail": (lib["name"] if isinstance(lib, dict) else str(lib)),
                           "entryClassHint": entry})
                break
    return ev


def scan_classes(class_descs) -> list[dict]:
    ev = []
    seen = set()
    for d in class_descs or []:
        for rx, label in CLASS_SHELLS:
            if rx.search(d) and label not in seen:
                seen.add(label)
                ev.append({"type": "entryClass", "vendor": label, "detail": d})
    return ev


def scan_assets(names) -> list[dict]:
    ev = []
    for n in names or []:
        if not n.startswith("assets/") and not n.startswith("res/raw/"):
            continue
        if SUSPICIOUS_ASSET_RE.search(n):
            ev.append({"type": "payloadAsset", "vendor": "加密 payload 候选",
                       "detail": n})
    return ev


def string_entropy(strings) -> float:
    """Mean Shannon entropy per string over a sample (dex string pool)."""
    sample = list(strings or [])[:20000]
    if not sample:
        return 0.0
    tot = 0.0
    n = 0
    for s in sample:
        if not s:
            continue
        c = Counter(s)
        ln = len(s)
        tot += -sum((v / ln) * math.log2(v / ln) for v in c.values())
        n += 1
    return tot / n if n else 0.0


def structural_heuristic(total_classes: int, dex_bytes: int, entropy: float) -> dict | None:
    """Few classes + huge dex + random strings == suspicious stub."""
    if not dex_bytes:
        return None
    per_mb = total_classes / (dex_bytes / (1024 * 1024.0))
    if dex_bytes > 1_500_000 and total_classes < 200:
        return {"type": "heuristic", "vendor": "主 dex 类数极少",
                "detail": f"classes={total_classes} dexBytes={dex_bytes} "
                          f"({per_mb:.0f} 类/MB)", "entryClassHint": None}
    if entropy > 6.9 and total_classes < 2000:
        return {"type": "heuristic", "vendor": "字符串熵异常高",
                "detail": f"entropy={entropy:.2f} classes={total_classes}",
                "entryClassHint": None}
    return None


def detect(native_libs=None, class_descs=None, asset_names=None,
           total_classes=0, dex_bytes=0, strings=None,
           application_class=None) -> dict:
    evidence: list[dict] = []
    evidence += scan_native_libs(native_libs)
    evidence += scan_classes(class_descs)
    evidence += scan_assets(asset_names)
    ent = string_entropy(strings)
    h = structural_heuristic(total_classes, dex_bytes, ent)
    if h:
        evidence.append(h)
    if application_class:
        for rx, label in CLASS_SHELLS:
            cd = "L" + application_class.replace(".", "/") + ";"
            if rx.search(cd):
                evidence.append({"type": "applicationClass", "vendor": label,
                                 "detail": application_class})
    strong = [e for e in evidence if e["type"] in ("native", "entryClass",
                                                  "applicationClass")]
    packed = bool(strong) or (h is not None and total_classes < 400)
    vendors = sorted({e["vendor"] for e in evidence})
    rec = _recommendation(packed, vendors, evidence)
    return {"packed": bool(packed), "vendors": vendors,
            "stringEntropy": round(ent, 3), "evidence": evidence[:40],
            "confidence": ("high" if strong else ("medium" if evidence else "none")),
            "recommendation": rec}


def _recommendation(packed, vendors, evidence) -> str:
    if not packed:
        if evidence:
            return "存在壳特征文件但入口类未命中，按静态索引继续；写 hook 前先 " \
                   "searchClasses 验证目标类是否真实存在。"
        return "未检测到加固特征，可直接静态索引并 hook。"
    kinds = {e["type"] for e in evidence}
    if "native" in kinds or "entryClass" in kinds:
        return "已确认加固（%s）。静态 dex 只含壳类，无法直接 hook 业务类。" \
               "两条路：1) 运行期脱壳后把 dump 出的 classes*.dex 用 loadDex 再索引；" \
               "2) 只 hook 壳的入口类（ClassLoader/ApplicationWrapper）做运行期注入，" \
               "配合 probe 返回的 entryClassHint。" % ", ".join(vendors)
    return "可疑壳特征（结构启发式命中，%s）。先 checkPacker 看证据链，" \
           "再用 searchClasses 抽样验证；若真实类不存在则按脱壳流程处理。" % ", ".join(vendors)
