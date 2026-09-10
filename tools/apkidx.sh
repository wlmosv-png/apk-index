#!/bin/sh
# apk-index 统一入口（零安装的仓库内跑法）： PYTHONPATH 指到 src，直接 -m apkindex。
# 需要环境里有 python3 >= 3.11（Android 自带的 shell 没有）；
# 装成包之后可以用 `apk-index` 命令，见 bin/apk-index 与 README。
# 用法: apkidx.sh <tools|env|selftest|version|doctor|sessions|pull|load|sid|call> [args...]
set -e

ROOT="${APK_INDEX_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
SRC="$ROOT/src"
PY="${APK_INDEX_PY:-python3}"

if [ ! -d "$SRC/apkindex" ]; then
  echo "apk-index 未部署: 找不到 $SRC/apkindex" >&2
  echo "把仓库放到 $ROOT，或设 APK_INDEX_ROOT=<仓库绝对路径>" >&2
  exit 3
fi

export PYTHONPATH="$SRC${PYTHONPATH:+:$PYTHONPATH}"
# 没显式给就放开常见的两处；越界由服务端 BAD_ARGUMENT 拦住，不静默
export APK_INDEX_ALLOWED_ROOTS="${APK_INDEX_ALLOWED_ROOTS:-/data/local/tmp:/storage/emulated/0/Download:/sdcard/Download}"
export APK_INDEX_CACHE="${APK_INDEX_CACHE:-$ROOT/.cache}"

cmd="${1:-tools}"; shift 2>/dev/null || true

case "$cmd" in
  tools|env|selftest|version)
    cd "$ROOT"; exec "$PY" -m apkindex.server "$cmd" ;;
  call)
    [ -n "${1:-}" ] || { echo "用法: apkidx.sh call <tool> '<json>'" >&2; exit 2; }
    cd "$ROOT"; exec "$PY" -m apkindex.server call "$@" ;;
  doctor|sessions|pull)
    cd "$ROOT"; exec "$PY" -m apkindex.cli "$cmd" "$@" ;;
  load|sid)
    # load 打全信封；sid 只吐 sessionId，方便 SID=$(apkidx.sh sid x.apk) 串命令
    [ -n "${1:-}" ] || { echo "用法: apkidx.sh sid <apk/aar/dex 路径>" >&2; exit 2; }
    cd "$ROOT"
    "$PY" -m apkindex.server call loadApk "{\"path\":\"$1\"}" > /tmp/.apkidx-load.json
    "$PY" -c 'import json,sys
d = json.load(open("/tmp/.apkidx-load.json"))
if not d.get("ok"):
    print(json.dumps(d, ensure_ascii=False)); sys.exit(1)
print(d["sessionId"])'
    ;;
  *)
    echo "未知子命令: $cmd（可用: tools env selftest version call doctor sessions pull load sid）" >&2
    exit 2 ;;
esac
