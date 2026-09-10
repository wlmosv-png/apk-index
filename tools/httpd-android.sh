#!/system/bin/sh
# 在 Android 侧把 apk-index 的 MCP HTTP 服务拉起来：chroot 进一个自带 python3 的
# Linux rootfs（Alpine/Debian 皆可）跑 httpd。
#
# 为什么要这么绕：手机上的终端环境大多会在每条命令结束后按进程组清理后台，
# 服务跟着死。从 Android root 用 setsid 起，实测能跨多次调用长期存活。
# 如果你不需要常驻，直接 python3 -m apkindex（stdio）或 apkindex.cli serve-http 就行。
#
# 幂等：已在跑就先停再起，保证跑的是最新代码。
# 用法:  APK_INDEX_ROOTFS=/path/to/rootfs sh tools/httpd-android.sh [端口]
# 端口默认 8732。

# ---- 三处需要按你的设备改的东西 --------------------------------------------
R="${APK_INDEX_ROOTFS:?请设 APK_INDEX_ROOTFS=<自带 python3 的 rootfs 绝对路径>}"
# 仓库根目录（含 src/apkindex）。默认取本脚本的上一级，随仓库放哪都不用改。
HOME_DIR="${APK_INDEX_HOME:-$(cd "$(dirname "$0")/.." && pwd)}"
LOG="${APK_INDEX_LOG:-/data/local/tmp/httpd-android.log}"
# ---------------------------------------------------------------------------
PORT=${1:-8732}

[ -x "$R/usr/bin/python3" ] || { echo "rootfs 里没有 python3: $R" >&2; exit 1; }
[ -d "$HOME_DIR/src/apkindex" ] || { echo "仓库路径不对: $HOME_DIR" >&2; exit 1; }
mkdir -p "$R/apk" "$R/data/local/tmp" "$R/storage/emulated/0" "$(dirname "$LOG")"

# chroot 里默认看不见宿主路径，客户端填的 APK 路径会撞上"不存在"。
# 把仓库和常用文件目录按【同一路径】绑进去：容器内外指向同一个文件，
# 填路径的人不用换算。/data/local/tmp 与 /storage/emulated/0 是 Android 侧
# root 可读的两处共享位置。
grep -q " $R/apk " /proc/mounts || mount --bind "$HOME_DIR" "$R/apk"
grep -q " $R/data/local/tmp " /proc/mounts || mount --bind /data/local/tmp "$R/data/local/tmp"
grep -q " $R/storage/emulated/0 " /proc/mounts || mount --bind /storage/emulated/0 "$R/storage/emulated/0"

# 按 cmdline 找旧进程（不靠 pidfile，重启后不残留）
PIDS=""
for d in /proc/[0-9]*; do
  [ -r "$d/cmdline" ] || continue
  if tr '\0' ' ' <"$d/cmdline" 2>/dev/null | grep -q "apkindex import httpd"; then
    PIDS="$PIDS ${d#/proc/}"
  fi
done
for p in $PIDS; do kill "$p" 2>/dev/null; done
[ -n "$PIDS" ] && sleep 1

# 缓存位置必须钉死：不设的话解析顺序会随 cwd 漂，索引散在两处，备份和空间统计都失真。
export APK_INDEX_CACHE="${APK_INDEX_CACHE:-$HOME_DIR/.cache}"
HOME=/root setsid chroot "$R" /usr/bin/python3 -c "
import os, sys
os.environ['HOME'] = '/root'
sys.path.insert(0, '/apk/src')
from apkindex import httpd
sys.exit(httpd.serve(host='127.0.0.1', port=$PORT, verbose=True))
" </dev/null >"$LOG" 2>&1 &

# GET /mcp 是健康检查，故意不要 token（启动器要靠它探活），所以鉴权开着也能验。
sleep 2
if [ -n "$APK_INDEX_MCP_TOKEN" ]; then
  HIT=$(curl -s -m 8 -H "Authorization: Bearer $APK_INDEX_MCP_TOKEN" "http://127.0.0.1:$PORT/mcp")
else
  HIT=$(curl -s -m 8 "http://127.0.0.1:$PORT/mcp")
fi
if echo "$HIT" | grep -q apk-index; then
  echo "apk-index MCP 已监听 http://127.0.0.1:$PORT/mcp（鉴权: ${APK_INDEX_MCP_TOKEN:+开}${APK_INDEX_MCP_TOKEN:-关}）"
else
  echo "启动失败，看日志: $LOG" >&2
  tail -5 "$LOG" 2>/dev/null
  exit 1
fi
