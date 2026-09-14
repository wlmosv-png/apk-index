#!/system/bin/sh
# 在 Android 侧把 apk-index 的 MCP HTTP 服务拉起来（chroot 进 Eta 的 Debian rootfs 跑 python3.14）。
# 为什么不在 Linux 工具环境里起：那个环境命令结束后会按进程组清理后台，服务跟着死；
# 从 Android root 用 setsid 起才活得久（实测跨多次工具调用仍存活）。
# 幂等：已在跑就先停再起，保证跑的是最新代码。参数：端口（默认 8732）。
# 2026-09-13：旧实例(fuck.andes/alpine)迁移后改为现实例(io.github.mangi.eta/debian)。
# 注意：/usr/local/bin/python3 是 rootfs 内的绝对符号链接链，宿主视角看是断链，
# 可用性只能在 chroot 内验证，别改回宿主 [ -x ] 检查。
R=/data/data/io.github.mangi.eta/files/terminal/debian/rootfs
LOG=/data/local/tmp/.gen/httpd-android.log
PORT=${1:-8732}
chroot "$R" /usr/local/bin/python3 -c "pass" 2>/dev/null || { echo "Debian rootfs 里 python3 不可用: $R"; exit 1; }
mkdir -p "$R/apk" "$R/data/local/tmp" "$R/storage/emulated/0" /data/local/tmp/.gen
# chroot 里默认看不见宿主路径，客户端会撞上"路径不存在"。把仓库和常用文件目录
# 按同一路径绑进去：/data/local/tmp/x.apk、/storage/emulated/0/Download/x.apk
# 在容器内外指向同一个文件，AI 填的路径才不用猜。
grep -q " $R/apk " /proc/mounts || mount --bind /data/local/tmp/apk-index "$R/apk"
grep -q " $R/data/local/tmp " /proc/mounts || mount --bind /data/local/tmp "$R/data/local/tmp"
grep -q " $R/storage/emulated/0 " /proc/mounts || mount --bind /storage/emulated/0 "$R/storage/emulated/0"
PIDS=""
for d in /proc/[0-9]*; do
  [ -r "$d/cmdline" ] || continue
  if tr '\0' ' ' <"$d/cmdline" 2>/dev/null | grep -q "apkindex import httpd"; then
    PIDS="$PIDS ${d#/proc/}"
  fi
done
for p in $PIDS; do kill "$p" 2>/dev/null; done
[ -n "$PIDS" ] && sleep 1
# 缓存位置必须钉死：不设的话解析顺序会随 cwd 漂（仓库 .cache 与 /root/.cache 都出现过），
# 索引散在两个地方，备份和空间统计都失真。指向宿主路径，chroot 里已绑定同名。
export APK_INDEX_CACHE="${APK_INDEX_CACHE:-/data/local/tmp/apk-index/.cache}"
HOME=/root setsid chroot "$R" /usr/local/bin/python3 -c "
import os, sys
os.environ['HOME'] = '/root'
sys.path.insert(0, '/apk/src')
from apkindex import httpd
sys.exit(httpd.serve(host='127.0.0.1', port=$PORT, verbose=True))
" </dev/null >"$LOG" 2>&1 &
# 健康检查不要 token（故意留的，见 docs/HTTP-DEPLOY.md），所以探活不受鉴权影响。
sleep 2
if [ -n "$APK_INDEX_MCP_TOKEN" ]; then
  AUTHH="Authorization: Bearer $APK_INDEX_MCP_TOKEN"
else
  AUTHH="X-Apk-Index-None: 1"
fi
if curl -s -m 8 "http://127.0.0.1:$PORT/mcp" | grep -q apk-index; then
  echo "apk-index MCP 已监听 http://127.0.0.1:$PORT/mcp"
  # 顺手把鉴权状态打出来：只看环境变量容易起完才发现 token 没传进 chroot。
  MODE=$(curl -s -m 5 -H "$AUTHH" -X POST "http://127.0.0.1:$PORT/mcp" \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
    -o /dev/null -w '%{http_code}' 2>/dev/null)
  case "$MODE" in
    200) [ -n "$APK_INDEX_MCP_TOKEN" ] && echo "tools/list 200 · token 已生效" \
         || echo "tools/list 200 · 无鉴权（仅本机可连）" ;;
    401) echo "tools/list 401 · token 不匹配，检查启动时的那个 shell 环境变量" ;;
    *)   echo "tools/list 异常状态 ${MODE:-无} · 看日志：$LOG" ;;
  esac
else
  echo "起来了但探活失败（curl 可能不存在），手打一次：curl -s http://127.0.0.1:$PORT/mcp"
  tail -5 "$LOG"
fi
exit 0
