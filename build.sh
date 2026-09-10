#!/usr/bin/env bash
# 打包 apk-index 分发包：只带源码/测试/文档，剔除缓存、临时目录与真机校准产物。
# 不再把 tar 的报错吞掉——之前 "2>/dev/null || tar ..." 的兜底写法会让第一遍
# 打包静默失败（列了仓库根不存在的 FIXTURES.txt），结果发出去的包里少了
# CHANGELOG.md 还显示 "OK"，这是最坏的一种"构建成功"。
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-dist/apk-index.tar.gz}"
mkdir -p "$(dirname "$OUT")"

ITEMS=(src tools tests fixtures docs bin README.md CHANGELOG.md LICENSE AUTHORS
       build.sh pyproject.toml .gitignore)
MISSING=()
KEEP=()
for it in "${ITEMS[@]}"; do
  if [ -e "$it" ]; then KEEP+=("$it"); else MISSING+=("$it"); fi
done
[ ${#MISSING[@]} -gt 0 ] && echo "跳过（仓库里没有）: ${MISSING[*]}" >&2

tar --exclude='./.calib' --exclude='./.testtmp' --exclude='./.diag*' \
    --exclude='./.cache' --exclude='./dist' \
    --exclude='./tools/patch*.py' --exclude='__pycache__' --exclude='*.pyc' \
    --transform='s,^\./,,;s,^,apk-index/,' \
    -czf "$OUT" "${KEEP[@]}"

echo "OK $OUT"
ls -l "$OUT"
echo "条目数: $(tar tzf "$OUT" | wc -l)"
for must in README.md CHANGELOG.md build.sh src/apkindex/cli.py src/apkindex/server.py \
            src/apkindex/queries.py tests/test_tools.py; do
  if python3 - "$OUT" "$must" <<'PYCHECK'
import sys, tarfile
out, want = sys.argv[1], sys.argv[2]
names = {n.split("/", 1)[1] for n in tarfile.open(out).getnames() if "/" in n}
sys.exit(0 if want in names else 1)
PYCHECK
  then echo "  含 $must"; else echo "  缺 $must" >&2; exit 1; fi
done
