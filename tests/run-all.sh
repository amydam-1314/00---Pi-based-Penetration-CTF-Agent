#!/usr/bin/env bash
# 包内自检：语法 + 单元测试（不碰真实数据）
set -uo pipefail
cd "$(dirname "$0")/.."
NODE="$(command -v node || command -v node.exe || echo /mnt/d/node。js/node.exe)"
fail=0
echo "== 语法检查（src/extensions/tests 全部 .ts/.mjs 可加载）"
shopt -s globstar nullglob 2>/dev/null || true
for f in src/**/*.ts extensions/*.ts; do
  # 只做语法解析（不解析 import，避免 peerDependencies 未安装导致假失败）
  "$NODE" -e "
const fs=require('fs');const {stripTypeScriptTypes}=require('node:module');
try{ stripTypeScriptTypes(fs.readFileSync(process.argv[1],'utf8'),{mode:'transform'}); }
catch(e){ console.error(e.message); process.exit(1); }
" "$f" >/dev/null 2>&1 && echo "  ok   $f" || { echo "  FAIL $f"; fail=$((fail+1)); }
done
echo "== 单元测试"
for t in tests/*.test.mjs; do
  if "$NODE" --experimental-strip-types "$t" >/tmp/kit-test.log 2>&1; then
    echo "  PASS $(basename "$t")  $(grep -c '^PASS' /tmp/kit-test.log) checks"
  else
    echo "  FAIL $(basename "$t")"; sed -n '1,12p' /tmp/kit-test.log | sed 's/^/       /'; fail=$((fail+1))
  fi
done
echo "== 端到端安装集成"
if "$NODE" --experimental-strip-types tests/install.e2e.mjs >/tmp/kit-e2e.log 2>&1; then
  echo "  PASS install.e2e.mjs  $(grep -c '^PASS' /tmp/kit-e2e.log) checks"
else
  echo "  FAIL install.e2e.mjs"; sed -n '1,14p' /tmp/kit-e2e.log | sed 's/^/       /'; fail=$((fail+1))
fi

echo "== 迁移自检"
TMP="$(mktemp -d)"; python3 db/migrate.py --db "$TMP/g.sqlite" >/dev/null 2>&1 && echo "  PASS migrate.py" || { echo "  FAIL migrate.py"; fail=$((fail+1)); }; rm -rf "$TMP"
echo
[ "$fail" -eq 0 ] && echo "✅ 全绿" || echo "✘ $fail 项失败"
exit "$fail"
