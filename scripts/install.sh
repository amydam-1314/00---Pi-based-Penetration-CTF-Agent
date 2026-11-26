#!/usr/bin/env bash
# pi-ctf-kit 安装检查（不写任何秘密）。用法: bash scripts/install.sh [--check-only]
set -uo pipefail
PKG="$(cd "$(dirname "$0")/.." && pwd)"
AGENT="${PI_CODING_AGENT_DIR:-$HOME/.pi/agent}"
CHECK_ONLY=0; [ "${1:-}" = "--check-only" ] && CHECK_ONLY=1
fail=0; ok() { printf '  ok   %s\n' "$1"; }; bad() { printf '  FAIL %s\n' "$1"; fail=$((fail+1)); }

echo "[1/5] Pi 与 Node"
pi_ver="$(pi --version 2>/dev/null | head -1)"
[ -n "$pi_ver" ] && ok "pi $pi_ver" || bad "找不到 pi（npm i -g @earendil-works/pi-coding-agent）"
node_ver="$(node -v 2>/dev/null)"
case "$node_ver" in v2[2-9]*|v[3-9][0-9]*) ok "node $node_ver";; *) bad "node 需要 >=22（当前 ${node_ver:-无}）";; esac

echo "[2/5] 包结构"
for d in extensions src db agents profiles prompts scripts config; do
  [ -d "$PKG/$d" ] && ok "$d/" || bad "$d/ 缺失"
done
python3 -c "import json;json.load(open('$PKG/package.json'))" 2>/dev/null && ok "package.json 合法" || bad "package.json 非法"

echo "[3/5] 配置（只检查存在性与字段，不打印值）"
CFG="$AGENT/env.json"
if [ -f "$CFG" ]; then
  python3 - "$CFG" <<'PY'
import json,sys
d=json.load(open(sys.argv[1],encoding="utf-8"))
root=d.get("projectRoot")
print("  ok   env.json 可解析；projectRoot =", root or "(未设置)")
ex=(d.get("execution") or {}).get("backend")
print("  ok   execution.backend =", ex or "(未设置 → 按 profile 推断)")
if root:
    import os; print("  ok   projectRoot 存在" if os.path.isdir(root) else "  FAIL projectRoot 不存在："+str(root))
PY
else
  bad "缺 $CFG（复制 config/env.sample.json 并填本机值）"
fi

echo "[4/5] agents / profiles"
[ "$(ls -1 "$PKG"/agents/*.md 2>/dev/null | wc -l)" -gt 0 ] && ok "agents/*.md" || bad "agents 为空"
python3 - "$PKG/profiles" <<'PY'
import json,glob,sys
fs=sorted(glob.glob(sys.argv[1]+"/*.json"))
bad=0
for f in fs:
    try:
        d=json.load(open(f,encoding="utf-8"))
        assert d.get("name") and d.get("marker")
    except Exception as e:
        print("  FAIL", f, e); bad+=1
print(f"  ok   {len(fs)-bad}/{len(fs)} 个 profile 合法")
PY

echo "[5/5] 数据库（schema 版本与迁移）"
TMP="$(mktemp -d)"; 
python3 "$PKG/db/migrate.py" --db "$TMP/gate.sqlite" >/dev/null 2>&1 && ok "migrations 可应用到新库" || bad "migrations 失败"
python3 - "$TMP/gate.sqlite" <<'PY'
import sqlite3,sys
v=sqlite3.connect(sys.argv[1]).execute("PRAGMA user_version;").fetchone()[0]
print(f"  ok   user_version={v}")
PY
rm -rf "$TMP"

echo
if [ "$fail" -gt 0 ]; then echo "有 $fail 项未通过"; exit 1; fi
echo "安装检查通过。安装包：pi install $PKG"
