#!/usr/bin/env bash
# stage.sh <n> <budget_s> -- <validation command...>
# Writes stages only from an actual bounded probe's exit status; no guessed pass.
set -eu
[ -n "${CTF_GATE_DB:-}" ] && [ -n "${CTF_GATE_DIR:-}" ] || { echo '[stage.sh] missing CTF_GATE_DB/CTF_GATE_DIR' >&2; exit 2; }
# gate_db.py 只走三处：显式环境变量 → CTF_ROOT → 本脚本所在项目根；都没有就报错（不退回盘符路径）
PY="${CTF_GATE_PY:-${CTF_ROOT:-}/_shared/gate_db.py}"
if [ ! -f "$PY" ]; then
  _self_root="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)"
  PY="${_self_root}/_shared/gate_db.py"
fi
[ -f "$PY" ] || { echo "[$(basename "$0")] 定位不到 gate_db.py（设 CTF_GATE_PY 或先 source _shared/root.sh）" >&2; exit 2; }
[ -f "$PY" ] || { echo '[stage.sh] gate_db.py unavailable' >&2; exit 2; }
[ "$#" -ge 4 ] || { echo 'usage: ./stage.sh <n> <budget_s> -- <validation command...>' >&2; exit 2; }
exec python3 "$PY" --db "$CTF_GATE_DB" stage-probe "$@"
