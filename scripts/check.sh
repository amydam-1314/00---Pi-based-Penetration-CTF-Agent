#!/usr/bin/env bash
# check.sh <stage>   校验 stages.n 为「通过」（部件1）
S="$1"; [ -z "$S" ] && { echo "usage: check.sh <stage>"; exit 3; }
S="${S#stage}"
[ -n "${CTF_GATE_DB:-}" ] && [ -n "${CTF_GATE_DIR:-}" ] || { echo "[check.sh] 缺少 CTF_GATE_DB/CTF_GATE_DIR，拒绝放行" >&2; exit 2; }
GATE="$CTF_GATE_DIR"
DB="$CTF_GATE_DB"
# gate_db.py：显式变量 → CTF_ROOT → 脚本所在项目根；都没有就报错（不退回盘符路径）
PY="${CTF_GATE_PY:-${CTF_ROOT:-}/_shared/gate_db.py}"
[ -f "$PY" ] || PY="$(cd "$(dirname "$0")/.." && pwd)/_shared/gate_db.py"
[ -f "$PY" ] || { echo "[check.sh] 定位不到 gate_db.py（设 CTF_GATE_PY 或先 source _shared/root.sh）" >&2; exit 2; }
[ -f "$PY" ] || { echo "[check.sh] gate_db.py 不可用" >&2; exit 2; }
CONTENT="$(python3 "$PY" --db "$DB" stage-get "$S" 2>/dev/null)" || {
  echo "[check.sh] stage${S} 缺失，拒绝放行" >&2; exit 1
}
case "$CONTENT" in
  通过)   echo "[check.sh] stage${S}: 通过"; exit 0 ;;
  不通过) echo "[check.sh] stage${S}: 不通过" >&2; exit 1 ;;
  回退)   echo "[check.sh] stage${S}: 回退" >&2; exit 1 ;;
  *)      echo "[check.sh] stage${S} 内容非法($CONTENT)" >&2; exit 1 ;;
esac
