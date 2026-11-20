#!/usr/bin/env bash
# check.sh <stage>   校验 stages.n 为「通过」（部件1）
S="$1"; [ -z "$S" ] && { echo "usage: check.sh <stage>"; exit 3; }
S="${S#stage}"
[ -n "${CTF_GATE_DB:-}" ] && [ -n "${CTF_GATE_DIR:-}" ] || { echo "[check.sh] 缺少 CTF_GATE_DB/CTF_GATE_DIR，拒绝放行" >&2; exit 2; }
GATE="$CTF_GATE_DIR"
DB="$CTF_GATE_DB"
PY="${CTF_GATE_PY:-/mnt/hgfs/pi-share/pi-ctf/_shared/gate_db.py}"
[ -f "$PY" ] || PY="/mnt/d/2026/pi-ctf/_shared/gate_db.py"
[ -f "$PY" ] || PY="D:/2026/pi-ctf/_shared/gate_db.py"
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
