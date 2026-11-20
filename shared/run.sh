#!/usr/bin/env bash
# run.sh <tag> <budget_s> -- <cmd...>   预算硬闸门（部件3）
# 只认 ctf-gate 注入的本主会话、本题目 SQLite 路径。
[ -n "${CTF_GATE_DB:-}" ] && [ -n "${CTF_GATE_DIR:-}" ] || { echo "[run.sh] 缺少 CTF_GATE_DB/CTF_GATE_DIR，拒绝执行" >&2; exit 2; }
[ "$#" -ge 4 ] || { echo 'usage: run.sh <tag> <budget_s> -- <cmd...>' >&2; exit 2; }
TAG="$1"; BUDGET="$2"; shift 2
[[ "$TAG" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,100}$ ]] || { echo '[run.sh] invalid tag' >&2; exit 2; }
[ "$1" = "--" ] || { echo '[run.sh] -- required' >&2; exit 2; }
shift
GATE="$CTF_GATE_DIR"
DB="$CTF_GATE_DB"
PY="${CTF_GATE_PY:-/mnt/hgfs/pi-share/pi-ctf/_shared/gate_db.py}"
[ -f "$PY" ] || PY="/mnt/d/2026/pi-ctf/_shared/gate_db.py"
[ -f "$PY" ] || PY="D:/2026/pi-ctf/_shared/gate_db.py"
[ -f "$PY" ] || { echo "[run.sh] gate_db.py 不可用" >&2; exit 2; }
EV="$GATE/evidence"
mkdir -p "$EV" 2>/dev/null
python3 "$PY" --db "$DB" init >/dev/null || exit 2
if COND="$(python3 "$PY" --db "$DB" falsified-get "$TAG" 2>/dev/null)"; then
  echo "[run.sh] tag '$TAG' 已被证伪，拒绝执行（条件: ${COND:-无}）" >&2
  exit 2
else
  QUERY_RC=$?
  [ "$QUERY_RC" -eq 1 ] || { echo '[run.sh] falsified query failed; refused' >&2; exit 2; }
fi
if [ -z "$BUDGET" ] || ! [[ "$BUDGET" =~ ^[0-9]+$ ]] || [ "$BUDGET" -gt 60 ]; then
  echo "[run.sh] budget 非法或超过60s上限" >&2; exit 2
fi
timeout --kill-after=2s "$BUDGET" "$@" > "$EV/$TAG.out" 2>&1
RC=$?
EXCERPT="$(head -c 4000 "$EV/$TAG.out")"
printf '%s\n' "$EXCERPT"
python3 "$PY" --db "$DB" evidence "$TAG" "$EV/$TAG.out" "$RC" "$EXCERPT" >/dev/null || exit 2
if [ $RC -eq 124 ] || [ $RC -eq 137 ]; then
  python3 "$PY" --db "$DB" falsify "$TAG" "timeout:${BUDGET}s" "exit $RC" >/dev/null || exit 2
  echo "[run.sh] 超时，tag '$TAG' 已登记 falsified" >&2
fi
exit $RC
