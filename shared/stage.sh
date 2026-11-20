#!/usr/bin/env bash
# stage.sh <n> <budget_s> -- <validation command...>
# Writes stages only from an actual bounded probe's exit status; no guessed pass.
set -eu
[ -n "${CTF_GATE_DB:-}" ] && [ -n "${CTF_GATE_DIR:-}" ] || { echo '[stage.sh] missing CTF_GATE_DB/CTF_GATE_DIR' >&2; exit 2; }
PY="${CTF_GATE_PY:-/mnt/hgfs/pi-share/pi-ctf/_shared/gate_db.py}"
[ -f "$PY" ] || PY="/mnt/d/2026/pi-ctf/_shared/gate_db.py"
[ -f "$PY" ] || PY="D:/2026/pi-ctf/_shared/gate_db.py"
[ -f "$PY" ] || { echo '[stage.sh] gate_db.py unavailable' >&2; exit 2; }
[ "$#" -ge 4 ] || { echo 'usage: ./stage.sh <n> <budget_s> -- <validation command...>' >&2; exit 2; }
exec python3 "$PY" --db "$CTF_GATE_DB" stage-probe "$@"
