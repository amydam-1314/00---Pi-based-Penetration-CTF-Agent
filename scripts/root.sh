#!/usr/bin/env bash
# 项目根/数据根定位（与 ~/.pi/agent/policies/roots.ts 同规则、同优先级、同报错口径）
#   source <项目根>/_shared/root.sh
# 优先级：CTF_PROJECT_ROOT > ctf.project.json 标记 > 目录特征（_shared/gate_db.py | ctf-boards/）
# 相对引用不默认相对 cwd：本脚本只负责发现根，并导出绝对路径。
set -uo pipefail

_ctf_marker_ok() {  # 目录里有合法标记
  local f="$1/ctf.project.json"
  [ -f "$f" ] || return 1
  grep -q '"kind"[[:space:]]*:[[:space:]]*"ctf-project"' "$f" 2>/dev/null
}

_ctf_feature_ok() { # 目录特征（兼容发现）：需成套，单有 ctf-boards/ 不算
  local d="$1"
  [ -f "$d/_shared/gate_db.py" ] && return 0
  [ -d "$d/ctf-boards" ] && [ -d "$d/_shared" ] && return 0
  return 1
}

_ctf_scan() { # 输出 "绝对路径<TAB>marker|feature"
  local d="$1"
  for _ in 1 2 3 4 5 6; do
    if _ctf_marker_ok "$d"; then printf '%s\tmarker\n' "$d"; return 0; fi
    if _ctf_feature_ok "$d"; then printf '%s\tfeature\n' "$d"; return 0; fi
    local up; up="$(cd "$d/.." 2>/dev/null && pwd)" || return 1
    [ "$up" = "$d" ] && return 1
    d="$up"
  done
  return 1
}

_enable_fail() { echo "[root.sh] $1" >&2; }

# env.json 的 projectRoot（与 roots.ts 同优先级：env.json > 环境变量 > 发现）
_ctf_env_json_root() {
  # 输出单行: <projectRoot><TAB><boardsRoot>；读不到就 return 1
  local f="" cand
  for cand in \
    "${PI_CODING_AGENT_DIR:-}/env.json" \
    "${PI_CODING_AGENT_DIR:-}/.pi/agent/env.json" \
    "${HOME:-/root}/.pi/agent/env.json"; do
    [ -n "$cand" ] && [ -f "$cand" ] && { f="$cand"; break; }
  done
  if [ -z "$f" ] && command -v cmd.exe >/dev/null 2>&1; then
    local win_home wsl_home
    win_home="$(cmd.exe /c 'echo %USERPROFILE%' 2>/dev/null | tr -d '\r')"
    wsl_home="$(wslpath -u "$win_home" 2>/dev/null)"
    [ -n "$wsl_home" ] && [ -f "$wsl_home/.pi/agent/env.json" ] && f="$wsl_home/.pi/agent/env.json"
  fi
  [ -n "$f" ] && [ -f "$f" ] || return 1
  command -v python3 >/dev/null 2>&1 || return 1
  python3 - "$f" 2>/dev/null <<'PYEOF'
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding='utf-8'))
    sys.stdout.write(str(d.get('projectRoot') or '') + chr(9) + str(d.get('boardsRoot') or ''))
except Exception:
    pass
PYEOF
}

if [ -z "${CTF_PROJECT_ROOT:-}" ]; then
  _ej="$(_ctf_env_json_root)" || _ej=""
  if [ -n "$_ej" ]; then
    CTF_PROJECT_ROOT="${_ej%%$'\t'*}"
    _ej_boards="${_ej#*$'\t'}"
    [ "$_ej_boards" = "$_ej" ] && _ej_boards=""
    [ -n "$_ej_boards" ] && PI_CTF_BOARDS_ROOT="${PI_CTF_BOARDS_ROOT:-$_ej_boards}"
  fi
fi

if [ -n "${CTF_PROJECT_ROOT:-}" ]; then
  if [ ! -d "$CTF_PROJECT_ROOT" ]; then
    _enable_fail "CTF_PROJECT_ROOT 不存在：$CTF_PROJECT_ROOT（修：改该环境变量，或删掉它让自动发现接管）"
    return 1 2>/dev/null || exit 1
  fi
  CTF_ROOT="$CTF_PROJECT_ROOT"; _CTF_BY="env"
  # 与 roots.ts 同口径的冲突检查：显式配置与"从当前位置向上发现"不一致就报错，不静默取其一
  if disc="$(_ctf_scan "$PWD")"; then
    d_root="${disc%%$'\t'*}"
    if [ "$(cd "$d_root" && pwd)" != "$(cd "$CTF_ROOT" && pwd)" ]; then
      _enable_fail "projectRoot 冲突：CTF_PROJECT_ROOT=$CTF_ROOT，向上发现=$d_root。修：删掉环境变量让发现结果生效，或把它改成 $d_root；二者取一"
      unset CTF_ROOT
      return 1 2>/dev/null || exit 1
    fi
  fi
else
  found="$(_ctf_scan "$PWD")" || {
    _enable_fail "找不到项目根（向上 6 层无 ctf.project.json / _shared/gate_db.py / ctf-boards/）。修：在项目根放 ctf.project.json，或设 CTF_PROJECT_ROOT"
    return 1 2>/dev/null || exit 1
  }
  CTF_ROOT="${found%%$'\t'*}"; _CTF_BY="${found##*$'\t'}"
  if [ "$_CTF_BY" = "feature" ]; then
    echo "[root.sh] 注意：根是按目录特征推断的（$CTF_ROOT），建议在该目录放 ctf.project.json" >&2
  fi
fi

CTF_BOARDS="${PI_CTF_BOARDS_ROOT:-${CTF_BOARDS:-$CTF_ROOT/ctf-boards}}"
if [ ! -d "$CTF_BOARDS" ]; then
  _enable_fail "数据根不存在：$CTF_BOARDS（修：建该目录，或用 PI_CTF_BOARDS_ROOT 指向真实位置）"
  return 1 2>/dev/null || exit 1
fi
export CTF_ROOT CTF_BOARDS
