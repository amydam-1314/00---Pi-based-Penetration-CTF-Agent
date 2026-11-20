#!/usr/bin/env bash
# tool.sh find <keyword> — 在工作区检索现成脚本/工具（按文件名与内容）
BASE="/mnt/d/2026/pi-ctf"
case "$1" in
  find)
    kw="${2:-}"
    echo "[tool.sh] search '$kw' in $BASE"
    find "$BASE" -maxdepth 3 -type f \( -name "*.py" -o -name "*.sh" -o -name "*.md" \) 2>/dev/null | while read -r f; do
      case "$f" in */_shared/tool.sh) continue;; esac
      if echo "$f" | grep -qi "$kw" || grep -qil -- "$kw" "$f" 2>/dev/null; then echo "  hit: ${f#$BASE/}"; fi
    done | head -40
    ;;
  *) echo "usage: tool.sh find <keyword>"; exit 2;;
esac
