#!/bin/bash
# board.sh — 黑板安全追加器（走 SQLite 权威通道，结构自适应：不硬编码契约，键名随当前板子走）
#
# 用法：
#   ./board.sh show                                  查看当前板 + 各数组长度（开局先看这个）
#   ./board.sh add <field> '<json对象>'               向数组字段追加一个 JSON 对象（键名以你给的片段为准）
#   ./board.sh append <field> '<字符串>'              向数组字段追加一个字符串（如 next）
# 便捷封装（键名优先从板子里已有行继承；仅当该数组为空时才用内置默认）：
#   ./board.sh verified <item> [evidence]
#   ./board.sh falsified <tag> <condition> [observed]
#   ./board.sh next <一句话>
#   ./board.sh flag '<flag值>' [basis]               仅拿到真 flag 后
#
# 原则（防死锁/防丢数据）：
#   1. 全部读写经 gate_db.py（SQLite 权威库）：snapshot 取当前 rev+板 → 内存合并 → import --rev。
#      绝不直接改 BOARD.json 文件——那是 SQLite 的缓存镜像，read 工具每次会用库内容重写它。
#   2. 只追加，从不删改旧行；rev 冲突（并行写）时 import 失败报错，重试一次即可。
#   3. 目标字段不是数组 → 报错退出，不猜结构。
#   4. 板子/环境变量缺失 → 拒绝执行并提示核对路径，不在别处自建假板。
set -u
DIR="${CTF_GATE_DIR:-}"
DB="${CTF_GATE_DB:-}"
PY="${CTF_GATE_PY:-/mnt/hgfs/pi-share/pi-ctf/_shared/gate_db.py}"
[ -f "$PY" ] || PY="/mnt/d/2026/pi-ctf/_shared/gate_db.py"
[ -f "$PY" ] || PY="D:/2026/pi-ctf/_shared/gate_db.py"
if [ -z "$DIR" ] || [ -z "$DB" ]; then
  echo "[board] CTF_GATE_DIR/CTF_GATE_DB 未注入。先跑: echo \$CTF_GATE_DIR 核对；不要在别处自建板子。" >&2
  exit 3
fi
[ -f "$DB" ] || { echo "[board] $DB 不存在——权威库未初始化，拒绝执行。先 echo \$CTF_GATE_DB 核对路径。" >&2; exit 3; }

python3 - "$PY" "$DB" "$@" <<'PY'
import json, subprocess, sys
py, db, args = sys.argv[1], sys.argv[2], sys.argv[3:]

def run(sub, stdin=None):
    return subprocess.run(["python3", py, "--db", db] + sub,
                          input=stdin, capture_output=True, text=True)

# 1) 取 SQLite 权威快照（rev + 全板）
snap = run(["snapshot"])
if snap.returncode != 0:
    print(f"[board] snapshot 失败: {snap.stderr.strip()[:200]} —— 先核对 CTF_GATE_DB 路径，别硬写。", file=sys.stderr)
    sys.exit(3)
try:
    meta = json.loads(snap.stdout)
    rev, b = str(meta["rev"]), meta["board"]
except Exception as e:
    print(f"[board] snapshot 输出异常: {e}", file=sys.stderr); sys.exit(3)

def outline():
    for k, v in b.items():
        if isinstance(v, list):
            print(f"[board] {k}: {len(v)} 行", file=sys.stderr)

def save():
    # 2) 合并后 import --rev（rev 不匹配 = 并行冲突 → 失败，不静默覆盖）
    imp = run(["import", "--rev", rev], json.dumps(b, ensure_ascii=False))
    if imp.returncode != 0:
        print(f"[board] import 失败（可能并行写入冲突或底稿过期）: {imp.stderr.strip()[:200]}\n[board] 请重试一次本命令（会重新取快照）。", file=sys.stderr)
        sys.exit(3)
    print("[board] 已写入 SQLite（rev 已递增）", file=sys.stderr)
    outline()

def arr(field):
    v = b.get(field)
    if not isinstance(v, list):
        print(f"[board] 字段 '{field}' 不存在或不是数组。当前字段: {list(b.keys())} —— 用 add/append 时以实际字段名为准。", file=sys.stderr)
        sys.exit(3)
    return v

def inherit(field, defaults):
    a = arr(field)
    if a and isinstance(a[0], dict):
        return list(a[0].keys())
    return defaults

cmd = args[0] if args else "show"
rest = args[1:]

if cmd == "show":
    print(json.dumps(b, ensure_ascii=False, indent=2)[:4000])
    outline()

elif cmd == "add":          # add <field> '<json>'
    field, blob = rest[0], rest[1]
    try:
        obj = json.loads(blob)
    except Exception as e:
        print(f"[board] 片段不是合法 JSON: {e}", file=sys.stderr); sys.exit(3)
    arr(field).append(obj); save()

elif cmd == "append":       # append <field> '<str>'
    field, s = rest[0], rest[1]
    arr(field).append(s); save()

elif cmd == "verified":
    # schema 硬要求：verified 行的身份键是 tag（无 tag 的行会被 canonical_board 静默丢弃）
    keys = inherit("verified", ["tag", "fact", "evidence"])
    obj = {keys[i]: rest[i] for i in range(min(len(rest), len(keys))) if rest[i]}
    if "tag" not in obj:
        print("[board] verified 必须有 tag（第一参数）：./board.sh verified <tag> <fact> [evidence]", file=sys.stderr); sys.exit(3)
    arr("verified").append(obj); save()

elif cmd == "falsified":
    keys = inherit("falsified", ["tag", "condition", "observed"])
    obj = {keys[i]: rest[i] for i in range(min(len(rest), len(keys))) if rest[i]}
    arr("falsified").append(obj); save()

elif cmd == "next":
    for s in rest:
        if s: arr("next").append(s)
    b["next"] = arr("next")[-5:]
    save()

elif cmd == "flag":
    if not rest or not rest[0]:
        print("[board] flag 值不能为空；没拿到真 flag 前 flags 保持不动。", file=sys.stderr); sys.exit(3)
    # "flag" 是闸门校验器要求的硬键：第一个参数永远是 flag 值，固定落在 "flag" 键；
    # 其余参数按继承键中除 flag 外的顺序填（如 basis）。
    keys = [k for k in inherit("flags", ["flag", "basis"]) if k != "flag"]
    keys.sort(key=lambda k: 0 if k == "basis" else 1)  # 第二参数优先落 basis 键
    obj = {"flag": rest[0]}
    for i, k in enumerate(keys):
        if i + 1 < len(rest) and rest[i + 1]:
            obj[k] = rest[i + 1]
    arr("flags").append(obj); save()

else:
    print(f"[board] 未知命令 {cmd}。可用: show | add <field> '<json>' | append <field> '<str>' | verified | falsified | next | flag", file=sys.stderr)
    sys.exit(2)
PY
