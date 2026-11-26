#!/bin/bash
# board.sh — 黑板安全追加器（走 SQLite 权威通道，结构自适应：不硬编码契约，键名随当前板子走）
#
# 用法：
#   ./board.sh resume                                开局第一步：结构化交接摘要（推荐，代替 show）
#   ./board.sh handoff                               收口前自检：不达标就 exit 1（缺什么一目了然）
#   ./board.sh show [field]                          查看整板（不截断）或只看某个字段
#   ./board.sh add <field> '<json对象>'               向数组字段追加一个 JSON 对象（键名以你给的片段为准）
#   ./board.sh append <field> '<字符串>'              向数组字段追加一个字符串（如 next）
#   ./board.sh set <field> '<json对象>'               设置对象字段（challenge/params），按键合并；写对象只能用这个
# 便捷封装（键名优先从板子里已有行继承；仅当该数组为空时才用内置默认）：
#   ./board.sh verified <item> [evidence]
#   ./board.sh falsified <tag> <condition> [observed]
#   ./board.sh next <一句话>
#   ./board.sh flag '<flag值>' [basis]               仅拿到真 flag 后（index 未知就先不写）
#   ./board.sh submitted '<值>' <index> [回执]       主 agent 拿到平台回执后补 index
#   ./board.sh angle <角度名> <结果>                 记录已试角度，防下一棒同角度重打
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
# gate_db.py 只走三处：显式环境变量 → CTF_ROOT → 本脚本所在项目根；都没有就报错（不退回盘符路径）
PY="${CTF_GATE_PY:-${CTF_ROOT:-}/_shared/gate_db.py}"
if [ ! -f "$PY" ]; then
  _self_root="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)"
  PY="${_self_root}/_shared/gate_db.py"
fi
[ -f "$PY" ] || { echo "[$(basename "$0")] 定位不到 gate_db.py（设 CTF_GATE_PY 或先 source _shared/root.sh）" >&2; exit 2; }
if [ -z "$DIR" ] || [ -z "$DB" ]; then
  # 通用解析：从 cwd 向上找 .board/（通用）或 .ctf-gate（CTF profile）
  _d="$PWD"; _root=""; _kind=""
  for _i in 1 2 3 4 5 6; do
    if [ -d "$_d/.board" ]; then _root="$_d"; _kind="board"; break; fi
    if [ -e "$_d/.ctf-gate" ]; then _root="$_d"; _kind="ctf"; break; fi
    [ "$_d" = "/" ] && break
    _d="$(dirname "$_d")"
  done
  if [ -n "$_root" ]; then
    if [ "$_kind" = "board" ]; then DIR="$_root/.board"; DB="$DIR/board.sqlite"
    else DIR="$_root/gate"; DB="$DIR/gate.sqlite"; fi
  fi
fi
if [ -z "$DIR" ] || [ -z "$DB" ]; then
  echo "[board] 找不到黑板：当前目录向上无 .board/ 或 .ctf-gate。先 board init，或显式设 CTF_GATE_DIR/CTF_GATE_DB。" >&2
  exit 3
fi
if [ ! -f "$DB" ]; then
  if [ "${1:-}" = "init" ]; then
    mkdir -p "$DIR" || exit 3
    python3 "$PY" --db "$DB" init || exit 3
    echo "[board] initialized $DB"
    exit 0
  fi
  echo "[board] $DB 不存在——先执行 board init（或核对 CTF_GATE_DB）。" >&2
  exit 3
fi

# surface import - 需要读管道；heredoc 已占用 stdin，先把它抓进环境变量
BOARD_STDIN=""
if [ "${1:-}" = "surface" ] && [ "${2:-}" = "import" ] && { [ "${3:-}" = "-" ] || [ -z "${3:-}" ]; }; then
  BOARD_STDIN="$(cat)"
  export BOARD_STDIN
fi

python3 - "$PY" "$DB" "$@" <<'PY'
import json, os, re, subprocess, sys
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

def counts(board):
    return {k: len(v) for k, v in board.items() if isinstance(v, list)}

def save():
    # 2) 合并后 import --rev（rev 不匹配 = 并行冲突 → 失败，不静默覆盖）
    imp = run(["import", "--rev", rev], json.dumps(b, ensure_ascii=False))
    if imp.returncode != 0:
        print(f"[board] import 失败（可能并行写入冲突或底稿过期）: {imp.stderr.strip()[:200]}\n[board] 请重试一次本命令（会重新取快照）。", file=sys.stderr)
        sys.exit(3)
    # 3) 写后读回：任何"写入成功但读不出来"的静默丢数据都在这里爆出来
    chk = run(["snapshot"])
    try:
        after = json.loads(chk.stdout)["board"]
    except Exception:
        print("[board] 写入后回读失败（snapshot 异常）—— 不要继续，先核对 CTF_GATE_DB。", file=sys.stderr); sys.exit(3)
    want, got = counts(b), counts(after)
    lost = {k: (want[k], got.get(k, 0)) for k in want if got.get(k, 0) < want[k]}
    if lost:
        print("[board] ⚠ 写入丢失（库里行数少于提交内容）：" + ", ".join(f"{k}: 提交 {a} → 库里 {c}" for k, (a, c) in lost.items())
              + "\n  可能原因：字段未在 gate_db.canonical_board 白名单里，或行缺主键（tag/flag/name）。"
              + "\n  别再重复同一写入，先把这条报给主 agent。", file=sys.stderr)
        sys.exit(4)
    print(f"[board] 已写入 SQLite 并回读校验通过（rev={rev}→+1；{', '.join(f'{k}={v}' for k, v in got.items())}）", file=sys.stderr)

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
    # 不截断：19KB 的板子切到 4KB，会让下一棒只看到两成（实测踩过）。
    if rest:
        f = rest[0]
        if f not in b:
            print(f"[board] 没有字段 '{f}'。当前字段: {list(b.keys())}", file=sys.stderr); sys.exit(3)
        print(json.dumps(b[f], ensure_ascii=False, indent=2))
    else:
        print(json.dumps(b, ensure_ascii=False, indent=2))
    outline()

elif cmd == "resume":
    def g(xs, k, d=""):
        return str(xs.get(k) or d).strip() if isinstance(xs, dict) else d
    def short(x, n):
        x = str(x or "").replace("\n", " ")
        return x[:n] + ("…" if len(x) > n else "")
    ch = b.get("challenge") if isinstance(b.get("challenge"), dict) else {}
    flags = b.get("flags") or []
    ver = b.get("verified") or []
    fal = b.get("falsified") or []
    ang = b.get("angles") or []
    nxt = b.get("next") or []
    print(f"[resume] 题: {g(ch,'name') or '(未填 challenge.name)'} | 目标: {g(ch,'remote') or '(未填 remote)'}")
    print(f"[resume] 计数: verified {len(ver)} / falsified {len(fal)} / angles {len(ang)} / next {len(nxt)} / flags {len(flags)}")
    print("[resume] --- flag 账本（按 index 判重，同一 index 的值轮换不要再交）---")
    if flags:
        for f in flags:
            print(f"[resume]   {g(f,'flag')}  index={g(f,'index') or '缺失'}  {short(g(f,'basis'),80)}")
    else:
        print("[resume]   （无）")
    print("[resume] --- 全部 verified（✓=有证据 / ·=缺证据，缺的下一棒无法复算）---")
    for v in ver:
        mark = "✓" if g(v, "evidence") else "·"
        print(f"[resume]   {mark} [{g(v,'tag')}] {short(g(v,'fact'),120)}")
        if g(v, "evidence"):
            print(f"[resume]       证据: {short(g(v,'evidence'),140)}")
    print("[resume] --- 全部 falsified（不要原样重打）---")
    for v in fal:
        print(f"[resume]   [{g(v,'tag')}] 条件: {short(g(v,'condition','(缺 condition)'),110)}")
    print("[resume] --- 已试角度（下一棒必须选不同角度）---")
    if ang:
        for a in ang:
            print(f"[resume]   {g(a,'name')} → {short(g(a,'result'),90)}")
    else:
        print("[resume]   （无记录：收口前请用 ./board.sh angle 记录）")
    print("[resume] --- next（上一棒留下的第一动作）---")
    if nxt:
        for i, n in enumerate(nxt):
            print(f"[resume]   {i+1}. {n}")
    else:
        print("[resume]   （空）")
    reds = []
    if not ver: reds.append("verified 为空：这一棒没留下任何已验证事实")
    m = sum(1 for v in ver if not g(v,"evidence"))
    if m: reds.append(f"{m}/{len(ver)} 条 verified 缺 evidence（下一棒无法复算，只能重跑）")
    m = sum(1 for f in flags if not g(f,"index"))
    if m: reds.append(f"{m}/{len(flags)} 条 flag 缺 index（可能重复提交被 duplicate）")
    m = sum(1 for v in fal if not g(v,"condition"))
    if m: reds.append(f"{m}/{len(fal)} 条 falsified 缺 condition（下一棒会原样重打）")
    if not ang: reds.append("angles 为空：下一棒可能重复同一角度")
    if not nxt: reds.append("next 为空：下一棒不知道从哪开工")
    if reds:
        print("[resume] ⚠ 交接红旗:")
        for r in reds: print(f"[resume]   - {r}")
    else:
        print("[resume] ✓ 交接项齐全")
    # 已耗时（闸门在 scaffold 时写 gate/started；没有就跳过）——超预算封存的机器依据
    # CTF_GATE_DIR 本身就是 gate 目录（不是题根），所以按候选列表找，避免 gate/gate/started
    cands = [os.path.join(os.environ.get("CTF_GATE_DIR", ""), "started"),
             os.path.join(os.environ.get("CTF_GATE_DIR", ""), "gate", "started"),
             os.path.join(os.path.dirname(os.environ.get("CTF_GATE_DB", "") or ""), "started"),
             "gate/started"]
    started = next((x for x in cands if x and os.path.isfile(x)), "")
    if started:
        try:
            from datetime import datetime, timezone
            t0 = datetime.fromisoformat(open(started).read().strip().replace("Z", "+00:00"))
            mins = int((datetime.now(timezone.utc) - t0).total_seconds() // 60)
            flag = " ⚠ 已超 90 分钟且无新 flag，按纪律换角度或封存" if mins > 90 and not flags else ""
            print(f"[resume] 已耗时: {mins} 分钟（超 90 分钟仍无新 flag ⇒ 该换角度或封存）{flag}")
        except Exception:
            pass
    print("[resume] 开工: 按 next 第一条动作；收口前跑 ./board.sh handoff 自检。")

elif cmd == "handoff":
    # 收口自检：缺项就 exit 1，迫使上一棒补到可交接。
    ver = b.get("verified") or []
    fal = b.get("falsified") or []
    flags = b.get("flags") or []
    nxt = b.get("next") or []
    ang = b.get("angles") or []
    fails, warns = [], []
    if not ver: fails.append("verified 为空：至少留 1 条已确认事实")
    for v in ver:
        if not str((v or {}).get("evidence") or "").strip():
            fails.append(f"verified[{v.get('tag') if isinstance(v,dict) else '?'}] 缺 evidence")
    for v in fal:
        if not str((v or {}).get("condition") or "").strip():
            fails.append(f"falsified[{v.get('tag') if isinstance(v,dict) else '?'}] 缺 condition")
    no_idx = [f for f in flags if not str((f or {}).get("index") or "").strip()]
    if no_idx:
        warns.append(f"{len(no_idx)} 条 flag 缺 index（仅主 agent 提交后能补，用 ./board.sh submitted <值> <index>）")
    action_re = re.compile(r"(curl|wget|nmap|nc |netcat|ssh|ftp|cat |head |tail |grep |ls |find |python|php|bash|sh |node|/\S+|https?://|mailto:)")
    if not nxt:
        fails.append("next 为空")
    elif not action_re.search(str(nxt[-1])):
        fails.append(f"next 最后一条没有具体动作（要含命令或路径/URL）：{str(nxt[-1])[:80]}")
    if not ang:
        warns.append("angles 为空：无法防止下一棒重复同一角度")
    run_info = run(["run-show"])
    try:
        inst = json.loads(run_info.stdout) if run_info.returncode == 0 else {}
    except Exception:
        inst = {}
    if not str(inst.get("instance_id") or "").strip():
        warns.append("instance_id 未设置：换实例后 scope=instance 的格子不会自动重置（./board.sh run set <id> [addr] [cid] [分钟]）")
    cov = [c for c in (b.get("coverage") or []) if isinstance(c, dict)]
    unc = [c for c in cov if c.get("state") == "untested"]
    if unc:
        sample = ", ".join(f"{c.get('surface')}:{c.get('method','GET')}:{c.get('param','(none)')}" for c in unc[:5])
        fails.append(f"coverage 有 {len(unc)} 个面 untested（先测，或标 blocked 并写 note）：{sample}")
    if fails:
        print("[handoff] ✗ 不达标：" + str(len(fails)) + " 项", file=sys.stderr)
        for x in fails: print("  - " + x, file=sys.stderr)
        for x in warns: print("  ~ " + x, file=sys.stderr)
        print("[handoff] 补齐后再收口；补齐方式: ./board.sh verified <tag> <fact> <evidence> / falsified <tag> <condition> / angle <名> <结果> / next '<动作+判据>'",
              file=sys.stderr)
        sys.exit(1)
    print(f"[handoff] ✓ 可交接（verified {len(ver)} / falsified {len(fal)} / angles {len(ang)} / flags {len(flags)}）")
    for x in warns: print("  ~ " + x)

elif cmd == "surface":     # surface add|set|list <surface> <method> <param> [state] [tag] [note] [scope]
    sub = rest[0] if rest else "list"
    def cov():
        c = b.get("coverage")
        if not isinstance(c, list):
            c = []
            b["coverage"] = c
        return c
    if sub in ("add", "set"):
        if len(rest) < 4:
            print("[board] 用法: surface add|set <surface> <method> <param> [state] [tag] [note] [scope]", file=sys.stderr)
            sys.exit(2)
        surface, method, param = rest[1], (rest[2] or "GET").upper(), rest[3] or "(none)"
        state = rest[4] if len(rest) > 4 and rest[4] else ("untested" if sub == "add" else "clean")
        tag = rest[5] if len(rest) > 5 else ""
        note = rest[6] if len(rest) > 6 else ""
        scope = rest[7] if len(rest) > 7 and rest[7] else "task"
        if state not in ("untested", "clean", "vuln", "blocked"):
            print(f"[board] state 必须是 untested|clean|vuln|blocked，收到 {state!r}", file=sys.stderr); sys.exit(2)
        if scope not in ("task", "instance"):
            print(f"[board] scope 必须是 task|instance，收到 {scope!r}", file=sys.stderr); sys.exit(2)
        rows = cov()
        found = None
        for r in rows:
            if isinstance(r, dict) and (r.get("surface"), (r.get("method") or "GET").upper(),
                                        r.get("param") or "(none)") == (surface, method, param):
                found = r
                break
        if found is None:
            rows.append({"surface": surface, "method": method, "param": param, "state": state,
                         "tag": tag, "note": note, "scope": scope})
        else:
            found.update({"state": state, "tag": tag, "note": note, "scope": scope})
        save()
    elif sub == "import":   # surface import <file|-> [default-method]
        src = rest[1] if len(rest) > 1 else "-"
        default_method = (rest[2] or "GET").upper() if len(rest) > 2 else "GET"
        try:
            text = (os.environ.get("BOARD_STDIN", "") if src == "-"
                    else open(src, encoding="utf-8", errors="replace").read())
        except OSError as e:
            print(f"[board] 读取 {src} 失败: {e}", file=sys.stderr); sys.exit(3)
        rows = cov()
        have = {(r.get("surface"), (r.get("method") or "GET").upper(), r.get("param") or "(none)")
                for r in rows if isinstance(r, dict)}
        added = 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("\t") if p.strip()]
            if len(parts) >= 3:
                surface, method, param = parts[0], parts[1].upper(), parts[2]
            else:
                toks = line.split()
                if len(toks) >= 2 and toks[0].upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TCP", "UDP", "FILE"):
                    surface, method, param = toks[1], toks[0].upper(), "(none)"
                else:
                    surface, method, param = toks[0], default_method, "(none)"
            key = (surface, method, param)
            if key in have:
                continue
            rows.append({"surface": surface, "method": method, "param": param,
                         "state": "untested", "tag": "", "note": "", "scope": "task"})
            have.add(key)
            added += 1
        if added:
            save()
        print(f"[surface] 新增 {added} 行 untested", file=sys.stderr)
    else:
        rows = [r for r in cov() if isinstance(r, dict)]
        if not rows:
            print("[board] coverage 为空：先用 ./board.sh surface add <surface> <method> <param> 登记")
        for r in sorted(rows, key=lambda x: (x.get("surface", ""), x.get("method", ""), x.get("param", ""))):
            print(f"[surface] {r.get('state','?'):9} {r.get('method','GET'):5} {r.get('surface','')} "
                  f"param={r.get('param','(none)')} scope={r.get('scope','task')} "
                  f"tag={r.get('tag','')} {r.get('note','')}")

elif cmd == "uncovered":   # 未测面清单（JSON）
    rows = [r for r in (b.get("coverage") or []) if isinstance(r, dict) and r.get("state") == "untested"]
    print(json.dumps(rows, ensure_ascii=False, indent=2))
    if rows:
        print(f"[uncovered] {len(rows)} 个面未测", file=sys.stderr)

elif cmd == "status":      # 一行摘要（含实例信息）：直接复用 gate_db status
    r = run(["status"])
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    sys.exit(r.returncode)

elif cmd == "run":         # run set <instance_id> [addr] [cid] [minutes] | run show
    sub = rest[0] if rest else "show"
    if sub == "set":
        r = run(["run-set"] + rest[1:])
    elif sub == "show":
        r = run(["run-show"])
    else:
        print("[board] 用法: run set <instance_id> [addr] [cid] [minutes] | run show", file=sys.stderr)
        sys.exit(2)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    sys.exit(r.returncode)

elif cmd == "claim":      # claim <name> [minutes] [--owner X] [--force]
    r = run(["claim"] + rest)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    sys.exit(r.returncode)

elif cmd == "claims":
    r = run(["claim-list"])
    sys.stdout.write(r.stdout)
    sys.exit(r.returncode)

elif cmd == "release":
    r = run(["claim-release"] + rest)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    sys.exit(r.returncode)

elif cmd == "check-close":   # 关闭实例前：所有 flag 必须已有 submitted index
    r = run(["unsubmitted"])
    sys.stdout.write(r.stdout)
    if r.returncode != 0:
        print("[check-close] 有 flag 未确认提交：实例关闭后这些值会作废，先提交并 ./board.sh submitted <值> <index>", file=sys.stderr)
    sys.exit(r.returncode)

elif cmd == "outcome":    # outcome add <kind> <value> [status] [basis]
    if len(rest) < 3 or rest[0] != "add":
        print("[board] 用法: outcome add <kind> <value> [status] [basis]", file=sys.stderr); sys.exit(2)
    kind, value = rest[1], rest[2]
    status = rest[3] if len(rest) > 3 and rest[3] else "open"
    basis = " ".join(rest[4:]) if len(rest) > 4 else ""
    lst = b.get("outcomes")
    if not isinstance(lst, list):
        lst = []
        b["outcomes"] = lst
    found = None
    for o in lst:
        if isinstance(o, dict) and o.get("kind") == kind and o.get("value") == value:
            found = o
            break
    if found is None:
        lst.append({"kind": kind, "value": value, "status": status, "basis": basis})
    else:
        found.update({"status": status, "basis": basis})
    save()

elif cmd == "outcomes":   # outcomes [kind]
    kind = rest[0] if rest else ""
    rows = [o for o in (b.get("outcomes") or []) if isinstance(o, dict)]
    rows += [
        {"kind": "flag", "value": f.get("flag"),
         "status": "submitted" if str(f.get("index") or "").strip() else "open",
         "basis": f.get("basis", "")}
        for f in (b.get("flags") or []) if isinstance(f, dict)
    ]
    if kind:
        rows = [r for r in rows if r["kind"] == kind]
    print(json.dumps(rows, ensure_ascii=False, indent=2))

elif cmd == "search":     # search <query> [limit]
    if not rest:
        print("[board] 用法: search <query> [limit]", file=sys.stderr); sys.exit(2)
    r = run(["search"] + rest)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    sys.exit(r.returncode)

elif cmd == "add":          # add <field> '<json>'
    field, blob = rest[0], rest[1]
    try:
        obj = json.loads(blob)
    except Exception as e:
        print(f"[board] 片段不是合法 JSON: {e}", file=sys.stderr); sys.exit(3)
    arr(field).append(obj); save()

elif cmd == "set":          # set <field> '<json>' —— 对象字段（challenge/params），按键合并
    field, blob = rest[0], rest[1]
    try:
        obj = json.loads(blob)
    except Exception as e:
        print(f"[board] 片段不是合法 JSON: {e}", file=sys.stderr); sys.exit(3)
    if not isinstance(obj, dict):
        print("[board] set 需要 JSON 对象；数组字段请用 add/append", file=sys.stderr); sys.exit(3)
    cur = b.get(field)
    if isinstance(cur, dict):
        merged = dict(cur)
        merged.update({k: v for k, v in obj.items() if v not in (None, "", [], {})})
        b[field] = merged
    elif not cur:
        b[field] = obj
    else:
        print(f"[board] 字段 '{field}' 是 {type(cur).__name__}，不是对象；数组字段请用 add/append", file=sys.stderr); sys.exit(3)
    save()


elif cmd == "append":       # append <field> '<str>'
    field, s = rest[0], rest[1]
    arr(field).append(s); save()

elif cmd == "verified":
    # schema 硬要求：verified 行的身份键是 tag（无 tag 的行会被 canonical_board 静默丢弃）
    keys = inherit("verified", ["tag", "fact", "evidence"])
    obj = {keys[i]: rest[i] for i in range(min(len(rest), len(keys))) if rest[i]}
    if "tag" not in obj:
        print("[board] verified 必须有 tag（第一参数）：./board.sh verified <tag> <fact> <evidence>", file=sys.stderr); sys.exit(3)
    ev_key = "evidence" if "evidence" in keys else (keys[-1] if len(keys) >= 3 else "evidence")
    if not str(obj.get(ev_key) or "").strip():
        print("[board] verified 必须带证据（第三参数）：命令原文/响应片段/证据文件路径，否则下一棒无法复算只能重跑。\n"
              "  例: ./board.sh verified 'oa-login' 'admin/1qaz@WSX 可登录 /admin/login.php' 'gate/evidence/oa-login.txt'",
              file=sys.stderr); sys.exit(3)
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
    v = (rest[0] if rest else "").strip()
    if not v:
        print("[board] flag 值不能为空；没拿到真 flag 前 flags 保持不动。", file=sys.stderr); sys.exit(3)
    # index 只有平台提交回执里才有 → 子 agent 通常不知道。第二参数是数字才当 index（兼容旧写法）。
    idx = ""
    basis_parts = rest[1:]
    if basis_parts and basis_parts[0].strip().isdigit():
        idx = basis_parts[0].strip(); basis_parts = basis_parts[1:]
    obj = {"flag": v}
    if idx: obj["index"] = idx
    if basis_parts:
        obj["basis"] = " ".join(basis_parts).strip()
    arr("flags").append(obj); save()
    if not idx:
        print("[board] 提示：index 未知可先不写 —— 主 agent 提交拿到回执后再补："
              "./board.sh submitted '<值>' <index>\n", file=sys.stderr)

elif cmd == "submitted":
    # 主 agent 拿到平台回执后补 index（同一 flag 值再追加一行，canonical 按值去重、后行覆盖空字段）
    if len(rest) < 2:
        print("[board] 用法: ./board.sh submitted '<flag值>' <index> [回执原文]", file=sys.stderr); sys.exit(3)
    v, idx = rest[0].strip(), rest[1].strip()
    if not idx.isdigit():
        print(f"[board] index 必须是数字（平台 flag_index，从 0 起），收到: {idx!r}", file=sys.stderr); sys.exit(3)
    cur = None
    for f in b.get("flags") or []:
        if isinstance(f, dict) and str(f.get("flag") or "").strip() == v:
            cur = f; break
    if cur is None:
        print(f"[board] flags 里没有这个值，先 ./board.sh flag '<值>' '<basis>' 记下来再加 index：{v}", file=sys.stderr)
        sys.exit(3)
    old_idx = str(cur.get("index") or "").strip()
    if old_idx and old_idx != idx:
        print(f"[board] 该 flag 已记录 index={old_idx}，与本次 {idx} 冲突（同一 index 的不同值是平台轮换，不算新 flag）。"
              f"\n  不覆盖：确认平台回执后手工核对，或换正确 index。", file=sys.stderr); sys.exit(3)
    obj = dict(cur); obj["index"] = idx
    if len(rest) > 2:
        note = " ".join(rest[2:]).strip()
        # append-only 铁律：已有 basis 不可改写，回执只在 basis 为空时落进去
        if note and not str(obj.get("basis") or "").strip():
            obj["basis"] = note
    b["flags"] = [f for f in (b.get("flags") or []) if not (isinstance(f, dict) and str(f.get("flag") or "").strip() == v)]
    b["flags"].append(obj); save()
    print(f"[board] 已补 index={idx}", file=sys.stderr)

elif cmd == "help":
    # 单一来源：闸门刷屏提示直接读这段，避免两份签名各自漂移
    print("resume | handoff | check-close | show [字段] | verified <tag> <fact> <evidence> | falsified <tag> <condition> [observed] | next '<动作+判据>' | flag '<值>' [basis] | submitted '<值>' <index> [回执] | angle <角度名> <结果> | surface add|set|list|import ... | uncovered | status | claim <name> [分钟] [--owner X] [--force] | claims | release <name> | run set|show ... | add <field> '<json>' | append <field> '<str>' | set <field> '<json>'")

elif cmd == "angle":
    if len(rest) < 2:
        print("[board] 用法: ./board.sh angle <角度名> <结果>   例: angle '源码审计' 'PHP 模板无 exec sink'", file=sys.stderr); sys.exit(3)
    name, result = rest[0].strip(), " ".join(rest[1:]).strip()
    from datetime import datetime, timezone
    at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lst = b.get("angles")
    if not isinstance(lst, list): lst = []; b["angles"] = lst
    for a in list(lst):
        if isinstance(a, dict) and a.get("name") == name:
            lst.remove(a)
    lst.append({"name": name, "result": result, "at": at})
    save()

else:
    print(f"[board] 未知命令 {cmd}。可用: resume | handoff | show [field] | add <field> '<json>' | set <field> '<json>' | append <field> '<str>' | verified | falsified | next | flag | angle", file=sys.stderr)
    sys.exit(2)
PY
