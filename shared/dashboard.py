#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CTF 编排仪表盘 v2 — 破军风格。只读扫描黑板/子代理运行，本地 HTTP 展示。

用法: python dashboard.py [port]   (默认 8800，浏览器开 http://localhost:8800)
"""
import http.server, json, os, re, sqlite3, sys, time
from datetime import datetime, timezone
from pathlib import Path

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8800

_ON_POSIX = os.name == "posix"
def _p(win_path: str) -> Path:
    if not _ON_POSIX:
        return Path(win_path)
    m = re.match(r"^([A-Za-z]):[/\\](.*)$", win_path)
    if m:
        return Path(f"/mnt/{m.group(1).lower()}/{m.group(2).replace('\\', '/')}")
    return Path(win_path)

BOARDS_ROOT = _p("D:/2026/pi-ctf/ctf-boards")
# 部署说明：自动取当前用户名的 Temp 目录（原硬编码示例为 pi-subagents-user-<你的用户名>）
RUNS_ROOT   = _p(str(Path("C:/Users") / os.environ.get("USERNAME", os.environ.get("USER", "your-user")) / "AppData/Local/Temp/pi-subagents-user-" + os.environ.get("USERNAME", os.environ.get("USER", "your-user")) / "async-subagent-runs"))
CTF_ROOT    = _p("D:/2026/pi-ctf")

def discover_contests():
    """通用比赛发现：D:/2026/pi-ctf 下任一子目录命中（.ctf-contest 标记 / challs|challenges 目录 /
    challenge-list.md / challenges.json）即视为一个比赛根。返回 [(contest名, 根目录, 题单解析器)]。"""
    contests = []
    if not CTF_ROOT.is_dir(): return contests
    for d in sorted(CTF_ROOT.iterdir()):
        if not d.is_dir() or d.name.startswith("_") or d.name == "ctf-boards": continue
        # 带 .ctf-gate 的是单题目录（可能内含拷贝的 challenges.json），不是比赛根
        if (d / ".ctf-gate").is_file(): continue
        is_contest = ((d / ".ctf-contest").is_file() or (d / "challs").is_dir()
                      or (d / "challenges").is_dir()
                      or (d / "challenge-list.md").is_file())
        # 注意：challenges.json 不作为比赛根证据——它常被拷贝进单题目录（tsecbench 实例）
        if is_contest:
            contests.append(d)
    return contests

def parse_contest_challenges(root: Path):
    """从比赛根解析题单，多格式兼容：md 表格 / challenges.json API 响应。"""
    rows = []
    md = root / "challenge-list.md"
    if md.is_file():
        for line in md.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.match(r"^\|\s*(\d+)\s*\|\s*(\S+)\s*\|\s*(.+?)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(WEEK\d)\s*\|\s*(\w+)\s*\|", line)
            if m:
                rows.append({"cat": m.group(2), "name": m.group(3), "score": int(m.group(4)), "solved": int(m.group(6)) > 0})
    js = root / "challenges.json"
    if not rows and js.is_file():
        try:
            data = json.loads(js.read_text(encoding="utf-8"))
            for c in (data if isinstance(data, list) else []):
                rows.append({"cat": str(c.get("difficulty", "?")),
                             "name": str(c.get("unique_code", "?")) + " " + str(c.get("description", ""))[:24],
                             "score": int(c.get("total_score", 0)),
                             "solved": bool(c.get("is_completed"))})
        except Exception: pass
    return rows

def read_sqlite(db_path):
    out = {"rev": 0, "challenge": {}, "stages": {}, "flags": [], "hypotheses": [],
           "falsified": [], "verified": [], "next": [], "updated": ""}
    try:
        db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2)
        db.row_factory = sqlite3.Row
        def q(sql, *a):
            try: return [dict(r) for r in db.execute(sql, a)]
            except Exception: return []
        m = {r["k"]: r["v"] for r in q("SELECT k,v FROM meta")}
        out["rev"] = int(m.get("rev", 0))
        out["updated"] = m.get("updated", "")
        out["challenge"] = {r["key"]: r["value"] for r in q("SELECT * FROM params WHERE key IN ('name','remote')")}
        for r in q("SELECT * FROM stages"):
            out["stages"][str(r["n"])] = {"state": r["state"], "at": r["at"]}
        out["flags"] = q("SELECT * FROM flags")
        out["hypotheses"] = q("SELECT * FROM hypotheses")
        out["falsified"] = q("SELECT * FROM falsified")
        out["verified"] = q("SELECT * FROM verified")
        out["next"] = [r["text"] for r in q("SELECT text FROM next_steps ORDER BY ord")]
        db.close()
    except Exception:
        pass
    return out

def scan_boards():
    boards = []
    if not BOARDS_ROOT.is_dir(): return boards
    for owner_dir in sorted(BOARDS_ROOT.iterdir()):
        if not owner_dir.is_dir(): continue
        owner = owner_dir / "OWNER.txt"
        owner_id = owner.read_text(encoding="utf-8").strip()[:8] if owner.is_file() else owner_dir.name[:8]
        ch_dir = owner_dir / "challenges"
        if not ch_dir.is_dir(): continue
        for c in sorted(ch_dir.iterdir()):
            if not c.is_dir(): continue
            db = c / "gate.sqlite"
            if not db.is_file(): continue
            data = read_sqlite(db)
            if data["rev"] == 0 and not data["flags"]: continue
            ct = c / "CHALLENGE.txt"
            task_dir = ct.read_text(encoding="utf-8").strip() if ct.is_file() else ""
            m = re.search(r"([a-z0-9-]+)$", task_dir.lower(), re.I)
            boards.append({
                "owner": owner_id, "id": c.name, "task_dir": task_dir,
                "short": m.group(1) if m else c.name[:8], **data,
            })
    return boards

def classify_error(err):
    if not err: return None
    e = str(err)
    for pat, label in [
        (r"refusing to erase", "证据保护"), (r"还没更新黑板", "黑板未更新"),
        (r"Rate limit|429", "429限流"), (r"Insufficient Balance|402|403", "余额耗尽"),
        (r"runner process.*exited", "进程崩溃"), (r"重活必须经", "预算闸"),
        (r"stages\.n", "阶段闸"), (r"timed out|ETIMEDOUT", "网络超时"),
        (r"先 read gate", "未先读板"), (r"Subagent stopped", "手动停止"),
    ]:
        if re.search(pat, e, re.I): return label
    return "其他"

def scan_runs():
    runs = []
    if not RUNS_ROOT.is_dir(): return runs
    for d in RUNS_ROOT.iterdir():
        if not d.is_dir(): continue
        try:
            j = json.loads((d / "status.json").read_text(encoding="utf-8"))
        except Exception:
            continue
        if not j or j.get("mode") != "single": continue
        s = j.get("steps", [{}])[0] if j.get("steps") else {}
        tok = j.get("totalTokens", {})
        started = j.get("startedAt", 0)
        runs.append({
            "id": j.get("runId", d.name)[:8],
            "state": j.get("state", "?"),
            "agent": s.get("agent", "?"),
            "model": (s.get("model") or "?").split("/")[-1],
            "turns": j.get("turnCount", 0),
            "tokens": tok.get("total", 0) if isinstance(tok, dict) else 0,
            "in_tok": tok.get("input", 0) if isinstance(tok, dict) else 0,
            "out_tok": tok.get("output", 0) if isinstance(tok, dict) else 0,
            "error": classify_error(s.get("error")),
            "cwd": (j.get("cwd") or "").replace("\\", "/").rstrip("/").split("/")[-1],
            "started": started,
            "last": j.get("lastActivityAt", 0),
            "duration": max(0, (j.get("lastActivityAt", 0) - started) // 1000),
        })
    runs.sort(key=lambda r: -r["started"])
    return runs

def collect():
    boards = scan_boards()
    runs = scan_runs()
    # 通用多比赛：自动发现全部比赛根，各自解析题单，带比赛名标签
    contests = []
    all_ch = []
    for root in discover_contests():
        chs = parse_contest_challenges(root)
        if not chs: continue
        contests.append({"name": root.name, "total": len(chs),
                         "solved": sum(1 for c in chs if c["solved"]),
                         "score": sum(c["score"] for c in chs if c["solved"])})
        for c in chs:
            c2 = dict(c); c2["contest"] = root.name
            all_ch.append(c2)
    chlist = all_ch

    # 每日 token（按启动日期归桶，全部 run）
    daily = {}
    for r in runs:
        if not r["started"]: continue
        d = datetime.fromtimestamp(r["started"] / 1000).strftime("%m-%d")
        b = daily.setdefault(d, {"in": 0, "out": 0})
        b["in"] += r["in_tok"]; b["out"] += r["out_tok"]
    daily_list = [{"date": k, **v} for k, v in sorted(daily.items())]

    # 模型统计
    models = {}
    for r in runs:
        m = models.setdefault(r["model"], {"runs": 0, "ok": 0, "fail": 0, "tokens": 0})
        m["runs"] += 1; m["tokens"] += r["tokens"]
        if r["state"] == "complete": m["ok"] += 1
        elif r["state"] == "failed": m["fail"] += 1

    # 失败原因
    err_dist = {}
    for r in runs:
        if r["state"] == "failed":
            k = r["error"] or "未知"
            err_dist[k] = err_dist.get(k, 0) + 1

    ok = sum(1 for r in runs if r["state"] == "complete")
    fail = sum(1 for r in runs if r["state"] == "failed")
    active = sum(1 for r in runs if r["state"] == "running")
    solved_cats = {}
    for c in chlist:
        solved_cats.setdefault(c["cat"], [0, 0])
        solved_cats[c["cat"]][1] += 1
        if c["solved"]: solved_cats[c["cat"]][0] += 1

    return {
        "ts": int(time.time()),
        "boards": boards,
        "runs": runs[:120],
        "chlist": chlist,
        "contests": contests,
        "daily": daily_list,
        "models": models,
        "cat_stats": {k: v for k, v in sorted(solved_cats.items())},
        "stats": {
            "total_boards": len(boards),
            "boards_with_flags": sum(1 for b in boards if b["flags"]),
            "total_flags": len({f["flag"] for b in boards for f in b["flags"]}),
            "total_runs": len(runs),
            "ok_runs": ok, "fail_runs": fail, "active_runs": active,
            "total_tokens": sum(r["tokens"] for r in runs),
            "in_tokens": sum(r["in_tok"] for r in runs),
            "out_tokens": sum(r["out_tok"] for r in runs),
            "wasted_tokens": sum(r["tokens"] for r in runs if r["state"] == "failed"),
            "err_dist": err_dist,
            "solved_challs": sum(1 for c in chlist if c["solved"]),
            "total_challs": len(chlist),
            "total_score": sum(c["score"] for c in chlist if c["solved"]),
        },
    }

PAGE = r"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<title>CTF 编排 · 总览</title>
<style>
:root {
  --bg: #09090b; --card: #131316; --border: #26262b; --border-hi: #3a3a41;
  --fg: #fafafa; --fg2: #d4d4d8; --muted: #8b8b93; --dim: #565660;
  --blue: #3b82f6; --emerald: #10b981; --amber: #f59e0b; --red: #ef4444;
  --violet: #8b5cf6; --cyan: #06b6d4; --rose: #f43f5e; --indigo: #6366f1;
  --font: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif;
  --mono: ui-monospace, "Cascadia Code", Consolas, monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font: 13px/1.55 var(--font); background: var(--bg); color: var(--fg2); padding: 22px 26px 60px; max-width: 1480px; margin: 0 auto; }
a { color: inherit; text-decoration: none; }

/* header */
.hdr { display: flex; align-items: baseline; justify-content: space-between; margin-bottom: 18px; }
.hdr h1 { font-size: 17px; font-weight: 600; color: var(--fg); letter-spacing: -0.01em; }
.hdr .sub { font-size: 11px; color: var(--muted); margin-top: 2px; }
.hdr .ts { font-size: 10px; color: var(--dim); font-family: var(--mono); }
.dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; background: var(--blue); animation: pulse 2s infinite; margin-right: 4px; vertical-align: 1px; }
@keyframes pulse { 0%,100% {opacity:1} 50% {opacity:.35} }

/* cards */
.card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; }
.card .chead { display: flex; align-items: center; justify-content: space-between; padding: 11px 14px; border-bottom: 1px solid var(--border); }
.card .chead .t { display: flex; align-items: center; gap: 6px; font-size: 11px; font-weight: 600; color: var(--fg); }
.card .chead .t .ic { color: var(--muted); font-size: 12px; }
.card .chead .r { font-size: 10px; color: var(--muted); }
.card .cbody { padding: 12px 14px; }

/* row 1: stat cards */
.stats { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin-bottom: 10px; }
.stat { padding: 12px 14px 10px; }
.stat .lbl { display: flex; align-items: center; gap: 5px; font-size: 10px; color: var(--muted); margin-bottom: 2px; }
.stat .lbl .ic { font-size: 11px; }
.stat .num { font-size: 24px; font-weight: 700; color: var(--fg); font-family: var(--mono); letter-spacing: -0.02em; }
.stat .num small { font-size: 11px; font-weight: 400; color: var(--muted); font-family: var(--font); }
.stat .subs { display: flex; flex-wrap: wrap; gap: 4px 10px; font-size: 10px; margin-top: 3px; }
.c-blue { color: var(--blue); } .c-em { color: var(--emerald); } .c-am { color: var(--amber); }
.c-red { color: var(--red); } .c-vi { color: var(--violet); } .c-cy { color: var(--cyan); } .c-mu { color: var(--muted); }

/* row2: token chart */
.row2 { display: grid; grid-template-columns: 240px 1fr; gap: 10px; margin-bottom: 10px; }
.tk-total .num { font-size: 26px; font-weight: 700; font-family: var(--mono); color: var(--fg); }
.tk-total .sub { font-size: 10px; color: var(--muted); }
.tbar { margin-bottom: 10px; }
.tbar .r1 { display: flex; justify-content: space-between; font-size: 10px; margin-bottom: 3px; }
.tbar .r1 .v { font-family: var(--mono); font-weight: 600; }
.tbar .track { height: 5px; border-radius: 3px; background: var(--border); overflow: hidden; }
.tbar .fill { height: 100%; border-radius: 3px; transition: width .5s; }
.chart-wrap { display: flex; flex-direction: column; }
.chart-legend { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
.chart-legend .lg { display: flex; gap: 12px; font-size: 9px; color: var(--muted); }
.chart-legend .lg span { display: inline-flex; align-items: center; gap: 4px; }
.chart-legend .sw { width: 8px; height: 8px; border-radius: 2px; display: inline-block; }
.rng { display: flex; gap: 2px; background: var(--border); border-radius: 6px; padding: 2px; }
.rng button { border: 0; background: transparent; color: var(--muted); font-size: 9px; padding: 2px 9px; border-radius: 5px; cursor: pointer; font-family: var(--font); }
.rng button.on { background: var(--bg); color: var(--fg); }
.rng button:hover:not(.on) { color: var(--fg2); }
.bars { display: flex; align-items: flex-end; gap: 3px; height: 170px; padding-top: 4px; }
.bcol { flex: 1; display: flex; flex-direction: column; justify-content: flex-end; height: 100%; min-width: 0; cursor: default; }
.bcol .b { width: 100%; border-radius: 2px 2px 0 0; transition: opacity .15s; min-height: 1px; }
.bcol:hover .b { opacity: .75; }
.bcol .dt { font-size: 8px; color: var(--dim); text-align: center; margin-top: 4px; font-family: var(--mono); white-space: nowrap; overflow: hidden; }
.btip { position: absolute; pointer-events: none; background: #1c1c21; border: 1px solid var(--border-hi); border-radius: 6px; padding: 6px 9px; font-size: 10px; z-index: 9; display: none; box-shadow: 0 4px 16px rgba(0,0,0,.5); }
.btip .d { color: var(--muted); font-size: 9px; margin-bottom: 2px; }
.btip .row { display: flex; justify-content: space-between; gap: 14px; font-family: var(--mono); }

/* row3: activity + flags */
.row3 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 10px; }
.alist { max-height: 300px; overflow-y: auto; }
.alist::-webkit-scrollbar { width: 4px; } .alist::-webkit-scrollbar-thumb { background: var(--border-hi); border-radius: 2px; }
.arow { display: flex; gap: 8px; align-items: flex-start; padding: 7px 0; border-bottom: 1px solid var(--border); }
.arow:last-child { border-bottom: 0; }
.arow .st { width: 14px; text-align: center; font-size: 10px; flex-shrink: 0; margin-top: 1px; }
.arow .mid { flex: 1; min-width: 0; }
.arow .l1 { font-size: 11px; color: var(--fg2); display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
.arow .l1 b { color: var(--fg); font-weight: 600; font-family: var(--mono); font-size: 10px; }
.arow .l2 { font-size: 10px; color: var(--muted); margin-top: 1px; }
.arow .rt { text-align: right; flex-shrink: 0; font-family: var(--mono); font-size: 9px; color: var(--dim); }
.arow .rt .tk { color: var(--muted); }
.badge { display: inline-block; font-size: 9px; padding: 0.5px 7px; border-radius: 8px; border: 1px solid; font-weight: 500; }
.bg-run { background: rgba(59,130,246,.12); border-color: rgba(59,130,246,.3); color: var(--blue); }
.bg-ok { background: rgba(16,185,129,.12); border-color: rgba(16,185,129,.3); color: var(--emerald); }
.bg-fail { background: rgba(239,68,68,.12); border-color: rgba(239,68,68,.3); color: var(--red); }
.bg-mu { background: rgba(139,139,147,.1); border-color: rgba(139,139,147,.25); color: var(--muted); }
.flg { padding: 8px 0; border-bottom: 1px solid var(--border); }
.flg:last-child { border-bottom: 0; }
.flg .fv { font-family: var(--mono); font-size: 11px; color: var(--emerald); word-break: break-all; }
.flg .fm { font-size: 10px; color: var(--muted); margin-top: 2px; display: flex; gap: 8px; }
.flg .fm .conf { color: var(--cyan); }

/* row4: boards */
.bgrid { display: grid; grid-template-columns: repeat(auto-fill, minmax(270px, 1fr)); gap: 8px; }
.bcard { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; }
.bcard:hover { border-color: var(--border-hi); }
.bcard .bh { display: flex; justify-content: space-between; align-items: center; margin-bottom: 7px; }
.bcard .nm { font-size: 12px; font-weight: 600; color: var(--fg); font-family: var(--mono); }
.bcard .rv { font-size: 9px; color: var(--dim); font-family: var(--mono); }
.sbar { display: flex; gap: 2px; margin-bottom: 7px; }
.seg { flex: 1; height: 5px; border-radius: 2px; background: var(--border); }
.seg.p { background: var(--emerald); } .seg.f { background: var(--red); } .seg.r { background: var(--amber); }
.bmeta { display: flex; gap: 10px; font-size: 10px; color: var(--muted); }
.bmeta b { color: var(--fg2); font-family: var(--mono); font-weight: 600; }
.bflag { margin-top: 6px; font-family: var(--mono); font-size: 10px; color: var(--emerald); background: rgba(16,185,129,.08); border-radius: 4px; padding: 3px 7px; word-break: break-all; }
.btags { margin-top: 6px; display: flex; flex-wrap: wrap; gap: 3px; }
.btag { font-size: 9px; padding: 0.5px 6px; border-radius: 7px; background: var(--border); color: var(--muted); font-family: var(--mono); }
.btag.hyp { color: var(--amber); } .btag.fal { color: var(--red); text-decoration: line-through; opacity: .7; }

/* row5: three cols */
.row5 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; margin-bottom: 10px; }
.hbar { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.hbar .lb { width: 64px; text-align: right; font-size: 10px; color: var(--muted); flex-shrink: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.hbar .tr { flex: 1; height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; }
.hbar .fl { height: 100%; border-radius: 3px; }
.hbar .ct { width: 28px; font-size: 10px; font-family: var(--mono); color: var(--fg2); text-align: right; flex-shrink: 0; }
.cat-row { display: flex; align-items: center; gap: 8px; padding: 5px 0; border-bottom: 1px solid var(--border); font-size: 11px; }
.cat-row:last-child { border-bottom: 0; }
.cat-row .cn { width: 70px; flex-shrink: 0; }
.cat-row .ctr { flex: 1; height: 4px; background: var(--border); border-radius: 2px; overflow: hidden; }
.cat-row .cf { height: 100%; background: var(--emerald); border-radius: 2px; }
.cat-row .cs { font-family: var(--mono); font-size: 10px; color: var(--muted); }

.empty { padding: 20px 0; text-align: center; color: var(--dim); font-size: 11px; }
@media (max-width: 1100px) { .stats { grid-template-columns: repeat(3, 1fr); } .row2 { grid-template-columns: 1fr; } .row3, .row5 { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<div class="hdr">
  <div>
    <h1>总览</h1>
    <div class="sub"><span class="dot"></span>CTF 编排系统 · 实时刷新</div>
  </div>
  <div class="ts" id="ts"></div>
</div>

<div class="stats" id="stats"></div>
<div class="row2">
  <div class="card stat tk-total">
    <div class="lbl"><span class="ic">⚡</span>Token 用量</div>
    <div class="num" id="tk-total">—</div>
    <div class="sub" id="tk-sub">—</div>
    <div id="tk-bars"></div>
  </div>
  <div class="card chart-wrap">
    <div class="chead">
      <div class="t"><span class="ic">📊</span>每日 Token 消耗</div>
      <div class="rng" id="rng"></div>
    </div>
    <div class="cbody">
      <div class="bars" id="bars"></div>
    </div>
  </div>
</div>

<div class="row3">
  <div class="card">
    <div class="chead"><div class="t"><span class="ic">📡</span>子代理活动</div><div class="r" id="run-count"></div></div>
    <div class="cbody alist" id="alist"></div>
  </div>
  <div class="card">
    <div class="chead"><div class="t"><span class="ic">🏁</span>Flag 收获</div><div class="r" id="flag-count"></div></div>
    <div class="cbody" id="flist" style="max-height:324px;overflow-y:auto"></div>
  </div>
</div>

<div class="card" style="margin-bottom:10px">
  <div class="chead"><div class="t"><span class="ic">🗂️</span>题目黑板</div><div class="r" id="board-count"></div></div>
  <div class="cbody"><div class="bgrid" id="bgrid"></div></div>
</div>

<div class="row5">
  <div class="card">
    <div class="chead"><div class="t"><span class="ic">⚠️</span>失败原因</div></div>
    <div class="cbody" id="errs"></div>
  </div>
  <div class="card">
    <div class="chead"><div class="t"><span class="ic">🤖</span>模型用量</div></div>
    <div class="cbody" id="models"></div>
  </div>
  <div class="card">
    <div class="chead"><div class="t"><span class="ic">🎯</span>题单分类</div><div class="r" id="cat-sub"></div></div>
    <div class="cbody" id="cats"></div>
  </div>
</div>
<div class="btip" id="btip"></div>

<script>
let D = null, RNG = 30;
const $ = id => document.getElementById(id);
const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const fmtTok = n => n >= 1e6 ? (n/1e6).toFixed(1)+'M' : n >= 1e3 ? (n/1e3).toFixed(1)+'k' : String(n);
const fmtDur = s => s < 60 ? s+'s' : Math.floor(s/60)+'m'+(s%60)+'s';
const fmtRel = ms => { if (!ms) return '—'; const d = Date.now()-ms, m = Math.floor(d/60000);
  if (m < 1) return '刚刚'; if (m < 60) return m+'分钟前'; const h = Math.floor(m/60);
  if (h < 24) return h+'小时前'; return Math.floor(h/24)+'天前'; };

async function load() {
  try { D = await (await fetch('/api/all')).json(); render(); }
  catch (e) { $('ts').textContent = '加载失败'; }
}

function render() {
  const S = D.stats;
  $('ts').textContent = new Date(D.ts*1000).toLocaleString('zh-CN', {hour12:false});

  // row1（破军风格：活跃卡带 X/N + 状态分解副标）
  const rate = S.total_runs?Math.round(S.ok_runs/S.total_runs*100):0;
  $('stats').innerHTML = [
    {ic:'▶', lbl:'子代理', num:S.active_runs, sub:`<span class="c-mu">/ ${S.total_runs} 次</span>`, cls:'c-blue',
     subs:`${S.active_runs?`<span class="c-blue">运行 ${S.active_runs}</span>`:''}${S.ok_runs?`<span class="c-em">完成 ${S.ok_runs}</span>`:''}${S.fail_runs?`<span class="c-red">失败 ${S.fail_runs}</span>`:''}`},
    {ic:'⚡', lbl:'Token 用量', num:fmtTok(S.total_tokens), sub:`<span class="c-mu">${S.total_runs} 次</span>`,
     subs:`<span class="c-blue">入 ${fmtTok(S.in_tokens)}</span><span class="c-vi">出 ${fmtTok(S.out_tokens)}</span>`},
    {ic:'⚠', lbl:'失败浪费', num:fmtTok(S.wasted_tokens), sub:`<span class="c-mu">${S.fail_runs} 次</span>`,
     subs:`<span class="c-mu">成功率 ${rate}%</span>`},
    {ic:'🏁', lbl:'Flag', num:S.total_flags, sub:`<span class="c-mu">${S.boards_with_flags} 题</span>`,
     subs:`<span class="c-cy">${S.solved_challs}/${S.total_challs} 题 · ${S.total_score} 分</span>`},
    {ic:'🗂', lbl:'黑板', num:S.total_boards, sub:`<span class="c-mu">题目分区</span>`,
     subs:`<span class="c-vi">有产出 ${S.boards_with_flags}</span><span class="c-mu">空转 ${S.total_boards-S.boards_with_flags}</span>`},
  ].map(s => `<div class="card stat">
    <div class="lbl"><span class="ic">${s.ic}</span>${s.lbl}</div>
    <div class="num">${s.num}<small>${s.sub||''}</small></div>
    <div class="subs">${s.subs||''}</div></div>`).join('');

  // row2 left
  $('tk-total').textContent = fmtTok(S.total_tokens);
  $('tk-sub').textContent = `入 ${fmtTok(S.in_tokens)} · 出 ${fmtTok(S.out_tokens)} · ${S.total_runs} 次运行`;
  const tot = S.total_tokens || 1;
  const bars = [
    ['输入', S.in_tokens, 'var(--blue)', 'c-blue'],
    ['输出', S.out_tokens, 'var(--violet)', 'c-vi'],
    ['失败浪费', S.wasted_tokens, 'var(--red)', 'c-red'],
  ];
  $('tk-bars').innerHTML = bars.map(([l,v,c,tc]) => `
    <div class="tbar"><div class="r1"><span class="c-mu">${l}</span><span class="v ${tc}">${fmtTok(v)}</span></div>
    <div class="track"><div class="fill" style="width:${v/tot*100}%;background:${c}"></div></div></div>`).join('');

  // row2 right: range buttons + chart
  $('rng').innerHTML = [7,14,30,90].map(d =>
    `<button class="${d===RNG?'on':''}" onclick="RNG=${d};renderChart()">${d}天</button>`).join('');
  renderChart();

  // row3 left: 活动流（运行中置顶，其余按时间倒序）
  const sorted = [...D.runs].sort((a,b) => (a.state==='running'?0:1)-(b.state==='running'?0:1) || b.started-a.started);
  $('run-count').textContent = `${S.active_runs} 运行 / ${D.runs.length} 条`;
  $('alist').innerHTML = sorted.slice(0, 40).map(r => {
    const st = r.state==='complete' ? ['✅','bg-ok','完成'] : r.state==='running' ? ['▶','bg-run','运行中'] : ['✗','bg-fail','失败'];
    const err = r.error ? `<span class="badge bg-fail" title="${esc(r.error)}">${esc(r.error)}</span>` : '';
    return `<div class="arow">
      <div class="st">${st[0]}</div>
      <div class="mid">
        <div class="l1"><b>${esc(r.cwd||r.id)}</b><span class="badge ${st[1]}">${esc(r.agent)}</span><span class="badge bg-mu" title="${esc(r.model)}">${esc(r.model)}</span>${err}</div>
        <div class="l2">${r.turns} 轮 · ${fmtTok(r.tokens)} tok · ${fmtDur(r.duration)}${r.state==='running'?' · <span class="c-blue">进行中</span>':''}</div>
      </div>
      <div class="rt"><div>${fmtRel(r.started)}</div><div class="tk">${r.id}</div></div>
    </div>`;
  }).join('');

  // row3 right: flags（显示原始 flag 串，不重拼格式）
  const flags = [];
  D.boards.forEach(b => b.flags.forEach(f => flags.push({b, f})));
  flags.sort((a,b) => (b.b.rev - a.b.rev));
  const seen = new Set();
  $('flag-count').textContent = `${flags.length} 个`;
  $('flist').innerHTML = flags.length ? flags.map(({b,f}) => {
    if (seen.has(f.flag)) return ''; seen.add(f.flag);
    return `<div class="flg">
      <div class="fv">${esc(f.flag)}</div>
      <div class="fm"><span class="conf">${esc(f.confidence||'')}</span><span>${esc(b.short)}</span><span>rev ${b.rev}</span></div>
    </div>`; }).join('') : '<div class="empty">暂无 flag</div>';

  // row4: boards（有 flag 优先，其次 rev 倒序）
  $('board-count').textContent = `${D.boards.length} 块`;
  $('bgrid').innerHTML = D.boards.slice().sort((a,b) => (b.flags.length-a.flags.length) || (b.rev-a.rev)).map(b => {
    let segs = '';
    for (let i=1; i<=9; i++) { const s = b.stages[i];
      segs += `<div class="seg ${s ? (s.state==='通过'?'p':s.state==='不通过'?'f':'r') : ''}" title="阶段${i}: ${s?s.state:'未到'}"></div>`; }
    const passed = Object.values(b.stages).filter(s=>s.state==='通过').length;
    const bf = b.flags.map(f=>`<div class="bflag">🏁 ${esc(f.flag)}</div>`).join('');
    const tags = b.hypotheses.map(h => {
      const dead = b.falsified.some(f=>f.tag===h.tag);
      return `<span class="btag ${dead?'fal':'hyp'}" title="${dead?'已证伪':'活跃假设'}">${esc(h.tag)}</span>`; }).join('');
    const nm = b.short === 'geek2026' ? 'geek2026（旧根板）' : b.short;
    const cname = b.challenge && b.challenge.name && b.challenge.name !== nm ? `<span class="c-mu" style="font-size:9px;font-weight:400"> · ${esc(b.challenge.name)}</span>` : '';
    return `<div class="bcard" title="${esc(b.task_dir)}">
      <div class="bh"><span class="nm">${esc(nm)}${cname}</span><span class="rv">rev ${b.rev}</span></div>
      <div class="sbar">${segs}</div>
      <div class="bmeta"><span>阶段 <b>${passed}/9</b></span><span>验证 <b>${b.verified.length}</b></span><span>证伪 <b>${b.falsified.length}</b></span><span class="c-mu">${esc(b.owner)}</span></div>
      ${bf}${tags?`<div class="btags">${tags}</div>`:''}
    </div>`;
  }).join('') || '<div class="empty">暂无黑板</div>';

  // row5: errors（悬停显示说明）
  const ERR_DESC = {'429限流':'API 限流，重试即浪费','进程崩溃':'Node runner 异常退出，无产出','余额耗尽':'402/403 provider 余额不足','网络超时':'API 请求超时','证据保护':'写板试图抹旧证据被拦','黑板未更新':'每回合需先写板再动手','阶段闸':'前置阶段未过就往下走被拦','预算闸':'重活命令未经 run.sh 包装','手动停止':'主 agent 主动 stop','未先读板':'写板前未先 read 拿 rev','其他':'未分类错误','未知':'无错误信息'};
  const errs = Object.entries(S.err_dist).sort((a,b)=>b[1]-a[1]);
  const emax = errs[0]?.[1] || 1;
  const ecolor = {'429限流':'var(--amber)','进程崩溃':'var(--red)','余额耗尽':'var(--red)','网络超时':'var(--amber)','证据保护':'var(--blue)','黑板未更新':'var(--blue)','阶段闸':'var(--blue)','预算闸':'var(--blue)','手动停止':'var(--dim)','未先读板':'var(--blue)','其他':'var(--dim)','未知':'var(--dim)'};
  $('errs').innerHTML = errs.length ? errs.map(([k,v]) => `
    <div class="hbar" title="${esc(ERR_DESC[k]||'')}"><span class="lb">${esc(k)}</span>
    <div class="tr"><div class="fl" style="width:${v/emax*100}%;background:${ecolor[k]||'var(--dim)'}"></div></div>
    <span class="ct">${v}</span></div>`).join('') : '<div class="empty">无失败 🎉</div>';

  // row5: models（按 token 排序，副标显示成功/失败数）
  const models = Object.entries(D.models).sort((a,b)=>b[1].tokens-a[1].tokens);
  const mmax = models[0]?.[1].tokens || 1;
  const mcolor = {'glm-5.3':'var(--violet)','deepseek-v4.1-flash':'var(--cyan)'};
  $('models').innerHTML = models.length ? models.map(([k,v]) => {
    const mlbl = k.replace(/:low$/, ' (low)');
    return `<div class="hbar" title="${v.runs} 次 · ${v.ok}✅ / ${v.fail}✗"><span class="lb" title="${esc(k)}">${esc(mlbl)}</span>
    <div class="tr"><div class="fl" style="width:${v.tokens/mmax*100}%;background:${mcolor[k]||'var(--indigo)'}"></div></div>
    <span class="ct" title="${v.ok}✅/${v.fail}✗">${fmtTok(v.tokens)}</span></div>`; }).join('') : '<div class="empty">—</div>';

  // row5: cats（多比赛：每个比赛一行进度 + 分类分布）
  const contests = D.contests || [];
  const cats = Object.entries(D.cat_stats);
  const cmax = Math.max(...cats.map(c=>c[1][1]), 1);
  $('cat-sub').textContent = `${S.solved_challs}/${S.total_challs} 已解`;
  $('cats').innerHTML =
    (contests.length ? contests.map(c =>
      `<div class="cat-row" title="${esc(c.name)}"><span class="cn" style="font-weight:600">${esc(c.name)}</span>` +
      `<div class="ctr"><div class="cf" style="width:${c.total? c.solved/c.total*100:0}%"></div></div>` +
      `<span class="cs">${c.solved}/${c.total} · ${c.score}分</span></div>`).join('')
      + `<div style="border-top:1px solid var(--border);margin:5px 0"></div>` : '')
    + (cats.map(([k,[s,t]]) => `
    <div class="cat-row"><span class="cn">${esc(k)}</span>
    <div class="ctr"><div class="cf" style="width:${s/cmax*100}%"></div></div>
    <span class="cs">${s}/${t}</span></div>`).join('') || '<div class="empty">—</div>');
}

function renderChart() {
  const data = D ? D.daily.slice(-RNG) : [];
  const tip = $('btip');
  if (!data.length) { $('bars').innerHTML = '<div class="empty">暂无数据</div>'; return; }
  const max = Math.max(...data.map(d => d.in + d.out), 1);
  const step = data.length > 40 ? 3 : data.length > 20 ? 2 : 1;
  $('bars').innerHTML = data.map((d, i) => {
    const tot = d.in + d.out, h = Math.max(2, tot/max*150);
    const hi = Math.max(1, d.in/tot*h), ho = Math.max(0, d.out/tot*h);
    const showDt = i % step === 0;
    return `<div class="bcol" data-i="${i}">
      <div class="b" style="height:${h}px">
        <div style="height:${hi}px;background:var(--blue);border-radius:2px 2px 0 0"></div>
        <div style="height:${ho}px;background:var(--violet);border-radius:2px 2px 0 0"></div>
      </div>
      ${showDt ? `<div class="dt">${d.date}</div>` : '<div class="dt">&nbsp;</div>'}
    </div>`;
  }).join('');
  document.querySelectorAll('.bcol').forEach(el => {
    el.onmouseenter = e => {
      const d = data[+el.dataset.i];
      tip.innerHTML = `<div class="d">${d.date}</div>
        <div class="row"><span style="color:var(--blue)">输入</span><span>${fmtTok(d.in)}</span></div>
        <div class="row"><span style="color:var(--violet)">输出</span><span>${fmtTok(d.out)}</span></div>
        <div class="row" style="border-top:1px solid var(--border);margin-top:3px;padding-top:3px"><span>合计</span><span>${fmtTok(d.in+d.out)}</span></div>`;
      tip.style.display = 'block';
    };
    el.onmousemove = e => { tip.style.left = Math.min(e.clientX+12, innerWidth-150)+'px'; tip.style.top = (e.clientY-60)+'px'; };
    el.onmouseleave = () => tip.style.display = 'none';
  });
}

load();
setInterval(load, 5000);
</script>
</body>
</html>"""

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/all":
            try:
                body = json.dumps(collect(), ensure_ascii=False, default=str).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception as e:
                self.send_response(500); self.end_headers(); self.wfile.write(str(e).encode())
        elif self.path in ("/", "/index.html"):
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404); self.end_headers()
    def log_message(self, *a): pass

if __name__ == "__main__":
    print(f"CTF 编排仪表盘 v2 → http://localhost:{PORT}  (Ctrl+C 停止)")
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    try: srv.serve_forever()
    except KeyboardInterrupt: print("\n已停止")
