#!/usr/bin/env python3
"""CTF 黑板（主会话 + 题目目录分区）。Windows 扩展与 Kali(SSH)/WSL 侧 run/stage/check 共用（Kali 走 HGFS 实时共享）。"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=3000;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS params (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS verified (
  tag TEXT PRIMARY KEY,
  fact TEXT NOT NULL DEFAULT '',
  evidence TEXT NOT NULL DEFAULT '',
  at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS falsified (
  tag TEXT PRIMARY KEY,
  condition TEXT NOT NULL DEFAULT '',
  observed TEXT NOT NULL DEFAULT '',
  reopen TEXT NOT NULL DEFAULT '',
  why TEXT NOT NULL DEFAULT '',
  at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hypotheses (
  tag TEXT PRIMARY KEY,
  idea TEXT NOT NULL DEFAULT '',
  falsifier TEXT NOT NULL DEFAULT '',
  budget TEXT NOT NULL DEFAULT '',
  at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tooling (
  name TEXT PRIMARY KEY,
  how TEXT NOT NULL DEFAULT '',
  why TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS next_steps (
  ord INTEGER PRIMARY KEY,
  text TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS flags (
  flag TEXT PRIMARY KEY,
  confidence TEXT NOT NULL DEFAULT '',
  basis TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS stages (
  n INTEGER PRIMARY KEY,
  state TEXT NOT NULL CHECK (state IN ('通过','不通过','回退')),
  evidence TEXT NOT NULL DEFAULT '',
  at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
  tag TEXT PRIMARY KEY,
  path TEXT NOT NULL DEFAULT '',
  rc INTEGER,
  excerpt TEXT NOT NULL DEFAULT '',
  at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS approved_budget (
  line TEXT PRIMARY KEY
);
"""

EMPTY_BOARD = {
    "challenge": {"name": "", "remote": ""},
    "params": {"N": "", "e": "", "a": "", "leak": "", "out1": "", "out2": ""},
    "verified": [],
    "falsified": [],
    "hypotheses": [],
    "tooling": [],
    "next": [],
    "flags": [],
}

BOARD_FIELDS = ("challenge", "params", "verified", "falsified", "hypotheses", "tooling", "next", "flags")


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect(db: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db) or ".", exist_ok=True)
    cx = sqlite3.connect(db, timeout=5)
    cx.row_factory = sqlite3.Row
    cx.execute("PRAGMA busy_timeout=3000")
    cx.execute("PRAGMA journal_mode=WAL")
    cx.executescript(SCHEMA)
    if cx.execute("SELECT 1 FROM meta WHERE k='rev'").fetchone() is None:
        cx.execute("INSERT INTO meta(k,v) VALUES('rev','0')")
        cx.execute("INSERT OR IGNORE INTO meta(k,v) VALUES('challenge_name','')")
        cx.execute("INSERT OR IGNORE INTO meta(k,v) VALUES('challenge_remote','')")
        cx.commit()
    return cx


def connect_readonly(db: str) -> sqlite3.Connection:
    """A status read must never manufacture an empty board."""
    if not os.path.isfile(db):
        raise FileNotFoundError(f"blackboard not found: {db}")
    cx = sqlite3.connect(f"file:{os.path.abspath(db).replace(os.sep, '/')}?mode=ro", uri=True, timeout=5)
    cx.row_factory = sqlite3.Row
    cx.execute("PRAGMA busy_timeout=3000")
    return cx


def bump(cx: sqlite3.Connection) -> int:
    cx.execute("UPDATE meta SET v = CAST(CAST(v AS INTEGER) + 1 AS TEXT) WHERE k='rev'")
    row = cx.execute("SELECT v FROM meta WHERE k='rev'").fetchone()
    return int(row["v"] if row else 0)


def meta_get(cx: sqlite3.Connection, k: str) -> str:
    row = cx.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
    return row["v"] if row else ""


def dump_board(cx: sqlite3.Connection) -> dict:
    params = {r["key"]: r["value"] for r in cx.execute("SELECT key, value FROM params")}
    return {
        "challenge": {
            "name": meta_get(cx, "challenge_name"),
            "remote": meta_get(cx, "challenge_remote"),
        },
        "params": params,
        "verified": [
            {"tag": r["tag"], "fact": r["fact"], "evidence": r["evidence"]}
            for r in cx.execute("SELECT tag, fact, evidence FROM verified ORDER BY tag")
        ],
        "falsified": [
            {
                "tag": r["tag"],
                "condition": r["condition"],
                "observed": r["observed"],
                "reopen": r["reopen"],
                "why": r["why"],
            }
            for r in cx.execute("SELECT tag, condition, observed, reopen, why FROM falsified ORDER BY tag")
        ],
        "hypotheses": [
            {"tag": r["tag"], "idea": r["idea"], "falsifier": r["falsifier"], "budget": r["budget"]}
            for r in cx.execute("SELECT tag, idea, falsifier, budget FROM hypotheses ORDER BY tag")
        ],
        "tooling": [
            {"name": r["name"], "how": r["how"], "why": r["why"]}
            for r in cx.execute("SELECT name, how, why FROM tooling ORDER BY name")
        ],
        "next": [r["text"] for r in cx.execute("SELECT text FROM next_steps ORDER BY ord")],
        "flags": [
            {"flag": r["flag"], "confidence": r["confidence"], "basis": r["basis"]}
            for r in cx.execute("SELECT flag, confidence, basis FROM flags ORDER BY flag")
        ],
    }


def import_board(cx: sqlite3.Connection, b: dict) -> None:
    """Import a complete snapshot only after optimistic revision validation.

    The caller must hold a BEGIN IMMEDIATE transaction. A stale snapshot may
    not erase evidence added by a runner, another child, or another process.
    """
    t = now()
    ch = b.get("challenge") if isinstance(b.get("challenge"), dict) else {}
    cx.execute("INSERT INTO meta(k,v) VALUES('challenge_name',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
               (str(ch.get("name") or ""),))
    cx.execute("INSERT INTO meta(k,v) VALUES('challenge_remote',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
               (str(ch.get("remote") or ""),))
    cx.execute("DELETE FROM params")
    params = b.get("params") if isinstance(b.get("params"), dict) else {}
    for k, v in params.items():
        cx.execute("INSERT INTO params(key,value) VALUES(?,?)", (str(k), "" if v is None else str(v)))
    cx.execute("DELETE FROM verified")
    for x in b.get("verified") or []:
        if not isinstance(x, dict):
            continue
        cx.execute("INSERT OR REPLACE INTO verified(tag,fact,evidence,at) VALUES(?,?,?,?)",
                   (str(x.get("tag") or ""), str(x.get("fact") or ""), str(x.get("evidence") or ""), t))
    cx.execute("DELETE FROM falsified")
    for x in b.get("falsified") or []:
        if not isinstance(x, dict):
            continue
        tag = str(x.get("tag") or "").strip()
        if not tag:
            continue
        cx.execute(
            "INSERT OR REPLACE INTO falsified(tag,condition,observed,reopen,why,at) VALUES(?,?,?,?,?,?)",
            (tag, str(x.get("condition") or ""), str(x.get("observed") or ""),
             str(x.get("reopen") or ""), str(x.get("why") or ""), t),
        )
    cx.execute("DELETE FROM hypotheses")
    for x in b.get("hypotheses") or []:
        if not isinstance(x, dict):
            continue
        tag = str(x.get("tag") or "").strip()
        if not tag:
            continue
        cx.execute("INSERT OR REPLACE INTO hypotheses(tag,idea,falsifier,budget,at) VALUES(?,?,?,?,?)",
                   (tag, str(x.get("idea") or ""), str(x.get("falsifier") or ""), str(x.get("budget") or ""), t))
    cx.execute("DELETE FROM tooling")
    for x in b.get("tooling") or []:
        if not isinstance(x, dict):
            continue
        name = str(x.get("name") or "").strip()
        if not name:
            continue
        cx.execute("INSERT OR REPLACE INTO tooling(name,how,why) VALUES(?,?,?)",
                   (name, str(x.get("how") or ""), str(x.get("why") or "")))
    cx.execute("DELETE FROM next_steps")
    for i, text in enumerate(b.get("next") or []):
        cx.execute("INSERT INTO next_steps(ord,text) VALUES(?,?)", (i, str(text)))
    cx.execute("DELETE FROM flags")
    for x in b.get("flags") or []:
        if not isinstance(x, dict):
            continue
        flag = str(x.get("flag") or "").strip()
        if not flag:
            continue
        cx.execute("INSERT OR REPLACE INTO flags(flag,confidence,basis) VALUES(?,?,?)",
                   (flag, str(x.get("confidence") or ""), str(x.get("basis") or "")))
    bump(cx)


def cmd_init(db: str) -> int:
    cx = connect(db)
    cx.close()
    return 0


def cmd_dump(db: str) -> int:
    try:
        cx = connect_readonly(db)
        json.dump(dump_board(cx), sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
        cx.close()
        return 0
    except (OSError, sqlite3.Error) as exc:
        print(f"dump failed: {exc}", file=sys.stderr)
        return 2


def cmd_snapshot(db: str) -> int:
    """Return revision and board from the same read transaction."""
    try:
        cx = connect_readonly(db)
        cx.execute("BEGIN")
        board = dump_board(cx)
        rev = int(meta_get(cx, "rev"))
        json.dump({"rev": rev, "board": board}, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        cx.rollback()
        cx.close()
        return 0
    except (OSError, sqlite3.Error, ValueError) as exc:
        print(f"snapshot failed: {exc}", file=sys.stderr)
        return 2


def cmd_list(db: str) -> int:
    """List one owner's challenge partitions without creating or modifying databases."""
    owner = os.path.dirname(os.path.abspath(db))
    tasks = os.path.join(owner, "challenges")
    if not os.path.isdir(tasks):
        return 0
    for slug in sorted(os.listdir(tasks)):
        if not all(c in "0123456789abcdef" for c in slug) or len(slug) != 16:
            continue
        folder = os.path.join(tasks, slug)
        challenge_file = os.path.join(folder, "CHALLENGE.txt")
        challenge_db = os.path.join(folder, "gate.sqlite")
        if not os.path.isfile(challenge_file) or not os.path.isfile(challenge_db):
            continue
        with open(challenge_file, encoding="utf-8") as f:
            challenge = f.read().strip()
        # A view is useful even when another Pi child is writing (WAL readers).
        try:
            cx = sqlite3.connect(f"file:{challenge_db.replace(os.sep, '/')}?mode=ro", uri=True, timeout=3)
            row = cx.execute("SELECT v FROM meta WHERE k='rev'").fetchone()
            rev = row[0] if row else "?"
            cx.close()
        except sqlite3.Error:
            rev = "unavailable"
        print(f"{slug}\t{rev}\t{challenge}\t{challenge_db}")
    return 0


def canonical_board(b: dict) -> dict:
    """Normalize the JSON form to the exact representation stored in SQLite."""
    def text(v): return "" if v is None else str(v)
    def rows(field, keys, id_key):
        result = {}
        for row in b[field]:
            if not isinstance(row, dict) or not row.get(id_key): continue
            key = text(row[id_key]).strip() if field in ("falsified", "hypotheses", "tooling", "flags") else text(row[id_key])
            result[key] = {col: text(row.get(col)) for col in keys}
            result[key][id_key] = key
        return [result[k] for k in sorted(result)]
    return {
        "challenge": {k: text(b["challenge"].get(k)) for k in ("name", "remote")},
        "params": {text(k): text(v) for k, v in b["params"].items()},
        "verified": rows("verified", ("tag", "fact", "evidence"), "tag"),
        "falsified": rows("falsified", ("tag", "condition", "observed", "reopen", "why"), "tag"),
        "hypotheses": rows("hypotheses", ("tag", "idea", "falsifier", "budget"), "tag"),
        "tooling": rows("tooling", ("name", "how", "why"), "name"),
        "next": [text(s) for s in b["next"]],
        "flags": rows("flags", ("flag", "confidence", "basis"), "flag"),
    }


def merge_missing_evidence(existing: dict, incoming: dict) -> tuple[dict, list[str]]:
    """Append-only repair: keep rows the writer dropped, refuse content rewrites.

    A sloppy whole-board rewrite (missing rows) is repaired instead of failing;
    an attempt to change an existing row's evidence stays a hard error.
    """
    notes: list[str] = []
    for field, key in (("verified", "tag"), ("falsified", "tag"), ("flags", "flag")):
        old = {row[key]: row for row in existing[field]}
        new = {row[key]: row for row in incoming[field]}
        for row_key, prior in old.items():
            if row_key not in new:
                incoming[field].append(dict(prior))
                notes.append(f"restored dropped {field}[{row_key}]")
                continue
            for column, value in prior.items():
                if column != key and value and new[row_key].get(column) != value:
                    raise ValueError(f"refusing to overwrite {field}[{row_key!r}].{column}; retain original evidence")
        incoming[field] = sorted(incoming[field], key=lambda row: row.get(key, ""))
    return incoming, notes


def cmd_import(db: str, expected_rev: str | None) -> int:
    if expected_rev is None:
        print("import requires --rev <n> (read the current BOARD before editing)", file=sys.stderr)
        return 2
    try:
        expected = int(expected_rev)
        if expected < 0: raise ValueError()
        b = json.loads(sys.stdin.read())
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"invalid import/revision: {exc}", file=sys.stderr)
        return 2
    if not isinstance(b, dict):
        print("import: top-level must be object", file=sys.stderr)
        return 2
    cx = connect(db)
    try:
        cx.execute("BEGIN IMMEDIATE")
        current = int(meta_get(cx, "rev") or "0")
        if current != expected:
            print(f"stale BOARD: expected rev={expected}, current rev={current}; read the current board and merge your changes", file=sys.stderr)
            cx.rollback()
            return 3
        existing = dump_board(cx)
        normalized = canonical_board(b)
        try:
            normalized, notes = merge_missing_evidence(existing, normalized)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            cx.rollback()
            return 2
        for note in notes:
            print(f"[merge] {note}", file=sys.stderr)
        if existing != normalized:
            import_board(cx, normalized)
        cx.commit()
    except Exception as e:
        cx.rollback()
        print(f"import failed: {e}", file=sys.stderr)
        return 2
    finally:
        cx.close()
    return 0


def cmd_rev(db: str) -> int:
    try:
        cx = connect_readonly(db)
        print(meta_get(cx, "rev") or "0")
        cx.close()
        return 0
    except (OSError, sqlite3.Error) as exc:
        print(f"rev failed: {exc}", file=sys.stderr)
        return 2


def cmd_falsified_get(db: str, tag: str) -> int:
    cx = connect_readonly(db)
    row = cx.execute("SELECT condition, observed, reopen FROM falsified WHERE tag=?", (tag,)).fetchone()
    cx.close()
    if not row:
        return 1
    cond = row["condition"] or "(no condition)"
    print(cond)
    return 0


def cmd_falsified_list(db: str) -> int:
    cx = connect_readonly(db)
    for r in cx.execute("SELECT tag, condition FROM falsified ORDER BY tag"):
        print(f"{r['tag']}\t{r['condition']}")
    cx.close()
    return 0


def cmd_falsify(db: str, tag: str, condition: str, observed: str) -> int:
    cx = connect(db)
    inserted = cx.execute(
        "INSERT INTO falsified(tag,condition,observed,reopen,why,at) VALUES(?,?,?,?,?,?) "
        "ON CONFLICT(tag) DO NOTHING",
        (tag, condition, observed, "", "", now()),
    )
    if inserted.rowcount:
        bump(cx)
    cx.commit()
    cx.close()
    return 0


def cmd_stages(db: str) -> int:
    cx = connect_readonly(db)
    for r in cx.execute("SELECT n, state FROM stages ORDER BY n"):
        print(f"{r['n']}\t{r['state']}")
    cx.close()
    return 0


def cmd_stage_get(db: str, n: str) -> int:
    cx = connect_readonly(db)
    row = cx.execute("SELECT state, evidence FROM stages WHERE n=?", (int(n),)).fetchone()
    cx.close()
    if not row:
        return 1
    print(row["state"])
    return 0


def cmd_stage_probe(db: str, args: list[str]) -> int:
    """Run a bounded validation command; state comes from its actual exit code."""
    if len(args) < 4 or args[2] != "--":
        print("usage: stage-probe <n> <budget_s> -- <validation command...>", file=sys.stderr)
        return 2
    try:
        n, budget = int(args[0]), int(args[1])
    except ValueError:
        return 2
    if not 1 <= n <= 9 or not 1 <= budget <= 60:
        print("stage must be 1..9; probe budget must be 1..60s", file=sys.stderr)
        return 2
    # A bare success command cannot validate an artifact. The supplied script
    # still decides what to check; this only rejects obvious no-op approvals.
    if len(args[3:]) < 2 or args[3] not in ("python3", "python", "bash", "sh", "sage"):
        print("stage probe must run a validation script (.py/.sh/.sage), not true/echo", file=sys.stderr)
        return 2
    script = args[4]
    task_dir = os.path.realpath(os.getcwd())
    script_path = os.path.realpath(script)
    valid_suffix = {"python3": ".py", "python": ".py", "bash": ".sh", "sh": ".sh", "sage": ".sage"}[args[3]]
    if not script.endswith(valid_suffix) or not os.path.isfile(script_path) or \
       os.path.commonpath((task_dir, script_path)) != task_dir:
        print("stage probe script must be an existing file inside this challenge directory", file=sys.stderr)
        return 2
    gate = os.environ.get("CTF_GATE_DIR", "")
    if not gate:
        print("CTF_GATE_DIR required", file=sys.stderr)
        return 2
    cx = connect(db)
    previous = dict(cx.execute("SELECT n,state FROM stages WHERE n < ?", (n,)))
    if any(previous.get(i) != "通过" for i in range(1, n)):
        cx.close()
        print("previous stages must exist and pass", file=sys.stderr)
        return 2
    # Invalidate old success before starting; a killed probe cannot leave a stale pass.
    cx.execute("INSERT INTO stages(n,state,evidence,at) VALUES(?,?,?,?) ON CONFLICT(n) DO UPDATE SET state=excluded.state,evidence=excluded.evidence,at=excluded.at",
               (n, "回退", "probe running", now()))
    cx.execute("DELETE FROM stages WHERE n > ?", (n,))
    bump(cx)
    cx.commit()
    cx.close()
    os.makedirs(os.path.join(gate, "evidence"), exist_ok=True)
    output = os.path.join(gate, "evidence", f"stage{n}-{time.time_ns()}.out")
    with open(output, "wb") as f:
        try:
            # GNU timeout bounds the command's process group as well as the parent.
            result = subprocess.run(["timeout", "--kill-after=2s", f"{budget}s", *args[3:]], stdout=f, stderr=subprocess.STDOUT)
            rc = result.returncode if result.returncode >= 0 else 128 - result.returncode
        except OSError as exc:
            f.write(str(exc).encode("utf-8"))
            rc = 127
    with open(output, "rb") as f:
        excerpt = f.read(4000).decode("utf-8", errors="replace")
    state = "通过" if rc == 0 else "不通过"
    cx = connect(db)
    cx.execute("UPDATE stages SET state=?,evidence=?,at=? WHERE n=?", (state, output, now(), n))
    cx.execute("INSERT OR REPLACE INTO evidence(tag,path,rc,excerpt,at) VALUES(?,?,?,?,?)",
               (f"stage-{n}", output, rc, excerpt, now()))
    bump(cx)
    cx.commit()
    cx.close()
    print(excerpt)
    print(f"[stage.sh] stage{n}: {state}; rc={rc}; evidence={output}")
    return rc


def cmd_evidence(db: str, tag: str, path: str, rc: str, excerpt: str) -> int:
    cx = connect(db)
    cx.execute(
        "INSERT INTO evidence(tag,path,rc,excerpt,at) VALUES(?,?,?,?,?) "
        "ON CONFLICT(tag) DO UPDATE SET path=excluded.path, rc=excluded.rc, excerpt=excluded.excerpt, at=excluded.at",
        (tag, path, int(rc) if rc not in ("", None) else None, excerpt[:4000], now()),
    )
    bump(cx)
    cx.commit()
    cx.close()
    return 0


def cmd_tooling_count(db: str) -> int:
    cx = connect_readonly(db)
    n = cx.execute("SELECT COUNT(*) AS n FROM tooling").fetchone()["n"]
    cx.close()
    print(n)
    return 0


def cmd_backup(db: str, destination: str) -> int:
    if not os.path.isfile(db):
        print("blackboard does not exist; backup refused", file=sys.stderr)
        return 2
    os.makedirs(os.path.dirname(os.path.abspath(destination)), exist_ok=True)
    with sqlite3.connect(db, timeout=5) as source, sqlite3.connect(destination, timeout=5) as target:
        source.backup(target)
    return 0


def cmd_reset(db: str) -> int:
    cx = connect(db)
    for table in ("params", "verified", "falsified", "hypotheses", "tooling", "next_steps",
                  "flags", "stages", "evidence", "approved_budget"):
        cx.execute(f"DELETE FROM {table}")
    cx.execute("INSERT INTO meta(k,v) VALUES('challenge_name','') ON CONFLICT(k) DO UPDATE SET v=''")
    cx.execute("INSERT INTO meta(k,v) VALUES('challenge_remote','') ON CONFLICT(k) DO UPDATE SET v=''")
    for k, v in EMPTY_BOARD["params"].items():
        cx.execute("INSERT INTO params(key,value) VALUES(?,?)", (k, v))
    bump(cx)
    cx.commit()
    cx.close()
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--db", default=os.environ.get("CTF_GATE_DB", ""))
    p.add_argument("cmd")
    p.add_argument("args", nargs=argparse.REMAINDER)
    ns = p.parse_args()
    db = ns.cmd if ns.cmd.endswith(".sqlite") and not ns.db else ns.db
    args = list(ns.args)
    cmd = ns.cmd
    if not db:
        # allow: gate_db.py <db> <cmd> ...
        if cmd.endswith(".sqlite") or cmd.endswith(".db"):
            db = cmd
            if not args:
                print("usage: gate_db.py --db PATH <cmd>", file=sys.stderr)
                return 2
            cmd = args.pop(0)
        else:
            print("CTF_GATE_DB or --db required", file=sys.stderr)
            return 2
    dispatch = {
        "init": lambda: cmd_init(db),
        "dump": lambda: cmd_dump(db),
        "list": lambda: cmd_list(db),
        "snapshot": lambda: cmd_snapshot(db),
        "import": lambda: cmd_import(db, args[1] if len(args) == 2 and args[0] == "--rev" else None),
        "rev": lambda: cmd_rev(db),
        "falsified-get": lambda: cmd_falsified_get(db, args[0]) if args else 2,
        "falsified-list": lambda: cmd_falsified_list(db),
        "falsify": lambda: cmd_falsify(db, args[0], args[1] if len(args) > 1 else "", args[2] if len(args) > 2 else "") if args else 2,
        "stages": lambda: cmd_stages(db),
        "stage-get": lambda: cmd_stage_get(db, args[0]) if args else 2,
        "stage-probe": lambda: cmd_stage_probe(db, args),
        "evidence": lambda: cmd_evidence(db, args[0], args[1] if len(args) > 1 else "", args[2] if len(args) > 2 else "0", args[3] if len(args) > 3 else "") if args else 2,
        "tooling-count": lambda: cmd_tooling_count(db),
        "backup": lambda: cmd_backup(db, args[0]) if args else 2,
        "reset": lambda: cmd_reset(db),
    }
    fn = dispatch.get(cmd)
    if not fn:
        print(f"unknown cmd {cmd}", file=sys.stderr)
        return 2
    return fn()


if __name__ == "__main__":
    sys.exit(main())
