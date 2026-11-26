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
from datetime import datetime, timedelta, timezone

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
CREATE TABLE IF NOT EXISTS coverage (
  surface TEXT NOT NULL,
  method  TEXT NOT NULL DEFAULT 'GET',
  param   TEXT NOT NULL DEFAULT '(none)',
  state   TEXT NOT NULL DEFAULT 'untested'
          CHECK (state IN ('untested','clean','vuln','blocked')),
  tag     TEXT NOT NULL DEFAULT '',
  note    TEXT NOT NULL DEFAULT '',
  scope   TEXT NOT NULL DEFAULT 'task'
          CHECK (scope IN ('task','instance')),
  at      TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (surface, method, param)
);
CREATE VIRTUAL TABLE IF NOT EXISTS search_fts USING fts5(
  kind, ref, text, tokenize='trigram'
);
CREATE TABLE IF NOT EXISTS outcomes (
  kind   TEXT NOT NULL DEFAULT 'result',
  value  TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  basis  TEXT NOT NULL DEFAULT '',
  at     TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (kind, value)
);
CREATE TABLE IF NOT EXISTS angles (
  name   TEXT PRIMARY KEY,
  result TEXT NOT NULL DEFAULT '',
  at     TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS claims (
  name       TEXT PRIMARY KEY,
  owner      TEXT NOT NULL DEFAULT '',
  expires_at TEXT NOT NULL DEFAULT '',
  at         TEXT NOT NULL DEFAULT ''
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
    "coverage": [],
    "angles": [],
    "outcomes": [],
}

BOARD_FIELDS = ("challenge", "params", "verified", "falsified", "hypotheses", "tooling", "next", "flags", "coverage", "angles", "outcomes")


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ensure_column(cx: sqlite3.Connection, table: str, column: str, decl: str) -> None:
    """Idempotent column migration for pre-existing DBs (CREATE IF NOT EXISTS won't add columns)."""
    cols = {r["name"] for r in cx.execute(f"PRAGMA table_info({table})")}
    if column not in cols:
        cx.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
        cx.commit()


def connect(db: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db) or ".", exist_ok=True)
    cx = sqlite3.connect(db, timeout=5)
    cx.row_factory = sqlite3.Row
    cx.execute("PRAGMA busy_timeout=3000")
    cx.execute("PRAGMA journal_mode=WAL")
    cx.executescript(SCHEMA)
    _ensure_column(cx, "flags", "idx", "TEXT NOT NULL DEFAULT ''")
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
            {"flag": r["flag"], "index": r["idx"], "confidence": r["confidence"], "basis": r["basis"]}
            for r in cx.execute("SELECT flag, idx, confidence, basis FROM flags ORDER BY flag")
        ],
        "coverage": [
            {
                "surface": r["surface"],
                "method": r["method"],
                "param": r["param"],
                "state": r["state"],
                "tag": r["tag"],
                "note": r["note"],
                "scope": r["scope"],
            }
            for r in cx.execute(
                "SELECT surface, method, param, state, tag, note, scope FROM coverage "
                "ORDER BY surface, method, param"
            )
        ],
        "angles": [
            {"name": r["name"], "result": r["result"], "at": r["at"]}
            for r in cx.execute("SELECT name, result, at FROM angles ORDER BY name")
        ],
        "outcomes": [
            {"kind": r["kind"], "value": r["value"], "status": r["status"], "basis": r["basis"]}
            for r in cx.execute("SELECT kind, value, status, basis FROM outcomes ORDER BY kind, value")
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
        cx.execute("INSERT OR REPLACE INTO flags(flag,idx,confidence,basis) VALUES(?,?,?,?)",
                   (flag, str(x.get("index") or ""), str(x.get("confidence") or ""), str(x.get("basis") or "")))
    cx.execute("DELETE FROM coverage")
    for x in b.get("coverage") or []:
        if not isinstance(x, dict):
            continue
        surface = str(x.get("surface") or "").strip()
        if not surface:
            continue
        method = str(x.get("method") or "GET").strip().upper() or "GET"
        param = str(x.get("param") or "(none)").strip() or "(none)"
        state = str(x.get("state") or "untested").strip() or "untested"
        if state not in ("untested", "clean", "vuln", "blocked"):
            state = "untested"
        scope = str(x.get("scope") or "task").strip() or "task"
        if scope not in ("task", "instance"):
            scope = "task"
        cx.execute(
            "INSERT OR REPLACE INTO coverage(surface,method,param,state,tag,note,scope,at) VALUES(?,?,?,?,?,?,?,?)",
            (surface, method, param, state, str(x.get("tag") or ""), str(x.get("note") or ""), scope, t),
        )
    cx.execute("DELETE FROM angles")
    for x in b.get("angles") or []:
        if not isinstance(x, dict):
            continue
        name = str(x.get("name") or "").strip()
        if not name:
            continue
        cx.execute("INSERT OR REPLACE INTO angles(name,result,at) VALUES(?,?,?)",
                   (name, str(x.get("result") or ""), str(x.get("at") or t)))
    cx.execute("DELETE FROM outcomes")
    for x in b.get("outcomes") or []:
        if not isinstance(x, dict):
            continue
        value = str(x.get("value") or "").strip()
        if not value:
            continue
        kind = str(x.get("kind") or "result").strip() or "result"
        cx.execute("INSERT OR REPLACE INTO outcomes(kind,value,status,basis,at) VALUES(?,?,?,?,?)",
                   (kind, value, str(x.get("status") or "open"), str(x.get("basis") or ""), t))
    rebuild_search(cx)
    bump(cx)


def rebuild_search(cx: sqlite3.Connection) -> None:
    """重建全文索引（派生数据，不单独 bump rev）。"""
    cx.execute("DELETE FROM search_fts")

    def add(kind: str, ref: str, parts: list[str]) -> None:
        text = " ".join(str(p or "") for p in parts).strip()
        if text:
            cx.execute("INSERT INTO search_fts(kind,ref,text) VALUES(?,?,?)", (kind, str(ref), text))

    for r in cx.execute("SELECT tag, fact, evidence FROM verified"):
        add("verified", r["tag"], [r["fact"], r["evidence"]])
    for r in cx.execute("SELECT tag, condition, observed, reopen, why FROM falsified"):
        add("falsified", r["tag"], [r["condition"], r["observed"], r["reopen"], r["why"]])
    for r in cx.execute("SELECT tag, idea, falsifier, budget FROM hypotheses"):
        add("hypotheses", r["tag"], [r["idea"], r["falsifier"], r["budget"]])
    for r in cx.execute("SELECT name, how, why FROM tooling"):
        add("tooling", r["name"], [r["how"], r["why"]])
    for i, r in enumerate(cx.execute("SELECT text FROM next_steps ORDER BY ord")):
        add("next", str(i), [r["text"]])
    for r in cx.execute("SELECT name, result FROM angles"):
        add("angles", r["name"], [r["result"]])
    for r in cx.execute("SELECT surface, method, param, state, tag, note FROM coverage"):
        add("coverage", f"{r['surface']} {r['method']} {r['param']}",
            [r["surface"], r["method"], r["param"], r["state"], r["tag"], r["note"]])
    for r in cx.execute("SELECT kind, value, status, basis FROM outcomes"):
        add("outcomes", r["value"], [r["kind"], r["value"], r["status"], r["basis"]])
    for r in cx.execute("SELECT flag, idx, confidence, basis FROM flags"):
        add("flags", r["flag"], [r["flag"], r["idx"], r["confidence"], r["basis"]])


def cmd_fields(_db: str | None = None) -> int:
    """机器可读契约：输出 BOARD_FIELDS 的 JSON（扩展据此校验，不解析 show 文本）。"""
    import json
    print(json.dumps({"fields": list(BOARD_FIELDS), "version": 1}, ensure_ascii=False))
    return 0


def cmd_schema_version(db: str) -> int:
    """输出数据文件的 schema 版本（PRAGMA user_version），供迁移判断。"""
    if not os.path.exists(db):
        print("0")
        return 0
    cx = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        print(cx.execute("PRAGMA user_version;").fetchone()[0])
    finally:
        cx.close()
    return 0


def cmd_init(db: str) -> int:
    cx = connect(db)
    cx.close()
    return 0


def _connect_migrating_or_fail(db: str) -> sqlite3.Connection:
    """Read path that still upgrades an existing DB (ALTER ... ADD COLUMN needs write access).
    Never manufactures a missing board: absent file is still an error."""
    if not os.path.isfile(db):
        raise FileNotFoundError(f"blackboard not found: {db}")
    return connect(db)


def cmd_dump(db: str) -> int:
    try:
        cx = _connect_migrating_or_fail(db)
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
        cx = _connect_migrating_or_fail(db)
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
    def cov_rows(rows_in):
        result = {}
        for row in rows_in:
            if not isinstance(row, dict):
                continue
            surface = text(row.get("surface")).strip()
            if not surface:
                continue
            method = (text(row.get("method")).strip().upper() or "GET")
            param = text(row.get("param")).strip() or "(none)"
            state = text(row.get("state")).strip() or "untested"
            if state not in ("untested", "clean", "vuln", "blocked"):
                state = "untested"
            scope = text(row.get("scope")).strip() or "task"
            if scope not in ("task", "instance"):
                scope = "task"
            key = f"{surface}|{method}|{param}"
            result[key] = {
                "surface": surface, "method": method, "param": param,
                "state": state, "tag": text(row.get("tag")),
                "note": text(row.get("note")), "scope": scope,
            }
        return [result[k] for k in sorted(result)]

    def outcome_rows(rows_in):
        result = {}
        for row in rows_in:
            if not isinstance(row, dict):
                continue
            value = text(row.get("value")).strip()
            if not value:
                continue
            kind = text(row.get("kind")).strip() or "result"
            result[f"{kind}|{value}"] = {
                "kind": kind, "value": value,
                "status": text(row.get("status")).strip() or "open",
                "basis": text(row.get("basis")),
            }
        return [result[k] for k in sorted(result)]

    return {
        "challenge": {k: text(b["challenge"].get(k)) for k in ("name", "remote")},
        "params": {text(k): text(v) for k, v in b["params"].items()},
        "verified": rows("verified", ("tag", "fact", "evidence"), "tag"),
        "falsified": rows("falsified", ("tag", "condition", "observed", "reopen", "why"), "tag"),
        "hypotheses": rows("hypotheses", ("tag", "idea", "falsifier", "budget"), "tag"),
        "tooling": rows("tooling", ("name", "how", "why"), "name"),
        "next": [text(s) for s in b["next"]],
        "flags": rows("flags", ("flag", "index", "confidence", "basis"), "flag"),
        "coverage": cov_rows(b.get("coverage") or []),
        "angles": rows("angles", ("name", "result", "at"), "name"),
        "outcomes": outcome_rows(b.get("outcomes") or []),
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


def cmd_coverage_uncovered(db: str) -> int:
    """JSON list of surfaces registered but never tested."""
    cx = connect_readonly(db)
    rows = [
        {"surface": r["surface"], "method": r["method"], "param": r["param"], "scope": r["scope"]}
        for r in cx.execute(
            "SELECT surface, method, param, scope FROM coverage WHERE state='untested' "
            "ORDER BY surface, method, param"
        )
    ]
    print(json.dumps(rows, ensure_ascii=False, indent=2))
    return 0


def _meta_set(cx: sqlite3.Connection, k: str, v: str) -> None:
    cx.execute("INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))


def _run_json_path(db: str) -> str:
    base = os.path.dirname(os.path.abspath(db))
    try:
        with open(os.path.join(base, "CHALLENGE.txt"), encoding="utf-8") as f:
            challenge = f.read().strip()
        if challenge and os.path.isdir(challenge):
            return os.path.join(challenge, "gate", "run.json")
    except OSError:
        pass
    return os.path.join(base, "gate", "run.json")


def cmd_run_set(db: str, args: list[str]) -> int:
    """Record the live instance; on instance change reset scope=instance coverage cells."""
    if not args:
        print("usage: run-set <instance_id> [addr] [cid] [minutes] [--no-reset]", file=sys.stderr)
        return 2
    no_reset = "--no-reset" in args
    argv = [a for a in args if a != "--no-reset"]
    iid = str(argv[0]).strip()
    addr = argv[1] if len(argv) > 1 else ""
    cid = argv[2] if len(argv) > 2 else ""
    minutes = argv[3] if len(argv) > 3 else ""
    cx = connect(db)
    prev = meta_get(cx, "instance_id")
    ts = now()
    reset = 0
    if prev and prev != iid and not no_reset:
        cur = cx.execute("UPDATE coverage SET state='untested', tag='', at=? WHERE scope='instance'", (ts,))
        reset = cur.rowcount or 0
    for k, v in (("instance_id", iid), ("instance_addr", addr), ("instance_cid", cid),
                 ("instance_minutes", minutes), ("instance_started_at", ts),
                 ("instance_updated_at", ts), ("instance_prev", prev)):
        _meta_set(cx, k, v)
    bump(cx)
    cx.commit()
    cx.close()
    data = {"instance_id": iid, "addr": addr, "cid": cid, "minutes": minutes,
            "started_at": ts, "prev_instance_id": prev, "reset_instance_scopes": reset}
    try:
        p = _run_json_path(db)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, p)
    except OSError:
        pass
    print(json.dumps(data, ensure_ascii=False, indent=2))
    return 0


def cmd_run_show(db: str) -> int:
    cx = connect_readonly(db)
    data = {k: meta_get(cx, k) for k in
            ("instance_id", "instance_addr", "instance_cid", "instance_minutes",
             "instance_started_at", "instance_updated_at", "instance_prev")}
    p = _run_json_path(db)
    data["run_json"] = p if os.path.isfile(p) else ""
    print(json.dumps(data, ensure_ascii=False, indent=2))
    return 0


def _parse_claim_args(args: list[str]) -> tuple[str, int, str, bool]:
    force = "--force" in args
    owner = ""
    rest: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--force":
            i += 1
            continue
        if a == "--owner" and i + 1 < len(args):
            owner = args[i + 1]
            i += 2
            continue
        rest.append(a)
        i += 1
    name = rest[0].strip() if rest else ""
    try:
        minutes = int(rest[1]) if len(rest) > 1 else 60
    except ValueError:
        minutes = 60
    owner = owner or os.environ.get("PI_SESSION_ID") or os.environ.get("USER") \
        or os.environ.get("USERNAME") or "unknown"
    return name, minutes, owner, force


def cmd_claim(db: str, args: list[str]) -> int:
    """Take a short lease on an attack surface so parallel agents do not collide."""
    name, minutes, owner, force = _parse_claim_args(args)
    if not name:
        print("usage: claim <name> [minutes] [--owner X] [--force]", file=sys.stderr)
        return 2
    cx = connect(db)
    ts = now()
    row = cx.execute("SELECT owner, expires_at FROM claims WHERE name=?", (name,)).fetchone()
    if row and not force and row["expires_at"] > ts and row["owner"] != owner:
        cx.close()
        print(json.dumps({"error": "claimed", "name": name, "owner": row["owner"],
                          "expires_at": row["expires_at"]}, ensure_ascii=False))
        return 1
    exp = (datetime.now(timezone.utc) + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
    cx.execute("INSERT INTO claims(name,owner,expires_at,at) VALUES(?,?,?,?) "
               "ON CONFLICT(name) DO UPDATE SET owner=excluded.owner, "
               "expires_at=excluded.expires_at, at=excluded.at",
               (name, owner, exp, ts))
    cx.commit()
    cx.close()
    print(json.dumps({"name": name, "owner": owner, "expires_at": exp, "minutes": minutes},
                     ensure_ascii=False))
    return 0


def cmd_claim_list(db: str) -> int:
    cx = connect_readonly(db)
    ts = now()
    rows = [
        {"name": r["name"], "owner": r["owner"], "expires_at": r["expires_at"],
         "active": bool(r["expires_at"] > ts)}
        for r in cx.execute("SELECT name, owner, expires_at FROM claims ORDER BY name")
    ]
    print(json.dumps(rows, ensure_ascii=False, indent=2))
    return 0


def cmd_claim_release(db: str, args: list[str]) -> int:
    if not args:
        print("usage: claim-release <name>", file=sys.stderr)
        return 2
    cx = connect(db)
    cur = cx.execute("DELETE FROM claims WHERE name=?", (args[0],))
    cx.commit()
    cx.close()
    print(json.dumps({"released": args[0], "count": cur.rowcount or 0}, ensure_ascii=False))
    return 0


def cmd_unsubmitted(db: str) -> int:
    """Flags recorded on the board but never confirmed by a platform submit."""
    cx = connect_readonly(db)
    rows = [
        {"flag": r["flag"], "basis": r["basis"]}
        for r in cx.execute("SELECT flag, basis FROM flags WHERE COALESCE(idx,'')='' ORDER BY flag")
    ]
    print(json.dumps(rows, ensure_ascii=False, indent=2))
    return 1 if rows else 0


def cmd_search(db: str, args: list[str]) -> int:
    """全文检索黑板（FTS5 trigram；支持路径/标签/CJK 子串）。"""
    if not args:
        print("usage: search <query> [limit]", file=sys.stderr)
        return 2
    query = args[0]
    try:
        limit = int(args[1]) if len(args) > 1 else 20
    except ValueError:
        limit = 20
    if not os.path.isfile(db):
        print(json.dumps({"error": f"blackboard not found: {db}"}, ensure_ascii=False))
        return 2
    cx = connect(db)
    if cx.execute("SELECT COUNT(*) FROM search_fts").fetchone()[0] == 0:
        rebuild_search(cx)
        cx.commit()
    phrase = '"' + query.replace('"', '""') + '"'
    try:
        if len(query) < 3:
            like = f"%{query}%"
            rows = cx.execute(
                "SELECT kind, ref, substr(text, 1, 80) AS snip FROM search_fts "
                "WHERE kind LIKE ? OR ref LIKE ? OR text LIKE ? LIMIT ?",
                (like, like, like, limit),
            ).fetchall()
        else:
            rows = cx.execute(
                "SELECT kind, ref, snippet(search_fts, 2, '[', ']', '…', 10) AS snip "
                "FROM search_fts WHERE search_fts MATCH ? ORDER BY rank LIMIT ?",
                (phrase, limit),
            ).fetchall()
    except sqlite3.Error as e:
        cx.close()
        print(json.dumps({"error": str(e)}, ensure_ascii=False))
        return 2
    cx.close()
    print(json.dumps(
        [{"kind": r["kind"], "ref": r["ref"], "snippet": r["snip"]} for r in rows],
        ensure_ascii=False, indent=2,
    ))
    return 0


def cmd_status(db: str) -> int:
    """One-line-per-fact machine summary for the orchestrator."""
    cx = connect_readonly(db)
    rev = cx.execute("SELECT v FROM meta WHERE k='rev'").fetchone()
    def count(sql: str, *a) -> int:
        return int(cx.execute(sql, a).fetchone()[0])
    uncovered = [
        {"surface": r["surface"], "method": r["method"], "param": r["param"], "scope": r["scope"]}
        for r in cx.execute(
            "SELECT surface, method, param, scope FROM coverage WHERE state='untested' "
            "ORDER BY surface, method, param"
        )
    ]
    nexts = [r["text"] for r in cx.execute("SELECT text FROM next_steps ORDER BY ord")]
    flags = [{"flag": r["flag"], "index": r["idx"]} for r in cx.execute("SELECT flag, idx FROM flags ORDER BY flag")]
    data = {
        "rev": (rev[0] if rev else "0"),
        "verified": count("SELECT COUNT(*) FROM verified"),
        "falsified": count("SELECT COUNT(*) FROM falsified"),
        "coverage": count("SELECT COUNT(*) FROM coverage"),
        "outcomes": count("SELECT COUNT(*) FROM outcomes"),
        "uncovered": uncovered,
        "flags": flags,
        "next": nexts,
        "instance_id": meta_get(cx, "instance_id"),
        "instance_addr": meta_get(cx, "instance_addr"),
        "instance_minutes": meta_get(cx, "instance_minutes"),
        "instance_started_at": meta_get(cx, "instance_started_at"),
        "handoff_ready": bool(
            count("SELECT COUNT(*) FROM verified") > 0
            and nexts
            and not uncovered
        ),
    }
    print(json.dumps(data, ensure_ascii=False, indent=2))
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
    # 不需要数据库的元数据命令：先处理，避免被 "CTF_GATE_DB required" 拦住
    if cmd == "fields":
        return cmd_fields()
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
        "fields": cmd_fields,
        "schema-version": lambda: cmd_schema_version(db),
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
        "uncovered": lambda: cmd_coverage_uncovered(db),
        "status": lambda: cmd_status(db),
        "run-set": lambda: cmd_run_set(db, args),
        "run-show": lambda: cmd_run_show(db),
        "claim": lambda: cmd_claim(db, args),
        "claim-list": lambda: cmd_claim_list(db),
        "claim-release": lambda: cmd_claim_release(db, args),
        "unsubmitted": lambda: cmd_unsubmitted(db),
        "search": lambda: cmd_search(db, args),
    }
    fn = dispatch.get(cmd)
    if not fn:
        print(f"unknown cmd {cmd}", file=sys.stderr)
        return 2
    return fn()


if __name__ == "__main__":
    sys.exit(main())
