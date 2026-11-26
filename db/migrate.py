#!/usr/bin/env python3
"""按 PRAGMA user_version 应用 db/migrations/*.sql（只向前；先备份）。

用法: python3 migrate.py --db <gate.sqlite> [--dry-run]
"""
from __future__ import annotations
import argparse, shutil, sqlite3, sys
from datetime import datetime, timezone
from pathlib import Path

MIG = Path(__file__).resolve().parent / "migrations"


def migrations() -> list[tuple[int, Path]]:
    out = []
    for f in sorted(MIG.glob("*.sql")):
        head = f.name.split("_", 1)[0]
        if head.isdigit():
            out.append((int(head), f))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    db = Path(a.db).resolve()
    db.parent.mkdir(parents=True, exist_ok=True)

    cx = sqlite3.connect(str(db))
    cur = cx.execute("PRAGMA user_version;").fetchone()[0]
    todo = [(n, f) for n, f in migrations() if n > cur]
    if not todo:
        print(f"schema 已是最新（user_version={cur}）")
        return 0
    print(f"user_version={cur} → 待应用 {[n for n, _ in todo]}")
    if a.dry_run:
        return 0
    if db.exists() and db.stat().st_size > 0:
        bak = db.with_suffix(f".bak-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}")
        shutil.copy2(db, bak)
        print(f"已备份 → {bak}")
    for n, f in todo:
        sql = f.read_text(encoding="utf-8")
        cx.executescript(sql)
        cx.commit()
        v = cx.execute("PRAGMA user_version;").fetchone()[0]
        if v != n:
            print(f"迁移 {f.name} 执行后 user_version={v}，期望 {n}", file=sys.stderr)
            return 1
        print(f"已应用 {f.name} → user_version={v}")
    cx.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
