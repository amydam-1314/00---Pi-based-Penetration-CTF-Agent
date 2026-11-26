#!/usr/bin/env python3
"""证据引用：持久化保存「资源 ID + 相对位置」，执行/排障时再解析成绝对路径。

存档格式（<题目目录>/gate/evidence/INDEX.tsv，制表符分隔）：
  id <TAB> rel <TAB> sha256 <TAB> size <TAB> recorded_at
  id  = <题目目录名>:<rel 去扩展名，斜杠转点>，稳定、可读
  rel = 相对「题目目录」的路径（搬迁后仍然有效）
  只在该行额外记录 abs_at_record（快照，仅排障用，不作依赖）

用法：
  python3 evidence_ref.py record  --challenge <题目目录> --file <文件> [--abs-snapshot]
  python3 evidence_ref.py resolve --challenge <题目目录> --id <id>
  python3 evidence_ref.py list    --challenge <题目目录>
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

INDEX = Path("gate") / "evidence" / "INDEX.tsv"
HEADER = "id\trel\tsha256\tsize\trecorded_at\tabs_at_record\n"


def challenge_id(challenge: Path) -> str:
    return challenge.resolve().name


def make_id(cid: str, rel: str) -> str:
    stem = os.path.splitext(rel)[0].replace("\\", "/").replace("/", ".").replace(" ", "_")
    return f"{cid}:{stem}"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def cmd_record(a) -> int:
    ch = Path(a.challenge).resolve()
    f = Path(a.file)
    if not f.is_absolute():
        print("错误：--file 需要用执行时的绝对路径（落库存档时会转成相对）", file=sys.stderr)
        return 2
    try:
        rel = os.path.relpath(f.resolve(), ch).replace("\\", "/")
    except ValueError:
        print(f"错误：{f} 不在题目目录 {ch} 之下，不能存成相对引用", file=sys.stderr)
        return 2
    if rel.startswith("../"):
        print(f"错误：{f} 超出题目目录，拒绝（rel={rel}）", file=sys.stderr)
        return 2
    idx = ch / INDEX
    idx.parent.mkdir(parents=True, exist_ok=True)
    if not idx.exists():
        idx.write_text(HEADER, encoding="utf-8")
    rid = make_id(challenge_id(ch), rel)
    row = "\t".join(
        [
            rid,
            rel,
            sha256(f),
            str(f.stat().st_size),
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            str(f.resolve()) if a.abs_snapshot else "",
        ]
    )
    with idx.open("a", encoding="utf-8") as fh:
        fh.write(row + "\n")
    print(rid)
    return 0


def cmd_resolve(a) -> int:
    ch = Path(a.challenge).resolve()
    idx = ch / INDEX
    if not idx.exists():
        print(f"没有索引：{idx}", file=sys.stderr)
        return 1
    for line in idx.read_text(encoding="utf-8").splitlines()[1:]:
        cols = line.split("\t")
        if cols and cols[0] == a.id:
            rel = cols[1]
            target = (ch / rel).resolve()
            ok = target.exists()
            print(f"{target}\t{'ok' if ok else 'missing'}")
            return 0 if ok else 1
    print(f"索引里没有该 id：{a.id}", file=sys.stderr)
    return 1


def cmd_list(a) -> int:
    ch = Path(a.challenge).resolve()
    idx = ch / INDEX
    if not idx.exists():
        print(f"没有索引：{idx}", file=sys.stderr)
        return 1
    for line in idx.read_text(encoding="utf-8").splitlines()[1:]:
        if not line.strip():
            continue
        cols = line.split("\t")
        exists = (ch / cols[1]).exists()
        print(f"{cols[0]}\t{cols[1]}\t{'ok' if exists else 'MISSING'}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("record")
    r.add_argument("--challenge", required=True)
    r.add_argument("--file", required=True)
    r.add_argument("--abs-snapshot", action="store_true", help="额外存一份绝对路径快照（仅排障）")
    r.set_defaults(fn=cmd_record)

    v = sub.add_parser("resolve")
    v.add_argument("--challenge", required=True)
    v.add_argument("--id", required=True)
    v.set_defaults(fn=cmd_resolve)

    l = sub.add_parser("list")
    l.add_argument("--challenge", required=True)
    l.set_defaults(fn=cmd_list)

    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
