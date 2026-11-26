import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DbClient } from "../src/db/client.ts";

const here = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"));
const pkgRoot = path.dirname(here);
const gatePy = path.join(pkgRoot, "db", "gate_db.py");
let n = 0; const pass = (s) => { n++; console.log("PASS", s); };

const work = fs.mkdtempSync(path.join(os.tmpdir(), "kit-db-"));
const dbPath = path.join(work, "gate.sqlite");
const c = new DbClient({ gatePy, dbPath });

c.write(["init"]);
assert.equal(c.rev(), "0");
pass("init 后 rev=0");

c.write(["falsify", "t1", "条件：X", "obs"], undefined);
assert.equal(c.rev(), "1");
pass("写入走 gate_db.py，rev=1");

const snap = c.snapshot();
assert.equal(snap.rev, 1);
assert.ok(Array.isArray(snap.board.falsified));
pass("snapshot 返回 {rev, board}");

// 旧 rev 写入必须被拒（并发保护契约）
const cur = JSON.parse(JSON.stringify(snap.board));
const bad = c.run(["import", "--rev", "0"], JSON.stringify(cur));
assert.notEqual(bad.status, 0);
assert.equal(c.rev(), "1");
pass("旧 rev 写入被拒，rev 不变");

fs.rmSync(work, { recursive: true, force: true });
console.log(`\n${n} db checks passed`);
