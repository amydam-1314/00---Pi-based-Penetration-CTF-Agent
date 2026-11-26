import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { stripTypeScriptTypes } from "node:module";

const pkg = path.dirname(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1")));
let n = 0; const pass = (s) => { n++; console.log("PASS", s); };

// 1) 语法可解析
stripTypeScriptTypes(fs.readFileSync(path.join(pkg, "ctf-gate/ctf-gate.ts"), "utf8"), { mode: "transform" });
pass("ctf-gate.ts 语法可解析");

// 2) 不再自带 SSH / 口令分支
const src = fs.readFileSync(path.join(pkg, "ctf-gate/ctf-gate.ts"), "utf8");
assert.ok(!/sshpass/.test(src), "不应再有 sshpass");
assert.ok(!/StrictHostKeyChecking/.test(src), "不应再自己拼 ssh");
assert.ok(/createAdapter\(/.test(src), "应调用统一执行后端");
pass("ctf-gate 不含自带 SSH 分支，改用 createAdapter");

// 3) BOARD_FIELDS 不再硬编码
assert.ok(!/const BOARD_FIELDS = \[/.test(src), "不应再有静态字段表");
assert.ok(/gate_db\.py fields/.test(src) || /"fields"\]/.test(src), "应从 gate_db.py fields 读取");
pass("BOARD_FIELDS 来自 gate_db.py 的字段接口");

// 4) 字段接口实际可读且与库一致
const { spawnSync } = await import("node:child_process");
// Windows 上 python3 可能不存在：按候选探测，和扩展里的 pyBin() 一致
let r = null;
for (const py of ["python3", "python", "py"]) {
  const t = spawnSync(py, [path.join(pkg, "db/gate_db.py"), "fields"], { encoding: "utf8" });
  if (t.status === 0) { r = t; break; }
  r = t;
}
assert.equal(r.status, 0, String(r.stderr || r.error));
const parsed = JSON.parse(r.stdout);
for (const f of ["challenge", "params", "verified", "falsified", "hypotheses", "tooling", "next", "flags"]) {
  assert.ok(parsed.fields.includes(f), `缺字段 ${f}`);
}
pass(`字段接口可用（${parsed.fields.length} 项）`);

console.log(`\n${n} ctf-gate checks passed`);
