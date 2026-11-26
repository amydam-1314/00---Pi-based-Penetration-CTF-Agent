import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { stripTypeScriptTypes } from "node:module";

const pkg = path.dirname(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1")));
const raw = fs.readFileSync(path.join(pkg, "extensions/kali-exec.ts"), "utf8");
stripTypeScriptTypes(raw, { mode: "transform" });
// 断言只看代码，不看注释
const src = raw.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n]*/g, " ");
let n = 0; const pass = (s) => { n++; console.log("PASS", s); };

pass("kali-exec.ts 语法可解析");

assert.ok(!/sshpass/.test(src), "不应再有 sshpass");
assert.ok(!/ssh -o/.test(src), "不应自己拼 ssh");
assert.ok(/createAdapter\(/.test(src), "应使用 createAdapter");
assert.ok(/adapter\.wrap\(/.test(src), "执行应走 adapter.wrap");
assert.ok(!/PI_CTF_REMOTE_SSH/.test(src), "不应再有自定义远端开关");
assert.ok(!/PI_KALI_SCRATCH/.test(src), "不应再有 scratch 回退");
pass("kali-exec 只剩 adapter 一条执行路径");

// 后端选择：显式配置优先，且不从 profile 猜主机
const { chooseBackend } = await import("../src/exec/index.ts");
assert.equal(chooseBackend({ config: { execution: { backend: "local" } }, profileTransport: "kali" }), "local");
assert.equal(chooseBackend({ config: { execution: { backend: "ssh" } }, profileTransport: "local" }), "ssh");
pass("Kali 原生配置 execution.backend=local 时，即使 profile=kali 也不会 SSH 回连");

console.log(`\n${n} kali-exec checks passed`);
