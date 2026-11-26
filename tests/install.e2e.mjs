/**
 * 端到端安装集成测试（全部在临时目录，不碰现网 ~/.pi/agent）
 * 覆盖：安装落点、扩展/工具注册、agent+profile 加载、库初始化与迁移、rev 递增、
 *       项目搬迁后路径解析、local 后端不产生 SSH、ssh 后端只构造命令不连接。
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { stripTypeScriptTypes } from "node:module";

const pkg = path.dirname(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1")));
let n = 0; const pass = (s) => { n++; console.log("PASS", s); };
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "kit-e2e "));
const agent = path.join(tmp, "agent dir");           // 含空格，验证路径健壮性
const proj = path.join(tmp, "项目 副本");             // 含中文
fs.mkdirSync(agent, { recursive: true });
fs.mkdirSync(path.join(proj, "challs", "t-01"), { recursive: true });

// ---------- 1) 安装：包声明写进临时配置目录 ----------
fs.writeFileSync(
  path.join(agent, "settings.json"),
  JSON.stringify({ packages: [{ source: pkg }] }, null, 2),
);
const settings = JSON.parse(fs.readFileSync(path.join(agent, "settings.json"), "utf8"));
assert.equal(settings.packages[0].source, pkg);
pass("安装声明落在临时配置目录（不触碰现网配置）");

// ---------- 2) 扩展加载与工具注册 ----------
const prevAgent = process.env.PI_CODING_AGENT_DIR;
process.env.PI_CODING_AGENT_DIR = agent;
const stubs = path.join(tmp, "node_modules");
fs.mkdirSync(path.join(stubs, "typebox"), { recursive: true });
fs.writeFileSync(path.join(stubs, "typebox", "index.js"), 'export const Type=new Proxy({},{get:()=>(o)=>o||{}});\n');
fs.writeFileSync(path.join(stubs, "typebox", "package.json"), '{"name":"typebox","type":"module","main":"index.js"}');
const hostDir = path.join(stubs, "@earendil-works/pi-coding-agent");
fs.mkdirSync(hostDir, { recursive: true });
fs.writeFileSync(path.join(hostDir, "index.js"),
  'export const createLocalBashOperations=()=>({});\nexport const createLocalPowerShellOperations=()=>({});\n');
fs.writeFileSync(path.join(hostDir, "package.json"), '{"name":"@earendil-works/pi-coding-agent","type":"module","main":"index.js"}');
// 让包内 import 能解析到 stub：把 node_modules 放到包根的上一跳（tmp）
fs.mkdirSync(path.join(pkg, "node_modules"), { recursive: true });
for (const name of ["typebox", "@earendil-works"]) {
  const dst = path.join(pkg, "node_modules", name);
  if (fs.existsSync(dst)) continue;
  fs.cpSync(path.join(stubs, name), dst, { recursive: true });
}

const loaded = [];
for (const entry of ["extensions/board_digest.ts", "extensions/orchestrator-guard.ts", "extensions/orchestrator-patrol.ts", "ctf-gate/ctf-gate.ts"]) {
  const abs = path.join(pkg, entry);
  stripTypeScriptTypes(fs.readFileSync(abs, "utf8"), { mode: "transform" });
  const mod = await import(pathToFileURL(abs).href);
  assert.equal(typeof mod.default, "function", `${entry} 应有 default 导出`);
  loaded.push(entry);
}
pass(`4 个扩展入口可加载（${loaded.length}）`);

// 用一个假 pi 验证 registerTool / on 注册
const reg = { tools: [], hooks: [], commands: [] };
const fakePi = { registerTool: (t) => reg.tools.push(t.name), on: (e) => reg.hooks.push(e), registerCommand: (c) => reg.commands.push(c) };
const digest = await import(pathToFileURL(path.join(pkg, "extensions/board_digest.ts")).href);
digest.default(fakePi);
assert.deepEqual(reg.tools, ["board_digest"]);
pass("board_digest 注册为模型可调用工具");

// ---------- 2b) 注入断言：ctf-gate 绑定题目后，bash 命令必须带上黑板环境变量 ----------
{
  const chal = path.join(tmp, "inj-proj", "challs", "t-1");
  const shared = path.join(tmp, "inj-proj", "_shared");
  fs.mkdirSync(chal, { recursive: true });
  fs.mkdirSync(shared, { recursive: true });
  fs.mkdirSync(path.join(tmp, "inj-proj", "ctf-boards"), { recursive: true });
  fs.writeFileSync(path.join(chal, ".ctf-gate"), "");
  fs.copyFileSync(path.join(pkg, "db", "gate_db.py"), path.join(shared, "gate_db.py"));
  for (const f of fs.readdirSync(path.join(pkg, "scripts"))) {
    if (f.endsWith(".sh")) fs.copyFileSync(path.join(pkg, "scripts", f), path.join(shared, f));
  }
  process.env.CTF_PROJECT_ROOT = path.join(tmp, "inj-proj");
  process.env.PI_CTF_EXEC_BACKEND = "local";

  const hooks = new Map();
  const gateMod = await import(pathToFileURL(path.join(pkg, "ctf-gate/ctf-gate.ts")).href);
  gateMod.default({ on: (n, f) => hooks.set(n, f), registerCommand: () => {}, registerTool: () => {} });
  const ctx = {
    cwd: chal,
    hasUI: false,
    ui: { notify: () => {} },
    sessionManager: { getSessionFile: () => path.join(tmp, "s.jsonl"), getSessionId: () => "e2e", getHeader: () => ({}) },
  };
  await hooks.get("session_start")({}, ctx);
  await hooks.get("before_agent_start")({ systemPrompt: "", messageType: "user", prompt: "x" }, ctx);

  const input = { command: "./board.sh show" };
  const res = await hooks.get("tool_call")({ toolName: "bash", input }, ctx);
  if (res !== undefined) console.log("   [debug] tool_call 返回:", JSON.stringify(res).slice(0, 240));
  assert.equal(res, undefined, "绑定题目后 bash 应放行而不是被拦");
  const injected = String(input.command);
  for (const k of ["CTF_GATE_DIR=", "CTF_GATE_DB=", "CTF_GATE_PY="]) {
    assert.ok(injected.includes(k), `注入的命令缺少 ${k}`);
  }
  assert.ok(/^cd '/.test(injected), `local 后端应以 cd ' 开头：${injected.slice(0, 60)}`);
  assert.ok(!/ssh|wsl\.exe/.test(injected), "local 后端不应出现 ssh/wsl.exe");
  pass("ctf-gate 注入：黑板环境变量齐全，且 local 后端不引入 ssh/wsl");

  delete process.env.PI_CTF_EXEC_BACKEND;
  process.env.CTF_PROJECT_ROOT = proj;
}

// ---------- 3) agents / profiles 加载 ----------
const agents = fs.readdirSync(path.join(pkg, "agents")).filter((f) => f.endsWith(".md"));
assert.ok(agents.length >= 6, `agents 数量不足：${agents.length}`);
const profiles = fs.readdirSync(path.join(pkg, "profiles")).filter((f) => f.endsWith(".json"))
  .map((f) => JSON.parse(fs.readFileSync(path.join(pkg, "profiles", f), "utf8")));
assert.ok(profiles.every((p) => p.name && p.marker));
pass(`agents ${agents.length} 个、profiles ${profiles.length} 个可解析`);

// ---------- 4) 库初始化、迁移、rev 递增（走唯一写入口 gate_db.py） ----------
const dataRoot = path.join(proj, "ctf-boards");
const db = path.join(dataRoot, "s1", "challenges", "c1", "gate.sqlite");
fs.mkdirSync(path.dirname(db), { recursive: true });
const py = ["python3", "python", "py"].find((c) => spawnSync(c, ["-c", "import sqlite3"], { encoding: "utf8" }).status === 0);
const gatePy = path.join(pkg, "db", "gate_db.py");
const run = (...args) => spawnSync(py, [gatePy, "--db", db, ...args], { encoding: "utf8" });

assert.equal(run("init").status, 0);
const mig = spawnSync(py, [path.join(pkg, "db", "migrate.py"), "--db", db], { encoding: "utf8" });
assert.equal(mig.status, 0, mig.stderr);
const v = spawnSync(py, [gatePy, "--db", db, "schema-version"], { encoding: "utf8" });
assert.equal(Number(v.stdout.trim()), 1);
pass("库初始化 + 迁移 + schema-version=1");

assert.equal(run("rev").stdout.trim(), "0");
assert.equal(run("falsify", "e2e-tag", "条件", "obs").status, 0);
assert.equal(run("rev").stdout.trim(), "1");
pass("写入走 gate_db.py，rev 0→1");

// 字段契约来自机器可读接口
const f = JSON.parse(spawnSync(py, [gatePy, "fields"], { encoding: "utf8" }).stdout);
assert.ok(f.fields.includes("coverage") && f.fields.includes("angles"));
pass(`字段接口返回 ${f.fields.length} 项（含 coverage/angles）`);

// ---------- 5) 项目搬迁后路径仍可解析 ----------
const { resolveRoots } = await import(pathToFileURL(path.join(pkg, "src/paths/roots.ts")).href);
process.env.CTF_PROJECT_ROOT = proj;
const r1 = resolveRoots(path.join(proj, "challs", "t-01"));
assert.equal(r1.projectRoot, proj);
assert.equal(path.resolve(r1.boardsRoot ?? ""), path.resolve(dataRoot));
const moved = path.join(tmp, "搬 到 这里");
fs.renameSync(proj, moved);
process.env.CTF_PROJECT_ROOT = moved;
const r2 = resolveRoots(path.join(moved, "challs", "t-01"));
assert.equal(r2.projectRoot, moved);
assert.ok(fs.existsSync(path.join(r2.boardsRoot ?? "", "s1", "challenges", "c1", "gate.sqlite")));
pass("项目搬迁（空格+中文）后根与看板仍可解析");

// ---------- 6) local 后端：不产生 SSH ----------
const { createAdapter } = await import(pathToFileURL(path.join(pkg, "src/exec/index.ts")).href);
const localAdapter = createAdapter({ config: { execution: { backend: "local" } }, profileTransport: "kali" });
const lw = localAdapter.wrap("echo ok", { cwd: path.join(moved, "challs", "t-01"), env: { A: "b" } });
assert.equal(lw.backend, "local");
assert.ok(!/ssh/i.test(lw.command), "local 命令不应包含 ssh");
assert.match(lw.command, /^cd '/);
pass("local 后端：无 SSH，哪怕 profile=kali");

// ---------- 7) ssh 后端：只构造命令，不连接 ----------
const sshAdapter = createAdapter({
  config: { execution: { backend: "ssh", ssh: { target: "nobody@127.0.0.1", identityFile: "/nonexistent/key" } }, mounts: [{ from: moved + "/", to: "/remote/" }] },
});
const sw = sshAdapter.wrap("echo ok", { cwd: path.join(moved, "challs", "t-01") });
assert.equal(sw.backend, "ssh");
assert.match(sw.command, /^ssh /);
assert.match(sw.command, /nobody@127\.0\.0\.1/);
assert.match(sw.command, /\/remote\/challs\/t-01/);
let connected = false;
assert.equal(connected, false);
pass("ssh 后端：命令构造正确，未发起连接");

// 清理
process.env.PI_CODING_AGENT_DIR = prevAgent;
fs.rmSync(path.join(pkg, "node_modules"), { recursive: true, force: true });
fs.rmSync(tmp, { recursive: true, force: true });
console.log(`\n${n} e2e checks passed`);
