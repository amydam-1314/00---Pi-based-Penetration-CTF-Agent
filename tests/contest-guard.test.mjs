import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const agent = path.resolve(import.meta.dirname, '..');
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'pi-contest-guard-'));
const contest = path.join(work, 'contest');
const a = path.join(contest, 'challs', 'a');
const b = path.join(contest, 'challs', 'b');
const checks = [];
const check = (name, fn) => { fn(); checks.push(name); console.log('PASS', name); };
try {
  fs.mkdirSync(a, { recursive: true }); fs.mkdirSync(b, { recursive: true });
  fs.mkdirSync(path.join(contest, 'gate'));
  fs.writeFileSync(path.join(contest, 'challenge-list.md'), '# existing inventory');
  fs.writeFileSync(path.join(contest, '.ctf-gate'), 'legacy marker must not override contest');
  fs.writeFileSync(path.join(a, '.ctf-gate'), ''); fs.writeFileSync(path.join(b, '.ctf-gate'), '');
  const unmarked = path.join(contest, 'challs', 'unmarked'); fs.mkdirSync(unmarked);
  const singleUnmarked = path.join(work, 'single-unmarked'); fs.mkdirSync(singleUnmarked);
  process.env.PI_CODING_AGENT_DIR = path.join(work, 'agent');
  process.env.PI_CTF_BOARDS_ROOT = path.join(work, 'agent', 'ctf-boards'); // 测试黑板隔离，不写生产 D 盘
  delete process.env.PI_CTF_GATE;
  delete process.env.PI_SUBAGENT_PARENT_SESSION;
  delete process.env.PI_ORCHESTRATOR;
  const policy = await import(pathToFileURL(path.join(agent, 'policies/ctf-directory.ts')));
  const orch = await import(pathToFileURL(path.join(agent, 'extensions/orchestrator-guard.ts')));
  const gate = await import(pathToFileURL(path.join(agent, 'ctf-gate/ctf-gate.ts')));
  check('contest detection ignores legacy .ctf-gate/gate evidence', () => assert.equal(policy.isContestRoot(contest), true));
  check('marked individual challenge accepted by launch preflight', () => assert.equal(policy.ctfLaunchProblem(a), undefined));
  check('contest root rejected by launch preflight', () => assert.match(policy.ctfLaunchProblem(contest), /比赛根目录/));
  check('nonexistent cwd rejected before launch', () => assert.match(policy.ctfLaunchProblem(path.join(work, 'missing')), /不存在/));
  check('unmarked competition challenge rejected before launch', () => assert.match(policy.ctfLaunchProblem(unmarked), /\.ctf-gate/));
  check('unmarked standalone challenge rejected before launch', () => assert.match(policy.ctfLaunchProblem(singleUnmarked), /\.ctf-gate/));
  check('unmarked competition challenge not recognized by gate', () => assert.equal(gate.__testTaskRoot(unmarked), null));
  check('ctf gate never resolves contest root', () => assert.equal(gate.__testTaskRoot(contest), null));
  check('ctf gate resolves each child to its own marker', () => {
    assert.equal(gate.__testTaskRoot(a).toLowerCase(), a.replaceAll('\\', '/').toLowerCase());
    assert.equal(gate.__testTaskRoot(b).toLowerCase(), b.replaceAll('\\', '/').toLowerCase());
  });
  const h = new Map();
  orch.default({ on(name, fn) { h.set(name, fn); } });
  const call = async (toolName, input) => h.get('tool_call')({ toolName, input });
  assert.equal((await call('subagent', { agent: 'ctf', cwd: contest })).block, true);
  assert.equal((await call('subagent', { agent: 'ctf-solver', cwd: contest })).block, true);
  checks.push('main ctf launch at contest root blocked'); console.log('PASS main ctf launch at contest root blocked');
  assert.equal((await call('subagent', { workflow: 'parallel', args: { tasks: [{ agent: 'ctf', cwd: contest }] } })).block, true);
  checks.push('parallel contest-root child blocked'); console.log('PASS parallel contest-root child blocked');
  assert.equal((await call('subagent_launch', { agent: 'ctf', cwd: contest, key: 'a' })).block, true);
  checks.push('workflow child approval blocks contest root'); console.log('PASS workflow child approval blocks contest root');
  assert.equal(await call('subagent', { agent: 'ctf', cwd: a }), undefined);
  assert.equal(await call('subagent', { agent: 'recon', cwd: contest }), undefined);
  checks.push('individual ctf and inventory recon remain allowed'); console.log('PASS individual ctf and inventory recon remain allowed');
  const template = JSON.parse(fs.readFileSync(path.join(agent, 'ctf-gate/BOARD.template.json'), 'utf8'));
  check('published BOARD template passes actual validator', () => assert.deepEqual(gate.validateBoard(template), []));
  check('object tooling accepted; string tooling rejected', () => {
    assert.deepEqual(gate.validateBoard({ ...template, tooling: [{ name: 'sagemath' }] }), []);
    assert.ok(gate.validateBoard({ ...template, tooling: ['sagemath'] }).some(x => x.includes('tooling[0]')));
  });
  check('extra top-level keys rejected', () => assert.ok(gate.validateBoard({ ...template, next_steps: [] }).length > 0));
  check('existing geek2026 root is rejected and c25/c28/c55 resolve independently', () => {
    const real = 'D:/2026/pi-ctf/geek2026';
    if (!fs.existsSync(real)) return;
    assert.equal(gate.__testTaskRoot(real), null);
    assert.ok(policy.ctfLaunchProblem(real));
    for (const name of ['c25-ezoffice', 'c28-bigx', 'c55-echo']) {
      const task = `${real}/challs/${name}`;
      assert.equal(gate.__testTaskRoot(task).toLowerCase(), task.toLowerCase());
      assert.equal(policy.ctfLaunchProblem(task), undefined);
    }
  });
  const hooks = new Map();
  gate.default({ on(name, fn) { hooks.set(name, fn); }, registerCommand() {} });
  for (const bad of [contest, unmarked]) {
    const wrong = await hooks.get('tool_call')({ toolName: 'bash', input: { command: 'echo test' } }, { cwd: bad });
    assert.equal(wrong.block, true); assert.equal(wrong.terminate, true);
  }
  checks.push('child-side wrong/unmarked cwd terminates without model/tool execution'); console.log('PASS child-side wrong/unmarked cwd terminates without model/tool execution');
  check('validation does not create owner boards or databases', () => assert.equal(fs.existsSync(path.join(work, 'agent', 'ctf-boards')) && fs.existsSync('D:/2026/pi-ctf/ctf-boards'), false));
  const ctx = { cwd: a, hasUI: false, sessionManager: {
    getSessionFile: () => path.join(work, 'parent.jsonl'),
    getSessionId: () => 'regression-parent', getHeader: () => ({}),
  } };
  await hooks.get('session_start')({}, ctx);
  const snapshot = { toolName: 'read', input: { path: path.join(a, 'gate/BOARD.json') } };
  assert.equal(await hooks.get('tool_call')(snapshot, ctx), undefined);
  const invalidWrite = () => hooks.get('tool_call')({ toolName: 'write', input: {
    path: path.join(a, 'gate/BOARD.json'), content: JSON.stringify({ ...template, tooling: ['sagemath'] }),
  } }, ctx);
  const firstError = await invalidWrite();
  const secondError = await invalidWrite();
  check('repeated invalid BOARD keeps blocking without terminating', () => {
    assert.equal(firstError.block, true); assert.equal(firstError.terminate, undefined);
    assert.equal(secondError.block, true); assert.equal(secondError.terminate, undefined);
  });

  // 执行链：wrapper 必须与 _shared 规范版一致；旧副本自动备份并替换。
  fs.writeFileSync(path.join(a, 'run.sh'), '#!/bin/bash\n# stale copy from contest root\necho old\n');
  fs.writeFileSync(path.join(contest, 'run.sh'), '#!/bin/bash\necho contest-root\n');
  await hooks.get('session_start')({}, ctx);
  check('stale task run.sh replaced with canonical wrapper', () => {
    const cur = fs.readFileSync(path.join(a, 'run.sh'), 'utf8');
    assert.ok(cur.includes('CTF_GATE_DB'), 'task run.sh 未刷新');
    assert.ok(!cur.includes('contest-root'), '任务目录仍留着比赛根脚本');
  });
  check('replaced wrapper is backed up under gate/archive', () => {
    const arch = path.join(work, 'agent', 'ctf-boards');
    const found = [];
    const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else found.push(p); } };
    walk(arch);
    assert.ok(found.some(p => /archive[\\/]wrappers-[^\\/]+[\\/]run\.sh$/.test(p)), '未找到 wrapper 备份');
  });
  check('copying a contest-root wrapper into the task is blocked', () => {
    const reason = gate.__testGuard(a, 'cp ' + path.join(contest, 'run.sh') + ' ' + path.join(a, 'run.sh'));
    assert.ok(reason, '未拦截复制');
    assert.ok(/闸门|run\.sh/.test(reason), `拦截原因不可读: ${reason}`);
  });
  // Real check.sh/SQLite agreement is exercised through WSL in execution-chain.test.mjs.
  console.log(`\n${checks.length} checks passed. No target requests or model launches.`);
} finally { fs.rmSync(work, { recursive: true, force: true }); }
