/**
 * orchestrator-patrol.ts — 主 agent 定时巡检（2 分钟）
 *
 * 不是"提醒你去查"，而是**自己去读子 agent 运行态**，算出每个 run 的轮数/状态，
 * 连同建议一起发给主 agent。主 agent 只需按建议 steer/stop。
 *
 * 数据源（pi-subagents 运行态目录）：
 *   %TEMP%\pi-subagents-user-<user>\async-subagent-runs\
 *     ├── .active-runs                    （活跃 run 清单）
 *     └── <runId>/
 *           ├── events.jsonl               （逐事件；turn 相关行可数轮数）
 *           └── output-0.log               （stdout）
 *
 * 只读文件，不调 subagent 工具。仅主会话启用；闲置 10 分钟跳过。
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { loadEnv, resolveRoots } from "../src/paths/roots.ts";

const ENV = loadEnv();
const ROOTS = resolveRoots(process.cwd());

/** 向上找 ctf-boards 根（最多 5 层） */
function findBoardsRoot(start: string): string | null {
  let d = start;
  for (let i = 0; i < 5; i++) {
    const p = path.join(d, "ctf-boards");
    try { if (fs.statSync(p).isDirectory()) return p; } catch { /* next */ }
    const up = path.dirname(d);
    if (up === d) break;
    d = up;
  }
  return null;
}

/** 由题目录定位它对应的 gate.sqlite（匹配 CHALLENGE.txt 内容） */
function findBoardDb(taskDir: string): string | null {
  if (!taskDir) return null;
  const root = findBoardsRoot(taskDir);
  if (!root) return null;
  const key = taskDir.replace(/\\/g, "/").toLowerCase();
  let sess: string[] = [];
  try { sess = fs.readdirSync(root); } catch { return null; }
  for (const s of sess) {
    const chDir = path.join(root, s, "challenges");
    let hs: string[] = [];
    try { hs = fs.readdirSync(chDir); } catch { continue; }
    for (const h of hs) {
      const cd = path.join(chDir, h);
      const tagF = path.join(cd, "CHALLENGE.txt");
      try {
        const c = fs.readFileSync(tagF, "utf8").replace(/\\/g, "/").trim().toLowerCase();
        if (!c) continue;
        if (c === key || key.endsWith(c) || c.endsWith(key)) {
          const db = path.join(cd, "gate.sqlite");
          if (fs.existsSync(db)) return db;
        }
      } catch { /* no tag */ }
    }
  }
  return null;
}

/** 读板摘要：仅用于定位库并生成 dump 命令（不代读内容） */
function boardDbOf(taskDir: string): string | null {
  return taskDir ? findBoardDb(taskDir) : null;
}

/** Windows 盘符路径 → WSL 路径（主 agent 的 bash 在 WSL） */
function toWsl(p: string): string {
  const m = /^([A-Za-z]):[\\/](.*)$/.exec(p);
  return m ? `/mnt/${m[1].toLowerCase()}/${m[2].replace(/\\/g, "/")}` : p;
}

const PATROL_MS = Number(process.env.PI_PATROL_MS || 60_000);   // 巡检周期：1 分钟（原 2 分钟）
const IDLE_SKIP_MS = Number(process.env.PI_PATROL_IDLE_MS || 600_000);
const TURN_LIMIT_DEFAULT = Number(process.env.PI_CTF_TURN_LIMIT || 45);  // 与 ctf-gate 默认一致（45 软限 + 10 缓冲）
/** 题目根目录（仅当 events 里抓不到完整路径时才用；不设则跳过 turn_limit 查询走默认 100） */
const CHALLS_ROOT = (process.env.PI_CTF_CHALLS_ROOT || "").replace(/\\/g, "/");
/** 建议阈值：超过 80% 上限就提醒 */
const WARN_RATIO = 0.8;

const LOG_PATH = process.env.PI_PATROL_LOG === "off"
  ? ""
  : (process.env.PI_PATROL_LOG || path.join(os.homedir(), ".pi", "agent", "patrol.log"));
/** 进程短标识：多个 Pi 窗口都挂巡检、都写同一个日志时能区分是谁写的 */
const PID_TAG = String(process.pid).slice(-5);
function plog(msg: string) {
  if (!LOG_PATH) return;
  try { fs.appendFileSync(LOG_PATH, `${new Date().toISOString()} [${PID_TAG}] ${msg}\n`); } catch { /* ignore */ }
}

function tmpRoot(): string | null {
  const t = process.env.TEMP || process.env.TMP || os.tmpdir();
  if (!t) return null;
  try {
    for (const d of fs.readdirSync(t)) {
      if (/^pi-subagents-user-/.test(d)) return path.join(t, d);
    }
  } catch { /* ignore */ }
  return null;
}

interface RunInfo {
  id: string;
  task: string;        // 题目名（challs/xxx 的末段；抓不到用短 id）
  taskDir: string;     // 题目完整路径（能抓到就用于读 turn_limit）
  turns: number;       // 轮数（events 里 turn 事件数）
  turnsKnown: boolean; // 是否真数到了 turn 事件（false = 解析不出，别当 0 轮）
  lastMs: number;      // 最后活动距今 ms
  limit: number;       // 该题轮数上限（gate/turn_limit，缺省 100）
}

/**
 * Kali 路径 → Windows 路径（本扩展在 Windows 侧执行，/mnt/... 直接 existsSync 必 false）。
 * 映射优先取 env.json 的 mounts（反查），其次按 /mnt/<盘>/ 约定；都不匹配就原样返回。
 */
function toWinPath(p: string): string {
  const s = p.replace(/\\/g, "/");
  for (const m of ENV.mounts ?? []) {
    const to = (m.to || "").replace(/\\/g, "/").replace(/\/+$/, "");
    if (!to) continue;
    if (s === to || s.startsWith(to + "/")) {
      const from = (m.from || "").replace(/\\/g, "/").replace(/\/+$/, "");
      return from + s.slice(to.length);
    }
  }
  const m2 = /^\/mnt\/([a-zA-Z])\/(.*)$/.exec(s);
  if (m2) return `${m2[1].toUpperCase()}:/${m2[2]}`;
  return s;
}

/**
 * 解析 run 的题目目录（不依赖任何固定目录名，换比赛照样成立）：
 *  1) run 目录里的元数据（state/launch/meta/run .json 的 cwd 字段）—— 最可靠
 *  2) events.jsonl 里的 "cwd":"..."
 *  3) events 里任何绝对路径，其目录下存在 gate/turn_limit 或 .ctf-gate
 *  4) events 里所有绝对路径里最长的一个（截到包含 gate/ 或文件名前的目录）
 */
function resolveTaskDir(runDir: string, evRaw: string): string {
  const tryDir = (raw: string): string | null => {
    if (!raw) return null;
    let d = toWinPath(raw.trim()).replace(/\/+$/, "");
    // 若给的是文件路径，取所在目录
    if (/\.(json|jsonl|log|txt|py|sh)$/i.test(d)) d = path.dirname(d);
    // 逐级向上最多 4 层，找 gate/turn_limit 或 .ctf-gate
    for (let i = 0; i < 5 && d && d !== path.dirname(d); i++) {
      try {
        if (fs.existsSync(path.join(d, "gate", "turn_limit"))) return d;
        if (fs.existsSync(path.join(d, ".ctf-gate"))) return d;
      } catch { /* ignore */ }
      d = path.dirname(d);
    }
    return null;
  };

  // 1) 元数据文件
  for (const f of ["state.json", "launch.json", "meta.json", "run.json", "info.json"]) {
    try {
      const j = JSON.parse(fs.readFileSync(path.join(runDir, f), "utf8"));
      for (const k of ["cwd", "workingDirectory", "workdir", "dir", "taskDir", "challengeDir"]) {
        const v = (j as any)?.[k];
        if (typeof v === "string" && v) {
          const hit = tryDir(v);
          if (hit) return hit;
        }
      }
    } catch { /* ignore */ }
  }
  // 2) events 里的 cwd 字段
  if (evRaw) {
    const reCwd = /"cwd"\s*:\s*"([^"]{3,})"/g;
    let m: RegExpExecArray | null;
    while ((m = reCwd.exec(evRaw))) {
      const hit = tryDir(m[1]);
      if (hit) return hit;
    }
    // 3) events 里所有绝对路径（Windows 盘符 或 /mnt/），逐个试
    const reAbs = /((?:[A-Za-z]:[\\/]|\/mnt\/)[^"\\s'<>|]+)/g;
    const seen = new Set<string>();
    while ((m = reAbs.exec(evRaw))) {
      const cand = m[1];
      if (seen.has(cand)) continue;
      seen.add(cand);
      const hit = tryDir(cand);
      if (hit) return hit;
      if (seen.size > 200) break;
    }
  }
  return "";
}

/** 从 events.jsonl 里数 turn、抓 cwd 题目名，并取最后修改时间 */
function readRun(dir: string, id: string): RunInfo | null {
  const ev = path.join(dir, "events.jsonl");
  let turns = 0;
  let task = "";
  let taskDir = "";
  let lastMs = Date.now();
  try {
    const st = fs.statSync(ev);
    lastMs = Date.now() - st.mtimeMs;
  } catch { /* 无 events，用目录时间 */ }
  try {
    const st = fs.statSync(dir);
    if (Date.now() - st.mtimeMs < lastMs) lastMs = Date.now() - st.mtimeMs;
  } catch { /* ignore */ }
  try {
    const raw = fs.readFileSync(ev, "utf8");
    for (const line of raw.split("\n")) {
      if (!line) continue;
      if (/"type"\s*:\s*"turn_(start|end)"/.test(line) || /"turn(Index|_start)"/.test(line)) turns += 1;
    }
    if (turns) turns = Math.ceil(turns / 2);   // turn_start + turn_end 成对
    taskDir = resolveTaskDir(dir, raw);        // 多源解析，不依赖 challs/ 目录名
  } catch { /* ignore */ }
  if (!taskDir) taskDir = resolveTaskDir(dir, "");
  if (taskDir) task = path.basename(taskDir);
  if (!task) task = id.slice(0, 8);
  // 该题轮数上限：优先 taskDir（从 events 抓到的真实路径），其次 CHALLS_ROOT + task
  let limit = TURN_LIMIT_DEFAULT;
  const candidates: string[] = [];
  if (taskDir) candidates.push(path.join(taskDir, "gate", "turn_limit"));
  if (task && CHALLS_ROOT) candidates.push(path.join(CHALLS_ROOT, task, "gate", "turn_limit"));
  for (const f of candidates) {
    try {
      if (fs.existsSync(f)) {
        const n = Number(fs.readFileSync(f, "utf8").trim());
        if (Number.isFinite(n) && n > 0) { limit = n; break; }
      }
    } catch { /* ignore */ }
  }
  const turnsKnown = turns > 0;
  return { id, task, taskDir, turns, turnsKnown, lastMs, limit };
}

/** 当前会话文件（.jsonl）；由 session_start 写入。空 = 不做会话过滤（宁可多报） */
let MY_SESSION = "";

/**
 * 只报"本会话派的" run：status.json 里的 sessionId 指向派活的主会话文件。
 * 多个 Pi 窗口各自派活、共用同一个 runs 目录 → 不过滤会把别人的 run 也报上来。
 */
function belongsToMe(runDir: string): boolean {
  if (!MY_SESSION) return true;
  try {
    const j = JSON.parse(fs.readFileSync(path.join(runDir, "status.json"), "utf8"));
    const sid = String((j as any)?.sessionId || "");
    if (!sid) return true;                    // 老 run 没有 sessionId → 保留
    const mine = path.basename(MY_SESSION).toLowerCase();
    const theirs = path.basename(sid).toLowerCase();
    if (!mine) return true;
    return theirs === mine || sid.toLowerCase().includes(mine);
  } catch {
    return true;                              // 读不到就保留（宁可多报）
  }
}

/** 读 run 的 status.json，返回 state（running/queued/paused/complete/failed/stopped）；读不到返回 "" */
function runState(runDir: string): string {
  try {
    const j = JSON.parse(fs.readFileSync(path.join(runDir, "status.json"), "utf8"));
    return String((j as any)?.state || "");
  } catch {
    return "";
  }
}

/**
 * 只有这些 state 值得巡检。
 * complete/failed/stopped：已结束，一定会误报 → 过滤。
 * paused：被 interrupt，不会自己继续（只在等主 agent resume）→ 不算活跃，否则一直提醒。
 */
const LIVE_STATES = new Set(["running", "queued"]);

function collect(): RunInfo[] {
  const root = tmpRoot();
  if (!root) return [];
  const runsDir = path.join(root, "async-subagent-runs");
  const out: RunInfo[] = [];
  let active: string[] = [];
  try {
    const raw = fs.readFileSync(path.join(runsDir, ".active-runs"), "utf8").trim();
    if (raw) {
      // 可能是 JSON 数组、JSON 对象或逐行 id
      try {
        const j = JSON.parse(raw);
        active = Array.isArray(j) ? j.map(String)
          : (j && typeof j === "object") ? Object.keys(j) : [];
      } catch {
        active = raw.split(/[\s,]+/).filter(Boolean);
      }
    }
  } catch { /* 无清单就扫目录 */ }
  if (!active.length) {
    // fallback：目录里可能有几百个历史 run，必须按 mtime 降序取最近的（否则全是旧目录）
    try {
      active = fs.readdirSync(runsDir)
        .filter((d) => !d.startsWith(".") && !d.startsWith("@"))
        .map((d) => {
          try { return { d, m: fs.statSync(path.join(runsDir, d)).mtimeMs }; } catch { return null; }
        })
        .filter((x): x is { d: string; m: number } => !!x)
        .sort((a, b) => b.m - a.m)
        .slice(0, 12)
        .map((x) => x.d);
    } catch { return []; }
  }
  for (const id of active.slice(0, 16)) {
    const dir = path.join(runsDir, id);
    try { if (!fs.statSync(dir).isDirectory()) continue; } catch { continue; }
    const st = runState(dir);
    // status.json 有 state 就按它过滤；读不到（异常终止/被 kill 的老 run）就按 events.jsonl 判断
    if (st && !LIVE_STATES.has(st)) continue;
    if (!st) {
      // 空壳目录（只剩 control/result-index，无 status.json）直接跳过，否则会报满一小时
      const ev = path.join(dir, "events.jsonl");
      if (!fs.existsSync(ev)) continue;
      try {
        if (Date.now() - fs.statSync(ev).mtimeMs > 3 * 60_000) continue;  // 3 分钟没动即视为已结束
      } catch { continue; }
    }
    // 只报本会话派的 run（多窗口共用同一 runs 目录，不过滤会报别人家的）
    if (!belongsToMe(dir)) continue;
    const r = readRun(dir, id);
    if (r) out.push(r);
  }
  // 兜底：只保留 60 分钟内有活动的（容忍长命令，如 run-long.sh 240s；空壳目录已由上面 events.jsonl 判据滤掉）
  return out.filter((r) => r.lastMs < 60 * 60_000);
}

function buildReport(runs: RunInfo[]): string | null {
  if (!runs.length) return null;
  const lines = runs.map((r) => {
    const ago = r.lastMs < 90_000 ? `${Math.round(r.lastMs / 1000)}s` : `${Math.round(r.lastMs / 60_000)}m`;
    if (!r.turnsKnown) {
      return `  - ${r.id.slice(0, 8)} ${r.task.padEnd(18)} 轮数未知(events 无 turn 事件)  最后活动 ${ago}前  ❓`;
    }
    const over = r.turns > r.limit;
    const warn = !over && r.turns >= Math.floor(r.limit * WARN_RATIO);
    const mark = over ? "⚠ 超限" : warn ? "△ 接近上限" : "✅";
    return `  - ${r.id.slice(0, 8)} ${r.task.padEnd(18)} 第 ${r.turns}/${r.limit} 轮  最后活动 ${ago}前  ${mark}`;
  });
  const advices: string[] = [];
  for (const r of runs) {
    if (!r.turnsKnown) {
      advices.push(`${r.id.slice(0, 8)} 轮数解析失败 —— 自己 subagent({action:"status"}) 看准确轮数，别信 0 轮`);
      continue;
    }
    if (r.turns > r.limit) {
      advices.push(`steer ${r.id.slice(0, 8)}：「已超 ${r.limit} 轮，立刻 ./board.sh next '<已确认事实 + 下一棒第一动作>' 后收口」`);
    } else if (r.turns >= Math.floor(r.limit * WARN_RATIO)) {
      advices.push(`steer ${r.id.slice(0, 8)}：「接近上限（${r.turns}/${r.limit}），准备收口或确认还能一击拿下」`);
    } else if (r.lastMs > 5 * 60_000) {
      advices.push(`${r.id.slice(0, 8)} 已 ${Math.round(r.lastMs / 60_000)} 分钟无活动 —— transcript 看是否卡死，必要时 interrupt`);
    }
  }
  if (!advices.length) advices.push("全部正常，无需干预（无活跃 run 时可考虑补位）");
  // 【主 agent 须自己执行】给每题生成读板命令；未读板前不要 steer
  const cmds: string[] = [];
  for (const r of runs) {
    const db = boardDbOf(r.taskDir);
    if (db) {
      const gate = ROOTS.sharedRoot ? toWsl(ROOTS.sharedRoot + "/gate_db.py") : null;
      cmds.push(
        gate
          ? `  - ${r.task}: python3 ${gate} --db ${toWsl(db)} dump`
          : `  - ${r.task}: board_digest({dir:"${r.taskDir}"})`,
      );
    }
  }
  const boardSec = cmds.length
    ? `\n【先读板再给建议】（不要凭记忆/凭轮数直接 steer）\n${cmds.join("\n")}`
    : "";
  return `[巡检] 活跃 ${runs.length} 个 run：\n${lines.join("\n")}\n建议：\n${advices.map((a) => "  - " + a).join("\n")}${boardSec}`;
}

export default function orchestratorPatrol(pi: any) {
  let lastActivity = Date.now();
  let timer: NodeJS.Timeout | null = null;
  let enabled = false;
  let count = 0;

  // 题目录判据：只看 .ctf-gate 标记（不依赖目录名，换比赛照样成立）
  const isTaskDir = (cwd: string) => {
    try { return fs.existsSync(path.join(cwd, ".ctf-gate")); } catch { return false; }
  };

  pi.on("session_start", async (_event: any, ctx: any) => {
    const cwd = String(ctx?.cwd || "");
    if (isTaskDir(cwd)) { plog(`skip(子会话) cwd=${cwd}`); return; }
    enabled = true;
    lastActivity = Date.now();
    try {
      const f = ctx?.sessionManager?.getSessionFile?.();
      MY_SESSION = f ? String(f) : "";
    } catch { MY_SESSION = ""; }
    plog(`start cwd=${cwd} interval=${PATROL_MS}ms limit=${TURN_LIMIT_DEFAULT} session=${MY_SESSION ? path.basename(MY_SESSION).slice(0, 24) : "(无)"}`);
    if (timer) clearInterval(timer);
    timer = setInterval(() => {
      if (!enabled) return;
      const idle = Date.now() - lastActivity;
      if (idle > IDLE_SKIP_MS) { plog(`skip(idle ${Math.round(idle / 1000)}s)`); return; }
      count += 1;
      const runs = collect();
      const report = buildReport(runs);
      if (!report) { plog(`#${count} no active runs`); return; }
      plog(`#${count} runs=${runs.length} -> ${JSON.stringify(runs.map((r) => [r.id.slice(0, 8), r.turns, r.limit]))}`);
      try {
        pi.sendMessage(
          { customType: "orchestrator-patrol", content: `[巡检 #${count}] ${report}`, display: true },
          { triggerTurn: true, deliverAs: "steer" },
        );
        plog(`#${count} sent`);
      } catch (e) {
        plog(`#${count} send FAIL ${String(e)}`);
      }
    }, PATROL_MS);
  });

  pi.on("tool_call", async () => { lastActivity = Date.now(); });
  pi.on("turn_start", async () => { lastActivity = Date.now(); });

  pi.on("session_shutdown", async () => {
    plog("shutdown");
    enabled = false;
    if (timer) { clearInterval(timer); timer = null; }
  });
}
