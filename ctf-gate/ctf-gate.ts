/**
 * ctf-gate.ts — CTF 解题「物理闸门 + 黑板 + 长预算」扩展 (pi harness 层)
 *
 * 激活：默认关，只在解题环境开（配置 roots / .ctf-gate / gate/ / 挑战特征）；
 *       关闭：PI_CTF_GATE=0 或 .no-ctf-gate；强制开：PI_CTF_GATE=1。
 * 判定对象：不是 ctx.cwd，而是「命令/写入路径指向的题目目录」（方案B，粘性）
 *       从任意目录启动，第一条 cd/路径命中项目根下的题目即接入该题闸门
 * 四部件：阶段闸门 / 数据判态 / 预算物理化 / 假设为键
 * 黑板：按「主会话 + 题目目录」隔离 SQLite：ctf-boards/<owner>/challenges/<task>/gate.sqlite
 *       同一题的父子会话共用；不同题的阶段、证伪 tag、证据不串板。
 *       读写经 <项目根>/_shared/gate_db.py（运行时由 policies/roots.ts 解析）；每轮注入 + 用 rev 强制更新
 * 证伪：falsified.tag 主键；拒绝时带回 condition
 * 长预算：run-long.sh / kill-long.sh（pid 仍在 gate/long/）
 * 新任务：./new-task.sh 或 /new-task
 * 阶段连续性：存在 stageN 时要求 1..N 全部存在且全部「通过」，不许跳阶
 * 用户直敲：user_bash 事件同样过闸门（!python3 / !rm 写状态 都会被拦）
 * 网络硬超时：curl 必须带 --max-time，wget 必须带 --timeout/-T，否则拦
 *             数值上限默认 65s（PI_CTF_GATE_NET_MAX 可调），超过同样拦
 *             （已带超时的网络命令不再被「重活必须走 run.sh」误拦）
 * 工具先行：新建 .py/.sh 等脚本前，BOARD.tooling 为空就拦，要求先查 toolbox
 */
import { createLocalBashOperations, type ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { isContestRoot } from "../src/paths/ctf-directory.ts";
import { resolveRoots, mapMount, loadEnv } from "../src/paths/roots.ts";
import { createAdapter, loadConfig } from "../src/exec/index.ts";
import { profileAt } from "../src/config/profiles.ts";

/** 机器配置（kali 主机、mounts）；不写死在源码里 */
const ENVCFG = loadEnv();

const KILL_SH = `#!/usr/bin/env bash
set -u
TAG="\${1:?usage: ./kill-long.sh <tag>}"
GATE="\${CTF_GATE_DIR:-gate}"
PIDF="$GATE/long/\${TAG}.pid"
[ -f "$PIDF" ] || { echo "no pid for '$TAG'" >&2; exit 1; }
PID="$(cat "$PIDF")"
if kill -0 "$PID" 2>/dev/null; then
  kill -TERM -- "-$PID" 2>/dev/null || kill -TERM "$PID" 2>/dev/null
  echo "[kill-long] killed pid/pgid $PID (tag $TAG)"
else
  echo "[kill-long] pid $PID not running"
fi
rm -f "$PIDF"
`;

const NEW_TASK_SH = `#!/usr/bin/env bash
set -u
GATE="\${CTF_GATE_DIR:-gate}"
DB="\${CTF_GATE_DB:-$GATE/../gate.sqlite}"
PY="\${CTF_GATE_PY:-\${CTF_ROOT:-}/_shared/gate_db.py}"
if [ ! -f "$PY" ]; then
  echo "[new-task] 找不到 gate_db.py（CTF_ROOT=\${CTF_ROOT:-未设置}）；先在 shell 里 source <项目根>/_shared/root.sh" >&2
  exit 2
fi
TS="$(date +%F_%H%M%S)"
D="$GATE/archive/$TS"
mkdir -p "$D"
if [ -f "$DB" ]; then
  python3 "$PY" --db "$DB" backup "$D/gate.sqlite" || exit 2
fi
[ -d "$GATE/evidence" ] && mv "$GATE/evidence" "$D"/ 2>/dev/null
[ -d "$GATE/long" ] && mv "$GATE/long" "$D"/ 2>/dev/null
python3 "$PY" --db "$DB" reset >/dev/null 2>&1 || python "$PY" --db "$DB" reset >/dev/null
mkdir -p "$GATE"/evidence "$GATE"/long
echo "[new-task] 旧状态已归档到 $D；SQLite 黑板已 reset"
`;

const BOARD_TEMPLATE = JSON.stringify(
  {
    challenge: { name: "", remote: "" },
    params: { N: "", e: "", a: "", leak: "", out1: "", out2: "" },
    verified: [], falsified: [], hypotheses: [], tooling: [], next: [], flags: [],
  }, null, 2,
) + "\n";

const LIGHT = /^\s*(ls|cat|head|tail|grep|rg|pwd|which|file|checksec|stat|wc|diff|xxd|strings|nm|objdump|readelf|ps|echo|sed\s+-n)\b/;
const HEAVY =
  /^(python3?|sage|gp|pari|gcc|g\+\+|cc|clang|go|cargo|java|node|ruby|perl|Rscript|php|lua|tclsh|deno|bun|bash|sh|dash|zsh|ksh|make|env|xargs|busybox|curl|wget|nc|ncat|socat|openssl|john|hashcat|sqlmap|ffuf|gobuster|radamsa)$/;
/** 按“命令词”判重活（不扫参数，避免 *.sh / 文件名误伤） */
function heavyCmd(seg: string, cwd: string = process.cwd(), full: string = seg): boolean {
  const w = cmdWord(seg).replace(/\\/g, "/").split("/").pop() ?? "";
  const name = w.replace(/\.exe$/i, "");
  if (!HEAVY.test(name)) return false;
  // 自带硬超时的网络/取数命令（curl -m/--max-time、timeout N ...）不算重活：
  // 它们的风险是挂死，超时参数已经解决；强制走 run.sh 只是多烧一轮。
  if ((name === "curl" || name === "wget") && /(?:^|\s)(?:-m|--max-time|-w|--timeout)\s*\d+/.test(seg)) return false;
  if (/^\s*timeout\s+\d+/.test(seg)) return false;
  // bash/sh -n 只是语法检查，不是重活
  if ((name === "bash" || name === "sh") && /(?:^|\s)-n\b/.test(seg)) return false;
  // 只读统计脚本：data/*.py 且文件头含 "# read-only" → 不算重活（仍受 stageGate 管）
  if (name === "python3" || name === "python") {
    const m = /(?:^|\s)([^\s|;&<>]*\bdata\/[^\s|;&<>]+\.py)\b/.exec(seg);
    if (m) {
      const cdTarget = /(?:^|[;&])\s*cd\s+([^\s;&]+)/.exec(full)?.[1];
      const cands = [
        path.isAbsolute(m[1]) ? m[1] : path.resolve(cwd, m[1]),
        cdTarget && !path.isAbsolute(m[1]) ? path.resolve(cdTarget, m[1]) : m[1],
      ].filter(Boolean) as string[];
      for (const p of cands) {
        try { if (/#\s*read-only/i.test(fs.readFileSync(p, "utf8").slice(0, 300))) return false; } catch {}
      }
    }
  }
  return true;
}
const WRITEY = /(>|>>|\btee\b|\bsed\s+-i\b|\btruncate\b|\bdd\b|\brm\b|\bmv\b|\bcp\b)/;
const STATE_PATHS = /gate[\\/][^\\/]*\.conclusion\b|gate[\\/]falsified\.list\b/;
const GATE_SCRIPTS = ["run.sh", "run-long.sh", "stage.sh", "check.sh", "kill-long.sh", "new-task.sh", "board.sh"];
const SCRIPT_PATHS = new RegExp("(^|[\\s\\\\/])(?:" + GATE_SCRIPTS.map((x) => x.replace(/\.sh$/, "")).join("|") + ")\\.sh\\b");
const BOARD_PATHS = /gate[\\/]BOARD\.json\b/;
/**
 * 受保护 = 本题目录内的闸门状态与闸门脚本。
 * 带路径范围的原因：_shared/ 里的工具箱脚本不该被自己保护（否则工具链改不动自己，
 * 这正是内嵌模板与 _shared 漂移的根因），/tmp 下的同名脚本也不该误伤。
 */
function isProtected(p: string): boolean {
  const w = toWinPath(p);
  if (STATE_PATHS.test(p) || STATE_PATHS.test(w)) return true;
  try {
    const br = path.resolve(toWinPath(boardsRoot()));
    const relB = path.relative(br, path.resolve(w));
    if (relB && !relB.startsWith("..") && !path.isAbsolute(relB) && /gate[\\/]/.test(w)) return true;
  } catch {
    /* 看板根未解析：按非看板处理，后面会报错 */
  }
  if (!SCRIPT_PATHS.test(p) && !SCRIPT_PATHS.test(w)) return false;
  if (!/[\\/]/.test(p) && !/[\\/]/.test(w)) return true; // 裸名（run.sh）
  const abs = path.isAbsolute(w) ? w : path.resolve(process.cwd(), w);
  if (GATE_SCRIPTS.includes(path.basename(abs))) return true;
  try { return findGateRoot(path.dirname(abs)) !== null; } catch { return true; }
}
// 取“首个真实命令词”，跳过 sudo/timeout/env/nice 等包装与参数
const WRAPPER = /^(?:sudo|env|command|nohup|nice|time|timeout)$/;
function cmdWord(seg: string): string {
  const toks = seg.trim().split(/\s+/);
  let i = 0;
  while (i < toks.length) {
    const t = toks[i];
    if (WRAPPER.test(t) || /^-[^\s]/.test(t) || /^[A-Za-z_][A-Za-z0-9_]*=/.test(t) || /^\d+(?:\.\d+)?[smhd]?$/.test(t)) { i++; continue; }
    break;
  }
  return toks[i] ?? "";
}
const baseName = (s: string) => cmdWord(s).split(/[\\/]/).pop() ?? "";
const isGateSeg = (s: string) => GATE_SCRIPTS.includes(baseName(s));
// _shared 下的编排/运维脚本：整体豁免 HEAVY（它们内部自带预算或只读），但 kali.sh 例外
const isSharedDriver = (s: string) => /_shared\/(solve|tool|doctor|snap|sync-runners|net)\.sh$/.test(cmdWord(s));
const isExemptSeg = (s: string) =>
  /^\s*\.\/(check|kill-long|new-task)\.sh\b/.test(s) ||
  (isSharedDriver(s) && !/_shared\/solve\.sh$/.test(cmdWord(s)));
const isRunSeg = (s: string) => /^(run|run-long)\.sh$/.test(baseName(s));

function splitSegments(cmd: string): string[] {
  const parts: string[] = [];
  let cur = "", inS = false, inD = false, esc = false;
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (esc) { cur += c; esc = false; continue; }
    if (c === "\\" && !inS) { cur += c; esc = true; continue; }
    if (c === "'" && !inD) { inS = !inS; cur += c; continue; }
    if (c === '"' && !inS) { inD = !inD; cur += c; continue; }
    // 重定向里的 & 不是分隔符：2>&1、>&2、&>file、&>>file
    const ampInRedirect = c === "&" && (cmd[i + 1] === ">" || cmd[i - 1] === ">");
    if (!inS && !inD && !ampInRedirect && (c === ";" || c === "\n" || c === "|" || c === "&")) {
      parts.push(cur); cur = "";
      while (i + 1 < cmd.length && (cmd[i + 1] === "|" || cmd[i + 1] === "&" || cmd[i + 1] === ";")) i++;
      continue;
    }
    cur += c;
  }
  parts.push(cur);
  return parts.map((s) => s.trim()).filter(Boolean);
}

function hasUnquotedSubst(cmd: string): boolean {
  let inS = false, inD = false, esc = false;
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (esc) { esc = false; continue; }
    if (c === "\\" && !inS) { esc = true; continue; }
    if (c === "'" && !inD) { inS = !inS; continue; }
    if (c === '"' && !inS) { inD = !inD; continue; }
    // 单引号内是字面量（本来就不执行）；双引号内的替换不会分词注入，都是常见安全写法
    // （如 curl -H "Cookie: $(cat ck.txt)"）。只有裸（无引号）状态的替换才拦。
    if (inS || inD) continue;
    if (c === "`") return true;
    if (c === "$" && cmd[i + 1] === "(") return true;
  }
  return false;
}

// ---- 激活判定 ----
const AGENT_DIR = process.env.PI_CODING_AGENT_DIR || path.join(process.env.USERPROFILE || process.env.HOME || ".", ".pi", "agent");
const CFG_PATH = process.env.PI_CTF_GATE_CONFIG || path.join(AGENT_DIR, "ctf-gate.json");
/** 看板根：env → roots 解析；两者都拿不到就报错（不创建替代位置） */
let boardsRootCache: string | null | undefined;
function boardsRoot(): string {
  if (boardsRootCache !== undefined && boardsRootCache !== null) return boardsRootCache;
  const r = process.env.PI_CTF_BOARDS_ROOT || resolveRoots(process.cwd()).boardsRoot;
  if (!r) {
    throw new Error(
      "看板根未解析：在 ~/.pi/agent/env.json 配 boardsRoot，或设 PI_CTF_BOARDS_ROOT；" +
        "不会自动创建替代目录",
    );
  }
  boardsRootCache = r.replace(/\\/g, "/");
  return boardsRootCache;
}

/** 主会话与题目共同决定黑板；没有选中题目时绝不读写库。 */
let ownerKey: string | null = null;
let activeBoardDir: string | null = null;
let activeTaskDir: string | null = null;

function boardSlug(key: string): string {
  return crypto.createHash("sha1").update(key).digest("hex").slice(0, 16);
}
function ownerDir(key: string): string {
  return path.join(boardsRoot(), boardSlug(key));
}
function taskIdentity(dir: string): string {
  const normalized = toWinPath(fs.realpathSync.native(dir)).replace(/\\/g, "/").toLowerCase();
  return normalized;
}
function challengeDir(key: string, dir: string): string {
  return path.join(ownerDir(key), "challenges", boardSlug(taskIdentity(dir)));
}
function challengeDbPath(key: string, dir: string): string {
  return path.join(challengeDir(key, dir), "gate.sqlite");
}
/**
 * gate_db.py：env 覆盖 → roots.sharedRoot（项目内资源相对项目根）。
 * 解析不到就抛错 —— 不退回 PATH 名（那会让 python 在 cwd 里找文件并失败，错误信息毫不相关）。
 */
function gatePy(): string {
  const explicit = process.env.CTF_GATE_PY;
  if (explicit) {
    if (fs.existsSync(explicit)) return explicit;
    throw new Error(`CTF_GATE_PY 指向的文件不存在：${explicit}（修：改成真实路径，或删掉该变量走自动解析）`);
  }
  const roots = resolveRoots(process.cwd());
  if (!roots.sharedRoot) {
    throw new Error(
      "解析不到项目根/共享目录，无法定位 gate_db.py：" +
        (roots.errors[0] ?? "未知原因") +
        "（修：在 env.json 配 projectRoot，或在项目根放 ctf.project.json）",
    );
  }
  const cand = path.join(roots.sharedRoot, "gate_db.py");
  if (!fs.existsSync(cand)) throw new Error(`${cand} 不存在（项目内资源应相对项目根；检查 _shared 是否完整）`);
  return cand.replace(/\\/g, "/");
}
function pyBin(): string {
  for (const c of ["python3", "python", "py"]) {
    const r = spawnSync(c, ["-c", "import sqlite3,sys;sys.exit(0)"], { encoding: "utf8" });
    if (r.status === 0) return c;
  }
  return "python3";
}
function dbRun(args: string[], stdin?: string): { status: number; stdout: string; stderr: string } {
  const db = dbPath();
  let script: string;
  try {
    script = gatePy();
  } catch (e: any) {
    // 不抛到 hook 外面（那会变成所有工具都报同一个莫名错误）：转成失败状态，由调用方按板问题处理
    return { status: 127, stdout: "", stderr: String(e?.message ?? e) };
  }
  const r = spawnSync(pyBin(), [script, "--db", db, ...args], {
    input: stdin, encoding: "utf8", timeout: 15000, windowsHide: true,
    // Windows 下 Python 默认不是 UTF-8，中文黑板经 stdin 会报 surrogates not allowed
    env: { ...process.env, PYTHONUTF8: "1", PYTHONIOENCODING: "utf-8" },
  });
  return { status: r.status ?? 1, stdout: r.stdout ?? "", stderr: r.stderr ?? String(r.error ?? "") };
}
function dbPath(): string {
  if (!ownerKey || !activeTaskDir) throw new Error("CTF 题目未选中；拒绝读取未分区的黑板");
  return challengeDbPath(ownerKey, activeTaskDir);
}
function resolveOwnerKey(ctx: any): string {
  const envParent = String(process.env.PI_SUBAGENT_PARENT_SESSION || "").trim();
  if (envParent) return envParent;
  const sm = ctx?.sessionManager;
  try {
    const header = sm?.getHeader?.();
    if (header?.parentSession) return String(header.parentSession);
  } catch {}
  const file = sm?.getSessionFile?.();
  if (file) return String(file);
  const id = sm?.getSessionId?.();
  if (id) return String(id);
  return "ephemeral";
}
function bindOwner(ctx: any, taskDir?: string | null): void {
  const owner = resolveOwnerKey(ctx);
  if (ownerKey !== owner) {
    activeBoardDir = null;
    activeTaskDir = null;
  }
  ownerKey = owner;
  if (!taskDir) return;
  if (isContestRoot(taskDir)) throw new Error("比赛根目录不可绑定单题黑板；请选独立题目目录");
  const root = fs.realpathSync.native(taskDir);
  if (activeTaskDir === root && activeBoardDir) return;
  activeTaskDir = root;
  const dir = challengeDir(owner, root);
  activeBoardDir = path.join(dir, "gate");
  fs.mkdirSync(path.join(activeBoardDir, "evidence"), { recursive: true });
  fs.mkdirSync(path.join(activeBoardDir, "long"), { recursive: true });
  fs.writeFileSync(path.join(ownerDir(owner), "OWNER.txt"), owner + "\n", "utf8");
  fs.writeFileSync(path.join(dir, "CHALLENGE.txt"), root + "\n", "utf8");
  const initialized = dbRun(["init"]);
  if (initialized.status !== 0) throw new Error(`CTF 黑板初始化失败：${initialized.stderr}`);
}
function G(): string {
  if (!activeBoardDir) throw new Error("CTF 题目未选中；拒绝读取未分区的黑板");
  return activeBoardDir;
}
function loadCfg(): { roots: string[]; signatures: boolean; shared?: string } {
  try {
    const c = JSON.parse(fs.readFileSync(CFG_PATH, "utf8"));
    return {
      roots: Array.isArray(c.roots) ? c.roots.map(String) : [],
      signatures: c.signatures !== false,
      shared: typeof c.shared === "string" ? c.shared : undefined,
    };
  } catch { return { roots: [], signatures: true }; }
}
const CFG = loadCfg();
const CHALLENGE_SIG = [
  /^task.*\.py$/i, /^chal.*\.py$/i, /^challenge.*\.py$/i, /^crypto.*\.py$/i, /^pwn.*\.py$/i,
  /\.(sage|pcap|pcapng|apk|elf|dmp)$/i, /^flag/i, /^cipher/i, /^enc(rypt(ed)?)?\./i,
];
function underRoot(cwd: string, roots: string[]): boolean {
  const c = path.resolve(cwd).replace(/\\/g, "/").toLowerCase();
  return roots.some((r) => {
    const rr = path.resolve(String(r)).replace(/\\/g, "/").toLowerCase().replace(/\/+$/, "");
    return !!rr && (c === rr || c.startsWith(rr + "/"));
  });
}
function looksLikeChallenge(cwd: string): boolean {
  try { return fs.readdirSync(cwd).some((f) => CHALLENGE_SIG.some((re) => re.test(f))); } catch { return false; }
}
function isBoardHome(p: string): boolean {
  const w = toWinPath(p).replace(/\\/g, "/").toLowerCase();
  let root = "";
  try {
    root = toWinPath(boardsRoot()).replace(/\\/g, "/").toLowerCase().replace(/\/+$/, "");
  } catch {
    return false; // 看板根未解析：不把任何目录误判成看板（解析错误会在真正读写板时暴露）
  }
  return !!root && (w === root || w.startsWith(root + "/"));
}
function disabled(cwd: string): boolean {
  if (process.env.PI_CTF_GATE === "0") return true;
  if (process.env.PI_CTF_GATE === "1") return false; // 强制开优先于 .no-ctf-gate
  if (isBoardHome(cwd)) return true; // 黑板目录永远不当题目
  if (fs.existsSync(path.join(cwd, ".no-ctf-gate"))) return true;
  if (fs.existsSync(path.join(cwd, ".ctf-gate"))) return false;
  if (fs.existsSync(path.join(cwd, "gate"))) return false;
  const w = toWinPath(cwd);
  if (CFG.roots.length && underRoot(w, CFG.roots)) {
    // roots 本身不当题目（项目根、仓库根都不应因此启用）
    if (CFG.roots.some((r) => toWinPath(String(r)).toLowerCase() === w.toLowerCase())) return true;
    // roots 下的子目录：只有“已有 gate/”或“看起来像题目”才启用
    return !looksLikeTaskDir(w);
  }
  if (CFG.signatures && looksLikeChallenge(cwd)) return false;
  return true;
}

// ---- 方案B：路径 → 题目目录解析（粘性）----
let activeGateDir: string | null = null;
let tmpWarned = false;   // /tmp 一次性提示（模块级：guardCore 与会话重置共用）
const SYS_PATH = /^(?:[a-z]:)?\/(?:tmp|dev|proc|sys|usr|bin|sbin|etc|var|opt|root|home|lib|lib64|boot|run|windows|program files)(?:\/|$)/i;

function toWinPath(p: string): string {
  let s = String(p ?? "").trim().replace(/^["']|["']$/g, "").replace(/\\/g, "/");
  const w = /^\/mnt\/([a-zA-Z])(?:\/(.*))?$/.exec(s);
  if (w) s = `${w[1].toUpperCase()}:/${w[2] ?? ""}`;
  const d = /^([a-zA-Z]):\//.exec(s);
  if (d) s = d[1].toUpperCase() + s.slice(1);
  return s.replace(/\/+$/, "") || "/";
}

function dirOf(p: string): string {
  try { if (fs.statSync(p).isDirectory()) return p; } catch {}
  return path.dirname(p);
}

function findGateRoot(dir: string): string | null {
  if (isBoardHome(dir)) return null;
  let cur = dir;
  for (let i = 0; i < 12; i++) {
    if (isBoardHome(cur) || isWorkspaceRoot(cur) || isContestRoot(cur)) return null;
    if (fs.existsSync(path.join(cur, "gate"))) return cur;
    const up = path.dirname(cur);
    if (up === cur) break;
    cur = up;
  }
  return null;
}

/** 工作区根：用 roots 解析；拿不到返回 null（调用方按"非工作区"处理） */
function ctfWorkspace(): string | null {
  return resolveRoots(process.cwd()).projectRoot;
}
function isWorkspaceRoot(dir: string): boolean {
  const ws = ctfWorkspace();
  if (!ws) return false;
  const a = path.resolve(toWinPath(dir));
  const b = path.resolve(toWinPath(ws));
  return a.toLowerCase() === b.toLowerCase();
}
function workspaceChallenge(dir: string): string | null {
  const ws = ctfWorkspace();
  if (!ws) return null;
  const base = path.resolve(toWinPath(ws));
  const candidate = path.resolve(toWinPath(dir));
  const rel = path.relative(base, candidate);
  // 只认真正在项目内的路径（用路径包含关系，不靠字符串前缀/形态）
  if (!rel || rel.startsWith("..") || path.isAbsolute(rel)) return null;
  const parts = rel.split(/[\\/]+/).filter(Boolean);
  if (!parts.length || parts[0].startsWith("_") || parts[0] === "gate") return null;
  // gate/ 是题目的状态路径，不是另一道题；按其父目录定位。
  const gateIndex = parts.indexOf("gate");
  if (gateIndex >= 0) parts.length = gateIndex;
  if (!parts.length) return null;
  const baseSlash = base.replace(/\\/g, "/");
  const roots = parts.map((_, i) => `${baseSlash}/${parts.slice(0, i + 1).join("/")}`);
  // 显式题目标记优先；比赛目录下有多道题时可标在各题目录。
  for (const root of [...roots].reverse()) {
    if (!isContestRoot(root) && fs.existsSync(path.join(root, ".ctf-gate"))) return root;
  }
  // 一层一题保留既有布局；嵌套比赛目录必须显式在题目目录放 .ctf-gate。
  if (roots.length !== 1) return null;
  const root = roots[0];
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) return null;
  if (looksLikeChallenge(root) || fs.existsSync(path.join(root, "gate")) ||
      fs.readdirSync(root).some((name) => /^(solve|exp|poc|brute).+\.(py|sh|sage|js|rb)$/i.test(name))) return root;
  return null;
}

function looksLikeTaskDir(dir: string): boolean {
  if (isBoardHome(dir)) return false;
  try {
    const names = fs.readdirSync(dir);
    if (names.includes("gate") || names.includes("data")) return true;
    if (names.some((n) => /^(solve|exp|poc|brute).*\.(py|sh|sage|js|rb)$/i.test(n))) return true;
    return names.some((f) => CHALLENGE_SIG.some((re) => re.test(f)));
  } catch { return false; }
}

function taskRootFor(dir: string): string | null {
  const d = toWinPath(dir);
  if (isBoardHome(d) || isContestRoot(d) || /(^|\/)_[^/]+$/.test(d)) return null;
  const w = workspaceChallenge(d);
  if (w) return disabled(w) ? null : w;
  // pi-ctf 内未知/多义的层级不能退化到通用 gate/ 或特征匹配逻辑。
  const wsRoot = ctfWorkspace();
  if (isWorkspaceRoot(d)) return null;
  if (wsRoot) {
    const relWs = path.relative(path.resolve(toWinPath(wsRoot)), path.resolve(d));
    if (relWs && !relWs.startsWith("..") && !path.isAbsolute(relWs)) return null;
  }
  // 配置范围之外，只有显式标记才算题目；用户主目录里的 gate/ 不是题。
  if (!underRoot(d, CFG.roots) && process.env.PI_CTF_GATE !== "1") {
    let cur = d;
    for (let i = 0; i < 12 && !isBoardHome(cur); i++) {
      if (isContestRoot(cur)) return null;
      if (fs.existsSync(path.join(cur, ".ctf-gate"))) return disabled(cur) ? null : cur;
      const up = path.dirname(cur);
      if (up === cur) break;
      cur = up;
    }
    return null;
  }
  if (disabled(d)) return null;
  const g = findGateRoot(d);
  if (g && !isContestRoot(g) && underRoot(g, CFG.roots)) return g;
  if (CFG.roots.some((r) => toWinPath(String(r)).toLowerCase() === d.toLowerCase())) return null;
  return looksLikeTaskDir(d) || process.env.PI_CTF_GATE === "1" ? d : null;
}

function cdTargets(cmd: string): string[] {
  const out: string[] = [];
  const re = /(?:^|[\s;&|(])(?:cd|pushd)\s+("[^"]*"|'[^']*'|[^\s;&|()]+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(cmd))) out.push(m[1].replace(/^["']|["']$/g, ""));
  return out;
}

function absPaths(cmd: string): string[] {
  const out: string[] = [];
  const re = /(?:[A-Za-z]:[\\/][^\s"'`;&|()<>]*|\/mnt\/[A-Za-z]\/[^\s"'`;&|()<>]*)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(cmd))) out.push(m[0]);
  return out;
}

function pathCandidates(cwd: string, cmd: string): string[] {
  const out: string[] = [];
  for (const t of cdTargets(cmd)) {
    const abs = /^(?:[A-Za-z]:[\\/]|\/)/.test(t) ? toWinPath(t) : toWinPath(path.resolve(cwd, t));
    if (!SYS_PATH.test(abs)) out.push(abs);
  }
  for (const p of absPaths(cmd)) {
    const d = dirOf(toWinPath(p));
    if (!SYS_PATH.test(d)) out.push(d);
  }
  return out;
}

function resolveGateDir(cands: string[]): string | null {
  for (const c of cands) {
    const t = taskRootFor(c);
    if (t) return t;
  }
  return null;
}

// ---- 状态文件 ----
/** 闸门脚本的唯一来源是 _shared/：缺失即硬失败，绝不回退到内嵌旧模板（部件2/3） */
const LOCAL_MAP: Record<string, string> = { "kill-long.sh": KILL_SH, "new-task.sh": NEW_TASK_SH };

function sharedScriptBody(name: string): string | null {
  const dirs: string[] = [];
  const envShared = (process.env.PI_CTF_SHARED || "").trim();
  if (envShared) dirs.push(envShared.endsWith(".sh") ? path.dirname(envShared) : envShared);
  if (CFG.shared) dirs.push(CFG.shared.endsWith(".sh") ? path.dirname(CFG.shared) : CFG.shared);
  const _sr = resolveRoots(process.cwd()).sharedRoot;
  if (_sr) dirs.push(_sr);
  for (const d of dirs) {
    try {
      const p = path.join(d, name);
      if (fs.existsSync(p)) return fs.readFileSync(p, "utf8");
    } catch {}
  }
  return null;
}

/** 返回硬失败原因；undefined = 脚手架就绪 */
function ensureScaffold(cwd: string): string | undefined {
  const gate = G();
  fs.mkdirSync(path.join(gate, "evidence"), { recursive: true });
  fs.mkdirSync(path.join(gate, "long"), { recursive: true });
  const missing: string[] = [];
  const scriptCwd = isBoardHome(cwd) ? "" : cwd;
  if (!scriptCwd) {
    dbRun(["init"]);
    return undefined; // 黑板目录不铺 run.sh
  }
  for (const name of GATE_SCRIPTS) {
    const p = path.join(scriptCwd, name);
    const body = LOCAL_MAP[name] ?? sharedScriptBody(name);
    if (!body) {
      missing.push(name); // unknown local copies are not a trusted fallback
      continue;
    }
    let current: string | null = null;
    try { current = fs.readFileSync(p, "utf8"); } catch {}
    if (current === body) continue;
    // 旧/手改过的 wrapper（含从比赛根目录拷来的）一律备份后换成规范版，避免双源漂移。
    if (current !== null) {
      const backup = path.join(gate, "archive", `wrappers-${new Date().toISOString().replace(/[:.]/g, "-")}`);
      try {
        fs.mkdirSync(backup, { recursive: true });
        fs.copyFileSync(p, path.join(backup, name));
      } catch {}
    }
    fs.writeFileSync(p, body, { mode: 0o755 });
  }
  const initialized = dbRun(["init"]);
  if (initialized.status !== 0) return `本题黑板不可用：${initialized.stderr}`;
  // 旧 JSON 是镜像，不能在每轮反向导入，否则会覆盖并行子代理刚写的 SQLite 数据。
  if (!missing.length) return undefined;
  return "缺少 _shared 闸门脚本（" + missing.join("、") + "）：设 PI_CTF_SHARED 指向 pi-ctf/_shared，" +
    "或在 ctf-gate.json 配 shared；已拒绝回退到内嵌旧模板（部件2/3）。";
}

function resetTask(_cwd: string): string {
  const g = G();
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const dest = path.join(g, "archive", ts);
  fs.mkdirSync(dest, { recursive: true });
  const db = dbPath();
  if (fs.existsSync(db)) {
    const backup = dbRun(["backup", path.join(dest, "gate.sqlite")]);
    if (backup.status !== 0) throw new Error(`CTF 黑板备份失败，拒绝重置：${backup.stderr}`);
  }
  for (const name of ["evidence", "long"]) {
    const src = path.join(g, name);
    if (fs.existsSync(src)) {
      try { fs.renameSync(src, path.join(dest, name)); } catch {}
    }
  }
  fs.mkdirSync(path.join(g, "evidence"), { recursive: true });
  fs.mkdirSync(path.join(g, "long"), { recursive: true });
  const reset = dbRun(["reset"]);
  if (reset.status !== 0) throw new Error(`CTF 黑板重置失败：${reset.stderr}`);
  return dest;
}

// ---- 黑板契约（schema 校验）----
/**
 * 看板字段：唯一事实源是 gate_db.py（机器可读接口 `fields`），不在 TS 里维护第二份列表。
 * 读不到或字段缺失 → 明确报错（历史上 angles / coverage 两次漂移都因此锁死全部工具）。
 */
const REQUIRED_FIELDS = ["challenge", "params", "verified", "falsified", "hypotheses", "tooling", "next", "flags"];
let boardFieldsCache: string[] | null = null;
function boardFields(): string[] {
  if (boardFieldsCache) return boardFieldsCache;
  const r = spawnSync(pyBin(), [gatePy(), "fields"], { encoding: "utf8", timeout: 10000, windowsHide: true });
  if (r.status !== 0) {
    throw new Error(`读看板字段失败（gate_db.py fields）：${(r.stderr || r.stdout || "").trim() || "无输出"}`);
  }
  let parsed: any;
  try { parsed = JSON.parse(String(r.stdout)); } catch {
    throw new Error(`gate_db.py fields 输出不是 JSON：${String(r.stdout).slice(0, 120)}`);
  }
  const fields = parsed?.fields;
  if (!Array.isArray(fields) || fields.length === 0) throw new Error("gate_db.py fields 未返回字段数组");
  const missing = REQUIRED_FIELDS.filter((f) => !fields.includes(f));
  if (missing.length) throw new Error(`gate_db.py fields 缺少扩展依赖的字段：${missing.join(", ")}`);
  boardFieldsCache = fields as string[];
  return boardFieldsCache;
}
const BOARD_ALIAS: Record<string, string> = { challenges: "challenge", param: "params", verify: "verified", verfied: "verified", falsify: "falsified", falsifiedTags: "falsified", hypothesis: "hypotheses", tools: "tooling", toolng: "tooling", todo: "next", flag: "flags" };

function editDistance(a: string, b: string): number {
  const m = a.length, n = b.length;
  const d: number[][] = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
  for (let j = 0; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++) for (let j = 1; j <= n; j++) {
    d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  }
  return d[m][n];
}

function suggestField(k: string): string | null {
  const low = k.toLowerCase();
  if (BOARD_ALIAS[k] || BOARD_ALIAS[low]) return BOARD_ALIAS[k] ?? BOARD_ALIAS[low];
  let best: string | null = null, bestD = 3;
  const known = (() => { try { return boardFields(); } catch { return []; } })();
  for (const f of known) {
    const d = editDistance(low, f);
    if (d < bestD) { bestD = d; best = f; }
  }
  return best;
}

/** 返回契约错误列表（空 = 合法） */
export function validateBoard(b: unknown): string[] {
  const errs: string[] = [];
  if (!b || typeof b !== "object" || Array.isArray(b)) return ["顶层必须是 JSON 对象"];
  const o = b as Record<string, any>;
  for (const k of Object.keys(o)) {
    if (fields.includes(k)) continue;
    const s = suggestField(k);
    errs.push(`未知字段 "${k}"${s ? `，是否想写 "${s}"？` : `（可用字段：${fields.join("/")}）`}`);
  }
  const asObj = (name: string) => {
    const v = o[name];
    if (v === undefined) return;
    if (!v || typeof v !== "object" || Array.isArray(v)) errs.push(`"${name}" 必须是对象`);
  };
  const asArr = (name: string): any[] => {
    const v = o[name];
    if (v === undefined) return [];
    if (!Array.isArray(v)) { errs.push(`"${name}" 必须是数组`); return []; }
    v.forEach((x, i) => { if (!x || typeof x !== "object" || Array.isArray(x)) errs.push(`"${name}[${i}]" 必须是对象`); });
    return v;
  };
  asObj("challenge"); asObj("params");
  const verified = asArr("verified"), falsified = asArr("falsified"), hypotheses = asArr("hypotheses"), tooling = asArr("tooling"), flags = asArr("flags"), angles = asArr("angles"), outcomes = asArr("outcomes");
  const next = o.next === undefined ? [] : o.next;
  if (!Array.isArray(next)) errs.push(`"next" 必须是数组`);
  else next.forEach((x: any, i: number) => { if (typeof x !== "string") errs.push(`"next[${i}]" 必须是字符串`); });
  const reqStr = (name: string, list: any[], key: string) => {
    list.forEach((x, i) => { if (x && typeof x === "object" && typeof x[key] !== "string") errs.push(`"${name}[${i}].${key}" 必填且为字符串`); });
  };
  reqStr("falsified", falsified, "tag");
  falsified.forEach((x: any, i: number) => {
    for (const k of ["condition", "observed", "reopen", "why"]) {
      if (x && typeof x === "object" && x[k] !== undefined && typeof x[k] !== "string") errs.push(`"falsified[${i}].${k}" 必须是字符串`);
    }
  });
  reqStr("tooling", tooling, "name");
  reqStr("flags", flags, "flag");
  reqStr("angles", angles, "name");
  reqStr("outcomes", outcomes, "value");
  for (const [name, list] of [["verified", verified], ["hypotheses", hypotheses]] as const) {
    list.forEach((_x: any, i: number) => { if (typeof _x?.tag !== "string" && _x?.tag !== undefined) errs.push(`"${name}[${i}].tag" 必须是字符串`); });
  }
  if (o.challenge && typeof o.challenge === "object" && !Array.isArray(o.challenge)) {
    for (const k of Object.keys(o.challenge)) if (!["name", "remote"].includes(k)) errs.push(`未知字段 "challenge.${k}"`);
    for (const k of ["name", "remote"]) if (o.challenge[k] !== undefined && typeof o.challenge[k] !== "string") errs.push(`"challenge.${k}" 必须是字符串`);
  }
  return errs.slice(0, 8);
}

function boardProblems(cwd: string): string | null {
  const { json, errors } = readBoard(cwd);
  if (json === null) return `${dbPath()} 缺失或 dump 失败：先修正黑板（唯一事实源）。`;
  if (errors.length) return "黑板契约错误：\n- " + errors.join("\n- ");
  return null;
}

function boardRev(): string {
  const r = dbRun(["rev"]);
  return r.status === 0 ? r.stdout.trim() : "";
}

function readBoard(_cwd: string): { raw: string; json: Record<string, unknown> | null; errors: string[] } {
  const r = dbRun(["snapshot"]);
  if (r.status !== 0) return { raw: "", json: null, errors: [r.stderr || "snapshot failed"] };
  try {
    const p = JSON.parse(r.stdout);
    const json = p.board as Record<string, unknown>;
    if (!Number.isSafeInteger(p.rev) || p.rev < 0 || !json || typeof json !== "object") throw new Error("invalid snapshot");
    return { raw: String(p.rev), json, errors: validateBoard(json) };
  } catch { return { raw: "", json: null, errors: ["snapshot JSON 非法"] }; }
}

function writeBoardJson(body: string, expectedRev: string): string | undefined {
  let parsed: unknown;
  try { parsed = JSON.parse(body); } catch (e) {
    return `BOARD.json 不是合法 JSON（未写入 SQLite）：${(e as Error).message}`;
  }
  const errs = validateBoard(parsed);
  if (errs.length) return "BOARD.json 契约错误（未写入 SQLite）：\n- " + errs.join("\n- ") +
    '\n正确示例：tooling=[{"name":"sagemath"}]；next=["读本题附件"]。模板：C:/Users/25715/.pi/agent/ctf-gate/BOARD.template.json。相同错误两次即 contact_supervisor，不再原样重试。';
  const r = dbRun(["import", "--rev", expectedRev], JSON.stringify(parsed));
  if (r.status !== 0) return `写入 SQLite 失败：${r.stderr || r.stdout}`;
  return undefined;
}

function syncFalsified(_cwd: string, _b: Record<string, unknown> | null): void {
  // SQLite 单源：import 时已写入 falsified 表，不再双写 .list
}

function conclusionState(_cwd: string, stage: number): string | null {
  const r = dbRun(["stage-get", String(stage)]);
  if (r.status !== 0) return null;
  return r.stdout.trim().split(/\s+/)[0] || null;
}

function stageNumbers(_cwd: string): number[] {
  const r = dbRun(["stages"]);
  if (r.status !== 0) throw new Error(`CTF 阶段查询失败，拒绝放行：${r.stderr}`);
  const out: number[] = [];
  for (const line of r.stdout.split("\n")) {
    const n = Number(line.split("\t")[0]);
    if (Number.isFinite(n) && n > 0) out.push(n);
  }
  return out.sort((a, b) => a - b);
}

/** 阶段闸门：1..max 必须全部存在且全部「通过」；返回拦截原因或 undefined */
function stageGate(cwd: string): string | undefined {
  const stages = stageNumbers(cwd);
  if (stages.length === 0) return undefined;
  const max = stages[stages.length - 1];
  const have = new Set(stages);
  for (let i = 1; i <= max; i++) {
    if (!have.has(i)) return `缺少 stages.n=${i}：已有到 stage${max} 的结论，不许跳阶（部件1）。`;
  }
  for (let i = 1; i <= max; i++) {
    const s = conclusionState(cwd, i);
    if (s !== "通过") return `stages.n=${i} = "${s ?? "缺失"}"，非「通过」，禁止进入 stage${i + 1}（部件1）。`;
  }
  return undefined;
}

/**
 * gate/falsified.list 解析：每行 `<tag>\t<证伪条件>`；无 tab 的旧行 = 只记了 tag。
 * 证伪必须能被复述成「在什么前提/实现/参数下失败」——只写「这条路不通」无法区分
 * 「方法没对」与「路本来就不通」。
 */
function falsifiedMap(_cwd: string): Map<string, string> {
  const out = new Map<string, string>();
  const r = dbRun(["falsified-list"]);
  if (r.status !== 0) throw new Error(`CTF 证伪查询失败，拒绝放行：${r.stderr}`);
  for (const raw of r.stdout.split("\n")) {
    const line = raw.replace(/\r$/, "");
    if (!line.trim()) continue;
    const i = line.indexOf("\t");
    const tag = i < 0 ? line.trim() : line.slice(0, i).trim();
    const cond = i < 0 ? "" : line.slice(i + 1).trim();
    if (!out.has(tag) || (!out.get(tag) && cond)) out.set(tag, cond);
  }
  return out;
}

/**
 * 网络命令是否有硬超时。
 * none      = 不是裸 curl/wget（或外层已有 timeout / 走 net.sh）
 * limited   = 自带 --max-time / --timeout，允许放行
 * unlimited = 会无限挂住，必须拦
 */
const NET_PREFIX = /^\s*(?:[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|\S+)\s+|sudo(?:\s+-\S+)*\s+|env\s+|command\s+|nohup\s+)*/;
const NET_MAX_LIMIT = (() => {
  const n = Number(process.env.PI_CTF_GATE_NET_MAX);
  return Number.isFinite(n) && n > 0 ? n : 65;
})();
function parseCurlMax(rest: string): number | null {
  const m = /--max-time[=\s]+(\d+)|-m\s*(\d+)/.exec(rest);
  return m ? Number(m[1] ?? m[2]) : null;
}
function parseWgetTimeout(rest: string): number | null {
  const m = /--timeout[=\s]+(\d+)|-T\s*(\d+)/.exec(rest);
  return m ? Number(m[1] ?? m[2]) : null;
}
function netState(seg: string): "none" | "limited" | "unlimited" | "toolong" {
  // net.sh 自带硬超时，视为已限时（同时避开 HEAVY 中 \bsh\b 对 net.sh 的误判）
  if (/\bnet\.sh\b/.test(seg)) return "limited";
  const p = NET_PREFIX.exec(seg)?.[0] ?? "";
  const rest0 = seg.slice(p.length);
  const tm = /^(?:[^\s/]*\/)?timeout\s+(\d+(?:\.\d+)?)\S*\s+/.exec(rest0);
  if (tm) {
    if (Number(tm[1]) > NET_MAX_LIMIT) return "toolong";
    // 外层 timeout 包住的网络命令也算已限时；包住其他命令则仍由 HEAVY 判
    const inner = rest0.slice(tm[0].length);
    return /^(?:[^\s/]*\/)?(curl|wget)\b/.test(inner) ? "limited" : "none";
  }
  const m = /^(?:[^\s/]*\/)?(curl|wget)\b/.exec(rest0);
  if (!m) return "none";
  const rest = rest0.slice(m[0].length);
  const n = m[1] === "curl" ? parseCurlMax(rest) : parseWgetTimeout(rest);
  if (n === null) return "unlimited";
  return n > NET_MAX_LIMIT ? "toolong" : "limited";
}

/** 判断一段命令是否“把内容写进受保护路径”（读 gate 文件并重定向到 /tmp 不算） */
function writesProtected(seg: string): boolean {
  const grab = (re: RegExp): string[] => {
    const out: string[] = [];
    let m: RegExpExecArray | null;
    while ((m = re.exec(seg))) out.push(m[1] ?? m[2] ?? m[3] ?? "");
    return out;
  };
  if (grab(/>>?\s*("[^"]+"|'[^']+'|\S+)/g).some(isProtected)) return true;
  if (grab(/\btee\s+(?:-a\s+)?("[^"]+"|'[^']+'|\S+)/g).some(isProtected)) return true;
  const seds = grab(/\bsed\s+-i\b([^;&|]*)/g);
  if (seds.some((args) => args.split(/\s+/).filter(Boolean).some(isProtected))) return true;
  // rm/dd/truncate：任一参数是闸门状态就算写
  const muts = grab(/\b(?:rm|dd|truncate)\b([^;&|]*)/g);
  for (const args of muts) {
    if (args.split(/\s+/).filter(Boolean).some(isProtected)) return true;
  }
  // cp/mv：只看目标（最后一个参数），允许把闸门文件备份到别处
  const copies = grab(/\b(?:cp|mv)\b([^;&|]*)/g);
  for (const args of copies) {
    const list = args.split(/\s+/).filter(Boolean).filter((a) => !a.startsWith("-"));
    if (list.length >= 2 && isProtected(list[list.length - 1])) return true;
  }
  return false;
}

/**
 * 命令级闸门（tool_call 与 user_bash 共用）。
 * 覆盖：命令替换 / 拼接 / 直改状态 / 重活绕 run.sh / falsified tag / 阶段连续性。
 * 顺带返回 segs / work：调用方不必再 splitSegments 一遍，过滤表达式只写一处。
 */
interface GuardResult {
  reason?: string;
  segs: string[];
  work: string[];
}

function guardCore(cwd: string, cmd: string, opts: { stage: boolean }): GuardResult {
  const out: GuardResult = { segs: [], work: [] };
  if (hasUnquotedSubst(cmd)) return { ...out, reason: "禁止未加引号的命令替换 $()/反引号。" };
  out.segs = splitSegments(cmd);
  if (out.segs.length === 0) return out;
  if (out.segs.some(isGateSeg)) {
    const gateIdx = out.segs.findIndex(isGateSeg);
    const before = out.segs.slice(0, gateIdx);
    const after = out.segs.slice(gateIdx + 1);
    const okBefore = before.every((s) => /^\s*(?:cd|pushd)\s+\S+\s*$/.test(s));
    if (!okBefore || after.length > 0 || out.segs.filter(isGateSeg).length > 1) {
      return { ...out, reason: "闸门脚本只允许单条执行（前面最多带 cd），禁止与其它命令用 ; && || | 拼接。" };
    }
  }
  for (const s of out.segs) {
    if (!isGateSeg(s) && writesProtected(s)) return { ...out, reason: "禁止绕过闸门脚本直接改闸门（部件2）。" };
  }
  // 禁止把别处（尤其是比赛根目录）的 run.sh/check.sh 拷进本题：wrapper 由扩展维护。
  for (const s of out.segs) {
    const m = /\b(?:cp|mv|install)\b([^;&|]*)/.exec(s);
    if (!m) continue;
    const args = m[1].split(/\s+/).filter((a) => a && !a.startsWith("-"));
    const names = args.map((a) => a.replace(/\\/g, "/").split("/").pop() ?? "");
    if (args.length >= 2 && names.some((n) => GATE_SCRIPTS.includes(n))) {
      return { ...out, reason: "闸门脚本由扩展自动铺设，禁止手工复制/替换 run.sh/check.sh 等；如需修复，执行 /gate-doctor 后重试。" };
    }
  }
  // kali.sh 只允许传文件（-u/-d）；带 -- 执行命令必须走 run.sh / run-long.sh
  for (const s of out.segs) {
    if (/_shared\/kali\.sh$/.test(cmdWord(s)) && /(?:^|\s)--(?:\s|$)/.test(s)) {
      return { ...out, reason: "kali.sh 只能用于传文件（-u/-d）；执行命令请走 ./run.sh <tag> <budget> -- <cmd>（长任务用 ./run-long.sh）。" };
    }
  }
  // /tmp 在 Kali 是 tmpfs，实测被打满过（7.7G/7.8G）导致后续任务全部失败；提示一次改用 /home
  if (!tmpWarned && cmd.includes("/tmp/")) {
    tmpWarned = true;
    return { ...out, reason:
      "/tmp 在 Kali 上是 tmpfs，曾被日志/wine 前缀/34MB 音频塞满（实测 7.7G/7.8G），之后所有任务都会失败。\n" +
      "请改用 $HOME/<短名>/（Kali 用户家目录，或题目录下 data/）。\n" +
      "确认要用 /tmp 就再执行一次本命令（此提示只出现一次）。" };
  }
  // 网络命令：必须先有硬超时，否则会无限挂住（实测 github/pypi 断流）
  const limitedNet = new Set<number>();
  for (let i = 0; i < out.segs.length; i++) {
    const st = netState(out.segs[i]);
    if (st === "unlimited") {
      return { ...out, reason: `网络命令必须带硬超时：curl 加 --max-time N（或 -m N），wget 加 --timeout N（或 -T N），且不超过 ${NET_MAX_LIMIT}s；也可用 $PI_CTF_SHARED/net.sh。` };
    }
    if (st === "toolong") {
      return { ...out, reason: `网络超时超过上限 ${NET_MAX_LIMIT}s（PI_CTF_GATE_NET_MAX 可调）：改小，或改用 $PI_CTF_SHARED/net.sh。` };
    }
    if (st === "limited") limitedNet.add(i);
  }
  for (let i = 0; i < out.segs.length; i++) {
    const s = out.segs[i];
    if (limitedNet.has(i)) continue;        // 已自带超时的网络命令
    if (isGateSeg(s)) continue;             // 闸门脚本自身（含 _shared/run.sh）
    if (isSharedDriver(s)) continue;        // _shared 编排/运维脚本（solve/tool/doctor/...）
    if (heavyCmd(s, cwd, cmd) && !LIGHT.test(s)) {
      return { ...out, reason: "重活必须经 ./run.sh <tag> <budget_s> -- <cmd>（部件3）。长任务见 run-long.sh。" };
    }
  }

  const fal = falsifiedMap(cwd);
  for (const s of out.segs) {
    if (isRunSeg(s)) {
      const tag = /(?:^|\s)(?:\S*\/)?(?:run|run-long)\.sh\s+(\S+)/.exec(s)?.[1] ?? "";
      if (fal.has(tag)) {
        const cond = fal.get(tag) || "旧条目只记了 tag，没写证伪条件";
        return { ...out, reason:
          `tag "${tag}" 已登记证伪（部件4；条件: ${cond}）。换实现不算新路线；前提/参数确实不同请开新 tag，` +
          "并在 BOARD.falsified 里写清与旧条目的差异（reopen）。" };
      }
    }
  }
  out.work = out.segs.filter((s) => !LIGHT.test(s) && !BOARD_PATHS.test(s) && !isExemptSeg(s));
  // stage.sh must remain callable to revalidate a failed stage; it verifies all predecessors itself.
  // run.sh wrapping a check_stage*.py probe is also allowed: debugging a validation script
  // via run.sh doesn't change stage state, so it shouldn't be blocked by the stage gate.
  const isDebugProbe = out.segs.some((s) =>
    isRunSeg(s) && /check_stage\d+\.py/.test(s));
  if (opts.stage && out.work.length > 0 && !out.segs.some((s) => baseName(s) === "stage.sh") && !isDebugProbe) {
    const g = stageGate(cwd);
    if (g) return { ...out, reason: g };
  }
  return out;
}

/**
 * 收口产物兜底：`board.sh flag '<值>'` 成功写板后，
 * 若 gate/evidence/flag.txt 不存在，就把该 flag 写进去。
 * 目的：避免"flag 只存在于子 agent 的聊天报告里"，让主 agent 事后可复算/自审。
 */
function ensureEvidenceFlag(gd: string, cmd: string): void {
  const m = /board\.sh\s+flag\s+(['"])([^'"]{4,512})\1/.exec(cmd);
  if (!m) return;
  const flag = m[2].trim();
  if (!/^(?:flag|FLAG|ctf|CTF)\{/.test(flag)) return;
  try {
    const ev = path.join(gd, "gate", "evidence");
    fs.mkdirSync(ev, { recursive: true });
    const f = path.join(ev, "flag.txt");
    if (!fs.existsSync(f)) fs.writeFileSync(f, flag + "\n", "utf8");
  } catch { /* 兜底失败不影响主流程 */ }
}

/** 新建脚本前必须先登记可用工具（BOARD.tooling），防“不查工具直接自己写” */
const SCRIPT_RE = /\.(py|sh|sage|js|rb|pl)$/i;
/** 探针/提交/解题类一次性脚本：不强制先查工具（它们是交互手段，不是自建解码器） */
const PROBE_SCRIPT_RE = /(?:^|[\\/])(?:p\d*|probe\w*|test\w*|submit\w*|solve\w*|forge\w*|brute\w*|gen\w*|dump\w*|check\w*|oracle\w*|x\d*|h\d*|g\d*|f\d*|rce\w*|relay\w*|ssrf\w*|lfi\w*|scan\w*|enum\w*|getflag\w*|exploit\w*)(?:[_-][\w-]+)?\.(?:py|sh|js|rb|pl)$/i;
function writeGate(cwd: string, p: string): string | undefined {
  if (!SCRIPT_RE.test(p)) return undefined;
  const abs = path.isAbsolute(p) ? p : path.resolve(cwd, p);
  if (fs.existsSync(abs)) return undefined;            // 改已有脚本不拦
  if (/[\\/]_shared[\\/]/.test(abs)) return undefined; // 维护工具箱本身不拦
  if (PROBE_SCRIPT_RE.test(abs)) return undefined;      // 探针/提交器类脚本免查
  const { json, errors } = readBoard(cwd);
  if (errors.length) return "黑板契约错误，先修黑板再写脚本：\n- " + errors.join("\n- ");
  const tooling = (json as any)?.tooling;
  if (Array.isArray(tooling) && tooling.length > 0) return undefined;
  return "写新脚本前先查现成工具，按优先级：① ./_shared/tool.sh find <关键词>（如 pcap/隐写/rsa/反编译）；② Kali 装现成实现（./run.sh setup-<名> 60 -- apt install -y <包> 或 pip3 install，可 apt-cache search 找包名）；③ web_search 找成熟开源实现；三处都查不到才允许自写，" +
         `并把过程写进 tooling[]：./board.sh add tooling '{"name":"<工具名>","how":"<怎么用>","why":""}'（查到就写命中项）；三处均无就写 {"name":"none","why":"已查 tool.sh/apt/pip/web，无现成实现：<一句话原因>"}。禁止跳过②③直接手抄源码自建解码器/密码原语。`;
}

/** 模拟 edit 工具的替换结果（用于写前校验）；无法模拟时返回 null（跳过校验） */
function simulateEdit(abs: string, input: any): string | null {
  try {
    let s = fs.readFileSync(abs, "utf8");
    const edits = Array.isArray(input?.edits) ? input.edits : [];
    if (!edits.length) return null;
    for (const ed of edits) {
      const oldT = String(ed?.oldText ?? "");
      const newT = String(ed?.newText ?? "");
      if (!oldT) return null;
      const i = s.indexOf(oldT);
      if (i < 0) return null;
      s = s.slice(0, i) + newT + s.slice(i + oldT.length);
    }
    return s;
  } catch { return null; }
}

// ---- 供离线测试使用（不参与扩展运行）----
export function __testBoardFields(): string[] {
  return boardFields();
}
export function __testWrap(cmd: string, cwd: string): string {
  activeTaskDir = cwd;
  return withGateEnv(cmd);
}
export function __testGuard(cwd: string, cmd: string, opts?: { stage?: boolean }): string | undefined {
  return guardCore(cwd, cmd, { stage: opts?.stage !== false }).reason;
}
export function __testStageGate(cwd: string): string | undefined {
  return stageGate(cwd);
}
export function __testActive(): string | null { return activeGateDir; }
export function __testDisabled(p: string): boolean { return disabled(p); }
export function __testTaskRoot(p: string): string | null { return taskRootFor(p); }
export function __testWriteGate(cwd: string, p: string): string | undefined {
  return writeGate(cwd, p);
}

function nativeToolPath(p: string, cwd: string): string {
  const raw = p.replace(/^@/, "");
  // Windows read/write/edit must never resolve /mnt/d as C:\\mnt\\d.
  return path.resolve(cwd, process.platform === "win32" ? toWinPath(raw) : raw);
}

/** 展示/提示用：映射失败时不抛错，返回可读的错误占位 */
function safeBashPath(p: string): string {
  try {
    return toBashPath(p);
  } catch (e: any) {
    return `<未映射: ${String(e?.message ?? e).slice(0, 90)}>`;
  }
}

function toBashPath(p: string): string {
  const w = toWinPath(p).replace(/\\/g, "/");
  // 实时通道：宿主路径 → Kali 路径，映射表只能来自 env.json 的 mounts。
  // 无匹配 = 配置缺失 → 报错，不退回盘符约定（否则会访问到错误目录/静态快照）。
  const mapped = mapMount(w, ENVCFG);
  if (mapped) return mapped;
  if (!w.includes(":")) return w; // 已经是 Linux 侧路径
  const mt = (ENVCFG.mounts ?? []).map((m) => `${m.from} → ${m.to}`).join("；") || "（未配置）";
  throw new Error(
    `路径未覆盖在 mounts 里：${w}。现有映射：${mt}。` +
      `修：在 ~/.pi/agent/env.json 的 mounts 增加该前缀，或把项目放到已映射的目录下`,
  );
}
function withGateEnv(cmd: string): string {
  if (!activeTaskDir) throw new Error("未绑定本题执行目录");
  const _roots = resolveRoots(process.cwd());
  const sharedDir = CFG.shared || _roots.sharedRoot || "";
  // 执行后端统一由 src/exec 决定：local（Pi 在目标环境里）或 ssh（Windows → 远端）。
  // 这里不再自行判断平台/SSH，避免同一会话里两个扩展落到不同机器。
  const cfg = loadConfig(path.join(AGENT_DIR, "env.json"));
  const adapter = createAdapter({
    config: cfg,
    profileTransport: "local",
    override: (process.env.PI_CTF_EXEC_BACKEND as "local" | "ssh" | undefined) ?? undefined,
  });
  const env: Record<string, string> = {
    CTF_GATE_DIR: G(),
    CTF_GATE_DB: dbPath(),
    CTF_GATE_PY: gatePy(),
    PI_CTF_SHARED: sharedDir,
    PYTHONUTF8: "1",
    PYTHONIOENCODING: "utf-8",
  };
  if (_roots.projectRoot) env.CTF_ROOT = _roots.projectRoot;
  if (_roots.boardsRoot) env.CTF_BOARDS = _roots.boardsRoot;
  return adapter.wrap(cmd, { cwd: activeTaskDir, env }).command;
}

export default function ctfGate(pi: ExtensionAPI) {
  // profile 闸：明确属于其它领域（如 .board 的 dev/渗透）时不注册；无标记时保持旧行为（主会话可能需要 new-task）。
  const taskProfile = profileAt(process.cwd());
  if (taskProfile && taskProfile.profile.validate !== "ctf") return undefined;
  const mirrorRev = new Map<string, string>();
  const mirrorBoard = new Map<string, Record<string, unknown>>();
  // 闸门拦截一律软拦：只拦不终止，按提示改正即恢复；空转由主 agent status/steer 盯，不靠自动 terminate。
  // （结构性终止只剩：cwd 未绑单题目录的 terminate:true，和 session_start 启动即拒。）
  const deny = (reason: string) => ({ block: true, reason });
  // 阈值式黑板节奏：连续 WORK_THRESHOLD 条干活命令未更新板子才拦；板子有变化即清零。
  // 比旧版「每回合首条命令即拦」少几乎全部拦截，同时保证黑板至少每几个动作更新一次（调度信号保留）。
  const WORK_THRESHOLD = 6;
  let lastBoardRaw: string | null = null;
  let workCount = 0;
  const resetWorkCount = () => { workCount = 0; };
  const dropBoard = () => { lastBoardRaw = null; };
  activeGateDir = null;

  // ---- 轮数上限（软限 + 缓冲豁免）----
  // TURN_LIMIT 轮内正常；TURN_LIMIT+1 ~ TURN_LIMIT+GRACE 为缓冲期（先警告一次，其余放行）；
  // 超过缓冲期后硬拦：只允许 board.sh 收口与只读查看，迫使 agent 写 next 后结束。
  const TURN_LIMIT_DEFAULT = Number(process.env.PI_CTF_TURN_LIMIT || 45);
  const TURN_GRACE = Number(process.env.PI_CTF_TURN_GRACE || 10);
  let TURN_LIMIT = TURN_LIMIT_DEFAULT;   // 可被题目级 gate/turn_limit 覆盖（主 agent 派活前写入）
  let turnCount = 0;
  let graceWarned = false;
  const resetTurns = () => { turnCount = 0; graceWarned = false; tmpWarned = false; };
  /** 题目级轮数上限：优先 gate/turn_limit 文件（内容为整数），否则默认值。与任务简报的「预算 ≤N 轮」对齐。 */
  const loadTurnLimit = (gd: string) => {
    TURN_LIMIT = TURN_LIMIT_DEFAULT;
    try {
      const f = path.join(gd, "gate", "turn_limit");
      if (fs.existsSync(f)) {
        const n = Number(fs.readFileSync(f, "utf8").trim());
        if (Number.isFinite(n) && n > 0) TURN_LIMIT = Math.floor(n);
      }
    } catch { /* 读不到就用默认 */ }
  };

  // 收口期仍允许的命令：board.sh（写板/收口）与只读查看。用字符串判断，避免正则歧义。
  const READONLY_CMDS = ["ls", "cat", "head", "tail", "wc", "grep", "rg", "find", "stat", "file",
                         "md5sum", "sha256sum", "echo", "pwd", "xxd", "od", "strings", "git status"];
  function isWrapUpCommand(cmd: string): boolean {
    const c = cmd.trim();
    if (!c) return true;
    if (c.includes("board.sh")) return true;                       // 写板/收口
    const first = c.split(/\s+/)[0].replace(/^.*[\/]/, "");        // 取命令名（去掉路径）
    if (READONLY_CMDS.some((r) => r === first || c.startsWith(r + " "))) return true;
    return false;
  }

  pi.on("session_start", async (_event, ctx) => {
    if (isContestRoot(ctx.cwd)) throw new Error("ctf 子会话禁止在比赛根目录启动；登录/下载请交 recon，解题请用 challs/<题号-题名>");
    resetTurns();
    const gd = taskRootFor(toWinPath(ctx.cwd));
    if (!gd || disabled(gd) || !fs.existsSync(path.join(ctx.cwd, ".ctf-gate")))
      throw new Error("ctf 单题目录缺少 .ctf-gate 或未被闸门识别，拒绝无闸运行");
    bindOwner(ctx, gd);
    activeGateDir = gd;
    const err = ensureScaffold(gd);
    if (err) ctx.ui?.notify?.(`[ctf-gate] ${err}`, "error");
  });

  pi.registerCommand("new-task", {
    description: "归档并重置指定题目的黑板（可传题目目录）",
    handler: async (args, ctx) => {
      const gd = args?.trim() ? taskRootFor(path.resolve(ctx.cwd, args.trim())) : taskRootFor(ctx.cwd);
      if (!gd || disabled(gd)) {
        ctx.ui?.notify?.("[ctf-gate] 请传明确的题目目录，未重置任何黑板", "warning");
        return;
      }
      bindOwner(ctx, gd);
      const dest = resetTask(gd);
      ctx.ui?.notify?.(`[ctf-gate] ${gd} 的旧状态归档到 ${dest}，黑板已重置`, "info");
    },
  });

  pi.registerCommand("gate-boards", {
    description: "列出当前主会话每道题的 SQLite 黑板（不创建新题）",
    handler: async (_args, ctx) => {
      const owner = resolveOwnerKey(ctx);
      const root = path.join(ownerDir(owner), "challenges");
      const rows: string[] = [];
      if (fs.existsSync(root)) for (const slug of fs.readdirSync(root).sort()) {
        if (!/^[a-f0-9]{16}$/.test(slug)) continue;
        const dir = path.join(root, slug);
        try {
          const name = fs.readFileSync(path.join(dir, "CHALLENGE.txt"), "utf8").trim();
          if (!fs.existsSync(path.join(dir, "gate.sqlite"))) continue;
          rows.push(`${name} -> ${path.join(dir, "gate.sqlite")}`);
        } catch {}
      }
      ctx.ui?.notify?.(rows.length ? rows.join("\n") : "[ctf-gate] 本主会话尚无题目黑板", "info");
    },
  });

  pi.registerCommand("gate-doctor", {
    description: "检查本题执行链：题目目录 / 库 / Kali 路径 / SSH 环境 / wrapper 版本",
    handler: async (_args, ctx) => {
      const gd = taskRootFor(ctx.cwd) ?? activeGateDir;
      if (!gd) {
        ctx.ui?.notify?.("[ctf-gate] 当前不在题目目录；先 cd 到挑战目录再运行", "warning");
        return;
      }
      bindOwner(ctx, gd);
      const rows: string[] = [];
      rows.push(`题目目录: ${gd}`);
      rows.push(`Kali 路径: ${safeBashPath(gd)}（HGFS 实时共享）`);
      rows.push(`黑板库: ${dbPath()}`);
      const kaliTarget = process.env.PI_KALI_HOST || ENVCFG.kali?.target || "未配置（见 env.json 的 kali.target）";
      rows.push(`bash 环境: 单 Kali 模式——Windows 宿主上每条 bash 自动经 SSH 在 Kali (${kaliTarget}) 执行并 cd 到本题；你写的命令就是 Kali 侧命令。`);
      for (const name of GATE_SCRIPTS) {
        const p = path.join(gd, name);
        const body = LOCAL_MAP[name] ?? sharedScriptBody(name);
        let state = "缺失";
        try {
          const cur = fs.readFileSync(p, "utf8");
          state = body && cur === body ? "规范" : "与规范不一致（将自动修复）";
        } catch {}
        rows.push(`${name}: ${state}`);
      }
      rows.push(`Kali 缺工具/依赖由子代理在 Kali 内自行安装；SSH 失败先查 ${kaliTarget} 可达性。`);
      ctx.ui?.notify?.(rows.join("\n"), "info");
    },
  });

  pi.on("before_agent_start", async (event, ctx) => {
    if (isContestRoot(ctx.cwd)) throw new Error("ctf.cwd 是比赛根目录；拒绝注入混题黑板，请用独立题目目录");
    const gd = taskRootFor(toWinPath(ctx.cwd));
    if (!gd || disabled(gd) || !fs.existsSync(path.join(ctx.cwd, ".ctf-gate")))
      throw new Error("ctf 单题目录缺少 .ctf-gate 或未绑定单题黑板；拒绝无闸运行");
    bindOwner(ctx, gd);
    activeGateDir = gd;   // 当前会话所在题目
    loadTurnLimit(gd);    // 题目级轮数上限（gate/turn_limit），与任务简报对齐
    // 阈值模式：每回合计数清零；板子内容作为比较基线（板子一变计数也归零）。
    // 干活命令连续 WORK_THRESHOLD 条没更新黑板才拦，避免每回合开局被拦的空转。
    resetWorkCount();
    const err = ensureScaffold(gd);
    const { json, raw, errors } = readBoard(gd);
    lastBoardRaw = raw;
    syncFalsified(gd, json);
    const body = json === null
      ? "（BOARD.json 缺失或 JSON 非法，请先修正）"
      : errors.length
        ? "（BOARD.json 契约错误，修正前注入内容为空）\n- " + errors.join("\n- ")
        : renderBoard(json);
    return {
      systemPrompt:
        event.systemPrompt +
        `\n\n## CTF 黑板（本题 ${gd}；SQLite：${dbPath()}，每轮由 harness dump 注入）\n` +
        "本题黑板只与同一主会话下的本题子 agent 共用；其它题有独立的阶段、证伪和证据。\n" +
        "\n【开工第一步 —— 不看历史产物就动手 = 白烧轮次】\n" +
        "  1) ./board.sh show                        先看 verified / falsified / next / flags\n" +
        "  2) ls -la && ls -la gate/evidence/        看已有脚本与证据（*_out.txt / *.bin / *.png / *.json）\n" +
        "  3) 有 findings*.md 必须先读               上一棒的完整结论、已证伪路线、卡点\n" +
        "  4) 有 solve*.py / probe*.py / an*.py 先看用法（读文件头部注释即可），能复用就复用\n" +
        "  禁止：重跑上一棒已经跑过的探测、重写已有的同一份脚本、重试 falsified[] 里已有的 tag。\n" +
        "  若你判断必须重做，先在 ./board.sh next 里写明「为什么上一棒的做法不够」再动手。\n" +
        "更新方式（唯一推荐）：用 ./board.sh 追加，**不要 write 整份覆盖** —— BOARD.json 只是 SQLite 缓存镜像，整份 write 与并发写者必然撞 rev，会连续失败白烧轮次。\n" +
        "  ./board.sh show                                     开局先看当前板与各数组长度\n" +
        "  ./board.sh verified <tag> <fact> [evidence]         追加一条已验证事实\n" +
        "  ./board.sh falsified <tag> <condition> [observed]   追加一条证伪（condition 必填）\n" +
        "  ./board.sh next '<一句话>'                           追加下一步\n" +
        "  ./board.sh flag '<值>' [basis]                       仅真 flag 落地后（会**自动**补写 gate/evidence/flag.txt，若你要放额外证据再自己写）\n" +
        "  ./board.sh add <field> '<json对象>' / append <field> '<字符串>'    数组字段（hypotheses/tooling 等）\n" +
        "  ./board.sh set challenge '{\"name\":\"#id 题名\",\"remote\":\"host:port\"}' | set params '{...}'   对象字段（challenge/params），**只能用它写**\n" +
        "board.sh 内部走 snapshot→合并→import --rev，只追加不删旧行；并行冲突时重试一次即成功。仅在确认无并发写者时才用 read→合并→write。\n" +
        "临时文件：**不要用 /tmp**（Kali 上是 tmpfs，实测被打满 7.7G/7.8G 后所有任务失败）；用 $HOME/<短名>/（Kali 家目录）或题目录 data/。\n" +
        `执行环境：read/write/edit 用宿主原生路径；bash 由统一执行后端决定（execution.backend=local 时就是本机/Kali 本地执行，=ssh 时才经远端），cwd 已自动进入本题\n` +
        "规则：连续 6 条干活命令内须更新一次黑板 —— 跑一条 ./board.sh next '<一句话>' 或 ./board.sh verified '<tag>' '<fact>' 即可解除，不必整份 write；查看类命令不计数；未更新只拦不终止。闸门拦截一律只拦不终止，按提示改正即恢复；环境故障（缺脚本/库不可用）立即 contact_supervisor，不要原样重试。\n" +
        "阶段入口：./stage.sh <n> <budget≤60> -- python3 data/check_stageN.py；必须独立验证真实产物，rc=0 写通过，其它写不通过；./check.sh <n> 只读判态。调试验证脚本可用 ./run.sh <tag> <budget> -- python3 data/check_stageN.py（不影响阶段状态），调通后再用 stage.sh 正式验证。普通 run 超时只证伪 tag，不推断阶段。\n" +
        "规则：新建脚本前先 $PI_CTF_SHARED/tool.sh find <关键词>，命中写进 tooling[]（没工具就填 name=none + why 原因）。\n" +
        "例外（免查，直接写）：探针/提交/解题类一次性脚本 —— p*/probe*/submit*/solve*/rce*/relay*/ssrf*/lfi*/scan*/enum*/oracle*/forge*/brute*/getflag*/exploit*/x*/h*/g*/f* 命名的 .py/.sh。\n" +
        "【可用脚本（都要用，别自己猜接口/自己写替代品）】\n" +
        "  ./run.sh <tag> <budget≤60> -- <cmd>            重活（编译/反汇编/大循环/批量探测）\n" +
        "                例外：curl/wget 带 -m/--max-time/--timeout、或命令前加 timeout N 的，直接执行即可（自带硬超时不算重活）\n" +
        "  ./run-long.sh <tag> <budget≤600> -- <cmd>      长任务（大文件处理/批量探测/循环跑二进制）\n" +
        "  $PI_CTF_SHARED/net.sh <url> [curl 参数...]          网络请求：自动带 --max-time 30 --retry 2（裸 curl 无超时会被拦）\n" +
        "  $PI_CTF_SHARED/container.py ensure <id> [<id>...]   开容器：自动腾配额，打印 address（**开容器只能用这个**）\n" +
        "  $PI_CTF_SHARED/container.py list | stop <id>        看占用 / 释放\n" +
        "  $PI_CTF_SHARED/tool.sh find <关键词>                检索工作区现成脚本/工具\n" +
        "  ./board.sh ...                                 写黑板（见上）\n" +
        "容器坑：平台真实接口是 POST /api/challenge/startChallenge {\"id\":\"<字符串>\"}；startContainer/start/openContainer 全部 404，不要猜。用 container.py 即可。\n" +
        "字段：challenge / params / verified[] / falsified[] / hypotheses[] / tooling[] / next[] / flags[]。\n" +
        "数组类型：verified/falsified/hypotheses/tooling/flags 的元素必须是对象；tooling 用 [{name: 'sagemath'}]，禁止 ['sagemath']；next 才是字符串数组。\n" +
        "连续两次相同契约/路径报错：contact_supervisor 报原错误等待回复，不要原样重试；闸门不会终止你，但重复撞同一堵墙只是浪费轮次。\n" +
        "证伪必须写条件：falsified[] = {tag, condition(在什么前提/实现/参数下失败), observed(实测输出), reopen(什么新信息可重开)}；" +
        "禁止只写「这条路不通」。\n" +
        `\n[轮数] 当前第 ${turnCount} 轮；软上限 ${TURN_LIMIT} 轮（来源 gate/turn_limit 或默认 ${TURN_LIMIT_DEFAULT}），缓冲 ${TURN_GRACE} 轮；超 ${TURN_LIMIT + TURN_GRACE} 轮后只允许 board.sh 收口与只读。任务简报里的「预算 ≤N 轮」以本行为准。\n` +
        (turnCount > TURN_LIMIT
          ? `⚠ 已进缓冲期：立刻收口 —— 拿到 flag 就 ./board.sh flag '<值>' '<basis>'，否则 ./board.sh next '<已确认事实 + 下一棒第一动作>' 然后结束。\n`
          : "") +
        "\n" + body + "\n" +
        (err ? `\n[ctf-gate] ${err}\n` : ""),
    };
  });

  // 每个 turn 开始同步官方 turnIndex（比自增可靠：重试/恢复不会错乱）；转成 1-based 便于与"第 N 轮"对齐
  pi.on("turn_start", async (event: any, _ctx) => {
    const idx = Number(event?.turnIndex ?? turnCount);
    turnCount = idx + 1;
  });

  pi.on("tool_call", async (event, ctx) => {
    const cwd = ctx.cwd;
    if (isContestRoot(cwd) || !taskRootFor(cwd) || !fs.existsSync(path.join(cwd, ".ctf-gate"))) return {
      block: true, terminate: true,
      reason: "ctf 未绑定单题目录/黑板，拒绝无闸工具调用。请在独立题目目录放 .ctf-gate 后重启；登录/按需下载交 recon。",
    };

    // ---- 轮数上限闸门：缓冲期后只允许收口与只读 ----
    if (turnCount > TURN_LIMIT + TURN_GRACE) {
      const isBash = event.toolName === "bash";
      const cmd = isBash ? String((event.input as { command?: string }).command ?? "") : "";
      const readOnlyTool = event.toolName === "read" || event.toolName === "grep" || event.toolName === "find" || event.toolName === "ls";
      if (isBash && !isWrapUpCommand(cmd)) {
        return deny(
          `已超轮数上限（第 ${turnCount} 轮，上限 ${TURN_LIMIT} + 缓冲 ${TURN_GRACE}）。现在只能收口，不能开新路线。\n` +
          `允许的命令：./board.sh verified|falsified|next|flag|show，以及只读查看（ls/cat/head/wc/grep/file/md5sum 等）。\n` +
          `请立刻执行：./board.sh next '<已确认事实 + 下一棒第一动作>'，然后结束回合。`);
      }
      // 写交付文件（findings*/subagent-artifacts 下的 md）属于收口动作，放行
      const p = String((event.input as { path?: string }).path ?? "");
      const isDeliverable = /findings[^/\\]*\.md$/i.test(p) || /subagent-artifacts[\\/]/.test(p);
      if (!isBash && !readOnlyTool && !isDeliverable) {
        return deny(
          `已超轮数上限（第 ${turnCount} 轮）。现在只能收口：用 ./board.sh 写结论/下一步，或写 findings*.md；不要再改代码或起新分析。`);
      }
    }
    // 缓冲期：超软限时警告一次（只拦这一条命令，提示后即放行）
    // 例外：写板命令永远放行——它是收口手段，拦了会造成"写板也被拦"的死锁观感
    const isBoardWriteEarly =
      event.toolName === "bash" &&
      /board\.sh(?:\s|$)/.test(String((event.input as { command?: string }).command ?? ""));
    if (turnCount > TURN_LIMIT && !graceWarned && !isBoardWriteEarly) {
      graceWarned = true;
      return deny(
        `轮数已达软上限（第 ${turnCount} 轮 / 上限 ${TURN_LIMIT}）。进入 ${TURN_GRACE} 轮缓冲豁免期：\n` +
        `请用这 ${TURN_GRACE} 轮做收尾——要么拿到 flag 写 ./board.sh flag，要么写 ./board.sh next 交接清楚。\n` +
        `缓冲期结束后只能执行写板与只读命令。再执行一次本命令即可继续。`);
    }

    if (event.toolName === "read") {
      const p = String((event.input as { path?: string }).path ?? "");
      const abs = nativeToolPath(p, cwd);
      (event.input as { path: string }).path = abs;
      if (!/(?:^|[\\/])gate[\\/]BOARD\.json$/i.test(abs)) return undefined;
      const requested = taskRootFor(dirOf(toWinPath(abs)));
      const currentTask = taskRootFor(cwd);
      const gd = requested ?? currentTask;
      if (!gd || disabled(gd)) {
        if (isBoardHome(abs)) return { block: true, reason: "未选中题目；请通过 /gate-boards 或 gate_db.py list/dump 查对应题库" };
        return undefined;
      }
      // 子代理在题 A 中不能读题 B 的 BOARD；父会话在题目目录外可指定要看的题。
      if (requested && currentTask && taskIdentity(requested) !== taskIdentity(currentTask)) {
        return { block: true, reason: "不能从当前题目目录跨题读取 BOARD.json" };
      }
      if (isBoardHome(abs) && toWinPath(abs) !== toWinPath(path.join(challengeDir(resolveOwnerKey(ctx), gd), "gate", "BOARD.json"))) {
        return { block: true, reason: "不能跨题/跨主会话读取黑板缓存" };
      }
      bindOwner(ctx, gd);
      const current = readBoard(gd);
      if (!current.json || current.errors.length) return { block: true, reason: boardProblems(gd) ?? "本题黑板读取失败" };
      const cache = path.join(G(), "BOARD.json");
      fs.writeFileSync(cache, JSON.stringify(current.json, null, 2) + "\n", "utf8");
      mirrorRev.set(dbPath(), current.raw);
      mirrorBoard.set(dbPath(), current.json);
      (event.input as { path: string }).path = cache;
      return undefined;
    }

    // write/edit：只看目标目录；不在题目内就用会话目录判定（不劫持粘性锁）
    if (event.toolName === "write" || event.toolName === "edit") {
      const p = String((event.input as { path?: string }).path ?? "");
      const abs = nativeToolPath(p, cwd);
      (event.input as { path: string }).path = abs;
      if (isBoardHome(abs) && !/(?:^|[\\/])gate[\\/]BOARD\.json$/i.test(abs)) {
        return { block: true, reason: "黑板数据库与状态目录不得直接用 write/edit 修改" };
      }
      const pTask = resolveGateDir([dirOf(toWinPath(abs))]);
      const currentTask = taskRootFor(cwd);
      const gd = pTask ?? currentTask;
      if (!gd || disabled(gd)) {
        if (isBoardHome(abs)) return { block: true, reason: "未选中题目；不得写黑板缓存" };
        return undefined;
      }
      if (pTask && currentTask && taskIdentity(pTask) !== taskIdentity(currentTask)) {
        return { block: true, reason: "不能从当前题目目录跨题写入；请派给另一题专属子代理" };
      }
      if (gd !== activeGateDir) { activeGateDir = gd; dropBoard(); }
      bindOwner(ctx, gd);
      const err = ensureScaffold(gd);
      if (err) return deny(err);
      const winAbs = toWinPath(abs).replace(/\\/g, "/");
      if (isBoardHome(abs) && !winAbs.toLowerCase().startsWith(toWinPath(path.dirname(G())).replace(/\\/g, "/").toLowerCase() + "/")) {
        return { block: true, reason: "不能跨题/跨主会话写黑板文件" };
      }
      const relGate = /(?:^|[\\/])gate[\\/]([^\\/]+)$/i.exec(winAbs);
      const relName = relGate?.[1];
      const isBoardJson = /(?:^|\/)gate\/BOARD\.json$/i.test(winAbs) &&
        (winAbs === toWinPath(path.join(gd, "gate", "BOARD.json")).replace(/\\/g, "/") ||
         winAbs === toWinPath(path.join(G(), "BOARD.json")).replace(/\\/g, "/"));
      if (/(?:^|\/)gate\/BOARD\.json$/i.test(winAbs) && !isBoardJson) {
        return { block: true, reason: "BOARD.json 必须属于当前题目或其当前会话分区，不能写其它题。" };
      }
      if (isBoardJson) {
        const current = readBoard(gd);
        if (!current.json || current.errors.length) return deny(boardProblems(gd) ?? "本题黑板快照不可用");
        const body = event.toolName === "write"
          ? String((event.input as { content?: string }).content ?? "")
          : simulateEdit(path.join(G(), "BOARD.json"), event.input as any);
        if (body === null) return { block: true, reason: "无法模拟对 BOARD.json 的 edit。推荐改用 ./board.sh verified/falsified/next/flag 追加（无需处理 rev）；确实要整份写才用 write。" };
        // The mirror was last refreshed at mirrorRev; never assume it is still current.
        const expectedRev = mirrorRev.get(dbPath());
        if (expectedRev === undefined) return deny("先 read gate/BOARD.json 取当前 rev，或直接用 ./board.sh 追加（推荐）；禁止用空白旧模板抹掉已有记录。");
        if (expectedRev !== current.raw) return deny(`BOARD 已变化：镜像 rev=${expectedRev}，当前 rev=${current.raw}。\n推荐直接用 ./board.sh verified/falsified/next/flag 追加（内部自动取最新 snapshot，不会有 rev 冲突）；\n若坚持整份写，请重新 read 当前 BOARD 后合并改动。`);
        let parsed: Record<string, unknown>;
        try { parsed = JSON.parse(body); } catch { return deny("BOARD.json 不是合法 JSON"); }
        const base = mirrorBoard.get(dbPath());
        if (base) {
          for (const field of ["verified", "falsified", "flags"] as const) {
            const oldRows = base[field] as any[];
            const newRows = parsed[field] as any[];
            const keyField = field === "flags" ? "flag" : "tag";
            if (!Array.isArray(newRows) || !Array.isArray(oldRows) || oldRows.some((row) => {
              const next = newRows.find((x) => x && x[keyField] === row[keyField]);
              return !next || Object.entries(row).some(([k, v]) => k !== keyField && v && next[k] !== v);
            })) return deny(`BOARD.${field} 不能删旧行或覆盖已有证据。\n改用 ./board.sh verified/falsified/flag 追加新行（永不覆盖旧行）；需更正就追加一条并在内容里注明与旧行的冲突。`);
          }
        }
        const werr = writeBoardJson(body, expectedRev);
        if (werr) return deny(werr);
        const after = readBoard(gd);
        if (!after.json || after.errors.length) return deny("写入后黑板读取失败；停止并联系主 agent");
        mirrorRev.set(dbPath(), after.raw);
        mirrorBoard.set(dbPath(), after.json);
        // Cache is informational only: write the canonical DB snapshot, not a lossy user JSON.
        (event.input as { content?: string }).content = JSON.stringify(after.json, null, 2) + "\n";
        const cache = path.join(G(), "BOARD.json");
        (event.input as { path: string }).path = cache;
        if (event.toolName === "write") (event.input as { content: string }).content = body;
        return undefined;
      }
      if (relName && (STATE_PATHS.test(relName) || /\.conclusion$/i.test(relName))) {
        return { block: true, reason: "闸门状态只能由闸门脚本写（部件2）。阶段请用 check.sh；证伪由 run.sh 超时登记。" };
      }
      if (isProtected(abs) || isBoardHome(abs) && /gate\.sqlite/i.test(winAbs)) {
        return { block: true, reason: "闸门状态/脚本只能由闸门脚本写（部件2）。" };
      }
      const w = writeGate(gd, abs);
      if (w) return { block: true, reason: w };
      return undefined;
    }
    if (event.toolName !== "bash") return undefined;

    // bash：路径命中题目就切换并锁定（粘性）；命令本身没路径时沿用锁
    const cmd = String((event.input as { command?: string }).command ?? "");
    if (activeGateDir && (isBoardHome(activeGateDir) || !fs.existsSync(activeGateDir))) { activeGateDir = null; dropBoard(); }
    const candidates = pathCandidates(cwd, cmd).map((p) => taskRootFor(p)).filter(Boolean) as string[];
    const currentTask = taskRootFor(cwd);
    const targets = new Set([...candidates, ...(currentTask ? [currentTask] : [])].map(taskIdentity));
    if (targets.size > 1) return { block: true, reason: "一条命令跨多道题；请按题分别执行以避免错库" };
    const gd = candidates[0] ?? currentTask;
    if (gd && gd !== activeGateDir) { activeGateDir = gd; dropBoard(); }
    if (!gd || disabled(gd)) return undefined;
    bindOwner(ctx, gd);
    const scaffoldErr = ensureScaffold(gd);
    if (scaffoldErr) return deny(scaffoldErr);
    if (cdTargets(cmd).some((p) => /^[A-Za-z]:[\\/]/.test(p))) {
      const kaliWs = ctfWorkspace() ? safeBashPath(ctfWorkspace() as string) : "<项目根的 Kali 映射>";
      return deny(`bash 在 Kali（自动 SSH）：cd 请用 Kali 路径（${kaliWs}/...）；read/write/edit 才用宿主路径。默认已自动进入本题，无须 cd。`);
    }

    const guard = guardCore(gd, cmd, { stage: true });
    if (guard.reason) return deny(guard.reason);

    const segs = guard.segs;
    if (segs.length === 0) return undefined;

    const boardNow = readBoard(gd);
    if (boardNow.json) syncFalsified(gd, boardNow.json);

    const work = guard.work;
    if (work.length === 0) {
      if (segs.some((s) => /new-task\.sh/.test(s))) dropBoard();
      if (event.input && typeof event.input === "object") {
        (event.input as { command: string }).command = withGateEnv(cmd);
      }
      return undefined;
    }
    if (boardNow.json === null || boardNow.errors.length > 0) {
      return deny(boardProblems(gd) ?? "BOARD.json 非法");
    }
    // 写板命令本身是"解除闸门"的手段：永远放行、且不参与计数。
    // （否则会出现死锁：连续 3 条未写板 → 连 ./board.sh 也被拦 → 板子永远不变 → 永远拦）
    const isBoardWrite = segs.some((s) => /board\.sh(?:\s|$)/.test(s));
    if (isBoardWrite) {
      ensureEvidenceFlag(gd, cmd);
      if (event.input && typeof event.input === "object") {
        (event.input as { command: string }).command = withGateEnv(cmd);
      }
      return undefined;
    }
    // 阈值式节奏检查：rev 变了（板子真有更新）→ 计数清零；没变 → 计数，超过阈值才拦。
    if (boardNow.raw !== lastBoardRaw) {
      lastBoardRaw = boardNow.raw;
      workCount = 0;
    }
    workCount += 1;
    if (workCount > WORK_THRESHOLD) {
      return deny(
        `已连续 ${WORK_THRESHOLD} 条干活命令未更新黑板（rev=${boardNow.raw || "?"}）。\n` +
        `解除：跑一条 ./board.sh next '<一句话>'（或 ./board.sh verified '<tag>' '<fact>'），一条即可。\n` +
        `不要 write 整份 BOARD.json —— 那是 ${dbPath()} 的缓存镜像，整份覆盖会撞 rev 并连续失败。`);
    }
    if (event.toolName === "bash" && event.input && typeof event.input === "object") {
      (event.input as { command: string }).command = withGateEnv(cmd);
    }
    return undefined;
  });

  // 用户直敲的 ! / !! 命令同样过闸门（不要求更新黑板，但拦重活与绕过写状态）
  pi.on("user_bash", async (event, ctx) => {
    const base = event.cwd || ctx.cwd;
    const candidates = pathCandidates(base, event.command).map((p) => taskRootFor(p)).filter(Boolean) as string[];
    const currentTask = taskRootFor(base);
    const targets = new Set([...candidates, ...(currentTask ? [currentTask] : [])].map(taskIdentity));
    if (targets.size > 1) return { result: {
      output: "[ctf-gate] 一条命令跨多道题；请按题分别执行以避免错库\n",
      exitCode: 126, cancelled: false, truncated: false,
    } };
    const gd = candidates[0] ?? currentTask;
    if (!gd || disabled(gd)) return undefined;
    bindOwner(ctx, gd);
    // 不为用户命令铺脚手架（避免在任意目录生成 run.sh），只按本题状态判闸
    const reason = guardCore(gd, event.command, { stage: true }).reason;
    if (reason) return {
      result: {
        output: `[ctf-gate] 已拦截：${reason}\n`,
        exitCode: 126,
        cancelled: false,
        truncated: false,
      },
    };
    const local = createLocalBashOperations();
    return { operations: {
      exec(command: string, cwd: string, options: any) {
        return local.exec(withGateEnv(command), cwd, options);
      },
    } };
  });
}

function renderBoard(b: Record<string, any>): string {
  const L: string[] = [];
  L.push("## 题目");
  L.push(`- 名称: ${b.challenge?.name ?? ""} | 远端: ${b.challenge?.remote ?? ""}`);
  L.push("## 关键参数（已确认，可复算）");
  for (const [k, v] of Object.entries(b.params ?? {})) if (v) L.push(`- ${k} = ${v}`);
  L.push("## 已证实（有产物/证据）");
  for (const x of b.verified ?? []) L.push(`- [${x.tag ?? "-"}] ${x.fact ?? ""} (证据: ${x.evidence ?? "-"})`);
  L.push("## 已证伪（必须带条件：在什么前提/实现/参数下失败；换实现≠新路线）");
  for (const x of b.falsified ?? []) {
    const cond = x.condition;
    L.push(`- [${x.tag ?? "-"}] ` +
      (cond
        ? cond
        : "⚠ 未记录证伪条件 → 补 condition（前提/实现/参数）与 observed（实测输出）" +
          (x.why ? `；旧记录(非条件): ${x.why}` : "")) +
      (x.observed ? ` | 观测: ${x.observed}` : "") +
      (x.reopen ? ` | 可重开: ${x.reopen}` : ""));
  }
  L.push("## 存活假设");
  for (const x of b.hypotheses ?? []) L.push(`- [${x.tag ?? "-"}] ${x.idea ?? ""} | 反证: ${x.falsifier ?? "-"} | 预算: ${x.budget ?? "-"}s`);
  L.push("## 现成工具（已确认可用）");
  for (const x of b.tooling ?? []) L.push(`- ${x.name ?? "?"}${x.how ? ` — ${x.how}` : ""}${x.why ? `（${x.why}）` : ""}`);
  L.push("## 下一步");
  for (const x of b.next ?? []) L.push(`- ${x}`);
  L.push("## 候选 flag（含置信度）");
  for (const x of b.flags ?? []) L.push(`- ${x.flag ?? ""} (置信度 ${x.confidence ?? "?"}: ${x.basis ?? ""})`);
  return L.join("\n");
}
