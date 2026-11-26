/**
 * kali-exec.ts — 子代理 bash 强制上 Kali（防串进操作员的 WSL 个人解题环境）
 *
 * 背景：WSL 是操作员本人的环境，工具少且不该被 AI 污染；全部进攻/侦察工具都在 Kali。
 * 作用：把 recon/pentest/audit/forensics 的每条 bash 命令包装成 ssh 到 Kali 执行。
 *       ctf 不用本扩展（ctf-gate 自带更完整的包装：环境变量注入 + 黑板绑定）。
 *
 * 工作目录映射：
 *   <项目根>/...              → <env.json mounts 里的 to>/...（HGFS 实时共享，Windows 侧文件可见）
 *   其它 Windows 路径          → Kali ~/agent-work（自建 scratch；文件读写请用 read/write/edit 工具）
 *
 * 开关：PI_KALI_EXEC=0 关闭（排障用）。
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";

import { AGENT_DIR, resolveRoots, loadEnv, mapMount } from "../src/paths/roots.ts";
import { createAdapter, loadConfig } from "../src/exec/index.ts";
import { profileAt } from "../src/config/profiles.ts";

const OFF = process.env.PI_KALI_EXEC === "0";

// 机器相关路径一律来自 env.json / 环境变量；缺失就不猜，返回 null 让调用方报错。
const ENV = loadEnv();
const HOST = process.env.PI_KALI_HOST || ENV.kali?.target || "";
const ROOTS = resolveRoots(process.cwd());
const BOARDS_ROOT = ROOTS.boardsRoot || process.env.PI_CTF_BOARDS_ROOT || "";
const GATE_PY = ROOTS.sharedRoot ? ROOTS.sharedRoot.replace(/\\/g, "/") + "/gate_db.py" : "";

// node:sqlite（Node 22.19+）；不可用时自动降级（不拦 falsified，但板路径仍可算）
let DatabaseSync: any = null;
try { DatabaseSync = createRequire(import.meta.url)("node:sqlite").DatabaseSync; } catch { DatabaseSync = null; }

/** 与 ctf-gate 完全一致的命名算法：sha1(key)[:16] */
function slug(key: string): string {
  return crypto.createHash("sha1").update(key).digest("hex").slice(0, 16);
}

/** 主会话 sessionId（pi-subagents 注入给子代理的环境变量）→ 与 ctf-gate 同一个 owner */
function ownerKey(): string {
  const e = String(process.env.PI_SUBAGENT_PARENT_SESSION || "").trim();
  return e;
}

/** 由题目目录算出黑板分区（与 ctf-gate 同一个库） */
function boardPaths(cwd: string): { db: string; dir: string } | null {
  const key = ownerKey();
  if (!key || !cwd) return null;
  const task = path.resolve(cwd).replace(/\\/g, "/").toLowerCase();
  const dir = path.join(BOARDS_ROOT, slug(key), "challenges", slug(task));
  return { db: path.join(dir, "gate.sqlite"), dir };
}

/** 板不存在则初始化（与 ctf-gate 的 bindOwner 等价） */
function ensureBoard(cwd: string): { db: string; dir: string } | null {
  const bp = boardPaths(cwd);
  if (!bp) return null;
  if (fs.existsSync(bp.db)) return bp;
  try {
    fs.mkdirSync(path.join(bp.dir, "gate", "evidence"), { recursive: true });
    fs.mkdirSync(path.join(bp.dir, "gate", "long"), { recursive: true });
    fs.writeFileSync(path.join(path.dirname(path.dirname(bp.dir)), "OWNER.txt"), ownerKey() + "\n", "utf8");
    fs.writeFileSync(path.join(bp.dir, "CHALLENGE.txt"), path.resolve(cwd) + "\n", "utf8");
  } catch { return null; }
  for (const py of ["python", "python3", "py"]) {
    try {
      execFileSync(py, [GATE_PY, "--db", bp.db, "init"], { stdio: "ignore", timeout: 15000 });
      if (fs.existsSync(bp.db)) return bp;
    } catch { /* next */ }
  }
  return null;
}

/** 该题黑板里已证伪（永久失败）的 tag 集合 */
function falsifiedTags(db: string): Set<string> {
  const out = new Set<string>();
  if (!DatabaseSync) return out;
  let d: any = null;
  try {
    d = new DatabaseSync(db, { readOnly: true });
    for (const r of d.prepare("select tag, condition from falsified").all()) {
      const t = String((r as any).tag || "").trim();
      if (t) out.add(t);
    }
  } catch { /* ignore */ } finally { try { d?.close(); } catch { /* ignore */ } }
  return out;
}

/** 黑板当前 rev（写板会 +1；“查看”不算更新） */
function boardRev(db: string): string {
  if (!DatabaseSync) return "";
  let d: any = null;
  try {
    d = new DatabaseSync(db, { readOnly: true });
    const r = d.prepare("select v from meta where k='rev'").get();
    return String((r as any)?.v ?? "");
  } catch { return ""; } finally { try { d?.close(); } catch { /* ignore */ } }
}

// ── 写板节奏闸门（与 ctf-gate 同款）：连续 N 条干活命令必须更新一次黑板 ──
const WORK_THRESHOLD = 3;
const READONLY_CMDS = ["ls", "cat", "head", "tail", "wc", "grep", "rg", "find", "stat", "file",
  "md5sum", "sha256sum", "echo", "pwd", "xxd", "od", "strings", "which", "id", "hostname", "date"];
const WRITE_OPS = /(^|[^>])>>?|\btee\b|\bsed\s+-i\b|\brm\b|\bmv\b|\bcp\b|\bdd\b|\btruncate\b/;

/** 每个黑板独立计数：A 题写板不能解除 B 题的拦截。 */
const BOARD_STATE = new Map<string, { work: number; rev: string }>();

function boardState(db: string): { work: number; rev: string } {
  let st = BOARD_STATE.get(db);
  if (!st) {
    st = { work: 0, rev: "" };
    BOARD_STATE.set(db, st);
  }
  return st;
}

function isReadonlyCmd(cmd: string): boolean {
  const first = cmd.trim().split(/\s+/)[0]?.replace(/^.*\//, "") || "";
  return READONLY_CMDS.includes(first) && !WRITE_OPS.test(cmd);
}
/** 口令：PI_KALI_PASS 环境变量优先，其次 _shared/.kali_pw（单行）；源码不放明文（与 ctf-gate 的 kaliPassword 对齐）。 */
let pwCache: string | null | undefined;
function kaliPass(): string | null {
  if (pwCache !== undefined) return pwCache;
  pwCache = null;
  const env = (process.env.PI_KALI_PASS || "").trim();
  if (env) { pwCache = env; return pwCache; }
  try {
    const pwFile = process.env.PI_KALI_PW_FILE || ENV.kali?.passwordFile;
    if (!pwFile) return pwCache;
    const v = fs.readFileSync(pwFile, "utf8").trim();
    if (v) pwCache = v;
  } catch { /* ignore */ }
  return pwCache;
}


export default function kaliExec(pi: ExtensionAPI) {
  if (OFF) return;
  pi.on("tool_call", async (event, ctx) => {
    if (event.toolName !== "bash") return undefined;
    // 执行后端只由 src/exec 决定（execution.backend 优先；显式配置，不从 profile 推断主机）。
    const taskProfile = profileAt(String(ctx.cwd || ""));
    const adapter = createAdapter({
      config: loadConfig(path.join(AGENT_DIR, "env.json")),
      profileTransport: taskProfile?.profile.transport,
    });
    if (adapter.backend !== "ssh") return undefined;
    const input = event.input as { command?: string };
    const cmd = String(input?.command ?? "");
    if (!cmd.trim()) return undefined;

    // ── 黑板绑定（与 ctf-gate 同一个库）：注入 CTF_GATE_DIR / CTF_GATE_DB / CTF_GATE_PY ──
    const board = ensureBoard(String(ctx.cwd || ""));
    const gateEnv: Record<string, string> = { PYTHONUTF8: "1", PYTHONIOENCODING: "utf-8" };
    if (board) {
      const sharedRoot = resolveRoots(String(ctx.cwd || "")).sharedRoot;
      gateEnv.CTF_GATE_DIR = path.join(board.dir, "gate");
      gateEnv.CTF_GATE_DB = board.db;
      if (sharedRoot) gateEnv.CTF_GATE_PY = path.join(sharedRoot, "gate_db.py");
      else ctx.ui?.notify?.("[kali-exec] 解析不到 sharedRoot，未注入 CTF_GATE_PY", "warning");
    }

    // ── falsified 重试拦截：./run.sh <tag> / ./run-long.sh <tag> 的 tag 已在板里证伪则拒 ──
    if (board) {
      const tm = /(?:\/\/)?(run|run-long)\.sh\s+([A-Za-z0-9_.-]+)/.exec(cmd);
      const tag = tm?.[2];
      if (tag) {
        const fals = falsifiedTags(board.db);
        if (fals.has(tag)) {
          return {
            block: true,
            reason: `[kali-exec] tag \`${tag}\` 已在本题目黑板 falsified（条件/原因见 ./board.sh show 或 gate_db.py dump）。换一个 tag 名重试，不要原样重跑。`,
          };
        }
      }
    }

    // ── 写板节奏闸门：写板命令永远放行、不计数；查看类不计数；其余计数（按黑板独立） ──
    if (board) {
      const st = boardState(board.db);
      if (/board\.sh(?:\s|$)/.test(cmd) || /gate_db\.py/.test(cmd)) {
        st.work = 0;                         // 写板本身就是解阵手段
      } else {
        const rev = boardRev(board.db);
        if (rev && rev !== st.rev) { st.rev = rev; st.work = 0; }
        if (!isReadonlyCmd(cmd)) {
          st.work += 1;
          if (st.work > WORK_THRESHOLD) {
            return {
              block: true,
              reason: `[kali-exec] 本题已连续 ${WORK_THRESHOLD} 条干活命令未更新黑板（rev=${rev || "?"}）。\n` +
                `解除：跑一条 ./board.sh next '<一句话>' 或 ./board.sh verified '<tag>' '<fact>'，一条即可（查看类命令不计数）。\n` +
                `本题板：${board.db}`,
            };
          }
        }
      }
    }
    // 执行：交给统一后端（local = 本机/Kali 本地；ssh = 远端）。本扩展不再自行构造远程命令。
    const wrapped = adapter.wrap(cmd, { cwd: String(ctx.cwd || ""), env: gateEnv });
    input.command = wrapped.command;
  });
}
