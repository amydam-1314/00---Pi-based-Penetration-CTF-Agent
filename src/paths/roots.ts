/**
 * roots.ts — 项目根 / 数据根 / 机器映射的唯一解析入口。
 *
 * 准则：**存储与引用尽量可迁移，执行时解析成绝对路径。**
 *   - 项目内文件/脚本/规则（_shared/gate_db.py、BOARD_RULES.md） → 相对 projectRoot
 *   - 扩展自带模板/资源（BOARD.template.json）                    → 相对扩展安装目录
 *   - 题目内附件/证据/报告                                        → 相对题目目录
 *   - SSH 密钥 / 外部软件 / 共享挂载点                             → 本机 env.json，不进提示词与代码
 *   - 工具执行用的 cwd、库路径                                     → 运行时解析成绝对路径
 *   - 日志与报告里的执行路径                                       → 保留绝对路径，便于排障
 *
 * 相对路径**不默认相对 cwd**：调用方必须声明基准（projectRoot / campaignRoot / 题目目录），
 * 本模块负责校验基准存在，并在缺失、多候选、映射不明时报错，而不是静默回退。
 */
import fs from "node:fs";
import path from "node:path";

export type Env = {
  /** 覆盖 projectRoot；无效则报错，不回退到猜测 */
  projectRoot?: string;
  /** 覆盖 boardsRoot */
  boardsRoot?: string;
  /** Kali SSH 目标，如 "user@host" */
  kali?: { target?: string; passwordFile?: string };
  /** 机器映射（示例）：[{ from: "<宿主挂载源>/", to: "<目标机挂载点>/" }] */
  mounts?: Array<{ from: string; to: string }>;
};

export type Roots = {
  projectRoot: string | null;
  campaignRoot: string | null;
  sharedRoot: string | null;
  boardsRoot: string | null;
  source: "env" | "walk" | "none";
  /** 自动发现时是凭标记还是凭目录特征 */
  discoveredBy?: "marker" | "feature" | "none";
  checked: string[];
  errors: string[];
};

export const AGENT_DIR =
  process.env.PI_CODING_AGENT_DIR ||
  path.join(process.env.USERPROFILE || process.env.HOME || ".", ".pi", "agent");

export function norm(p: string): string {
  return p.replace(/\\/g, "/").replace(/\/+$/, "");
}

function isDir(p: string): boolean {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
}

function isFile(p: string): boolean {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

/** 读 ~/.pi/agent/env.json；缺失或坏掉都返回 {}，并把原因记进 errors（不静默） */
export function loadEnv(errors: string[] = []): Env {
  const f = path.join(AGENT_DIR, "env.json");
  if (!isFile(f)) return {};
  try {
    const parsed = JSON.parse(fs.readFileSync(f, "utf8"));
    if (!parsed || typeof parsed !== "object") throw new Error("不是 JSON 对象");
    return parsed as Env;
  } catch (e: any) {
    errors.push(`env.json 解析失败：${e?.message ?? e}`);
    return {};
  }
}

export const MARKER = "ctf.project.json";

/** 优先认专用标记；目录特征只作兼容发现（精度低，易误认） */
export function projectMarker(dir: string): { ok: boolean; kind?: string; error?: string } {
  const f = path.join(dir, MARKER);
  if (!isFile(f)) return { ok: false };
  try {
    const j = JSON.parse(fs.readFileSync(f, "utf8"));
    if (j?.kind !== "ctf-project") return { ok: false, error: `${f} 存在但 kind 不是 ctf-project` };
    return { ok: true, kind: j.kind };
  } catch (e: any) {
    return { ok: false, error: `${f} 解析失败：${e?.message ?? e}` };
  }
}

function qualifiesAsProject(dir: string): boolean {
  if (projectMarker(dir).ok) return true;
  // 目录特征只作兼容发现，且必须"像一整套项目"：
  //   - 有 _shared/gate_db.py（强特征）
  //   - 或有 ctf-boards/ 且同时有 _shared/（弱特征+配套）
  // 单有 ctf-boards/ 不算——扩展安装目录里就可能有测试残留的 ctf-boards/，会把 agents 目录误认成项目根。
  if (isFile(path.join(dir, "_shared", "gate_db.py"))) return true;
  if (isDir(path.join(dir, "ctf-boards")) && isDir(path.join(dir, "_shared"))) return true;
  return false;
}

function qualifiesAsCampaign(dir: string): boolean {
  return isDir(path.join(dir, "challs"));
}

/** 从 start 向上最多 6 层找项目根；nearest 优先 */
export function findRoots(
  start: string,
  errors: string[] = [],
): { projectRoot: string | null; campaignRoot: string | null; checked: string[]; sourceKind: "marker" | "feature" | "none" } {
  const checked: string[] = [];
  let marked: string | null = null;   // 带专用标记的目录（唯一权威）
  let feature: string | null = null;  // 仅凭目录特征推断（兼容，可能误认）
  let campaignRoot: string | null = null;
  let d = path.resolve(start);
  for (let i = 0; i < 6; i++) {
    checked.push(d);
    const mk = projectMarker(d);
    if (mk.error) errors.push(mk.error + "（修好该文件或删掉它，改走目录特征发现）");
    if (!marked && mk.ok) marked = d;
    if (!feature && qualifiesAsProject(d)) feature = d;
    if (!campaignRoot && qualifiesAsCampaign(d)) campaignRoot = d;
    if (marked && campaignRoot) break;
    const up = path.dirname(d);
    if (up === d) break;
    d = up;
  }
  const projectRoot = marked ?? feature;
  return { projectRoot, campaignRoot, checked, sourceKind: marked ? "marker" : feature ? "feature" : "none" };
}

export function resolveRoots(start = process.cwd()): Roots {
  const errors: string[] = [];
  const env = loadEnv(errors);

  let projectRoot: string | null = null;
  let source: Roots["source"] = "none";

  const envRoot = env.projectRoot || process.env.CTF_PROJECT_ROOT;
  if (envRoot) {
    if (isDir(envRoot)) {
      projectRoot = path.resolve(envRoot);
      source = "env";
    } else {
      const where = env.projectRoot ? "~/.pi/agent/env.json 的 projectRoot" : "环境变量 CTF_PROJECT_ROOT";
      errors.push(
        `配置的 projectRoot 不存在：${envRoot}（来源：${where}）。修：改成真实路径，或删掉该键让自动发现接管；**不回退**到发现结果`,
      );
      // 显式配置失效 = 停止，不静默回退
      return {
        projectRoot: null,
        campaignRoot: null,
        sharedRoot: null,
        boardsRoot: null,
        source: "env",
        discoveredBy: "none",
        checked: [],
        errors,
      };
    }
  }

  const walked = findRoots(start, errors);
  if (!projectRoot && walked.projectRoot) {
    projectRoot = walked.projectRoot;
    source = "walk";
  }
  if (envRoot && walked.projectRoot && norm(walked.projectRoot) !== norm(projectRoot ?? "")) {
    errors.push(
      `projectRoot 冲突：env.json/环境变量=${projectRoot}，向上发现=${walked.projectRoot}。` +
        `修：要么删掉 ~/.pi/agent/env.json 的 projectRoot（让发现结果生效），要么把它改成 ${walked.projectRoot}；二者取一，别同时存在`,
    );
    return {
      projectRoot: null,
      campaignRoot: null,
      sharedRoot: null,
      boardsRoot: null,
      source: "env",
      discoveredBy: walked.sourceKind,
      checked: walked.checked,
      errors,
    };
  }

  const campaignRoot = walked.campaignRoot;
  const sharedRoot = projectRoot ? path.join(projectRoot, "_shared") : null;

  const boardsEnv = env.boardsRoot || process.env.PI_CTF_BOARDS_ROOT;
  let boardsRoot: string | null = null;
  if (boardsEnv) {
    if (isDir(boardsEnv)) boardsRoot = path.resolve(boardsEnv);
    else errors.push(`配置的 boardsRoot 不存在：${boardsEnv}`);
  } else if (projectRoot) {
    for (const cand of [path.join(projectRoot, "ctf-boards"), path.join(campaignRoot ?? projectRoot, "ctf-boards")]) {
      if (isDir(cand)) {
        boardsRoot = cand;
        break;
      }
    }
    if (!boardsRoot)
      errors.push(
        `在 ${projectRoot} 下找不到 ctf-boards 目录。修：在该目录建 ctf-boards/，或在 ~/.pi/agent/env.json 用 boardsRoot 指向真实位置`,
      );
  } else {
    errors.push(
      `没有找到项目根（从 ${start} 向上 6 层无 ${MARKER}、无 _shared/gate_db.py、无 ctf-boards/）。` +
        `修：在项目根放 ${MARKER}，或在 ~/.pi/agent/env.json 设 projectRoot`,
    );
  }

  return {
    projectRoot,
    campaignRoot,
    sharedRoot,
    boardsRoot,
    source,
    discoveredBy: walked.sourceKind,
    checked: walked.checked,
    errors,
  };
}

/** 基准是显式概念，不做字符串形态猜测（不靠 "challs/" 之类判断） */
export type Base = "project" | "campaign" | "extension" | "boards" | "challenge";

export type ResolveCtx = { roots: Roots; challengeDir?: string };

/**
 * 把「可迁移引用」解析成执行用的绝对路径。
 * - 绝对路径：原样返回（执行/日志可以持有绝对路径）
 * - 相对路径：**必须显式给 base**，按该基准解析；基准缺失 → 报错，不猜 cwd、不猜形态
 */
export function resolvePath(ref: string, base: Base, ctx: ResolveCtx): { abs: string | null; error?: string } {
  if (path.isAbsolute(ref) || /^[A-Za-z]:[\\/]/.test(ref)) return { abs: path.resolve(ref) };
  let root: string | null | undefined;
  switch (base) {
    case "project":
      root = ctx.roots.projectRoot;
      break;
    case "campaign":
      root = ctx.roots.campaignRoot;
      break;
    case "extension":
      root = AGENT_DIR;
      break;
    case "boards":
      root = ctx.roots.boardsRoot;
      break;
    case "challenge":
      root = ctx.challengeDir ?? null;
      if (!root) return { abs: null, error: `base=challenge 需要 challengeDir（当前未提供）` };
      break;
  }
  if (!root) return { abs: null, error: `相对路径 "${ref}" 需要 base=${base}，但该基准未解析出来（见 roots.errors）` };
  return { abs: path.resolve(root, ref) };
}

/**
 * 按 env.json 的 mounts 把宿主路径映射到目标机路径。
 * 规则：最长前缀优先；必须命中路径分段边界（`C:/case` 不会匹配 `C:/case2`）；大小写不敏感；无匹配返回 null（不猜）。
 */
export function mapMount(hostPath: string, env?: Env): string | null {
  const e = env ?? loadEnv();
  const p = norm(hostPath);
  const maps = (e.mounts ?? [])
    .filter((m) => m && typeof m.from === "string" && m.from.trim())
    .map((m) => ({ from: norm(m.from), to: norm(m.to ?? "") }))
    .sort((a, b) => b.from.length - a.from.length); // 最长前缀优先
  const lower = p.toLowerCase();
  for (const m of maps) {
    const from = m.from.toLowerCase();
    if (lower === from || lower.startsWith(from + "/")) {
      const rest = p.slice(m.from.length).replace(/^\/+/, "");
      return rest ? `${m.to}/${rest}` : m.to;
    }
  }
  return null;
}

/** 反查：目标机路径 → 宿主路径（同样最长前缀优先；无匹配 null） */
export function unmapMount(targetPath: string, env?: Env): string | null {
  const e = env ?? loadEnv();
  const p = norm(targetPath);
  const maps = (e.mounts ?? [])
    .filter((m) => m && typeof m.to === "string" && m.to.trim())
    .map((m) => ({ from: norm(m.from), to: norm(m.to) }))
    .sort((a, b) => b.to.length - a.to.length);
  const lower = p.toLowerCase();
  for (const m of maps) {
    const to = m.to.toLowerCase();
    if (lower === to || lower.startsWith(to + "/")) {
      const rest = p.slice(m.to.length).replace(/^\/+/, "");
      return rest ? `${m.from}/${rest}` : m.from;
    }
  }
  return null;
}
