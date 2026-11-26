import fs from "node:fs";
import { resolveRoots } from "./roots.ts";
import path from "node:path";

/** Contest-level data is not a challenge, even if legacy gate/ or flag files exist. */
export function isContestRoot(dir: string): boolean {
  const p = path.resolve(dir);
  if (fs.existsSync(path.join(p, ".ctf-contest"))) return true;
  const isDir = (name: string) => {
    try { return fs.statSync(path.join(p, name)).isDirectory(); } catch { return false; }
  };
  if (isDir("challs") || isDir("challenges")) return true;
  return ["challenge-list.md", "challenge_list.json", "_shared/challenge_list.json"]
    .some((name) => fs.existsSync(path.join(p, name)));
}

/** Resolve only filesystem paths; never guess a working directory from task prose. */
export function ctfLaunchProblem(cwd: unknown): string | undefined {
  if (typeof cwd !== "string" || !cwd.trim()) return "ctf 必须显式传入一道题的 cwd";
  if (process.platform === "win32" && /^\/mnt\/[a-z](?:\/|$)/i.test(cwd)) {
    return "ctf.cwd 必须用宿主原生的 Windows 路径，不能传 WSL/Linux 挂载路径（/mnt/...）";
  }
  try {
    if (!fs.statSync(cwd).isDirectory()) return "ctf.cwd 不是目录";
  } catch { return "ctf.cwd 不存在；先创建题目目录再派"; }
  if (isContestRoot(cwd)) {
    return "ctf.cwd 是比赛根目录，禁止当作单题解题或取料。请派到 challs/<题号-题名>/；平台登录/题单/按需下载由主 agent 用 browser/web_fetch 自己做或交 recon，复用已有材料";
  }
  const w = path.resolve(cwd).replace(/\\/g, "/").toLowerCase().replace(/\/+$/, "");
  const roots = resolveRoots(cwd);
  if (roots.projectRoot && w === roots.projectRoot.replace(/\\/g, "/").toLowerCase().replace(/\/+$/, "")) {
    return "ctf.cwd 不能是题目工作区根目录（项目根）";
  }
  // A valid directory is not necessarily a challenge. Require an explicit marker
  // for all launches, including one-level folders and paths outside pi-ctf.
  if (!fs.existsSync(path.join(cwd, ".ctf-gate")))
    return "ctf.cwd 缺少 .ctf-gate；先确认它是独立单题目录并创建标记，再派 ctf";
  return undefined;
}
