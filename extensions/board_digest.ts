/**
 * board_digest.ts — 只读看板汇总，**只给主 agent 用**。
 *
 * 读 ctf-boards 下每个会话的 challenges/<slug>/gate.sqlite（按 CHALLENGE.txt 的题目目录匹配），
 * 每题压成 4-6 行：rev / idle / flags / verified / falsified / next / stages。
 * 不写任何文件，不建库；找不到板子就直说，不猜。
 */
import fs from "node:fs";
import path from "node:path";
import { Type } from "typebox";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { resolveRoots, resolvePath } from "../src/paths/roots.ts";

const AGENT_DIR =
  process.env.PI_CODING_AGENT_DIR ||
  path.join(process.env.USERPROFILE || process.env.HOME || ".", ".pi", "agent");

const MAX_LINE = 150;

function norm(p: string): string {
  return p.replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
}

function cut(s: string, n = MAX_LINE): string {
  const t = String(s ?? "").replace(/\s+/g, " ").trim();
  return t.length > n ? t.slice(0, n - 1) + "…" : t;
}

/** 主 agent 判定：cwd 向上 5 层内出现 .ctf-gate → 这是子 agent 的题目目录 */
function insideChallenge(cwd: string): string | null {
  let d = path.resolve(cwd);
  for (let i = 0; i < 5; i++) {
    if (fs.existsSync(path.join(d, ".ctf-gate"))) return d;
    const up = path.dirname(d);
    if (up === d) break;
    d = up;
  }
  return null;
}

/** 看板根由 roots.ts 统一解析（env.json → CTF_BOARDS_ROOT → projectRoot/ctf-boards），不猜。 */
function boardsRoot(): string | null {
  return resolveRoots(process.cwd()).boardsRoot;
}

type Board = { db: string; session: string; dirPath: string; slug: string };

/** 扫所有会话的 CHALLENGE.txt，按题目目录匹配（大小写/分隔符不敏感） */
function scanBoards(): Board[] {
  const root = boardsRoot();
  if (!root) return [];
  const out: Board[] = [];
  let sessions: string[] = [];
  try {
    sessions = fs.readdirSync(root).filter((s) => {
      try {
        return fs.statSync(path.join(root, s)).isDirectory();
      } catch {
        return false;
      }
    });
  } catch {
    return [];
  }
  for (const s of sessions) {
    const chdir = path.join(root, s, "challenges");
    let slugs: string[] = [];
    try {
      slugs = fs.readdirSync(chdir);
    } catch {
      continue;
    }
    for (const slug of slugs) {
      const db = path.join(chdir, slug, "gate.sqlite");
      const marker = path.join(chdir, slug, "CHALLENGE.txt");
      if (!fs.existsSync(db)) continue;
      let dirPath = "";
      try {
        dirPath = fs.readFileSync(marker, "utf8").trim().split("\n")[0].trim();
      } catch {
        continue;
      }
      out.push({ db, session: s, dirPath, slug });
    }
  }
  return out;
}

function ageLabel(iso: string | undefined): string {
  if (!iso) return "?";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "?";
  const mins = Math.max(0, Math.round((Date.now() - t) / 60000));
  if (mins < 60) return `${mins}m`;
  const h = Math.floor(mins / 60);
  return h < 48 ? `${h}h` : `${Math.floor(h / 24)}d`;
}

function fmtAgo(ms: number): string {
  const mins = Math.max(0, Math.round(ms / 60000));
  if (mins < 60) return `${mins}m`;
  const h = Math.floor(mins / 60);
  return h < 48 ? `${h}h` : `${Math.floor(h / 24)}d`;
}

async function openDb(db: string): Promise<any> {
  const mod: any = await import("node:sqlite");
  return new mod.DatabaseSync(db, { readOnly: true });
}

async function digest(b: Board): Promise<string[]> {
  const lines: string[] = [];
  const dirFs = b.dirPath.replace(/\\/g, "/");
  const name = path.basename(dirFs);
  let st: fs.Stats | null = null;
  try {
    st = fs.statSync(b.db);
  } catch {
    /* ignore */
  }
  const idle = st ? fmtAgo(Date.now() - st.mtimeMs) : "?";

  let db: any;
  try {
    db = await openDb(b.db);
  } catch (e: any) {
    lines.push(`${name}   ⚠ 打不开库（${cut(e?.message ?? e, 80)}）  ${b.db}`);
    return lines;
  }
  const q = (sql: string): any[] => {
    try {
      return db.prepare(sql).all();
    } catch {
      return [];
    }
  };
  const meta = new Map<string, string>();
  for (const r of q("select k, v from meta")) meta.set(String(r.k), String(r.v));

  const flags = q("select flag, basis from flags order by rowid");
  const ver = q("select tag, fact from verified order by rowid");
  const fal = q("select tag, condition from falsified order by rowid");
  const nxt = q("select text from next_steps order by ord");
  const stg = q("select n, state from stages");
  const evc = q("select count(*) as c from evidence")[0]?.c ?? 0;
  const hyp = q("select count(*) as c from hypotheses")[0]?.c ?? 0;

  const ok = stg.filter((s: any) => s.state === "通过").length;
  const bad = stg.filter((s: any) => s.state === "不通过").length;
  const back = stg.filter((s: any) => s.state === "回退").length;

  const head = [
    `${name}`,
    `rev ${meta.get("rev") ?? "0"}`,
    `idle ${idle}`,
    flags.length ? `flags ${flags.length}` : "flags 0",
    `v${ver.length}/f${fal.length}/h${hyp}`,
  ].join(" · ");
  lines.push(head);
  if (b.dirPath) lines.push(`   dir    ${b.dirPath}`);
  const remote = meta.get("challenge_remote");
  if (remote) lines.push(`   remote ${cut(remote, 100)}`);

  for (const f of flags) {
    lines.push(`   FLAG   ${cut(f.flag, 80)}${f.basis ? "  ← " + cut(f.basis, 70) : ""}`);
  }
  if (ver.length) {
    lines.push(`   verified   ${ver.map((v: any) => cut(`${v.tag}`, 34)).join(" | ")}`);
  }
  if (fal.length) {
    lines.push(
      `   falsified  ${fal.map((v: any) => cut(`${v.tag}${v.condition ? " (" + v.condition + ")" : ""}`, 60)).join(" | ")}`,
    );
  }
  if (nxt.length) {
    lines.push(`   next  ${cut(nxt[0].text, 120)}${nxt.length > 1 ? ` (+${nxt.length - 1})` : ""}`);
  }
  if (stg.length || evc) {
    lines.push(`   stages ${ok}通过/${bad}不通过${back ? `/${back}回退` : ""} · evidence ${evc}`);
  }
  // turn limit（在题目目录里，不在 ctf-boards 里）
  if (b.dirPath) {
    try {
      const n = fs.readFileSync(path.join(b.dirPath.replace(/\\/g, "/"), "gate", "turn_limit"), "utf8").trim();
      if (n) lines.push(`   turn_limit ${n}`);
    } catch {
      /* 无 */
    }
  }
  try {
    db.close();
  } catch {
    /* ignore */
  }
  return lines;
}

export default function boardDigest(pi: ExtensionAPI) {
  pi.registerTool({
    name: "board_digest",
    label: "Board Digest",
    description:
      "只读汇总 CTF 题板（gate.sqlite）：rev、空转时长、flags、verified、falsified、next、stages。" +
      "主 agent 专用；子 agent 调用会被拒绝。传 dir=一个题目目录，或 root=战役根目录（一次看全部题）。",
    promptSnippet: "Digest CTF boards read-only: rev / idle / flags / verified / falsified / next",
    promptGuidelines: [
      "用 board_digest 看战况，不要用 bash 手拼 gate_db.py 路径（拼错会读到别的题的库）。",
      "判断某题是否卡住看 idle + rev；判断是否能收口看 flags 与 next。",
    ],
    parameters: Type.Object({
      dir: Type.Optional(Type.String({ description: "题目目录：绝对路径，或相对项目根/战役根的引用（如 challs/f2-01）" })),
      root: Type.Optional(Type.String({ description: "战役根目录，一次汇总其下所有题" })),
      db: Type.Optional(Type.String({ description: "直接给 gate.sqlite 路径" })),
      onlyActive: Type.Optional(Type.Boolean({ description: "只列出 rev>0 或 flags>0 的题（默认 true，root 模式）" })),
      base: Type.Optional(
        Type.Union(
          [
            Type.Literal("project"),
            Type.Literal("campaign"),
            Type.Literal("boards"),
            Type.Literal("extension"),
          ],
          { description: "dir/root 是相对引用时必填：相对哪个基准解析（不猜）" },
        ),
      ),
    }),
    async execute(_id, params) {
      // 主 agent 专用：像 orchestrator-guard 一样先认子 agent 进程，再兜底看 cwd
      if (process.env.PI_SUBAGENT_PARENT_SESSION) {
        return {
          content: [{ type: "text", text: "board_digest 只给主 agent 用（当前是子 agent 会话）。请用 ./board.sh show 读本题板。" }],
          details: { error: "main_agent_only" },
        };
      }
      const denied = insideChallenge(process.cwd());
      if (denied) {
        return {
          content: [
            {
              type: "text",
              text: `board_digest 只给主 agent 用：当前 cwd 在题目目录（${denied}）内。请用 board.sh show / --db 直接读本题板。`,
            },
          ],
          details: { error: "main_agent_only" },
        };
      }
      const all = scanBoards();
      if (!boardsRoot()) {
        const r = resolveRoots(process.cwd());
        const why = r.errors.length ? r.errors.join("；") : "未找到看板目录";
        return { content: [{ type: "text", text: `找不到 ctf-boards 目录：${why}（可设 env.json 的 boardsRoot 或环境变量 PI_CTF_BOARDS_ROOT）` }], details: { error: "no_boards_root", errors: r.errors } };
      }

      // 单库直读
      if (params?.db) {
        const dbp = String(params.db);
        const hit: Board = { db: dbp, session: "?", dirPath: "", slug: path.basename(path.dirname(dbp)) };
        return { content: [{ type: "text", text: (await digest(hit)).join("\n") }], details: { mode: "db" } };
      }

      // 相对引用必须显式给 base（不按字符串形态猜、不默认 cwd）
      const rootsNow = resolveRoots(process.cwd());
      const absOf = (v: string): { abs: string | null; error?: string } => {
        const isAbs = path.isAbsolute(v) || /^[A-Za-z]:[\\/]/.test(v);
        if (isAbs) return { abs: norm(v) };
        const base = params?.base;
        if (!base) {
          return {
            abs: null,
            error: `"${v}" 是相对引用，必须显式传 base（project|campaign|boards|extension），例：{root:"<战役>",base:"project"}`,
          };
        }
        const r = resolvePath(v, base as any, { roots: rootsNow });
        if (!r.abs) return r;
        if (!fs.existsSync(r.abs)) return { abs: null, error: `按 base=${base} 解析得到 ${r.abs}，但该路径不存在` };
        return { abs: norm(r.abs) };
      };

      let target: string | null = null;
      let resolveErr: string | undefined;
      const rawTarget = params?.dir ?? params?.root;
      if (rawTarget) {
        const r = absOf(String(rawTarget));
        target = r.abs;
        resolveErr = r.error;
      }
      if (!target) {
        return {
          content: [{ type: "text", text: `无法解析路径：${resolveErr ?? "缺少 dir/root"}` }],
          details: { error: "unresolved_path", message: resolveErr },
        };
      }

      const isRoot = Boolean(params?.root);
      // CHALLENGE.txt 存的是登记时的绝对目录 → 搬迁后不能直接比。
      // 因此用「身份」匹配：把路径折叠成 <战役目录>/challs/<题目目录>（末三段，且倒数第二段是 challs）。
      // 全等匹配优先；身份匹配命中多个就报错列候选，不静默取一。
      const identity = (p: string): string | null => {
        const seg = norm(p).split("/").filter(Boolean);
        const i = seg.lastIndexOf("challs");
        if (i < 1 || i + 1 >= seg.length) return null;
        return seg.slice(i - 1).join("/");
      };

      const matchByAbs = (b: Board): boolean => {
        const p = norm(b.dirPath);
        return isRoot ? p === target || p.startsWith(target + "/") : p === target;
      };

      let matched = all.filter(matchByAbs);
      let matchBy = "absolute";
      if (!matched.length) {
        const want = identity(target);
        if (want) {
          matched = all.filter((b) => identity(b.dirPath) === want);
          matchBy = "identity";
        }
      }

      if (matchBy === "identity") {
        const dirs = [...new Set(matched.map((b) => b.dirPath))];
        if (dirs.length > 1) {
          return {
            content: [
              {
                type: "text",
                text:
                  `身份「${identity(target)}」命中 ${dirs.length} 个题目目录，拒绝猜：\n` +
                  dirs.map((d) => "  - " + d).join("\n") +
                  `\n改用绝对路径，或把 CHALLENGE.txt 更新成当前目录后再查。`,
              },
            ],
            details: { error: "ambiguous", candidates: dirs },
          };
        }
      }

      if (!matched.length) {
        const leaf = target.split("/").pop() || "\u0000";
        const parent = target.split("/").slice(0, -1).join("/");
        const near = [...new Set(all.map((b) => norm(b.dirPath)))]
          .filter((q) => q.includes(leaf) || (parent && q.startsWith(parent + "/")))
          .slice(0, 8);
        return {
          content: [
            {
              type: "text",
              text:
                `没有匹配 ${target} 的题板。\n` +
                `现有板子 ${all.length} 个（${new Set(all.map((b) => b.session)).size} 个会话）。` +
                (near.length ? `\n相近：\n${near.map((n) => "  " + n).join("\n")}` : ""),
            },
          ],
          details: { error: "no_match", boards: all.length },
        };
      }

      // 同题多板（多会话）告警
      const warn: string[] = [];
      const byDir = new Map<string, Board[]>();
      for (const b of matched) {
        const k = norm(b.dirPath);
        byDir.set(k, [...(byDir.get(k) ?? []), b]);
      }
      for (const [k, list] of byDir) if (list.length > 1) warn.push(`⚠ 同一题目目录有 ${list.length} 个板子：${k}（已按最新取用）`);

      // 同题多板：每个题目目录只渲染一个（最新 mtime），其余在 warn 里点名
      const newest = new Map<string, Board>();
      for (const b of matched) {
        const k = norm(b.dirPath);
        const prev = newest.get(k);
        if (!prev) {
          newest.set(k, b);
          continue;
        }
        const m1 = fs.statSync(prev.db).mtimeMs;
        const m2 = fs.statSync(b.db).mtimeMs;
        if (m2 > m1) newest.set(k, b);
      }
      const unique = [...newest.values()].sort((a, b) => norm(a.dirPath).localeCompare(norm(b.dirPath)));

      const out: string[] = [];
      let shown = 0;
      let withFlag = 0;
      let active = 0;
      const blocks: string[] = [];
      for (const b of unique) {
        const lines = await digest(b);
        const txt = lines.join("\n");
        const hasFlag = lines.some((l) => l.includes("FLAG   "));
        const revN = Number((lines[0]?.match(/rev (\d+)/) ?? [])[1] ?? 0);
        if (hasFlag) withFlag++;
        if (revN > 0) active++;
        const skip = isRoot && params?.onlyActive !== false && !hasFlag && revN === 0;
        if (skip) continue;
        blocks.push(txt);
        shown++;
      }
      if (!blocks.length) {
        out.push(`root 下有 ${unique.length} 道题，但没有 rev>0 / 有 flag 的（onlyActive=false 可全看）`);
      } else {
        out.push(...blocks);
      }
      const summary = `\n—— 共 ${unique.length} 题（${matched.length} 板）· 有活 ${active} · 有 flag ${withFlag} · 显示 ${shown}${warn.length ? "\n" + warn.join("\n") : ""}`;
      return {
        content: [{ type: "text", text: out.join("\n\n") + summary }],
        details: { mode: isRoot ? "root" : "dir", matched: matched.length, shown, withFlag, active, warnings: warn },
      };
    },
  });
}
