/**
 * profiles.ts — 领域 profile 的唯一加载入口（profiles/*.json）。
 *
 * 字段：
 *   marker    任务目录标记（文件或目录名）
 *   boardDb   黑板路径（相对任务根），或 "boards"（扫 ctf-boards）
 *   rules     规则文件候选（按序取第一个存在的）
 *   budget    预算文件（相对任务根），null 表示无
 *   validate  "ctf" 才跑比赛根校验
 *   transport "kali" 才经 SSH 到 Kali；"local" 保持本机
 */
import fs from "node:fs";
import path from "node:path";

import { AGENT_DIR } from "../paths/roots.ts";

export interface ProfileCfg {
  name: string;
  marker: string;
  boardDb: string[];
  rules: string[];
  budget?: string | null;
  validate?: "ctf" | "none";
  transport?: "kali" | "local";
  fields?: string[];
}

export interface TaskProfile { root: string; profile: ProfileCfg }

const PROFILE_DIR = path.join(AGENT_DIR, "profiles");

export function loadProfiles(): ProfileCfg[] {
  let names: string[] = [];
  try {
    names = fs.readdirSync(PROFILE_DIR).filter((n) => n.endsWith(".json"));
  } catch {
    return [];
  }
  const out: ProfileCfg[] = [];
  for (const n of names) {
    try {
      const value: unknown = JSON.parse(fs.readFileSync(path.join(PROFILE_DIR, n), "utf8"));
      if (!value || typeof value !== "object") continue;
      const rec = value as Record<string, unknown>;
      const marker = typeof rec.marker === "string" ? rec.marker : "";
      if (!marker) continue;
      out.push({
        name: typeof rec.name === "string" ? rec.name : n.replace(/\.json$/, ""),
        marker,
        boardDb: Array.isArray(rec.boardDb) ? rec.boardDb.filter((x): x is string => typeof x === "string") : [],
        rules: Array.isArray(rec.rules) ? rec.rules.filter((x): x is string => typeof x === "string") : [],
        budget: typeof rec.budget === "string" ? rec.budget : null,
        validate: rec.validate === "ctf" ? "ctf" : "none",
        transport: rec.transport === "kali" ? "kali" : "local",
        fields: Array.isArray(rec.fields) ? rec.fields.filter((x): x is string => typeof x === "string") : undefined,
      });
    } catch {
      /* skip broken profile */
    }
  }
  return out;
}

/** 向上找任务标记；only 指定时只认该 profile 的 marker。 */
export function findTask(cwd: string, profiles: ProfileCfg[], only?: string): TaskProfile | null {
  const active = only ? profiles.filter((p) => p.name === only) : profiles;
  if (!active.length) return null;
  let dir = path.resolve(cwd);
  for (let i = 0; i < 6; i++) {
    for (const p of active) {
      if (fs.existsSync(path.join(dir, p.marker))) return { root: dir, profile: p };
    }
    const up = path.dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  return null;
}

/** 当前目录所属 profile；没有标记返回 null（调用方据此保持“不干预”）。 */
export function profileAt(cwd: string): TaskProfile | null {
  return findTask(cwd, loadProfiles());
}
