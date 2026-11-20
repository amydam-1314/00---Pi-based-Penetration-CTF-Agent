/**
 * fofa.ts — FOFA 资产测绘工具（只读），仅挂给 pentest。
 *
 * key 来源（先环境变量，后配置文件）：
 *   - env:  FOFA_KEY（必需）、FOFA_EMAIL（可选）、FOFA_BASE（可选，默认 https://fofa.info）
 *   - file: <agent-dir>/fofa.json  ->  { "email": "...", "key": "..." }
 * 不做任何写操作，只查资产。
 */
import fs from "node:fs";
import path from "node:path";
import { Type } from "typebox";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const AGENT_DIR =
  process.env.PI_CODING_AGENT_DIR ||
  path.join(process.env.USERPROFILE || process.env.HOME || ".", ".pi", "agent");

const DEFAULT_FIELDS = "host,ip,port,protocol,title,domain,server,os,country_name";
const MAX_CHARS = 20000;

function creds(): { key: string; email: string } {
  const envKey = (process.env.FOFA_KEY || "").trim();
  const envEmail = (process.env.FOFA_EMAIL || "").trim();
  if (envKey) return { key: envKey, email: envEmail };
  try {
    const c = JSON.parse(fs.readFileSync(path.join(AGENT_DIR, "fofa.json"), "utf8"));
    return { key: String(c?.key ?? "").trim(), email: String(c?.email ?? "").trim() };
  } catch {
    return { key: "", email: "" };
  }
}

export default function fofaTool(pi: ExtensionAPI) {
  pi.registerTool({
    name: "fofa_search",
    label: "FOFA Search",
    description:
      "Query FOFA (cyberspace search engine) for internet-facing assets. Read-only. " +
      'query uses FOFA syntax, e.g. `app="nginx" && country="CN"` or `domain="example.com"`.',
    promptSnippet: "Search FOFA for authorized asset discovery (read-only)",
    promptGuidelines: [
      "Use fofa_search for authorized asset/attack-surface discovery against a target, instead of scraping search engines.",
    ],
    parameters: Type.Object({
      query: Type.String({ description: "FOFA query syntax" }),
      size: Type.Optional(Type.Integer({ minimum: 1, maximum: 100, description: "Number of results (default 20)." })),
      page: Type.Optional(Type.Integer({ minimum: 1, description: "Page number (default 1)." })),
      fields: Type.Optional(Type.String({ description: "Comma-separated FOFA fields (optional)." })),
    }),
    async execute(_id, params, signal) {
      const { key, email } = creds();
      if (!key) {
        return {
          content: [{ type: "text", text:
            "FOFA 未配置：设置环境变量 `FOFA_KEY`（及可选 `FOFA_EMAIL`），或在 `~/.pi/agent/fofa.json` 写 `{\"email\":\"...\",\"key\":\"...\"}`。" }],
          details: { error: "no_key" },
        };
      }
      const q = String((params as { query?: string })?.query ?? "").trim();
      if (!q) {
        return { content: [{ type: "text", text: "query 不能为空。" }], details: { error: "empty_query" } };
      }
      const p = params as { size?: number; page?: number; fields?: string };
      const size = Math.min(Math.max(Number(p.size) || 20, 1), 100);
      const page = Math.max(Number(p.page) || 1, 1);
      const fields = (p.fields || DEFAULT_FIELDS).trim();
      const base = (process.env.FOFA_BASE || "https://fofa.info").replace(/\/+$/, "");
      const u = new URL(base + "/api/v1/search/all");
      u.searchParams.set("key", key);
      if (email) u.searchParams.set("email", email);
      u.searchParams.set("qbase64", Buffer.from(q, "utf8").toString("base64"));
      u.searchParams.set("size", String(size));
      u.searchParams.set("page", String(page));
      u.searchParams.set("fields", fields);

      try {
        const r = await fetch(u, { signal, headers: { Accept: "application/json" } });
        const text = await r.text();
        let j: any = null;
        try { j = JSON.parse(text); } catch { /* keep raw */ }
        if (!r.ok) {
          return { content: [{ type: "text", text: `FOFA HTTP ${r.status}：${text.slice(0, 500)}` }], details: { status: r.status } };
        }
        if (j && j.error) {
          return { content: [{ type: "text", text: `FOFA error: ${j.errmsg || j.error}` }], details: { error: j.error } };
        }
        const out = JSON.stringify(j, null, 2);
        return {
          content: [{ type: "text", text: out.length > MAX_CHARS ? `${out.slice(0, MAX_CHARS)}\n…[truncated]` : out }],
          details: { query: q, size, page, fields },
        };
      } catch (e) {
        return { content: [{ type: "text", text: `FOFA 请求失败：${(e as Error).message}` }], details: { error: "request_failed" } };
      }
    },
  });
}
