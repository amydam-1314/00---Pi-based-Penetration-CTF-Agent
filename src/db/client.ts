/**
 * 看板数据库访问 —— 唯一写入口仍是 Python 的 db/gate_db.py。
 *
 * 约定（对应「程序与数据分离」）：
 *   - 本模块只做「调用 gate_db.py + 解析输出」，不直接执行 SQL 写入；
 *   - TS 侧不实现第二套 SQL 写入逻辑，避免两套契约漂移（历史 bug：angles / coverage）；
 *   - schema 版本用 SQLite 的 PRAGMA user_version 管理，迁移脚本在 db/migrations/。
 */
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

export interface DbExecResult {
  status: number;
  stdout: string;
  stderr: string;
}

export interface DbClientOptions {
  /** gate_db.py 的绝对路径（package 自带或项目 _shared 里的那份） */
  gatePy: string;
  /** gate.sqlite 绝对路径 */
  dbPath: string;
  /** python 解释器，按顺序探测 */
  pythonCandidates?: string[];
}

export class DbClient {
  private py: string | null = null;
  private opts: DbClientOptions;
  constructor(opts: DbClientOptions) {
    this.opts = opts;
  }

  private python(): string {
    if (this.py) return this.py;
    for (const c of this.opts.pythonCandidates ?? ["python3", "python", "py"]) {
      const r = spawnSync(c, ["-c", "import sqlite3,sys;sys.exit(0)"], { encoding: "utf8" });
      if (r.status === 0) return (this.py = c);
    }
    throw new Error("找不到可用的 Python（需要 sqlite3 模块）");
  }

  run(args: string[], stdin?: string): DbExecResult {
    if (!fs.existsSync(this.opts.gatePy)) throw new Error(`gate_db.py 不存在：${this.opts.gatePy}`);
    const r = spawnSync(this.python(), [this.opts.gatePy, "--db", this.opts.dbPath, ...args], {
      input: stdin,
      encoding: "utf8",
      timeout: 20000,
      env: { ...process.env, PYTHONUTF8: "1", PYTHONIOENCODING: "utf-8" },
    });
    return { status: r.status ?? 1, stdout: r.stdout ?? "", stderr: r.stderr ?? String(r.error ?? "") };
  }

  /** 读：dump / rev / stages 等只读命令 */
  read(args: string[]): string {
    const r = this.run(args);
    if (r.status !== 0) throw new Error(`gate_db 读取失败（${args.join(" ")}）：${r.stderr || r.stdout}`);
    return r.stdout;
  }

  /** 写：只允许通过 gate_db.py 的 import/verified/falsified 等命令 */
  write(args: string[], payload?: string): void {
    const r = this.run(args, payload);
    if (r.status !== 0) throw new Error(`gate_db 写入失败（${args.join(" ")}）：${r.stderr || r.stdout}`);
  }

  rev(): string {
    return this.read(["rev"]).trim();
  }

  /** schema 版本：PRAGMA user_version（数据文件自带版本，迁移据此判断） */
  schemaVersion(): number {
    const sql = "PRAGMA user_version;";
    const tmp = path.join(path.dirname(this.opts.dbPath), ".schema_probe.sqlite");
    const r = spawnSync(this.python(), ["-c", `
import sqlite3,sys,shutil
src,dst=sys.argv[1],sys.argv[2]
shutil.copyfile(src,dst)
cx=sqlite3.connect(dst)
print(cx.execute("PRAGMA user_version;").fetchone()[0])
cx.close()
import os; os.remove(dst)
`, this.opts.dbPath, tmp], { encoding: "utf8" });
    if (r.status !== 0) throw new Error(`读 schema 版本失败：${r.stderr || r.stdout}`);
    void sql;
    return Number(r.stdout.trim() || 0);
  }

  /** 只读快照（snapshot 命令返回 {rev, board}） */
  snapshot(): { rev: number; board: Record<string, unknown> } {
    const out = this.read(["snapshot"]);
    const p = JSON.parse(out) as { rev: number; board: Record<string, unknown> };
    if (!Number.isSafeInteger(p.rev) || !p.board) throw new Error("snapshot 输出格式非法");
    return p;
  }
}
