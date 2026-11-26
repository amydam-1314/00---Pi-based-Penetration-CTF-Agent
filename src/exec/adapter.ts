/**
 * ExecutionAdapter —— 唯一的「在哪台机器上跑命令」决策点。
 *
 * 背景：以前 ctf-gate 与 kali-exec 各自判断 SSH（判据还不同），同一会话里可能落到不同机器。
 * 现在两个扩展都只调这里：
 *   backend = config.execution.backend ?? (profile.transport === "kali" ? "ssh" : "local")
 *
 * local：命令在 Pi 进程所在主机执行（Pi 跑在 Kali/VM 上时，这就是"本地执行"，无需 SSH）
 * ssh  ：Pi 在 Windows、工具链在远端时使用；口令走 SSHPASS 环境变量，不进 argv
 */
import fs from "node:fs";
import path from "node:path";

export type Backend = "local" | "ssh";

export interface SshCfg {
  target?: string;
  passwordFile?: string | null;
  identityFile?: string | null;
  /** 额外 ssh 选项，如 ["-p","2222"] */
  extraArgs?: string[];
}

export interface MountCfg {
  from: string;
  to: string;
}

export interface ExecConfig {
  execution?: { backend?: Backend; ssh?: SshCfg };
  mounts?: MountCfg[];
}

export interface WrapOptions {
  cwd: string;
  env?: Record<string, string>;
  /** 仅 local 用：是否 cd 到 cwd（默认 true） */
  cd?: boolean;
}

export interface Wrapped {
  command: string;
  /** 人类可读形式（日志/提示用，不含口令） */
  display: string;
  backend: Backend;
}

const q = (s: string) => `'${s.replace(/'/g, "'\\''")}'`;
const norm = (p: string) => p.replace(/\\/g, "/").replace(/\/+$/, "");

/** 宿主路径 → 远端路径；无匹配返回 null（不猜） */
export function mapPath(p: string, mounts: MountCfg[] = []): string | null {
  const src = norm(p);
  const maps = mounts
    .filter((m) => m && typeof m.from === "string" && m.from.trim())
    .map((m) => ({ from: norm(m.from), to: norm(m.to ?? "") }))
    .sort((a, b) => b.from.length - a.from.length); // 最长前缀优先
  const lower = src.toLowerCase();
  for (const m of maps) {
    const from = m.from.toLowerCase();
    if (lower === from || lower.startsWith(from + "/")) {
      const rest = src.slice(m.from.length).replace(/^\/+/, "");
      return rest ? `${m.to}/${rest}` : m.to;
    }
  }
  return null;
}

function envExports(env?: Record<string, string>): string {
  if (!env) return "";
  const parts = Object.entries(env)
    .filter(([, v]) => v !== undefined && v !== null)
    .map(([k, v]) => `${k}=${q(String(v))}`);
  return parts.length ? `export ${parts.join(" ")}; ` : "";
}

export class LocalAdapter {
  readonly backend: Backend = "local";
  wrap(cmd: string, opts: WrapOptions): Wrapped {
    const cd = opts.cd === false ? "" : `cd ${q(opts.cwd)} && `;
    const inner = `${cd}${envExports(opts.env)}${cmd}`;
    return { command: inner, display: inner, backend: this.backend };
  }
}

export class SshAdapter {
  readonly backend: Backend = "ssh";
  private cfg: SshCfg;
  private mounts: MountCfg[];
  constructor(cfg: SshCfg, mounts: MountCfg[]) {
    this.cfg = cfg;
    this.mounts = mounts;
  }

  /** 预检：缺主机/缺凭据就抛错，不静默降级到 local */
  preflight(): void {
    if (!this.cfg.target) {
      throw new Error("execution.ssh.target 未配置（env.json）；要本地执行就把 execution.backend 设为 local");
    }
    if (!this.cfg.passwordFile && !this.cfg.identityFile && !process.env.SSHPASS) {
      throw new Error(
        "SSH 后端缺凭据：配 execution.ssh.identityFile（推荐）或 passwordFile，或设 SSHPASS 环境变量",
      );
    }
  }

  wrap(cmd: string, opts: WrapOptions): Wrapped {
    this.preflight();
    const remoteCwd = mapPath(opts.cwd, this.mounts);
    if (!remoteCwd) {
      throw new Error(
        `工作目录未覆盖在 mounts 里：${opts.cwd}。现有映射：${JSON.stringify(this.mounts)}`,
      );
    }
    const inner = `cd ${q(remoteCwd)} && ${envExports(opts.env)}${cmd}`;

    if (this.cfg.identityFile) {
      const args = ["-i", q(this.cfg.identityFile), "-o", "BatchMode=yes", ...(this.cfg.extraArgs ?? [])];
      const ssh = `ssh ${args.join(" ")} -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -o LogLevel=ERROR ${q(this.cfg.target!)} ${q(inner)}`;
      return { command: ssh, display: ssh, backend: this.backend };
    }
    // 口令：走 SSHPASS 环境变量（sshpass -e），不进 argv / 进程列表
    let pp: string | null = null;
    try {
      pp = this.cfg.passwordFile ? fs.readFileSync(this.cfg.passwordFile, "utf8").trim() : null;
    } catch {
      pp = null;
    }
    if (pp) process.env.SSHPASS = pp;
    const ssh = `sshpass -e ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -o LogLevel=ERROR ${q(this.cfg.target!)} ${q(inner)}`;
    return { command: ssh, display: ssh, backend: this.backend };
  }
}

export interface AdapterInput {
  config: ExecConfig;
  /** profile 的 transport；未声明则按 local */
  profileTransport?: "local" | "kali";
  /** 显式覆盖（测试/一次性场景） */
  override?: Backend;
}

/** 唯一决策：谁在这里判断后端，其他地方都不许再判 SSH */
export function createAdapter(input: AdapterInput): LocalAdapter | SshAdapter {
  const backend: Backend =
    input.override ??
    input.config.execution?.backend ??
    (input.profileTransport === "kali" ? "ssh" : "local");
  if (backend === "ssh") return new SshAdapter(input.config.execution?.ssh ?? {}, input.config.mounts ?? []);
  return new LocalAdapter();
}

/** 便于测试：只有 backend 名字 */
export function chooseBackend(input: AdapterInput): Backend {
  return createAdapter(input).backend;
}

/** 读 env.json（缺文件返回 {}，坏 JSON 抛错——不静默） */
export function loadConfig(file: string): ExecConfig {
  if (!fs.existsSync(file)) return {};
  const raw = fs.readFileSync(file, "utf8");
  try {
    return JSON.parse(raw) as ExecConfig;
  } catch (e: any) {
    throw new Error(`配置文件不是合法 JSON：${file}（${e?.message ?? e}）`);
  }
}

export const _internals = { q, norm, path };
