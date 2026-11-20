/**
 * kali-exec.ts — 子代理 bash 强制上 Kali（防串进操作员的 WSL 个人解题环境）
 *
 * 背景：WSL 是操作员本人的环境，工具少且不该被 AI 污染；全部进攻/侦察工具都在 Kali。
 * 作用：把 recon/pentest/audit/forensics 的每条 bash 命令包装成 ssh 到 Kali 执行。
 *       ctf 不用本扩展（ctf-gate 自带更完整的包装：环境变量注入 + 黑板绑定）。
 *
 * 工作目录映射：
 *   D:/2026/pi-ctf/...        → /mnt/hgfs/pi-share/pi-ctf/...（HGFS 实时共享，Windows 侧文件可见）
 *   其它 Windows 路径          → Kali ~/agent-work（自建 scratch；文件读写请用 read/write/edit 工具）
 *
 * 开关：PI_KALI_EXEC=0 关闭（排障用）。
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const OFF = process.env.PI_KALI_EXEC === "0";
// ⚠️ 部署时配置（见 .env.example）：
//   PI_KALI_HOST — Kali 的 "user@host"（必填）
//   PI_KALI_PASS — SSH 密码（必填；密钥登录可改 ssh -i 去掉 sshpass）
const HOST = process.env.PI_KALI_HOST || "";
const PASS = process.env.PI_KALI_PASS || "";

/** Windows 路径 → Kali 路径；仅在 Kali 有对应时返回（pi-ctf 走 HGFS），否则 null。 */
function toKaliPath(p: string): string | null {
  const w = p.replace(/\\/g, "/");
  const m = /^([A-Za-z]):\/(.*)$/.exec(w);
  if (!m) return null;
  const drive = m[1].toLowerCase();
  const rest = m[2];
  if (drive === "d" && rest.toLowerCase().startsWith("2026/pi-ctf/")) {
    return "/mnt/hgfs/pi-share/pi-ctf/" + rest.slice("2026/pi-ctf/".length);
  }
  return null;
}

export default function kaliExec(pi: ExtensionAPI) {
  if (OFF) return;
  if (!HOST || !PASS) throw new Error("[kali-exec] 未配置 PI_KALI_HOST/PI_KALI_PASS：参照 .env.example 设置后重启。");
  pi.on("tool_call", async (event, ctx) => {
    if (event.toolName !== "bash") return undefined;
    const input = event.input as { command?: string };
    const cmd = String(input?.command ?? "");
    if (!cmd.trim()) return undefined;
    const quote = (s: string) => `'${s.replace(/'/g, "'\\''")}'`;
    const mapped = toKaliPath(String(ctx.cwd || ""));
    // 映射得到的工作目录可能还没建（HGFS 侧应已存在；防御性 mkdir 不碍事）
    const cwd = mapped ?? "~/agent-work";
    const pre = mapped
      ? `cd ${quote(mapped)} 2>/dev/null || { mkdir -p ~/agent-work; cd ~/agent-work; };`
      : `mkdir -p ~/agent-work 2>/dev/null; cd ~/agent-work;`;
    const inner = `${pre} ${cmd}`;
    input.command =
      `sshpass -p ${quote(PASS)} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=15 -o LogLevel=ERROR ` +
      `${quote(HOST)} ${quote(inner)}`;
    return undefined;
  });
}
