/**
 * orchestrator-guard.ts — 主 agent 调度台硬闸（全局加载，但只在「主会话」生效）
 *
 * 目的：主 agent 是调度台，不该自己碰目标。这里拦住主会话 bash 里直接对目标动手的命令
 *      （curl/nmap/ssh/sqlmap…），拦消息会指路：平台轻操作走 browser/web_fetch，打点利用走 subagent。
 *
 * 只在主会话作用：后台子 agent 的运行器进程带 PI_SUBAGENT_PARENT_SESSION，
 * 命中即整体不注册——否则会把 ctf/pentest 的 curl/nmap 一起拦死。
 *
 * 目标交互命令的硬拦默认**关闭**（操作员放行）：命中时只在 stderr 提示一行。
 * 需要恢复硬拦：设置环境变量 PI_GUARD_STRICT=1。
 *
 * 只拦 bash：`browser`/`web_fetch` 工具不拦——CTF 平台的登录/看题/下附件/交 flag/查回执
 *      是调度事务，主 agent 可直接用这两个工具做（AGENTS.md「CTF 平台例外」）。
 * 放行：本地文件操作、脚本、包管理、git、读黑板用的 python3/sqlite3、localhost/127.0.0.1。
 * 开关：PI_ORCHESTRATOR=0 关闭。
 *
 * 边界：按「命令词」判，不按是否出现 IP/URL——避免把 `grep -r "http://" logs`
 *       这类本地检索误伤。缺点是 `python3 -c "requests.get(...)"` 这类绕过拦不到，
 *       它防的是手滑，不是沙箱。
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { ctfLaunchProblem } from "../src/paths/ctf-directory.ts";
import { profileAt } from "../src/config/profiles.ts";

const OFF = process.env.PI_ORCHESTRATOR === "0";
// 后台子 agent（含 detached runner）不加载本闸。
const IS_CHILD = !!process.env.PI_SUBAGENT_PARENT_SESSION;

/** 目标交互命令（curl/nmap/ssh/nc…）的硬拦只在显式开启时生效。 */
const STRICT = process.env.PI_GUARD_STRICT === "1";

/** 命令位置上的网络/攻击工具：主 agent 自己不该跑。 */
const NET_TOOLS = new Set([
  "curl", "wget", "http", "httpie", "aria2c",
  "nc", "ncat", "netcat", "socat", "telnet", "ftp", "lftp",
  "nmap", "masscan", "zmap", "rustscan",
  "sqlmap", "hydra", "medusa", "ncrack", "patator",
  "ffuf", "gobuster", "dirb", "dirsearch", "feroxbuster", "wfuzz", "nikto", "wpscan", "nuclei",
  "ssh", "scp", "sftp", "sshpass", "rsync", "rdesktop", "xfreerdp", "mstsc",
  "smbclient", "smbmap", "rpcclient", "enum4linux", "crackmapexec", "nxc", "netexec",
  "evil-winrm", "impacket-psexec", "impacket-wmiexec", "responder",
  "ldapsearch", "ldapwhoami", "kerbrute", "bloodhound-python",
  "dig", "nslookup", "host", "whois", "ping", "ping6", "arping", "traceroute", "tracepath", "mtr", "hping3",
  "mysql", "psql", "redis-cli", "mongo", "mongosh", "msfconsole",
  "ab", "wrk", "hey", "vegeta",
]);

const WRAPPERS = new Set(["sudo", "env", "command", "nohup", "nice", "time", "doas"]);
const ASSIGN = /^[A-Za-z_][A-Za-z0-9_]*=/;
const DURATION = /^\d+(?:\.\d+)?[smhd]?$/;

/** 取一段命令的词首（跳过 sudo/env/赋值/timeout 等包装）。 */
function firstWord(seg: string): string {
  const toks = seg.trim().split(/\s+/).filter(Boolean);
  let i = 0;
  while (i < toks.length) {
    const t = toks[i];
    if (WRAPPERS.has(t) || ASSIGN.test(t) || t.startsWith("-") || DURATION.test(t)) { i++; continue; }
    if (t === "timeout") { i += 2; continue; } // timeout <dur> cmd
    break;
  }
  const w = toks[i] ?? "";
  return w.split(/[\\/]/).pop() ?? w; // 去掉路径，保留命令名
}

/** 按 ; | & 换行切段，尊重引号；重定向里的 & 不算分隔。 */
function segments(cmd: string): string[] {
  const parts: string[] = [];
  let cur = "", inS = false, inD = false, esc = false;
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (esc) { cur += c; esc = false; continue; }
    if (c === "\\" && !inS) { cur += c; esc = true; continue; }
    if (c === "'" && !inD) { inS = !inS; cur += c; continue; }
    if (c === '"' && !inS) { inD = !inD; cur += c; continue; }
    const ampRedir = c === "&" && (cmd[i + 1] === ">" || cmd[i - 1] === ">");
    if (!inS && !inD && !ampRedir && (c === ";" || c === "\n" || c === "|" || c === "&")) {
      parts.push(cur); cur = "";
      while (i + 1 < cmd.length && (cmd[i + 1] === "|" || cmd[i + 1] === "&" || cmd[i + 1] === ";")) i++;
      continue;
    }
    cur += c;
  }
  parts.push(cur);
  return parts.map((s) => s.trim()).filter(Boolean);
}

/** 段是否只指向本机回环（本地仪表盘、本地服务探活不算「目标」）。
 * 严格版：段内所有 URL 必须都是 localhost/127.0.0.1；无 URL 时 localhost 必须是独立 host 词。
 * 防 `curl http://evil.com/?x=localhost` 这类伪装。 */
function isLocalSegment(seg: string): boolean {
  const urls = seg.match(/https?:\/\/[^\s'"]+/g) ?? [];
  if (urls.length) {
    return urls.every((u) => /^https?:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?=[:\/]|$)/i.test(u));
  }
  return /(^|\s)(?:localhost|127\.0\.0\.1)([:\s\/]|$)/i.test(seg);
}

/** 命中返回工具名，否则 undefined。导出以便离线测试。 */
export function offendingTool(cmd: string): string | undefined {
  for (const seg of segments(cmd)) {
    if (isLocalSegment(seg)) continue; // 本机回环不算目标
    const w = firstWord(seg).replace(/\.exe$/i, "");
    if (NET_TOOLS.has(w)) return w;
  }
  return undefined;
}

export default function orchestratorGuard(pi: ExtensionAPI) {
  if (OFF || IS_CHILD) return;
  pi.on("tool_call", async (event, ctx) => {
    // Direct launches and workflow child approval both pass here before model work.
    if (event.toolName === "subagent" || event.toolName === "subagent_launch") {
      const input = event.input as any;
      const check = (child: any) => {
        if (!child || !["ctf", "ctf-solver"].includes(child.agent)) return undefined;
        return ctfLaunchProblem(child.cwd);
      };
      let problem: string | undefined;
      if (event.toolName === "subagent_launch" || !input.action) {
        problem = check(input);
        if (!problem && input.workflow === "parallel" && Array.isArray(input.args?.tasks)) {
          for (const child of input.args.tasks) {
            problem = check(child);
            if (problem) break;
          }
        }
      }
      if (problem) return { block: true, reason: `[orchestrator-guard] ${problem}` };
      return undefined;
    }
    if (event.toolName !== "bash") return undefined;
    // 只有 transport=kali 的 profile（CTF/渗透）才限制主 agent 直接碰目标；dev/本地项目放行。
    const taskProfile = profileAt(String(ctx?.cwd || ""));
    if (!taskProfile || taskProfile.profile.transport !== "kali") return undefined;
    const input: unknown = event.input;
    const cmd = input && typeof input === "object" && "command" in input && typeof input.command === "string"
      ? input.command
      : "";
    const tool = offendingTool(cmd);
    if (!tool) return undefined;
    // 操作员已放开主 agent 的目标交互命令（curl/wget/nmap/ssh/nc 等）。
    // 想恢复硬拦：设置 PI_GUARD_STRICT=1。默认只提示不拦截。
    if (!STRICT) {
      console.warn(`[orchestrator-guard] 放行 \`${tool}\`（严格拦截已关闭；PI_GUARD_STRICT=1 可恢复）`);
      return undefined;
    }
    return {
      block: true,
      reason:
        `[orchestrator-guard] 主 agent 不得自己在 bash 里对目标动手：\`${tool}\` 是目标交互命令。\n` +
        "怎么走：CTF 平台的登录/看题/下附件/交 flag/查回执用 `browser`/`web_fetch` 工具（调度事务，可直接做）；" +
        "对目标打点/利用写成 `subagent` 任务（recon / pentest / audit / forensics / ctf）。" +
        "本地文件、读黑板（python3/sqlite3）、localhost 不受限。",
    };
  });
}
