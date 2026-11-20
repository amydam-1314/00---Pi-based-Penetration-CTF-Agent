/**
 * destructive-guard.ts — 破坏性动作闸（只拦，不调模型）
 *
 * 只管「不可逆 / 影响业务」的直接效果，不管过程，也不猜攻击链。
 * 原则：拿不准放行；只读放行；通过漏洞 payload 打（SQLi/XSS/SSTI/SSRF/XXE、
 *      上传 webshell、弱口令、扫描、sqlmap --os-shell、whoami/id/ls/cat）一律放行。
 *
 * 判定尽量锚在「命令位置」或「写入目标路径」，避免把笔记/脚本里的字符串误判成执行。
 * 开关：PI_CTF_DESTRUCTIVE=0 或 PI_PENTEST_DESTRUCTIVE=0 时整体关闭。
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const OFF =
  process.env.PI_CTF_DESTRUCTIVE === "0" || process.env.PI_PENTEST_DESTRUCTIVE === "0";

/** 命令位置前缀：行首、`;`/`&`/`|` 之后、或 `sh -c "` 之后；允许 sudo/env/... 包装。 */
const CP =
  String.raw`(?:^|[;&|]\s*|\|\s*|(?:ba|z|k)?sh\s+-c\s*["']?\s*)` +
  String.raw`(?:(?:sudo|env|nohup|nice|command|time)\s+|timeout\s+\d+\S*\s+)*`;

type Rule = { re: RegExp; why: string };
const R = (src: string, flags: string, why: string): Rule => ({
  re: new RegExp(src, flags.includes("m") ? flags : flags + "m"),
  why,
});

const BLOCK: Rule[] = [
  // 停 / 禁 / 重启服务
  R(CP + String.raw`systemctl\s+(?:stop|disable|restart|mask|poweroff|halt)\b`, "i", "停止/禁用/重启服务"),
  R(CP + String.raw`service\s+\S+\s+(?:stop|restart)\b`, "i", "停止/重启服务"),
  R(CP + String.raw`(?:shutdown|reboot|poweroff|halt)(?:\s|$)`, "i", "关机/重启主机"),
  // 删库表（锚在数据库客户端命令上，避免笔记/脚本里的 SQL 被误判）
  R(CP + String.raw`(?:mysql|mariadb|psql|sqlite3|sqlcmd)\b[^\n]*(?:DROP\s+(?:TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE|DELETE\s+FROM\s+[\w.\x60"\[\]]+\s*(?:;|$))`, "im", "对数据库执行破坏性 SQL"),
  R(CP + String.raw`(?:redis-cli|mongosh|mongo)\b[^\n]*(?:FLUSHALL|FLUSHDB|dropDatabase|drop\b)`, "i", "清空数据库"),
  // 账号 / 权限
  R(CP + String.raw`(?:useradd|userdel|usermod|groupadd|groupdel|chpasswd)\b`, "i", "增删改用户/组"),
  R(CP + String.raw`passwd\s+[A-Za-z_]`, "i", "修改某个用户密码"),
  R(CP + String.raw`net\s+user\s+\S+\s+\/add\b`, "i", "创建用户"),
  R(CP + String.raw`(?:mysql|psql|sqlite3)[^\n]*\b(?:GRANT|REVOKE)\s+[\w*]`, "i", "授予/回收数据库权限"),
  // 防火墙 / 启动项
  R(CP + String.raw`iptables\s+(?:-\w+\s+)*-F\b`, "i", "清空防火墙规则"),
  R(CP + String.raw`iptables\s+--flush\b`, "i", "清空防火墙规则"),
  R(CP + String.raw`nft\s+flush\b`, "i", "清空 nft 规则"),
  R(CP + String.raw`ufw\s+(?:disable|reset)\b`, "i", "关闭/重置 ufw"),
  R(CP + String.raw`crontab\s+-(?:r|e)\b`, "i", "删除/编辑计划任务"),
  // 删系统目录
  R(CP + String.raw`rm\s+(?:-\w*[rf]\w*\s+)+(?:~|\/(?:etc|var|home|root|usr|boot|bin|sbin|lib)(?:\/|\s|$)|\/(?:\s|$))`, "i", "删除系统目录"),
  // DoS
  R(String.raw`--flood\b`, "i", "洪泛攻击"),
  R(String.raw`\bhping3\b[^\n]*--flood`, "i", "洪泛攻击"),
  R(String.raw`\bab\s+[^\n]*-n\s*[1-9]\d{5,}`, "i", "超高并发压测"),
  R(String.raw`\bwrk\b[^\n]*-c\s*[1-9]\d{3,}`, "i", "超高并发压测"),
  // 直接删除业务数据（API）
  R(CP + String.raw`curl\b[^\n]*(?:-X\s*DELETE|--request\s+DELETE)\b`, "i", "直接 DELETE 业务接口"),
];

const CONFIG_NAMES = /(?:^|\/)(?:nginx\.conf|httpd\.conf|my\.cnf|redis\.conf|php\.ini|web\.config)$/i;

/** 提取「被写入的目标路径」，避免把 `cat /etc/passwd > /tmp/x` 当成写 /etc。 */
function writeTargets(cmd: string): string[] {
  const out: string[] = [];
  const push = (s: string | undefined) => {
    if (!s) return;
    const t = s.replace(/^["']|["']$/g, "").trim();
    if (t) out.push(t);
  };
  let m: RegExpExecArray | null;
  const reRedir = /(?:>>?)\s*("[^"]+"|'[^']+'|[^\s;&|()<>]+)/g;
  while ((m = reRedir.exec(cmd))) push(m[1]);
  const reTee = /\btee\b((?:\s+-\w+)*)\s+("[^"]+"|'[^']+'|\S+)/g;
  while ((m = reTee.exec(cmd))) push(m[2]);
  const reSed = /\bsed\s+-i\b([^\n;&|]*)/g;
  while ((m = reSed.exec(cmd))) for (const a of m[1].split(/\s+/)) if (a && !a.startsWith("-")) push(a);
  const reTrunc = /\btruncate\b([^\n;&|]*)/g;
  while ((m = reTrunc.exec(cmd))) for (const a of m[1].split(/\s+/)) if (a && !a.startsWith("-") && !/^\d+$/.test(a)) push(a);
  const reCopy = /\b(?:cp|mv)\b([^\n;&|]*)/g;
  while ((m = reCopy.exec(cmd))) {
    const args = m[1].split(/\s+/).filter((a) => a && !a.startsWith("-"));
    if (args.length >= 2) push(args[args.length - 1]);
  }
  const reDd = /\bdd\b[^\n;&|]*\bof=("[^"]+"|'[^']+'|\S+)/g;
  while ((m = reDd.exec(cmd))) push(m[1]);
  return out;
}

/** 命中返回原因，否则 undefined。导出以便离线测试。 */
export function inspectCommand(cmd: string): string | undefined {
  for (const rule of BLOCK) if (rule.re.test(cmd)) return rule.why;
  for (const t of writeTargets(cmd)) {
    const p = t.replace(/\\/g, "/");
    if (/^\/etc\//i.test(p)) return "写入 /etc 系统配置";
    if (CONFIG_NAMES.test(p)) return "改写服务配置";
  }
  return undefined;
}

export default function destructiveGuard(pi: ExtensionAPI) {
  if (OFF) return;
  pi.on("tool_call", async (event) => {
    if (event.toolName !== "bash") return undefined;
    const cmd = String((event.input as { command?: string })?.command ?? "");
    const why = inspectCommand(cmd);
    if (!why) return undefined;
    return {
      block: true,
      reason:
        `[destructive-guard] 拒绝执行：${why}。\n` +
        "这是不可逆或影响业务的操作。改用只读方式 / 经漏洞验证，或由操作员明确授权后再执行。\n" +
        `命令：${cmd.slice(0, 200)}`,
    };
  });
}
