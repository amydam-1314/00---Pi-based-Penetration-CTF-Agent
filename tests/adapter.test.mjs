import assert from "node:assert/strict";
import { createAdapter, chooseBackend, mapPath, LocalAdapter, SshAdapter } from "../src/exec/adapter.ts";

let n = 0; const pass = (s) => { n++; console.log("PASS", s); };

// 1) 决策：唯一入口
assert.equal(chooseBackend({ config: {}, profileTransport: "local" }), "local");
assert.equal(chooseBackend({ config: { execution: { backend: "local" } }, profileTransport: "kali" }), "local");
assert.equal(chooseBackend({ config: {}, profileTransport: "kali" }), "ssh");
assert.equal(chooseBackend({ config: { execution: { backend: "ssh" } } }), "ssh");
assert.equal(chooseBackend({ config: {}, override: "local" }), "local");
pass("后端决策：配置 > profile > 默认 local，且可显式覆盖");

// 2) local：就是本机执行
const local = createAdapter({ config: {}, profileTransport: "local" });
assert.ok(local instanceof LocalAdapter);
const w = local.wrap("echo hi", { cwd: "/srv/pi-ctf", env: { CTF_GATE_DIR: "/srv/pi-ctf/gate" } });
assert.equal(w.backend, "local");
assert.match(w.command, /^cd '\/srv\/pi-ctf' && export CTF_GATE_DIR='\/srv\/pi-ctf\/gate'; echo hi$/);
pass("local 适配器：cd + export + 原命令，无 SSH");

// 3) ssh：缺配置必须报错，不静默降级
const ssh = createAdapter({ config: { mounts: [{ from: "/srv/pi-ctf/", to: "/remote/pi-ctf/" }] }, profileTransport: "kali" });
assert.ok(ssh instanceof SshAdapter);
assert.throws(() => ssh.wrap("echo hi", { cwd: "/srv/pi-ctf" }), /target 未配置/);
pass("ssh 适配器：缺 target 直接抛错（不降级 local）");

// 4) ssh：映射缺失报错
const ssh2 = createAdapter({
  config: { execution: { backend: "ssh", ssh: { target: "u@h", identityFile: "/k" } }, mounts: [{ from: "/srv/pi-ctf/", to: "/remote/" }] },
});
assert.throws(() => ssh2.wrap("echo hi", { cwd: "/elsewhere/x" }), /未覆盖在 mounts/);
pass("ssh 适配器：cwd 不在 mounts 内 → 报错");

// 5) 路径映射：边界/最长前缀/大小写/无匹配
const mounts = [
  { from: "/srv/pi-ctf/", to: "/remote/ctf/" },
  { from: "/srv/pi-ctf/deep/", to: "/remote/deep/" },
  { from: "/SRV/Up/", to: "/remote/up/" },
];
assert.equal(mapPath("/srv/pi-ctf/a/b", mounts), "/remote/ctf/a/b");
assert.equal(mapPath("/srv/pi-ctf/deep/x", mounts), "/remote/deep/x");     // 最长前缀
assert.equal(mapPath("/srv/pi-ctf2/x", mounts), null);                     // 边界：不得匹配 pi-ctf
assert.equal(mapPath("/srv/up/x", mounts), "/remote/up/x");                // 大小写不敏感
assert.equal(mapPath("/nope/x", mounts), null);
pass("路径映射：边界/最长前缀/大小写/无匹配=null");

// 6) wsl 后端：Windows 盘符路径映射到 /mnt/<drive>
const wsl = createAdapter({ config: { execution: { backend: "wsl", wsl: { distro: "Arch" } } } });
const ww = wsl.wrap("echo ok", { cwd: "D:/2026/kit/challs/t-01", env: { A: "b" } });
assert.equal(ww.backend, "wsl");
assert.match(ww.command, /^wsl\.exe -d Arch --cd '\/mnt\/d\/2026\/kit\/challs\/t-01' -- bash -lc /);
pass("wsl 后端：盘符路径自动映射 /mnt/d 并生成 wsl.exe 命令");

const { defaultBackendFor } = await import("../src/exec/adapter.ts");
assert.equal(defaultBackendFor("win32"), "wsl");
assert.equal(defaultBackendFor("linux"), "local");
assert.equal(defaultBackendFor("win32", "ssh"), "ssh");
pass("平台默认后端：Windows→wsl、Linux→local，显式配置优先");

console.log(`\n${n} adapter checks passed`);
