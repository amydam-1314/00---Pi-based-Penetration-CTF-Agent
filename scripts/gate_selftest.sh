#!/usr/bin/env bash
# gate_selftest.sh — 闸门/路径迁移的可重复自检（不碰任何真实题板）
#
# 用法: bash _shared/gate_selftest.sh [-k]      -k 保留临时目录便于排障
#
# 断言来源（不凭印象）：
#   S1/S5 路径解析四分支 —— policies/roots.ts、_shared/root.sh 的当前实现
#   S2 挂载映射 —— roots.ts mapMount 的实现语义（最长前缀/边界/大小写/无匹配=null）
#   S3 看板 rev —— gate_db.py import --rev 的既有契约
#   S4 run: 命名空间 —— _shared/run.sh 的既有契约（只认 run:<tag>；超时登记 run:<tag>）
#   S6 迁移前后一致性 —— 与 ctf-gate.ts.bak-migrate-* 的路径函数逐项对比
# 运行态断言（未绑题拒绝启动、连续不写板拦截）需要扩展/模型在场，这里只登记 SKIP，
# 由真实子 agent 在临时题目录里完成。
set -uo pipefail

KEEP=0
[ "${1:-}" = "-k" ] && KEEP=1

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# 扩展安装目录（policies/、ctf-gate/ 在这里），不是项目目录
AGENT="${PI_CODING_AGENT_DIR:-$HOME/.pi/agent}"
if [ ! -d "$AGENT/policies" ]; then
  _up="$(cmd.exe /c 'echo %USERPROFILE%' 2>/dev/null | tr -d '\r')"
  [ -n "$_up" ] && AGENT="$(wslpath -u "$_up" 2>/dev/null)/.pi/agent"
fi
[ -d "$AGENT/policies" ] || { echo "[selftest] 找不到扩展目录（policies/roots.ts）" >&2; exit 2; }
PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; }
skip() { SKIP=$((SKIP+1)); printf '  SKIP  %s\n' "$1"; }
expect_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "want=[$3] got=[$2]"; fi; }
expect_contains() { case "$2" in *"$3"*) ok "$1";; *) bad "$1" "want~[$3] got=[$2]";; esac; }

# 临时根：Windows 可见（脚本要用 Windows 侧 node 跑 roots.ts），且含空格与中文
TMPW="$(cmd.exe /c 'echo %LOCALAPPDATA%' 2>/dev/null | tr -d '\r')"
TMPWSL="$(wslpath -u "$TMPW" 2>/dev/null || echo /tmp)"
BASE="$TMPWSL/Gate SelfTest 自检/$$"
mkdir -p "$BASE" || exit 2
cleanup() { [ "$KEEP" = "1" ] || rm -rf "$BASE"; }
trap cleanup EXIT
echo "临时目录: $BASE"

GD="$ROOT/_shared/gate_db.py"
NODE="$(command -v node 2>/dev/null || command -v node.exe 2>/dev/null || echo /mnt/d/node。js/node.exe)"

# ---------- S1 根解析四分支 + 空格/中文 ----------
echo "[S1] 根解析四分支"
mkcfg() { mkdir -p "$1"; printf '%s' "$2" > "$1/env.json"; }
PROJ="$BASE/项目 副本"; mkdir -p "$PROJ/_shared" "$PROJ/challs/t-01"
printf '{"kind":"ctf-project"}' > "$PROJ/ctf.project.json"
cp "$GD" "$ROOT/_shared/root.sh" "$PROJ/_shared/"; mkdir -p "$PROJ/ctf-boards"
CFG_NONE="$BASE/cfg-none"; mkcfg "$CFG_NONE" '{"note":"no projectRoot"}'
CFG_BAD="$BASE/cfg-bad";   mkcfg "$CFG_BAD" "{\"projectRoot\":\"$BASE/不存在的目录\"}"
CFG_CONF="$BASE/cfg-conf"; mkdir -p "$BASE/别处"; mkcfg "$CFG_CONF" "{\"projectRoot\":\"$BASE/别处\"}"

run_root() { # $1=cwd $2=agentcfg $3=envvar
  ( cd "$1" && PI_CODING_AGENT_DIR="$2" CTF_PROJECT_ROOT="${3:-}" bash -c "source '$PROJ/_shared/root.sh' 2>/dev/null; printf '%s' \"\${CTF_ROOT:-}\"" )
}
err_of() { # 同参数，取 stderr 首行
  ( cd "$1" && PI_CODING_AGENT_DIR="$2" CTF_PROJECT_ROOT="${3:-}" bash -c "source '$PROJ/_shared/root.sh'" 2>&1 >/dev/null | head -1 )
}

# A 无配置 + 唯一标记 → 正常解析（空格/中文路径）
expect_eq "A 无配置→按标记发现（空格/中文）" "$(run_root "$PROJ/challs/t-01" "$CFG_NONE" "")" "$PROJ"
# B 显式配置有效 → 用它
expect_eq "B 显式配置有效" "$(run_root /tmp "$CFG_NONE" "$PROJ")" "$PROJ"
# C 显式配置失效 → 报错且不给根
expect_eq "C 配置失效→无根" "$(run_root /tmp "$CFG_BAD" "")" ""
expect_contains "C 报错指明来源" "$(err_of /tmp "$CFG_BAD" "")" "不存在"
# D 冲突 → 报错且不给根
expect_eq "D 来源冲突→无根" "$(run_root "$PROJ/challs/t-01" "$CFG_CONF" "")" ""
expect_contains "D 报错指出冲突双方" "$(err_of "$PROJ/challs/t-01" "$CFG_CONF" "")" "冲突"
# E 无根 → 报错
expect_contains "E 找不到根→报错" "$(err_of /tmp "$CFG_NONE" "")" "找不到项目根"

# ---------- S2 挂载映射语义 ----------
echo "[S2] mount 映射（最长前缀/边界/大小写/无匹配）"
if "$NODE" --version >/dev/null 2>&1; then
  cp "$AGENT/policies/roots.ts" "$BASE/roots.ts"
  cat > "$BASE/map.mjs" <<'JS'
const { mapMount } = await import("./roots.ts");
const env = { mounts: [
  { from: "C:/case", to: "/mnt/hostcase" },
  { from: "C:/case/proj", to: "/mnt/proj" },
  { from: "E:/有 空格/项目", to: "/mnt/space/项目" },
]};
const cases = [
  ["C:/case/x", "/mnt/hostcase/x"],
  ["C:/case2/x", null],
  ["c:/CASE/proj/a", "/mnt/proj/a"],
  ["E:/有 空格/项目/data/x", "/mnt/space/项目/data/x"],
  ["F:/no/x", null],
];
let bad = 0;
for (const [i, want] of cases) {
  const got = mapMount(i, env);
  if (got !== want) { bad++; console.log(`BAD ${i} → ${got} (want ${want})`); }
}
console.log(bad ? "MAPFAIL" : "MAPOK");
JS
  out="$(cd "$BASE" && "$NODE" --experimental-strip-types map.mjs 2>&1 | tail -2)"
  expect_contains "S2 映射用例全过" "$out" "MAPOK"
else
  skip "S2 没有 node，跳过（映射语义未验证）"
fi

# ---------- S3 看板 rev 契约 ----------
echo "[S3] 看板写入：rev 递增 / 旧 rev 拒绝"
TDB="$BASE/board/gate.sqlite"; mkdir -p "$BASE/board"
python3 "$GD" --db "$TDB" init >/dev/null 2>&1
# 板 JSON 按 gate_db.py 的 BOARD_FIELDS 动态生成（契约变了也不用改测试；缺键会撞 canonical_board 的 KeyError）
board_json() {
  python3 - "$ROOT/_shared/gate_db.py" "$1" <<'PYEOF'
import re, sys, json
src = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r"BOARD_FIELDS\s*=\s*\(([^)]*)\)", src)
fields = [x.strip().strip('"\'') for x in m.group(1).split(",") if x.strip()]
obj = {"challenge": {"name": "selftest", "remote": ""}, "params": {}, "next": [f"selftest {sys.argv[2]}"]}
for f in fields:
    obj.setdefault(f, [] if f not in ("challenge", "params") else {})
print(json.dumps(obj))
PYEOF
}
rev_of() { python3 "$GD" --db "$TDB" rev 2>/dev/null | tr -d ' \n'; }
board_json r1 | python3 "$GD" --db "$TDB" import --rev 0 >/dev/null 2>&1
expect_eq "S3 首次 import → rev=1" "$(rev_of)" "1"
board_json r1b | python3 "$GD" --db "$TDB" import --rev 0 >/dev/null 2>&1
expect_eq "S3 旧 rev 写入被拒（rev 不变）" "$(rev_of)" "1"
board_json r2 | python3 "$GD" --db "$TDB" import --rev 1 >/dev/null 2>&1
expect_eq "S3 正确 rev 写入 → rev=2" "$(rev_of)" "2"

# ---------- S4 run: 命名空间契约 ----------
echo "[S4] run.sh：裸 tag 放行 / run:<tag> 拦 / 超时登记 run:<tag>"
TDIR="$BASE/课 题 01"; mkdir -p "$TDIR/gate"
export CTF_GATE_DIR="$TDIR/gate" CTF_GATE_DB="$TDB" CTF_GATE_PY="$PROJ/_shared/gate_db.py"
python3 "$GD" --db "$TDB" falsify "run:ns-block" "selftest" "x" >/dev/null 2>&1
python3 "$GD" --db "$TDB" falsify "ns-plain" "selftest" "x" >/dev/null 2>&1
out1="$(cd "$TDIR" && bash "$ROOT/_shared/run.sh" ns-block 5 -- echo SHOULD_NOT_RUN 2>&1)"; rc1=$?
expect_eq "S4 run:<tag> 已证伪 → 拒绝(exit 2)" "$rc1" "2"
expect_contains "S4 拒绝原因可读" "$out1" "已被证伪"
out2="$(cd "$TDIR" && bash "$ROOT/_shared/run.sh" ns-plain 5 -- echo PLAIN_OK 2>&1)"; rc2=$?
expect_eq "S4 裸 tag 不拦同名 run(exit 0)" "$rc2" "0"
expect_contains "S4 裸 tag 实际执行" "$out2" "PLAIN_OK"
(cd "$TDIR" && bash "$ROOT/_shared/run.sh" ns-slow 1 -- sleep 3 >/dev/null 2>&1); rc3=$?
expect_eq "S4 超时 → exit 124" "$rc3" "124"
cond="$(python3 "$GD" --db "$TDB" falsified-get "run:ns-slow" 2>/dev/null | head -1)"
expect_contains "S4 超时登记为 run:<tag>" "$cond" "timeout:1s"

# ---------- S5 运行态断言：登记 SKIP（需扩展/模型在场） ----------
echo "[S5] 运行态断言（需真实子 agent）"
skip "未绑定题目时拒绝启动 —— 需 ctf-gate 扩展在场（重启后由子 agent 验证）"
skip "连续不写板触发闸门 —— 需 ctf-gate 扩展在场（重启后由子 agent 验证）"

# ---------- S6 与迁移前实现的一致性 ----------
echo "[S6] 迁移前后路径函数一致性"
BAK="$(ls -1 "$AGENT/ctf-gate/ctf-gate.ts.bak-migrate-"* 2>/dev/null | tail -1)"
if [ -n "${BAK:-}" ] && "$NODE" --version >/dev/null 2>&1; then
  mkdir -p "$BASE/parity/node_modules/typebox" "$BASE/parity/node_modules/@earendil-works/pi-coding-agent"
  printf 'export const Type = new Proxy({}, { get: () => (o) => o || {} });\n' > "$BASE/parity/node_modules/typebox/index.js"
  printf '{"name":"typebox","type":"module","main":"index.js"}\n' > "$BASE/parity/node_modules/typebox/package.json"
  printf 'export const createLocalBashOperations = () => ({});\n' > "$BASE/parity/node_modules/@earendil-works/pi-coding-agent/index.js"
  printf '{"name":"@earendil-works/pi-coding-agent","type":"module","main":"index.js"}\n' > "$BASE/parity/node_modules/@earendil-works/pi-coding-agent/package.json"
  mkdir -p "$BASE/parity/policies" "$BASE/parity/ctf-gate"
  cp "$AGENT/policies/"*.ts "$BASE/parity/policies/"
  cp "$BAK" "$BASE/parity/ctf-gate/old.ts"; cp "$AGENT/ctf-gate/ctf-gate.ts" "$BASE/parity/ctf-gate/new.ts"
  for f in old new; do
    [ -s "$BASE/parity/ctf-gate/$f.ts" ] || { bad "S6 源码复制失败：$f.ts" ""; }
  done
  printf '\nexport { gatePy, toBashPath, isWorkspaceRoot, workspaceChallenge, looksLikeChallenge };\n' >> "$BASE/parity/ctf-gate/old.ts"
  printf '\nexport { gatePy, toBashPath, isWorkspaceRoot, workspaceChallenge, looksLikeChallenge };\n' >> "$BASE/parity/ctf-gate/new.ts"
  cat > "$BASE/parity/p.mjs" <<'JS'
const A = await import("./ctf-gate/old.ts");
const B = await import("./ctf-gate/new.ts");
const inputs = {
  isWorkspaceRoot: ["D:/2026/pi-ctf", "D:/2026/pi-ctf/tsec-37edc64/challs/f2-05"],
  workspaceChallenge: ["D:/2026/pi-ctf/tsec-37edc64/challs/f2-05", "D:/2026/pi-ctf/tsec-37edc64/challs/f2-05/gate", "D:/2026/pi-ctf"],
  looksLikeChallenge: ["D:/2026/pi-ctf/ctf-boards/a/challenges/b/gate", "D:/2026/pi-ctf/tsec-37edc64/challs/f2-05"],
  toBashPath: ["D:/2026/pi-ctf/tsec-37edc64/challs/f2-05", "D:/2026/pi-ctf/a b/中文/x.txt"],
};
let diff = 0, n = 0;
for (const [fn, args] of Object.entries(inputs)) {
  for (const a of args) {
    const s = (m) => { try { return JSON.stringify(m[fn](a)); } catch (e) { return "ERR"; } };
    n++;
    if (s(A) !== s(B)) { diff++; console.log(`DIFF ${fn}(${a}) old=${s(A)} new=${s(B)}`); }
  }
}
console.log(diff ? `PARITY-DIFF ${diff}/${n}` : `PARITY-OK ${n}`);
JS
  out="$(cd "$BASE/parity" && "$NODE" --experimental-strip-types p.mjs 2>&1 | tail -3)"
  expect_contains "S6 与迁移前一致（排除已记录的 toBashPath 根映射变化）" "$out" "PARITY-OK"
  [ -n "$out" ] && case "$out" in *PARITY-DIFF*) printf '        差异明细: %s\n' "$out";; esac
else
  skip "S6 缺少迁移前备份或 node，未对比"
fi

# ---------- S7 内部函数冒烟：抓"改名漏改"这类 ReferenceError ----------
echo "[S7] 内部函数冒烟（改名遗漏导致的初始化期崩溃）"
if "$NODE" --version >/dev/null 2>&1; then
  S7="$BASE/smoke"; mkdir -p "$S7/node_modules/typebox" "$S7/node_modules/@earendil-works/pi-coding-agent" "$S7/policies" "$S7/ctf-gate"
  printf 'export const Type = new Proxy({}, { get: () => (o) => o || {} });\n' > "$S7/node_modules/typebox/index.js"
  printf '{"name":"typebox","type":"module","main":"index.js"}\n' > "$S7/node_modules/typebox/package.json"
  printf 'export const createLocalBashOperations = () => ({});\nexport const createLocalPowerShellOperations = () => ({});\n' > "$S7/node_modules/@earendil-works/pi-coding-agent/index.js"
  printf '{"name":"@earendil-works/pi-coding-agent","type":"module","main":"index.js"}\n' > "$S7/node_modules/@earendil-works/pi-coding-agent/package.json"
  cp "$AGENT/policies/"*.ts "$S7/policies/"
  cp "$AGENT/ctf-gate/ctf-gate.ts" "$S7/ctf-gate/gate.ts"
  # 把顶层 function 全部导出，然后逐个调用，只对 ReferenceError 判失败
  python3 - "$S7/ctf-gate/gate.ts" <<'PYEOF'
import re, sys
p = sys.argv[1]
src = open(p, encoding="utf-8").read()
names = sorted(set(re.findall(r"^function\s+([A-Za-z_$][\w$]*)", src, flags=re.M)))
src += "\nexport { " + ", ".join(names) + " };\n"
open(p, "w", encoding="utf-8").write(src)
open(p + ".names", "w", encoding="utf-8").write("\n".join(names))
PYEOF
  cat > "$S7/s.mjs" <<'JS'
import { readFileSync } from "node:fs";
const names = readFileSync(new URL("./ctf-gate/gate.ts.names", import.meta.url), "utf8").split("\n").filter(Boolean);
const mod = await import("./ctf-gate/gate.ts");
const probes = [
  [],
  ["D:/2026/pi-ctf/tsec-37edc64/challs/f2-05"],
  ["D:/2026/pi-ctf/ctf-boards/a/challenges/b/gate"],
  ["echo hello"],
  ["python3 -c 'print(1)'"],
];
const bad = [];
for (const n of names) {
  const fn = mod[n];
  if (typeof fn !== "function") continue;
  for (const args of probes) {
    try { fn(...args); } catch (e) {
      const msg = String(e?.message ?? e);
      if (/is not defined/.test(msg)) { bad.push(`${n}: ${msg}`); break; }
    }
  }
}
console.log(bad.length ? "SMOKE-BAD " + bad.join(" | ") : `SMOKE-OK ${names.length} 个函数`);
JS
  out="$(cd "$S7" && "$NODE" --experimental-strip-types s.mjs 2>&1 | tail -2)"
  expect_contains "S7 内部函数无 ReferenceError" "$out" "SMOKE-OK"
  case "$out" in *SMOKE-BAD*) printf '        %s\n' "$out";; esac
else
  skip "S7 没有 node，跳过冒烟"
fi

# ---------- S8 看板字段契约对齐 ----------
echo "[S8] 扩展 BOARD_FIELDS 与 gate_db.py 是否一致（漂移会静默锁死所有工具）"
fields_of() { python3 - "$1" <<'PYEOF'
import re, sys
src = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r"BOARD_FIELDS\s*=\s*[\[(]([^\]\)]*)[\])]", src)
print(",".join(sorted(x.strip().strip('"\'') for x in m.group(1).split(",") if x.strip())) if m else "NOTFOUND")
PYEOF
}
ext_fields="$(fields_of "$AGENT/ctf-gate/ctf-gate.ts")"
db_fields="$(fields_of "$ROOT/_shared/gate_db.py")"
if [ "$ext_fields" = "NOTFOUND" ] || [ "$db_fields" = "NOTFOUND" ]; then
  bad "S8 找不到 BOARD_FIELDS 定义" "ext=$ext_fields db=$db_fields"
elif [ "$ext_fields" = "$db_fields" ]; then
  ok "S8 字段一致（$db_fields）"
else
  bad "S8 字段不一致" "扩展=[$ext_fields] gate_db=[$db_fields]"
fi

# ---------- S9 关键常量与迁移前一致 ----------
echo "[S9] 闸门关键常量（迁移前 vs 当前）"
BAK2="$(ls -1 "$AGENT/ctf-gate/ctf-gate.ts.bak-migrate-"* 2>/dev/null | tail -1)"
if [ -n "${BAK2:-}" ]; then
  const_of() { grep -oE "$2 = [0-9]+;" "$1" 2>/dev/null | head -1 | grep -oE "[0-9]+"; }
  for c in WORK_THRESHOLD; do
    a="$(const_of "$BAK2" "WORK_THRESHOLD")"; b="$(const_of "$AGENT/ctf-gate/ctf-gate.ts" "WORK_THRESHOLD")"
    expect_eq "S9 $c 未变（迁移前=$a）" "$b" "$a"
  done
else
  skip "S9 缺少迁移前备份"
fi

# ---------- 收尾 ----------
echo
echo "结果: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ "$KEEP" = "1" ] && echo "临时目录保留: $BASE"
[ "$FAIL" -eq 0 ] || exit 1
