# pi-ctf-kit

CTF / 授权渗透工作台：闸门、看板、执行后端，打包成可安装的 Pi package。

```bash
pi install ./pi-ctf-kit          # 本地目录
pi install git:github.com/<you>/pi-ctf-kit@v0.1.0
```

## 目录

```
extensions/   Pi 工具注册（board_digest / orchestrator-guard / orchestrator-patrol）
src/paths/    根解析（项目根、数据根）与目录身份判定
src/exec/     ExecutionAdapter：local / ssh 两种后端的唯一选择点
src/db/       看板访问客户端（只调用 gate_db.py，不自己写 SQL）
db/           gate_db.py（唯一写入口）、SQLite schema、migrations
agents/       角色提示（ctf / recon / pentest / audit / forensics / awd-hardening）
profiles/     ctf / dev / pentest 领域配置
prompts/      主提示词模板
scripts/      install.sh（安装检查）、board.sh / root.sh / gate_selftest.sh
config/       env.sample.json（配置样例，不含真实值）
tests/        adapter / db / 迁移自检
```

## 五条约束（本包的设计前提）

1. **代码与运行数据分离**：包内只放代码、schema、迁移与样例；`gate.sqlite`、会话日志、证据、
   真实 `env.json`、凭据一律留在数据目录，`.gitignore` 已排除。
2. **唯一写入口**：看板写操作只有 Python 的 `db/gate_db.py`（`board.sh` 与扩展工具都调它）。
   TS 侧 `src/db/client.ts` 只做调用与解析，不实现第二套 SQL 写入——历史上
   `angles` / `coverage` 两次契约漂移都是"两处各自维护字段表"造成的。
3. **资源按包根解析**：模板、schema、脚本都相对包根；项目根与数据根只能来自
   `env.json` 的 `projectRoot` / `boardsRoot`、标记文件 `ctf.project.json`、或显式参数。
   相对路径必须声明基准，解析失败就报错，不按 cwd 或 `$HOME` 猜。
4. **执行后端统一**：`createAdapter()` 是唯一决策点——
   `execution.backend` > `profile.transport` > 默认 `local`。
   `ctf-gate` 与 `kali-exec` 都调用它，不允许各自判断 SSH。
5. **迁移用 `PRAGMA user_version`**：`db/migrations/NNNN_*.sql` 只向前应用，
   `db/migrate.py` 应用前先备份；WAL 只用于本机磁盘（SQLite 官方不建议放网络文件系统）。

## 配置

```bash
cp config/env.sample.json ~/.pi/agent/env.json   # 然后填值
```

| 字段 | 说明 |
|---|---|
| `projectRoot` | 项目根（VM 原生路径，如 `/srv/pi-ctf`） |
| `boardsRoot` | 看板根；`null` = `<projectRoot>/ctf-boards` |
| `execution.backend` | `local`（Pi 就在目标环境里）或 `ssh`（Windows Pi → 远端） |
| `execution.ssh` | `target` / `identityFile`（推荐）/ `passwordFile`；口令走 `SSHPASS`，不进 argv |
| `mounts` | 仅 ssh 后端需要：宿主路径 → 远端挂载点，最长前缀优先、分段边界匹配 |

## 自检

```bash
bash scripts/install.sh      # 环境/结构/配置/迁移检查
bash tests/run-all.sh        # 语法 + 单元测试 + 迁移自检
bash scripts/gate_selftest.sh # 闸门与路径的端到端自检（需要项目目录）
```

## 已知边界

- `agents/`、`profiles/` 不是 Pi 自动发现的资源类型，需要安装脚本或扩展按包根读取
  （本包在 `scripts/install.sh` 里检查并提示位置）。
- ssh 后端的 `StrictHostKeyChecking=accept-new` 是 TOFU（首次记录指纹），不是完整主机身份校验。
- 看板"目录身份"是兼容匹配（`<战役>/challs/<题目>`），战役目录改名会失效。
