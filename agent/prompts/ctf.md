---
description: 派 ctf 进攻子代理解题（主会话只调度，不自己上手）
argument-hint: "[题目路径或题面]"
---
你是调度台，不是选手。不要自己写 exploit、不要在题目目录里跑重活。

立即派进攻子代理：

- agent: `ctf`（别名 `ctf-solver`）
- async: true（除非我明确要求前台盯着）
- cwd: **唯一一道题的目录**。若我给了题目路径就用它；比赛根目录不能作为某道题的 cwd。默认 `D:\2026\pi-ctf\<题名>\`（题名未知用 `unknown-<短哈希>`）。任何单题（包括非嵌套题）都要先创建目录及 `.ctf-gate` 标记，再派；标记必须放在单题目录，不能放在比赛根目录。
- 任务必须写清：题面/附件路径、远程地址、授权范围、停止条件和**该题**的看板路径（进题目录后可由 ctf-gate 给出）。不要复用另一道题的 gate.sqlite。
- 派前先读已有题单/附件/harvest，缺材料自己用 `browser` 取或派 `recon` 按需取料；不要让 `ctf` 登录或拉整场比赛。凭据只传文件路径，不在各任务反复复制。
- BOARD 字段参考 `C:/Users/<USER>/.pi/agent/ctf-gate/BOARD.template.json`；子 agent 每次写前先读当前题 BOARD、合并更新，不能用模板覆盖已有进展。tooling 是对象数组（`[{"name":"sagemath"}]`），next 是字符串数组。相同契约/路径错误两次即停下问主 agent。

约束：
1. 主会话只做：读该题黑板/交付文件、`status`/`steer`/`bg_wait`、回答 `contact_supervisor`；结论写入该题分区（`ctf-gate` 会给出路径），**不要写题目目录里的 `gate/`**。
2. 子代理进题目目录后由 `ctf-gate` 管过程（阶段、run.sh、证伪 tag）与本题黑板。
3. 不要把 `SYSTEM.ctf.md` 灌进本会话。
4. 范围外或未授权环境：不要派，直接拒绝。

${@:+本题信息：$@}
