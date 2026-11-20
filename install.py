#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一键装机：把仓库文件装进本机 pi 的 agent 目录并替换部署占位符。

用法（在本仓库根目录执行）：
    python3 install.py                    # 装到 ~/.pi/agent（Windows: %USERPROFILE%\\.pi\\agent）
    python3 install.py --workspace D:/2026/pi-ctf   # 指定 CTF 工作区（默认 D:/2026/pi-ctf）

做四件事：
  1. agent/ 下的提示词/扩展/策略 复制到 ~/.pi/agent/（已存在的同名文件会先备份到 ~/.pi/agent/backups/install-<时间戳>/）
  2. 把所有 `C:/Users/<USER>` 占位符替换成你的真实用户名
  3. shared/ 复制到工作区 _shared/（run.sh/stage.sh/board.sh/gate_db.py/dashboard.py…）
  4. 提示你配置 .env（PI_KALI_HOST / PI_KALI_PASS / FOFA_KEY）

注意：本脚本不覆盖 auth.json / models.json / settings.json / sessions 等个人配置；
settings.json.example 仅供参考（provider/模型自己改）。
"""
import argparse, os, shutil, sys, time
from pathlib import Path

REPO = Path(__file__).resolve().parent
USER = os.environ.get("USERNAME") or os.environ.get("USER") or "your-user"
HOME = Path(os.environ.get("USERPROFILE") or os.environ["HOME"])
AGENT_DIR = HOME / ".pi" / "agent"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", default="D:/2026/pi-ctf", help="CTF 工作区根（默认 D:/2026/pi-ctf）")
    args = ap.parse_args()
    ws = Path(args.workspace)

    if not AGENT_DIR.is_dir():
        print(f"[install] 未找到 {AGENT_DIR} —— 先安装 pi-coding-agent 再跑本脚本"); sys.exit(1)

    # 1. 备份
    ts = time.strftime("%Y%m%d-%H%M%S")
    bak = AGENT_DIR / "backups" / f"install-{ts}"
    bak.mkdir(parents=True, exist_ok=True)

    # 2. agent/ → ~/.pi/agent/（替换 <USER> 占位符）
    replaced = copied = 0
    for src in (REPO / "agent").rglob("*"):
        if src.is_dir(): continue
        rel = src.relative_to(REPO / "agent")
        dst = AGENT_DIR / rel
        if dst.exists():
            (bak / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(dst, bak / rel)
        dst.parent.mkdir(parents=True, exist_ok=True)
        text = src.read_text(encoding="utf-8")
        if "<USER>" in text:
            text = text.replace("C:/Users/<USER>", f"C:/Users/{USER}")
            replaced += 1
        dst.write_text(text, encoding="utf-8", newline="\n")
        copied += 1
    print(f"[install] agent 层：复制 {copied} 个文件（{replaced} 个做了 <USER> 替换）；旧文件备份在 {bak}")

    # 3. shared/ → 工作区 _shared/
    ws.mkdir(parents=True, exist_ok=True)
    shared_dst = ws / "_shared"; shared_dst.mkdir(parents=True, exist_ok=True)
    n = 0
    for src in (REPO / "shared").rglob("*"):
        if src.is_dir(): continue
        shutil.copy2(src, shared_dst / src.name); n += 1
    print(f"[install] shared 层：{n} 个脚本 → {shared_dst}")

    # 4. skills（可选：--with-skills）
    if "--with-skills" in sys.argv:
        sk_dst = AGENT_DIR / "skills"; sk_dst.mkdir(parents=True, exist_ok=True)
        for d in (REPO / "skills").iterdir():
            if d.is_dir(): shutil.copytree(d, sk_dst / d.name, dirs_exist_ok=True)
        print(f"[install] skills：→ {sk_dst}")

    # 5. 环境变量提示
    print("""
[install] 完成前还差最后一步——配置环境变量（放系统环境变量或 pi 启动脚本里）：
  PI_KALI_HOST   必填，Kali 的 SSH 目标，形如 "kali@192.168.x.x"
  PI_KALI_PASS   必填，SSH 密码（改密钥登录见 README）
  FOFA_KEY       可选，pentest 的 fofa_search 工具用
  PI_CTF_BOARDS_ROOT  可选，黑板根目录（默认 D:/2026/pi-ctf/ctf-boards）
  PI_CTF_SHARED       可选，闸门脚本目录（默认 <工作区>/_shared）
参照 .env.example 填好后重启 pi，派一个 ctf 子代理到带 .ctf-gate 的题目目录做冒烟。""")

if __name__ == "__main__":
    main()
