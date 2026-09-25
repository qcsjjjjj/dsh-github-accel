# 发布流程

本仓库当前状态：**源码已就绪，停在「建 GitHub 仓库并推送」这一步**。
原因只有一个：这台机器上没有 `gh` CLI，也没有任何 GitHub 凭据
（没有 `~/.git-credentials`、没有 `GH_TOKEN`、没有凭据管理器条目、没设置过全局 git 身份）。

下面两条路选一条即可。

---

## 阶段 A — 本地准备（**已完成，无需操作**）

| 已完成 | 说明 |
| --- | --- |
| `git init -b main` + 首次提交 | 身份只设在本仓库：`qcsjjjjj <qcsjjjjj@users.noreply.github.com>` |
| `package.json` | 去掉 `private`、补 `license` / `repository` / `homepage` / `bugs` / `keywords` / `engines`；peer 范围加上预发布分支 |
| `LICENSE` | MIT |
| `.gitignore` | 忽略 `node_modules/`、`*.tgz`、`recon/*.json`（勘察脚本的机器相关输出） |
| `.gitattributes` | `* -text` —— 不做任何换行转换。`client/client.js` 是被逐字节加载进浏览器的，检出时的换行改写会让「仓库内容」和「实际加载内容」不一致 |
| `CHANGELOG.md` | 0.1.0 / 0.2.0 完整改动清单 |
| `docs/` | 方案、Watt Toolkit 源码调研、国内不稳根因清单、调研原始数据 |
| 去机器化 | 清掉了源码与文档里所有本机绝对路径 |

核对：

```powershell
git log --oneline
git status --short          # 应该是干净的
```

---

## 阶段 B — 建仓库并推送

### 路线 1：本仓库自带的脚本（推荐，不需要装东西）

需要一个 **classic PAT**（勾 `repo`）：<https://github.com/settings/tokens>

```powershell
$env:GH_TOKEN = 'github_pat_...'          # 或者用 -Token 传
.\publish-dsh-github-accel.ps1 -Step repo
```

它会：确认令牌身份 → 建公开仓库 → 提交 → 推送 → 打上 `dsh-plugin` topic。

- `-DryRun` 只打印请求，不发出去。
- 令牌只作为一次性的 `http.extraheader` 传给 `git push`，**不会写进 `.git/config`**。
- 默认 `-Proxy ''`。若当时 `github.com` 直连不通，可以 `-Proxy 'http://127.0.0.1:18999'`
  借本插件自己的 CONNECT 代理。

### 路线 2：手动

```powershell
# 1) 建仓库：https://github.com/new
#    name: dsh-github-accel    Public    不要勾 README/.gitignore/license（本地已有）

# 2) 身份 + 提交（只设这个仓库）
git config user.name  qcsjjjjj
git config user.email "qcsjjjjj@users.noreply.github.com"
git add -A
git commit -m "dsh-github-accel 0.2.0"

# 3) 推送（会弹 GitHub 登录；GitHub 早已不接受账号密码，用 PAT 当密码）
git remote add origin https://github.com/qcsjjjjj/dsh-github-accel.git
git push -u origin main

# 4) 打 topic（仓库页 About 齿轮 → Topics）
#    dsh-plugin
```

---

## 阶段 C — Release（可选）

不发 npm 的话，预构建 tarball 是让插件市场优先展示「预构建安装」而不是「从源码构建」的
唯一办法。本仓库声明了 `dsh.bundle` 且没有构建步骤，源码装也能用，所以**不是必需**。

```powershell
npm pack                                  # 生成 dsh-github-accel-0.2.0.tgz
$env:GH_TOKEN = 'github_pat_...'
.\publish-dsh-github-accel.ps1 -Step release -Tag v0.2.0
```

> ⚠️ 资产名必须**不带版本号**（`dsh-github-accel.tgz`）。
> `releases/latest/download/<name>` 是照字面取文件名的：带版本号的名字今天有效，
> 下一次发版就会 404，而且没人会立刻察觉。脚本已经处理了这一点。

---

## 阶段 D — 插件市场（**当前明确不做**）

等仓库跑起来、自己用一段时间没问题之后再说。那天需要准备的东西：

1. **仓库必须建满 24 小时**（上游 CI 的硬门槛，自动卡点，不是对代码质量的评价）。
2. 仓库要有 `dsh-plugin` topic（阶段 B 已经打了）。
3. 仓库根 `package.json` 要声明 `dsh.bundle`（本仓库有）。
4. Fork <https://github.com/awesome-dsh-plugin/awesome-dsh-plugin>，
   加**一个**文件 `data/plugins/qcsjjjjj__dsh-github-accel.yml`：

```yaml
url: https://github.com/qcsjjjjj/dsh-github-accel
name: qcsjjjjj/dsh-github-accel
category: network
description:
  en: Accelerates GitHub for DSH without a TLS man-in-the-middle. hosts takeover plus a per-domain loopback SNI-passthrough tunnel, a local CONNECT proxy and a PAC fallback; browsers, git, npm and ghcr all go through the same validated connection pool.
  zh: 不做 TLS 中间人的 GitHub 加速。hosts 接管 + 一域名一地址的 SNI 直通，另有本地 CONNECT 代理与 PAC 兜底；浏览器、git、npm、ghcr 共用同一个经过端到端校验的连接池。
# 做了阶段 C 就取消下面这行的注释（资产名不带版本号）
# tarball: https://github.com/qcsjjjjj/dsh-github-accel/releases/latest/download/dsh-github-accel.tgz
```

5. 提 PR。CI 会检查条目数、`dsh.bundle`、仓库年龄、`awesome-lint` 与站点构建。

---

## 回滚

| 想撤销 | 命令 |
| --- | --- |
| 撤销本地 git 仓库 | `Remove-Item .git -Recurse -Force` |
| 撤销「插件写进 hosts / 系统代理」的改动 | `node tools\recover.mjs`（管理员） |
| 删除远端仓库 | 仓库页 Settings → 最下方 Delete this repository |

本插件**不改任何全局设置**：不写系统代理（除非你显式开 PAC）、不装证书、不装驱动、
不装系统服务。撤销 = 关开关，或 `tools/recover.mjs`。
