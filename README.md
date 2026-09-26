# dsh-github-accel

给 [DSH（DeepSeek Harness）](https://github.com/deepseek-ai/dsh) 用的 GitHub 加速插件。
**不做 TLS 中间人、不装证书、不改系统代理**，浏览器 / `git` / `npm` / `ghcr.io` 一次全通。
开关在**会话顶部栏偏右**的位置（席位 `conversation.session.header.utilities`，
标题之后、角落按钮之前）。

> 版本 0.2（2026-09-25）· MIT · 仅 Windows 实测
>
> 这一版把「GitHub 时好时坏」查到了机制层面并逐个修掉 —— 包括两个**会让 DSH 进程直接退出**
> 或**慢慢泄漏 socket** 的真 bug。改动清单见 [`CHANGELOG.md`](CHANGELOG.md)。

## 文档

| 文件 | 内容 |
| --- | --- |
| 本文件 | 使用与运维手册 |
| [`CHANGELOG.md`](CHANGELOG.md) | 每个版本改了什么、为什么 |
| [`docs/PLAN-2026-09-25.md`](docs/PLAN-2026-09-25.md) | 0.2 的完整方案：本机实测证据、架构、实施结果、**三处自我勘误** |
| [`docs/research-watt-toolkit.md`](docs/research-watt-toolkit.md) | Watt Toolkit（Steam++）网络加速模块的**源码级**调研，含每条的源码路径与可信度标注 |
| [`docs/github-cn-instability-checklist.md`](docs/github-cn-instability-checklist.md) | 「GitHub 在国内不稳」的根因清单与逐条验证方法 |
| [`docs/PUBLISHING.md`](docs/PUBLISHING.md) | 发布到 GitHub / 插件市场的流程 |

---

## 一句话原理

**不做 TLS 中间人。** hosts 把每个域名指向**一个独立的回环地址**（`127.0.0.2`、
`127.0.0.3`……），本机在这些地址的 443 上只读 ClientHello 里的 SNI，然后把**原始字节**
转发到该域名的真实 IP。客户端看到的永远是 GitHub 自己的证书，所以浏览器、`curl`、
`git`、Node `fetch` 一次全通，**不需要装任何证书**。

### 为什么不用 Steam++ / Watt Toolkit 那套

它把域名指到 `127.0.0.1`，再在本地做 **TLS 中间人**（逐域名现签自签证书）。本机实测的代价：

| 客户端 | 走 MITM 的结果 | 原因 |
| --- | --- | --- |
| Edge / Chrome | ✅ 能上 | 认 Windows 信任库里那张 `CN=SteamTools Certificate` |
| `curl` / .NET / git(schannel) | ❌ `0x80092012` | schannel 做吊销检查，自签叶子证书查不到吊销状态 |
| Node `fetch` | ❌ `UNABLE_TO_VERIFY_LEAF_SIGNATURE` | Node 不读 Windows 证书库 |

「浏览器能上 ≠ 命令行能上」，而 DSH 的插件、`git`、`npm`、`ghcr.io` 全在命令行这一侧。
MITM 能带来的唯一好处（把 SNI 伪装成 `Github`）对我们不成立，所以**拒绝中间人**。

---

## 三条通路（互为备份）

| 通路 | 做什么 | 需要管理员 | 影响范围 |
| --- | --- | --- | --- |
| **P1 hosts** | hosts 接管 + 一域名一地址的 SNI 直通 | 是（写 hosts） | 全系统：浏览器、git、curl、Node 全走加速 |
| **P2 代理** | `127.0.0.1:18999` 上的 CONNECT 代理 | 否 | 只影响设置了 `HTTPS_PROXY` 的工具链 |
| **P3 PAC** | 把 `AutoConfigURL` 指向本地 PAC，只代理 GitHub 域名 | 否（只写 `HKCU`） | 浏览器；**hosts 写不进去时的兜底** |

模式：`both`（默认，P1+P2）、`hosts`（只有 P1）、`proxy`（只有 P2）。
P3 默认策略 `auto`：**只在 P1 失败时才启用**，避免两条路互相干扰。

---

## 它到底解决了哪些「GitHub 时好时坏」

每一条都有本机实测证据（细节见 `docs/PLAN-2026-09-25.md`）。

### 1. hosts 是唯一让浏览器「只有一个地址」的那一层，而那个地址会阶段性死掉

```
系统 DNS 对 github.com 只回 1 条 A 记录：20.205.243.166
实测：20.205.243.166 在 5 个不同 SNI 上全部 timeout（0/5）
      同一时刻 140.82.112.4 / 140.82.113.4 对 github.com 回 200 ✔
浏览器没有多候选切换 → 用户看到「GitHub 打不开」
```

隧道有**完整的候选池 + 并行竞速 + 坏地址降权**，严格比裸路径可靠。这也是
`github.com` 默认走隧道的原因（`DSH_GITHUB_ACCEL_AUTO_APP=1` 可以改回自适应）。

### 2. 坏地址必须**真的被换下去**（老版本的致命缺陷）

黑洞型的坏地址不报错、只是不出声。老代码只把「RST + 一个字节都没发出去」判为坏地址，
而我们**总是要先转发 ClientHello**，所以那个条件是永远不成立的 —— 结果是
**坏地址永远霸占候选表第一位，每次请求都先撞它一遍**。

现在改成看**上游回了几个字节**：

| 情况 | 判定 | 后果 |
| --- | --- | --- |
| 上游一个字节都没回就 RST | 硬失败 | 连续 2 次进冷却（30 s 起，指数退避到 5 min） |
| 上游一个字节都没回、拖了 ≥1.5 s | **卡死（stall）** | **一次就降权**（15 s 冷却） |
| 已经传过字节才断（浏览器关页面） | 软失败 | 不惩罚 |

### 3. 端到端校验，而不是「TCP 通就算好」

实测「能握手 ≠ 服务这个 Host」：

```
Host: github.com @ 20.205.243.168 -> 403   （api 的地址）
Host: github.com @ 20.205.243.165 -> 400   （codeload 的地址）
Host: github.com @ 140.82.112.4   -> 200   （真服务 github.com）
```

所以校验 = **校验证书的 TLS 握手 + 真发一个 `HEAD /` + 按域名核对状态码**
（`EXPECTED_STATUS`）。后台每 90 s 对热域名重跑一次，不在连接路径上跑。

### 4. hosts 条目绝不留「没有监听的地址」

老版本只要**任一** 443 监听成功就写全部域名。现在**按域名逐个判断**：
谁的监听起来了才写谁。写之前原子落盘（临时文件 + rename），写之后**读回校验**。

> 参考事故：Steam++ 的加速没开时，它在 hosts 里留的 31 条 `127.0.0.1` 会把 GitHub
> 变成 `ECONNREFUSED 127.0.0.1:443` —— 从「有点慢」直接变「完全打不开」，而且没有提示。

### 5. 连接复用不会再串域名

浏览器做 HTTP/2 连接复用（coalescing）的前提是「新 origin 解析出的 IP 里有某条已存在
连接的目标 IP」。实测 `raw.githubusercontent.com` 的证书 SAN **包含 `github.com`**，
所以它们一旦共用地址，浏览器就会把 github.com 的请求发到 Fastly 上，得到
`Fastly error: unknown domain: github.com`。

**一域名一地址**让这个前提永远不成立。位置表固定在 `server/domains.js` 的
`DOMAIN_TABLE` 里 —— 增删域名不会让其它域名的地址平移（老版本按下标算，改一次表就全抖一次）。

### 6. 顺手治好 IPv6 黑洞

本机有全局 IPv6（CERNET），而实测**有 AAAA 且 4 条全部 timeout** 的域名：

```
github.githubassets.com          2606:50c0:800x::215
avatars.githubusercontent.com    2606:50c0:800x::154
raw.githubusercontent.com        2606:50c0:800x::154
user-images.githubusercontent.com 2606:50c0:800x::154
pkg-containers.githubusercontent.com 2606:50c0:800x::154
```

Windows 默认前缀策略里 IPv6 优先于 IPv4，浏览器就会先撞黑洞。
**域名一旦写进 hosts，Windows 解析器就只给 IPv4 答案、AAAA 被直接抑制** ——
所以把这 5 个域名（以及整族 `githubusercontent`）一起接管，等于顺手把黑洞绕过去了。

### 7. 上游「连得上但一声不吭」时，换一个并重放 ClientHello

这是这条网络上最恶心的失败模式：坏地址不报错，只是**不出声**。
浏览器那边看到的是「连接建立了但一直不出内容」，会干等到自己超时（15–30 s）。

我们有一个浏览器没有的优势：**ClientHello 还在我们手里**。所以只要
「已经转发出去、上游一个字节都没回、且超过 1.5 s」，就直接丢掉这条上游、
换一个候选把**同一段 ClientHello 重放过去** —— 对客户端完全透明。

实测：一个模拟黑洞上游，客户端拿到好上游的回应只用了 **405 ms**，而不是干等 15 s。
（`test/accel.test.mjs` 第 9b 节就是这个场景的回归测试。）

### 8. 改完 hosts 一定要清 DNS 缓存

Windows 的 DNS 客户端缓存里 hosts 条目是**预载**的，实测 `github.com` 的 TTL 能到 **6.9 天**。
不清缓存的话「开关点了没反应 / 有时灵有时不灵」。现在每次改 hosts（开启、关闭、自修）
都会自动 `ipconfig /flushdns`。

### 9. hosts 看门狗：自己的块被改掉了会修回来

hosts 是**共享资源**：别的加速器会改它，安全软件会把它重置成默认值
（Windows Defender 的 `SettingsModifier:Win32/HostsFileHijack` 就会这么干），用户也会手工编辑。
我们那份块一旦没了，接管就静默失效 —— 表现成「有时候快有时候慢」。

后台每 90 s 校验一次：条目丢了就重写回去（连续失败 3 次就停手并报错）。
但**见到别人的接管块（`# Steam++ Start` 等）直接认输**，绝不和另一个加速器抢同一个文件。

### 10. 崩溃/强杀之后能自己恢复

- 写 hosts 前落盘**哨兵**（`~/.dsh/dsh-github-accel/active.json`：pid + 域名 + 时间）；
- 插件每次装载先 `repairIfStale()`：哨兵还在但进程已死 → 说明上次是异常退出 → 先撤干净；
- 进程**正常退出**时会同步撤掉 hosts 与 PAC（强杀时靠上面的启动自检）；
- **上次的开关状态会被记住**（`prefs.json`），DSH 重启后自动接回来；
- 应急一条命令：`node tools/recover.mjs`（不需要 DSH 在跑）。

### 11. 检测到别人在接管 hosts 就**认输**

如果 hosts 里出现 `# Steam++ Start` / `# Watt Toolkit Start` 之类的块，插件**拒绝争夺**，
并在 `status.lastError` 与体检里明确报告。绝不和另一个加速器抢同一个文件。

---

## 安装

```powershell
# 从本地源码目录装（插件没有构建步骤，源码直接可用）
dsh plugin --profile web add "F:\path\to\dsh-github-accel"

# 或者在你的 profile 目录里加 link 依赖（改源码即时生效）
#   ~/.dsh/profiles/web/package.json
#   "dependencies": { "dsh-github-accel": "link:C:/path/to/dsh-github-accel" }
```

重启 DSH 后，会话顶部栏右侧出现 GitHub 开关。

> **需要重启才生效。** 宿主半边是进程启动时加载的，改源码不会热更新。

---

## 快速开始

```powershell
# 1) 体检（只读，不改任何东西）
node tools\doctor.mjs

# 2) 点顶部栏右侧的 GitHub 开关；或直接打本地路由：
#    GET http://127.0.0.1:3080/dsh-github-accel/toggle?on=1&mode=both

# 3) 「GitHub 又不行了」时的两步
node tools\doctor.mjs          # 先看是哪条腿断了
node tools\recover.mjs         # 要彻底恢复原状（需要管理员权限）
```

### 工具一览

| 工具 | 作用 | 需要管理员 |
| --- | --- | --- |
| `tools/doctor.mjs` | 一屏体检：hosts / 代理 / PAC / 每个热域名的候选地址端到端结果 | 否 |
| `tools/bench.mjs` | 经隧道 vs 直连的 TLS 握手延迟对比（p50/p95），验收提速是否达标 | 否 |
| `tools/recover.mjs` | 应急还原：撤 hosts + 还原系统代理 + 删状态文件 | 是 |
| `tools/rewrite-hosts.mjs` | 不重启 DSH 就重写 hosts 接管块；**只写真的有监听的域名** | 是 |
| `tools/reset-hosts.mjs` | 只撤 hosts 块（`--restore` 用备份整体还原） | 是 |
| `tools/dev-proxy.mjs` | 跑一个只开代理的临时实例（`127.0.0.1:18998`），零风险 | 否 |
| `tools/live-check.mjs` | 看候选排序与冷却是否按预期工作 | 否 |
| `recon/probe*.mjs` | 只读勘察脚本：把「这台网络上 GitHub 各域名/各地址的真实现状」量出来 | 否 |

> 工具里的绝对路径一律可以用相对路径写 —— 上面的例子都假设当前目录就是插件根目录。
> （`node "C:\path\to\..."` 这种形式在 Windows 上对带空格的路径才必要。）

### 本地路由（浏览器半边用）

本宿主的 exact 路由对 POST 一律 405，所以三条都用 GET：

```
GET /dsh-github-accel/status
GET /dsh-github-accel/toggle?on=1&mode=both&pac=auto    # on=0 关闭并撤掉 hosts
GET /dsh-github-accel/diagnose
```

---

## 域名与地址分配

序号固定在 `server/domains.js`，**只往后追加，不插队**。

| # | 地址 | 域名 |
| --- | --- | --- |
| 0 | 127.0.0.2 | github.com |
| 1 | 127.0.0.3 | api.github.com |
| 2 | 127.0.0.4 | codeload.github.com |
| 3 | 127.0.0.5 | uploads.github.com |
| 4 | 127.0.0.6 | collector.github.com |
| 5 | 127.0.0.7 | alive.github.com |
| 6 | 127.0.0.8 | github.githubassets.com |
| 7 | 127.0.0.9 | avatars.githubusercontent.com |
| 8 | 127.0.0.10 | camo.githubusercontent.com |
| 9 | 127.0.0.11 | raw.githubusercontent.com |
| 10 | 127.0.0.12 | objects.githubusercontent.com |
| 11 | 127.0.0.13 | release-assets.githubusercontent.com |
| 12 | 127.0.0.14 | user-images.githubusercontent.com |
| 13 | 127.0.0.15 | pkg-containers.githubusercontent.com |
| 14 | 127.0.0.16 | gist.githubusercontent.com |
| 15 | 127.0.0.17 | npm.pkg.github.com |
| 16 | 127.0.0.18 | ghcr.io |

**默认不接管**：`github.io`、`pages.github.com`（用户自己的站点）、
`gist.github.com`（系统 DNS 实测返回 `2001::1` 这种明显污染值；只有运行时校验确实
找到可用地址时才接管，否则放它走直连快速失败）。

**显式 opt-in**（默认永远不接管）：`github.io`、`pages.github.com`。
那是用户自己的站点，「顺手接管」的风险不对等。要收它们得点名：

```powershell
$env:DSH_GITHUB_ACCEL_INCLUDE = 'github.io,pages.github.com'
```

---

## 环境变量

> **默认取向是「成功率优先，其次才是速度」。** 这条网络对 GitHub 的封锁是分钟级抖动的，
> 在这种对手面前「快」是靠不住的——1.2s 就把一个其实 1.6s 能连上的候选砍掉，
> 换来的只是「更快地失败」。浏览器自己会等 30s 以上，**10s 内成功严格优于 5s 内放弃**。
> 想换回速度优先，把下面的超时/预算调小即可。

| 变量 | 默认 | 作用 |
| --- | --- | --- |
| `DSH_GITHUB_ACCEL_AUTO_APP` | `0` | `1` = 自适应（github.com 直连健康就不接管）。默认总是接管 |
| `DSH_GITHUB_ACCEL_HIJACK_APP` | — | `1`/`0` 强制接管 / 不接管 github.com |
| `DSH_GITHUB_ACCEL_EXCLUDE` | — | 逗号分隔，永不接管的域名 |
| `DSH_GITHUB_ACCEL_INCLUDE` | — | 逗号分隔，**显式 opt-in** 的域名（目前只认 `github.io` / `pages.github.com`） |
| `DSH_GITHUB_ACCEL_IPS` | — | 手工钉住地址：`github.com=1.2.3.4,ghcr.io=...` |
| `DSH_GITHUB_ACCEL_DOH` | 空 | 可选 DoH 端点（只作为 DNS 明显被污染时的补充来源） |
| `DSH_GITHUB_ACCEL_POOL` | `1` | `0` 关闭预热池 |
| `DSH_GITHUB_ACCEL_POOL_KEEP` / `_TTL_MS` | `2` / `5000` | 预热池每个域名的条数与存活时间 |
| `DSH_GITHUB_ACCEL_RACE_WIDTH` | `6` | 同时竞速的候选数（靠铺开抢，而不是等超时逐个试） |
| `DSH_GITHUB_ACCEL_CONNECT_TIMEOUT_MS` | `3000` | 单个候选的连接超时 |
| `DSH_GITHUB_ACCEL_RACE_TOTAL_MS` | `8000` | 一轮竞速的总预算（要能扫完 12–16 个候选） |
| `DSH_GITHUB_ACCEL_STALL_MS` | `2500` | 上游多久不回一个字节就判定为黑洞（降权） |
| `DSH_GITHUB_ACCEL_FIRST_BYTE_MS` | `3000` | 上游多久不回第一个字节就**换一个上游并重放 ClientHello**（`0` 关掉） |
| `DSH_GITHUB_ACCEL_UPSTREAM_ATTEMPTS` | `2` | 一条客户端连接最多试几个上游 |
| `DSH_GITHUB_ACCEL_CONNECT_DEADLINE_MS` | `12000` | 一条客户端连接在上游侧的总预算 |
| `DSH_GITHUB_ACCEL_COOLDOWN_MS` / `_MAX_MS` | `15000` / `120000` | 坏地址冷却的基数与上限（调短 = 少把可能还活着的地址排除在外） |
| `DSH_GITHUB_ACCEL_HEALTH_MS` | `45000` | 后台端到端复检间隔 |
| `DSH_GITHUB_ACCEL_VALIDATE_WINDOW` | `6` | 每轮复检在候选表上滑动的窗口（见下） |
| `DSH_GITHUB_ACCEL_VALIDATE_TTL_MS` | `300000` | 「已验证」的有效期 |
| `DSH_GITHUB_ACCEL_WATCH_MS` | `60000` | 自适应模式下的直连复检间隔 |
| `DSH_GITHUB_ACCEL_PAC` | `auto` | `auto` / `on` / `off` |
| `DSH_GITHUB_ACCEL_LOOPBACK_PREFIX` | `127.0.0.` | 回环地址前缀（个别安全软件拦非 `.1` 回环时可改） |
| `DSH_GITHUB_ACCEL_VERBOSE` | — | `1` 打印每条隧道的目标 IP |

---

## 已知边界（老实说清楚）

1. **443 被别的程序占用**：`start()` 先用**连接探针**问「有没有人应答」（Windows 的
   `SO_REUSEADDR` 会让 bind 假成功），有人在服务就直接报 `port-taken` 并**不动 hosts** ——
   443 拿不到还写 hosts 会把全系统域名指到一个没有服务的地方，比不加速更糟。
2. **上游整体不可达时，谁也没办法**。实测 `20.205.243.166` 会阶段性对**所有** SNI
   timeout（不是按域名挑的），而它是 `github.com` 唯一的 A 记录。这时隧道会在
   4 s 内试完全部候选然后失败 —— 至少是**快速失败**而不是无限白等。
3. **HTTP/3 / Alt-Svc**：`github.githubassets.com` 会回
   `alt-svc: h3=":443";ma=86400`。走 hosts 时浏览器会往 `127.0.0.x:443/udp` 试一次 QUIC，
   本机没有 UDP 服务、内核立刻回 ICMP，代价很小；但它会**反复重试**（缓存 24 h）。
   想彻底关掉：Edge 策略 `QuicAllowed=0`（需重启浏览器）；或者切到 **P3 PAC 模式** ——
   RFC 7838 §2.4 明确规定「配置了代理的客户端不应该直连替代服务」。
4. **`github.io` 这张宽证书**：它和 `*.githubusercontent` / `github.com` 在同一个 SAN 组里。
   我们靠一域名一地址阻断复用；但**你自己**在浏览器里访问 `github.io` 站点时，
   它和别的 `github.io` 站点之间仍可能正常复用（那是 GitHub 的正常行为，不归我们管）。
5. **安全软件可能拦 hosts 写入**：Windows Defender 的
   `SettingsModifier:Win32/HostsFileHijack` 会拦写并把 hosts 重置成默认值（官方没有白名单）。
   写后读回校验能发现这种情况，但它会反复发生 —— 那种机器上请用 **P3 PAC** 模式。
6. **不要再试图用 DoH 绕 hosts**：Chromium 在 `ResolveLocally()` 里**同步**处理 HOSTS
   条目，Secure DNS 根本不会介入。所以「关掉浏览器的安全 DNS」是**没有必要**的。
7. 不写系统代理（除非你显式开 PAC）、不装证书、不改任何其它全局设置；
   **撤销 = 关开关**，或 `node tools/recover.mjs`。

---

## 测试

```powershell
node test/accel.test.mjs     # 核心机制 + B1/B2 两项回归（socket 泄漏 / 事件回调里抛异常）
node tools/bench.mjs         # 提速验收：隧道 p95 ≤ 直连 p95 + 100 ms、单次最大 ≤ 2 s
```

`test/accel.test.mjs` 里第 9、10 节是**回归测试**，对应 0.1 版本里两个真实事故：

- **B1 socket 泄漏**：客户端 `destroy()` 时走的是 `close` 而不是 `end`，
  `client.pipe(up)` 永远不会调用 `up.end()`，上游 socket 半开着留到进程结束。
  实测跑完 7 次 curl 之后 `status.connections` 停在 7 再也不归零，
  而 `trace` **永远是空的** —— 因为记 trace 的回调从来没跑过（诊断能力被一起废掉）。
- **B2 事件回调里抛异常 = DSH 直接死**：代理路径里引用了另一个作用域里的
  `clientClosed`，`ReferenceError` 从 `'error'` 回调里抛出去是**进程级未捕获异常**，
  而 DSH 的 `bin.js` 里没有 `uncaughtException` 处理器。
