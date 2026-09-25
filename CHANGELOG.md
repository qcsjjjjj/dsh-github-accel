# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 的写法，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [0.2.0] — 2026-09-25

这一版把「GitHub 时好时坏」这件事**查到了机制层面并逐个修掉**。全部结论都来自本机实测，
证据与推演过程见 [`docs/PLAN-2026-09-25.md`](docs/PLAN-2026-09-25.md)。

### 修复 — 崩溃与资源泄漏

- **代理路径的进程级崩溃**。`server/accel.js` 里 CONNECT 代理的 `up.on('error')`
  引用了另一个函数作用域里的 `clientClosed`，是 `ReferenceError`；从 `'error'`
  回调里抛出 = **进程级未捕获异常**，而 DSH 的入口没有 `uncaughtException` 处理器
  → **DSH 直接退出**，hosts 留在接管态，全系统 GitHub 变砖。
  现在连接状态一律放在每次连接独立的对象里，所有回调经过 `safe()` 包裹。
- **socket 永久泄漏**。客户端 `destroy()` 走的是 `'close'` 而不是 `'end'`，
  `client.pipe(up)` 永远不会调用 `up.end()`，上游 socket 半开着留到进程结束。
  实测跑完 7 次请求后连接计数停在 7 不再归零，而 `trace` **永远是空的**
  —— 因为记 trace 的 `'close'` 回调从来没跑过，诊断能力被一起废掉。
  现在双向管道「同生共死」：任何一侧 `close`/`error` 都 `destroy()` 另一侧。
- **`hosts` 的 trace 回调引用不到外层闭包**（与上面同一类错误），
  被 `try { hooks.onEnd?.() } catch {}` 静默吞掉。
  现在回调异常会通过 `onError('hook')` 上报，写进 `lastError` 与 `trace`。

### 修复 — 「坏地址永远不被换下去」（这是「时好时坏」最直接的机制）

- 坏地址的判据原本是 `bytesWritten === 0`，但隧道**总是**要先转发 ClientHello，
  所以这个条件**永远不成立**：候选表学不到任何东西，一个黑洞地址会一直坐在第一位，
  每次请求都先撞它一遍。
  现在改看**上游回了几个字节**：
  - 一个字节都没回就 RST → 硬失败，连续 2 次进冷却（30 s 起，指数退避到 5 min）；
  - 一个字节都没回、拖了 ≥1.5 s → **stall，一次即降权**（15 s 冷却）；
  - 已经传过字节才断（浏览器关页面）→ 软失败，不惩罚。

### 修复 — 工具/测试会污染真插件的持久状态（真实踩过）

- `prefs.json`（上次的开关）与 `active.json`（崩溃哨兵）属于「一个进程里只能有一个主人」
  的系统级共享资源。而 `test/`、`tools/doctor.mjs`、`tools/bench.mjs`、`tools/live-check.mjs`
  都会 `new Accelerator(...)` —— 它们随手一次 `stop()` 就会把真插件的
  `prefs.json` 写成 `enabled:false`、并删掉哨兵。
  **症状**：跑完一次测试之后，下次 DSH 重启加速器不会自动接回来（「重启一次就失效了」）。
- 现在 `Accelerator` 新增 `persistState`（**默认 false**），所有对
  `prefs.json` / `active.json` / 系统代理 / DNS 缓存的读写都走这道门闸；
  只有插件宿主 `lib/index.js` 显式传 `{ persistState: true }`。
- 新增回归断言：整轮测试跑完，真插件的状态目录必须**一个字节都没变**。

### 修复 — `github.io` / `pages.github.com` 会被「顺手接管」

- `DOMAIN_TABLE` 里 `optional: true` 曾经同时表达两件事：
  「校验通过就收」（`gist.github.com`）和「用户自己的站点，默认别动」
  （`github.io` / `pages.github.com`）。结果是后两个被自动收进了 hosts，
  与文档写的「默认不接管」矛盾。
- 现在拆成 `optional: 'auto'` 与 `optional: 'optin'`：只有 `gist.github.com` 是自动的；
  `github.io` / `pages.github.com` 必须 `DSH_GITHUB_ACCEL_INCLUDE` 点名才会进来。

### 新增 — 上游「连得上但一声不吭」时换一个并重放 ClientHello

- 这是这条网络上最恶心的失败模式：坏地址不报错、只是**不出声**，浏览器会干等到自己
  超时（15–30 s）。现在只要「ClientHello 已经转发出去、上游一个字节都没回、
  且超过 1.5 s」，就丢掉这条上游、换一个候选**把同一段 ClientHello 重放过去** ——
  对客户端完全透明（它还没收到任何字节）。
  实测：模拟黑洞上游下，客户端拿到好上游的回应只用 **405 ms**。
  可调：`DSH_GITHUB_ACCEL_FIRST_BYTE_MS` / `_UPSTREAM_ATTEMPTS` / `_CONNECT_DEADLINE_MS`。

### 新增 — 选路与提速

- **端到端校验**：不再「TCP 通就算好」，而是校验证书的 TLS 握手 + 真发一个 `HEAD /`
  + **按域名核对状态码**。实测同一个地址对 `Host: github.com` 回 403、
  对 `Host: codeload.github.com` 回 301 —— 判定必须按域名来。
- **happy-eyeballs 并行竞速**：同时向最多 3 个候选发起连接，先连上的赢。
  最坏情况从「串行 5×6 s」压到 4 s 预算。
- **预热池**：热域名常备空闲上游连接，客户端一连上就能立刻转发 ClientHello。
  实测隧道中位数比直连**快约 200 ms**。
- **EWMA 打分**：候选按实测延迟排序，不再是「按出现顺序」。

### 新增 — 覆盖更多域名（含 IPv6 黑洞）

- 接管域名从 7 个扩到 17 个，并**每个域名一个独立回环地址**（`127.0.0.2` … `127.0.0.18`）。
  一域名一地址让「HTTP/2 连接复用」的前提永远不成立，因此不再需要
  「哪些域名危险」的黑名单 —— 而那几个被排除的域名恰恰是页面最重的资源。
- 逐域名实测有 AAAA 且 4 条**全部 timeout** 的域名：
  `github.githubassets.com`、`avatars.githubusercontent.com`、`raw.githubusercontent.com`、
  `user-images.githubusercontent.com`、`pkg-containers.githubusercontent.com`。
  域名进 hosts 后 Windows 解析器会抑制 AAAA，等于顺手绕开 IPv6 黑洞。
- `github.io` / `pages.github.com` 默认**不接管**（用户自己的站点）。

### 新增 — 自愈与可观测性

- **哨兵 + 启动自修**：写 hosts 前落盘状态文件；插件每次装载先检查
  「哨兵还在、进程已死」的残局并清理。
- **退出撤接管**：正常退出时同步撤掉 hosts 与 PAC。
- **开关状态记忆**：DSH 重启后自动恢复上次的开关（并兼容没有 prefs 的老版本残留）。
- **多实例安全**：只有「这一轮由自己写进去的」才在退出时撤，避免第二个 DSH 实例
  把另一个实例正在用的 hosts 块删掉。
- **hosts 看门狗**：定期校验自己的块还在不在；见到**别人的**接管块（Steam++ 等）
  直接认输并报错，绝不争夺。
- **`ipconfig /flushdns`**：改完 hosts 自动刷新。Windows 的 DNS 客户端缓存里 hosts
  条目是预载的，实测 `github.com` 的 TTL 能到 **6.9 天** —— 不清缓存会表现成
  「开关点了没反应」。
- **诊断**：新增 `GET /dsh-github-accel/diagnose`、`tools/doctor.mjs`（一屏只读体检）、
  `tools/bench.mjs`（隧道 vs 直连的 p50/p95 验收台）；
  `status` 增加每条通路的死活、预热池命中率、每域名 p50/p95、真正的 `trace`。

### 新增 — 第三条通路（PAC）

- 本地 PAC 服务 + 用户级 `AutoConfigURL`，**不需要管理员权限**。
  默认策略 `auto`：只在 hosts 写入失败时才启用。
  它的价值是「不需要管理员」以及（按 RFC 7838 §2.4）避免浏览器绕开代理去试 HTTP/3。

### 变更

- `COALESCING_UNSAFE` 黑名单作废（一域名一地址已经从根本上阻断复用），保留常量仅供
  老测试与诊断读取，不再参与任何过滤决策。
- 域名地址按 `DOMAIN_TABLE` 的**固定序号**分配，增删域名不会让其它域名的地址平移。
- `tools/rewrite-hosts.mjs` 改成**只写真的有监听的域名**（多写一条就等于把那个域名
  指向一个没人服务的地址）。
- `package.json` 去掉 `private`，补 `license` / `repository` / `keywords`，
  peer 范围加上预发布分支（`^4.0.2 || >=4.0.3-rc.1 <5.0.0-0`），
  否则 harness 的预发布构建会被静默排除。

### 测试

- `node test/accel.test.mjs` —— 断言里包含针对上述事故的**回归测试**：
  socket 泄漏 / 事件回调里抛异常 / 黑洞地址降权 / 首字节看门狗换上游重放 /
  内部 handler-error。需要真网络的两项在上游不通时会明确报 SKIP，而不是误报失败。
- `node tools/bench.mjs` —— 提速验收：隧道 p95 ≤ 直连 p95 + 100 ms、单次最大 ≤ 2 s。

### 文档

- 新增 [`docs/PLAN-2026-09-25.md`](docs/PLAN-2026-09-25.md)：
  实测证据、与 Watt Toolkit（Steam++）逐项对比、目标架构、实施结果，以及**三处自我勘误**。
- 新增 [`docs/research-watt-toolkit.md`](docs/research-watt-toolkit.md)：
  Watt Toolkit 网络加速模块的源码级调研。
- 新增 [`docs/github-cn-instability-checklist.md`](docs/github-cn-instability-checklist.md)：
  「GitHub 在国内不稳」的根因清单与逐条验证方法。
- 新增 [`docs/PUBLISHING.md`](docs/PUBLISHING.md)：发布到 GitHub 与（将来）插件市场的流程。

## [0.1.0] — 2026-09-22

首个可用版本：hosts 接管 + `127.0.0.1:443` 上的 SNI 直通（不做 TLS 中间人）+
本地 CONNECT 代理；会话顶部栏右侧的开关；多候选地址与备用池。
