# Watt Toolkit（原 Steam++ / SteamTools）网络加速模块 · Windows 实现调研

> **证据基线（可复现）**
> - 源码：`https://github.com/BeyondDimension/SteamTools`，默认分支 `develop`，本次锁定 commit **d04213147e77a8d73277fa8b86eeecfa444df071**（2026-08-31，本次为本地浅克隆）。
> - 上游血缘：加速插件的反向代理几乎逐文件抄自 **FastGithub 2.1.4**（源码里每条文件头都留着 `// https://github.com/dotnetcore/FastGithub/blob/2.1.4/...`），并跟进了 FastGithub `58f79ddc…` 的 TLS 中间件版本。注意：`dotnetcore/FastGithub` 上游仓库现已 404（GitHub API 实测 `HTTP/1.1 404 Not Found`），所以**现在 Watt 仓库内的这份 fork 才是该实现的一手可查副本**。
> - 子模块（本次按 Watt 仓库锁定的 commit 拉取）：
>   - `ref/Common` = `818b673aba6a1c0b0e85616fea1fbbcffdea6469`（`TlsSniPattern`、`DomainPattern`）
>   - `ref/WTTS.MicroServices.ClientSDK` = `380d1ab71d835490e26398af0067a2672d9fb772`（`AccelerateProjectDTO`、`IDomainConfig`、API 路由）
> - **在线一手数据**：`POST https://api.steampp.net/accelerator/projectgroups` 无需鉴权即可返回加速项目表（实测 200，28,513 字节）。原始/展开数据已随本仓库保存：`docs/research-data/accelerator-projectgroups.json`、`docs/research-data/accelerator-flat.json`。
> - 可信度标注：**已证实**＝有源码/官方文档/RFC 原文或可复现实测；**推断**＝依据某处源码逻辑推导；**未找到证据**＝明确否认，不是"没查"。

---

## 1. 重定向层：hosts？系统代理？PAC？

**结论：Windows 上是"四选一的互斥模式"，不是并列同时启用；默认 Hosts 模式，hosts 全部指向单个 `127.0.0.1`（不是 127.0.0.x 多地址），PAC/系统代理另有独立模式。**

| 项 | 结论 | 可信度 |
|---|---|---|
| hosts 文件 | **是**。`ProxyMode.Hosts` 模式下由 `IHostsFileService.UpdateHosts()` 写 `%SystemRoot%\System32\drivers\etc\hosts` | 已证实（`Services.Implementation/Net/HostsFileServiceImpl.cs`；`WindowsPlatformServiceImpl.Net.Hosts.cs`） |
| 写入地址 | **单个回环地址 `127.0.0.1`**。代码：`var localhost = IPAddress.Any.Equals(proxyIp_.Value) ? IPAddress.Loopback.ToString() : proxyIp!;`；再对每个 `ListenDomainNames` 生成 `域名 -> 127.0.0.1` | 已证实（`Services/Mvvm/ProxyService.Operate.cs:250-265`） |
| 是否用 127.0.0.x | **否**（无 127.0.0.0/8 拆分逻辑）。已做交叉验证：全仓 `*.cs` grep `127\.0\.0\.[2-9]` **零命中**，`127.0.0.1` 命中 10 处。唯一例外：若服务端 `ListenDomainNames` 项里写成 `"IP 域名"`（空格分隔），则以该项自带 IP 为准 —— **这是"一域名一 IP"的钩子** | 已证实（同上 `host.Contains(' ')` 分支 + 全仓 grep）；表中当前无此类项 → 端点行为推断 |
| 系统代理（WinINET） | **是**，`ProxyMode.System`：`platformService.SetAsSystemProxyAsync(true, ip, port)`，Windows 上当绑定 `0.0.0.0` 时自动改为 `127.0.0.1` | 已证实（`ProxyService.Operate.cs:187-200`） |
| PAC | **是**，`ProxyMode.PAC`：`pacUrl = http://{ip}:{port}/pac` → `SetAsSystemPACProxyAsync(true, pacUrl)`；PAC 内容由服务端按域名表达式动态生成 `if (shExpMatch(host,'…')) return pac;` 否则 `DIRECT` | 已证实（`ProxyService.Operate.cs:202-214`；`HttpProxyPacMiddleware.cs`） |
| DNS 拦截 | **是（Windows 专有）**，`ProxyMode.DNSIntercept`：用 WinDivert 驱动在链路层改写 DNS 应答为 `127.0.0.1`/`::1`（见 §4） | 已证实（`PacketIntercept/DnsInterceptor.cs`） |
| 并列还是同时 | **互斥单选**。`ProxySettings.ProxyMode` 是一个枚举值；`ProxyModes`（Windows）= `Hosts, DNSIntercept, PAC, System`，非管理员可见项如上；`ProxyModeValue` 若取值不在列表内会回落 `ProxyModes[0]`。启动 switch 只走一个分支 | 已证实（`Settings/ProxySettings.ProxyMode.cs`、`Settings/Abstractions/IProxySettings.cs:266`、`ProxyService.Operate.cs:144-222`） |
| 默认值 | `DefaultProxyMode = ProxyMode.Hosts`；默认端口 `SystemProxyPortId = 26561`；默认代理 IP = `0.0.0.0`（Windows 上 System/PAC 模式会收敛为 127.0.0.1） | 已证实（`IProxySettings.cs:201-206, 266`） |
| 备注 | Hosts 模式下 443 端口被占用会直接拒绝启动并提示占用进程名/PID（`SocketHelper.GetProcessByTcpPort(443)`） | 已证实（`ProxyService.Operate.cs:149-185`） |

---

## 2. 本地监听：端口 / 地址 / 协议 / 是否 MITM

**结论：Hosts 模式监听 `0.0.0.0:443` 做 TLS 中间人（自签根证书 + 按 SNI 现签叶子证书）；System/PAC/VPN 模式监听 `0.0.0.0:26561` 做 HTTP 正向代理（支持 CONNECT 隧道）。做 MITM，但并非全域名：未匹配的域名走"泛化反代"，HTTP 代理里非 TLS 的 CONNECT 走裸隧道。**

| 项 | 细节 | 可信度 |
|---|---|---|
| 进程形态 | 反向代理是**独立子进程** `Steam++.Accelerator`（Kestrel + YARP），由主程序通过 IPC 拉起、通过 IPC 接收设置（`ReverseProxySettings` MemoryPack 序列化） | 已证实（`BD.WTTS.Client.Plugins.Accelerator.ReverseProxy/Program.cs`；`IReverseProxyService.Constants.cs:235-242`） |
| Hosts/DNSIntercept 监听 | `ListenHttpsReverseProxy()`：`options.Listen(ProxyIp, 443)`，`Protocols = Http1AndHttp2AndHttp3` | 已证实（`Extensions/KestrelServerOptionsExtensions.cs:116-136`；端口常量 `Models/Abstractions/IReverseProxyConfig.GlobalListener.cs:35-40`，取"≥443 的第一个可用端口"） |
| 附加 HTTP 监听 | Hosts 模式下若 `EnableHttpProxyToHttps=true`（默认 true）再听 **80** 端口，仅用于 301 到 https | 已证实（`KestrelServerOptionsExtensions.cs:100-109`；`HttpReverseProxyMiddleware.cs:118-122`） |
| System/PAC/VPN 监听 | `ListenHttpProxy()`：`options.Listen(ProxyIp, HttpProxyPort=26561)`，`Protocols = Http1AndHttp2AndHttp3`，管线 = `FlowAnalyze → HttpProxyMiddleware → UseTls → TunnelMiddleware` | 已证实（`KestrelServerOptionsExtensions.cs:25-51`） |
| HTTP 代理协议 | 自己实现 request-line/header 解析：CONNECT → 回 `HTTP/1.1 200 Connection Established` 后进隧道；普通绝对 URI → 转发 | 已证实（`HttpServer/Middleware/HttpProxyMiddleware.cs`） |
| TLS 直通（隧道） | `TunnelMiddleware`：仅当 `ProxyProtocol == TunnelProxy` **且** 该连接没有 `ITlsConnectionFeature`（即没被 MITM）时做裸 TCP 双向 copy | 已证实（`TunnelMiddleware.cs:34-56`） |
| 是否 MITM | **是**。`UseTls()` = `TlsInvadeMiddleware` → `UseHttps(TlsHandshakeCallbackOptions.OnConnection)` → `TlsRestoreMiddleware`；握手回调里 `ServerCertificate = certService.GetOrCreateServerCert(ctx.ClientHelloInfo.ServerName)` | 已证实（`Extensions/ListenOptionsExtensions.cs:40-57`） |
| 根证书 | 自签 CA：`C=CN, O=BeyondDimension, OU=Technical Department, CN=<RootCertificateName>`，装到 **`StoreName.Root, StoreLocation.LocalMachine`**（机器级受信任根，需要管理员）；有效天数 `CertificateConstants.CertificateValidDays`；到期有定时器重新信任并重启代理 | 已证实（`Services.Implementation/Certificate/CertificateManagerImpl.cs:100-117`；`CertGenerator.cs`；`YarpReverseProxyServiceImpl.cs:43-88`） |
| 叶子证书 | 每 SNI 现签：`CN=<domain>`，SAN = `<domain>` + `Environment.MachineName` + `127.0.0.1` + `::1`，有效期 1 年，`IMemoryCache` 缓存（`entry.SetAbsoluteExpiration(notAfter)`） | 已证实（`HttpServer/Certificates/CertService.cs:70-103`；`CertGenerator.CreateEndCertificate` 的 `dnsBuilder.Add(subjectName.Name[3..])`） |
| 哪些域名"直通" | **没有基于域名的 TLS 直通白名单**。443 监听器上凡是 TLS 连接一律先被解出明文（MITM），再按域名配置决定"反代 / 重定向 / 返回定制响应 / 直接失败"。未匹配域名但解析到本机 → `defaultDomainConfig`（`TlsSni=true`）泛化反代到原域名 | 已证实（`HttpReverseProxyMiddleware.cs:77-216`、`:201-215`） |
| SOCKS5 | **没有本地 SOCKS5 服务端**。`Socks5ProxyEnable/Socks5ProxyPortId(8868)` 只存在于设置与 IPC DTO，全仓 grep 只有"出站连 SOCKS4/5 上游代理"的实现 | 已证实（负结论：`ReverseProxy` 目录内 `Socks*` 全部命中为 `ExternalProxyType` 与二级代理出站握手） |
| Git/SSH 专用监听 | 代码存在（`ListenGitReverseProxy` 9418、`ListenSshReverseProxy` 22 + `GithubGitReverseProxyHandler`/`GithubSshReverseProxyHandler`），但**在启动处被注释掉**，当前版本不生效 | 已证实（`YarpReverseProxyServiceImpl.cs:192-193`） |
| 二级代理（出站） | 默认 `Socks5`，默认目标 `127.0.0.1:7890`，支持 Http/Socks4/Socks5 + 账号密码；可全局走，也可按"排除列表"直连 | 已证实（`IProxySettings.cs:236-261`；`Http/ReverseProxyHttpClientHandler.cs:69-250`） |

---

## 3. IP 选择：服务端给"最优 IP"吗？本地测速吗？粘滞/切换？TTL？

**结论：服务端不下发"测速后的最优 IP 列表"。它下发的是"域名 → 转发目标"表，其中转发目标**可以**是固定 IP（当前 GitHub 项就是固定 IP），也可以是中转域名。本地**不做延迟测速**（代理路径上的 `TestSpeedAsync()` 直接 `throw new NotImplementedException()`），只用 DoH 解析结果**按序尝试、每 IP 10 秒超时、谁先连通用谁**，属于"失败切换"而非"最优选择"。**

| 问题 | 结论 | 可信度 |
|---|---|---|
| 是否有自家测速接口下发最优 IP | **未找到证据**。`IAccelerateClient` 只有 `All()`（`POST accelerator/projectgroups`）与 `GetMyIP()`；`GetMyIP` 的现行实现是直接请求第三方 `https://v4.ipip.net` / `https://v6.ipip.net`（超时 7.75 s），且只用于判断本机是否具备 IPv6 | 已证实（`WTTS.MicroServices.ClientSDK@380d1ab/src/BD.WTTS.MicroServices.ClientSDK/Services/Implementation/MicroServiceClientBase.Clients.cs`） |
| 服务端下发的字段 | `Name / Port / MatchDomainNames / ForwardDomainNames / IgnoreSSLCertVerification / FakeServerName / ProxyType / ListenDomainNames / FakeUserAgent / Items`（子项）/ `Version` | 已证实（`AccelerateProjectDTO.cs`；live API 实测返回同名字段） |
| 固定 IP 从哪来 | `ForwardDomainNames`：`ProxyType.Local` 且该值是 IP → `IDomainConfig.IPAddress`（连接时优先用它）；不是 IP → `IDomainConfig.ForwardDestination`（改连这个域名，Host/SNI 保持原样） | 已证实（`.../Models/Accelerator/Yarp.Configuration/DomainConfig.cs:134-197`） |
| 当前 GitHub 项的固定 IP（2026-09-25 实测 API） | `github.com → 20.207.73.82`；`github.io → 185.199.110.153`；`raw/camo/avatars/user-images/objects.githubusercontent.com → 23.235.37.133`；`github.dev → 20.43.185.14`；`githubapp.com → 140.82.112.29`；其余（api/assets/education）走 `*.rmbgame.net` 中转域名 | 已证实（`docs/research-data/accelerator-flat.json`） |
| 本地延迟测速（代理路径） | **无**。`DomainResolver.TestSpeedAsync()` → `throw new NotImplementedException()` | 已证实（`Services.Implementation/DomainResolver.cs:52-55`） |
| 本地延迟测速（UI 路径） | 有，但只在"网络检查"里用：`INetworkTestService` 提供 Ping / UDP DNS / DoH / 打开 URL / 上传 / 下载测速 / STUN(RFC3489/5389)，用于排查网络环境，不参与选 IP | 已证实（`Services/INetworkTestService.cs`；`UI/ViewModels/NetworkCheckControlViewModel.cs:167,196-197`） |
| 连接时的选择算法 | `ConnectCallback`：把 `GetIPEndPointsAsync()` 产出的 IP 逐个试连（顺序 = 配置固定 IP → 转发域名解析结果 → 本域名 DoH 解析结果），单个 IP 超时 **10 s**，全失败抛 `AggregateException("Could not find any IP that can be successfully connected.")` | 已证实（`Http/ReverseProxyHttpClientHandler.cs:258-289, 344-370`） |
| "粘滞 / 记忆最优 IP" | **无显式实现**（没有 best-IP 记录文件/字段）。粘滞效果来自两处：DoH 缓存 TTL 9.9 分钟 + 每域名独立连接池（见 §6）复用 TCP/TLS 连接 | 已证实（负结论）+ 推断（粘滞来源） |
| 失败切换 | **有**，逐 IP 重试（含超时回退）；另有 YARP 层错误原样回写给客户端 | 已证实 |
| 缓存 TTL | DoH 解析缓存 `TimeSpan.FromMinutes(9.9)`（key = DoH 地址 + 域名 + 查询类型）；DNS 拦截模式伪造应答的 TTL = 5 分钟；`domainConfigCache`（域名→配置）无过期 | 已证实（`Net/DnsDohAnalysisService.cs:16,97,175-204`；`PacketIntercept/DnsInterceptor.cs:20`；`Models/ReverseProxyConfig.cs:10,157-166`） |
| 服务端加速（`ProxyType.ServerAccelerate`） | 存在：加 `X-Watt-Token` + `X-Watt-Origin-Dest-*` 头，优先 HTTP/3 转发到 Watt 自家服务端（token 由 `GenerateServerSideProxyToken` 换取，5 s 超时，进程内缓存）。启动时会为这类项目预取 token | 已证实（`HttpReverseProxyMiddleware.cs:141-149, 473-480`；`ProxyService.Operate.cs:77-78, 402-429`） |

---

## 4. DNS：怎么绕污染？DoH？内置 DNS 服务器？

| 问题 | 结论 | 可信度 |
|---|---|---|
| 用 DoH 吗 | **默认开**（`DefaultUseDoh = true`）。候选 10 个：`dns.pub`、`1.12.12.12`、`120.53.53.53`、`dns.alidns.com`、`223.5.5.5`、`223.6.6.6`、`dns.google`、`cloudflare-dns.com`、`doh.360.cn`、`101.6.6.6:8443`（默认落到 `https://doh.pub/resolve`） | 已证实（`IProxySettings.cs:281`；`UI/ViewModels/ProxySettingsWindowViewModel.cs:34-46`；`Net/DnsDohAnalysisService.cs:27`） |
| 非 DoH 路径 | 用 `ProxyMasterDns`（默认 `223.5.5.5`）走 UDP/53（DnsClient.NET），也支持 `"System Default"` | 已证实（`IProxySettings.cs:216`；`Net/DnsAnalysisServiceImpl.cs`） |
| 启动前 DNS 健康检查 | **有**（`ProxyBeforeDNSCheck` 默认 true）：对全部候选 DoH/DNS **并发**测试域名 `dnscheck-test.steampp.net`，取最先成功的那个作为本次加速的 DoH 地址 | 已证实（`ProxyService.Operate.cs:80-90, 485-548`） |
| 为何能绕污染 | DoH 请求本身走 TCP/443 到已知 IP 的 DoH 端点（`UseProxy=false`、`HttpNoProxy`，避免自环），结果直接用于连接；Hosts 模式下解析明确改用 **Dnspod** 而不是系统 DNS，注释写明"hosts 加速下不能用系统默认 DNS，否则会解析到 hosts/拦截器上无限循环" | 已证实（`Services.Implementation/DomainResolver.cs:25-35`；`DnsDohAnalysisService.GetDnsHttpClient`） |
| 内置 DNS 服务器 | **没有**：不监听 53/UDP。但有"DNS 拦截"模式：WinDivert 过滤 `udp.DstPort == 53`，把命中加速表域名的 **A 应答改写成 127.0.0.1、AAAA 改写成 ::1（TTL 5 分钟）**，改包后 `Impostor=true` 原地回注，并调用 `dnsapi!DnsFlushResolverCache` 刷缓存；退出时 `sc stop WinDivert1.4` | 已证实（`PacketIntercept/DnsInterceptor.cs`；`Models/Abstractions/IReverseProxyConfig.GlobalListener.cs`） |
| IPv6 | 先探测本机 IPv6（`Accelerate.GetMyIP(ipV6:true)`）；解析时 AAAA 为空会自动回落 A 记录；`isIPv6` 由 DNS 层探测（对 `ipv6.rmbgame.net` 查 AAAA 是否等于 `2400:3200::1`） | 已证实（`ProxyService.cs:779-785`；`Net/DnsDohAnalysisService.cs:191-195`；`Net/DnsAnalysisServiceImpl.cs:114-142`） |

---

## 5. SNI 解析：ClientHello 跨 TCP 分段怎么处理？有没有"累积到完整 record"？

| 问题 | 结论 | 可信度 |
|---|---|---|
| 是否自研 ClientHello 解析器 | **没有**。全仓（`src` 全量 grep `ClientHello`）只有一处命中：`certService.GetOrCreateServerCert(ctx.ClientHelloInfo.ServerName)` —— 用的是 ASP.NET Core Kestrel 的 `TlsHandshakeCallbackOptions.OnConnection`，SNI 由框架/SslStream 抽出 | 已证实（`Extensions/ListenOptionsExtensions.cs:44-54`） |
| 有没有"累积到完整 TLS record 再解析"的实现 | **未找到证据**。没有 record 长度累加、没有 `0x16 0x03 0x01 + length` 的读整包逻辑 | 已证实（负结论） |
| 唯一的裸字节嗅探 | `TlsInvadeMiddleware.IsTlsConnectionAsync`：`ReadAtLeastAsync(2)` 只看首两字节是否 `0x16 0x03`，随后 `Input.AdvanceTo(result.Buffer.Start)` **把数据原样退回**，不消费、不假设整条记录已在缓冲区内。判断结果只用于"非 TLS 时塞一个假 `ITlsConnectionFeature`，逼 `UseHttps` 跳过握手" | 已证实（`HttpServer/Middleware/TlsInvadeMiddleware.cs:37-59`；`TlsRestoreMiddleware.cs`；`FakeTlsConnectionFeature.cs`） |
| 因此跨 TCP 分段怎么办 | 由 `SslStream`/Kestrel 以"流"语义重组（TLS 本就是流式记录层，分段不影响 SNI 提取）。**这是框架属性，不是 Watt 的实现**，本仓库无相关处理/兼容代码 | 推断（依据：上述代码路径 + .NET `SslStream` 语义；未在任何一手文档中找到针对该 fork 的显式说明） |
| 附带的 SNI 伪造能力 | `TlsSniPattern` 支持 `@domain` / `@ipaddress` / `@random` 模板，由服务端 `FakeServerName` 提供；`GetTlsSniPattern()`：`TlsSni==false → None`，未配模板 → `@domain`，配了 → 按模板展开。出站连接实际用 `WithDomain(host).WithRandom()`，连 IP 时再 `.WithIPAddress(ip)`（即可以把真实 IP 拼进 SNI） | 已证实（`Common@818b673/src/BD.Common/Net/TlsSniPattern.cs`；`DomainConfig.cs:111-131`；`ReverseProxyHttpClientHandler.cs:34, 309`） |
| 当前表里的 SNI 伪装 | 仅 `Github UserContent` 项配了 `FakeServerName = "Github"`，其余 GitHub 项为空（= 用真实 SNI） | 已证实（live API） |

---

## 6. 连接预热 / 池化

| 项 | 结论 | 可信度 |
|---|---|---|
| 预连接 / 预热 | **无**。`grep -i "preconnect\|warm\|预热\|预连接"` 全仓 0 命中 | 已证实（负结论） |
| 连接池粒度 | **每个 (域名, 域名配置) 一个 `SocketsHttpHandler`**：`ReverseProxyHttpClientFactory.CreateHttpClient(domain, domainConfig)` → `LifeTimeKey(domain, domainConfig)` → `ConcurrentDictionary` 缓存 `Lazy<LifetimeHttpHandler>`；`HttpReverseProxyMiddleware` 用 `httpClientFactory.CreateHttpClient(context.Request.Host.Host, domainConfig)` 逐域名取客户端 | 已证实（`Services.Implementation/ReverseProxyHttpClientFactory.cs:48-56`；`Http/LifeTimeKey.cs`；`HttpReverseProxyMiddleware.cs:133`） |
| 连接复用 | 由 `SocketsHttpHandler` 池化（HTTP/1.1 keep-alive、HTTP/2 多路复用），`EnableMultipleHttp2Connections = true`、`EnableMultipleHttp3Connections = true`；`NoProxy`、`AllowAutoRedirect=false`、`AutomaticDecompression=None` | 已证实（`Http/ReverseProxyHttpClientHandler.cs:54-67`） |
| handler 生命周期 | **首次 10 s，之后每次 100 s** 轮换：到时把旧 handler 交给 `LifetimeHttpHandlerCleaner`，字典里换成新的 `Lazy<>`；旧 handler 只有在其 `WeakReference` 已死（无在途请求）时才真正 `Dispose`，清理循环间隔 10 s | 已证实（`ReverseProxyHttpClientFactory.cs:16-69`；`Http/LifetimeHttpHandler.cs`；`Http/LifetimeHttpHandlerCleaner.cs`） |
| Kestrel 侧 | `NoLimit()`（取消 `MaxRequestBodySize` / 最小请求响应速率限制）、`UseShutdownTimeout(1s)`、`AddServerHeader=false`、`BackgroundServiceExceptionBehavior.Ignore` | 已证实（`Extensions/KestrelServerOptionsExtensions.cs:13-18`；`YarpReverseProxyServiceImpl.cs:174-180`；`YarpReverseProxyServiceImpl.Startup.cs:13-18`） |
| 流量统计 | `FlowAnalyze` 中间件包裹 `context.Transport` 计数（UI 的上行/下行曲线） | 已证实（`FlowAnalyze/*.cs`；`IReverseProxyService.Constants` 的 `GetFlowStatistics_Bytes`） |

---

## 7. GitHub 域名清单 + HTTP/2 连接复用（coalescing）问题

### 7.1 清单：来自**服务端下发**（不在仓库里）

仓库里**没有** GitHub 域名表——`MatchDomainNames/ListenDomainNames/ForwardDomainNames` 全部来自 `POST https://api.steampp.net/accelerator/projectgroups`（`IMicroServiceClient.Instance.Accelerate.All()`，`isAnonymous:false` 但实测匿名也能取到）。下表是 2026-09-25 实测抓取（原始 JSON 见 `docs/research-data/accelerator-projectgroups.json`）：

| 加速项 | MatchDomainNames | 写入 hosts 的 ListenDomainNames | 转发目标 ForwardDomainNames | SNI 伪装 | 忽略证书校验 |
|---|---|---|---|---|---|
| Github 网站 (Git Push) | `github.com;pages.github.com;gist.github.com` | 同左 | **20.207.73.82** | — | true |
| Github UserContent | `githubusercontent.com;raw.github.com` | `raw.github.com;githubusercontent.com;raw.githubusercontent.com;camo.githubusercontent.com;cloud.githubusercontent.com;avatars.githubusercontent.com;avatars0/1/2/3.githubusercontent.com;user-images.githubusercontent.com;objects.githubusercontent.com;private-user-images.githubusercontent.com` | **23.235.37.133** | `Github` | true |
| Github Api | `api.github.com` | 同左 | `githubapi.rmbgame.net`（中转域名） | — | true |
| Github Assets | `github.githubassets.com;support-assets.githubassets.com;` | 同左 | `githubdocs.rmbgame.net` | — | true |
| Github Education | `education.github.com` | 同左 | `educationgithub.rmbgame.net` | — | true |
| Github Dev | `github.dev` | 同左 | **20.43.185.14** | — | true |
| Github App | `githubapp.com` | `githubapp.com;` | **140.82.112.29** | — | true |
| Github.io | `github.io;*.github.io` | `github.io;www.github.io` | **185.199.110.153** | — | true |
| Github Resources / Uploads / Archiveprogram | `resources.github.com` / `uploads.github.com` / `archiveprogram.github.com` | 同左 | 同名（= 直连原域名，仅换 DNS 解析路径） | — | true |
| （同组附带） | `hub.docker.com`、`greasyfork.org;update.greasyfork.org` | — | — | — | — |

> 注：`MatchDomainNames` 是**前缀锚定**表达式（`^{pattern}`，`*`→`[^\.]*`，`;` 分隔，`/` 开头则为正则），所以它既能按域名也能按 **URL 前缀**匹配（表里 Steam 项就有 `https://steamcommunity.com/comment` 这种）。因此 `githubusercontent.com` 这条**不会**直接匹配 `raw.githubusercontent.com`——后者靠 hosts 映射进本机后落入 `defaultDomainConfig` 泛化反代（或靠 `MatchDomainNames` 之外的其它项）处理。可信度：匹配语义已证实（`Common@818b673/src/BD.Common/Net/DomainPattern.cs`），"raw.githubusercontent.com 实际走哪条分支"为推断。

同样存在的加速项目（同表）：Steam 系列、Twitch、Origin、Uplay、公共 CDN（fonts.googleapis 等）、验证码（recaptcha/hCaptcha/arkoselabs）、Nexus Mods/Fandom、网盘（OneDrive/MEGA/Dropbox）、Pinterest/Artstation/Imgur/vercel/appcenter。

### 7.2 它怎么避免 HTTP/2 connection coalescing 串域名

**三层机制，且第一层是"天然免疫"：**

1. **本地 MITM 证书按域名逐张签发**（`CertService.GetOrCreateServerCert(SNI)`，SAN 只含该域名 + 本机名 + 两个回环 IP）。按 RFC 9113 §9.1.1，连接复用要求服务器证书对目标源有效；证书不覆盖第二个域名 → 浏览器**不能**把 `raw.githubusercontent.com` 的请求塞进 `github.com` 的那条连接。这比"一域名一 IP"更强：即使两个域名解析到同一 IP 也不会合并。可信度：证书逻辑**已证实**（`CertService.cs:70-103`）；"浏览器因此不合并"为**已证实**（RFC 9113 §9.1.1 + §10.1 Server Authority：`https://www.rfc-editor.org/rfc/rfc9113.html#section-9.1.1`）。
2. **上游连接池按域名隔离**：每个域名一个 `SocketsHttpHandler`（§6），因此中枢侧也不会把 A 域名的请求复用 B 域名的上游连接。
3. **上游证书校验允许"同证书不同名"但要求 SAN 覆盖**：当出现 `RemoteCertificateNameMismatch` 时，若 `TlsIgnoreNameMismatch` 为真直接放行，否则读取证书 SAN 与请求域名做匹配（支持 `*` 通配）。当前 GitHub 项全部 `IgnoreSSLCertVerification=true`（因为它们刻意连固定 IP / 中转域名）。可信度：已证实（`ReverseProxyHttpClientHandler.cs:320-335, 377-440`）。

另外两条相关设计：`ProxyType.Redirect` 用 `ForwardDomainNames + Port` 拼新 URL 做 302；`ProxyType.ServerAccelerate` 走 Watt 自家服务端代理（`X-Watt-Origin-Dest-*` 头 + HTTP/3），此时"上游 IP 选择"完全交给服务端。

---

## 8. 失败与回滚：hosts 怎么恢复？有看门狗吗？

| 机制 | 细节 | 可信度 |
|---|---|---|
| hosts 分段标记 | `# Steam++ Start` … `# Steam++ End`（当前生效区），`# Steam++ Backup Start` … `# Steam++ Backup End`（被覆盖的**原始行**，逐行以 `#{原行号} {原行内容}` 注释形式备份） | 已证实（`HostsFileServiceImpl.cs:129-132, 556-576`） |
| 恢复方式 | `RemoveHostsByTag()`：删掉生效区并把备份区原行插回**原行号位置**（`stringBuilder.GetLineIndex(line_num-1)`），再删备份区 → 用户原本的 hosts 内容逐行还原 | 已证实（同上 `Restore()`/`is_restore` 分支） |
| 正常退出 | 插件 `OnExit()` → `ProxyService.ExitAsync()` → `StopProxyServiceAsync(isExit:true)`：**先清 hosts 再停反代**（顺序在代码里显式注释"先停止接入代理流量"）；退出路径下清 hosts 失败不阻塞停止流程（避免留下"半开"状态） | 已证实（`Plugins/Plugin.cs:167-178`；`ProxyService.cs:814-820`；`ProxyService.Operate.cs:339-365`） |
| 系统代理/PAC 回滚 | 非管理员进程退出时**跳过**回滚（`callSet=false`），交给管理员进程退出时统一清（`WindowsPlatformServiceImpl.IDisposable` 里 `SetAsSystemProxyAsync(false)` / `SetAsSystemPACProxyAsync(false)`） | 已证实（`ProxyService.Operate.cs:331-338`；`WindowsPlatformServiceImpl.IDisposable.cs:20-34`） |
| 崩溃 | **没有**崩溃自动还 hosts：加速插件未覆写 `OnUnhandledException`（全仓只有 `PluginBase`/`PluginsCore` 的空实现）。崩溃后 hosts 里会残留 `# Steam++ Start/End` 段，直到用户下次"停止加速/网络修复" | 已证实（`Startup.GlobalExceptionHandler.cs:117-136`；`PluginBase.cs:58-61`；grep `OnUnhandledException` 无 Accelerator 覆写） |
| 看门狗 | **有**：提权进程用 `FileSystemWatcher` 监视 hosts（`Changed`/`Deleted`），被外部改动/删除后重新写回；防抖：2.65 s 内重复触发会取消上一次并随机延迟 550–850 ms 再写，避免与别的程序打架 | 已证实（`HostsFileServiceImpl.cs:19-125`） |
| 其它自愈 | ① 标记区重复（`Code_CommunityFix_Hosts_MarkDuplicate_`）→ 先把 hosts 备份成 `hosts.spp.bak`，再重置为默认 hosts 后重写；② hosts 不存在 → 写回微软默认模板内容；③ 只读属性 → 临时 `IsReadOnly=false`，写完恢复；④ 文件 >50 MB 直接拒绝操作；⑤ 读文件 `IOException` → 提示"读取 hosts 失败" | 已证实（`HostsFileServiceImpl.cs:174-278, 360-376, 884-896`；`WindowsPlatformServiceImpl.Net.Hosts.cs`） |
| 网络修复按钮（FixNetwork） | 还 hosts + 关系统代理 + 关 PAC + `netsh winsock reset` | 已证实（`ProxyService.cs:752-777`） |
| 证书到期 | 根证书到期时间触发 `System.Timers.Timer` → 重新 `CheckRootCertificate` → `StopProxyAsync()` + `StartProxyImpl()` 重启 | 已证实（`YarpReverseProxyServiceImpl.cs:43-88`） |

---

## 9. 社区里「GitHub 访问不稳」的常见根因 + 验证 + 缓解

> 与 Watt 的取舍对照看：Watt 的方案恰好覆盖了下面 1/2/3/6/7 五条。
> **查 DNS 前必读**：`Resolve-DnsName github.com -Type A` 会**先读 hosts**，看到的是 hosts 里的回环地址（假象）；必须加 **`-DnsOnly`** 才是真实 DNS 应答（实测：不带 → `127.0.0.2`，带 → `20.205.243.166`）。另一个坑：Windows 的 `Resolve-DnsName -Type` 与 `nslookup -type=` **都不支持 `HTTPS` 记录类型**（枚举里没有），查 HTTPS RR 只能用 `edge://net-internals/#dns` 或带 HTTPS 支持的 `dig`。已证实（[Resolve-DnsName](https://learn.microsoft.com/en-us/powershell/module/dnsclient/resolve-dnsname) + 实测）

| # | 根因 | 为什么会导致不稳 | 验证方法（Windows） | 缓解手段 | 可信度 |
|---|---|---|---|---|---|
| 1 | **DNS 污染 / 投毒**（github.com、raw.githubusercontent.com 被解析到错误/黑洞 IP） | 解析结果不可用 → 连接超时或连到错误主机 | **`Resolve-DnsName github.com -Type A -DnsOnly`**（`-DnsOnly` 跳过 hosts 与缓存直查解析器）；`nslookup raw.githubusercontent.com 8.8.8.8`；DoH 对照：`Invoke-RestMethod "https://doh.pub/dns-query?name=github.com&type=A"`（JSON Answer）或 `curl "https://dns.alidns.com/resolve?name=…&type=A"`；看是否返回 0.0.0.0/回环/保留地址 | 换 DoH/可信 DNS、hosts 固定可用 IP、DoH 客户端（Watt 就是启动前并发测 DoH 取最快） | 机制**已证实**（FOCI'14 摘要原文："…by injecting forged DNS replies or **TCP resets**"——[usenix.org](https://www.usenix.org/conference/foci14/workshop-program/presentation/anonymous)）；Watt 的应对**已证实**（`HttpReverseProxyMiddleware.cs:103-110, 207-214`） |
| 2 | **单 A 记录 / 单 IP 无冗余** | 一个 IP 被限速或路由劣化时全站受影响 | `Resolve-DnsName github.com -Type A -DnsOnly -Server 223.5.5.5`（看条数；**实测 `github.com` 只有 1 条 `20.205.243.166`**，`codeload.github.com` 同样只有 1 条）；多记录只出现在 Fastly 段：`raw/objects.githubusercontent.com` → `185.199.108-111.133`（4 条） | 多 IP 轮询/失败切换（Watt：逐 IP 试连、每 IP 10 s 超时）；**别指望 DNS 层故障转移**，pin IP 需定期核对（Fastly 段会变） | 已证实（上述 A 记录条数为实测；Watt 侧 `ReverseProxyHttpClientHandler.ConnectCallback`）。"单条记录是大路不稳主因"为**推断**；"GitHub 官方 DNS 事故导致"**未找到证据**（近两月 50 条 incident 中 DNS 命中 0）。参考 [RFC 2181 §5.1](https://www.rfc-editor.org/rfc/rfc2181.txt) |
| 3 | **TLS ClientHello 被 SNI 阻断 / MTU 分片问题** | 机制已证实：**GFW 先放行 TCP 三次握手，收到含被封 SNI 的 ClientHello 后向两端注入 RST**；且该三元组在约 60–180 秒内任何包都会再触发 RST（"残留封锁"） | **Wireshark**：`tcp.flags.reset == 1`（比对 RST 的 TTL/`ip.id` 判断是否为中间人注入）、`tls.handshake.extensions_server_name`、`icmp.type == 3 && icmp.code == 4`（PMTUD 黑洞）；`curl -v https://github.com` 看建连后是否立刻 RST；`ping -f -l 1472 <host>` 复现 PMTUD 黑洞 | **ClientHello 分片**：GoodbyeDPI / zapret / GreenTunnel（分片、乱序、按 SNI 位置切分）；**MTU**：`netsh interface ipv4 set subinterface "WLAN" mtu=1400 store=persistent`；或改用支持 SNI 伪装的代理（Watt：`TlsSniPattern` 支持 `@domain/@ipaddress/@random`） | **SNI-RST 机制：已证实**（[FOCI'19 Chai et al.](https://www.usenix.org/system/files/foci19-paper_chai_update.pdf)、[net4people/bbs#43](https://github.com/net4people/bbs/issues/43)、[USENIX Sec'23 Wu](https://www.usenix.org/conference/usenixsecurity23/presentation/wu-mingshi)、[USENIX Sec'25 Zohaib](https://www.usenix.org/conference/usenixsecurity25/presentation/zohaib)、[NDSS DNS-Privacy'21](https://www.ndss-symposium.org/wp-content/uploads/dnspriv21-02-paper.pdf)；工具仓库 [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI)、[zapret](https://github.com/bol-van/zapret)、[GreenTunnel](https://github.com/SadeghHayeri/GreenTunnel)）；**MTU/PMTUD 黑洞机制：已证实**（[RFC 1191](https://www.rfc-editor.org/rfc/rfc1191.html)、[RFC 2923](https://www.rfc-editor.org/rfc/rfc2923)、[RFC 4821](https://www.rfc-editor.org/rfc/rfc4821)、[RFC 8899](https://www.rfc-editor.org/rfc/rfc8899)）；**"GitHub 不稳由此导致"仍是推断**（本机 WLAN MTU=1500 且 `ping -f -l 1472` 有回复，未复现）。Watt 侧应对能力**已证实**（`TlsSniPattern.cs`、live API 表） |
| 4 | **IPv6 黑洞**（有 AAAA 记录但 v6 不通） | 浏览器优先 v6 → 每次连接先等超时再回落 v4 | `Resolve-DnsName <域名> -Type AAAA -DnsOnly`；`Get-NetIPAddress -AddressFamily IPv6`（看是否有**全局**地址而非仅 `fe80::`）；`netsh interface ipv6 show prefixpolicies`（Windows 默认 `::/0`=40 > `::ffff:0:0/96`=35，即 v6 优先）；`curl -6` vs `curl -4` 对比 | **微软建议用前缀策略而非整体禁用**；如需强制 v4：`DisabledComponents` = `0x20`(32) 表示 *Prefer IPv4 over IPv6*，`0xFF`(255) 完全禁用（改注册表后重启） | **范围限定（重要实测）**：`raw.githubusercontent.com` 有 4 条 AAAA（`2606:50c0:8000-8003::154`），而 **`github.com`、`github.io`、`objects.githubusercontent.com`、`codeload.github.com` 完全没有 AAAA** → 该根因**只能解释 raw 这一个域**，不能用来解释 github.com 网页不稳。**诊断陷阱**：`ping -6 github.com` 失败**不能**作为 v6 黑洞证据（它根本没有 AAAA），必须用 `raw.githubusercontent.com` 做对照。已证实（实测 + [RFC 6724](https://www.rfc-editor.org/rfc/rfc6724.txt) + [MS：Configure IPv6](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-ipv6-in-windows)）；Watt 侧 AAAA 空回落 A **已证实**（`DnsDohAnalysisService.cs:191-195`） |
| 5 | **Chrome/Edge Secure DNS（DoH）"绕过 hosts"** | 直觉上认为 hosts 会被 DoH 覆盖 | `chrome://net-internals/#dns` 看解析来源；开/关 Secure DNS 分别测同一 hosts 生效域名（实测：hosts 指回环后开关 DoH 都失败） | **与 DoH 无关，不必关**；修正 hosts 即可 | **该说法已证伪**：Chromium 任务序列为 **缓存 → HOSTS → DoH/系统**，`out_tasks->push_back(TaskType::HOSTS)` 无条件执行且在 DNS 任务之前，hosts 命中即**根本不发 DoH 查询**。已证实（[Chromium `net/dns/host_resolver_manager.cc`](https://github.com/chromium/chromium/blob/ee7ef8016281439932a81bdac80a66f9a31efb62/net/dns/host_resolver_manager.cc) + 本机源码 `net/dns/host_resolver_manager_job.cc` 的 `ServeFromHosts()`/"handled synchronously in ResolveLocally()" + 实测）。会真正绕过 hosts 的是：尾点域名、浏览器/系统缓存（`ipconfig /flushdns` + 重启浏览器）、ECH/HTTPS RR、以及 #7 的 QUIC 直连 |
| 6 | **HTTP/2 connection coalescing 串域名** | 三个前提**同时**满足才发生：同 IP + 证书覆盖目标域名 + 双方都是 h2；一挂全挂。**纠错**：常见的"hosts 只改 github.com，导致 github.io 被复用到错 IP"**不成立**——`github.com` 证书 SAN 仅 `github.com`/`www.github.com` 且两域 IP 不同，`SpdySession::CanPool()` 的证书校验直接不通过。真正有风险的是**宽证书段**（如 `github.io` 那张 + `185.199.108.0/22` 同段域名） | `edge://net-export/` 抓包后用 netlog viewer 看 HTTP/2 session 的 `IPEndPoint`；DevTools → Network → Connection ID。**注意 `chrome://net-internals/#http2` 在新版 Edge/Chrome 已被移除**（跳 `#events`），别再照旧写法 | 一域名一 IP、或让各域名证书互不覆盖（Watt：本地 MITM 逐域名签证书，天然阻断；同时上游每域名独立连接池）。**没有**单独关 coalescing 的开关；`--disable-http2` 或走代理（pooling 对代理不生效）可规避 | 机制**已证实**：[RFC 9113 §9.1.1 Connection Reuse](https://www.rfc-editor.org/rfc/rfc9113.html#section-9.1.1) 原文——"For 'https' resources, connection reuse additionally depends on having a certificate that is valid for the host in the URI. The certificate presented by the server MUST satisfy any checks that the client would perform when forming a new TLS connection for the host in the URI."（同措辞亦见被取代的 RFC 7540 §9.1.1；RFC 9113 废弃 7540/8740，421 现见 [RFC 9110 §15.5.20](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.20)，"connection coalescing" 一词在 9113 正文已不出现、仅见附录 B）。Chromium 另有专门管控 coalescing 的企业策略与可观测案例：[41396334](https://issues.chromium.org/issues/41396334)、[40651774](https://issues.chromium.org/issues/40651774)。Watt 的阻断手段**已证实**（`CertService.cs`、`ReverseProxyHttpClientFactory.cs`） |
| 7 | **Alt-Svc / HTTP3(QUIC) 绕过 hosts/代理** | 服务器广告 `h3=":443"` 后浏览器改走 QUIC/UDP，绕过只处理 TCP 的 hosts+本地代理链路；且 Alt-Svc 缓存 24 h，UDP 被封时会反复重试再超时回落 | `chrome://net-internals/#http2`（Alt-Svc 表）/ `#quic`；DevTools 协议列显示 `h3`；实测 `github.githubassets.com` 目前真的回 `alt-svc: h3=":443";ma=86400,h3-29=":443";ma=86400,h3-27=":443";ma=86400` | 关 QUIC：Edge 策略 **`QuicAllowed`**（`SOFTWARE\Policies\Microsoft\Edge` 下 `REG_DWORD 0`，Dynamic Policy Refresh=No → 需重启浏览器）/ `chrome://flags/#enable-quic`；代理侧屏蔽 `Alt-Svc` 响应头 | 机制**已证实**：[RFC 7838 §2.4](https://www.rfc-editor.org/rfc/rfc7838.txt) 原文——"A client configured to use a proxy for a given request SHOULD NOT directly connect to an alternative service for this request, but instead route it through that proxy."；§3.1 规定 Alt-Svc 缓存 "fresh for 24 hours"；另有 **HTTPS RR（[RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html) type 65）**可在 DNS 层通告 `alpn=h3` + `ipv4hint` 直接给 IP，同样绕过 hosts。Watt 侧无专门处理（仅透传响应头）→ 潜在短板。 |
| 8 | 其它干扰 | 运营商 QoS 限速、ECH、DNS 缓存陈旧、Fastly 边缘选点、`netsh winsock reset` 副作用 | `ipconfig /displaydns`（**官方明确含 hosts 预载**，实测 hosts 项 TTL 极大，如 `github.com` 缓存 TTL≈597616 s≈6.9 天；改 hosts 后须 `ipconfig /flushdns` **并重启浏览器**）；`curl -s -D - https://github.com/ -o NUL` 看 `x-github-edge-region`（实测本机落 `fra` 法兰克福 → **纯 hosts 无法干预 Fastly 选点**）；`netsh int tcp show global` | ECH 可关：Edge 策略 `EncryptedClientHelloEnabled=0`；网络层：`netsh int tcp set global autotuninglevel=…`。**注意 `netsh winsock reset` 会移除自定义 LSP**，可能让旧版 VPN/加速客户端失效（Watt 的"网络修复"里就有这一条） | 逐条：DNS 缓存行为**已证实**（[ipconfig](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ipconfig)）；ECH 规范**已证实**（**[RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html)**，SVCB 的 ech 见 [RFC 9848](https://www.rfc-editor.org/rfc/rfc9848.html)——**不要再写 draft-ietf-tls-esni**）；hosts×ECH 交叉点讨论见 [tlswg issue #670](https://github.com/tlswg/draft-ietf-tls-esni/issues/670)；"运营商限速/连接数限制是主因"**未找到证据**（OONI 的 Web Connectivity 只测封锁不测速率）；"Fastly 选点异常导致不稳"**未找到证据** |

---

## 10. Windows 上 hosts 被安全软件锁定 / 需要管理员权限的常见处理

（本节素材由并行调研子代理给出，含本机实测。）

| 项 | 结论 | 可信度 |
|---|---|---|
| 真正的拒因是 ACL，不是只读位 | 本机实测：`attrib hosts` 只有 `A`；`icacls` 显示 `etc` 目录 `BUILTIN\Users:(RX)`，hosts 继承后 Users=RX → 写入得 `ERROR_ACCESS_DENIED (5)`。官方 KB 也明说"管理员账号登录也会被拒，要用管理员身份运行编辑器" | 已证实（[KB923947](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/cannot-modify-hosts-lmhosts-files)、[icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)） |
| UAC 虚拟化 | 路径 `%Windir%\system32` **在**被虚拟化范围内，但只对"无 requestedExecutionLevel 的 32 位旧应用"生效；虚拟化后写入被重定向到 `%LOCALAPPDATA%\VirtualStore\...` → **进程以为写成功、hosts 没变**。这是"假成功"排查要点 | 已证实（[UAC 虚拟化策略](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)） |
| 常见锁源 | ① **Defender 的 hosts 篡改检测**（`SettingsModifier:Win32/HostsFileHijack`）——官方原文：会拦"修改 hosts 插入受保护域名条目"的行为，处置时"把 hosts 重置为默认、删除已有条目"，且**官方未提供该检测的白名单**；② 文件只读位；③ 他人以 `FileShare.None` 独占打开（`ERROR_SHARING_VIOLATION 32`）；④ 第三方杀软自我保护（卡巴斯基 Self-Defense 等） | ①**已证实**（[HostsFileHijack](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=SettingsModifier:Win32/HostsFileHijack)）、②③**已证实**、④自保机制**已证实**但"某杀软专门锁 hosts"**未找到证据** |
| 关于受控文件夹访问（CFA） | **纠正一个常见误传**：CFA 官方默认受保护文件夹只有用户 `Documents/Favorites/Music/Pictures/Videos`、`Public` 同名目录与引导扇区，**全文没有 hosts**；只有手动把 `C:\Windows`（或 `etc` 目录）加进 Protected folders 才可能拦到 hosts。所以"CFA 拦 hosts"只能算**推断**，不是已证实 | 已证实（[CFA overview](https://learn.microsoft.com/en-us/defender-endpoint/controlled-folder-access-overview)——原文无 hosts）+ 推断（需手动加目录才会命中） |
| Defender 排除项 | `Add-MpPreference -ExclusionPath 'C:\Windows\System32\drivers\etc'`（文件夹粒度官方支持；单文件 hosts 未文档化 → 推断）+ `Add-MpPreference -ExclusionProcess '<你的程序.exe>'`；CFA 白名单用 `-ControlledFolderAccessAllowedApplications` / UI 在"勒索软件防护 → 受控文件夹访问 → 允许应用" | 已证实（[排除项配置](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-exclusions-configure)、[customize controlled folders](https://learn.microsoft.com/en-us/defender-endpoint/customize-controlled-folders)） |
| 诊断"谁锁着" | `handle64.exe -nobanner hosts`、或 `handle64.exe -a` 全量导出后过滤 `etc\hosts`（实测能定位到 `(---)` 授权句柄）；Process Explorer Ctrl+F Find Handle；`openfiles /query` 默认不可用（需 `openfiles /local on` + 重启）；PowerShell 最小探测 `[System.IO.File]::Open($p,'Open','ReadWrite','None')` 抛的异常类型可区分"权限"还是"共享冲突" | 已证实（[handle](https://learn.microsoft.com/en-us/sysinternals/downloads/handle)、[openfiles](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/openfiles)） |
| 错误码对照 | 5 `ACCESS_DENIED`（ACL/filter）；32 `SHARING_VIOLATION`（不兼容共享模式）；33 `LOCK_VIOLATION`；19 是 `ERROR_WRITE_PROTECT`（介质写保护）**不是** `ERROR_READ_ONLY`；只读位是 **6009 (0x1779)** `ERROR_FILE_READ_ONLY` | 已证实（[错误码 0-499](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-)、[6000-8199](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--6000-8199-)，并修正了题目里的一处笔误） |
| 工程化处理 | ① 提权（清单 `requireAdministrator` 或计划任务/服务代写）；② 写临时文件 + `File.Replace`（保留 DACL，失败有专门错误码）；③ `attrib -r` / `icacls` 授权（降安全基线，慎用）；④ 重试+退避（仅对共享冲突类）；⑤ 写后重读校验防"假成功"；⑥ 不用 hosts 的替代：`netsh winhttp`（只影响 WinHTTP，浏览器不看）、`HKCU\...\Internet Settings\AutoConfigURL`/`ProxyServer`（免管理员，浏览器生效）、Edge 策略 `ProxySettings`、`netsh dnsclient` DoH、WinDivert/WFP/Wintun 网络层 | 已证实（[File.Replace](https://learn.microsoft.com/en-us/dotnet/api/system.io.file.replace)、[netsh winhttp](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-winhttp)、[Edge ProxySettings](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/proxysettings)、[WinDivert](https://reqrypt.org/windivert.html)） |
| **Watt 自己的做法（源码对照）** | ① 主进程非提权时通过 **IPC 调用提权进程**里的 `IHostsFileService` 代写（`GetPrivilegedThisAsync()`）；② 只读属性临时去掉再恢复；③ 区分 `UnauthorizedAccessException`/`SecurityException` → 专门提示"文件无权限"；④ `FileSystemWatcher` + 抖动重写对抗外部反复覆盖；⑤ 标记重复时先备份 `hosts.spp.bak` 再重置；⑥ 写失败立刻 `StopProxyAsync()` 回退，不留半成品 | 已证实（`Services.Implementation/Net/HostsFileServiceImpl.cs:49-63, 231-248, 594-601, 366-372`；`ProxyService.Operate.cs:270-281`） |

---

## 11. 对本项目最有借鉴价值的 5 条结论

1. **"逐域名自签叶子证书"是解决浏览器 connection coalescing 串域名最干净的本地手段**——只要 MITM 为每个 SNI 现签一张 SAN 只含该域名的证书，浏览器就不可能把 A 域名复用到 B 域名的连接上（RFC 9113 §9.1.1 要求证书覆盖才可复用）。比"一域名一 IP"更可靠：即便多域名解析到同一 IP 也不会合并。代价是必须让用户信任一张机器级根证书。（`CertService.GetOrCreateServerCert` / `CertGenerator.CreateEndCertificate`）
2. **上游连接池按 (域名, 配置) 分仓 + handler 生命周期轮换**是一套可直接抄的稳健组合：既避免上游复用造成的串域名，又用"弱引用 + 延迟 Dispose"保证轮换时不会打断在途请求（首 10 s、后续 100 s、10 s 一轮清理）。\（`LifeTimeKey` / `ReverseProxyHttpClientFactory` / `LifetimeHttpHandlerCleaner`）
3. **hosts 写入要设计成"可精确回放的标记区"**：`# Start/# End` 生效区 + `# Backup Start/# End` 里用 `#{原行号} {原行}` 记录被覆盖的行，停止时按原行号插回。这比"整文件备份再全量还原"鲁棒得多（多个软件共存时不会互相覆盖），也天然幂等（`ContainsHostsByTag` 可判定是否需要清理）。再加 `FileSystemWatcher` 看门狗 + 随机化去抖（550–850 ms / 2.65 s 节流）对抗外部覆盖。
4. **DNS 侧的正确姿势是"启动前并发测所有 DoH 候选、取最先可用者"，并且解析必须绕开系统 DNS**（hosts/DNS 拦截模式下强制用 Dnspod，否则会解析到自己造成回环）。配合"解析结果缓存 TTL 9.9 分钟 + 逐 IP 试连（10 s 超时）"，用很小的代码量拿到了"抗污染 + 失败切换"。**不要指望服务端下发"测速最优 IP"**——Watt 自己也没有，它只在表里给固定 IP 或中转域名。
5. **可观测的运维面比智能选路更值钱**：Watt 把"网络检查"（Ping/UDP DNS/DoH/打开 URL/上下行测速/STUN）、"网络修复"（还 hosts + 关系统代理/PAC + `netsh winsock reset`）、"流量曲线"（FlowAnalyze）、"请求日志"都做成了产品内建能力；而它的已知短板（崩溃不自动还 hosts、Alt-Svc/HTTP3 未做屏蔽）恰好说明：**回滚路径要么做看门狗，要么做启动自检**——两者缺一，用户就会遇到"打不开网页又不知道是谁改的"。

---

## 附录 A：核心文件索引（commit d0421314）

| 主题 | 文件 |
|---|---|
| 模式选择 / 启动停止 / hosts 写入 | `src/BD.WTTS.Client.Plugins.Accelerator/Services/Mvvm/ProxyService.Operate.cs`、`ProxyService.cs` |
| 设置默认值（端口/IP/DNS/DoH） | `src/BD.WTTS.Client.Plugins.Accelerator/Settings/Abstractions/IProxySettings.cs`、`Settings/ProxySettings.ProxyMode.cs` |
| hosts 读写/标记/看门狗/提权 IPC | `src/BD.WTTS.Client/Services.Implementation/Net/HostsFileServiceImpl.cs`、`WindowsPlatformServiceImpl.Net.Hosts.cs` |
| Kestrel 监听与 TLS 中间件 | `.../Accelerator.ReverseProxy/Extensions/KestrelServerOptionsExtensions.cs`、`ListenOptionsExtensions.cs`、`HttpServer/Middleware/TlsInvadeMiddleware.cs`/`TlsRestoreMiddleware.cs`/`TunnelMiddleware.cs`/`HttpProxyMiddleware.cs` |
| 证书 | `Services.Implementation/Certificate/CertificateManagerImpl.cs`、`CertGenerator.cs`、`HttpServer/Certificates/CertService.cs` |
| IP 选择 / DoH / 连接 | `Services.Implementation/DomainResolver.cs`、`Http/ReverseProxyHttpClientHandler.cs`、`ReverseProxyHttpClientFactory.cs`、`Http/LifetimeHttpHandler*.cs` |
| DNS 与拦截 | `Services.Implementation/Net/DnsDohAnalysisService.cs`、`DnsAnalysisServiceImpl.cs`、`PacketIntercept/DnsInterceptor.cs` |
| 域名配置模型 | `.../Models/ReverseProxyConfig.cs`、`Common@818b673: src/BD.Common/Net/DomainPattern.cs`、`TlsSniPattern.cs`、`MicroServices.ClientSDK@380d1ab: .../Accelerator/AccelerateProjectDTO.cs`、`.../Accelerator/Yarp.Configuration/DomainConfig.cs` |

## 附录 B：证据文件

随本仓库保存（`docs/research-data/`）：

- `accelerator-projectgroups.json` —— `POST https://api.steampp.net/accelerator/projectgroups` 原始响应（28,513 B，2026-09-25 抓取）
- `accelerator-flat.json` —— 展开后的 69 条加速项

仅给出来源、未随仓库再分发：

- Chromium 解析器源码 `net/dns/host_resolver_manager_job.cc`（§9 第 5 条依据）——
  见 <https://github.com/chromium/chromium/blob/ee7ef8016281439932a81bdac80a66f9a31efb62/net/dns/host_resolver_manager_job.cc>
- SteamTools 源码——见 <https://github.com/BeyondDimension/SteamTools>（commit `d04213147e77a8d73277fa8b86eeecfa444df071`）
