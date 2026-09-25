# 中国大陆访问 GitHub 不稳定：8 条根因 · 原理／验证／缓解／可信度

> 实测环境：Windows 10 22H2，解析器 202.113.112.51（CERNET）。标「实测」的结论均在本机复现。
> **全局纠错（3 条，均实测）**：
> 1. **`Resolve-DnsName -Type HTTPS` 在 Windows 上不存在**（`-Type` 的 RecordType 枚举无 HTTPS），`nslookup -type=HTTPS` 报 `unknown query type`。查 HTTPS RR 只能用 `edge://net-internals/#dns`。
> 2. **`chrome://net-internals/#http2` 已移除**（Edge 153 跳 `#events`，提示改用 net-export），HTTP/2 复用只能靠 `edge://net-export/`。
> 3. **本机 hosts 有 `# dsh-github-accel` 段**（`github.com→127.0.0.2` 等）。任何 DNS 排查若不加 `-DnsOnly`、不先看 hosts，都会把 hosts 预载值误判成 DNS 污染。这是本次最容易得出的错误结论。

## 1. DNS 污染 / 投毒
- **原理**：出口旁路监听 DNS，抢在权威应答前注入伪造 A 记录，客户端采纳先到的应答 → 被导向错误/黑洞 IP。
- **验证**：`Resolve-DnsName github.com -Type A -DnsOnly`（**`-DnsOnly` 必加**，否则读到 hosts 预载值 127.0.0.2 造成假象）；DoH 对比 `Invoke-RestMethod "https://doh.pub/dns-query?name=github.com&type=A"`；`curl.exe -v https://github.com` 看 `Connected to` 真实 IP。
- **缓解**：系统 DNS 改 DoH/DoT（223.5.5.5 / 119.29.29.29）；代理走**域名分流**而非改 hosts。
- **可信度**：机制 已证实——[FOCI'14](https://www.usenix.org/conference/foci14/workshop-program/presentation/anonymous) 原文 "…by injecting forged DNS replies or TCP resets."；具体污染值（`0.0.0.0`/`59.24.3.173`）**未找到证据**（OONI / GreatFire / gfw.report 在本网络全部超时，勿引用）。

## 2. 单条 A 记录 / 单 IP 无冗余
- **原理**：`github.com` 经 GeoDNS 只下发**单条** A 记录，同一 RRSet 内无第二地址 → 客户端无法自行切换边缘，该边缘不可达时只能等 TTL 重查。
- **验证**：`Resolve-DnsName github.com -Type A -DnsOnly -Server 223.5.5.5 | Measure-Object`；对照 `Resolve-DnsName github.io -Type A -DnsOnly`。
- **实测**：`github.com` → `20.205.243.166`（**1 条**，五个解析器一致）；`raw/objects.githubusercontent.com` → `185.199.108-111.133`（4 条，Fastly 段才有轮换）。
- **缓解**：不要指望 DNS 层故障转移；本地 pin IP 须**定期核对**（[api.github.com/meta](https://api.github.com/meta)），Fastly 段会变。
- **可信度**：单条 A 记录 已证实（实测）；「单点致大陆不稳」**推断**；GitHub status 的 DNS incident **未找到证据**（近两月 50 条 incident 中 "DNS" 命中 0 次）。
- **URL**：[RFC 2181 §5.1](https://www.rfc-editor.org/rfc/rfc2181.txt)（RRSet 一致性）· [RFC 1794](https://www.rfc-editor.org/rfc/rfc1794.txt) · [GitHub IP 地址文档](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-githubs-ip-addresses)

## 3. MTU / 分片 + TLS ClientHello 的 SNI 阻断
- **原理**：① SNI 在 ClientHello 中**明文**承载且先于加密通道发出；实测中国的论文显示 GFW **先放行 TCP 三次握手**，收到含被封 SNI 的 ClientHello 后向两端**注入 RST**，且残留封锁（约 60–180 秒）内该三元组任何包都再触发 RST。表现即「握手刚起就 Connection reset / 长时间无响应」。② PMTUD 黑洞：路径 MTU 小于本机 MTU 且带 DF 位时，中间设备丢大包**却不回** ICMP fragmentation needed；ClientHello（含 PQ key share 可 >1400B）与证书链最易装不下 → 小请求正常、一握手就卡死。
- **验证**：`curl -v --max-time 15 https://github.com/` 看断在 TLS handshake 前/中；`Test-NetConnection github.com -Port 443 -InformationLevel Detailed` 能连即排除 IP 层封锁；`netsh interface ipv4 show subinterfaces` 看 MTU，`ping -f -l 1472 HOST` 二分（`-f` 置 DF）。Wireshark：`tcp.flags.reset == 1`（比对 TTL/ip.id 判断 RST 是否**注入**）、`tls.handshake.extensions_server_name`（命中被封域名时是否紧跟 RST）、`icmp.type == 3 && icmp.code == 4`（该来不来即黑洞嫌疑）。
- **缓解**：TLS 分片把 ClientHello 拆成多个小 TCP 段，使单包内不出现完整 SNI——GoodbyeDPI（`-e`/`--frag-by-sni`/`--native-frag`，默认 `-9`）、zapret（`--dpi-desync=split|disorder`＋`--dpi-desync-split-pos=sniext,midsld`）、GreenTunnel。MTU 侧：`netsh interface ipv4 set subinterface "WLAN" mtu=1400 store=persistent`，或依赖 PLPMTUD。
- **可信度**：SNI-RST 机制 **已证实**；MTU 机制 **已证实（RFC）**，但「GitHub 不稳由此导致」为 **推断**（本机实测 WLAN MTU=1500、`ping -f -l 1472` 有回复，未复现黑洞；亦无一手指向 GitHub 特定路径）。
- **URL**：[FOCI 2019 ESNI 论文](https://www.usenix.org/system/files/foci19-paper_chai_update.pdf) · [net4people/bbs #43](https://github.com/net4people/bbs/issues/43) · [USENIX Sec 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/wu-mingshi) · [USENIX Sec 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/zohaib) · [NDSS DNS-Privacy 2021](https://www.ndss-symposium.org/wp-content/uploads/dnspriv21-02-paper.pdf) · [RFC 6066](https://www.rfc-editor.org/rfc/rfc6066.html) · [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) · [zapret](https://github.com/bol-van/zapret) · [GreenTunnel](https://github.com/SadeghHayeri/GreenTunnel) · [RFC 1191](https://www.rfc-editor.org/rfc/rfc1191.html) / [2923](https://www.rfc-editor.org/rfc/rfc2923.html) / [4821](https://www.rfc-editor.org/rfc/rfc4821.html) / [8899](https://www.rfc-editor.org/rfc/rfc8899.html) · [Wireshark tcp](https://www.wireshark.org/docs/dfref/t/tcp.html) / [tls](https://www.wireshark.org/docs/dfref/t/tls.html)

## 4. IPv6 黑洞
- **原理**：系统按 RFC 6724 优先 v6（实测默认前缀策略 `::/0`=40 > `::ffff:0:0/96`=35），AAAA 存在但 v6 出口黑洞 → 先超时再回落 v4，表现为长时间卡顿。
- **验证**：`Resolve-DnsName raw.githubusercontent.com -Type AAAA`（实测 4 条 `2606:50c0:8000-8003::154`）；`Get-NetIPAddress -AddressFamily IPv6`；`netsh interface ipv6 show interface`；`netsh interface ipv6 show prefixpolicies`；`curl -6 -v` 对比 `curl -4 -v`。
- **★两个易踩的坑**：
  1. `ping -6 github.com` 失败**不能**证明 v6 黑洞——`github.com` **根本没有 AAAA 记录**，失败只是因为无 v6 地址可查。必须用 `raw.githubusercontent.com` 这类**确有 AAAA** 的域名做对照。
  2. 本机 hosts 有 `# dsh-github-accel` 段（`github.com→127.0.0.2`、`api.github.com→127.0.0.3` …），`Resolve-DnsName` 会直接返回这些值，**排查前先看 hosts，勿误判成 DNS 污染**。
- **★范围限定（实测）**：`github.com`、`github.io`、`objects.githubusercontent.com`、`codeload.github.com` **完全没有 AAAA**；只有 `raw.githubusercontent.com` 有。故此根因**只对 raw 域成立**，不能解释 github.com 网页卡顿。
- **★本机 IPv6 事实（本次两次复核一致）**：WLAN 有 **2 个全局地址** `2001:250:405:500::/64`（`PrefixOrigin=RouterAdvertisement`），即**本机具备全局 v6**，是 v6 优先路径的候选对象。（另一位同机调研者测得「仅 fe80::」——RA 派生地址会随网络变化，排查时以**当次** `Get-NetIPAddress` 为准。）
- **缓解**：`curl -4`；`netsh interface ipv6 set prefixpolicy`（先 `show prefixpolicy` 看现值，再把 `::ffff:0:0/96` 的 precedence 提到 >40）；注册表 `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisabledComponents`——**0x20(32)= Prefer IPv4 over IPv6（Microsoft 推荐）**、**0xFF(255)= 完全禁用 IPv6**；Microsoft 明确建议用 prefix policy 而非整体禁用，改后需重启。
- **可信度**：AAAA 分布与全局 v6 存在 已证实（实测）；「v6 黑洞导致 GitHub 不稳」仅限 raw 域，**推断**（未复现该路径）。Chromium 官方 Happy Eyeballs 文档 **未找到证据**（所有 `chromium.*` 源站在本网络不可达，官方镜像 `net/docs/` 无 happy-eyeballs.md），替代一手来源为 Google 署名的 IETF HEv3 草案。
- **URL**：[RFC 6724](https://www.rfc-editor.org/rfc/rfc6724.html) · [RFC 8305](https://www.rfc-editor.org/rfc/rfc8305.html) · [RFC 6555](https://www.rfc-editor.org/rfc/rfc6555.html) · [MS Learn 配置 IPv6（DisabledComponents 0x20/0xFF）](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-ipv6-in-windows) · [netsh interface](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) · [Test-NetConnection](https://learn.microsoft.com/en-us/powershell/module/nettcpip/test-netconnection) · [IETF HEv3 草案](https://datatracker.ietf.org/doc/draft-pauly-v6ops-happy-eyeballs-v3/)

## 5. Secure DNS（DoH）绕过 hosts —— **该说法不成立**
- **原理（真实）**：Chromium 任务序列为 **缓存 → HOSTS → DoH/系统解析**；`HostResolverManager::CreateTaskSequence()` 里 `out_tasks->push_back(TaskType::HOSTS)` 无条件执行，位置在 DNS/DoH 任务**之前**，hosts 命中即根本不发 DoH 查询。故 DoH 不会覆盖 hosts。
- **验证**：`chrome://net-internals/#dns`（域名查询框 + Host resolver cache / Clear host cache）；反证法——hosts 指向 `127.0.0.1` 后开/关 Secure DNS 均失败。
- **缓解**：**与 DoH 无关，不必关闭**；应修正 hosts 条目。确要关：`HKLM\SOFTWARE\Policies\Google\Chrome\DnsOverHttpsMode=off`（Edge 换 `...\Microsoft\Edge\...`）。
- **可信度**：已证实（[Chromium 源码](https://github.com/chromium/chromium/blob/ee7ef8016281439932a81bdac80a66f9a31efb62/net/dns/host_resolver_manager.cc) + 实测）；`AsyncDns` **不是**策略而是 net 层 feature（[features.cc](https://github.com/chromium/chromium/blob/ee7ef8016281439932a81bdac80a66f9a31efb62/net/base/features.cc)）；Firefox 是否读 hosts **未找到证据**。
- **URL**：[`host_resolver_manager_job.cc`（ServeFromHosts）](https://github.com/chromium/chromium/blob/ee7ef8016281439932a81bdac80a66f9a31efb62/net/dns/host_resolver_manager_job.cc) · [Edge DnsOverHttpsMode](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/dnsoverhttpsmode) · [Mozilla DoH](https://support.mozilla.org/en-US/kb/firefox-dns-over-https)

## 6. HTTP/2 连接复用 / connection coalescing
- **原理**：三前提同时满足才复用——**同 IP + 证书覆盖目标域名 + h2(ALPN)**；此时多域名共用一条 TCP，任一被阻断则「一挂全挂」。
- **验证**：`edge://net-export/` 抓 netlog → NetLog Viewer 看 HTTP/2 session 的 `IPEndPoint` 与复用域名；`edge://net-internals/#sockets`；`curl -sS -o NUL -w "%{http_version} %{remote_ip}\n" https://TARGET/` 与 `--http1.1` 对比。
- **★纠错**：「hosts 只改 github.com 导致 github.io 被复用送错 IP」**不成立**——`github.com` 证书 SAN 仅 `github.com`/`www.github.com`，且两域 IP 不同，`SpdySession::CanPool()` 的证书校验直接不通过。真正有风险的是 `github.io` 那张宽证书（SAN 含 `*.githubusercontent.com`）＋ `185.199.108.0/22` 同段域名。
- **缓解**：`--disable-http2`（源码确认，本次未实测）；走代理（IP-based pooling 对代理连接不生效）。**无**单独关 coalescing 的开关。
- **可信度**：复用前提 已证实（[RFC 9113 §9.1.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-9.1.1) 原文 "…depends on having a certificate that is valid for the host in the URI"）；`CanPool` 校验 已证实（[源码](https://github.com/chromium/chromium/blob/ee7ef8016281439932a81bdac80a66f9a31efb62/net/spdy/spdy_session.cc)）；专用开关 **未找到证据**。注：RFC 9113 已废弃 RFC 7540/8740，421 移至 [RFC 9110 §15.5.20](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.20)。

## 7. Alt-Svc / HTTP3(QUIC) 绕过 hosts 与代理
- **原理**：`Alt-Svc: h3=":443"` 通告同源 QUIC 端点，浏览器在 **UDP 443** 另开连接并整体迁走，绕开只转发 TCP 的本地代理/hosts 加速器；RFC 7838 亦规定该端点 "in every way as the origin"。缓存 **24h** 才过期，故 UDP 被阻断后仍反复重试再超时回落。
- **验证**：`curl -s -D - https://github.githubassets.com/ -o NUL`（实测确实返回 `alt-svc: h3=":443";ma=86400,...`）；`curl --http1.1` vs `--http3`（本机 curl 8.4.0 不含 HTTP3，会报 "doesn't support this"）。
- **缓解**：Edge 策略 `QuicAllowed=0`（`SOFTWARE\Policies\Microsoft\Edge`，REG_DWORD，需重启浏览器）；代理层丢弃 UDP 443。DNS 层可阻断 HTTPS RR（type 65）。
- **可信度**：已证实。规范级依据 RFC 7838 §2.4 原文：*"A client configured to use a proxy for a given request SHOULD NOT directly connect to an alternative service for this request, but instead route it through that proxy."* → 浏览器直连 QUIC 端点属实现层违规。
- **URL**：[RFC 7838](https://www.rfc-editor.org/rfc/rfc7838.txt)（§2.4 代理、§3.1 24h）· [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html)（HTTPS RR type 65，`alpn=h3`＋`ipv4hint` 同样可绕过 hosts）· [Edge QuicAllowed](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/quicallowed)

## 8. Windows 其它干扰
- **8a TLS 1.3 ECH / 加密 SNI**：ECH 把 SNI/ALPN 加密，须先经 DNS 取 ECH 公钥。已是正式 **RFC 9849**（Proposed Standard），配套 **RFC 9848** 定义 SVCB 的 `ech` SvcParam——写成 `draft-ietf-tls-esni` 已过时。验证 `edge://net-internals/#dns` 看 HTTPS 记录是否含 `ech`；缓解 Edge 策略 `EncryptedClientHelloEnabled=0`。**已证实**。URL：[RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html) · [RFC 9848](https://www.rfc-editor.org/rfc/rfc9848.html) · [Edge ECH 策略](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/encryptedclienthelloenabled)
- **8b 运营商 QoS / 限速 / 连接数限制**：OONI NDT 原文称其结果 "can potentially be used to examine cases of throttling"，但主检测试 Web Connectivity **只测封锁不测速率**。故「GitHub 在华被限速」的定量报告与「并发连接数上限」均 **未找到证据**。URL：[OONI NDT](https://ooni.org/nettest/ndt/) · [Web Connectivity](https://ooni.org/nettest/web-connectivity/)
- **8c DNS 缓存与 hosts 生效**：`ipconfig /displaydns`（官方原文明确含 hosts 预载条目）· `ipconfig /flushdns`。实测 `github.com` 缓存 TTL 597616 秒（≈6.9 天，hosts 预载特征）vs `github.map.fastly.net` 3598 秒（真实记录）。改 hosts 后须 flush ＋ **重启浏览器**（浏览器另有独立 host cache 与 Alt-Svc 缓存）。**已证实**。URL：[ipconfig 文档](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ipconfig)
- **8d Fastly 边缘选点**：Fastly 官方称其 DNS 按网络邻近度选最近 POP；GitHub 官方登记 Fastly 为 CDN 子处理者。实测本机 `github.com` 落 `x-github-edge-region: fra`（法兰克福）。**纯 hosts 无法干预选点**，需能主动选路的出口。**已证实**。URL：[Fastly 客户案例](https://www.fastly.com/customers/github) · [Fastly POP 网络](https://www.fastly.com/documentation/guides/getting-started/concepts/using-fastlys-global-pop-network/) · [GitHub 子处理者](https://docs.github.com/en/site-policy/privacy-policies/github-subprocessors)
- **8e netsh 真实语义**：`netsh int tcp show global`（实测 `Receive Window Auto-Tuning Level : normal`）· `netsh int tcp set global autotuninglevel=` 合法值 `disabled|highlyrestricted|restricted|normal|experimental` · `netsh winsock reset` **会移除自定义 LSP**，可能使旧版 VPN/加速客户端失效并需重装。**已证实**。URL：[netsh 上下文](https://learn.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts) · [netsh winsock](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-winsock)

## 排障最短路径
0. **先看 hosts**（`notepad %SystemRoot%\System32\drivers\etc\hosts`）——本机 `github.com` 已被指向 `127.0.0.2`，不看会误判
1. `Resolve-DnsName github.com -Type A -DnsOnly` → 是否返回 `127.0.0.0/8` 或 `0.0.0.0`
2. 与 DoH（`doh.pub`）对比，再 `curl -v` 看实际连的 IP
3. `curl -v --max-time 15 https://github.com/` → 断在 TLS handshake 即 SNI-RST 嫌疑（第 3 条）
4. **v6 检查必须用有 AAAA 的域名**：`Resolve-DnsName raw.githubusercontent.com -Type AAAA`（`github.com` 无 AAAA，拿它测会得出错误结论）
5. `curl -s -D - https://github.githubassets.com/ -o NUL` → 看有无 `alt-svc: h3=…`
6. 下发 `QuicAllowed=0` 后**重启浏览器**，重测静态资源是否还中途卡住
7. `ipconfig /flushdns` → 重启浏览器 → 复测

> 说明：第 5 条（Secure DNS 绕过 hosts）经源码核查后**证伪**——它是常见误传，不要按它去关 DoH。真正会绕过 hosts/代理的是第 7 条 Alt-Svc/QUIC 与第 6 条的证书覆盖判定。
