/**
 * dsh-github-accel — 加速核心（纯 Node，无 DSH 依赖，可独立测试）
 *
 * 设计要点：**不做 TLS 中间人**。
 *
 * Steam++（Watt Toolkit）走的是「hosts → 127.0.0.1 + 本地反代 + 自签根证书 MITM」，
 * 代价是所有客户端都得信任它的根证书，而且 schannel 的吊销检查、Node 自带的 CA 列表
 * 都会报错（本机实测 0x80092012 与 UNABLE_TO_VERIFY_LEAF_SIGNATURE）。
 *
 * 这里改成「hosts → 127.0.0.x + **SNI 直通**」：本机 443 上只读 ClientHello 里的
 * SNI，然后把**原始字节**转发到该域名的真实 IP。客户端看到的永远是 GitHub 自己的
 * 证书，于是浏览器、curl、git、Node fetch 全都不用额外配置。
 *
 * 三条通路（互为备份，谁可用用谁）：
 *   P1 hosts + 一域名一地址 SNI 直通 —— 系统级；需要管理员写 hosts
 *   P2 127.0.0.1:18999 上的 CONNECT 代理 —— 无需管理员，给 git/curl/npm
 *   P3 PAC + 当前用户系统代理 —— 无需管理员，**抗浏览器 Secure DNS 与 IPv6 黑洞**
 *
 * 分层实现见同目录的 domains / hosts / net / tunnel / sysproxy；本文件只做编排。
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import {
  APP_DOMAIN,
  DEFAULT_DOMAINS,
  DOMAIN_TABLE,
  HOT_DOMAINS,
  LOOPBACK_PREFIX,
  OPTIONAL_DOMAINS,
  OPT_IN_DOMAINS,
  PROXY_ONLY_DOMAINS,
  COALESCING_UNSAFE,
  decideHijackDomains,
  loopbackFor,
} from './domains.js'
import { DEFAULTS, HOSTS_END, HOSTS_START, HostsBlock } from './hosts.js'
import {
  CandidateTable,
  EXPECTED_STATUS,
  FALLBACK_IPS,
  GITHUB_IP_PREFIXES,
  IP_TTL_MS,
  VALIDATE_TTL_MS,
  WarmPool,
  acceptableStatus,
  connectAny,
  dohResolve,
  isGithubDomain,
  isUsable,
  likelyGithubIp,
  looksLikeWrongHost,
  parseList,
  parseOverrides,
  probeDirect,
  probePort,
  raceConnect,
  resolveRealIps,
  tlsReachable,
  validateEndpoint,
  withFallback,
} from './net.js'
import { ProxyServer, TunnelServer, awaitFirstByte, isCompleteTlsRecord, parseHostHeader, parseSni, relay, safe } from './tunnel.js'
import { PacServer, STATE_DIR, disableAutoConfig, enableAutoConfig, ensureStateDir, flushDns, readProxyState } from './sysproxy.js'

/* ── 向后兼容的再导出 ──────────────────────────────────────────────────────
 * 老的 test/tools 直接 `import { ... } from '../server/accel.js'`，保持可用。 */
export {
  APP_DOMAIN,
  COALESCING_UNSAFE,
  DEFAULT_DOMAINS,
  DOMAIN_TABLE,
  DEFAULTS,
  EXPECTED_STATUS,
  FALLBACK_IPS,
  GITHUB_IP_PREFIXES,
  HOSTS_END,
  HOSTS_START,
  HOT_DOMAINS,
  HostsBlock,
  IP_TTL_MS,
  LOOPBACK_PREFIX,
  OPTIONAL_DOMAINS,
  OPT_IN_DOMAINS,
  PROXY_ONLY_DOMAINS,
  CandidateTable,
  PacServer,
  ProxyServer,
  TunnelServer,
  VALIDATE_TTL_MS,
  WarmPool,
  acceptableStatus,
  awaitFirstByte,
  connectAny,
  decideHijackDomains,
  dohResolve,
  isCompleteTlsRecord,
  isGithubDomain,
  isUsable,
  likelyGithubIp,
  looksLikeWrongHost,
  loopbackFor,
  parseHostHeader,
  parseList,
  parseOverrides,
  parseSni,
  probeDirect,
  probePort,
  raceConnect,
  relay,
  resolveRealIps,
  tlsReachable,
  validateEndpoint,
  withFallback,
}

const log = (...a) => {
  if (process.env.DSH_GITHUB_ACCEL_VERBOSE === '1') console.log('[accel]', ...a)
}

/* ── 状态文件（哨兵）：让「上次没撤干净」可以被发现 ───────────────────────── */
const statePath = () => path.join(ensureStateDir(), 'active.json')

function readState() {
  try {
    return JSON.parse(fs.readFileSync(statePath(), 'utf8'))
  } catch {
    return undefined
  }
}
function writeState(value) {
  try {
    fs.writeFileSync(statePath(), JSON.stringify(value, null, 2), 'utf8')
  } catch {}
}
function clearState() {
  try {
    fs.rmSync(statePath(), { force: true })
  } catch {}
}
function pidAlive(pid) {
  if (!pid || typeof pid !== 'number') return false
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    return error.code === 'EPERM'
  }
}

/** 上次的开关状态：DSH 重启后要能自己恢复（否则用户会以为「又坏了」）。 */
const prefsPath = () => path.join(ensureStateDir(), 'prefs.json')
function readPrefs() {
  try {
    return JSON.parse(fs.readFileSync(prefsPath(), 'utf8'))
  } catch {
    return {}
  }
}
function writePrefs(value) {
  try {
    fs.writeFileSync(prefsPath(), JSON.stringify({ ...readPrefs(), ...value }, null, 2), 'utf8')
  } catch {}
}

/** 网络指纹：换 Wi-Fi / 插网线 / 睡眠唤醒之后它一定会变。 */function networkFingerprint() {
  try {
    const ifaces = os.networkInterfaces()
    const parts = []
    for (const [name, addrs] of Object.entries(ifaces)) {
      for (const a of addrs ?? []) {
        if (a.internal) continue
        parts.push(`${name}:${a.family}:${a.address}`)
      }
    }
    return parts.sort().join('|')
  } catch {
    return 'unknown'
  }
}

/* ── 加速器 ──────────────────────────────────────────────────────────────── */

export class Accelerator {
  constructor(options = {}) {
    this.allDomains = DOMAIN_TABLE.map((e) => e.domain)
    this.domains = options.domains ?? DEFAULT_DOMAINS
    this.excluded = options.excluded ?? parseList(process.env.DSH_GITHUB_ACCEL_EXCLUDE)
    /* 自动可选（校验通过就收） vs 显式 opt-in（点名才收）。见 server/domains.js。 */
    this.optional = options.optional ?? OPTIONAL_DOMAINS
    this.optIn = (options.optIn ?? parseList(process.env.DSH_GITHUB_ACCEL_INCLUDE)).filter((d) =>
      OPT_IN_DOMAINS.includes(d),
    )

    this.sniPort = options.sniPort ?? DEFAULTS.sniPort
    this.httpPort = options.httpPort ?? DEFAULTS.httpPort
    this.proxyPort = options.proxyPort ?? DEFAULTS.proxyPort
    this.pacPort = options.pacPort ?? Number(process.env.DSH_GITHUB_ACCEL_PAC_PORT ?? 18998)

    this.hosts = new HostsBlock({
      path: options.hostsPath ?? DEFAULTS.hostsPath,
      domains: this.domains,
      referenceDomains: this.allDomains,
    })
    /** hosts / 系统代理是不是**这一轮由我们**改的（多实例时决定退出要不要撤）。 */
    this.oursApplied = false

    /*
     * 持久化开关：**默认关**，只有插件宿主（lib/index.js）会显式打开。
     *
     * 为什么必须默认关：状态文件（prefs.json / active.json）与「上次开关」「崩溃哨兵」
     * 属于**系统级共享资源**，一个进程里只能有一个主人。而测试、doctor、bench、
     * live-check 都会 `new Accelerator(...)` —— 如果它们随手 `stop()` 一下，
     * 就会把真插件的 prefs 改成 `enabled:false`（下次 DSH 重启不再自动加速）
     * 并删掉哨兵（崩溃恢复失去线索）。这是真实踩过的坑，不是假想。
     */
    this.persistState = options.persistState === true || process.env.DSH_GITHUB_ACCEL_PERSIST === '1'

    this.table = new CandidateTable({
      fallbacks: options.fallbacks ?? FALLBACK_IPS,
      overrides: options.overrides ?? parseOverrides(process.env.DSH_GITHUB_ACCEL_IPS),
      ttlMs: options.ipTtlMs ?? IP_TTL_MS,
      validateTtlMs: options.validateTtlMs ?? VALIDATE_TTL_MS,
      dohEndpoint: options.dohEndpoint ?? process.env.DSH_GITHUB_ACCEL_DOH ?? '',
    })

    /* 单个候选地址的连接超时。**必须短**：GitHub 的 A 记录里常有在特定网络下不可达的地址
       （实测 github.com 的 5 个候选里 3 个连得上但不服务内容），而我们只在「有候选失败时」
       才顶上下一个。超时越长，坏候选把我们拖着的时间就越长。
       实测数据支撑：TCP 连接 210–305 ms，所以 1200 ms 已经是 4 倍余量。 */
    this.connectTimeoutMs = Number(options.connectTimeoutMs ?? process.env.DSH_GITHUB_ACCEL_CONNECT_TIMEOUT_MS ?? 1200)
    /* 同时竞速的候选数。3 个而不是 2 个：实测 p95 就是被「前两个都坏」拖到 1.5–2.5 s 的。 */
    this.raceWidth = Number(options.raceWidth ?? process.env.DSH_GITHUB_ACCEL_RACE_WIDTH ?? 3)
    this.raceTotalMs = Number(options.raceTotalMs ?? process.env.DSH_GITHUB_ACCEL_RACE_TOTAL_MS ?? 4000)
    this.staggerMs = Number(options.staggerMs ?? process.env.DSH_GITHUB_ACCEL_RACE_STAGGER_MS ?? 200)

    /* 预热池：热域名常备空闲上游连接，省掉「客户端连上后才开始连上游」的那一个 RTT。
       TTL 要短：上游会主动关掉空闲连接，而 FIN 还没被我们处理到的那一小段窗口里，
       取出来的就是一条死连接（拿到后会触发一次透明重连，白等一个来回）。 */
    this.poolEnabled = options.poolEnabled ?? process.env.DSH_GITHUB_ACCEL_POOL !== '0'
    this.poolKeep = Number(options.poolKeep ?? process.env.DSH_GITHUB_ACCEL_POOL_KEEP ?? 2)
    this.poolTtlMs = Number(options.poolTtlMs ?? process.env.DSH_GITHUB_ACCEL_POOL_TTL_MS ?? 5000)
    this.pool = new WarmPool({ keep: this.poolKeep, ttlMs: this.poolTtlMs })

    /* github.com（交互式应用）要不要进隧道。
       默认进（autoApp=false）：浏览器对 github.com 只有一个 DNS 答案、没有我们的多候选切换，
       而 GitHub 的 A 记录在这台网络上会几分钟一轮地某个 IP 不通。 */
    this.autoApp = options.autoApp ?? process.env.DSH_GITHUB_ACCEL_AUTO_APP === '1'
    const hijackAppEnv = process.env.DSH_GITHUB_ACCEL_HIJACK_APP
    this.hijackApp = options.hijackApp ?? (hijackAppEnv === undefined ? undefined : hijackAppEnv === '1')
    this.directProbeTimeoutMs = Number(options.directProbeTimeoutMs ?? process.env.DSH_GITHUB_ACCEL_DIRECT_TIMEOUT_MS ?? 4000)
    this.watchIntervalMs = Number(options.watchIntervalMs ?? process.env.DSH_GITHUB_ACCEL_WATCH_MS ?? 60_000)
    this.healthIntervalMs = Number(options.healthIntervalMs ?? process.env.DSH_GITHUB_ACCEL_HEALTH_MS ?? 90_000)
    this.pacPolicy = options.pac ?? process.env.DSH_GITHUB_ACCEL_PAC ?? 'auto'

    /* 上游侧的三个时间预算（详见 server/tunnel.js 的 connectUpstream 注释）：
       stallMs              上游多久不回一个字节就判定为黑洞地址（用于降权）
       firstByteMs          上游多久不回第一个字节就**换一个并重放 ClientHello**
       maxUpstreamAttempts  一条客户端连接最多试几个上游
       connectDeadlineMs    一条客户端连接在上游侧的总预算 */
    this.stallMs = Number(options.stallMs ?? process.env.DSH_GITHUB_ACCEL_STALL_MS ?? 1500)
    this.firstByteMs = Number(options.firstByteMs ?? process.env.DSH_GITHUB_ACCEL_FIRST_BYTE_MS ?? 1500)
    this.maxUpstreamAttempts = Number(options.maxUpstreamAttempts ?? process.env.DSH_GITHUB_ACCEL_UPSTREAM_ATTEMPTS ?? 3)
    this.connectDeadlineMs = Number(options.connectDeadlineMs ?? process.env.DSH_GITHUB_ACCEL_CONNECT_DEADLINE_MS ?? 8000)

    this.tunnel = new TunnelServer({
      openUpstream: (host, opts) => this.openUpstream(host, opts),
      record: (entry) => this.record(entry),
      log,
      idleTimeoutMs: Number(options.idleTimeoutMs ?? process.env.DSH_GITHUB_ACCEL_IDLE_MS ?? 600_000),
      stallMs: this.stallMs,
      firstByteMs: this.firstByteMs,
      maxUpstreamAttempts: this.maxUpstreamAttempts,
      connectDeadlineMs: this.connectDeadlineMs,
    })
    this.proxy = new ProxyServer({
      openUpstream: (host, opts) => this.openUpstream(host, opts),
      record: (entry) => this.record(entry),
      log,
      stallMs: this.stallMs,
      firstByteMs: this.firstByteMs,
      maxUpstreamAttempts: this.maxUpstreamAttempts,
      connectDeadlineMs: this.connectDeadlineMs,
    })
    this.tunnel.onUpstreamError = (host, ip, error, hard) => this.table.record(host, ip, { ok: false, why: error?.code ?? error?.message, hard })
    this.proxy.onUpstreamError = this.tunnel.onUpstreamError
    /* 黑洞地址（一个字节都没回、拖了 1.5 s 以上）也要降权 —— 它既不报错也不回数据，
       不特殊处理就会永远霸占候选表第一位。 */
    this.tunnel.onUpstreamStall = (host, ip) => this.table.record(host, ip, { ok: false, why: 'stall', stall: true })
    this.proxy.onUpstreamStall = this.tunnel.onUpstreamStall
    this.tunnel.onConnectFailed = (host) => {
      this.counters.connectFailures += 1
      this.perHost(host).fails += 1
    }
    this.proxy.onConnectFailed = this.tunnel.onConnectFailed
    /* 管道回调里出的错一律记到 lastError —— 静默吞掉正是 B2 能藏那么久的原因。 */
    this.tunnel.onHandlerError = (error) => {
      this.lastError = `handler: ${error?.message ?? error}`
    }
    this.proxy.onHandlerError = this.tunnel.onHandlerError

    this.pac = new PacServer({ port: this.pacPort, proxyPort: this.proxyPort })

    this.watchTimer = undefined
    this.healthTimer = undefined
    this.directHealth = undefined
    this.skipped = []
    this.listeners = []
    this.lastError = undefined
    this.lastReport = undefined
    this.pacActive = false
    this.fingerprint = networkFingerprint()
    this.exitHookInstalled = false

    this.trace = []
    this.traceLimit = Number(options.traceLimit ?? 120)
    this.counters = { tunnels: 0, poolHits: 0, failovers: 0, connectFailures: 0, upstreamErrors: 0, validations: 0, networkChanges: 0 }
    this.perDomain = new Map()
    /** mode: 上一次 start 用的模式（recheck 要用）。 */
    this.mode = undefined
  }

  perHost(host) {
    let e = this.perDomain.get(host)
    if (!e) {
      e = { host, conns: 0, pool: 0, fails: 0, upstreamMs: [] }
      this.perDomain.set(host, e)
    }
    return e
  }

  /** 记一条隧道记录（环形缓冲）。 */
  record(entry) {
    if (entry.event === 'tunnel') this.counters.tunnels += 1
    if (entry.via === 'pool') this.counters.poolHits += 1
    if (entry.event === 'upstream-error') this.counters.upstreamErrors += 1
    if (entry.tried?.length) this.counters.failovers += 1
    if (entry.host) {
      const e = this.perHost(entry.host)
      if (entry.event === 'tunnel') e.conns += 1
      if (entry.via === 'pool') e.pool += 1
      if (typeof entry.upstreamMs === 'number') {
        e.upstreamMs.push(entry.upstreamMs)
        if (e.upstreamMs.length > 60) e.upstreamMs.shift()
      }
      if (entry.event === 'connect-failed') e.fails += 1
    }
    this.trace.push({ at: new Date().toISOString(), ...entry })
    if (this.trace.length > this.traceLimit) this.trace.splice(0, this.trace.length - this.traceLimit)
  }

  // ── 选路与连接 ───────────────────────────────────────────────────────────

  /** 这个域名值不值得占预热池（热域名 + 标准 443 端口）。 */
  poolAllowed(host, port) {
    return this.poolEnabled && port === 443 && (HOT_DOMAINS.includes(host) || this.perHost(host).conns > 0)
  }

  /**
   * 拿一条上游连接。**这是整条链路的性能关键点**：
   *   ① 预热池里有现货 → 立刻返回（省掉一个上游 RTT）；
   *   ② 没有 → happy-eyeballs 并行竞速（最坏 4.5 s，而不是串行的 30 s）。
   * 无论哪条路，都会顺手把池子补回去。
   */
  async openUpstream(host, { port = 443, attempt = 0, budgetMs } = {}) {
    const started = Date.now()
    if (this.poolAllowed(host, port)) {
      const entry = this.pool.take(host)
      if (entry && isUsable(entry.socket)) {
        this.table.record(host, entry.ip, { ok: true })
        void this.prefetch(host, port)
        return { socket: entry.socket, ip: entry.ip, via: 'pool', ms: Date.now() - started }
      }
    }
    const ips = await this.table.candidates(host)
    let result
    try {
      result = await raceConnect({
        host,
        port,
        ips,
        width: this.raceWidth,
        perTimeoutMs: this.connectTimeoutMs,
        staggerMs: this.staggerMs,
        /* 一条客户端连接在上游侧的总预算由调用方（隧道）控制：重试时后面的尝试会拿到更小的预算。 */
        totalMs: Math.max(600, Math.min(this.raceTotalMs, budgetMs ?? this.raceTotalMs)),
      })
    } catch (error) {
      /* 竞速全败时必须把失败的候选记下来 —— 否则候选表永远学不到东西，
         下一次还会先撞同一个坏地址（这正是「时好时坏」的来源之一）。 */
      for (const entry of error.tried ?? []) {
        const ip = entry.split('(')[0]
        this.table.record(host, ip, { ok: false, why: entry, hard: true })
      }
      throw error
    }
    this.table.record(host, result.ip, { ok: true, ms: result.raceMs })
    if (result.tried?.length) {
      this.counters.failovers += 1
      this.record({ event: 'failover', host, used: result.ip, skipped: result.tried, raceMs: result.raceMs })
      /* 有候选被跳过 —— 把跳过的那些按硬失败记一笔（它们确实连不上）。 */
      for (const entry of result.tried) {
        const ip = entry.split('(')[0]
        this.table.record(host, ip, { ok: false, why: entry, hard: true })
      }
    }
    void this.prefetch(host, port)
    return { socket: result.socket, ip: result.ip, via: 'race', ms: Date.now() - started, tried: result.tried, raceMs: result.raceMs }
  }

  /** 后台补货。失败无所谓。 */
  prefetch(host, port) {
    if (!this.poolAllowed(host, port)) return Promise.resolve()
    return this.pool.refill(host, async () => {
      const ips = await this.table.candidates(host)
      const r = await raceConnect({
        host,
        port,
        ips,
        width: this.raceWidth,
        perTimeoutMs: this.connectTimeoutMs,
        staggerMs: this.staggerMs,
        totalMs: this.raceTotalMs,
      })
      return { socket: r.socket, ip: r.ip }
    })
  }

  // ── 监听 ─────────────────────────────────────────────────────────────────

  /** 兼容旧调用：只在 127.0.0.1 上开一个监听。 */
  listen({ port, mode, address = '127.0.0.1', defaultHost } = {}) {
    return this.tunnel.listenOn({ port, mode, address, defaultHost })
  }

  /** 一域名一地址地开监听（掐掉跨域连接复用，见 server/domains.js）。 */
  async listenPerDomain({ port, mode, domains }) {
    const list = (domains ?? this.hosts.safeDomains).map((domain) =>
      typeof domain === 'string' ? { domain, address: this.hosts.loopbackForDomain(domain) } : domain,
    )
    return this.tunnel.listenPerDomain({ port, mode, domains: list })
  }

  listenConnectProxy(port = this.proxyPort) {
    return this.proxy.listen(port)
  }

  closeListeners({ mode, domains } = {}) {
    this.tunnel.closeListeners({ mode, domains })
    if (!mode) this.proxy.close()
    if (!mode) this.pac.close()
  }

  // ── 健康循环 ─────────────────────────────────────────────────────────────

  /**
   * 后台端到端校验：**这是「这个地址到底能不能用」的唯一可信来源**。
   * 只对热域名和最近出过问题的域名跑，避免打爆上游。
   */
  async validate(hosts = HOT_DOMAINS) {
    const results = []
    for (const host of hosts) {
      if (this.excluded.includes(host)) continue
      const ips = (await this.table.candidates(host)).slice(0, 3)
      if (ips.length === 0) {
        results.push({ host, okCount: 0, total: 0, reason: 'no-candidates' })
        continue
      }
      const settled = await Promise.all(ips.map((ip) => validateEndpoint(ip, host).catch(() => undefined)))
      let okCount = 0
      settled.forEach((r, i) => {
        if (!r) return
        this.counters.validations += 1
        this.table.recordValidation(host, ips[i], r)
        if (r.ok) okCount += 1
      })
      results.push({ host, okCount, total: ips.length, ips })
    }
    return results
  }

  /** 复检：直连从健康变不健康（或反过来）时，把 github.com 收进/放出隧道。 */
  async recheck() {
    if (!this.autoApp || this.hijackApp !== undefined) return
    if (this.excluded.includes(APP_DOMAIN)) return
    const dnsIps = await resolveRealIps(APP_DOMAIN, this.table.dnsCache, this.table.overrides).catch(() => [])
    const health = await probeDirect(APP_DOMAIN, dnsIps, this.directProbeTimeoutMs)
    this.directHealth = health
    const hijacked = this.hosts.domains.includes(APP_DOMAIN)
    const shouldHijack = !health.healthy
    if (shouldHijack === hijacked) return
    this.record({ event: 'auto-switch', host: APP_DOMAIN, hijack: shouldHijack, healthy: health.healthy })
    this.lastError = `auto: github.com 直连${health.healthy ? '恢复 → 撤出隧道' : '不可达 → 收进隧道'}`
    const next = new Set(this.domains.filter((d) => !this.excluded.includes(d)))
    if (shouldHijack) next.add(APP_DOMAIN)
    else next.delete(APP_DOMAIN)
    await this.restartListeners({ port: this.sniPort, mode: 'sni', domains: [...next] })
    await this.restartListeners({ port: this.httpPort, mode: 'http', domains: [...next] })
    this.hosts.domains = [...next]
    const applied = this.hosts.apply()
    if (applied.ok) {
      this.flushDnsIfOwner()
      this.saveState({ pid: process.pid, at: new Date().toISOString(), domains: [...next], addresses: this.hosts.addressMap })
    }
  }

  /** 关掉某类监听再按新的域名集合重开，并把 hosts 收敛成「监听真的起来了」的那些。 */
  async restartListeners({ port, mode, domains }) {
    this.tunnel.closeListeners({ mode })
    const results = await this.listenPerDomain({ port, mode, domains })
    return results
  }

  /**
   * hosts 完整性看门狗。
   *
   * 借鉴 Watt Toolkit 的 `FileSystemWatcher`：hosts 是**共享资源**，别的程序会改它 ——
   * 另一个加速器接管、安全软件把它重置成默认值（Defender 的
   * `SettingsModifier:Win32/HostsFileHijack` 就会这么做）、或者用户手工编辑。
   * 一旦我们那份块没了，接管就静默失效（浏览器悄悄走回了直连，表现成「有时候快有时候慢」）。
   *
   * 这里的做法比它保守：
   *   - 发现有**别人的**接管块 → 直接认输并大声报错，绝不和人抢；
   *   - 只是我们自己的条目丢了 → 重写回去；连续失败 3 次就停手并报错。
   */
  verifyHosts() {
    if (!this.persistState) return { ok: true, skipped: true, reason: 'not-owner' }
    const expected = this.hosts.addressMap
    const wanted = Object.keys(expected)
    if (wanted.length === 0) return { ok: true, skipped: true }

    const foreign = this.hosts.detectForeign()
    if (foreign.length > 0) {
      this.lastError = `hosts 被别的加速器接管（${foreign.join(', ')}）—— 已停止争夺，请先关掉它`
      if (!this.hostsForeignReported) {
        this.hostsForeignReported = true
        this.record({ event: 'hosts-foreign', foreign })
      }
      return { ok: false, reason: 'foreign-owner', foreign }
    }

    const entries = this.hosts.currentEntries()
    const missing = wanted.filter((domain) => !entries.some((e) => e.domain === domain && e.address === expected[domain]))
    if (missing.length === 0) {
      this.hostsRepairAttempts = 0
      return { ok: true, entries: entries.length }
    }

    if ((this.hostsRepairAttempts ?? 0) >= 3) {
      return { ok: false, reason: 'repair-given-up', missing }
    }
    this.hostsRepairAttempts = (this.hostsRepairAttempts ?? 0) + 1
    const applied = this.hosts.apply()
    this.record({ event: 'hosts-repair', missing, ok: applied.ok, reason: applied.reason, attempt: this.hostsRepairAttempts })
    if (applied.ok) {
      this.hostsRepairAttempts = 0
      this.flushDnsIfOwner()
    } else this.lastError = `hosts 被改写且无法修复：${applied.reason}`
    return { ok: applied.ok, reason: applied.reason, missing }
  }

  /** 定时器：健康校验 + 网络变化检测 + 池清扫。 */
  startHealthLoop() {
    if (this.healthTimer || !this.healthIntervalMs) return
    this.healthTimer = setInterval(() => {
      void safe(async () => {
        const now = networkFingerprint()
        if (now !== this.fingerprint) {
          this.fingerprint = now
          this.counters.networkChanges += 1
          this.record({ event: 'network-change' })
          this.table.reset()
          this.pool.close()
          this.pool = new WarmPool({ keep: this.poolKeep, ttlMs: this.poolTtlMs })
        }
        this.pool.sweep()
        this.hostsIntegrity = this.verifyHosts()
        /* 只校验「热域名 + 最近出过问题的域名」，别把上游打爆。 */
        const hosts = new Set(HOT_DOMAINS)
        for (const [host, e] of this.perDomain) if (e.fails > 0) hosts.add(host)
        await this.validate([...hosts].slice(0, 8))
        this.record({ event: 'health', hosts: [...hosts].length })
      }, () => {})()
    }, this.healthIntervalMs)
    if (this.healthTimer.unref) this.healthTimer.unref()
  }

  startWatch() {
    if (this.watchTimer || !this.watchIntervalMs) return
    this.watchTimer = setInterval(() => {
      void safe(() => this.recheck(), () => {})()
    }, this.watchIntervalMs)
    if (this.watchTimer.unref) this.watchTimer.unref()
  }

  // ── 自愈 ─────────────────────────────────────────────────────────────────

  /**
   * 自检并修复「上一次没撤干净」的现场。
   *
   * 场景：DSH 被强杀（或某个未捕获异常把进程带走了），hosts 留在接管态而 443 上
   * 已经没有人监听 —— 这时全系统的 GitHub 会变成 `ECONNREFUSED 127.0.0.x:443`，
   * 比不加速还糟，而且没有任何提示。所以插件每次装载都要先看一眼状态文件。
   */
  repairIfStale() {
    /* 不是主人的实例（测试 / 工具）连读都不读，更不会去动系统级的东西。 */
    if (!this.persistState) return []
    const state = readState()
    const notes = []
    if (!state) {
      /* 没有状态文件但 hosts 里有我们的块：可能是更老的版本留下的。
         这种情况要**记住它**（legacyActive），因为那说明用户本来就在用加速 ——
         升上来不该让他的开关悄悄变成「关」。 */
      if (this.hosts.isApplied()) {
        this.legacyActive = true
        const removed = this.hosts.remove()
        if (removed.changed) this.flushDnsIfOwner()
        notes.push({ action: 'removed-orphan-hosts', ok: removed.ok })
      }
      /* 系统代理里可能也留着我们的 PAC。 */
      const restored = this.restoreSysproxy()
      if (restored.changed) notes.push({ action: 'restored-sysproxy', ok: restored.ok })
      return notes
    }
    if (state.pid && state.pid !== process.pid && pidAlive(state.pid)) {
      notes.push({ action: 'kept-live-owner', pid: state.pid })
      return notes
    }
    this.record({ event: 'repair-stale', previousPid: state.pid, domains: state.domains?.length ?? 0 })
    const removed = this.hosts.remove()
    notes.push({ action: 'removed-stale-hosts', ok: removed.ok, reason: removed.reason })
    if (removed.changed) this.flushDnsIfOwner()
    const restored = this.restoreSysproxy()
    if (restored.changed) notes.push({ action: 'restored-sysproxy', ok: restored.ok })
    this.dropState()
    return notes
  }

  /**
   * 装载时的入口：修残局 → 按上次的开关状态自动恢复。
   * 之所以要自动恢复：退出钩子会在 DSH 退出时撤掉 hosts（那是对的，否则 GitHub 会被指到
   * 一个没有服务的地址），但如果不在下次启动时接回来，用户就会觉得「重启一次就失效了」。
   */
  async bootstrap({ pac } = {}) {
    const repaired = this.repairIfStale()
    this.installExitHook()
    const prefs = this.loadPrefs()
    /* 老版本（没有 prefs.json）留下的接管块被清掉了 —— 那说明用户本来就在用，
       升级不该把他的开关悄悄变成「关」。 */
    const wantOn = prefs.enabled === undefined ? this.legacyActive === true : prefs.enabled === true
    if (!wantOn) return { repaired, resumed: false, legacy: Boolean(this.legacyActive) }
    try {
      const report = await this.start({ mode: prefs.mode ?? 'both', pac: pac ?? prefs.pac ?? this.pacPolicy })
      return { repaired, resumed: true, legacy: prefs.enabled === undefined, report }
    } catch (error) {
      this.lastError = `bootstrap: ${error?.message ?? error}`
      return { repaired, resumed: false, error }
    }
  }

  /**
   * 进程退出时撤掉接管。**必须是同步的** —— `exit` 事件里没有异步机会。
   * 这不能替代哨兵机制（强杀时根本不触发），但能覆盖正常退出与 `process.exit()`。
   */
  installExitHook() {
    if (this.exitHookInstalled) return
    this.exitHookInstalled = true
    process.on('exit', () => {
      /*
       * 只有「这一轮是我们自己写进去的」才允许撤。
       * 否则开了第二个 DSH 实例时，先退出的那个会把另一个实例正在用的 hosts 块删掉 ——
       * 于是活着的那份隧道瞬间失去所有浏览器流量来源，表现成「莫名就不加速了」。
       */
      if (!this.oursApplied) return
      try {
        if (this.hosts.isApplied()) this.hosts.remove()
      } catch {}
      try {
        this.restoreSysproxy()
      } catch {}
      try {
        this.dropState()
      } catch {}
    })
  }

  // ── 系统级共享状态的「主人」门闸 ──────────────────────────────────────────
  //
  // 下面这几个包装是**必须**的：prefs.json / active.json / 系统代理 / DNS 缓存
  // 都属于「一个进程里只能有一个主人」的资源。测试、doctor、bench、live-check
  // 都会 new 一个 Accelerator —— 没有这道门闸时，它们随手一次 stop() 就能把真插件
  // 的 prefs 改成 enabled:false（下次 DSH 重启不再自动加速）并删掉崩溃哨兵。

  saveState(value) {
    if (this.persistState) writeState(value)
  }
  dropState() {
    if (this.persistState) clearState()
  }
  savePrefs(value) {
    if (this.persistState) writePrefs(value)
  }
  loadPrefs() {
    return this.persistState ? readPrefs() : {}
  }
  flushDnsIfOwner() {
    if (this.persistState) flushDns()
  }
  restoreSysproxy() {
    if (!this.persistState) return { ok: true, changed: false, reason: 'not-owner' }
    return disableAutoConfig()
  }

  // ── 开关 ─────────────────────────────────────────────────────────────────

  /**
   * 开启加速。
   *
   * 顺序很重要：
   *   1. 先修上一次的残局（repairIfStale）；
   *   2. 决定这一轮接管哪些域名（github.com 可选自适应）；
   *   3. 一域名一地址开监听，**记下哪些真的起来了**；
   *   4. 只把「监听确实起来了」的域名写进 hosts；
   *   5. 起代理（和 PAC，按策略）；
   *   6. 起健康循环 + 预热热域名。
   *
   * @param opts - { mode: 'hosts'|'proxy'|'both', writeHosts, pac }
   */
  async start({ mode = 'both', writeHosts = true, pac = this.pacPolicy, sniPort = this.sniPort, httpPort = this.httpPort } = {}) {
    const report = {
      mode,
      sni: [],
      http: [],
      proxy: null,
      pac: null,
      hosts: null,
      direct: null,
      skipped: [],
      repaired: [],
      timings: {},
    }
    const t0 = Date.now()
    this.mode = mode

    /* 幂等：先关掉上一轮可能还开着的监听与连接（否则重复 bind → EADDRINUSE）。 */
    this.tunnel.closeAll()
    this.proxy.close()
    this.pac.close()
    this.table.reset()
    this.pool.close()
    this.pool = new WarmPool({ keep: this.poolKeep, ttlMs: this.poolTtlMs })

    report.repaired = this.repairIfStale()
    report.timings.repairMs = Date.now() - t0

    if (mode === 'proxy' || mode === 'both') {
      report.proxy = await this.listenConnectProxy()
    }
    if (mode === 'proxy') {
      /* 纯代理模式也允许挂 PAC：那正是「写不了 hosts 也要覆盖浏览器」的用法。 */
      const wantPacHere = (pac === 'on' || (pac === 'auto' && this.pacPolicy === 'on')) && this.persistState
      if (wantPacHere && report.proxy?.ok) {
        const pacUp = await this.pac.listen()
        report.pac = pacUp.ok ? { ...pacUp, ...enableAutoConfig(pacUp.url) } : pacUp
        this.pacActive = report.pac.ok === true
      } else {
        report.pac = { ok: false, reason: pac === 'off' ? 'off' : 'not-needed' }
      }
      report.timings.totalMs = Date.now() - t0
      this.lastReport = report
      return report
    }

    /* 1) 要不要把交互式应用也放进隧道？先探一次**浏览器会用的那个地址**。
       注意：这里只能探 DNS 给的答案，不能带上我们的备用池 —— 备用池连通不代表
       浏览器连通（浏览器只有 DNS 那一个地址，没有我们的多候选切换）。 */
    const needProbe = this.autoApp && this.hijackApp === undefined && !this.excluded.includes(APP_DOMAIN)
    if (needProbe) {
      const dnsIps = await resolveRealIps(APP_DOMAIN, this.table.dnsCache, this.table.overrides).catch(() => [])
      report.direct = await probeDirect(APP_DOMAIN, dnsIps, this.directProbeTimeoutMs)
      this.directHealth = report.direct
      this.record({
        event: 'direct-probe',
        host: APP_DOMAIN,
        healthy: report.direct.healthy,
        ip: report.direct.ip,
        ms: report.direct.ms,
        scope: 'dns-only',
        tried: report.direct.tried,
      })
    }

    /* 2) 自动可选域名：只有在校验确实找到可用地址时才接管（例如 gist.github.com）。
       `github.io` / `pages.github.com` **不在这里** —— 它们是用户自己的站点，
       属于「显式 opt-in」，靠 DSH_GITHUB_ACCEL_INCLUDE 才会进来。 */
    const optionalOk = []
    for (const host of this.optional) {
      if (this.excluded.includes(host)) continue
      if (PROXY_ONLY_DOMAINS.includes(host)) continue
      const ips = await this.table.candidates(host).catch(() => [])
      if (ips.length === 0) {
        this.record({ event: 'optional-skip', host, why: 'no-candidates' })
        continue
      }
      const checks = await Promise.all(ips.slice(0, 2).map((ip) => validateEndpoint(ip, host).catch(() => undefined)))
      const good = checks.find((c) => c?.ok)
      this.counters.validations += checks.length
      checks.forEach((c, i) => c && this.table.recordValidation(host, ips[i], c))
      if (good) optionalOk.push(host)
      else this.record({ event: 'optional-skip', host, why: 'unreachable' })
    }

    /* opt-in 域名只有在被显式点名时才进来 —— 它们是用户自己的站点，不替用户做决定。 */
    const optInOk = []
    for (const host of this.optIn) {
      if (this.excluded.includes(host)) continue
      const ips = await this.table.candidates(host).catch(() => [])
      optInOk.push(host)
      this.record({ event: 'optin-include', host, candidates: ips.length })
    }

    const wanted = [...new Set([...this.domains, ...optionalOk, ...optInOk])].filter((d) => !this.excluded.includes(d))
    const decision = decideHijackDomains({
      domains: wanted,
      excluded: this.excluded,
      directHealthy: report.direct?.healthy === true,
      autoApp: this.autoApp,
      hijackApp: this.hijackApp,
    })
    this.skipped = decision.skipped

    if (decision.hijack.length === 0) {
      report.hosts = this.hosts.remove()
      this.dropState()
      this.hosts.domains = []
      this.startWatch()
      this.startHealthLoop()
      report.timings.totalMs = Date.now() - t0
      this.lastReport = report
      return report
    }

    /* 3) 开监听。先问一句「443/80 有没有人在服务」：Windows 的 SO_REUSEADDR 会让 bind
       假成功，真绑上去就会把别人（例如正在加速的 Steam++）的连接抢走。 */
    const sniBusy = await probePort(sniPort)
    this.hosts.domains = decision.hijack
    report.sni = sniBusy
      ? [{ ok: false, reason: 'port-taken', port: sniPort }]
      : await this.listenPerDomain({ port: sniPort, mode: 'sni' })
    const httpBusy = await probePort(httpPort)
    report.http = httpBusy
      ? [{ ok: false, reason: 'port-taken', port: httpPort }]
      : await this.listenPerDomain({ port: httpPort, mode: 'http' })
    report.timings.listenMs = Date.now() - t0

    /* 4) **只写监听确实起来了的域名**（老代码是「任一成功就全写」，一个域名挂掉会让
       全系统那个域名指到一个没人监听的地址）。 */
    const up = new Set(report.sni.filter((r) => r?.ok).map((r) => r.domain))
    const applicable = decision.hijack.filter((d) => up.has(d))
    const dropped = decision.hijack.filter((d) => !up.has(d))
    for (const d of dropped) this.skipped.push({ domain: d, reason: 'no-listener' })
    this.hosts.domains = applicable

    const sniOk = applicable.length > 0
    if (sniOk) {
      if (writeHosts) {
        report.hosts = { ...this.hosts.apply(), advertised: applicable.length, dropped }
        /* 改完 hosts 一定要清 DNS 缓存：Windows 客户端缓存里 hosts 条目是预载的，
           实测 `github.com` 的 TTL 能到 6.9 天，不清的话「开关点了没反应」。 */
        if (report.hosts.ok === true) report.hosts.flushed = this.flushDnsIfOwner()
      } else {
        report.hosts = { ok: false, reason: 'skipped' }
      }
    } else {
      report.hosts = { ok: false, reason: 'skipped-port-taken' }
    }

    /* 5) PAC：hosts 写不进去时浏览器就完全没有覆盖 —— 那时把它打开。
       'auto' 策略下只有 hosts 失败才启用；也允许强制 on/off。 */
    const wantPac = pac === 'on' || (pac === 'auto' && report.hosts?.ok !== true)
    if (wantPac && report.proxy?.ok && this.persistState) {
      const pacUp = await this.pac.listen()
      report.pac = pacUp.ok ? { ...pacUp, ...enableAutoConfig(pacUp.url) } : pacUp
      this.pacActive = report.pac.ok === true
    } else {
      this.pacActive = false
      report.pac = { ok: false, reason: wantPac && !this.persistState ? 'not-owner' : pac === 'off' ? 'off' : 'not-needed' }
      if (pac === 'off') this.restoreSysproxy()
    }

    if (report.hosts?.ok === true) {
      this.oursApplied = true
      this.saveState({ pid: process.pid, at: new Date().toISOString(), domains: applicable, addresses: this.hosts.addressMap })
    }
    if (report.pac?.ok === true) this.oursApplied = true

    /* 6) 健康循环 + 热域名预热。 */
    this.startWatch()
    this.startHealthLoop()
    for (const host of HOT_DOMAINS) {
      if (!applicable.includes(host)) continue
      void this.prefetch(host, 443)
    }
    report.timings.totalMs = Date.now() - t0
    this.lastReport = report
    this.savePrefs({ enabled: true, mode, pac })
    log('start done', JSON.stringify(report.timings))
    return report
  }

  /** 关闭：停监听 + 撤 hosts + 撤 PAC + 清缓存。 */
  async stop({ removeHosts = true } = {}) {
    if (this.watchTimer) {
      clearInterval(this.watchTimer)
      this.watchTimer = undefined
    }
    if (this.healthTimer) {
      clearInterval(this.healthTimer)
      this.healthTimer = undefined
    }
    this.tunnel.closeAll()
    this.proxy.close()
    this.pac.close()
    this.pool.close()
    this.table.reset()
    this.pacActive = false
    this.dropState()
    this.savePrefs({ enabled: false })
    const restored = this.restoreSysproxy()
    const removed = removeHosts ? this.hosts.remove() : { ok: true, changed: false }
    /* 撤掉接管同样要清缓存，否则浏览器还会继续往 127.0.0.x 打一段时间。 */
    if (removed.changed) removed.flushed = this.flushDnsIfOwner()
    this.oursApplied = false
    return { hosts: removed, sysproxy: restored }
  }

  // ── 诊断 ─────────────────────────────────────────────────────────────────

  /** 现场跑一次全链路自检，直接给结论。 */
  async diagnose() {
    const checks = []
    const push = (name, ok, detail) => checks.push({ name, ok, detail })

    push('hosts 接管块存在', this.hosts.isApplied(), this.hosts.path)
    const entries = this.hosts.currentEntries()
    push('hosts 条目指向本机回环地址', entries.every((e) => e.address.startsWith('127.')), `${entries.length} 条`)
    const foreign = this.hosts.detectForeign()
    push('hosts 里没有别的加速器接管块', foreign.length === 0, foreign.join(', ') || '（无）')

    const listening = this.tunnel.list.filter((l) => l.mode === 'sni')
    push('SNI 监听已就绪', listening.length > 0, `${listening.length} 个：${listening.map((l) => l.address).join(', ')}`)

    /* 每个条目都要有对应监听，否则那个域名会 CONNREFUSED。 */
    const orphan = entries.filter((e) => !listening.some((l) => l.address === e.address))
    push('每个 hosts 条目都有对应监听', orphan.length === 0, orphan.map((o) => o.domain).join(', ') || '（无）')

    const proxyOk = await probePort(this.proxyPort)
    push('CONNECT 代理在监听', proxyOk, `127.0.0.1:${this.proxyPort}`)

    const proxyState = readProxyState()
    push(
      'PAC（系统代理）状态',
      true,
      proxyState.autoConfigUrl.exists ? `AutoConfigURL=${proxyState.autoConfigUrl.value}` : '未启用',
    )

    /* 端到端：真的经隧道发一次请求。 */
    const targets = [APP_DOMAIN, 'api.github.com', 'github.githubassets.com', 'raw.githubusercontent.com']
    for (const host of targets) {
      const ips = await this.table.candidates(host).catch(() => [])
      const results = await Promise.all(ips.slice(0, 3).map((ip) => validateEndpoint(ip, host).catch(() => undefined)))
      const okList = results.filter((r) => r?.ok)
      push(
        `上游可达：${host}`,
        okList.length > 0,
        okList.length > 0
          ? `${okList.length}/${ips.slice(0, 3).length} 个候选可用，最快 ${Math.min(...okList.map((r) => r.tlsMs ?? 9e9))}ms`
          : `全部不可用：${ips.slice(0, 3).join(', ')}`,
      )
    }

    const verdict = checks.every((c) => c.ok)
    return { verdict, checks, at: new Date().toISOString() }
  }

  /** UI / 排查用的状态快照。 */
  status() {
    const overrides = this.table.overrides ?? {}
    const resolved = [...this.table.dnsCache.entries()].map(([host, v]) => ({
      host,
      ips: v.ips,
      candidates: withFallback(host, v.ips, this.table.fallbacks).length,
      used: this.table.lastUsed?.[host],
      good: v.good,
      ageMs: Date.now() - v.at,
      pinned: false,
    }))
    for (const [host, ip] of Object.entries(overrides)) {
      resolved.push({ host, ips: [ip], used: this.table.lastUsed?.[host], good: ip, ageMs: 0, pinned: true })
    }
    const stats = {}
    for (const [host, e] of this.perDomain) {
      const list = [...e.upstreamMs].sort((a, b) => a - b)
      stats[host] = {
        conns: e.conns,
        poolHits: e.pool,
        fails: e.fails,
        upstreamP50: list.length ? list[Math.floor(list.length * 0.5)] : null,
        upstreamP95: list.length ? list[Math.min(list.length - 1, Math.floor(list.length * 0.95))] : null,
      }
    }
    return {
      domains: this.domains.length,
      hostsDomains: this.hosts.safeDomains,
      proxyOnlyDomains: this.domains.filter((d) => PROXY_ONLY_DOMAINS.includes(d)),
      currentEntries: this.hosts.currentEntries(),
      hostsApplied: this.hosts.isApplied(),
      proxyPort: this.proxyPort,
      pacPort: this.pacPort,
      pacActive: this.pacActive,
      sniPort: this.sniPort,
      connections: this.tunnel.active?.size ?? 0,
      totalConnections: this.counters.tunnels,
      lastError: this.lastError,
      ipTtlMs: this.table.ttlMs,
      connectTimeoutMs: this.connectTimeoutMs,
      raceWidth: this.raceWidth,
      stallMs: this.stallMs,
      firstByteMs: this.firstByteMs,
      maxUpstreamAttempts: this.maxUpstreamAttempts,
      connectDeadlineMs: this.connectDeadlineMs,
      poolEnabled: this.poolEnabled,
      counters: { ...this.counters },
      pool: this.pool.snapshot(),
      stats,
      cooldownIps: this.table
        .snapshot()
        .filter((r) => r.coolingForMs > 0)
        .map((r) => ({ host: r.host, ip: r.ip, forMs: r.coolingForMs, lastError: r.lastError })),
      addressStats: this.table.snapshot(),
      pinned: Object.keys(overrides).length,
      resolved,
      /* 一域名一地址的映射（浏览器跨域复用就靠它失效）。 */
      addresses: this.hosts.addressMap,
      listeners: this.tunnel.list.concat(this.proxy.server ? [{ address: this.proxy.address, port: this.proxy.port, mode: 'proxy' }] : []),
      autoApp: this.autoApp,
      hijackApp: this.hijackApp,
      excluded: this.excluded,
      direct: this.directHealth,
      skipped: this.skipped,
      hostsIntegrity: this.hostsIntegrity,
      stateDir: STATE_DIR,
      foreignHostsBlocks: this.hosts.detectForeign(),
      /* 最近若干条隧道记录：出现异常时直接看这里。 */
      trace: this.trace.slice(-20),
    }
  }
}
