/**
 * 网络层：候选地址 / 端到端校验 / 打分与冷却 / 并行竞速 / 预热池。
 *
 * 这一层回答一个问题：**「这一次连接，应该连哪个地址？」**
 *
 * 老实现的三处不足（都有实测证据，见 docs/PLAN-2026-09-25.md）：
 *
 * 1. 只按 **TCP 能不能连上** 判好坏 —— 实测 `github.com` 的 5 个候选里有 3 个
 *    「TCP 通、TLS 握手也通，但真发 HTTP 请求就 timeout」，而 `20.205.243.168`
 *    （api 的地址）对 `SNI=github.com` 握手成功却回 400。所以必须**端到端校验**：
 *    校验证书的 TLS 握手 + 真发一个 HEAD 看有没有响应。
 * 2. **串行试错**，单址 6 s —— 最坏 5×6 = 30 s。改成 **happy-eyeballs 并行竞速**：
 *    同时向 2 个候选发起连接，先连上的赢，整体预算 4 s。
 * 3. **每次连接都要现连上游**。浏览器每开一条新连接就要多等一个上游 RTT，
 *    实测经隧道 TLS 0.67–3.38 s（直连只要 0.42–0.63 s）。加**预热池**：
 *    热域名常备 1–2 条空闲的上游连接，客户端一连上就 pop 出来用。
 */
import net from 'node:net'
import dns from 'node:dns'
import tls from 'node:tls'
import https from 'node:https'

// ── 常量 ───────────────────────────────────────────────────────────────────

/** 解析缓存的存活时间。必须过期：DNS 偶尔会给到被污染的答案。 */
export const IP_TTL_MS = Number(process.env.DSH_GITHUB_ACCEL_IP_TTL_MS ?? 60_000)

/** 候选地址上一次「端到端校验通过」的有效期。 */
export const VALIDATE_TTL_MS = Number(process.env.DSH_GITHUB_ACCEL_VALIDATE_TTL_MS ?? 600_000)

/** GitHub 常用网段：只用来排序（把明显不像 GitHub 的答案挪到最后），不用来丢弃。 */
export const GITHUB_IP_PREFIXES = ['20.205.243.', '140.82.', '185.199.', '192.30.255.', '20.27.', '20.29.', '4.237.']

export function likelyGithubIp(ip) {
  return GITHUB_IP_PREFIXES.some((prefix) => ip.startsWith(prefix))
}

/** 是不是 GitHub 自己的域名。 */
export function isGithubDomain(host) {
  if (typeof host !== 'string') return false
  return (
    host === 'github.com' ||
    host === 'ghcr.io' ||
    host.endsWith('.github.com') ||
    host.endsWith('.githubusercontent.com')
  )
}

/**
 * 静态兜底池 —— **每一行都经过本机实测**（2026-09-25，`recon/probe.mjs`）。
 *
 * 分域名列，跨域名只做「提升优先级」，绝不引进别的域名的专属地址：
 * 实测 `20.205.243.168` 对 `SNI=github.com` 握手能过但 HTTP 回 400。
 *
 * 没进池子的地址都是有理由的，别往里加：
 *   - `140.82.114.4` / `140.82.121.4`：TCP/TLS 都通，但 `Host: github.com` 请求 timeout。
 *   - `gist.github.com`：系统 DNS 被污染（37.61.54.158），池里 4 个地址也全部 ECONNRESET/timeout
 *     → 池子故意留空，靠运行时校验决定要不要接管。
 */
export const FALLBACK_IPS = {
  'github.com': ['20.205.243.166', '140.82.113.4', '140.82.112.4'],
  'api.github.com': ['20.205.243.168', '140.82.113.6', '140.82.112.6', '20.205.243.166'],
  'codeload.github.com': ['20.205.243.165', '140.82.113.9', '140.82.112.9'],
  'uploads.github.com': ['20.205.243.161'],
  'collector.github.com': ['140.82.114.22', '20.205.243.166'],
  'alive.github.com': ['140.82.114.26', '20.205.243.166'],
  'github.githubassets.com': [
    '185.199.111.215',
    '185.199.110.215',
    '185.199.108.215',
    '185.199.109.215',
    '185.199.111.154',
    '185.199.108.154',
    '185.199.109.154',
    '185.199.110.154',
  ],
  'npm.pkg.github.com': ['20.205.243.164'],
  'ghcr.io': ['20.205.243.164'],
  'raw.githubusercontent.com': ['185.199.108.133', '185.199.109.133', '185.199.110.133', '185.199.111.133'],
  'objects.githubusercontent.com': ['185.199.108.133', '185.199.109.133', '185.199.110.133', '185.199.111.133'],
  'release-assets.githubusercontent.com': ['185.199.108.133', '185.199.109.133', '185.199.110.133', '185.199.111.133'],
  'avatars.githubusercontent.com': ['185.199.108.133', '185.199.109.133', '185.199.110.133', '185.199.111.133'],
  'user-images.githubusercontent.com': ['185.199.108.133', '185.199.109.133', '185.199.110.133', '185.199.111.133'],
  'gist.githubusercontent.com': ['185.199.108.133', '185.199.109.133', '185.199.110.133', '185.199.111.133'],
  'camo.githubusercontent.com': ['185.199.108.133', '185.199.109.133', '185.199.110.133', '185.199.111.133'],
  'pkg-containers.githubusercontent.com': ['185.199.108.154', '185.199.109.154', '185.199.110.154', '185.199.111.154'],
  'gist.github.com': [],
}

/** 逗号分隔的列表（环境变量用）。 */
export function parseList(text) {
  if (!text) return []
  return String(text)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
}

/** 手工钉住的 IP 表：`github.com=20.205.243.166,api.github.com=...`。 */
export function parseOverrides(text) {
  const out = {}
  if (!text) return out
  for (const piece of String(text).split(',')) {
    const [host, ip] = piece.split('=')
    if (host && ip && host.trim() && ip.trim()) out[host.trim()] = ip.trim()
  }
  return out
}

/** 合并解析结果与备用池（去重；上次成功过的地址提到最前）。 */
export function withFallback(host, ips, fallbacks = FALLBACK_IPS, good) {
  const extra = fallbacks[host] ?? []
  const merged = [...ips, ...extra.filter((ip) => !ips.includes(ip))]
  if (good && merged.includes(good)) return [good, ...merged.filter((ip) => ip !== good)]
  return merged
}

// ── DNS ────────────────────────────────────────────────────────────────────

/**
 * 解析域名到真实 IP（`dns.resolve4` **绕过 hosts** —— 这正是本方案能工作的原因：
 * hosts 把域名指向 127.0.0.x，而 resolve4 直接问 DNS 拿真地址）。
 */
export function resolveRealIps(host, cache, overrides = {}, ttlMs = IP_TTL_MS) {
  if (overrides[host]) return Promise.resolve([overrides[host]])
  const hit = cache && cache.get(host)
  const order = (ips) => {
    if (!hit || !hit.good || !ips.includes(hit.good)) return ips
    return [hit.good, ...ips.filter((ip) => ip !== hit.good)]
  }
  if (hit && Date.now() - hit.at < ttlMs) return Promise.resolve(order(hit.ips))
  return new Promise((resolve, reject) => {
    dns.resolve4(host, (err, addrs) => {
      if (err || !addrs || addrs.length === 0) {
        /* 解析失败时退回上一次的答案（哪怕过期），总比直接断掉好。 */
        if (hit) return resolve(order(hit.ips))
        return reject(err ?? new Error(`no A record for ${host}`))
      }
      if (cache) cache.set(host, { ips: addrs, at: Date.now(), good: hit ? hit.good : undefined })
      resolve(order(addrs))
    })
  })
}

/**
 * 可选 DoH。
 *
 * **默认关闭**，而且不把它当命脉：本机实测 Cloudflare / Google / Quad9 的 DoH 全部
 * timeout，只有 `doh.pub` 可用，而它对 `github.com` 给出的答案与系统 DNS **完全相同**。
 * 也就是说在这台网络上 DoH 提供不了「更多候选」，只能作为「系统 DNS 明显被污染时」
 * 的补充来源（例如 gist.github.com）。
 */
export const DOH_ENDPOINT = process.env.DSH_GITHUB_ACCEL_DOH ?? ''

export function dohResolve(host, endpoint = DOH_ENDPOINT, timeoutMs = 5000) {
  if (!endpoint) return Promise.resolve([])
  return new Promise((resolve) => {
    let settled = false
    const done = (v) => {
      if (settled) return
      settled = true
      resolve(v)
    }
    const timer = setTimeout(() => done([]), timeoutMs)
    if (timer.unref) timer.unref()
    const req = https.request(
      `${endpoint}?name=${encodeURIComponent(host)}&type=A`,
      { headers: { accept: 'application/dns-json' }, servername: new URL(endpoint).hostname },
      (res) => {
        let body = ''
        res.on('data', (c) => (body += c))
        res.on('end', () => {
          clearTimeout(timer)
          try {
            const json = JSON.parse(body)
            done((json.Answer ?? []).filter((a) => a.type === 1).map((a) => a.data))
          } catch {
            done([])
          }
        })
      },
    )
    req.on('error', () => {
      clearTimeout(timer)
      done([])
    })
    req.end()
  })
}

// ── 端口探测 ───────────────────────────────────────────────────────────────

/**
 * 探测某个本机端口是否已经有人在服务。
 *
 * 为什么不能靠 bind 判断：Windows 上别人 LISTEN 在 `0.0.0.0:443` 时，我们 bind
 * `127.0.0.1:443` 会「成功」，于是悄悄把本机那条路径抢过来，把正在工作的加速器打断。
 */
export function probePort(port, timeoutMs = 1500, address = '127.0.0.1') {
  return new Promise((resolve) => {
    const socket = net.connect(port, address)
    let done = false
    const finish = (answer) => {
      if (done) return
      done = true
      socket.destroy()
      resolve(answer)
    }
    socket.setTimeout(timeoutMs)
    socket.on('connect', () => finish(true))
    socket.on('error', () => finish(false))
    socket.on('timeout', () => finish(false))
  })
}

// ── 连通性 ─────────────────────────────────────────────────────────────────

/** 到某个地址做一次 TLS 握手，只关心「通不通」（校验证书）。 */
export function tlsReachable(ip, servername, timeoutMs = 4000) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host: ip, port: 443, servername, rejectUnauthorized: true })
    let settled = false
    const done = (ok, why) => {
      if (settled) return
      settled = true
      try {
        socket.destroy()
      } catch {}
      resolve({ ok, why })
    }
    socket.setTimeout(timeoutMs)
    socket.once('secureConnect', () => done(true))
    socket.once('error', (e) => done(false, e.code ?? e.message))
    socket.once('timeout', () => done(false, 'timeout'))
  })
}

/** 直连健康度：逐个试 TLS 握手。 */
export async function probeDirect(host, ips, timeoutMs = 4000) {
  const tried = []
  const started = Date.now()
  for (const ip of ips) {
    const r = await tlsReachable(ip, host, timeoutMs)
    tried.push({ ip, ok: r.ok, why: r.why })
    if (r.ok) return { healthy: true, ip, ms: Date.now() - started, tried }
  }
  return { healthy: false, ms: Date.now() - started, tried }
}

/** Fastly 之类的「这个边缘没有这个域名」页面的特征。 */
export function looksLikeWrongHost(text) {
  return /unknown domain|Fastly error|No such app|domain is not configured/i.test(text)
}

/**
 * 每个域名在根路径上发 `HEAD /` 时**可接受的状态码**。
 *
 * 这一层是用来挡住「能握手，但这个边缘不服务这个 Host」的地址的。实测（2026-09-25）：
 *
 *   Host: github.com  @ 20.205.243.168 -> 403      （api 的地址，不服务 github.com）
 *   Host: github.com  @ 20.205.243.165 -> 400      （codeload 的地址）
 *   Host: github.com  @ 140.82.112.4   -> 200      （真服务 github.com）
 *   Host: codeload.github.com @ 20.205.243.165 -> 301   （同一个地址对 codeload 是对的）
 *
 * 也就是说「同一个 IP 对不同 Host 的表现完全不同」，所以判定必须**按域名**来。
 * 只靠 TLS 握手是不够的：那几个错地址的握手全部能过。
 */
export const EXPECTED_STATUS = {
  'github.com': [200, 301, 302],
  'api.github.com': [200, 301, 302, 403],
  'codeload.github.com': [200, 301, 302, 404],
  'uploads.github.com': [200, 301, 302, 403],
  'github.githubassets.com': [200, 301, 302, 404],
  'npm.pkg.github.com': [200, 301, 302, 403, 405],
  'ghcr.io': [200, 301, 302, 401, 403, 405],
}

/** 没在表里的域名：任何非 5xx 的响应都算「这个边缘在应答」。 */
export const DEFAULT_STATUS = [200, 301, 302, 401, 403, 404, 405]

export function acceptableStatus(host, status) {
  if (typeof status !== 'number' || status <= 0) return false
  return (EXPECTED_STATUS[host] ?? DEFAULT_STATUS).includes(status)
}

/**
 * **端到端校验**：这个地址到底能不能服务这个域名？
 *
 * 两步，缺一不可：
 *   ① TLS 握手且**校验证书**（`rejectUnauthorized: true` + `servername = host`）
 *      —— 证明它确实持有这个域名的证书；
 *   ② 真发一个 HTTP 请求，必须拿到响应 —— 证明这个边缘确实服务这个 Host。
 *
 * 只有 ① 是不够的：实测 api 的 `20.205.243.168` 对 `SNI=github.com` 握手成功，
 * 但真发请求回 400。
 *
 * @returns {{ok, tlsMs, ttfbMs, status, why}}
 */
export function validateEndpoint(ip, host, { timeoutMs = 6000, port = 443, path = '/' } = {}) {
  return new Promise((resolve) => {
    const started = process.hrtime.bigint()
    const out = { ip, host, ok: false, tlsMs: null, ttfbMs: null, status: null, why: null }
    let socket
    try {
      socket = tls.connect({ host: ip, port, servername: host, rejectUnauthorized: true })
    } catch (error) {
      out.why = `throw:${error.message}`
      return resolve(out)
    }
    let done = false
    const finish = (why) => {
      if (done) return
      done = true
      out.why = out.why ?? why ?? null
      try {
        socket.destroy()
      } catch {}
      resolve(out)
    }
    socket.setTimeout(timeoutMs)
    socket.once('secureConnect', () => {
      out.tlsMs = Math.round(Number(process.hrtime.bigint() - started) / 1e6)
      socket.write(
        `HEAD ${path} HTTP/1.1\r\n` +
          `Host: ${host}\r\n` +
          `User-Agent: dsh-github-accel/validate\r\n` +
          `Accept: */*\r\n` +
          `Connection: close\r\n\r\n`,
      )
    })
    let body = ''
    socket.on('data', (chunk) => {
      if (out.status !== null) return
      body += chunk.toString('latin1', 0, Math.min(chunk.length, 1024))
      const m = body.match(/^HTTP\/1\.[01] (\d{3})/)
      if (!m) return
      out.ttfbMs = Math.round(Number(process.hrtime.bigint() - started) / 1e6)
      out.status = Number(m[1])
      if (looksLikeWrongHost(body)) {
        out.why = 'wrong-host'
        return finish('wrong-host')
      }
      if (!acceptableStatus(host, out.status)) {
        out.why = `unexpected-status:${out.status}`
        return finish(out.why)
      }
      out.ok = true
      finish(null)
    })
    socket.once('error', (e) => finish(e.code ?? e.message))
    socket.once('timeout', () => finish('timeout'))
  })
}

// ── 连接 ───────────────────────────────────────────────────────────────────

/** 一条已经连上的上游连接还能不能用。 */
export function isUsable(socket) {
  return Boolean(socket) && socket.destroyed === false && socket.writable === true && socket.readableEnded !== true
}

/**
 * Happy-eyeballs 竞速连接：同时向最多 `width` 个候选发起 TCP 连接，**先连上的赢**。
 *
 * 为什么必须并行：GitHub 的 A 记录里常有在特定网络下不可达的地址（实测
 * `github.com` 的 5 个候选里 3 个连得上但不服务内容），串行试错在单址 6 s 的超时下
 * 最坏要等 30 s。并行 + 短超时把最坏情况压到 `totalMs`。
 *
 * @returns {{socket, ip, tried, raceMs}}
 */
export function raceConnect({
  host,
  port = 443,
  ips,
  width = 2,
  perTimeoutMs = 1800,
  staggerMs = 250,
  totalMs = 4500,
} = {}) {
  return new Promise((resolve, reject) => {
    const list = (ips ?? []).filter(Boolean)
    const tried = []
    const startedAt = Date.now()
    const inflight = new Set()
    let next = 0
    let settled = false
    let deadline
    let timer

    const cleanup = () => {
      clearTimeout(deadline)
      clearTimeout(timer)
      timer = undefined
    }
    const failAll = () => {
      if (settled) return
      settled = true
      cleanup()
      for (const s of inflight) {
        try {
          s.destroy()
        } catch {}
      }
      inflight.clear()
      const error = new Error(`all ${list.length} addresses failed for ${host}: ${tried.join(', ')}`)
      error.tried = tried
      reject(error)
    }
    const win = (socket, ip) => {
      if (settled) return
      settled = true
      cleanup()
      for (const s of inflight) {
        if (s === socket) continue
        try {
          s.destroy()
        } catch {}
      }
      inflight.clear()
      resolve({ socket, ip, tried, raceMs: Date.now() - startedAt })
    }

    const start = (ip) => {
      const socket = net.connect({ host: ip, port })
      inflight.add(socket)
      let closed = false
      const drop = (why) => {
        if (closed) return
        closed = true
        inflight.delete(socket)
        if (!settled) tried.push(`${ip}(${why})`)
        try {
          socket.destroy()
        } catch {}
      }
      socket.setTimeout(perTimeoutMs)
      socket.once('connect', () => {
        closed = true
        socket.setTimeout(0)
        win(socket, ip)
      })
      socket.once('error', (e) => {
        drop(e.code ?? e.message)
        schedule()
      })
      socket.once('timeout', () => {
        drop('timeout')
        schedule()
      })
      socket.once('close', () => {
        inflight.delete(socket)
      })
    }

    /**
     * 把在途连接补到 width 条。
     * 第一个候选立刻发；第二个及以后要等 staggerMs —— 避免第一个明明能连上却白付一次握手。
     * 任何一个失败都立刻顶上下一个（不再等 stagger），保证「在途条数」始终填满。
     */
    function schedule() {
      if (settled) return
      while (next < list.length && inflight.size < width && (next === 0 || Date.now() - startedAt >= staggerMs)) {
        start(list[next])
        next += 1
      }
      if (settled) return
      if (next < list.length && inflight.size < width && !timer) {
        timer = setTimeout(() => {
          timer = undefined
          schedule()
        }, Math.max(1, staggerMs - (Date.now() - startedAt)))
      }
      if (inflight.size === 0 && next >= list.length) failAll()
    }

    if (list.length === 0) return failAll()
    deadline = setTimeout(() => failAll(), totalMs)
    schedule()
  })
}

/**
 * 兼容旧 API：依次尝试候选地址，返回第一个连上的 socket。
 * 内部走 raceConnect（width=1 时行为与老实现一致，但超时更短）。
 */
export function connectAny({ host, port, ips, timeoutMs = 1800, width = 2 }) {
  return raceConnect({ host, port, ips, width, perTimeoutMs: timeoutMs, totalMs: Math.max(timeoutMs * 2, 4000) })
}

// ── 预热池 ─────────────────────────────────────────────────────────────────

/**
 * 预热池：热域名常备若干条**已经连上的空闲上游连接**。
 *
 * 为什么值：经隧道 TLS 的耗时 = 「上游 TCP 往返」+「上游 TLS 处理」。
 * 直连时前者与 TCP 三次握手合并，我们却在收到 ClientHello **之后**才开始连上游，
 * 于是白白多出一个 RTT（实测 0.67–3.38 s 的抖动主要来自这里）。池里有现货时，
 * 客户端一连上就能立刻把 ClientHello 转发出去。
 */
export class WarmPool {
  constructor({ keep = 2, ttlMs = 8000 } = {}) {
    this.keep = keep
    this.ttlMs = ttlMs
    this.entries = new Map()
    this.pending = new Map()
    this.hits = 0
    this.misses = 0
    this.closing = false
  }

  /** 取一条现成的上游连接；没有就返回 undefined（调用方去现连）。 */
  take(host) {
    const list = this.entries.get(host)
    if (!list || list.length === 0) {
      this.misses += 1
      return undefined
    }
    while (list.length > 0) {
      const entry = list.pop()
      if (isUsable(entry.socket) && Date.now() - entry.at < this.ttlMs) {
        this.hits += 1
        return entry
      }
      try {
        entry.socket.destroy()
      } catch {}
    }
    this.misses += 1
    return undefined
  }

  /**
   * 补充一条（异步、后台）。`connect` 必须返回 `{ socket, ip }`。
   * 同一个域名同时只补一条，避免把候选地址打爆。
   */
  refill(host, connect) {
    if (this.closing) return Promise.resolve()
    const list = this.entries.get(host) ?? []
    if (list.length >= this.keep) return Promise.resolve()
    if (this.pending.has(host)) return this.pending.get(host)
    const task = (async () => {
      try {
        const { socket, ip } = await connect()
        if (this.closing || !isUsable(socket)) {
          try {
            socket.destroy()
          } catch {}
          return
        }
        const entry = { socket, at: Date.now(), ip }
        const drop = () => {
          const l = this.entries.get(host)
          if (!l) return
          const i = l.indexOf(entry)
          if (i >= 0) l.splice(i, 1)
        }
        socket.on('close', drop)
        socket.on('error', () => {})
        socket.on('timeout', drop)
        const l = this.entries.get(host) ?? []
        l.push(entry)
        this.entries.set(host, l)
      } catch {
        /* 补货失败无所谓，连接路径会自己现连。 */
      } finally {
        this.pending.delete(host)
      }
    })()
    this.pending.set(host, task)
    return task
  }

  snapshot() {
    const out = {}
    for (const [host, list] of this.entries) {
      out[host] = list.filter((e) => isUsable(e.socket)).length
    }
    return { warm: out, hits: this.hits, misses: this.misses }
  }

  /** 清掉过期/已经不可用的现货，避免一直占着内存与上游连接。 */
  sweep() {
    const now = Date.now()
    for (const [host, list] of this.entries) {
      const keep = []
      for (const entry of list) {
        if (isUsable(entry.socket) && now - entry.at < this.ttlMs) {
          keep.push(entry)
          continue
        }
        try {
          entry.socket.destroy()
        } catch {}
      }
      if (keep.length) this.entries.set(host, keep)
      else this.entries.delete(host)
    }
  }

  close() {
    this.closing = true
    for (const list of this.entries.values()) {
      for (const entry of list) {
        try {
          entry.socket.destroy()
        } catch {}
      }
    }
    this.entries.clear()
    this.pending.clear()
  }
}

// ── 候选地址表：打分 + 冷却 ────────────────────────────────────────────────

/**
 * 每个域名的地址表现（打分 / 冷却 / 校验时间）。
 *
 * 与老实现的区别：
 *   - 成功不只是「记 good」，而是更新 EWMA 延迟（选路时按延迟排序，不是按出现顺序）；
 *   - 失败**不立刻拉黑**：软失败（客户端先断开、已经传过字节）只降权；
 *     硬失败（客户端没断且一个字节都没发出去）连续 2 次才进冷却，冷却时长指数退避；
 *   - 校验通过时间单独记（`validatedAt`），后台健康循环会刷新它。
 */
export class CandidateTable {
  constructor({
    fallbacks = FALLBACK_IPS,
    overrides = {},
    ttlMs = IP_TTL_MS,
    validateTtlMs = VALIDATE_TTL_MS,
    cooldownBaseMs = Number(process.env.DSH_GITHUB_ACCEL_COOLDOWN_MS ?? 30_000),
    cooldownMaxMs = Number(process.env.DSH_GITHUB_ACCEL_COOLDOWN_MAX_MS ?? 300_000),
    dohEndpoint = DOH_ENDPOINT,
  } = {}) {
    this.fallbacks = fallbacks
    this.overrides = overrides
    this.ttlMs = ttlMs
    this.validateTtlMs = validateTtlMs
    this.cooldownBaseMs = cooldownBaseMs
    this.cooldownMaxMs = cooldownMaxMs
    this.dohEndpoint = dohEndpoint

    /** host -> { ips, at, good } —— DNS 解析缓存（沿用老结构，resolveRealIps 直接改它）。 */
    this.dnsCache = new Map()
    /** host -> Map<ip, {ewmaMs, okN, failN, streak, cooldownUntil, validatedAt, lastError}> */
    this.stats = new Map()
    /** host -> 额外的 DoH 候选 */
    this.extra = new Map()
    this.lastUsed = {}
  }

  stat(host, ip) {
    let byIp = this.stats.get(host)
    if (!byIp) {
      byIp = new Map()
      this.stats.set(host, byIp)
    }
    let s = byIp.get(ip)
    if (!s) {
      s = { ip, ewmaMs: undefined, okN: 0, failN: 0, streak: 0, cooldownUntil: 0, validatedAt: 0, lastError: undefined }
      byIp.set(ip, s)
    }
    return s
  }

  /**
   * 记录一次真实连接的结果。
   *
   * 三种失败必须区分开，否则候选表要么学不到东西、要么乱拉黑：
   *
   *   hard  —— 上游**一个字节都没回**就直接报错（RST/ECONNRESET）。地址坏了。
   *   stall —— 上游**一个字节都没回**而且拖了很久（客户端最后自己放弃）。也是地址坏了。
   *            这一条是关键：黑洞型的坏地址不会报错，只会一直不出声 ——
   *            老代码只认「RST + 一个字节都没发出去」，于是这种地址**永远留在候选表最前面**，
   *            每次请求都先撞它一遍。这正是「GitHub 时好时坏」最直接的机制。
   *   soft  —— 已经传过字节了（浏览器关页面 / 取消请求）。不惩罚。
   */
  record(host, ip, { ok, ms, why, hard = false, stall = false } = {}) {
    if (!ip) return
    const s = this.stat(host, ip)
    if (ok) {
      s.okN += 1
      s.streak = 0
      s.cooldownUntil = 0
      s.lastError = undefined
      if (typeof ms === 'number' && ms > 0) s.ewmaMs = s.ewmaMs === undefined ? ms : Math.round(s.ewmaMs * 0.7 + ms * 0.3)
      s.validatedAt = s.validatedAt || Date.now()
      this.lastUsed[host] = ip
      return
    }
    s.failN += 1
    s.lastError = why
    if (stall) {
      /* 卡死一次就降权：客户端已经白等了 1.5 s 以上，代价比误判一个大得多。
         冷却短（base/2），真好的地址下一轮健康检查会立刻把它捞回来。 */
      s.streak += 1
      s.cooldownUntil = Date.now() + Math.max(15_000, Math.round(this.cooldownBaseMs / 2))
      const hit = this.dnsCache.get(host)
      if (hit && hit.good === ip) this.dnsCache.set(host, { ...hit, good: undefined })
      return
    }
    if (!hard) {
      /* 软失败：完全不动 streak，避免把好地址冤枉成坏地址。 */
      return
    }
    s.streak += 1
    if (s.streak >= 2) {
      const factor = Math.min(2 ** (s.streak - 2), 8)
      s.cooldownUntil = Date.now() + Math.min(this.cooldownBaseMs * factor, this.cooldownMaxMs)
      /* 冷却中的地址不能再当「上次成功的那个」。 */
      const hit = this.dnsCache.get(host)
      if (hit && hit.good === ip) this.dnsCache.set(host, { ...hit, good: undefined })
    }
  }

  /** 后台校验结果：好地址记延迟，坏地址直接进冷却（校验是端到端的，可信度高）。 */
  recordValidation(host, ip, result) {
    const s = this.stat(host, ip)
    if (result.ok) {
      s.validatedAt = Date.now()
      s.cooldownUntil = 0
      s.streak = 0
      const ms = result.tlsMs ?? result.ttfbMs
      if (typeof ms === 'number' && ms > 0) s.ewmaMs = s.ewmaMs === undefined ? ms : Math.round(s.ewmaMs * 0.6 + ms * 0.4)
      return
    }
    s.validatedAt = 0
    s.cooldownUntil = Date.now() + this.cooldownBaseMs
    s.lastError = result.why ?? 'validate-failed'
  }

  isCooling(host, ip) {
    return (this.stats.get(host)?.get(ip)?.cooldownUntil ?? 0) > Date.now()
  }

  isVerified(host, ip) {
    const s = this.stats.get(host)?.get(ip)
    return Boolean(s) && s.validatedAt > 0 && Date.now() - s.validatedAt < this.validateTtlMs
  }

  /**
   * 候选地址（排序后）。
   *
   * 顺序：pinned > 已验证（按 EWMA 延迟升序）> DNS 答案 > 备用池 > 冷却中的（垫底）
   *       > 明显不像 GitHub 的（最垫底）
   */
  async candidates(host) {
    let dnsIps = []
    try {
      dnsIps = await resolveRealIps(host, this.dnsCache, this.overrides, this.ttlMs)
    } catch {
      dnsIps = this.dnsCache.get(host)?.ips ?? []
    }
    if (this.dohEndpoint && dnsIps.length === 0) {
      const extra = await dohResolve(host, this.dohEndpoint)
      if (extra.length) this.extra.set(host, extra)
    }
    const total = withFallback(host, dnsIps, this.fallbacks, undefined)
    const all = [...new Set([...total, ...(this.extra.get(host) ?? [])])]
    const ranked = []
    for (const ip of all) {
      const s = this.stats.get(host)?.get(ip)
      ranked.push({
        ip,
        verified: Boolean(s) && s.validatedAt > 0 && Date.now() - s.validatedAt < this.validateTtlMs,
        cooling: this.isCooling(host, ip),
        ewma: s?.ewmaMs ?? Number.POSITIVE_INFINITY,
        best: s?.validatedAt ?? 0,
        likely: likelyGithubIp(ip),
        pinned: this.overrides[host] === ip,
      })
    }
    ranked.sort((a, b) => {
      if (a.pinned !== b.pinned) return a.pinned ? -1 : 1
      if (a.cooling !== b.cooling) return a.cooling ? 1 : -1
      if (a.verified !== b.verified) return a.verified ? -1 : 1
      if (a.likely !== b.likely) return a.likely ? -1 : 1
      if (a.ewma !== b.ewma) return a.ewma - b.ewma
      return 0
    })
    const out = ranked.map((r) => r.ip)
    /* 全在冷却里也要把候选交出去：宁可试一次，也不要直接失败。 */
    return out
  }

  /** 诊断快照。 */
  snapshot() {
    const rows = []
    for (const [host, byIp] of this.stats) {
      for (const s of byIp.values()) {
        rows.push({
          host,
          ip: s.ip,
          ok: s.okN,
          fail: s.failN,
          ewmaMs: s.ewmaMs,
          coolingForMs: Math.max(0, s.cooldownUntil - Date.now()),
          verifiedAgeMs: s.validatedAt ? Date.now() - s.validatedAt : null,
          lastError: s.lastError,
        })
      }
    }
    return rows
  }

  /** 网络变了（换了 Wi-Fi / 睡眠唤醒）→ 所有历史结论作废。 */
  reset() {
    this.dnsCache.clear()
    this.stats.clear()
    this.extra.clear()
    this.lastUsed = {}
  }
}
