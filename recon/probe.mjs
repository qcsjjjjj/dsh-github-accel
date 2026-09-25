/**
 * 只读勘察：把「这台网络上 GitHub 各域名 / 各候选地址」的真实现状量出来。
 *
 * 量四件事：
 *   1. 每个候选 IP 的 TCP 连接延迟（多次取最小，避开抖动）；
 *   2. 每个候选 IP 做完 TLS 握手 + 真发一个 HTTP 请求的端到端结果
 *      ——「TLS 通」不等于「这个边缘服务这个 Host」，必须看到真实响应头；
 *   3. 每个域名的证书 SAN —— 决定哪些域名可以共用回环地址（连接复用分组）；
 *   4. DNS 答案（系统解析器 vs 备用池）。
 *
 * 用法：node recon/probe.mjs [--json out.json]
 */
import net from 'node:net'
import tls from 'node:tls'
import dns from 'node:dns'
import fs from 'node:fs'

const DOMAINS = [
  'github.com',
  'api.github.com',
  'codeload.github.com',
  'github.githubassets.com',
  'uploads.github.com',
  'npm.pkg.github.com',
  'ghcr.io',
  'raw.githubusercontent.com',
  'objects.githubusercontent.com',
  'release-assets.githubusercontent.com',
  'avatars.githubusercontent.com',
  'user-images.githubusercontent.com',
  'pkg-containers.githubusercontent.com',
  'gist.githubusercontent.com',
  'gist.github.com',
  'camo.githubusercontent.com',
  'collector.github.com',
  'alive.github.com',
  'github.io',
  'pages.github.com',
]

/** 与 server/accel.js 的 FALLBACK_IPS 对齐（这里复制一份，recon 要独立于被测代码）。 */
const FALLBACK_IPS = {
  'github.com': ['20.205.243.166', '140.82.112.4', '140.82.113.4', '140.82.114.4', '140.82.121.4'],
  'api.github.com': ['20.205.243.168', '140.82.112.6', '140.82.113.6', '20.205.243.166'],
  'codeload.github.com': ['20.205.243.165', '140.82.112.9', '140.82.113.9'],
  'gist.github.com': ['20.205.243.166', '140.82.112.4', '140.82.113.4'],
  'github.githubassets.com': ['185.199.108.154', '185.199.109.154', '185.199.110.154', '185.199.111.154'],
  'raw.githubusercontent.com': ['185.199.108.133', '185.199.109.133', '185.199.110.133', '185.199.111.133'],
}

const CONNECT_TIMEOUT = Number(process.env.PROBE_CONNECT_TIMEOUT ?? 2500)
const CONNECT_ROUNDS = Number(process.env.PROBE_ROUNDS ?? 2)
const HTTP_TIMEOUT = Number(process.env.PROBE_HTTP_TIMEOUT ?? 6000)

function resolve4(host) {
  return new Promise((resolve) => dns.resolve4(host, (err, addrs) => resolve(err ? [] : addrs ?? [])))
}

/** 单次 TCP 连接耗时（毫秒）；失败返回 { ok:false, why }。 */
function tcpConnect(ip, port = 443, timeoutMs = CONNECT_TIMEOUT) {
  return new Promise((resolve) => {
    const started = process.hrtime.bigint()
    const socket = net.connect(port, ip)
    let done = false
    const finish = (ok, why) => {
      if (done) return
      done = true
      const ms = Number(process.hrtime.bigint() - started) / 1e6
      socket.destroy()
      resolve({ ok, why, ms: Math.round(ms) })
    }
    socket.setTimeout(timeoutMs)
    socket.once('connect', () => finish(true))
    socket.once('error', (e) => finish(false, e.code ?? e.message))
    socket.once('timeout', () => finish(false, 'timeout'))
  })
}

/** 多轮 TCP 连接，返回 { min, ok, fails }。 */
async function tcpProbe(ip) {
  const results = []
  for (let i = 0; i < CONNECT_ROUNDS; i += 1) results.push(await tcpConnect(ip))
  const ok = results.filter((r) => r.ok)
  return {
    minMs: ok.length ? Math.min(...ok.map((r) => r.ms)) : null,
    okCount: ok.length,
    rounds: results.length,
    fails: results.filter((r) => !r.ok).map((r) => r.why),
  }
}

/**
 * 端到端：到 ip 用 servername 完成 TLS 握手（**校验证书**），再真发一个 HTTP 请求。
 * 返回 status / server / 首字节耗时 / 证书 SAN / ALPN。
 */
function endToEnd(ip, servername, path = '/', timeoutMs = HTTP_TIMEOUT) {
  return new Promise((resolve) => {
    const started = process.hrtime.bigint()
    const out = { ip, servername, tlsMs: null, status: null, server: null, alpn: null, san: null, error: null, bytes: 0, ttfbMs: null }
    let socket
    try {
      socket = tls.connect({ host: ip, port: 443, servername, rejectUnauthorized: true, ALPNProtocols: ['http/1.1'] })
    } catch (error) {
      out.error = `connect-throw:${error.message}`
      return resolve(out)
    }
    let done = false
    const finish = (error) => {
      if (done) return
      done = true
      if (error) out.error = out.error ?? error
      try {
        socket.destroy()
      } catch {}
      resolve(out)
    }
    socket.setTimeout(timeoutMs)
    socket.once('secureConnect', () => {
      out.tlsMs = Math.round(Number(process.hrtime.bigint() - started) / 1e6)
      out.alpn = socket.alpnProtocol ?? null
      try {
        const cert = socket.getPeerCertificate()
        out.san = cert && cert.subjectaltname ? cert.subjectaltname : null
        out.issuer = cert && cert.issuer ? cert.issuer.O ?? cert.issuer.CN ?? null : null
      } catch {}
      const head =
        `HEAD ${path} HTTP/1.1\r\n` +
        `Host: ${servername}\r\n` +
        `User-Agent: dsh-github-accel-probe\r\n` +
        `Accept: */*\r\n` +
        `Connection: close\r\n\r\n`
      socket.write(head)
    })
    socket.on('data', (chunk) => {
      if (out.status === null) {
        out.ttfbMs = Math.round(Number(process.hrtime.bigint() - started) / 1e6)
        const text = chunk.toString('latin1')
        const m = text.match(/^HTTP\/1\.[01] (\d{3})/)
        out.status = m ? Number(m[1]) : -1
        const s = text.match(/^Server:\s*(.+)$/im)
        out.server = s ? s[1].trim() : null
        out.firstBytes = text.slice(0, 200)
        finish(null)
      }
    })
    socket.once('error', (e) => finish(e.code ?? e.message))
    socket.once('timeout', () => finish('timeout'))
  })
}

/** 并发跑一批任务。 */
async function pool(items, limit, worker) {
  const out = new Array(items.length)
  let cursor = 0
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const index = cursor
      cursor += 1
      if (index >= items.length) return
      out[index] = await worker(items[index], index)
    }
  })
  await Promise.all(runners)
  return out
}

const report = { at: new Date().toISOString(), connectTimeoutMs: CONNECT_TIMEOUT, domains: {} }

const resolved = {}
await pool(DOMAINS, 12, async (host) => {
  resolved[host] = await resolve4(host)
})

for (const host of DOMAINS) {
  const dnsIps = resolved[host] ?? []
  const extra = FALLBACK_IPS[host] ?? []
  const candidates = [...new Set([...dnsIps, ...extra])]
  report.domains[host] = { dnsIps, candidates: candidates.length, results: [] }
}

const jobs = []
for (const host of DOMAINS) {
  for (const ip of [...new Set([...(resolved[host] ?? []), ...(FALLBACK_IPS[host] ?? [])])]) {
    jobs.push({ host, ip })
  }
}
process.stderr.write(`probe: ${jobs.length} host/ip pairs\n`)

await pool(jobs, 16, async ({ host, ip }) => {
  const tcp = await tcpProbe(ip)
  const e2e = tcp.minMs === null ? { ip, servername: host, error: 'tcp-unreachable' } : await endToEnd(ip, host)
  report.domains[host].results.push({ ip, tcp, e2e })
})

/* ── 汇总输出 ─────────────────────────────────────────────────────────────── */
const lines = []
for (const host of DOMAINS) {
  const d = report.domains[host]
  lines.push(`\n### ${host}   dns=[${d.dnsIps.join(', ')}]`)
  const rows = d.results
    .slice()
    .sort((a, b) => (a.tcp.minMs ?? 9e9) - (b.tcp.minMs ?? 9e9))
    .map((r) => ({
      ip: r.ip,
      tcp: r.tcp.minMs === null ? `FAIL(${r.tcp.fails.join('/')})` : `${r.tcp.minMs}ms`,
      tls: r.e2e.tlsMs === null ? '-' : `${r.e2e.tlsMs}ms`,
      ttfb: r.e2e.ttfbMs === null ? '-' : `${r.e2e.ttfbMs}ms`,
      status: r.e2e.status === null ? '-' : r.e2e.status,
      server: r.e2e.server ?? '-',
      err: r.e2e.error ?? '',
    }))
  const w = [16, 16, 10, 10, 7, 22]
  lines.push(`  ${'ip'.padEnd(w[0])}${'tcp-min'.padEnd(w[1])}${'tls'.padEnd(w[2])}${'ttfb'.padEnd(w[3])}${'http'.padEnd(w[4])}${'server'.padEnd(w[5])}err`)
  for (const r of rows) {
    lines.push(
      `  ${r.ip.padEnd(w[0])}${String(r.tcp).padEnd(w[1])}${String(r.tls).padEnd(w[2])}${String(r.ttfb).padEnd(w[3])}${String(r.status).padEnd(w[4])}${String(r.server).padEnd(w[5])}${r.err}`,
    )
  }
  const s = d.results.find((r) => r.e2e.san)?.e2e.san
  if (s) lines.push(`  cert SAN: ${s}`)
}

process.stdout.write(`${lines.join('\n')}\n`)

/* 证书分组：哪些域名共享同一张证书 → 才可能被浏览器连接复用。 */
const SAN_GROUPS = {}
for (const host of DOMAINS) {
  const san = report.domains[host].results.find((r) => r.e2e.san)?.e2e.san
  if (!san) continue
  ;(SAN_GROUPS[san] ??= []).push(host)
}
process.stdout.write('\n### 证书 SAN 分组（同组 = 浏览器有复用前提）\n')
for (const [san, hosts] of Object.entries(SAN_GROUPS)) {
  const shared = hosts.length > 1 ? ' <-- 多个域名共享' : ''
  process.stdout.write(`  [${hosts.join(', ')}]${shared}\n      ${san}\n`)
}

const jsonIndex = process.argv.indexOf('--json')
const outPath = jsonIndex >= 0 ? process.argv[jsonIndex + 1] : 'recon/probe.json'
try {
  fs.writeFileSync(outPath, JSON.stringify(report, null, 2), 'utf8')
  process.stdout.write(`\nJSON -> ${outPath}\n`)
} catch (error) {
  process.stderr.write(`写 JSON 失败：${error.message}\n`)
}
