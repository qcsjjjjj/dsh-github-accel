/**
 * GitHub 候选地址大扫除。
 *
 * 目的：当「所有已知候选都 timeout」时，回答两个问题：
 *   1. 是**全部** GitHub 地址不通，还是只有我们池子里那几个不通？
 *   2. 有没有别的、能真正服务 `github.com` 的地址可以补进备用池？
 *
 * 判据分两层（和 server/net.js 的 validateEndpoint 一致）：
 *   - TCP 连得上；
 *   - TLS 握手成功且**校验证书**（rejectUnauthorized: true, servername = host）；
 *   - 真发一个 HEAD /，按域名核对状态码。
 *
 * 直接连 IP —— 完全绕开 hosts 与 DNS，所以结论是干净的。
 *
 * 用法：
 *   node recon/probe4-candidates.mjs                # 默认扫 github.com
 *   node recon/probe4-candidates.mjs api.github.com
 *   node recon/probe4-candidates.mjs raw.githubusercontent.com
 */
import net from 'node:net'
import tls from 'node:tls'

const host = process.argv[2] ?? 'github.com'
const CONNECT_TIMEOUT = 1800
const TLS_TIMEOUT = 5000

/** 公开的 GitHub 网段 + Watt Toolkit 线上表里给出的固定 IP（本机 DNS 不会给这些）。 */
function candidates() {
  const out = new Set()
  // GitHub 自己的边缘（DNS 给的就是这一段）
  for (const last of [160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170]) out.add(`20.205.243.${last}`)
  // GitHub 在美国/欧洲的边缘，历史 A 记录
  for (const c of [112, 113, 114, 115, 116, 121]) for (const last of [3, 4, 5, 6, 9, 22, 25, 26, 29]) out.add(`140.82.${c}.${last}`)
  // GitHub Pages / Fastly（githubusercontent / githubassets 用）
  for (const c of [108, 109, 110, 111]) for (const last of [133, 153, 154, 215]) out.add(`185.199.${c}.${last}`)
  // 老 GitHub 网段
  for (const last of [1, 2, 3, 4, 5]) out.add(`192.30.255.${last}`)
  // Watt Toolkit 线上加速表里写的固定 IP（和我们 DNS 给的完全不同，值得一试）
  out.add('20.207.73.82') // 它表里的 github.com
  out.add('23.235.37.133') // 它表里的 githubusercontent.com
  out.add('20.43.185.14') // 它表里的 github.dev
  out.add('140.82.112.29') // 它表里的 githubapp.com
  return [...out]
}

function tcp(ip) {
  return new Promise((resolve) => {
    const t0 = Date.now()
    const s = net.connect(443, ip)
    let done = false
    const fin = (ok, why) => {
      if (done) return
      done = true
      try {
        s.destroy()
      } catch {}
      resolve({ ok, why, ms: Date.now() - t0 })
    }
    s.setTimeout(CONNECT_TIMEOUT)
    s.once('connect', () => fin(true))
    s.once('error', (e) => fin(false, e.code ?? e.message))
    s.once('timeout', () => fin(false, 'timeout'))
  })
}

function tlsHttp(ip, servername) {
  return new Promise((resolve) => {
    const out = { tls: false, tlsMs: null, status: null, why: null, san: null, server: null }
    const s = tls.connect({ host: ip, port: 443, servername, rejectUnauthorized: true })
    let done = false
    const fin = (why) => {
      if (done) return
      done = true
      out.why = out.why ?? why ?? null
      try {
        s.destroy()
      } catch {}
      resolve(out)
    }
    s.setTimeout(TLS_TIMEOUT)
    s.once('secureConnect', () => {
      out.tls = true
      out.tlsMs = Date.now()
      try {
        const c = s.getPeerCertificate()
        out.san = c?.subjectaltname ?? null
      } catch {}
      s.write(`HEAD / HTTP/1.1\r\nHost: ${servername}\r\nUser-Agent: dsh-probe\r\nConnection: close\r\n\r\n`)
    })
    s.on('data', (chunk) => {
      const t = chunk.toString('latin1')
      const m = t.match(/^HTTP\/1\.[01] (\d{3})/)
      if (m) {
        out.status = Number(m[1])
        const sv = t.match(/^Server:\s*(.+)$/im)
        if (sv) out.server = sv[1].trim()
        fin(null)
      }
    })
    s.once('error', (e) => fin(e.code ?? e.message))
    s.once('timeout', () => fin('timeout'))
  })
}

const ips = candidates()
console.log(`扫描 ${ips.length} 个候选，目标 Host = ${host}（直连 IP，绕开 hosts 与 DNS）\n`)

const results = []
/* 并发 12：够快，又不会把这条本来就窄的链路打炸。 */
const queue = [...ips]
const workers = Array.from({ length: 12 }, async () => {
  while (queue.length) {
    const ip = queue.shift()
    /* eslint-disable no-await-in-loop */
    const t = await tcp(ip)
    if (!t.ok) {
      results.push({ ip, tcp: false, why: t.why, ms: t.ms })
      continue
    }
    const h = await tlsHttp(ip, host)
    results.push({ ip, tcp: true, ms: t.ms, tls: h.tls, tlsMs: h.tlsMs ? h.tlsMs - t.ms : null, status: h.status, server: h.server, why: h.why, san: h.san })
  }
})

await Promise.all(workers)

results.sort((a, b) => Number(b.tls) - Number(a.tls) || a.ms - b.ms)

console.log('状态   IP                 TCP     TLS        HTTP   Server')
console.log('─'.repeat(88))
for (const r of results) {
  const verdict = r.tls ? '✅通  ' : r.tcp ? 'TLS✗  ' : 'TCP✗  '
  console.log(
    `${verdict} ${r.ip.padEnd(18)} ${String(r.ms + 'ms').padEnd(7)} ${String(r.tlsMs !== null && r.tlsMs !== undefined ? Math.round(r.tlsMs) + 'ms' : '-').padEnd(10)} ${String(r.status ?? '-').padEnd(6)} ${r.server ?? r.why ?? ''}`,
  )
}

const tcpOk = results.filter((r) => r.tcp)
const tlsOk = results.filter((r) => r.tls && accepted(r.status))
const wrongHost = results.filter((r) => r.tls && !accepted(r.status))

function accepted(status) {
  const table = {
    'github.com': [200, 301, 302],
    'api.github.com': [200, 301, 302, 403],
    'codeload.github.com': [200, 301, 302, 404],
    'github.githubassets.com': [200, 301, 302, 404],
  }
  return (table[host] ?? [200, 301, 302, 401, 403, 404, 405]).includes(status)
}

console.log(`\n汇总：TCP 通 ${tcpOk.length}/${results.length}   TLS 通 ${results.filter((r) => r.tls).length}   真正服务该 Host 的 ${tlsOk.length}`)
if (tlsOk.length) {
  console.log('\n★ 可用地址（可以直接补进 server/net.js 的 FALLBACK_IPS）：')
  for (const r of tlsOk) console.log(`    ${r.ip}   tcp ${r.ms}ms  tls ${Math.round(r.tlsMs)}ms  http ${r.status}`)
}
if (wrongHost.length) {
  console.log('\n能握手但不服务这个 Host（状态码/内容不对，不能进池子）：')
  for (const r of wrongHost) console.log(`    ${r.ip}  http ${r.status}`)
}
if (!tcpOk.length) console.log('\n所有候选 TCP 都连不上 → 这台机器此刻到 GitHub 是整体不通，不是选路问题。')
