/**
 * 只读勘察 第二组：IPv6、DoH、被污染的 gist、证书与 QUIC 广告。
 * 用法：node recon/probe2.mjs
 */
import net from 'node:net'
import tls from 'node:tls'
import dns from 'node:dns'
import { request as httpsRequest } from 'node:https'

const line = (...a) => process.stdout.write(`${a.join(' ')}\n`)

function tcpConnect(ip, port = 443, timeoutMs = 4000) {
  return new Promise((resolve) => {
    const started = process.hrtime.bigint()
    const socket = net.connect({ host: ip, port, family: ip.includes(':') ? 6 : 4 })
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

function tlsProbe(ip, servername, timeoutMs = 6000) {
  return new Promise((resolve) => {
    const started = process.hrtime.bigint()
    const out = { ip, servername, ok: false, ms: null, why: null, alpn: null, san: null, server: null, status: null }
    const socket = tls.connect({ host: ip, port: 443, servername, ALPNProtocols: ['h2', 'http/1.1'], rejectUnauthorized: true })
    let done = false
    const finish = (why) => {
      if (done) return
      done = true
      out.why = why ?? null
      try {
        socket.destroy()
      } catch {}
      resolve(out)
    }
    socket.setTimeout(timeoutMs)
    socket.once('secureConnect', () => {
      out.ok = true
      out.ms = Math.round(Number(process.hrtime.bigint() - started) / 1e6)
      out.alpn = socket.alpnProtocol ?? null
      try {
        const c = socket.getPeerCertificate()
        out.san = c?.subjectaltname ?? null
      } catch {}
      socket.write(`HEAD / HTTP/1.1\r\nHost: ${servername}\r\nConnection: close\r\n\r\n`)
    })
    socket.on('data', (chunk) => {
      const t = chunk.toString('latin1')
      const m = t.match(/^HTTP\/1\.[01] (\d{3})/)
      if (m && out.status === null) out.status = Number(m[1])
      const s = t.match(/^Server:\s*(.+)$/im)
      if (s) out.server = s[1].trim()
      if (out.status !== null) finish(null)
    })
    socket.once('error', (e) => finish(e.code ?? e.message))
    socket.once('timeout', () => finish('timeout'))
  })
}

/* ── 1. IPv6 ─────────────────────────────────────────────────────────────── */
line('\n=== 1. IPv6 到 GitHub 边缘 ===')
const aaaa = await new Promise((r) => dns.resolve6('raw.githubusercontent.com', (e, a) => r(e ? [] : a)))
line('  raw.githubusercontent.com AAAA =', aaaa.join(', ') || '(无)')
for (const ip of aaaa) {
  const tcp = await tcpConnect(ip)
  const t = tcp.ok ? await tlsProbe(ip, 'raw.githubusercontent.com') : null
  line(`  ${ip}  tcp=${tcp.ok ? tcp.ms + 'ms' : 'FAIL(' + tcp.why + ')'}  tls=${t ? t.ms + 'ms' : '-'}  http=${t?.status ?? '-'}`)
}

/* ── 2. DoH ──────────────────────────────────────────────────────────────── */
line('\n=== 2. DoH 可用性（决定能不能拿到「不污染 + 完整」的 A 记录）===')
const DOH = [
  ['Cloudflare', 'https://1.1.1.1/dns-query', '1.1.1.1'],
  ['Google', 'https://8.8.8.8/dns-query', '8.8.8.8'],
  ['AliDNS', 'https://223.5.5.5/dns-query', '223.5.5.5'],
  ['DNSPod', 'https://doh.pub/dns-query', 'doh.pub'],
  ['Quad9', 'https://9.9.9.9/dns-query', '9.9.9.9'],
]
async function dohQuery(url, name, ip, type = 'A') {
  const started = Date.now()
  return new Promise((resolve) => {
    let settled = false
    const done = (r) => {
      if (settled) return
      settled = true
      resolve(r)
    }
    setTimeout(() => done({ ok: false, why: 'timeout', ms: Date.now() - started }), 6000)
    const req = httpsRequest(
      `${url}?name=${encodeURIComponent(name)}&type=${type}`,
      { headers: { accept: 'application/dns-json' }, servername: new URL(url).hostname },
      (res) => {
        let body = ''
        res.on('data', (c) => (body += c))
        res.on('end', () => {
          try {
            const json = JSON.parse(body)
            const answers = (json.Answer ?? []).filter((a) => a.type === 1 || a.type === 28).map((a) => a.data)
            done({ ok: true, ms: Date.now() - started, answers })
          } catch (error) {
            done({ ok: false, why: `parse:${error.message}`, ms: Date.now() - started })
          }
        })
      },
    )
    req.on('error', (e) => done({ ok: false, why: e.code ?? e.message, ms: Date.now() - started }))
    req.end()
  })
}
for (const [label, url] of DOH) {
  const r = await dohQuery(url, 'github.com')
  line(`  ${label.padEnd(12)} ${r.ok ? `${r.ms}ms  github.com -> ${r.answers.join(', ')}` : `FAIL ${r.why}`}`)
}
line('\n  DoH 对各个域名给出的答案：')
for (const host of ['github.com', 'api.github.com', 'gist.github.com', 'raw.githubusercontent.com', 'codeload.github.com']) {
  const r = await dohQuery('https://1.1.1.1/dns-query', host)
  const a4 = await dohQuery('https://223.5.5.5/dns-query', host)
  line(`    ${host.padEnd(30)} cloudflare=[${r.ok ? r.answers.join(',') : r.why}]  alidns=[${a4.ok ? a4.answers.join(',') : a4.why}]`)
}

/* ── 3. gist 的真实地址 ──────────────────────────────────────────────────── */
line('\n=== 3. gist.github.com：系统 DNS 给的地址 vs DoH 给的地址 ===')
const gistSys = await new Promise((r) => dns.resolve4('gist.github.com', (e, a) => r(e ? [] : a)))
line('  系统 DNS:', gistSys.join(', '))
const gistDoh = await dohQuery('https://1.1.1.1/dns-query', 'gist.github.com')
line('  Cloudflare DoH:', gistDoh.ok ? gistDoh.answers.join(', ') : gistDoh.why)
for (const ip of [...new Set([...(gistDoh.answers ?? []), ...gistSys])]) {
  const t = await tlsProbe(ip, 'gist.github.com')
  line(`  ${ip.padEnd(18)} tls=${t.ms ?? '-'}ms http=${t.status ?? '-'} ${t.why ?? ''}`)
}

/* ── 4. 各个 github 域名的 A 记录全集（系统 vs DoH） ──────────────────────── */
line('\n=== 4. 系统 DNS vs Cloudflare DoH（A 记录条数差异）===')
const ALL = [
  'github.com', 'api.github.com', 'codeload.github.com', 'github.githubassets.com',
  'uploads.github.com', 'npm.pkg.github.com', 'ghcr.io', 'objects.githubusercontent.com',
  'release-assets.githubusercontent.com', 'pkg-containers.githubusercontent.com',
]
for (const host of ALL) {
  const sys = await new Promise((r) => dns.resolve4(host, (e, a) => r(e ? [] : a)))
  const doh = await dohQuery('https://1.1.1.1/dns-query', host)
  line(`  ${host.padEnd(38)} sys(${sys.length})=[${sys.join(',')}]`)
  line(`  ${''.padEnd(38)} doh(${doh.ok ? doh.answers.length : 'x'})=[${doh.ok ? doh.answers.join(',') : doh.why}]`)
}
