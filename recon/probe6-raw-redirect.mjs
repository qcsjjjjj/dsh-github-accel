/**
 * `raw.githubusercontent.com` 在 140.82.x 上回 301 —— 它指向哪？
 *
 * 这决定了那两个地址能不能进兜底池：
 *   - 指向**同一个主机名** → 浏览器会重新解析（hosts → 127.0.0.11）→ 又回 301 → **死循环**，绝不能加；
 *   - 指向**别的主机**（S3 / objects / raw.github.com）→ 那是一次正常跳转，可以加。
 */
import tls from 'node:tls'

const IPS = ['140.82.116.3', '140.82.121.4', '185.199.108.133', '185.199.109.133', '185.199.110.133', '185.199.111.133']
const PATH = '/github/gitignore/main/Node.gitignore'

function get(ip, host = 'raw.githubusercontent.com', path = PATH, timeoutMs = 7000) {
  return new Promise((resolve) => {
    const out = { ip, tls: false, status: null, location: null, server: null, why: null, bytes: 0 }
    const s = tls.connect({ host: ip, port: 443, servername: host, rejectUnauthorized: true })
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
    s.setTimeout(timeoutMs)
    s.once('secureConnect', () => {
      out.tls = true
      s.write(`GET ${path} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: dsh-probe\r\nAccept: */*\r\nConnection: close\r\n\r\n`)
    })
    s.on('data', (chunk) => {
      out.bytes += chunk.length
      const t = chunk.toString('latin1')
      const m = t.match(/^HTTP\/1\.[01] (\d{3})/)
      if (m && out.status === null) {
        out.status = Number(m[1])
        const loc = t.match(/^location:\s*(.+)$/im)
        if (loc) out.location = loc[1].trim()
        const sv = t.match(/^server:\s*(.+)$/im)
        if (sv) out.server = sv[1].trim()
      }
      /* 头部收全就够判断了 */
      if (out.status !== null) fin(null)
    })
    s.once('error', (e) => fin(e.code ?? e.message))
    s.once('timeout', () => fin('timeout'))
  })
}

console.log(`试取 ${PATH}\n`)
const results = []
for (const ip of IPS) {
  /* eslint-disable no-await-in-loop */
  const r = await get(ip)
  results.push(r)
  console.log(
    `${ip.padEnd(18)} tls=${String(r.tls).padEnd(5)} http=${String(r.status ?? '-').padEnd(5)} ` +
      `location=${r.location ?? '-'}  server=${r.server ?? '-'}  ${r.why ?? ''}`,
  )
}

console.log('\n=== 判断 ===')
const redirects = results.filter((r) => r.status === 301 || r.status === 302)
if (!redirects.length) {
  console.log('  没有拿到可用的跳转 —— 这些地址暂时都不能用。')
} else {
  for (const r of redirects) {
    let host = null
    try {
      host = new URL(r.location).hostname
    } catch {
      /* location 可能是相对路径 */
    }
    const loops = host === null || host === 'raw.githubusercontent.com' || host.endsWith('.githubusercontent.com')
    console.log(
      `  ${r.ip} -> ${r.location}\n      ${loops ? '⛔ 指向 githubusercontent 家族（很可能死循环）→ **不要**放进池子' : '✅ 指向别的主机 → 可以放进池子当兜底'}`,
    )
  }
}
