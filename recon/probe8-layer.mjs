/** 精确定位 github.com 到底死在哪一层：TCP / TLS 握手 / 证书 / HTTP。 */
import { validateEndpoint, tlsReachable } from '../server/net.js'

const HOST = process.argv[2] ?? 'github.com'
const IPS = (process.argv[3] ?? '140.82.116.9,140.82.116.3,140.82.113.4,20.205.243.166').split(',')

for (const ip of IPS) {
  /* eslint-disable no-await-in-loop */
  const r = await validateEndpoint(ip, HOST, { timeoutMs: 6000 })
  const t = await tlsReachable(ip, HOST, 4000)
  console.log(
    `${ip.padEnd(17)} validate ok=${String(r.ok).padEnd(5)} tls=${String(r.tlsMs ?? '-').padStart(6)}ms ` +
      `http=${String(r.status ?? '-').padEnd(5)} why=${String(r.why ?? '-').padEnd(28)} | 单独握手=${t.ok ? 'ok' : t.why}`,
  )
}
process.exit(0)
