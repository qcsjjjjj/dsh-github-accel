/**
 * dsh-github-accel — 现场体检：连续两次请求，看候选排序与冷却是否生效
 *
 * 用旧的单地址逻辑时，github.com 的 DNS 答案（本机是 20.205.243.166）一挂，
 * 每次请求都要先撞它一遍（6 s 超时）才轮到备用地址。修好之后：
 *   - 第一次：撞一次坏地址 → 换到可用地址（慢但成功）
 *   - 第二次：直接用上次成功的地址（应该很快）
 *
 * 用法：node tools/live-check.mjs
 */
import tls from 'node:tls'
import { Accelerator } from '../server/accel.js'

const PORT = 8444
const accel = new Accelerator({ sniPort: PORT, httpPort: 8082, proxyPort: 18997 })

const up = await accel.listen({ port: PORT, mode: 'sni' })
if (!up.ok) {
  console.error(`无法在 127.0.0.1:${PORT} 监听：${up.reason}`)
  process.exit(1)
}

/** 经 SNI 直通发一次 HTTPS 请求，返回 { ms, status }。 */
function request(host) {
  return new Promise((resolve) => {
    const started = Date.now()
    const socket = tls.connect({ host: '127.0.0.1', port: PORT, servername: host }, () => {
      let data = ''
      socket.setEncoding('utf8')
      socket.on('data', (chunk) => {
        data += chunk
        const idx = data.indexOf('\r\n')
        if (idx > 0) {
          resolve({ ms: Date.now() - started, status: data.slice(0, idx) })
          socket.destroy()
        }
      })
      socket.write(`GET / HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: dsh-live-check\r\nConnection: close\r\n\r\n`)
    })
    socket.on('error', (e) => resolve({ ms: Date.now() - started, status: 'ERR ' + (e.code ?? e.message) }))
    setTimeout(() => {
      resolve({ ms: Date.now() - started, status: 'TIMEOUT' })
      socket.destroy()
    }, 45000)
  })
}

for (const host of ['github.com', 'gist.github.com', 'api.github.com']) {
  for (const round of [1, 2]) {
    const r = await request(host)
    console.log(`${host.padEnd(18)} 第 ${round} 次: ${String(r.ms).padStart(6)} ms  ${r.status}`)
  }
}

const st = accel.status()
console.log('\n每个域名的候选与实际连上：')
for (const r of st.resolved ?? []) {
  console.log(`  ${r.host.padEnd(32)} ips=${JSON.stringify(r.ips)} cand=${r.candidates} used=${r.used ?? '-'} good=${r.good ?? '-'}`)
}
console.log('冷却中的地址: ' + JSON.stringify(st.cooldownIps ?? []))
console.log('lastError: ' + (st.lastError ?? '(无)'))

await accel.stop({ removeHosts: false })
process.exit(0)
