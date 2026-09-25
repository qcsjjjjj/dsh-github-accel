/**
 * 判定「github.com 现在为什么不通」：是地址不通，还是 **SNI 被针对**？
 *
 * 做法：拿同一批 IP，用不同的 servername 各做一次 TLS 握手 + 一次 HTTP 请求。
 *   - 如果「同一个 IP + api.github.com 的 SNI」能通、「github.com 的 SNI」不通
 *     → 是 SNI 维度的干扰（换地址没用）。
 *   - 如果两个 SNI 都不通 → 是这个 IP 不通（换地址有用）。
 *
 * 用法：node recon/probe3-sni.mjs
 */
import tls from 'node:tls'

const IPS = ['20.205.243.166', '20.205.243.168', '140.82.113.4', '140.82.112.4', '20.205.243.165']
const SNIS = ['github.com', 'api.github.com', 'codeload.github.com', 'github.githubassets.com', 'raw.githubusercontent.com']

/** 到 ip 用 sni 握手，再发一个 HEAD。返回握手与响应结果。 */
function attempt(ip, sni, timeoutMs = 6000) {
  return new Promise((resolve) => {
    const started = Date.now()
    const out = { ip, sni, tls: false, tlsMs: null, status: null, why: null }
    let socket
    try {
      socket = tls.connect({ host: ip, port: 443, servername: sni, rejectUnauthorized: false })
    } catch (error) {
      out.why = `throw:${error.message}`
      return resolve(out)
    }
    let done = false
    const finish = (why) => {
      if (done) return
      done = true
      out.why = out.why ?? why ?? null
      if (!out.tlsMs) out.ms = Date.now() - started
      try {
        socket.destroy()
      } catch {}
      resolve(out)
    }
    socket.setTimeout(timeoutMs)
    socket.once('secureConnect', () => {
      out.tls = true
      out.tlsMs = Date.now() - started
      socket.write(`HEAD / HTTP/1.1\r\nHost: ${sni}\r\nConnection: close\r\n\r\n`)
    })
    socket.on('data', (chunk) => {
      const m = chunk.toString('latin1').match(/^HTTP\/1\.[01] (\d{3})/)
      if (m) {
        out.status = Number(m[1])
        return finish(null)
      }
    })
    socket.once('error', (e) => finish(e.code ?? e.message))
    socket.once('timeout', () => finish('timeout'))
  })
}

const IGNORE = process.env.PROBE3_IGNORE_SSL === '0' ? false : true
void IGNORE

const w = [17, 32, 7, 9, 8, 22]
const rows = []
for (const ip of IPS) {
  for (const sni of SNIS) {
    /* 逐条来：这条网络对并发握手很敏感，并发会掩盖真实结论。 */
    // eslint-disable-next-line no-await-in-loop
    const r = await attempt(ip, sni)
    rows.push(r)
    process.stdout.write(
      `${ip.padEnd(w[0])}${sni.padEnd(w[1])}${String(r.tls).padEnd(w[2])}${String(r.tlsMs ?? '-').padEnd(w[3])}${String(r.status ?? '-').padEnd(w[4])}${r.why ?? ''}\n`,
    )
  }
}

console.log('\n=== 按 SNI 汇总（同一 SNI 在多少个 IP 上握手成功）===')
for (const sni of SNIS) {
  const list = rows.filter((r) => r.sni === sni)
  const ok = list.filter((r) => r.tls)
  console.log(`  ${sni.padEnd(32)} ${ok.length}/${list.length} 握手成功，HTTP 有响应的 ${list.filter((r) => r.status !== null).length} 个`)
}
console.log('\n=== 按 IP 汇总 ===')
for (const ip of IPS) {
  const list = rows.filter((r) => r.ip === ip)
  console.log(`  ${ip.padEnd(17)} ${list.filter((r) => r.tls).length}/${list.length} 握手成功`)
}

/*
 * 结论要按 **IP 为单位** 判断，不能只看「存在某个 SNI 通/不通」——
 * 后者会把「IP 整体被黑洞」 + 「不同边缘服务不同 Host（403/400）」误判成 SNI 干扰。
 * 初版这里判错过一次，改掉。
 */
const perIp = IPS.map((ip) => {
  const list = rows.filter((r) => r.ip === ip)
  const tlsOk = list.filter((r) => r.tls).length
  const served = list.filter((r) => r.status !== null && r.status < 400).length
  return { ip, tlsOk, total: list.length, served, uniformDead: tlsOk === 0, uniformAlive: tlsOk === list.length }
})

console.log('\n=== 结论 ===')
const allDead = perIp.every((r) => r.uniformDead)
if (allDead) {
  console.log('  所有 IP × 所有 SNI 都失败 → 这段时间到 GitHub 整体不通，不是选路问题。')
} else {
  for (const r of perIp) {
    const shape = r.uniformDead
      ? '整体黑洞（对所有 SNI 都 timeout）→ **IP 维度失效，换地址有效**'
      : r.uniformAlive
        ? `TLS 全通，但只有 ${r.served}/${r.total} 个 Host 真的被服务 → **边缘服务范围不同**（403/400 = 不服务这个 Host）`
        : '部分 SNI 通、部分不通 → 值得进一步查 SNI 维度干扰'
    console.log(`  ${r.ip.padEnd(17)} ${shape}`)
  }
  console.log('\n  提示：GFW 的 SNI-RST 注入表现为「收到含受限 SNI 的 ClientHello 后向两端注入 RST」，')
  console.log('        残留封锁约 60–180 s；要靠 Wireshark 对比 RST 的 TTL / ip.id 才能和正常 RST 区分。')
}

