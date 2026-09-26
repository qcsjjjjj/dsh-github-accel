/**
 * 试验：把 ClientHello **拆成两段**发出去，能不能绕过按 SNI 的封锁？
 *
 * 背景（本机 2026-09-26 实测）：
 *   同一个 IP、同一个时刻，`SNI=github.com` 是「TLS 握手能过、随后 HTTP 请求零响应」，
 *   而 `SNI=codeload.github.com` / `api.github.com` / `raw.githubusercontent.com` 都能拿到
 *   真实响应。也就是说被针对的**是这个域名本身**。
 *
 * 我们是 SNI 直通，没法改 SNI（那需要中间人）。但**分段**是合法的 TCP 行为：
 * 把第一个 TLS 记录拆到两个 TCP 段里，只做单包模式匹配的中间盒就看不到完整的 SNI。
 * GoodbyeDPI / zapret / GreenTunnel 用的就是这个原理（它们的 `--split-pos`）。
 *
 * 判据：写完之后能不能收到**上游回的任意字节**（ServerHello）。
 * 收到了就说明这条连接活过来了。
 *
 * 用法：node recon/probe7-split.mjs [sni]
 */
import net from 'node:net'
import tls from 'node:tls'

const SNI = process.argv[2] ?? 'github.com'
const IPS = (process.argv[3] ?? '140.82.116.9,140.82.116.5,140.82.116.3,140.82.113.4,20.205.243.166').split(',')
const READ_TIMEOUT = 6000

/** 抓一个真实的 ClientHello（比手搓字节可信）。 */
async function captureClientHello(servername) {
  return new Promise((resolve, reject) => {
    let done = false
    const sink = net.createServer((sock) => {
      let whole = Buffer.alloc(0)
      sock.on('error', () => {})
      sock.on('data', (c) => {
        whole = Buffer.concat([whole, c])
        if (!done && whole.length >= 5 && whole.length >= 5 + whole.readUInt16BE(3)) {
          done = true
          resolve(whole)
          sock.destroy()
          sink.close()
        }
      })
    })
    sink.on('error', reject)
    sink.listen(0, '127.0.0.1', () => {
      const c = tls.connect({ host: '127.0.0.1', port: sink.address().port, servername })
      c.on('error', () => {})
    })
    setTimeout(() => {
      if (!done) reject(new Error('capture timeout'))
    }, 5000)
  })
}

/** SNI 主机名在 ClientHello 里的字节偏移（用来把切点放在名字中间）。 */
function sniSpan(buf) {
  try {
    let p = 5
    p += 4 + 2 + 32
    p += 1 + buf[p]
    p += 2 + buf.readUInt16BE(p)
    p += 1 + buf[p]
    const extEnd = p + 2 + buf.readUInt16BE(p)
    p += 2
    while (p + 4 <= Math.min(extEnd, buf.length)) {
      const type = buf.readUInt16BE(p)
      const len = buf.readUInt16BE(p + 2)
      p += 4
      if (type === 0x0000) {
        const nameLen = buf.readUInt16BE(p + 3)
        return { start: p + 5, end: p + 5 + nameLen }
      }
      p += len
    }
  } catch {}
  return null
}

/**
 * 按给定的分段方式发出去，看上游有没有回字节。
 * @param pieces 一组 {from,to} 切片；写成多个 write，段与段之间留 30ms。
 */
function tryPieces(ip, buf, pieces, timeoutMs = READ_TIMEOUT) {
  return new Promise((resolve) => {
    const started = Date.now()
    const out = { ip, pieces: pieces.length, gotBytes: 0, ms: null, why: null }
    const s = net.connect(443, ip)
    let done = false
    const fin = (why) => {
      if (done) return
      done = true
      out.why = out.why ?? why ?? null
      if (!out.ms) out.ms = Date.now() - started
      try {
        s.destroy()
      } catch {}
      resolve(out)
    }
    s.setNoDelay(true)
    s.setTimeout(timeoutMs)
    s.once('connect', () => {
      let i = 0
      const send = () => {
        if (i >= pieces.length) return
        const { from, to } = pieces[i]
        i += 1
        try {
          s.write(buf.subarray(from, to))
        } catch (e) {
          return fin(`write:${e.code ?? e.message}`)
        }
        if (i < pieces.length) setTimeout(send, 30)
      }
      send()
    })
    s.on('data', (chunk) => {
      out.gotBytes += chunk.length
      out.ms = Date.now() - started
      fin(null)
    })
    s.once('error', (e) => fin(e.code ?? e.message))
    s.once('timeout', () => fin('timeout'))
  })
}

const ch = await captureClientHello(SNI)
const span = sniSpan(ch)
console.log(`ClientHello ${ch.length} 字节，SNI=${SNI} 落在 [${span ? `${span.start},${span.end})` : '?'}\n`)

const SPLITS = []
SPLITS.push({ name: '整条一次写（现在的做法）', pieces: [{ from: 0, to: ch.length }] })
if (span) {
  SPLITS.push({ name: `在 SNI 名字里切（${span.start + 3}）`, pieces: [{ from: 0, to: span.start + 3 }, { from: span.start + 3, to: ch.length }] })
  SPLITS.push({ name: `在 SNI 名字末尾前切（${span.end - 1}）`, pieces: [{ from: 0, to: span.end - 1 }, { from: span.end - 1, to: ch.length }] })
}
SPLITS.push({ name: '只切出 TLS 记录头（5 字节）', pieces: [{ from: 0, to: 5 }, { from: 5, to: ch.length }] })
SPLITS.push({ name: '切掉记录头+握手头（9 字节）', pieces: [{ from: 0, to: 9 }, { from: 9, to: ch.length }] })

for (const ip of IPS) {
  console.log(`── ${ip}`)
  for (const s of SPLITS) {
    /* eslint-disable no-await-in-loop */
    const r = await tryPieces(ip, ch, s.pieces)
    const ok = r.gotBytes > 0
    console.log(`   ${ok ? '✅' : '❌'} ${s.name.padEnd(34)} 收到 ${String(r.gotBytes).padStart(5)} 字节  ${r.ms}ms  ${r.why ?? ''}`)
  }
}
process.exit(0)
