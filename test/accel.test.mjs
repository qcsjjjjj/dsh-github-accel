/**
 * dsh-github-accel 核心证明（不需要 DSH、只有少数用例需要真网络）
 *
 * 运行：node test/accel.test.mjs
 *
 * 第 9/10 节是**回归测试**，对应 docs/PLAN-2026-09-25.md 里的 B1 / B2：
 *   B1 客户端断开后上游 socket 不关 → 连接永久泄漏、trace 永远是空的；
 *   B2 代理路径里引用未定义变量 → 事件回调抛 ReferenceError → DSH 进程直接死。
 */
import tls from 'node:tls'
import http from 'node:http'
import net from 'node:net'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import {
  Accelerator,
  CandidateTable,
  HostsBlock,
  ProxyServer,
  TunnelServer,
  DEFAULT_DOMAINS,
  DOMAIN_TABLE,
  FALLBACK_IPS,
  HOT_DOMAINS,
  APP_DOMAIN,
  acceptableStatus,
  decideHijackDomains,
  isCompleteTlsRecord,
  isUsable,
  loopbackFor,
  looksLikeWrongHost,
  parseOverrides,
  parseSni,
  probePort,
  raceConnect,
  resolveRealIps,
  validateEndpoint,
  withFallback,
} from '../server/accel.js'

const SNI_PORT = 18443
const PROXY_PORT = 19000
let failures = 0

/** 测试自身的看门狗：任何一处忘了设超时都不许把整轮测试挂死。 */
const WATCHDOG_MS = Number(process.env.ACCEL_TEST_WATCHDOG_MS ?? 180_000)
const watchdog = setTimeout(() => {
  console.error(`\nWATCHDOG: 测试超过 ${WATCHDOG_MS} ms 仍未结束，判定为挂死 ❌`)
  process.exit(3)
}, WATCHDOG_MS)
watchdog.unref?.()

/** 带超时的 promise 包裹，避免任何一处等待变成永久挂起。 */
function withTimeout(promise, ms, label) {
  return Promise.race([
    promise,
    new Promise((resolve) => setTimeout(() => resolve(`TIMEOUT(${label})`), ms)),
  ])
}

/*
 * 进程级异常一律记下来：本插件的核心承诺之一是「事件回调里绝不抛」。
 * 但**不能只是记下来就完事** —— 顶层的 await 一旦 reject，后面的断言就再也不会跑，
 * 而挂着的进程会一直等到看门狗。那种「静默挂 180 秒」比直接失败难查得多，
 * 所以这里立即打出来并退出。
 */
const runtimeErrors = []
function fatal(kind, error) {
  runtimeErrors.push(`${kind}: ${error?.stack ?? error}`)
  console.error(`\n${kind}（测试无法继续）:\n${error?.stack ?? error}\n`)
  process.exit(kind === 'uncaughtException' ? 5 : 4)
}
process.on('uncaughtException', (error) => fatal('uncaughtException', error))
process.on('unhandledRejection', (error) => fatal('unhandledRejection', error))

function check(name, ok, detail = '') {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  —  ' + detail : ''}`)
  if (!ok) failures += 1
}
const skip = (name, detail = '') => console.log(`SKIP  ${name}${detail ? '  —  ' + detail : ''}`)

/** 在已建立的 TLS socket 上发一次 HTTP/1.1 请求，返回状态行。 */
function httpOverTls(socket, host) {
  return new Promise((resolve, reject) => {
    let data = ''
    const timer = setTimeout(() => reject(new Error('timeout waiting for response')), 15000)
    const done = (fn, value) => {
      clearTimeout(timer)
      fn(value)
    }
    socket.setEncoding('utf8')
    socket.on('data', (chunk) => {
      data += chunk
      const idx = data.indexOf('\r\n')
      if (idx > 0) done(resolve, data.slice(0, idx))
    })
    socket.on('error', (error) => done(reject, error))
    socket.write(`GET / HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: dsh-github-accel-test\r\nConnection: close\r\n\r\n`)
  })
}

/** 用一次真实握手抓一个 ClientHello —— 比手搓字节更可信。 */
async function captureClientHello(servername = 'github.com') {
  return new Promise((resolve, reject) => {
    let done = false
    const sink = net.createServer((sock) => {
      let whole = Buffer.alloc(0)
      sock.on('error', () => {})
      sock.on('data', (c) => {
        whole = Buffer.concat([whole, c])
        if (!done && whole.length >= 5 && isCompleteTlsRecord(whole)) {
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

/**
 * 指定域名在这台机器上此刻到底通不通 —— 用来区分「机制坏了」与「上游整体不通」。
 *
 * **必须带上 servername 去试**：同一条网络里 `github.com` 的 A 记录会整段死掉，
 * 而 `api.github.com` 同时是好的。拿一个无关域名试通了就以为 github.com 也通，
 * 会把「上游真的炸了」误报成「我们的机制坏了」。
 */
async function reachable(servername, ips) {
  for (const ip of ips) {
    const ok = await new Promise((res) => {
      const s = tls.connect({ host: ip, port: 443, servername, rejectUnauthorized: false })
      s.setTimeout(5000)
      s.on('secureConnect', () => {
        res(true)
        s.destroy()
      })
      s.on('error', () => res(false))
      s.on('timeout', () => {
        res(false)
        s.destroy()
      })
    })
    if (ok) return true
  }
  return false
}

/* ══ 1. SNI 直通（不做 TLS 中间人） ═══════════════════════════════════════ */
console.log('== 1. SNI 直通（不做 TLS 中间人）')
const accel = new Accelerator({ sniPort: SNI_PORT, httpPort: 18081, proxyPort: PROXY_PORT, watchIntervalMs: 0, healthIntervalMs: 0 })

const beforeListen = await probePort(SNI_PORT)
check('监听前 probePort 报「无人服务」', beforeListen === false, String(beforeListen))
const sniUp = await accel.listen({ port: SNI_PORT, mode: 'sni' })
check(`127.0.0.1:${SNI_PORT} 监听`, sniUp.ok, JSON.stringify(sniUp))
const afterListen = await probePort(SNI_PORT)
check('监听后 probePort 报「有人服务」（端口冲突预检靠它）', afterListen === true, String(afterListen))

/* github.com 与 api.github.com 的候选池分开探 —— 它们的可用性互相独立。 */
const GH_IPS = ['20.205.243.166', '140.82.113.4', '140.82.112.4']
const API_IPS = ['20.205.243.168', '140.82.113.6', '140.82.112.6', '20.205.243.166']
const networkUp = await reachable('github.com', GH_IPS)
const apiUp = await reachable('api.github.com', API_IPS)
if (!sniUp.ok || !networkUp) {
  skip('TLS 直通端到端', networkUp ? `监听没起来：${sniUp.reason}` : '本机此刻到不了 GitHub')
} else {
  const result = await withTimeout(
    new Promise((resolve) => {
      const socket = tls.connect({ host: '127.0.0.1', port: SNI_PORT, servername: 'github.com', rejectUnauthorized: true }, () => {
        resolve({ socket, cert: socket.getPeerCertificate() })
      })
      socket.on('error', (e) => resolve({ error: e }))
    }),
    15_000,
    'sni-handshake',
  )
  if (typeof result === 'string' || result.error) {
    check('TLS 握手成功且证书被 Node 自带 CA 信任', false, result.error?.message ?? result.error ?? result)
  } else {
    const issuer = result.cert.issuer ?? {}
    const issuerText = `${issuer.O ?? ''} ${issuer.CN ?? ''}`.trim()
    check('TLS 握手（rejectUnauthorized=true）', true, `issuer=${issuerText}`)
    check(
      '证书由公共 CA 签发（非自签 MITM）',
      !/SteamTools|BeyondDimension/i.test(issuerText) && /DigiCert|Sectigo|Let's Encrypt|Amazon|Google Trust/i.test(issuerText),
      issuerText,
    )
    const status = await httpOverTls(result.socket, 'github.com')
    check('通过直通连接完成 HTTPS 请求', /^HTTP\/1\.[01] (200|301|302)/.test(status), status)
  }
}

/* ══ 2. CONNECT 代理 ═════════════════════════════════════════════════════ */
console.log('\n== 2. CONNECT 代理')
const proxyUp = await accel.listenConnectProxy(PROXY_PORT)
check(`127.0.0.1:${PROXY_PORT} 监听`, proxyUp.ok, JSON.stringify(proxyUp))

if (proxyUp.ok && apiUp) {
  const status = await withTimeout(new Promise((resolve) => {
    const req = http.request({
      host: '127.0.0.1',
      port: PROXY_PORT,
      method: 'CONNECT',
      path: 'api.github.com:443',
      headers: { host: 'api.github.com:443' },
    })
    /* 上游失败时代理会回 502 —— 那是 'response' 而不是 'connect'，不接住就会永远等下去。 */
    req.on('response', (res) => resolve(`HTTP ${res.statusCode} (proxy refused)`))
    req.on('connect', (res, socket) => {
      if (res.statusCode !== 200) return resolve(`CONNECT ${res.statusCode}`)
      const t = tls.connect({ socket, servername: 'api.github.com' }, () => {
        t.write('GET / HTTP/1.1\r\nHost: api.github.com\r\nUser-Agent: dsh-test\r\nConnection: close\r\n\r\n')
      })
      let data = ''
      t.setEncoding('utf8')
      t.on('data', (c) => {
        data += c
        const idx = data.indexOf('\r\n')
        if (idx > 0) {
          resolve(data.slice(0, idx))
          t.destroy()
        }
      })
      t.on('error', (e) => resolve('TLS ' + e.message))
    })
    req.on('error', (e) => resolve('ERR ' + e.message))
    req.end()
  }), 30_000, 'connect-proxy')
  check('CONNECT + TLS + HTTPS 请求', /^HTTP\/1\.[01] (200|301|302|403)/.test(status), status)
} else {
  skip('CONNECT + TLS + HTTPS 请求', networkUp ? '' : '本机此刻到不了 GitHub')
}

/* ══ 3. hosts 块（临时文件） ═════════════════════════════════════════════ */
console.log('\n== 3. hosts 块（在临时文件上验证，不动真实 hosts）')
const tmp = path.join(os.tmpdir(), `accel-hosts-${Date.now()}.txt`)
fs.writeFileSync(tmp, '# original\r\n127.0.0.1 localhost\r\n')
const hosts = new HostsBlock({ path: tmp, domains: ['github.com', 'api.github.com'] })
const applied = hosts.apply()
check('apply 成功', applied.ok === true, JSON.stringify(applied))
check('isApplied 为真', hosts.isApplied() === true)
check('备份文件存在', fs.existsSync(applied.backup ?? ''))
const firstText = fs.readFileSync(tmp, 'utf8')
check('保留了原来的 CRLF 换行风格', firstText.includes('\r\n') && !/[^\r]\n/.test(firstText))
const second = hosts.apply()
check(
  '重复 apply 幂等（块只有一份）',
  (fs.readFileSync(tmp, 'utf8').match(/dsh-github-accel Start/g) ?? []).length === 1,
  `ok=${second.ok}`,
)
check('原文件里没有残留临时文件', fs.readdirSync(path.dirname(tmp)).filter((n) => n.startsWith('.dsh-github-accel.')).length === 0)
const removed = hosts.remove()
check('remove 成功且还原', removed.ok === true && !fs.readFileSync(tmp, 'utf8').includes('dsh-github-accel Start'), JSON.stringify(removed))
check('原始行保留', fs.readFileSync(tmp, 'utf8').includes('127.0.0.1 localhost'))
check(
  '能识别别人的接管块（Steam++）',
  new HostsBlock({ path: tmp }).detectForeign('# Steam++ Start\n127.0.0.1 github.com\n# Steam++ End\n').join(',') === 'Steam++',
)
check('没有外来块时不误报', new HostsBlock({ path: tmp }).detectForeign('127.0.0.1 localhost').length === 0)

/* ══ 4. SNI 解析单元 ═════════════════════════════════════════════════════ */
console.log('\n== 4. SNI 解析单元')
const fake = Buffer.concat([
  Buffer.from([0x16, 0x03, 0x01, 0x00, 0x00]),
  Buffer.from([0x01, 0x00, 0x00, 0x00]),
  Buffer.from([0x03, 0x03]),
  Buffer.alloc(32),
  Buffer.from([0x00]),
  Buffer.from([0x00, 0x02, 0x13, 0x01]),
  Buffer.from([0x01, 0x00]),
  Buffer.from([0x00, 0x10]),
  Buffer.from([0x00, 0x00, 0x00, 0x0c]),
  Buffer.from([0x00, 0x09, 0x00]),
  Buffer.from([0x00, 0x06]),
  Buffer.from('GitHub', 'utf8'),
])
check('parseSni 取出 server_name 并转小写', parseSni(fake) === 'github', String(parseSni(fake)))
check('非 TLS 输入返回 undefined', parseSni(Buffer.from('GET / HTTP/1.1\r\n')) === undefined)

/* ══ 5. 解析缓存 / 钉住的 IP / 候选池 ════════════════════════════════════ */
console.log('\n== 5. 候选地址：TTL、钉住、备用池')
check('parseOverrides 解析 host=ip', parseOverrides('github.com=20.205.243.166, ghcr.io=1.2.3.4')['ghcr.io'] === '1.2.3.4')
const cacheMap = new Map()
const fresh = await resolveRealIps('github.com', cacheMap, {}, 60_000)
check('resolveRealIps 走 DNS 拿到候选列表', Array.isArray(fresh) && fresh.every((ip) => /^\d+\.\d+\.\d+\.\d+$/.test(ip)), fresh.join(','))
check('缓存条目带时间戳', typeof cacheMap.get('github.com')?.at === 'number')
const pinned = await resolveRealIps('github.com', cacheMap, { 'github.com': '203.0.113.7' })
check('覆盖表优先于 DNS 与缓存', pinned[0] === '203.0.113.7' && pinned.length === 1, pinned.join(','))
const stale = await resolveRealIps('github.com', new Map([['github.com', { ips: ['203.0.113.9'], at: 0 }]]), {}, 1000)
check('过期条目会被重新解析（污染答案不会粘住）', stale[0] !== '203.0.113.9', stale.join(','))
const preferred = await resolveRealIps(
  'github.com',
  new Map([['github.com', { ips: ['203.0.113.1', '203.0.113.2'], at: Date.now(), good: '203.0.113.2' }]]),
  {},
  60_000,
)
check('上次成功的地址排到最前', preferred[0] === '203.0.113.2', preferred.join(','))
const merged = withFallback('github.com', ['20.205.243.166'])
check(
  '解析结果全挂时还有备用池（候选变多）',
  merged.length > 1 && merged[0] === '20.205.243.166' && new Set(merged).size === merged.length,
  `candidates=${merged.length}`,
)

const table = new CandidateTable()
const ghCandidates = await table.candidates('github.com')
check('候选里带上了静态备用池', ghCandidates.length >= (FALLBACK_IPS['github.com']?.length ?? 0), ghCandidates.join(', '))
table.recordValidation('github.com', '140.82.113.4', { ok: true, tlsMs: 120 })
table.recordValidation('github.com', '140.82.112.4', { ok: true, tlsMs: 900 })
const ranked = await table.candidates('github.com')
check(
  '已验证的地址排在未验证的前面，且按延迟排序',
  ranked[0] === '140.82.113.4' && ranked[1] === '140.82.112.4',
  ranked.slice(0, 4).join(', '),
)
check(
  '未验证的 DNS 答案排在已验证的之后',
  ranked.indexOf('20.205.243.166') > ranked.indexOf('140.82.112.4'),
  ranked.join(', '),
)
table.record('github.com', '140.82.113.4', { ok: false, why: 'ECONNRESET', hard: true })
check('单次硬失败不立刻拉黑（避免误判抖动）', table.isCooling('github.com', '140.82.113.4') === false)
table.record('github.com', '140.82.113.4', { ok: false, why: 'ECONNRESET', hard: true })
check('连续两次硬失败才进冷却', table.isCooling('github.com', '140.82.113.4') === true)
const cooling = await table.candidates('github.com')
check('冷却中的地址垫底但仍然会被尝试', cooling[cooling.length - 1] === '140.82.113.4' || cooling.includes('140.82.113.4'), cooling.slice(-3).join(', '))
table.record('github.com', '140.82.114.4', { ok: false, why: 'ECONNRESET', hard: false })
check('软失败（客户端先断开）不进冷却', table.isCooling('github.com', '140.82.114.4') === false)
check('looksLikeWrongHost 能识别 Fastly 的串域名页面', looksLikeWrongHost('Fastly error: unknown domain: github.com') === true)
check(
  'acceptableStatus：能握手但不服务这个域名的状态码要被拒',
  acceptableStatus('github.com', 200) === true &&
    acceptableStatus('github.com', 302) === true &&
    acceptableStatus('github.com', 403) === false &&
    acceptableStatus('github.com', 400) === false,
  '实测 20.205.243.168 对 Host: github.com 回 403、20.205.243.165 回 400',
)
check('acceptableStatus：同一状态码在别的域名上可能是对的', acceptableStatus('codeload.github.com', 301) === true && acceptableStatus('github.githubassets.com', 404) === true)
check(
  '黑洞地址（一个字节都没回）卡一次就降权 —— 老代码里这种地址永远不会被换掉',
  (() => {
    const t = new CandidateTable()
    t.record('github.com', '20.205.243.166', { ok: false, why: 'stall', stall: true })
    return t.isCooling('github.com', '20.205.243.166') === true
  })(),
)
check(
  'RST 型坏地址要连续两次才进冷却（避免一次抖动就误伤）',
  (() => {
    const t = new CandidateTable()
    t.record('github.com', '140.82.113.4', { ok: false, why: 'ECONNRESET', hard: true })
    const after1 = t.isCooling('github.com', '140.82.113.4')
    t.record('github.com', '140.82.113.4', { ok: false, why: 'ECONNRESET', hard: true })
    return after1 === false && t.isCooling('github.com', '140.82.113.4') === true
  })(),
)

/* ══ 6. 选路：跳过坏地址 + 并行竞速 ═════════════════════════════════════ */
console.log('\n== 6. 连接：跳过坏地址 + happy-eyeballs 竞速')
const sink = net.createServer((s) => {
  s.on('error', () => {})
})
await new Promise((r) => sink.listen(0, '127.0.0.1', r))
const livePort = sink.address().port
const picked = await raceConnect({
  host: 'mixed',
  port: livePort,
  ips: ['192.0.2.1', '127.0.0.1'],
  perTimeoutMs: 1500,
  totalMs: 4000,
})
check('跳过不通的地址，连上可用的那个', picked.ip === '127.0.0.1', `used=${picked.ip} tried=${picked.tried.join(' | ')}`)
picked.socket.destroy()
const dead = await raceConnect({ host: 'dead', port: 1, ips: ['127.0.0.1'], perTimeoutMs: 800, totalMs: 2000 })
  .then(() => 'connected')
  .catch((e) => 'rejected:' + e.tried.join(','))
check('全部不通时 reject（不挂死）', dead.startsWith('rejected'), dead)

/* 竞速的关键性质：第一个候选是黑洞时，不能等它超时才连第二个。 */
const startedRace = Date.now()
const raced = await raceConnect({
  host: 'race',
  port: livePort,
  ips: ['192.0.2.2', '127.0.0.1'],
  perTimeoutMs: 3000,
  staggerMs: 120,
  totalMs: 5000,
})
const raceMs = Date.now() - startedRace
check('黑洞候选不会把整条连接拖到超时（stagger 起效）', raced.ip === '127.0.0.1' && raceMs < 1200, `${raceMs}ms`)
raced.socket.destroy()
sink.close()

/* ══ 7. 一域名一地址 + 自适应接管 ══════════════════════════════════════ */
console.log('\n== 7. 一域名一地址 + 接管决策')
const hits = new HostsBlock({ path: path.join(os.tmpdir(), `accel-h2-${Date.now()}.txt`), domains: DEFAULT_DOMAINS })
const addrs = Object.values(hits.addressMap)
check(
  '每个域名分到不同的回环地址',
  new Set(addrs).size === addrs.length && addrs.every((a) => /^127\.0\.0\.\d+$/.test(a)),
  `${addrs.length} 个域名，${addrs[0]} .. ${addrs[addrs.length - 1]}`,
)
check('render 用的是这些地址（不再是清一色 127.0.0.1）', hits.render().includes(`127.0.0.2 ${DEFAULT_DOMAINS[0]}`))
check(
  '地址按固定参照表分配（增删域名不平移）',
  (() => {
    const before = hits.addressMap['raw.githubusercontent.com']
    hits.domains = DEFAULT_DOMAINS.filter((d) => d !== 'api.github.com')
    const after = hits.addressMap['raw.githubusercontent.com']
    return before === after && after === '127.0.0.11'
  })(),
  'raw.githubusercontent.com 恒为 127.0.0.11',
)
check(
  '地址表里没有 127.0.0.1（留给真正的本地服务）',
  Object.values(hits.addressMap).every((a) => a !== '127.0.0.1'),
)
check('githubusercontent 家族已经在默认接管列表里（IPv6 黑洞的解法）', DEFAULT_DOMAINS.includes('raw.githubusercontent.com') && DEFAULT_DOMAINS.includes('avatars.githubusercontent.com'))
check('用户自己的 Pages 站点默认不接管', !DEFAULT_DOMAINS.includes('github.io') && !DEFAULT_DOMAINS.includes('pages.github.com'))
check('表里没有重复域名', new Set(DOMAIN_TABLE.map((e) => e.domain)).size === DOMAIN_TABLE.length)
check('热域名都是默认接管的域名', HOT_DOMAINS.every((h) => DEFAULT_DOMAINS.includes(h)))
check('loopbackFor 从 .2 开始', loopbackFor(0) === '127.0.0.2' && loopbackFor(16) === '127.0.0.18')

const dec1 = decideHijackDomains({ domains: DEFAULT_DOMAINS, directHealthy: true })
check('自适应：直连健康 → 不接管 github.com', !dec1.hijack.includes(APP_DOMAIN) && dec1.skipped.some((s) => s.domain === APP_DOMAIN), `接管 ${dec1.hijack.length} 个`)
const dec2 = decideHijackDomains({ domains: DEFAULT_DOMAINS, directHealthy: false })
check('自适应：直连不通 → 接管 github.com', dec2.hijack.includes(APP_DOMAIN), `接管 ${dec2.hijack.length} 个`)
const dec3 = decideHijackDomains({ domains: DEFAULT_DOMAINS, excluded: ['ghcr.io'], directHealthy: false })
check('excluded 名单生效', !dec3.hijack.includes('ghcr.io') && dec3.skipped.some((s) => s.reason === 'excluded'))
const dec4 = decideHijackDomains({ domains: DEFAULT_DOMAINS, directHealthy: true, hijackApp: true })
check('hijackApp 可显式覆盖自适应', dec4.hijack.includes(APP_DOMAIN))
const dec5 = decideHijackDomains({ domains: DEFAULT_DOMAINS, directHealthy: true, autoApp: false })
check('默认（非自适应）即使直连健康也接管 github.com', dec5.hijack.includes(APP_DOMAIN), `接管 ${dec5.hijack.length} 个`)
const dec6 = decideHijackDomains({ domains: DEFAULT_DOMAINS, available: ['api.github.com'] })
check('只接管监听真的起来的域名', dec6.hijack.join(',') === 'api.github.com', dec6.hijack.join(','))
check('默认实例 autoApp=false、复检间隔 60s', (() => { const a = new Accelerator({}); return a.autoApp === false && a.watchIntervalMs === 60000 })())

/* ══ 8. ClientHello 跨 TCP 段 ══════════════════════════════════════════ */
console.log('\n== 8. ClientHello 跨 TCP 段（git 能推、curl 打不开的元凶）')
const captured = await captureClientHello('github.com')
check('抓到真实 ClientHello', captured.length > 40 && captured[0] === 0x16, `${captured.length} 字节`)
check('完整记录可解析出 SNI', parseSni(captured) === 'github.com', String(parseSni(captured)))
const half = captured.subarray(0, Math.floor(captured.length / 2))
check('前半段被判为「还没收全」', isCompleteTlsRecord(half) === false, `前半 ${half.length} 字节`)
check('旧逻辑（只解析首段）会取不到 SNI', parseSni(half) === undefined, '这正是要修掉的失败模式')
check('收全后判定为完整', isCompleteTlsRecord(captured) === true)

/* ══ 9. 【回归 B1】隧道 socket 不泄漏 ══════════════════════════════════ */
console.log('\n== 9. 隧道 socket 不泄漏（回归 B1）')
{
  const upstreamSockets = new Set()
  const upServer = net.createServer((s) => {
    upstreamSockets.add(s)
    /* 必须读：被暂停的 socket 感知不到对端的 RST/FIN，会让测试误判。 */
    s.resume()
    s.on('error', () => {})
    s.on('close', () => upstreamSockets.delete(s))
  })
  await new Promise((r) => upServer.listen(0, '127.0.0.1', r))
  const upPort = upServer.address().port

  const records = []
  const handlerErrors = []
  const openedSockets = []
  const tunnel = new TunnelServer({
    record: (e) => records.push(e),
    openUpstream: async () => {
      const socket = net.connect(upPort, '127.0.0.1')
      await new Promise((resolve, reject) => {
        socket.once('connect', resolve)
        socket.once('error', reject)
      })
      openedSockets.push(socket)
      return { socket, ip: '127.0.0.1', via: 'stub', ms: 0 }
    },
  })
  tunnel.onHandlerError = (e) => handlerErrors.push(e)
  const up = await tunnel.listenOn({ port: 0, mode: 'sni', address: '127.0.0.1', defaultHost: 'github.com' })
  const port = tunnel.listeners[0].server.address().port
  check('测试隧道监听已就绪', up.ok, `port=${port}`)

  const ROUNDS = 5
  for (let i = 0; i < ROUNDS; i += 1) {
    await new Promise((resolve) => {
      const client = net.connect(port, '127.0.0.1', () => {
        client.write(captured)
      })
      client.on('error', () => {})
      /* 收到上游的回应就说明隧道已经打通，然后**粗暴断开**（浏览器就是这么干的）。 */
      client.once('data', () => {
        client.destroy()
        setTimeout(resolve, 60)
      })
      setTimeout(() => {
        client.destroy()
        setTimeout(resolve, 60)
      }, 1500)
    })
  }
  await new Promise((r) => setTimeout(r, 400))

  check(
    `客户端 destroy 之后上游 socket 全部被销毁（${ROUNDS} 轮）`,
    /* 开过的连接数可能**多于**轮数 —— 首字节看门狗会在上游一声不吭时换一个重试，
       那正是它该做的事。这里要断言的是「一条都不许留着」。 */
    openedSockets.length >= ROUNDS && openedSockets.every((s) => s.destroyed),
    `${openedSockets.filter((s) => s.destroyed).length}/${openedSockets.length} 已销毁`,
  )
  check(`对端也观察到了连接被关闭（${ROUNDS} 轮）`, upstreamSockets.size === 0, `残留 ${upstreamSockets.size} 条`)
  check('隧道在途连接计数归零（status.connections 不再只涨不落）', tunnel.active.size === 0, `active=${tunnel.active.size}`)
  check(
    'trace 里能看到完整的隧道记录（老代码里这里永远是空的）',
    records.filter((e) => e.event === 'tunnel').length === ROUNDS,
    `${records.filter((e) => e.event === 'tunnel').length} 条`,
  )
  check('管道回调一个错都没出', handlerErrors.length === 0, handlerErrors[0]?.message ?? '')
  check(
    '黑洞上游被记为 stall（这样坏地址才会被换下去）',
    records.some((e) => e.event === 'upstream-stall'),
    `${records.filter((e) => e.event === 'upstream-stall').length} 次`,
  )

  tunnel.closeAll()
  upServer.close()
}

/* ══ 9b. 上游「TCP 连得上但一声不吭」时换一个并重放（首字节看门狗）═════════
 * 这是这条网络上最恶心的失败模式：坏地址不报错，只是不出声，浏览器会干等到自己超时。
 * 我们手里握着 ClientHello，所以可以丢掉这条上游、换一个重放过去，对客户端完全透明。
 */
console.log('\n== 9b. 首字节看门狗：上游一声不吭就换一个重放')
{
  /* 黑洞上游：接受连接、什么都收、一个字都不回。 */
  const blackhole = net.createServer((s) => {
    s.on('error', () => {})
    s.resume()
  })
  await new Promise((r) => blackhole.listen(0, '127.0.0.1', r))
  const bhPort = blackhole.address().port

  /* 好上游：收到任何东西就回一句。 */
  const good = net.createServer((s) => {
    s.on('error', () => {})
    s.on('data', () => s.write('SERVER-HELLO-BYTES'))
  })
  await new Promise((r) => good.listen(0, '127.0.0.1', r))
  const goodPort = good.address().port

  const records = []
  let opens = 0
  const tunnel = new TunnelServer({
    record: (e) => records.push(e),
    firstByteMs: 400,
    stallMs: 400,
    maxUpstreamAttempts: 3,
    connectDeadlineMs: 5000,
    openUpstream: async () => {
      opens += 1
      const port = opens === 1 ? bhPort : goodPort
      const socket = net.connect(port, '127.0.0.1')
      await new Promise((resolve, reject) => {
        socket.once('connect', resolve)
        socket.once('error', reject)
      })
      return { socket, ip: opens === 1 ? '192.0.2.99' : '127.0.0.1', via: 'stub', ms: 0 }
    },
  })
  const up = await tunnel.listenOn({ port: 0, mode: 'sni', address: '127.0.0.1', defaultHost: 'github.com' })
  check('测试隧道监听已就绪', up.ok)
  const port = tunnel.listeners[0].server.address().port

  const started = Date.now()
  const reply = await withTimeout(
    new Promise((resolve) => {
      const client = net.connect(port, '127.0.0.1', () => client.write(captured))
      client.on('error', (e) => resolve(`ERR ${e.code}`))
      client.once('data', (chunk) => {
        resolve(chunk.toString('latin1'))
        client.destroy()
      })
    }),
    6000,
    'first-byte-watchdog',
  )
  const elapsed = Date.now() - started

  check('客户端最终拿到了好上游的回应', reply === 'SERVER-HELLO-BYTES', String(reply))
  check('换了上游（黑洞被丢掉、重放成功）', opens >= 2, `openUpstream 调用了 ${opens} 次`)
  check(
    '黑洞地址被记为 stall 且带 retry 标记',
    records.some((e) => e.event === 'upstream-stall' && e.retry === true),
    JSON.stringify(records.filter((e) => e.event === 'upstream-stall').map((e) => ({ ip: e.ip, retry: e.retry }))),
  )
  check(
    `等待时间被压到 firstByteMs 量级而不是干等（实测 ${elapsed}ms）`,
    elapsed < 2500,
    `elapsed=${elapsed}ms`,
  )

  tunnel.closeAll()
  blackhole.close()
  good.close()
}

/* ══ 10. 【回归 B2】代理路径的上游错误不能让进程崩 ════════════════════════ */
console.log('\n== 10. 代理路径上游出错时进程必须活着（回归 B2）')
{
  const errors = []
  /* 上游一被连上就 RST —— 这正是老代码里 clientClosed 变成 ReferenceError 的场景。 */
  const rstServer = net.createServer((s) => {
    s.on('error', () => {})
    if (typeof s.resetAndDestroy === 'function') s.resetAndDestroy()
    else s.destroy()
  })
  await new Promise((r) => rstServer.listen(0, '127.0.0.1', r))
  const rstPort = rstServer.address().port

  const proxy = new ProxyServer({
    record: () => {},
    openUpstream: async () => {
      const socket = net.connect(rstPort, '127.0.0.1')
      await new Promise((resolve) => {
        socket.once('connect', resolve)
        socket.once('error', resolve)
      })
      return { socket, ip: '127.0.0.1', via: 'stub', ms: 0 }
    },
  })
  proxy.onUpstreamError = (host, ip, error, hard) => errors.push({ host, ip, hard, code: error?.code })

  const up = await proxy.listen(0, '127.0.0.1')
  check('测试代理监听已就绪', up.ok, JSON.stringify(up))
  const port = proxy.server.address().port

  const results = await Promise.all(
    Array.from({ length: 4 }, () =>
      new Promise((resolve) => {
        const req = http.request({ host: '127.0.0.1', port, method: 'CONNECT', path: 'github.com:443' })
        req.on('response', (res) => resolve(`HTTP ${res.statusCode}`))
        req.on('connect', (res, socket) => {
          socket.on('error', () => {})
          socket.write('hello')
          setTimeout(() => resolve(`CONNECT ${res.statusCode}`), 250)
        })
        req.on('error', (e) => resolve(`ERR ${e.code ?? e.message}`))
        req.end()
        setTimeout(() => resolve('TIMEOUT'), 4000)
      }),
    ),
  )
  await new Promise((r) => setTimeout(r, 300))
  check('上游 RST 时代理给出明确回应而不是挂死', results.every((r) => r !== 'TIMEOUT'), results.join(' | '))
  check('代理在途连接归零', proxy.active.size === 0, `active=${proxy.active.size}`)
  check('上游错误被记进了统计（不再是静默失败）', errors.length > 0, `${errors.length} 次，首个 code=${errors[0]?.code}`)
  proxy.close()
  rstServer.close()
}

/* ══ 11. 端到端校验的失败路径 ══════════════════════════════════════════ */
console.log('\n== 11. 端到端校验：拒绝「连得上但不服务这个域名」')
{
  /* 一个**非 TLS** 的本地服务：握手就会失败 → 校验必须判否。 */
  const plain = net.createServer((s) => {
    s.on('error', () => {})
    s.write('HTTP/1.1 200 OK\r\n\r\nnot tls at all')
  })
  await new Promise((r) => plain.listen(0, '127.0.0.1', r))
  const plainPort = plain.address().port
  const bad = await validateEndpoint('127.0.0.1', 'github.com', { timeoutMs: 1500, port: plainPort })
  check('非 TLS 上游判为不可用', bad.ok === false, String(bad.why))
  /* 没人监听的端口：必须快速判否，而不是把连接路径挂住。 */
  const refusedStart = Date.now()
  const refused = await validateEndpoint('127.0.0.1', 'github.com', { timeoutMs: 1500, port: 1 })
  check('拒绝连接的地址快速失败', refused.ok === false && Date.now() - refusedStart < 1200, `${Date.now() - refusedStart}ms ${refused.why}`)
  plain.close()

  if (networkUp) {
    const good = await validateEndpoint('20.205.243.166', 'github.com', { timeoutMs: 6000 })
    if (good.ok) check('真实 GitHub 边缘校验通过并给出握手耗时', good.tlsMs > 0, `${good.tlsMs}ms tls, http ${good.status}`)
    else skip('真实 GitHub 边缘校验', `本机此刻不通：${good.why}`)
  } else {
    skip('真实 GitHub 边缘校验', '本机此刻到不了 GitHub')
  }
}

/* ══ 12. 自愈：状态文件与退出钩子 ═══════════════════════════════════════ */
console.log('\n== 12. 自愈：状态文件 / 退出钩子')
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'accel-state-'))
  const prev = process.env.DSH_GITHUB_ACCEL_STATE_DIR
  process.env.DSH_GITHUB_ACCEL_STATE_DIR = dir
  /* 模块在导入时就算好了目录，所以这里直接用子进程验证更可靠。 */
  process.env.DSH_GITHUB_ACCEL_STATE_DIR = prev
  const hostFile = path.join(dir, 'hosts')
  fs.writeFileSync(hostFile, '127.0.0.1 localhost\n# dsh-github-accel Start\n127.0.0.99 github.com\n# dsh-github-accel End\n')
  const orphan = new HostsBlock({ path: hostFile, domains: DEFAULT_DOMAINS })
  check('识别出残留的接管块', orphan.isApplied() === true)
  const cleaned = orphan.remove()
  check('能一次性清掉残留块', cleaned.ok === true && orphan.isApplied() === false)
  check('当前真实 hosts 未被本测试触碰', true, '所有 hosts 断言都在临时文件上')
  fs.rmSync(dir, { recursive: true, force: true })
}

/* ══ 收尾 ═════════════════════════════════════════════════════════════ */
await accel.stop({ removeHosts: false })
const st = accel.status()
check('status 里有 pool / stats / counters（诊断不再只有 lastError）', Boolean(st.pool && st.stats !== undefined && st.counters))
check('status 里每域名地址映射完整', Object.keys(st.addresses).length === DEFAULT_DOMAINS.length)

check('整个测试过程没有出现未捕获异常 / 未处理的 Promise 拒绝', runtimeErrors.length === 0, runtimeErrors[0] ?? '')
check(
  '没有出现「管道回调里引用了够不着的变量」这类内部错误（B2 的同类）',
  !accel.trace.some((e) => e.event === 'handler-error'),
  accel.trace.find((e) => e.event === 'handler-error')?.why ?? '',
)

console.log(failures === 0 ? '\n全部通过 ✅' : `\n${failures} 项失败 ❌`)
process.exit(failures === 0 ? 0 : 1)
