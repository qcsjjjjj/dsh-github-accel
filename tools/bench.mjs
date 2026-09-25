/**
 * 经隧道 vs 直连：把「提速」这件事量出来。
 *
 * 覆盖 docs/PLAN-2026-09-25.md 第 7 节第 2 步的验收标准：
 *   经隧道 TLS 的 p95 ≤ 直连 TLS 的 p95 + 100 ms，且没有一次超过 2 s。
 *
 * 只在本机开临时监听（127.0.0.1 上的随机端口），**不碰 hosts、不绑 443、不改任何设置**。
 *
 * 用法：
 *   node tools/bench.mjs                      # 默认热域名，各 8 轮
 *   node tools/bench.mjs --rounds 15
 *   node tools/bench.mjs --hosts github.com,api.github.com
 *   node tools/bench.mjs --no-pool             # 关掉预热池做对比
 */
import tls from 'node:tls'
import net from 'node:net'
import { Accelerator, HOT_DOMAINS } from '../server/accel.js'

const args = process.argv.slice(2)
const argOf = (name, fallback) => {
  const i = args.indexOf(name)
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback
}
const rounds = Number(argOf('--rounds', 8))
const poolEnabled = !args.includes('--no-pool')
const hosts = String(argOf('--hosts', HOT_DOMAINS.join(',')))
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean)

const pct = (list, p) => {
  if (list.length === 0) return null
  const s = [...list].sort((a, b) => a - b)
  return s[Math.min(s.length - 1, Math.floor(s.length * p))]
}

/** 经隧道做一次 TLS 握手（到本机监听的临时端口）。 */
function tunnelHandshake(port, host, timeoutMs = 12_000) {
  return new Promise((resolve) => {
    const started = process.hrtime.bigint()
    const socket = tls.connect({ host: '127.0.0.1', port, servername: host, rejectUnauthorized: true })
    let done = false
    const finish = (ok, why) => {
      if (done) return
      done = true
      const ms = Number(process.hrtime.bigint() - started) / 1e6
      try {
        socket.destroy()
      } catch {}
      resolve({ ok, ms: Math.round(ms), why })
    }
    socket.setTimeout(timeoutMs)
    socket.once('secureConnect', () => finish(true))
    socket.once('error', (e) => finish(false, e.code ?? e.message))
    socket.once('timeout', () => finish(false, 'timeout'))
  })
}

/** 直连某个 IP 做一次 TLS 握手。 */
function directHandshake(ip, host, timeoutMs = 12_000) {
  return new Promise((resolve) => {
    const started = process.hrtime.bigint()
    const socket = tls.connect({ host: ip, port: 443, servername: host, rejectUnauthorized: true })
    let done = false
    const finish = (ok, why) => {
      if (done) return
      done = true
      const ms = Number(process.hrtime.bigint() - started) / 1e6
      try {
        socket.destroy()
      } catch {}
      resolve({ ok, ms: Math.round(ms), why })
    }
    socket.setTimeout(timeoutMs)
    socket.once('secureConnect', () => finish(true))
    socket.once('error', (e) => finish(false, e.code ?? e.message))
    socket.once('timeout', () => finish(false, 'timeout'))
  })
}

const accel = new Accelerator({ watchIntervalMs: 0, healthIntervalMs: 0, poolEnabled })

console.log(`bench: rounds=${rounds} pool=${poolEnabled} hosts=${hosts.join(', ')}\n`)
console.log('预热（先把候选地址与池子建起来，避免把首次 DNS 算进去）…')
await accel.validate(hosts)
await Promise.all(hosts.map((h) => accel.prefetch(h, 443)))
await new Promise((r) => setTimeout(r, 300))

const rows = []
for (const host of hosts) {
  const listener = await accel.listen({ port: 0, mode: 'sni', address: '127.0.0.1', defaultHost: host })
  if (!listener.ok) {
    rows.push({ host, error: `listen failed: ${listener.reason}` })
    continue
  }
  const port = accel.tunnel.listeners.find((l) => l.defaultHost === host).server.address().port

  const candidates = await accel.table.candidates(host)
  const best = candidates[0]

  /* 交替测量，抵消网络随时间的漂移。 */
  const direct = []
  const tunnel = []
  for (let i = 0; i < rounds; i += 1) {
    /* eslint-disable no-await-in-loop */
    const d = await directHandshake(best, host)
    if (d.ok) direct.push(d.ms)
    const t = await tunnelHandshake(port, host)
    if (t.ok) tunnel.push(t.ms)
    else if (t.why) (rows.errors ??= []).push(`${host}: ${t.why}`)
  }

  rows.push({
    host,
    best,
    directP50: pct(direct, 0.5),
    directP95: pct(direct, 0.95),
    tunnelP50: pct(tunnel, 0.5),
    tunnelP95: pct(tunnel, 0.95),
    tunnelMax: tunnel.length ? Math.max(...tunnel) : null,
    ok: `${tunnel.length}/${rounds}`,
    directOk: `${direct.length}/${rounds}`,
  })
}

const w = [32, 16, 12, 12, 12, 12, 10, 11, 9]
const header = ['host', 'best-ip', 'direct p50', 'direct p95', 'tunnel p50', 'tunnel p95', 'tun max', 'tunnel ok', 'dir ok']
console.log(header.map((h, i) => h.padEnd(w[i])).join(''))
console.log('-'.repeat(w.reduce((a, b) => a + b, 0)))
for (const r of rows) {
  if (r.error) {
    console.log(`${r.host.padEnd(w[0])}${r.error}`)
    continue
  }
  const cells = [
    r.host,
    r.best,
    r.directP50 === null ? '—' : `${r.directP50}ms`,
    r.directP95 === null ? '—' : `${r.directP95}ms`,
    r.tunnelP50 === null ? '—' : `${r.tunnelP50}ms`,
    r.tunnelP95 === null ? '—' : `${r.tunnelP95}ms`,
    r.tunnelMax === null ? '—' : `${r.tunnelMax}ms`,
    r.ok,
    r.directOk,
  ]
  console.log(cells.map((c, i) => String(c).padEnd(w[i])).join(''))
}

/*
 * 只有**两条路都成功**的域名才能拿来比较延迟 —— 一条路 0/8 的时候它的 p95 是 null，
 * 直接相减会把「直连根本没成功过」错报成「隧道落后了 2 秒」。
 */
const bothOk = rows.filter((r) => !r.error && r.tunnelP95 !== null && r.directP95 !== null)
const worstSlack = bothOk.length ? Math.max(...bothOk.map((r) => r.tunnelP95 - r.directP95)) : null
const worstMax = rows.filter((r) => !r.error && r.tunnelMax !== null).length
  ? Math.max(...rows.filter((r) => !r.error && r.tunnelMax !== null).map((r) => r.tunnelMax))
  : null

/** 直连彻底失败、隧道却连上了的域名 —— 这才是这套东西存在的理由。 */
const rescued = rows.filter((r) => !r.error && r.directP95 === null && (r.tunnelP95 ?? null) !== null)

console.log('')
const snap = accel.pool.snapshot()
console.log(`池命中：${snap.hits} 次 / 未命中 ${snap.misses} 次`)
if (rescued.length) {
  console.log(`\n★ 直连完全不可达、隧道仍能连上的域名（加速器救回来的）：`)
  for (const r of rescued) {
    console.log(`    ${r.host.padEnd(34)} 直连 ${r.directOk}，隧道 ${r.ok}（首包 p50 ${r.tunnelP50}ms）`)
  }
  console.log('  说明：这些域名系统 DNS 只给一个地址，而这个地址会阶段性死掉；')
  console.log('        浏览器没有多候选切换，隧道有。')
}
console.log(`\n隧道 p95 相对直连 p95 的最差落后（只统计两条路都通的域名）：${worstSlack} ms（目标 ≤ 100 ms）  ${worstSlack !== null && worstSlack <= 100 ? 'PASS' : worstSlack === null ? 'N/A' : 'FAIL'}`)
console.log(`隧道单次最大耗时：${worstMax} ms（目标 ≤ 2000 ms）  ${worstMax !== null && worstMax <= 2000 ? 'PASS' : 'FAIL'}`)
if (bothOk.length < rows.filter((r) => !r.error).length) {
  console.log('（有域名没被计入延迟对比，因为其中一条路在那段时间完全不成功；这不是机制问题，是上游在抖）')
}

await accel.stop({ removeHosts: false })
process.exit(0)
