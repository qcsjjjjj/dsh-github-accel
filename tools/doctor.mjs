/**
 * dsh-github-accel — 一屏体检（**只读，不改任何东西**）
 *
 * 「GitHub 又不行了」的时候第一条命令就是它。它会依次回答：
 *   1. hosts 现在是什么状态？有没有别人的接管块？每条映射上真的有监听吗？
 *   2. CONNECT 代理在不在？
 *   3. 系统代理 / PAC 有没有被改？
 *   4. 每个热域名的候选地址，现在**端到端**能不能用（TLS 校验证书 + 真发 HTTP 请求）？
 *   5. 结论 + 下一步该做什么。
 *
 * 用法：
 *   node tools/doctor.mjs
 *   node tools/doctor.mjs --hosts github.com,raw.githubusercontent.com
 *   node tools/doctor.mjs --json > doctor.json
 */
import { Accelerator, DEFAULT_DOMAINS, DEFAULTS, HOT_DOMAINS, HostsBlock, probePort, validateEndpoint } from '../server/accel.js'
import { readProxyState } from '../server/sysproxy.js'

const args = process.argv.slice(2)
const argOf = (name, fallback) => {
  const i = args.indexOf(name)
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback
}
const asJson = args.includes('--json')
const targets = String(argOf('--hosts', HOT_DOMAINS.join(',')))
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean)

const out = { at: new Date().toISOString(), hosts: {}, proxy: {}, domains: [], verdict: 'unknown', actions: [] }
const say = (...a) => {
  if (!asJson) console.log(...a)
}

/* ── 1. hosts ────────────────────────────────────────────────────────────── */
const hosts = new HostsBlock({ domains: DEFAULT_DOMAINS })
const applied = hosts.isApplied()
const entries = hosts.currentEntries()
const foreign = hosts.detectForeign()
const sniPort = DEFAULTS.sniPort

say('== 1. hosts 接管')
say(`  接管块存在 : ${applied ? '是' : '否'}`)
say(`  条目数     : ${entries.length}`)
say(`  别人的块   : ${foreign.length ? foreign.join(', ') + '  ← 注意，别和它抢' : '（无）'}`)

const listening = []
for (const entry of entries) {
  /* eslint-disable no-await-in-loop */
  const ok = await probePort(sniPort, 1000, entry.address)
  listening.push({ ...entry, listening: ok })
}
const orphans = listening.filter((e) => !e.listening)
for (const e of listening) {
  say(`    ${e.listening ? 'OK  ' : 'DEAD'}  ${e.address.padEnd(14)} ${e.domain}`)
}
out.hosts = { applied, entries: listening.length, orphan: orphans.length, foreign }
if (foreign.length) out.actions.push(`hosts 里有别的加速器（${foreign.join(', ')}）的接管块：先关掉它，再开本插件`)
if (orphans.length) out.actions.push(`有 ${orphans.length} 条映射指向没有监听的地址（${orphans.map((o) => o.domain).join(', ')}）：运行 node tools/recover.mjs 清掉`)

/* ── 2. CONNECT 代理 ─────────────────────────────────────────────────────── */
say('\n== 2. CONNECT 代理')
const proxyPort = Number(argOf('--proxy-port', DEFAULTS.proxyPort))
const proxyUp = await probePort(proxyPort)
say(`  127.0.0.1:${proxyPort} : ${proxyUp ? '在监听' : '没有监听'}`)
out.proxy = { port: proxyPort, listening: proxyUp, ...readProxyState() }
if (!proxyUp) out.actions.push('CONNECT 代理没起来：在插件里关一下再开一次（它不需要管理员权限，应该总能起来）')

/* ── 3. 系统代理 / PAC ───────────────────────────────────────────────────── */
say('\n== 3. 系统代理（PAC）')
const state = readProxyState()
say(`  AutoConfigURL : ${state.autoConfigUrl.exists ? state.autoConfigUrl.value : '（未设置）'}`)
say(`  ProxyEnable   : ${state.proxyEnable.exists ? state.proxyEnable.value : '（未设置）'}`)
say(`  ProxyServer   : ${state.proxyServer.exists ? state.proxyServer.value : '（未设置）'}`)

/* ── 4. 每个热域名的候选地址 ────────────────────────────────────────────── */
say('\n== 4. 上游可达性（端到端：校验证书 + 真发一次请求）')
const table = new Accelerator({ watchIntervalMs: 0, healthIntervalMs: 0 }).table

for (const host of targets) {
  const all = await table.candidates(host)
  /* 只探前 N 个：候选池现在有十几个，全探一轮要好几分钟。
     但**必须把总数说出来** —— 否则「1/4 可用」会让人以为池子里只有 4 个、快要没救了，
     而实际上隧道会一直往下扫到第 12 个。 */
  const PROBE = Number(process.env.DOCTOR_PROBE ?? 8)
  const ips = all.slice(0, PROBE)
  if (ips.length === 0) {
    say(`  ${host.padEnd(38)} 没有候选地址（DNS 与备用池都没给）`)
    out.domains.push({ host, ips, good: [], total: 0 })
    continue
  }
  const results = await Promise.all(ips.map((ip) => validateEndpoint(ip, host, { timeoutMs: 7000 }).catch(() => undefined)))
  const good = []
  results.forEach((r, i) => {
    if (!r) return
    if (r.ok) good.push({ ip: ips[i], tlsMs: r.tlsMs, ttfbMs: r.ttfbMs, status: r.status })
  })
  out.domains.push({ host, ips, good, total: all.length })
  const best = good.reduce((a, b) => (a === null || b.tlsMs < a.tlsMs ? b : a), null)
  say(
    `  ${host.padEnd(38)} 探了 ${good.length}/${ips.length} 个可用（候选池共 ${all.length} 个）` +
      (best ? `  最快 ${best.ip} tls=${best.tlsMs}ms ttfb=${best.ttfbMs}ms http=${best.status}` : '  ← 前几个全不可用'),
  )
}

const deadHosts = out.domains.filter((d) => d.good.length === 0)
if (deadHosts.length) {
  out.actions.push(`这些域名当前没有任何可用上游：${deadHosts.map((d) => d.host).join(', ')} —— 大概率是本机网络到 GitHub 断了，等一会儿再试`)
}

/* ── 5. 结论 ─────────────────────────────────────────────────────────────── */
const hardFail = orphans.length > 0 || deadHosts.length > 0 || foreign.length > 0
out.verdict = hardFail ? 'attention' : applied || proxyUp ? 'healthy' : 'off'

say('\n== 结论')
say(`  ${out.verdict === 'healthy' ? '✅ 加速链路正常' : out.verdict === 'off' ? '⚪ 加速没开（不影响正常使用）' : '⚠️ 有问题需要处理'}`)
for (const action of out.actions) say(`  · ${action}`)
if (out.actions.length === 0) say('  · 没有需要处理的事项')

if (asJson) process.stdout.write(JSON.stringify(out, null, 2))
process.exit(hardFail ? 1 : 0)
