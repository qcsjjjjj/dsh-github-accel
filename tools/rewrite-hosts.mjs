/**
 * dsh-github-accel — 在**不重启 DSH** 的前提下安全地重写 hosts 接管块。
 *
 * 为什么需要「安全」这两个字：hosts 里多写一个域名，就意味着那个域名被指向一个回环
 * 地址。如果那个地址上没有监听，浏览器访问它会得到 `ECONNREFUSED` —— 比不加速更糟。
 * 历史上 Steam++ 就是这么把 GitHub 弄成「完全打不开」的（它在 hosts 里留了 31 条，
 * 自己却没在 443 上监听）。
 *
 * 所以这个脚本：
 *   1. 对每个候选域名的回环地址做一次**真实连接探测**；
 *   2. 只把「确实有人在服务」的域名写进 hosts；
 *   3. 一个都没有就拒绝写入并退出（不改动任何东西）。
 *
 * 用法（写 hosts 需要管理员权限）：
 *   node tools/rewrite-hosts.mjs                 # 默认接管表
 *   node tools/rewrite-hosts.mjs --dry-run       # 只报告，不写
 *   node tools/rewrite-hosts.mjs --domains github.com,api.github.com
 */
import { HostsBlock, DEFAULT_DOMAINS, probePort, DEFAULTS } from '../server/accel.js'

const args = process.argv.slice(2)
const argOf = (name, fallback) => {
  const i = args.indexOf(name)
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback
}
const dryRun = args.includes('--dry-run')
const domains = String(argOf('--domains', DEFAULT_DOMAINS.join(',')))
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean)

const hosts = new HostsBlock({ domains })
const port = Number(argOf('--port', DEFAULTS.sniPort))

console.log(`检查 ${domains.length} 个域名的回环地址上是否有监听（:${port}）…\n`)
const alive = []
const dead = []
for (const domain of domains) {
  const address = hosts.loopbackForDomain(domain)
  /* eslint-disable no-await-in-loop */
  const ok = await probePort(port, 1200, address)
  ;(ok ? alive : dead).push({ domain, address })
  console.log(`  ${ok ? 'OK  ' : 'MISS'}  ${address.padEnd(14)} ${domain}`)
}

console.log('')
if (dead.length) console.log(`将被跳过（没有监听，写了会 CONNREFUSED）：${dead.map((d) => d.domain).join(', ')}`)
if (alive.length === 0) {
  console.error('\n没有任何地址在提供服务 —— 拒绝改写 hosts。请先让插件跑起来（重启 DSH 后开一次开关）。')
  process.exit(1)
}

if (dryRun) {
  console.log(`\n--dry-run：没有改动。将写入 ${alive.length} 条。`)
  process.exit(0)
}

hosts.domains = alive.map((a) => a.domain)
const result = hosts.apply()
if (!result.ok) {
  console.error(`\n写入 hosts 失败：${result.reason} —— 请用管理员身份运行`)
  process.exit(1)
}
console.log(`\n已写入 ${result.entries} 条（备份：${result.backup}）`)
