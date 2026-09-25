/** 确认 raceConnect 的单候选超时到底有没有生效（用必然不可达的 TEST-NET 黑洞）。 */
import { raceConnect } from '../server/net.js'

const t0 = Date.now()
const result = await raceConnect({
  host: 'blackhole',
  port: 443,
  ips: ['192.0.2.1', '192.0.2.2', '192.0.2.3'],
  width: 3,
  perTimeoutMs: 1200,
  staggerMs: 200,
  totalMs: 4000,
})
  .then(() => 'connected')
  .catch((e) => 'rejected: ' + e.tried.join(', '))
const ms = Date.now() - t0
console.log(`耗时 ${ms} ms  ->  ${result}`)
console.log(
  ms < 2200
    ? '✅ 单候选超时生效（~1.4s 全部判失败）'
    : '❌ 单候选超时**没有**生效 —— 实际是撞了 totalMs 兜底（4s），这正是「GitHub 不通时每个连接都要干等 4 秒」的原因',
)
process.exit(0)
