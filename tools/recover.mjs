/**
 * dsh-github-accel — 应急还原（**不需要 DSH 在跑**）
 *
 * 什么时候用：DSH 被强杀 / 崩溃 / 蓝屏重启之后，hosts 里可能还留着接管块，
 * 而 443 上已经没有人监听 —— 那时全系统的 GitHub 会变成 `ECONNREFUSED 127.0.0.x:443`，
 * 浏览器上表现为「GitHub 完全打不开」，而且看不出是谁干的。
 *
 * 一条命令恢复原状：
 *   1. 撤掉 hosts 里的接管块；
 *   2. 还原被改过的系统代理（PAC / AutoConfigURL）；
 *   3. 删掉状态文件。
 *
 * 用法（写 hosts 需要管理员权限）：
 *   node tools/recover.mjs              # 只撤我们写的那一段，其余原样保留
 *   node tools/recover.mjs --restore    # 直接用首次接管时的备份整体覆盖 hosts（更彻底）
 *   node tools/recover.mjs --dry-run    # 只看会发生什么，不动任何东西
 */
import fs from 'node:fs'
import { HostsBlock, DEFAULTS, HOSTS_START } from '../server/accel.js'
import { disableAutoConfig, readProxyState } from '../server/sysproxy.js'

const dryRun = process.argv.includes('--dry-run')
const restore = process.argv.includes('--restore')
const path = DEFAULTS.hostsPath
const backup = `${path}.dsh-github-accel.bak`

console.log('== dsh-github-accel 应急还原 ==\n')

if (!fs.existsSync(path)) {
  console.error(`找不到 hosts：${path}`)
  process.exit(1)
}

const hosts = new HostsBlock({ path })
const applied = hosts.isApplied()
console.log(`hosts 路径        : ${path}`)
console.log(`接管块是否存在    : ${applied ? '是（需要清理）' : '否'}`)
console.log(`备份文件          : ${fs.existsSync(backup) ? backup : '（没有）'}`)
const proxy = readProxyState()
console.log(`AutoConfigURL     : ${proxy.autoConfigUrl.exists ? proxy.autoConfigUrl.value : '（未设置）'}`)
console.log('')

if (dryRun) {
  console.log('--dry-run：什么都没做。')
  process.exit(0)
}

let failures = 0

if (restore) {
  if (!fs.existsSync(backup)) {
    console.error(`没有备份文件，无法 --restore：${backup}`)
    failures += 1
  } else {
    try {
      fs.copyFileSync(backup, path)
      console.log('已用备份整体还原 hosts')
    } catch (error) {
      console.error(`还原 hosts 失败：${error.code ?? error.message} —— 请用管理员身份运行`)
      failures += 1
    }
  }
} else if (applied) {
  const result = hosts.remove()
  if (result.ok) console.log(result.changed ? '已移除 hosts 接管块' : 'hosts 里没有接管块')
  else {
    console.error(`移除失败：${result.reason} —— 请用管理员身份运行`)
    failures += 1
  }
}

const restored = disableAutoConfig()
console.log(restored.changed ? `已还原系统代理（${restored.restored}）` : '系统代理没有被我们改过，无需还原')

if (failures === 0) {
  console.log('\n完成。现在浏览器 / git / curl 都会走 GitHub 的真实地址。')
  process.exit(0)
}
console.log('\n有步骤失败，请按上面的提示处理后重试。')
process.exit(1)
