/**
 * dsh-github-accel 应急还原工具
 *
 * 用途：如果 DSH 被强杀（而不是正常退出），插件来不及撤掉 hosts 接管块，
 * 那 github.com 会被指到没有服务的 127.0.0.1，浏览器会连不上。
 * 这条命令直接按标记把块删干净，不需要 DSH 在跑。
 *
 * 用法（需要管理员权限，因为 hosts 在系统目录）：
 *   node tools/reset-hosts.mjs            # 移除接管块
 *   node tools/reset-hosts.mjs --restore  # 用备份文件整体还原
 */
import fs from 'node:fs'
import { HostsBlock, DEFAULTS, HOSTS_START } from '../server/accel.js'

const path = DEFAULTS.hostsPath
const restore = process.argv.includes('--restore')
const backup = `${path}.dsh-github-accel.bak`

if (!fs.existsSync(path)) {
  console.error(`找不到 hosts: ${path}`)
  process.exit(1)
}

try {
  if (restore) {
    if (!fs.existsSync(backup)) {
      console.error(`没有备份文件: ${backup}`)
      process.exit(1)
    }
    fs.copyFileSync(backup, path)
    console.log(`已用备份还原 hosts: ${backup} -> ${path}`)
  } else {
    const hosts = new HostsBlock({ path })
    const before = fs.readFileSync(path, 'utf8').includes(HOSTS_START)
    const result = hosts.remove()
    console.log(
      before
        ? result.ok
          ? `已移除接管块（${path}）`
          : `移除失败：${result.reason}  —— 请用管理员身份运行`
        : '当前 hosts 里没有接管块（无需处理）',
    )
  }
} catch (error) {
  console.error(`失败：${error.code ?? error.message} —— 请用管理员身份运行`)
  process.exit(1)
}
