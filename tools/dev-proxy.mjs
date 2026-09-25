/**
 * dsh-github-accel — 临时 CONNECT 代理（给还没重启 DSH 的场景用）
 *
 * 背景：插件代码改了（多候选地址 + 备用池），但已经加载进 DSH 进程里的还是旧代码，
 * 要重启才生效。这个脚本直接跑**新代码**的代理半边，不碰 hosts、不绑 443，
 * 所以零风险：
 *
 *   node tools/dev-proxy.mjs          # 默认 127.0.0.1:18998
 *   $env:HTTPS_PROXY = 'http://127.0.0.1:18998'
 *   git ls-remote https://github.com/...
 *
 * 用完 Ctrl+C 或杀进程即可。
 */
import { Accelerator } from '../server/accel.js'

const port = Number(process.env.DSH_GITHUB_ACCEL_DEV_PROXY_PORT ?? 18998)
const accel = new Accelerator({ proxyPort: port })

const result = await accel.listenConnectProxy(port)
if (!result.ok) {
  console.error(`dev-proxy 启动失败: ${result.reason}`)
  process.exit(1)
}
console.log(`dsh-github-accel dev-proxy listening on http://127.0.0.1:${port} (CONNECT, 多候选+备用池)`)
process.on('SIGINT', () => process.exit(0))
process.on('SIGTERM', () => process.exit(0))
