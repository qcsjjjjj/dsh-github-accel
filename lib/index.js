/**
 * dsh-github-accel host entry.
 *
 * 宿主半边负责真正的加速（见 ../server/accel.js），浏览器半边只需要三个 GET 路由：
 *
 *   GET /dsh-github-accel/status                    -> 状态快照
 *   GET /dsh-github-accel/toggle?on=1|0&mode=both   -> 开关
 *   GET /dsh-github-accel/diagnose                  -> 现场全链路自检
 *
 * GET + query，不用 POST：本宿主的 exact 路由对 POST 一律 405
 * （和 dsh-sidebar-panels 记录的是同一条约束）。
 *
 * 模式：
 *   both   —— hosts 接管（需要管理员写 hosts）+ 127.0.0.1:18999 的 CONNECT 代理
 *   hosts  —— 只要系统级那条（hosts + 一域名一地址的 SNI 直通）
 *   proxy  —— 只要 CONNECT 代理；不需要管理员，但只有认 HTTPS_PROXY 的工具受益
 *
 * ── 中文备注 ────────────────────────────────────────────────────────────────
 * 三条通路互为备份：hosts（系统级）、CONNECT 代理（工具链）、PAC/系统代理
 * （无需管理员，且能绕过浏览器自己的 Secure DNS）。装载时会先修上一次的残局
 * （repairIfStale），再按上次的开关状态自动恢复。
 */
import { Accelerator, DEFAULT_DOMAINS } from '../server/accel.js'

export const name = 'dsh-github-accel'

/** Services required before the routes can mount. */
export const inject = ['webServer']

export const STATUS_PATH = '/dsh-github-accel/status'
export const TOGGLE_PATH = '/dsh-github-accel/toggle'
export const DIAGNOSE_PATH = '/dsh-github-accel/diagnose'

/** One accelerator per host process. */
const accel = new Accelerator()
let lastReport = null
let enabled = false
let bootstrapNote = null

function json(res, code, body) {
  const text = JSON.stringify(body)
  res.writeHead(code, {
    'content-type': 'application/json',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(text),
  })
  res.end(text)
}

/**
 * 一次 start() 到底算不算「开了」。
 * 三条通路任一可用就算开；hosts 模式那条只认系统级通路真的起来。
 */
function evaluate(report, mode) {
  if (!report) return false
  const sniOk = Array.isArray(report.sni) ? report.sni.some((r) => r?.ok) : Boolean(report.sni?.ok)
  const hostsOk = report.hosts?.ok === true
  const proxyOk = report.proxy?.ok === true
  const pacOk = report.pac?.ok === true
  if (mode === 'proxy') return proxyOk || pacOk
  if (mode === 'hosts') return sniOk && hostsOk
  return hostsOk || proxyOk || pacOk
}

function status() {
  return {
    enabled,
    domains: DEFAULT_DOMAINS,
    bootstrapNote,
    ...accel.status(),
    report: lastReport,
  }
}

/**
 * Mount the routes.
 * @param ctx - host context carrying webServer.
 */
export function apply(ctx) {
  ctx.effect(
    () => () => {
      /* 插件卸载 / DSH 退出时别把 hosts 留在接管状态：优雅撤掉。 */
      void accel.stop().catch(() => {})
    },
    'dsh-github-accel: teardown',
  )

  /*
   * 装载即自检：
   *   ① 上一次若是被强杀（hosts 留着、443 上没人监听），先修干净 —— 否则全系统的
   *      GitHub 会变成「连到一个没有服务的回环地址」，比不加速更糟；
   *   ② 把上次的开关状态接回来（退出钩子会撤 hosts，不接回来用户会以为「又坏了」）。
   */
  void accel
    .bootstrap()
    .then((result) => {
      bootstrapNote = {
        repaired: result.repaired,
        resumed: result.resumed,
        error: result.error ? String(result.error.message ?? result.error) : undefined,
      }
      if (result.resumed) {
        lastReport = result.report
        enabled = evaluate(result.report, result.report?.mode ?? 'both')
      }
    })
    .catch((error) => {
      bootstrapNote = { error: String(error?.message ?? error) }
    })

  ctx.inject(['webServer'], (host) => {
    host.webServer.register({
      kind: 'exact',
      path: STATUS_PATH,
      handler: (req, res) => json(res, 200, status()),
    })

    host.webServer.register({
      kind: 'exact',
      path: DIAGNOSE_PATH,
      handler: (req, res) => {
        void accel
          .diagnose()
          .then((result) => json(res, 200, { ...result, ...status() }))
          .catch((error) => json(res, 500, { error: error?.message ?? String(error), ...status() }))
      },
    })

    host.webServer.register({
      kind: 'exact',
      path: TOGGLE_PATH,
      handler: async (req, res) => {
        let on = true
        let mode = 'both'
        let pac = accel.pacPolicy
        try {
          const url = new URL(req.url ?? TOGGLE_PATH, 'http://dsh.invalid')
          on = url.searchParams.get('on') !== '0'
          mode = url.searchParams.get('mode') ?? 'both'
          pac = url.searchParams.get('pac') ?? accel.pacPolicy
        } catch {
          /* 参数异常按默认值处理：这是本机控制面，不该因为解析失败 500。 */
        }
        try {
          if (on) {
            lastReport = await accel.start({ mode, writeHosts: mode !== 'proxy', pac })
            enabled = evaluate(lastReport, mode)
          } else {
            lastReport = await accel.stop({ removeHosts: true })
            enabled = false
          }
          json(res, 200, status())
        } catch (error) {
          json(res, 500, { error: error?.message ?? String(error), ...status() })
        }
      },
    })
  })
}
