/**
 * 一次性核查：在真实浏览器里量一下右上角那几个控件的实际位置，确认我们的
 * 兜底按钮和右侧栏开关不重合。
 *
 * 用 DSH profile 里已有的 puppeteer-core + 本机 Edge，headless 打开 DSH Web。
 * 用法：node tools/measure-overlay.mjs [url]
 *
 * 依赖：profile 的 node_modules 里要有 puppeteer-core（`dsh` 自带依赖之一）。
 */
import { existsSync } from 'node:fs'
import { homedir } from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const CANDIDATES = [
  path.join(process.env['PROGRAMFILES(X86)'] ?? 'C:\\Program Files (x86)', 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
  path.join(process.env.PROGRAMFILES ?? 'C:\\Program Files', 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
]
const edge = CANDIDATES.find((p) => existsSync(p))
if (!edge) {
  console.error('找不到 msedge.exe，试过：\n  ' + CANDIDATES.join('\n  '))
  process.exit(1)
}

let puppeteer
try {
  /* puppeteer-core 装在 DSH profile 里，不在本插件目录，所以按绝对路径 import。
     DSH_HOME 未设置时退回 ~/.dsh。 */
  const profileDir = process.env.DSH_GITHUB_ACCEL_PROFILE_DIR ?? path.join(process.env.DSH_HOME ?? path.join(homedir(), '.dsh'), 'profiles', 'web')
  const entry = path.join(profileDir, 'node_modules', 'puppeteer-core', 'lib', 'puppeteer', 'puppeteer-core.js')
  if (!existsSync(entry)) throw new Error(`没有找到 ${entry}（可用 DSH_GITHUB_ACCEL_PROFILE_DIR 指定 profile 目录）`)
  puppeteer = (await import(pathToFileURL(entry).href)).default
} catch (error) {
  console.error('puppeteer-core 不可用：' + error.message)
  process.exit(1)
}

const browser = await puppeteer.launch({
  executablePath: edge,
  headless: 'new',
  args: ['--no-first-run', '--no-default-browser-check', '--window-size=1400,900'],
})
const page = await browser.newPage()
await page.setViewport({ width: 1400, height: 900 })
await page.goto(process.argv[2] ?? 'http://127.0.0.1:3080/', { waitUntil: 'domcontentloaded', timeout: 60000 })
/* 等前端挂起来（会话界面出现即算就绪） */
await new Promise((r) => setTimeout(r, 8000))

const report = await page.evaluate(() => {
  const box = (el) => {
    if (!el) return null
    const r = el.getBoundingClientRect()
    const style = getComputedStyle(el)
    return {
      tag: el.tagName.toLowerCase(),
      cls: el.className && String(el.className).slice(0, 60),
      left: Math.round(r.left),
      right: Math.round(r.right),
      top: Math.round(r.top),
      width: Math.round(r.width),
      height: Math.round(r.height),
      display: style.display,
      visible: style.display !== 'none' && r.width > 0,
    }
  }
  const pick = (sel) => [...document.querySelectorAll(sel)].map(box)
  return {
    url: location.href,
    bodyWidth: document.body.getBoundingClientRect().width,
    accelOverlay: pick('[data-github-accel-overlay]'),
    accelHeader: pick('[data-github-accel-in-header]'),
    heroRightbar: pick('[data-hero-rightbar-trigger]'),
    productExpand: pick('[data-sidebar-right-expand]'),
    hasHeaderSeat: document.querySelectorAll('[data-github-accel-in-header]').length > 0,
    activePanelVisibleText: (document.body.innerText || '').slice(0, 120).replace(/\s+/g, ' '),
  }
})

console.log(JSON.stringify(report, null, 1))

const visibleAccel = report.accelOverlay.concat(report.accelHeader).filter((b) => b && b.visible)
const others = report.heroRightbar.concat(report.productExpand).filter((b) => b && b.visible)
for (const a of visibleAccel) {
  for (const o of others) {
    const overlap = a.left < o.right && o.left < a.right && a.top < o.bottom && o.top < a.bottom
    console.log(
      `重叠检查: accel(${a.left}-${a.right}) vs ${o.cls || o.tag}(${o.left}-${o.right}) -> ${overlap ? '❌ 重合' : '✅ 不重合'}`,
    )
  }
}
if (!visibleAccel.length) console.log('注意：页面上没找到可见的加速按钮（可能还没挂载或当前状态不同）')

await browser.close()
