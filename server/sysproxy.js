/**
 * 第三条腿：PAC + 当前用户的系统代理（Windows / WinINET）。
 *
 * ## 为什么需要它
 *
 * `hosts` 那条腿有一个硬天花板：**需要管理员权限**。DSH 不是管理员启动时写不进去，
 * 浏览器就完全没有覆盖，只剩下给命令行用的 CONNECT 代理。PAC 走的是用户级注册表
 * （`HKCU`），不需要管理员，正好补上这个缺口。
 *
 * 另外两种场景也用它：
 *   - 安全软件会拦 hosts 写入（Windows Defender 的 `SettingsModifier:Win32/HostsFileHijack`
 *     会拦写并把 hosts 重置成默认值，官方没有白名单）—— 那种机器上 hosts 通路根本不可用；
 *   - 按 RFC 7838 §2.4，「被配置为使用代理的客户端**不应该**为请求直连替代服务」，
 *     也就是说走 PAC 时浏览器不会绕开代理去试 HTTP/3 —— 而 hosts 那条路上
 *     浏览器仍然会往 `127.0.0.x:443/udp` 试一次 QUIC（本机没有 UDP 服务，
 *     内核立刻回 ICMP，代价很小但确实存在）。
 *
 * ## 一个曾经写错的理由（保留在此，免得后人再抄一遍）
 *
 * 本文件早先版本说「PAC 抗浏览器 Secure DNS」——**这是不对的**。Chromium 的
 * `HostResolverManager` 在 `ResolveLocally()` 里**同步**处理 HOSTS 条目
 * （`ServeFromHosts()`，注释明确写着 "handled synchronously ... prior to Job creation"），
 * Secure DNS 只在需要真去查 DNS 的时候才介入，因此**不会绕过 hosts**。
 * hosts 通路真正的弱点只有「需要管理员」和「会被安全软件拦」两条。
 *
 * ## 安全规约
 *
 * 1. 只动 `AutoConfigURL` 一个值，**先把原值（以及存在与否）记下来**，关闭时逐字段还原；
 * 2. 还原信息写进状态文件，**进程被强杀后下次启动也能还原**；
 * 3. `ProxyEnable` / `ProxyServer` 一律不碰 —— 那是别人的地盘。
 */
import fs from 'node:fs'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import { execFileSync } from 'node:child_process'

const REG_KEY = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'

export const STATE_DIR =
  process.env.DSH_GITHUB_ACCEL_STATE_DIR ?? path.join(os.homedir(), '.dsh', 'dsh-github-accel')

export function ensureStateDir() {
  try {
    fs.mkdirSync(STATE_DIR, { recursive: true })
  } catch {}
  return STATE_DIR
}

/** 读一个注册表值；不存在返回 `{ exists: false }`。 */
export function readReg(name) {
  if (process.platform !== 'win32') return { exists: false, unsupported: true }
  try {
    const out = execFileSync('reg.exe', ['query', REG_KEY, '/v', name], {
      encoding: 'utf8',
      windowsHide: true,
      /* 值不存在时 reg.exe 会往 stderr 写一行本地化的错误，别让它污染调用方的输出。 */
      stdio: ['ignore', 'pipe', 'ignore'],
    })
    const m = out.match(new RegExp(`${name}\\s+REG_\\w+\\s+(.*)`, 'i'))
    return m ? { exists: true, value: m[1].trim() } : { exists: false }
  } catch {
    return { exists: false }
  }
}

export function writeReg(name, value) {
  if (process.platform !== 'win32') return { ok: false, reason: 'not-windows' }
  try {
    execFileSync('reg.exe', ['add', REG_KEY, '/v', name, '/t', 'REG_SZ', '/d', value, '/f'], {
      encoding: 'utf8',
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'ignore'],
    })
    return { ok: true }
  } catch (error) {
    return { ok: false, reason: `reg-add-failed:${error.status ?? error.message}` }
  }
}

export function deleteReg(name) {
  if (process.platform !== 'win32') return { ok: false, reason: 'not-windows' }
  try {
    execFileSync('reg.exe', ['delete', REG_KEY, '/v', name, '/f'], {
      encoding: 'utf8',
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'ignore'],
    })
    return { ok: true }
  } catch {
    /* 值本来就不存在时 reg delete 也会返回非 0 —— 那就是我们想要的状态。 */
    return { ok: true, alreadyAbsent: true }
  }
}

/**
 * 广播一次设置变更，让已经开着的浏览器立刻重新读取代理配置。
 * 失败无所谓：浏览器自己也会轮询。
 */
export function notifySettingsChanged() {
  if (process.platform !== 'win32') return
  try {
    execFileSync(
      'powershell.exe',
      [
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        "$sig='[DllImport(\"user32.dll\",SetLastError=true,CharSet=CharSet.Auto)]public static extern IntPtr SendMessageTimeout(IntPtr hWnd,uint Msg,UIntPtr wParam,string lParam,uint fuFlags,uint uTimeout,out UIntPtr lpdwResult);';" +
          "$t=Add-Type -MemberDefinition $sig -Name W -Namespace I -PassThru;" +
          '$r=[UIntPtr]::Zero; [void]$t::SendMessageTimeout([IntPtr]0xffff,0x1A,[UIntPtr]::Zero,"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",2,1000,[ref]$r)',
      ],
      { windowsHide: true, stdio: 'ignore', timeout: 8000 },
    )
  } catch {}
}

/** 生成只代理 GitHub 域名的 PAC。 */
export function buildPac(proxyPort, host = '127.0.0.1') {
  const proxy = `PROXY ${host}:${proxyPort}`
  return `// dsh-github-accel PAC —— 只把 GitHub 域名交给本地隧道，其余一律直连。
function FindProxyForURL(url, host) {
  if (isPlainHostName(host) || host === 'localhost' || host === '127.0.0.1') return 'DIRECT';
  if (dnsDomainIs(host, '.github.com') || host === 'github.com') return '${proxy}';
  if (dnsDomainIs(host, '.githubusercontent.com') || host === 'githubusercontent.com') return '${proxy}';
  if (dnsDomainIs(host, '.githubassets.com') || host === 'githubassets.com') return '${proxy}';
  if (dnsDomainIs(host, '.github.io') || host === 'ghcr.io' || dnsDomainIs(host, '.ghcr.io')) return '${proxy}';
  if (dnsDomainIs(host, '.pkg.github.com')) return '${proxy}';
  return 'DIRECT';
}
`
}

/**
 * PAC 服务（本地小 HTTP 服务，只发 `/proxy.pac`）。
 * 单独一个端口，别和 CONNECT 代理混在一起 —— PAC 是普通 GET，走代理端口会绕圈子。
 */
export class PacServer {
  constructor({ port = 18998, proxyPort = 18999, address = '127.0.0.1' } = {}) {
    this.port = port
    this.proxyPort = proxyPort
    this.address = address
    this.server = undefined
  }

  get url() {
    return `http://${this.address}:${this.port}/proxy.pac`
  }

  listen() {
    const body = buildPac(this.proxyPort, this.address)
    const server = http.createServer((req, res) => {
      try {
        if ((req.url ?? '').startsWith('/proxy.pac')) {
          res.writeHead(200, {
            'content-type': 'application/x-ns-proxy-autoconfig',
            'content-length': Buffer.byteLength(body),
            'cache-control': 'no-store',
          })
          res.end(body)
          return
        }
        res.writeHead(404, { 'content-type': 'text/plain' })
        res.end('not found\n')
      } catch {
        /* 只读服务，出错了也不能抛。 */
      }
    })
    server.on('error', () => {})
    this.server = server
    return new Promise((resolve) => {
      const done = (result) => {
        server.off('listening', onListening)
        server.off('error', onError)
        resolve(result)
      }
      const onListening = () => done({ ok: true, port: this.port, url: this.url })
      const onError = (e) => done({ ok: false, reason: e.code ?? e.message, port: this.port })
      server.once('listening', onListening)
      server.once('error', onError)
      try {
        server.listen(this.port, this.address)
      } catch (error) {
        done({ ok: false, reason: error.code ?? error.message, port: this.port })
      }
    })
  }

  close() {
    try {
      this.server?.close()
    } catch {}
    this.server = undefined
  }
}

const RESTORE_FILE = () => path.join(ensureStateDir(), 'sysproxy-restore.json')

/**
 * 把当前用户的 `AutoConfigURL` 指向我们的 PAC，并记录原值以便还原。
 * @returns {{ok, reason?, previous?}}
 */
export function enableAutoConfig(url) {
  if (process.platform !== 'win32') return { ok: false, reason: 'not-windows' }
  const previous = readReg('AutoConfigURL')
  const current = { exists: previous.exists, value: previous.value ?? null, at: new Date().toISOString(), url }
  try {
    fs.writeFileSync(RESTORE_FILE(), JSON.stringify(current, null, 2), 'utf8')
  } catch {
    /* 记不下来就不要改注册表：宁可没有 PAC，也不能留下一个没法还原的改动。 */
    return { ok: false, reason: 'cannot-persist-restore-point' }
  }
  const written = writeReg('AutoConfigURL', url)
  if (!written.ok) return { ok: false, reason: written.reason }
  notifySettingsChanged()
  return { ok: true, previous: current }
}

/** 还原成我们改之前的样子（幂等：没有还原点就什么都不做）。 */
export function disableAutoConfig() {
  if (process.platform !== 'win32') return { ok: true, reason: 'not-windows' }
  let saved
  try {
    saved = JSON.parse(fs.readFileSync(RESTORE_FILE(), 'utf8'))
  } catch {
    return { ok: true, changed: false, reason: 'no-restore-point' }
  }
  const result = saved.exists ? writeReg('AutoConfigURL', saved.value) : deleteReg('AutoConfigURL')
  try {
    fs.rmSync(RESTORE_FILE(), { force: true })
  } catch {}
  notifySettingsChanged()
  return { ok: result.ok !== false, changed: true, restored: saved.exists ? saved.value : '(deleted)' }
}

/** 当前系统代理状态（诊断用）。 */
export function readProxyState() {
  return {
    autoConfigUrl: readReg('AutoConfigURL'),
    proxyEnable: readReg('ProxyEnable'),
    proxyServer: readReg('ProxyServer'),
  }
}

/**
 * 清一次系统 DNS 解析缓存。
 *
 * **这一步不做，改 hosts 可能几分钟甚至更久都不生效**：Windows 的 DNS 客户端缓存里
 * hosts 条目是预载的，实测 `ipconfig /displaydns` 里 `github.com` 的 TTL 能到 6.9 天。
 * 浏览器还有自己的一层缓存。也就是说「开关点了没反应 / 有时灵有时不灵」里有相当一部分
 * 是这个缓存造成的，而不是链路本身有问题。
 *
 * 需要管理员权限（写 hosts 成功时我们本来就是管理员）。失败不影响主流程。
 */
export function flushDns() {
  if (process.platform !== 'win32') return { ok: false, reason: 'not-windows' }
  try {
    execFileSync('ipconfig.exe', ['/flushdns'], { windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'], timeout: 10_000 })
    return { ok: true }
  } catch (error) {
    return { ok: false, reason: `flush-failed:${error.status ?? error.message}` }
  }
}
