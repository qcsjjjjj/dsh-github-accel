/**
 * hosts 文件接管块：幂等写入 / 移除 / 原子落盘 / 外来块检测。
 *
 * 三条硬要求（都来自真实事故）：
 *
 * 1. **绝不留下「指向没有人监听的地址」的条目**。历史上 Steam++ 在 hosts 里留了 31 条
 *    127.0.0.1 而自己没在 443 上监听，结果 GitHub 从「有点慢」变成「完全打不开」，
 *    而且没有任何提示告诉用户是谁干的。所以：写之前必须确认监听已就绪
 *    （由调用方用 `only` 参数保证），写完必须**读回来校验**。
 *
 * 2. **原子写**。直接 `writeFileSync` 覆盖 hosts，一旦在写一半时崩溃/断电，系统解析
 *    就废了。改成「同目录临时文件 + rename」，rename 在 NTFS 上是原子的。
 *
 * 3. **崩溃也要能恢复**。除了备份，还提供一个「哨兵」状态文件（见 state.js），
 *    下次启动能发现「上次的接管没撤」并自动修复。
 */
import fs from 'node:fs'
import path from 'node:path'

import { DEFAULT_DOMAINS, DOMAIN_TABLE, loopbackFor } from './domains.js'

export const HOSTS_START = '# dsh-github-accel Start'
export const HOSTS_END = '# dsh-github-accel End'

/** 别人写的接管块标记：检测到就拒绝启动，绝不和别人抢 hosts。 */
export const FOREIGN_MARKERS = [
  { name: 'Steam++', start: '# Steam++ Start', end: '# Steam++ End' },
  { name: 'Steam++(alt)', start: '#Steam++ Start', end: '#Steam++ End' },
  { name: 'SteamTools', start: '# SteamTools Start', end: '# SteamTools End' },
  { name: 'Watt Toolkit', start: '# Watt Toolkit Start', end: '# Watt Toolkit End' },
]

/** 本机默认路径与端口。 */
export const DEFAULTS = {
  sniPort: 443,
  httpPort: 80,
  proxyPort: 18999,
  hostsPath: process.env.SystemRoot
    ? `${process.env.SystemRoot}\\System32\\drivers\\etc\\hosts`
    : '/etc/hosts',
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

/** 同步小睡（真睡眠，不烧 CPU）—— 写 hosts 重试在同步 API 里用得上。 */
function sleepSync(ms) {
  try {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms)
  } catch {
    /* 极少数环境不支持 SharedArrayBuffer 时退化成不等待。 */
  }
}

export class HostsBlock {
  /**
   * @param opts - { path, domains, referenceDomains, backupPath }
   *   domains          这一轮要接管的域名（子集即可）
   *   referenceDomains 地址分配的固定参照表（默认就是完整域名表，保证序号稳定）
   */
  constructor({ path = DEFAULTS.hostsPath, domains = DEFAULT_DOMAINS, referenceDomains = DOMAIN_TABLE.map((e) => e.domain), backupPath } = {}) {
    this.path = path
    this.domains = [...domains]
    this.referenceDomains = referenceDomains
    this.backupPath = backupPath ?? `${path}.dsh-github-accel.bak`
  }

  // ── 域名与地址 ────────────────────────────────────────────────────────────

  /** 当前这一轮要写进 hosts 的域名（去重、去空，按固定参照表排序 ⇒ 块内容稳定可复现）。 */
  get safeDomains() {
    const set = new Set(this.domains.filter((d) => typeof d === 'string' && d.length > 0))
    const rank = (d) => {
      const i = this.referenceDomains.indexOf(d)
      return i < 0 ? this.referenceDomains.length + [...set].indexOf(d) : i
    }
    return [...set].sort((a, b) => rank(a) - rank(b))
  }

  /** 域名 -> 它分到的本机回环地址；不在参照表里就退回「表长 + 动态下标」。 */
  loopbackForDomain(domain) {
    const fixed = this.referenceDomains.indexOf(domain)
    if (fixed >= 0) return loopbackFor(fixed)
    const dynamic = this.safeDomains.indexOf(domain)
    return loopbackFor(this.referenceDomains.length + Math.max(0, dynamic))
  }

  /** 域名 -> 地址的完整映射（status / 诊断用）。 */
  get addressMap() {
    return Object.fromEntries(this.safeDomains.map((d) => [d, this.loopbackForDomain(d)]))
  }

  /** 本机地址 -> 它服务的域名（监听端用；认不出来返回 undefined）。 */
  domainForAddress(address) {
    return this.safeDomains.find((d) => this.loopbackForDomain(d) === address)
  }

  /** 某个域名是否正在被接管。 */
  addressFor(domain) {
    return this.safeDomains.includes(domain) ? this.loopbackForDomain(domain) : undefined
  }

  // ── 文本处理 ─────────────────────────────────────────────────────────────

  read() {
    return fs.readFileSync(this.path, 'utf8')
  }

  /** 去掉本插件写过的块（含空行清理），返回干净文本。 */
  strip(text) {
    const lines = text.split(/\r?\n/)
    const out = []
    let inside = false
    for (const line of lines) {
      const trimmed = line.trim()
      if (trimmed === HOSTS_START) {
        inside = true
        continue
      }
      if (trimmed === HOSTS_END) {
        inside = false
        continue
      }
      if (!inside) out.push(line)
    }
    return out.join('\n')
  }

  /** 检测别人的接管块。返回命中的标记列表。 */
  detectForeign(text = this.tryRead()) {
    if (typeof text !== 'string') return []
    return FOREIGN_MARKERS.filter((m) => text.includes(m.start) || text.includes(m.end)).map((m) => m.name)
  }

  tryRead() {
    try {
      return this.read()
    } catch {
      return undefined
    }
  }

  /** 生成要写入的块：一域名一地址，地址按固定参照表算（增删域名不平移）。 */
  render(domains = this.safeDomains) {
    const lines = domains.map((d) => `${this.loopbackForDomain(d)} ${d}`)
    return [HOSTS_START, ...lines, HOSTS_END].join('\n')
  }

  /** 当前是否已接管。 */
  isApplied() {
    const text = this.tryRead()
    return typeof text === 'string' && text.includes(HOSTS_START)
  }

  /** 现在生效的 hosts 条目（诊断用）。 */
  currentEntries() {
    const text = this.tryRead()
    if (typeof text !== 'string') return []
    const out = []
    let inside = false
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim()
      if (line === HOSTS_START) {
        inside = true
        continue
      }
      if (line === HOSTS_END) {
        inside = false
        continue
      }
      if (!inside || line === '' || line.startsWith('#')) continue
      const [address, ...names] = line.split(/\s+/)
      for (const name of names) out.push({ address, domain: name })
    }
    return out
  }

  // ── 落盘 ─────────────────────────────────────────────────────────────────

  /**
   * 原子写：同目录临时文件 + rename。
   * 写 hosts 常见的失败是安全软件短暂锁文件，所以带重试。
   */
  writeAtomic(text, attempts = 4) {
    const dir = path.dirname(this.path)
    const tmp = path.join(dir, `.dsh-github-accel.${process.pid}.${Date.now()}.tmp`)
    let lastError
    for (let i = 0; i < attempts; i += 1) {
      try {
        fs.writeFileSync(tmp, text, 'utf8')
        fs.renameSync(tmp, this.path)
        return { ok: true }
      } catch (error) {
        lastError = error
        try {
          fs.rmSync(tmp, { force: true })
        } catch {}
        /* EPERM/EACCES 是权限问题，重试没意义 —— 直接返回，让上层报 elevation-required。 */
        if (error.code === 'EPERM' || error.code === 'EACCES') break
        /* EBUSY/EEXIST 之类可能是杀软锁，等一下再试。 */
        if (i < attempts - 1) sleepSync(120 * (i + 1))
      }
    }
    try {
      fs.rmSync(tmp, { force: true })
    } catch {}
    return { ok: false, error: lastError }
  }

  static reasonFor(error) {
    const code = error && error.code
    if (code === 'EPERM' || code === 'EACCES') return 'elevation-required'
    return `write-failed:${code ?? (error && error.message) ?? 'unknown'}`
  }

  /**
   * 写入接管块（先备份一次，写后读回校验）。
   * @param opts - { domains } 这一轮实际要写的域名（默认用构造时的 domains）
   * @returns {{ok, reason?, backup?, entries?, foreign?}}
   */
  apply({ domains } = {}) {
    if (domains) this.domains = [...domains]
    const wanted = this.safeDomains
    if (wanted.length === 0) return { ok: true, entries: 0, reason: 'nothing-to-hijack' }

    let text
    try {
      text = this.read()
    } catch (error) {
      return { ok: false, reason: HostsBlock.reasonFor(error) }
    }

    const foreign = this.detectForeign(text)
    let backup = this.backupPath
    try {
      /* 首次接管留一份「原样」备份；之后不再覆盖（否则备份的是我们自己的产物）。 */
      if (!fs.existsSync(backup)) fs.writeFileSync(backup, text, 'utf8')
    } catch (error) {
      return { ok: false, reason: `backup-failed:${error.code ?? error.message}` }
    }

    /* 保留原来的换行风格：CRLF 的 hosts 被写成 LF，虽然能用，但会让别的工具误判。 */
    const crlf = /\r\n/.test(text)
    const clean = this.strip(text).replace(/\s*$/, '')
    const block = this.render(wanted)
    let next = `${clean}\n\n${block}\n`
    if (crlf) next = next.replace(/\n/g, '\r\n')

    const written = this.writeAtomic(next)
    if (!written.ok) return { ok: false, reason: HostsBlock.reasonFor(written.error), foreign }

    /* 读回校验：确认块真的在文件里，且条目数对得上。 */
    const back = this.tryRead() ?? ''
    const okEntries = back.includes(HOSTS_START) && wanted.every((d) => back.includes(` ${d}`) || back.includes(`\t${d}`))
    if (!okEntries) return { ok: false, reason: 'verify-failed', backup, foreign }

    return { ok: true, backup, entries: wanted.length, domains: wanted, addresses: this.addressMap, foreign }
  }

  /** 移除接管块（原子写 + 校验）。 */
  remove() {
    let text
    try {
      text = this.read()
    } catch (error) {
      return { ok: false, reason: HostsBlock.reasonFor(error) }
    }
    if (!text.includes(HOSTS_START) && !text.includes(HOSTS_END)) return { ok: true, changed: false }
    const clean = this.strip(text).replace(/\s*$/, '')
    const crlf = /\r\n/.test(text)
    const written = this.writeAtomic(crlf ? `${clean}\r\n`.replace(/\n/g, '\r\n') : `${clean}\n`)
    if (!written.ok) return { ok: false, reason: HostsBlock.reasonFor(written.error) }
    const back = this.tryRead() ?? ''
    if (back.includes(HOSTS_START)) return { ok: false, reason: 'verify-failed' }
    return { ok: true, changed: true }
  }
}

export { sleep }
