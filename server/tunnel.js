/**
 * 隧道层：SNI / Host 嗅探 + 无泄漏的双向管道。
 *
 * 这个文件修掉两个会让人以为「插件时好时坏」的硬伤：
 *
 * ## 硬伤 1：socket 泄漏（老代码 `client.pipe(up); up.pipe(client)` 之后不管了）
 *
 * 浏览器关连接时走的是 `destroy()`，**不会**触发 `end`，于是 `client.pipe(up)` 永远
 * 不会调用 `up.end()`，上游 socket 就那样半开着留到进程结束。实测跑完 7 次 curl 之后
 * `status.connections` 停在 7 再也没归零，而 `trace` 永远是空的 —— 因为记 trace 的
 * `up.on('close')` 回调从来没跑过。也就是说：**诊断能力被这个 bug 一起废掉了**。
 *
 * 修法：双向管道必须「同生共死」——任何一侧 `close` 就把另一侧 `destroy()`。
 *
 * ## 硬伤 2：事件处理器里抛异常 = DSH 直接死
 *
 * 老代码在 CONNECT 代理的 `up.on('error')` 里引用了 `listenOn` 闭包里的 `clientClosed`
 * （`accel.js:851`），那是个 ReferenceError。Node 的 `'error'` 回调里抛出的异常
 * 是**进程级未捕获异常**，而 DSH 的 `bin.js` 里没有 `uncaughtException` 处理器
 * —— 于是 DSH 直接退出，hosts 留在接管态，全系统 GitHub 变砖。
 *
 * 修法：① 连接状态改成**每次连接独立的对象**，不依赖闭包变量；
 *       ② 所有回调体一律经过 `safe()`，任何时候都不允许抛出去。
 */
import net from 'node:net'

/** 包一层：回调里无论发生什么，都不允许把异常抛进事件循环。 */
export function safe(fn, onError) {
  return (...args) => {
    try {
      const r = fn(...args)
      if (r && typeof r.then === 'function' && typeof r.catch === 'function') r.catch((e) => onError?.(e))
      return r
    } catch (error) {
      onError?.(error)
      return undefined
    }
  }
}

// ── 嗅探（纯函数） ─────────────────────────────────────────────────────────

/**
 * 第一个 TLS 记录（ClientHello）是否已经收全。
 *
 * 必须判断这个才解析 SNI：ClientHello 可能**被拆到两个 TCP 段**里
 * （curl/schannel 的 ClientHello 比 git/OpenSSL 大，更容易跨段）。
 * 只 `once('data')` 就解析，遇到跨段就会取不到 SNI 直接断开——
 * 症状正是「git 能推、curl 打不开」这种看起来毫无道理的差异。
 */
export function isCompleteTlsRecord(buf) {
  if (buf.length < 5) return false
  if (buf[0] !== 0x16) return false
  return buf.length >= 5 + buf.readUInt16BE(3)
}

/** 从 ClientHello 里取出 SNI；解析不出返回 undefined。 */
export function parseSni(buf) {
  try {
    if (buf.length < 5 || buf[0] !== 0x16) return undefined
    let p = 5
    if (buf[p] !== 0x01) return undefined // 不是 ClientHello
    p += 4 // handshake type + 3 字节长度
    p += 2 // client version
    p += 32 // random
    if (p >= buf.length) return undefined
    p += 1 + buf[p] // session id
    if (p + 2 > buf.length) return undefined
    p += 2 + buf.readUInt16BE(p) // cipher suites
    if (p >= buf.length) return undefined
    p += 1 + buf[p] // compression methods
    if (p + 2 > buf.length) return undefined
    const extEnd = p + 2 + buf.readUInt16BE(p)
    p += 2
    while (p + 4 <= Math.min(extEnd, buf.length)) {
      const type = buf.readUInt16BE(p)
      const len = buf.readUInt16BE(p + 2)
      p += 4
      if (type === 0x0000) {
        const nameLen = buf.readUInt16BE(p + 3)
        const name = buf.toString('utf8', p + 5, p + 5 + nameLen)
        if (!name) return undefined
        return name.toLowerCase()
      }
      p += len
    }
    return undefined
  } catch {
    return undefined
  }
}

/** 从明文 HTTP 请求头里取 Host（80 端口用）。 */
export function parseHostHeader(buf) {
  try {
    const head = buf.toString('latin1', 0, Math.min(buf.length, 8192))
    const m = head.match(/^Host:\s*([^\s:]+)/im)
    return m ? m[1].toLowerCase() : undefined
  } catch {
    return undefined
  }
}

// ── 双向管道 ───────────────────────────────────────────────────────────────

/**
 * 把两个 socket 对接，并保证**任何一侧结束都让另一侧一起走**。
 *
 * @param a 客户端 socket
 * @param b 上游 socket
 * @param hooks - { onError(side, error), onEnd(reason) }
 * @returns {{kill: (reason?: string) => void, detach: () => void}}
 *   kill   立即拆除这条连接（两侧一起）
 *   detach 只解除「同生共死」的绑定，不动任何 socket。
 *          **换上游**要用它：那一步只该丢掉上游、留住客户端。
 */
export function relay(a, b, hooks = {}) {
  let done = false
  const report = (side, error) => {
    try {
      hooks.onError?.(side, error)
    } catch {}
  }
  const kill = (reason = 'killed') => {
    if (done) return
    done = true
    detach()
    for (const socket of [a, b]) {
      try {
        socket.destroy()
      } catch {}
    }
    /* onEnd 自己绝不许把异常漏出去，但**也不许静默吞掉**：
       这类「回调里引用了够不着的变量」正是 B2 那一类崩溃的温床，必须能被看见。 */
    try {
      hooks.onEnd?.(reason)
    } catch (error) {
      report('hook', error)
    }
  }

  /* 先挂 error 处理器：没有监听者的 'error' 事件本身就是进程级异常。 */
  const onClientError = (e) => report('client', e)
  const onUpstreamError = (e) => report('upstream', e)
  const onClientClose = () => kill('client-closed')
  const onUpstreamClose = () => kill('upstream-closed')

  function detach() {
    a.off('error', onClientError)
    b.off('error', onUpstreamError)
    a.off('close', onClientClose)
    b.off('close', onUpstreamClose)
    try {
      a.unpipe(b)
      b.unpipe(a)
    } catch {}
  }

  a.on('error', onClientError)
  b.on('error', onUpstreamError)
  a.on('close', onClientClose)
  b.on('close', onUpstreamClose)

  /* 小包（TLS 握手、HTTP/2 帧）不要被 Nagle 算法攒着，能省下几毫秒到几十毫秒。 */
  try {
    a.setNoDelay(true)
    b.setNoDelay(true)
  } catch {}

  a.pipe(b)
  b.pipe(a)
  return { kill, detach }
}

// ── 监听 ───────────────────────────────────────────────────────────────────

/**
 * 监听管理器：一个域名一个地址一个监听（见 server/domains.js 里关于连接复用的说明）。
 *
 * 它不认识 Accelerator，只要求传入一个 `openUpstream(host)`：
 *   `async (host) => { socket, ip, via: 'pool'|'race', ms }`
 * 这样监听层与选路层解耦，两边都能单独测。
 */
export class TunnelServer {
  /**
   * @param opts - { openUpstream, record, log, idleTimeoutMs, maxSniff }
   */
  constructor({
    openUpstream,
    record = () => {},
    log = () => {},
    idleTimeoutMs = 600_000,
    stallMs = 1500,
    firstByteMs = 1500,
    maxUpstreamAttempts = 3,
    connectDeadlineMs = 8000,
  } = {}) {
    this.openUpstream = openUpstream
    this.record = record
    this.log = log
    this.idleTimeoutMs = idleTimeoutMs
    /** 上游「多久不回一个字节」就判定为黑洞地址。正常边缘 400 ms 左右就回 ServerHello。 */
    this.stallMs = stallMs
    /** 上游多久不回第一个字节就**换一个**并重放 ClientHello。0 = 关掉。 */
    this.firstByteMs = firstByteMs
    /** 一条客户端连接最多试几个上游（含首字节看门狗触发的重试）。 */
    this.maxUpstreamAttempts = maxUpstreamAttempts
    /** 一条客户端连接在上游侧的**总**时间预算。 */
    this.connectDeadlineMs = connectDeadlineMs
    this.listeners = []
    /** 在途的客户端 socket —— 关闭时要一并拆掉，别把连接留到进程结束。 */
    this.active = new Set()
    /** 由 Accelerator 接上的可选钩子。 */
    this.onUpstreamError = undefined
    this.onUpstreamStall = undefined
    this.onConnectFailed = undefined
    this.onHandlerError = undefined
    this.closed = false
  }

  get list() {
    return this.listeners.map((l) => ({ address: l.address, port: l.port, mode: l.mode, domain: l.defaultHost }))
  }

  /**
   * 起一个监听，按首包里的 SNI / Host 决定上游。
   * @param opts - { port, mode: 'sni'|'http', address, defaultHost }
   */
  listenOn({ port, mode, address = '127.0.0.1', defaultHost }) {
    const maxSniff = mode === 'sni' ? 16384 : 8192
    const server = net.createServer((client) => {
      this.handleClient({ client, port, mode, address, defaultHost, maxSniff })
    })
    server.on(
      'error',
      safe((e) => {
        this.log('listen error', mode, port, address, e.code ?? e.message)
      }),
    )
    this.listeners.push({ server, address, port, mode, defaultHost })
    return new Promise((resolve) => {
      const done = (result) => {
        server.off('listening', onListening)
        server.off('error', onError)
        resolve(result)
      }
      const onListening = () => done({ ok: true, port, address, domain: defaultHost })
      const onError = (e) => done({ ok: false, reason: e.code ?? e.message, port, address, domain: defaultHost })
      server.once('listening', onListening)
      server.once('error', onError)
      try {
        server.listen(port, address)
      } catch (error) {
        done({ ok: false, reason: error.code ?? error.message, port, address, domain: defaultHost })
      }
    })
  }

  /** 一域名一地址地开监听。 */
  async listenPerDomain({ port, mode, domains }) {
    const results = []
    for (const { domain, address } of domains) {
      /* eslint-disable no-await-in-loop */
      results.push(await this.listenOn({ port, mode, address, defaultHost: domain }))
    }
    return results
  }

  /** 关掉监听（可只关某一类 / 某类里的某几个域名）。 */
  closeListeners({ mode, domains } = {}) {
    const wanted = domains ? new Set(domains) : undefined
    const keep = []
    for (const entry of this.listeners) {
      const matchMode = !mode || entry.mode === mode
      const matchDomain = !wanted || wanted.has(entry.defaultHost)
      if (matchMode && matchDomain) {
        try {
          entry.server.close()
        } catch {}
        continue
      }
      keep.push(entry)
    }
    this.listeners = keep
  }

  closeAll() {
    for (const entry of this.listeners) {
      try {
        entry.server.close()
      } catch {}
    }
    this.listeners = []
    /* 在途连接也一起拆：只 close() 监听不会断开已经建立的隧道。 */
    for (const client of this.active) {
      try {
        client.destroy()
      } catch {}
    }
    this.active.clear()
  }

  // ── 单条连接 ─────────────────────────────────────────────────────────────

  /** 处理一条客户端连接。整体包在 safe 里：任何意外都不许冒到事件循环。 */
  handleClient({ client, mode, address, defaultHost, maxSniff }) {
    const startedAt = Date.now()
    /* 连接状态放**独立对象**里。老代码把它放在闭包变量里，代理那条路径够不着，
       于是 `clientClosed` 变成 ReferenceError —— 而那是进程级崩溃。 */
    const conn = {
      mode,
      address,
      startedAt,
      host: undefined,
      ip: undefined,
      via: undefined,
      clientClosed: false,
      upBytes: 0,
      downBytes: 0,
      kill: undefined,
      finished: false,
    }

    const finish = (extra) => {
      if (conn.finished) return
      conn.finished = true
      this.record({
        event: 'tunnel',
        mode,
        host: conn.host,
        ip: conn.ip,
        via: conn.via,
        address,
        upBytes: conn.upBytes,
        downBytes: conn.downBytes,
        ms: Date.now() - startedAt,
        end: conn.clientClosed ? 'client-closed' : 'upstream-closed',
        ...extra,
      })
    }
    /* finish 必须挂在 conn 上：connectUpstream 是**另一个方法**，够不着这里的闭包。
       （老代码正是栽在「回调引用了另一个作用域里的变量」上。） */
    conn.finish = finish

    client.on(
      'error',
      safe(() => {
        conn.clientClosed = true
      }),
    )
    client.on('close', () => {
      conn.clientClosed = true
      this.active.delete(client)
      /* 客户端先断开 → 上游随后那声 ECONNRESET/EPIPE 是我们自己关的，不是地址坏。 */
      if (conn.kill) {
        try {
          conn.kill('client-closed')
        } catch {}
      }
    })
    this.active.add(client)

    let buf = Buffer.alloc(0)
    let resolved = false

    const onData = safe((chunk) => {
      if (resolved) return
      buf = Buffer.concat([buf, chunk])
      const ready = mode === 'sni' ? isCompleteTlsRecord(buf) : buf.includes('\r\n\r\n')
      if (!ready) {
        if (buf.length > maxSniff) {
          this.log('header too large', mode, buf.length)
          client.destroy()
        }
        return
      }
      resolved = true
      client.off('data', onData)
      client.pause()

      /* 每个域名有自己的地址；万一解析不出 SNI，就用这个地址归属的域名兜底。 */
      const host = (mode === 'sni' ? parseSni(buf) : parseHostHeader(buf)) ?? defaultHost
      if (!host) {
        this.record({ event: 'no-host', mode, address, ms: Date.now() - startedAt })
        client.destroy()
        return
      }
      conn.host = host
      void this.connectUpstream({ client, conn, buf, host, mode, defaultHost })
    })

    client.on('data', onData)
  }

  /**
   * 选路 + 建立上游 + 转发首包 + 双向管道。全程不抛。
   *
   * ## 上游「TCP 连得上但一个字节都不回」怎么处理
   *
   * 这是这条网络上最恶心的一种失败：坏地址不会报错，只是**不出声**。浏览器那边看到的是
   * 「连接建立了但一直不出内容」，会干等到自己超时（15–30 s）。
   *
   * 我们有一个它没有的优势：**ClientHello 还在我们手里**。所以只要
   * 「已经转发出去、但上游一个字节都没回、且超过了 `firstByteMs`」，
   * 就可以丢掉这条上游、换一个候选**把同一段 ClientHello 重放过去** ——
   * 对客户端完全透明（它还没收到任何字节，重放的是同一个请求）。
   *
   * 代价从「等客户端超时」变成 `firstByteMs`（默认 1.5 s）。
   */
  async connectUpstream({ client, conn, buf, host, mode, defaultHost }) {
    const upstreamPort = mode === 'sni' ? 443 : 80
    const deadline = Date.now() + this.connectDeadlineMs
    let lastError
    for (let attempt = 0; attempt < this.maxUpstreamAttempts; attempt += 1) {
      if (client.destroyed) return
      const remaining = deadline - Date.now()
      if (attempt > 0 && remaining < 600) break
      try {
        const opened = await this.openUpstream(host, { mode, port: upstreamPort, defaultHost, attempt, budgetMs: Math.max(600, remaining) })
        if (client.destroyed) {
          opened.socket.destroy()
          return
        }
        conn.ip = opened.ip
        conn.via = opened.via

        /* 预热池里的现货可能已经被上游悄悄关掉（FIN 还没处理到）。
           第一次写就失败时**透明重连一次**：ClientHello 还在我们手里，可以重放。 */
        if (buf.length) {
          const sent = await writeOnce(opened.socket, buf)
          if (!sent.ok && opened.via === 'pool') {
            try {
              opened.socket.destroy()
            } catch {}
            continue
          }
          if (!sent.ok) throw new Error(`write-failed:${sent.why}`)
        }

        const link = relay(client, opened.socket, {
          onError: (side, error) => {
            if (side === 'hook') {
              /* 管道回调自己出错了 —— 记下来（不静默），但连接继续按正常路径结束。 */
              this.record({
                event: 'handler-error',
                mode,
                host,
                why: error?.message ?? String(error),
                ms: Date.now() - conn.startedAt,
              })
              this.onHandlerError?.(error)
              return
            }
            if (side !== 'upstream') return
            /* 「一个字节都没回」才是地址坏的标志。
               不能用 bytesWritten 判断 —— 我们**总是**要先把 ClientHello 转发给上游，
               所以 bytesWritten 永远大于 0，那个条件等于永远不拉黑（老代码就是这样，
               于是一个黑洞地址会永远霸占候选表的第一位）。 */
            const hard = !conn.clientClosed && opened.socket.bytesRead === 0
            this.record({
              event: 'upstream-error',
              mode,
              host,
              ip: opened.ip,
              via: opened.via,
              code: error?.code ?? error?.message,
              hard,
              upBytes: opened.socket.bytesWritten,
              downBytes: opened.socket.bytesRead,
              ms: Date.now() - conn.startedAt,
            })
            this.onUpstreamError?.(host, opened.ip, error, hard)
          },
          onEnd: () => {
            conn.upBytes = opened.socket.bytesWritten ?? 0
            conn.downBytes = opened.socket.bytesRead ?? 0
            /* 黑洞判据：ClientHello 已经转发出去了，却一个字节都没回来，而且拖了够久。
               （正常边缘 400 ms 左右就回 ServerHello，实测数据见 docs/PLAN-2026-09-25.md。） */
            if (opened.socket.bytesRead === 0 && Date.now() - conn.startedAt >= this.stallMs) {
              this.record({
                event: 'upstream-stall',
                mode,
                host,
                ip: opened.ip,
                via: opened.via,
                ms: Date.now() - conn.startedAt,
              })
              this.onUpstreamStall?.(host, opened.ip)
            }
            conn.finish?.()
          },
        })
        conn.kill = (reason) => link.kill(reason)

        /* 首字节看门狗：上游一声不吭就换一个（见上面的方法注释）。 */
        if (buf.length && this.firstByteMs > 0 && opened.socket.bytesRead === 0) {
          const stalled = await awaitFirstByte(opened.socket, this.firstByteMs)
          if (stalled && !client.destroyed && attempt < this.maxUpstreamAttempts - 1 && Date.now() < deadline) {
            this.record({ event: 'upstream-stall', mode, host, ip: opened.ip, via: opened.via, retry: true, ms: Date.now() - conn.startedAt })
            this.onUpstreamStall?.(host, opened.ip)
            /* 只丢上游，留住客户端：ClientHello 马上会被重放。 */
            link.detach()
            conn.kill = undefined
            try {
              opened.socket.destroy()
            } catch {}
            continue
          }
        }

        /* 连上之后就允许空闲超时回收（浏览器会挂着 keep-alive 连接不放）。 */
        if (this.idleTimeoutMs > 0) {
          client.setTimeout(this.idleTimeoutMs, () => {
            try {
              link.kill('idle-timeout')
            } catch {}
          })
        }
        client.resume()
        return
      } catch (error) {
        lastError = error
        if (attempt < this.maxUpstreamAttempts - 1 && !client.destroyed) continue
      }
    }
    this.record({
      event: 'connect-failed',
      mode,
      host,
      address: conn.address,
      why: lastError?.message ?? 'unknown',
      ms: Date.now() - conn.startedAt,
    })
    this.onConnectFailed?.(host, lastError)
    try {
      client.destroy()
    } catch {}
  }
}

/**
 * CONNECT / 绝对 URI 的本地 HTTP 代理（给 git / npm / curl / go 这类能读 HTTPS_PROXY 的工具链）。
 *
 * 这是**不需要管理员权限**的那条腿：hosts 写不进去时的备用通路。
 * 也只做盲转发 —— 不终止 TLS、不看内容、不落盘。
 */
export class ProxyServer {
  /**
   * @param opts - { openUpstream, record, log, idleTimeoutMs }
   */
  constructor({
    openUpstream,
    record = () => {},
    log = () => {},
    idleTimeoutMs = 1_800_000,
    stallMs = 1500,
    firstByteMs = 1500,
    maxUpstreamAttempts = 3,
    connectDeadlineMs = 8000,
  } = {}) {
    this.openUpstream = openUpstream
    this.record = record
    this.log = log
    this.idleTimeoutMs = idleTimeoutMs
    this.stallMs = stallMs
    this.firstByteMs = firstByteMs
    this.maxUpstreamAttempts = maxUpstreamAttempts
    this.connectDeadlineMs = connectDeadlineMs
    this.server = undefined
    this.address = '127.0.0.1'
    this.port = undefined
    this.active = new Set()
    this.onUpstreamError = undefined
    this.onUpstreamStall = undefined
    this.onHandlerError = undefined
    this.onConnectFailed = undefined
  }

  listen(port, address = '127.0.0.1') {
    this.port = port
    this.address = address
    const server = net.createServer((client) => {
      this.handle({ client })
    })
    server.on(
      'error',
      safe((e) => this.log('proxy server error', e.code ?? e.message)),
    )
    this.server = server
    return new Promise((resolve) => {
      const done = (result) => {
        server.off('listening', onListening)
        server.off('error', onError)
        resolve(result)
      }
      const onListening = () => done({ ok: true, port, address })
      const onError = (e) => done({ ok: false, reason: e.code ?? e.message, port, address })
      server.once('listening', onListening)
      server.once('error', onError)
      try {
        server.listen(port, address)
      } catch (error) {
        done({ ok: false, reason: error.code ?? error.message, port, address })
      }
    })
  }

  close() {
    try {
      this.server?.close()
    } catch {}
    this.server = undefined
    for (const client of this.active) {
      try {
        client.destroy()
      } catch {}
    }
    this.active.clear()
  }

  handle({ client }) {
    const startedAt = Date.now()
    const conn = { clientClosed: false, finished: false, target: undefined, ip: undefined, via: undefined, kill: undefined }
    const finish = (end) => {
      if (conn.finished) return
      conn.finished = true
      this.record({
        event: 'tunnel',
        mode: 'proxy',
        host: conn.target,
        ip: conn.ip,
        via: conn.via,
        ms: Date.now() - startedAt,
        end,
      })
    }
    /* 同上：forward 是另一个方法，够不着这里的闭包，所以要挂到 conn 上。 */
    conn.finish = finish
    client.on(
      'error',
      safe(() => {
        conn.clientClosed = true
      }),
    )
    client.on('close', () => {
      conn.clientClosed = true
      this.active.delete(client)
      try {
        conn.kill?.('client-closed')
      } catch {}
      finish('client-closed')
    })
    this.active.add(client)

    let buf = Buffer.alloc(0)
    let settled = false
    const onData = safe((chunk) => {
      if (settled) return
      buf = Buffer.concat([buf, chunk])
      const sep = buf.indexOf('\r\n\r\n')
      if (sep < 0) {
        if (buf.length > 8192) {
          client.destroy()
          return
        }
        return
      }
      settled = true
      client.off('data', onData)
      const head = buf.toString('latin1', 0, sep + 4)
      const rest = buf.subarray(sep + 4)
      const connectMatch = head.match(/^CONNECT\s+(\[?[^\s:\]]+\]?):(\d+)\s+HTTP\/1\.[01]/i)
      if (connectMatch) {
        void this.forward({ client, conn, host: connectMatch[1].replace(/^\[|\]$/g, ''), port: Number(connectMatch[2]) || 443, first: rest, respond: true })
        return
      }
      const plainMatch = head.match(/^([A-Z]+)\s+(https?:\/\/[^\s]+)\s+HTTP\/1\.[01]/i)
      if (plainMatch) {
        let target
        try {
          target = new URL(plainMatch[2])
        } catch {
          client.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n')
          return
        }
        /* 绝对 URI 要改写成 origin-form 才能发给目标服务器。 */
        const rewrittenHead = head
          .replace(/^([A-Z]+)\s+https?:\/\/[^\s]+\s+HTTP\/1\.1/i, `$1 ${target.pathname}${target.search} HTTP/1.1`)
          .replace(/^Proxy-Connection:.*\r\n/im, '')
        client.pause()
        void this.forward({
          client,
          conn,
          host: target.hostname,
          port: Number(target.port) || (target.protocol === 'https:' ? 443 : 80),
          first: Buffer.concat([Buffer.from(rewrittenHead, 'latin1'), rest]),
          respond: false,
        })
        return
      }
      client.end('HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n')
    })
    client.on('data', onData)
  }

  async forward({ client, conn, host, port, first, respond }) {
    conn.target = host
    const deadline = Date.now() + this.connectDeadlineMs
    let lastError
    let responded = false
    for (let attempt = 0; attempt < this.maxUpstreamAttempts; attempt += 1) {
      if (client.destroyed) return
      if (attempt > 0 && deadline - Date.now() < 600) break
      try {
        const opened = await this.openUpstream(host, { mode: 'proxy', port, attempt, budgetMs: Math.max(600, deadline - Date.now()) })
        if (client.destroyed) {
          opened.socket.destroy()
          return
        }
        conn.ip = opened.ip
        conn.via = opened.via
        if (respond && !responded) {
          client.write('HTTP/1.1 200 Connection Established\r\n\r\n')
          responded = true
        }
        if (first?.length) {
          const sent = await writeOnce(opened.socket, first)
          if (!sent.ok && opened.via === 'pool') {
            try {
              opened.socket.destroy()
            } catch {}
            continue
          }
          if (!sent.ok) throw new Error(`write-failed:${sent.why}`)
        }
        const link = relay(client, opened.socket, {
          onError: (side, error) => {
            if (side === 'hook') {
              this.record({ event: 'handler-error', mode: 'proxy', host, why: error?.message ?? String(error) })
              this.onHandlerError?.(error)
              return
            }
            if (side !== 'upstream') return
            /* 同上：判据是「上游回了几个字节」，不是「我们发了几个字节」。 */
            const hard = !conn.clientClosed && opened.socket.bytesRead === 0
            this.record({
              event: 'upstream-error',
              mode: 'proxy',
              host,
              ip: opened.ip,
              via: opened.via,
              code: error?.code ?? error?.message,
              hard,
            })
            this.onUpstreamError?.(host, opened.ip, error, hard)
          },
          onEnd: () => {
            /* 和 SNI 通道同样的判据：一个字节都没回、而且拖了很久 → 这个地址是黑洞。 */
            if (opened.socket.bytesRead === 0 && Date.now() - conn.startedAt >= this.stallMs) {
              this.record({ event: 'upstream-stall', mode: 'proxy', host, ip: opened.ip, ms: Date.now() - conn.startedAt })
              this.onUpstreamStall?.(host, opened.ip)
            }
            conn.finish?.(conn.clientClosed ? 'client-closed' : 'upstream-closed')
          },
        })
        conn.kill = (reason) => link.kill(reason)

        /* 首字节看门狗：CONNECT 已经回过 200 了也不要紧 —— 客户端还没收到任何
           **被代理过去的**数据，所以换上游重放首包对它是透明的。 */
        if (first?.length && this.firstByteMs > 0 && opened.socket.bytesRead === 0) {
          const stalled = await awaitFirstByte(opened.socket, this.firstByteMs)
          if (stalled && !client.destroyed && attempt < this.maxUpstreamAttempts - 1 && Date.now() < deadline) {
            this.record({ event: 'upstream-stall', mode: 'proxy', host, ip: opened.ip, via: opened.via, retry: true })
            this.onUpstreamStall?.(host, opened.ip)
            link.detach()
            conn.kill = undefined
            try {
              opened.socket.destroy()
            } catch {}
            continue
          }
        }

        if (this.idleTimeoutMs > 0) {
          client.setTimeout(this.idleTimeoutMs, () => {
            try {
              link.kill('idle-timeout')
            } catch {}
          })
        }
        client.resume()
        return
      } catch (error) {
        lastError = error
        if (attempt < this.maxUpstreamAttempts - 1 && !client.destroyed) continue
      }
    }
    this.record({ event: 'connect-failed', mode: 'proxy', host, why: lastError?.message ?? 'unknown' })
    try {
      if (respond) client.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n')
      else client.destroy()
    } catch {}
  }
}

/**
 * 等上游的第一个字节。
 *
 * 用来对付「TCP 连得上但一声不吭」的坏地址：超过 `ms` 还没回任何字节就返回 true，
 * 调用方据此换一个上游、把已经转发出去的首包**重放**过去（对客户端透明）。
 *
 * @returns 超时且一个字节都没等到 → true；上游开口 / 关闭 / 报错 → false
 */
export function awaitFirstByte(socket, ms) {
  if (socket.bytesRead > 0) return Promise.resolve(false)
  return new Promise((resolve) => {
    let done = false
    const finish = (stalled) => {
      if (done) return
      done = true
      clearTimeout(timer)
      socket.off('data', onData)
      socket.off('close', onClose)
      socket.off('error', onClose)
      resolve(stalled)
    }
    const onData = () => finish(false)
    /* 上游自己关了 / 报错了 → 交给 relay 的钩子走正常路径，这里不算「卡死」。 */
    const onClose = () => finish(false)
    const timer = setTimeout(() => finish(true), ms)
    socket.on('data', onData)
    socket.on('close', onClose)
    socket.on('error', onClose)
  })
}

/** 写一次，返回成败（不抛）。 */
function writeOnce(socket, buf) {
  return new Promise((resolve) => {
    if (!socket.writable) return resolve({ ok: false, why: 'not-writable' })
    let settled = false
    const done = (ok, why) => {
      if (settled) return
      settled = true
      socket.off('error', onError)
      resolve({ ok, why })
    }
    const onError = (e) => done(false, e.code ?? e.message)
    socket.once('error', onError)
    try {
      socket.write(buf, (err) => done(!err, err ? (err.code ?? err.message) : undefined))
    } catch (error) {
      done(false, error.code ?? error.message)
    }
  })
}
