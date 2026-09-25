/**
 * 域名表 + 回环地址分配（纯数据与纯函数，无副作用，便于测试）
 *
 * ## 为什么「一个域名 = 一个回环地址」
 *
 * 浏览器的 HTTP/2 **连接复用（coalescing / IP pooling）** 有两个前提：
 *   ① 新 origin 解析出的 IP 里包含某条已存在连接的目标 IP；
 *   ② 那条连接的证书对新的 origin 有效。
 * 两个都满足时，浏览器会把 A 域名的请求发到 B 域名建立的连接上。
 *
 * 本机实测的证书 SAN：
 *
 *   github.com                        -> DNS:github.com, DNS:www.github.com
 *   api/codeload/uploads/collector/   -> DNS:*.github.com, DNS:github.com
 *     alive.github.com
 *   raw/objects/release-assets/       -> DNS:*.github.com, DNS:*.github.io,
 *   avatars/user-images/pkg-containers/   DNS:*.githubusercontent.com,
 *   gist.githubusercontent/github.io      DNS:github.com, DNS:github.io,
 *                                         DNS:githubusercontent.com
 *
 * 也就是说 `*.githubusercontent.com` 那组的证书**对 github.com 也有效**。历史上这些域名
 * 如果和 github.com 一起被指向 `127.0.0.1`，浏览器就会把 github.com 的请求复用到 Fastly
 * 边缘上，拿到 `Fastly error: unknown domain: github.com`。
 *
 * 结论：**每个域名分一个独立的 127.0.0.x**。这样前提①永远不成立，复用不可能发生，
 * 我们就不需要维护「哪些域名危险」这张黑名单了 —— 而那批 githubusercontent 域名
 * 恰恰是浏览器浏览 GitHub 时最需要的（头像、raw 文件、附件），把它们的毛病一起治好。
 *
 * ## 地址必须「按固定序号」分配
 *
 * 序号写死在这张表里，而不是「按当前接管了哪些域名」的下标算。否则一旦增删一个域名，
 * 后面所有域名的地址都会平移，hosts 全量重写 + 浏览器要等 DNS 缓存过期，白白抖一次。
 */

/** 交互式应用域名 —— 唯一承载表单 / CSRF / POST 的那一个。 */
export const APP_DOMAIN = 'github.com'

/**
 * 回环地址前缀。
 * 默认 `127.0.0.`，于是序号 i 拿到 `127.0.0.(i+2)`（`127.0.0.1` 留给普通本地服务）。
 * 个别安全软件会拦非 `.1` 的回环地址，那时把前缀改成 `127.1.` 之类即可。
 */
export const LOOPBACK_PREFIX = process.env.DSH_GITHUB_ACCEL_LOOPBACK_PREFIX ?? '127.0.0.'

/** 表里第 index 个域名的回环地址。 */
export function loopbackFor(index) {
  return `${LOOPBACK_PREFIX}${index + 2}`
}

/**
 * 域名表。**顺序即地址分配序号**，只允许往后追加，不允许中间插入或删除。
 *
 * why 字段是给后来者看的：改这张表之前先读它。
 *
 * 关于 **AAAA / IPv6 黑洞**（2026-09-25 逐域名实测 `Resolve-DnsName -Type AAAA -DnsOnly`）：
 * 本机有**全局 IPv6 地址**（RA 派生的 /64），而 **4 条 GitHub 的 AAAA 全部 timeout**；
 * Windows 默认前缀策略里 `::/0`(40) 优先于 `::ffff:0:0/96`(35)，也就是**浏览器会优先试 IPv6**。
 * 一旦某个域名被写进 hosts，Windows 解析器就只给 IPv4 答案、AAAA 直接被抑制（实测
 * `github.com` 在 hosts 里时 `AAAA=[]`）—— 这等于顺手把 IPv6 黑洞绕过去了。
 *
 * 实测**有 AAAA**（因此接管它们是有真实收益的）：
 *   github.githubassets.com、avatars.githubusercontent.com、raw.githubusercontent.com、
 *   user-images.githubusercontent.com、pkg-containers.githubusercontent.com
 * 实测**没有 AAAA**（接管它们是为了统一走多候选选路、免于 DNS 污染）：
 *   objects / release-assets / camo / gist.githubusercontent.com
 *   github.com、api / codeload / uploads / collector / alive.github.com、npm.pkg.github.com、ghcr.io
 */
export const DOMAIN_TABLE = [
  { domain: 'github.com', hot: true, why: '交互式应用。它的证书只覆盖自己和 www，必须独享地址' },
  { domain: 'api.github.com', hot: true, why: 'REST API，插件与工具链都走它' },
  { domain: 'codeload.github.com', hot: true, why: 'git clone / tarball 下载' },
  { domain: 'uploads.github.com', why: 'release 与 LFS 上传' },
  { domain: 'collector.github.com', why: '页面遥测；不接管会让页面加载多等一轮' },
  { domain: 'alive.github.com', why: '页面心跳' },
  { domain: 'github.githubassets.com', hot: true, why: '页面 JS/CSS 主站：**有 AAAA**（IPv6 黑洞受害者），也是实测最慢的一个' },
  { domain: 'avatars.githubusercontent.com', hot: true, why: '头像：**有 AAAA**，一屏几十个请求，黑洞时整页卡住' },
  { domain: 'camo.githubusercontent.com', why: 'Markdown 里的外链图片代理（无 AAAA）' },
  { domain: 'raw.githubusercontent.com', hot: true, why: 'README 图片与文件：**有 AAAA**，黑洞受害者' },
  { domain: 'objects.githubusercontent.com', why: '附件与归档（无 AAAA）' },
  { domain: 'release-assets.githubusercontent.com', why: 'release 下载（无 AAAA）' },
  { domain: 'user-images.githubusercontent.com', why: 'issue / PR 里的图片：**有 AAAA**，黑洞受害者' },
  { domain: 'pkg-containers.githubusercontent.com', why: '容器包层数据：**有 AAAA**（ghcr 的实际数据面）' },
  { domain: 'gist.githubusercontent.com', why: 'gist 内容（无 AAAA；网页版 gist.github.com 另议）' },
  { domain: 'npm.pkg.github.com', why: 'npm registry' },
  { domain: 'ghcr.io', why: '容器 registry' },
  {
    domain: 'gist.github.com',
    optional: true,
    why: '系统 DNS 实测返回 `2001::1`（明显的污染标记）；只有校验确实找到可用地址时才接管，否则放它走直连快速失败',
  },
  {
    domain: 'github.io',
    optional: true,
    why: '用户自己的 Pages 站点；接管风险不对等，默认不动',
  },
  {
    domain: 'pages.github.com',
    optional: true,
    why: '同上，GitHub 自己的 Pages 门户',
  },
]

/** 默认接管的域名（不含 optional）。 */
export const DEFAULT_DOMAINS = DOMAIN_TABLE.filter((e) => !e.optional).map((e) => e.domain)

/**
 * 只有在「运行时校验确实找到了可用地址」时才接管的域名。
 * 它们不出现在任何静态兜底池里。 */
export const OPTIONAL_DOMAINS = DOMAIN_TABLE.filter((e) => e.optional).map((e) => e.domain)

/** 高流量域名：值得占用预热池、值得更勤地重测。 */
export const HOT_DOMAINS = DOMAIN_TABLE.filter((e) => e.hot).map((e) => e.domain)

/**
 * 历史包袱：这一批曾经因为「连接复用」被禁止写进 hosts。
 *
 * 现在已经不需要这个守卫了 —— 一域名一地址本身就杜绝了复用前提（见文件头）。
 * 这个常量只保留给老版本的测试与诊断代码读取，**不再参与任何过滤决策**。
 * @deprecated 用 loopbackFor / DOMAIN_TABLE 表达地址隔离。
 */
export const COALESCING_UNSAFE = [
  'raw.githubusercontent.com',
  'gist.githubusercontent.com',
  'objects.githubusercontent.com',
  'release-assets.githubusercontent.com',
  'avatars.githubusercontent.com',
  'user-images.githubusercontent.com',
  'pkg-containers.githubusercontent.com',
]

/**
 * 只走代理、不写 hosts 的域名（现在只剩下「确实没有可用上游」的那些）。 */
export const PROXY_ONLY_DOMAINS = ['gist.github.com']

/**
 * 决定这一轮接管哪些域名（纯函数）。
 * @param opts - { domains, excluded, directHealthy, autoApp, hijackApp, available }
 *   available: 可选；只有监听真的起来了的域名才允许接管（见 plan D6）。
 * @returns { hijack, skipped }，skipped 里带原因。
 */
export function decideHijackDomains({
  domains = [],
  excluded = [],
  directHealthy = false,
  autoApp = true,
  hijackApp = undefined,
  available = undefined,
} = {}) {
  const hijack = []
  const skipped = []
  const avail = available ? new Set(available) : undefined
  for (const domain of domains) {
    if (excluded.includes(domain)) {
      skipped.push({ domain, reason: 'excluded' })
      continue
    }
    if (domain === APP_DOMAIN) {
      const take = hijackApp === undefined ? (autoApp ? !directHealthy : true) : hijackApp === true
      if (!take) {
        skipped.push({ domain, reason: 'direct-healthy' })
        continue
      }
    }
    if (avail && !avail.has(domain)) {
      skipped.push({ domain, reason: 'no-listener' })
      continue
    }
    hijack.push(domain)
  }
  return { hijack, skipped }
}
