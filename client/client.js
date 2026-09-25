/**
 * dsh-github-accel — GitHub 加速开关（会话顶部栏右侧 + 空会话兜底）
 *
 * 两个席位，一颗按钮：
 *
 *   1. `conversation.session.header.utilities`（kind: list, scope: session）
 *      —— 会话 header 里「标题之后、角落之前」的位置，也就是顶部栏偏右。
 *   2. `shell.overlay`（kind: list, scope: root）
 *      —— 空会话 / 没有会话的页面上，产品的会话 header 整段不渲染
 *      （hideChrome），席位 1 根本不会挂载；这一份是那种页面的入口，
 *      照 dsh-hero-rightbar 的做法用 `position: fixed` 画在 header 角落的位置
 *      （top: 11px; right: 12px，28px 控件）。
 *
 * 两份同时存在于 DOM 时由**一条 CSS 仲裁**，不需要在 render 期间读 DOM：
 *
 *   body:has([data-github-accel-in-header]) [data-github-accel-overlay] { display: none }
 *
 * 浏览器在任何 DOM 变化后重算 :has()，所以「header 画出来了就藏浮层」永远成立，
 * 也不会出现两颗按钮。
 *
 * 悬停提示只有一个：有 primitives.Tooltip 时不再挂原生 title（之前两个提示
 * 就是「原生 title + Tooltip 组件」叠在一起造成的）。
 */
window.__ModuleLoader__.load({
	id: 'dsh-github-accel',
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });

		const react = require('react');
		/* primitives 只用来拿 Tooltip；拿不到就退化成原生 title 属性，绝不能因此
		   让整个 factory 抛错（一抛就没按钮了）。 */
		let primitives = null;
		try {
			primitives = require('@deepseek-ai/dsh-client-ui-primitives');
		} catch (error) {
			primitives = null;
		}
		const Tooltip = primitives && primitives.Tooltip ? primitives.Tooltip : null;

		const NS = 'githubAccel';
		const STATUS_URL = '/dsh-github-accel/status';
		const TOGGLE_URL = '/dsh-github-accel/toggle';

		const zh = {
			on: 'GitHub 加速已开启',
			off: 'GitHub 加速已关闭',
			turnOn: '开启 GitHub 加速',
			turnOff: '关闭 GitHub 加速',
			busy: '正在切换…',
			hostsNeedAdmin: 'hosts 需要管理员权限，已在代理模式下运行',
			portTaken: '本机 443 已被占用（Steam++ 正在加速？先停掉它）',
			failed: '切换失败，稍后再试',
			proxyOnly: '仅代理模式：只对设置了 HTTPS_PROXY 的工具生效',
			appDirect: 'github.com 直连正常，浏览器不经过加速器（只加速其余域名与工具链）',
			verifyFailed: 'hosts 写进去了但读回来不对，已回滚；试试用管理员身份重开 DSH',
			noListener: '部分域名的监听没起来，那些域名不会被接管（不会把浏览器指向空地址）',
			notNeeded: 'hosts 已生效，系统代理无需接管',
			foreign: '检测到别的加速器（如 Steam++）在接管 hosts，请先关掉它',
			pathsHosts: '系统通路（hosts）',
			pathsProxy: '代理通路',
			pathsPac: '浏览器 PAC 通路'
		};
		const en = {
			on: 'GitHub acceleration is on',
			off: 'GitHub acceleration is off',
			turnOn: 'Turn on GitHub acceleration',
			turnOff: 'Turn off GitHub acceleration',
			busy: 'Switching…',
			hostsNeedAdmin: 'hosts needs administrator rights; running in proxy mode',
			portTaken: 'localhost:443 is taken (Steam++ accelerating? stop it first)',
			failed: 'Switch failed; try again',
			proxyOnly: 'Proxy mode only: applies to tools that honour HTTPS_PROXY',
			appDirect: 'github.com is reachable directly, so the browser stays off the tunnel (only the other domains and the toolchain are accelerated)',
			verifyFailed: 'hosts was written but read-back failed; rolled back. Try restarting DSH as administrator',
			noListener: 'Some domain listeners did not start; those domains are left alone (never pointed at an empty address)',
			notNeeded: 'hosts took effect, the system proxy is left alone',
			foreign: 'Another accelerator (e.g. Steam++) owns the hosts file — turn it off first',
			pathsHosts: 'system path (hosts)',
			pathsProxy: 'proxy path',
			pathsPac: 'browser PAC path'
		};

		const CSS = `
.dsh-github-accel-btn {
	display: inline-flex;
	align-items: center;
	gap: 6px;
	height: 28px;
	padding: 0 10px;
	color: var(--dsw-alias-label-secondary);
	background: transparent;
	border: .5px solid var(--dsw-alias-border-l4);
	border-radius: 28px;
	cursor: pointer;
	pointer-events: auto;
	white-space: nowrap;
}
.dsh-github-accel-btn:hover { background: var(--dsw-alias-interactive-bg-hover); }
.dsh-github-accel-btn[data-on="true"] { border-color: var(--dsw-alias-brand-primary, #4d6bfe); color: var(--dsw-alias-brand-primary, #4d6bfe); }
.dsh-github-accel-btn[data-busy="true"] { opacity: .6; cursor: default; }
.dsh-github-accel-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--dsw-alias-label-secondary, #9aa0a6); flex: none; }
.dsh-github-accel-btn[data-on="true"] .dsh-github-accel-dot { background: var(--dsw-alias-brand-primary, #4d6bfe); }
/* 空会话那份浮层：贴着**主栏**的右边缘，而不是窗口右边缘 —— 产品把右侧栏推出来
   （push 模式）时主栏变窄，浮层也要跟着往左让开，否则会盖在右侧栏的标签条上。
   --dsh-accel-right-offset 由下面的 installRightOffset() 实时写入（= 右侧栏占的宽度）。
   浮层几何对外发布（别的 DSH 插件的浮层可以靠这组变量紧跟在本按钮左边 8px）：
     --dsh-accel-overlay-shift  右上角让位量（控件在时 48px，不在时 12px）
     --dsh-accel-overlay-width  本按钮宽度 */
:root { --dsh-accel-overlay-width: 84px; --dsh-accel-overlay-shift: 12px; } /* dsh-accel-overlay-geometry: published */
.dsh-github-accel-btn[data-github-accel-overlay] {
	position: fixed;
	top: 11px;
	right: calc(var(--dsh-accel-right-offset, 0px) + var(--dsh-accel-overlay-shift, 12px));
	width: var(--dsh-accel-overlay-width, 84px);
	justify-content: center;
	z-index: 1;
}
body:has([data-hero-rightbar-trigger]),
body:has([data-sidebar-right-expand]) {
	--dsh-accel-overlay-shift: 48px;
}
/* 右侧栏全屏时它自己覆盖整个视口，浮层入口就不需要了。 */
body:has([data-sidebar-right-panel="fullscreen"]) .dsh-github-accel-btn[data-github-accel-overlay] {
	display: none;
}
/* 仲裁：header 里那份挂上了，浮层这份就藏起来。浏览器按 :has() 自动重算。 */
body:has([data-github-accel-in-header]) [data-github-accel-overlay] { display: none; }

/* 右侧栏打开（push 模式）时主栏变窄，header 的右边缘落在窗口中间 —— 这是产品
   自己的布局，我们**不干预**：header 里的两颗按钮就该跟着主栏走到窗口中间。
   要跟主栏走的只有空会话那份浮层，它由 --dsh-accel-right-offset 计算。 */
[class$="_headerUtilities"] {
	margin-left: auto !important;
	flex: 0 0 auto !important;
}
.dsh-github-accel-hint {
	position: fixed;
	top: 44px;
	right: 12px;
	max-width: 320px;
	padding: 8px 10px;
	color: var(--dsw-alias-label-primary);
	background: var(--dsw-alias-bg-elevated, var(--dsw-alias-bg-base));
	border: .5px solid var(--dsw-alias-border-l4);
	border-radius: 10px;
	box-shadow: 0 6px 20px rgb(0 0 0 / 24%);
	font-size: 12px;
	line-height: 18px;
	z-index: 2;
}
`;

		function ensureStyles() {
			const id = 'dsh-github-accel/styles';
			if (document.querySelector('style[data-plugin-css=' + JSON.stringify(id) + ']') !== null) return;
			const tag = document.createElement('style');
			tag.dataset.plugin = 'dsh-github-accel';
			tag.dataset.pluginCss = id;
			tag.textContent = CSS;
			document.head.appendChild(tag);
		}

		/** 一句话概括切换结果，用来告诉用户为什么没生效。 */
		function explain(report, tOwn) {
			if (!report) return undefined;
			const hosts = report.hosts;
			/* 监听结果现在是「一域名一地址」的数组。 */
			const sniList = Array.isArray(report.sni) ? report.sni : report.sni ? [report.sni] : [];
			if (Array.isArray(hosts?.foreign) && hosts.foreign.length > 0) return tOwn('foreign');
			if (hosts && hosts.ok === false && hosts.reason === 'elevation-required') return tOwn('hostsNeedAdmin');
			if (hosts && hosts.ok === false && hosts.reason === 'verify-failed') return tOwn('verifyFailed');
			if (sniList.length > 0 && sniList.every((r) => r && r.ok === false) && sniList.some((r) => r.reason === 'EADDRINUSE' || r.reason === 'port-taken'))
				return tOwn('portTaken');
			if (Array.isArray(report.skipped) && report.skipped.some((s) => s.domain === 'github.com' && s.reason === 'direct-healthy'))
				return tOwn('appDirect');
			if (Array.isArray(hosts?.dropped) && hosts.dropped.length > 0) return tOwn('noListener');
			if (report.mode === 'proxy') return tOwn('proxyOnly');
			if (report.pac && report.pac.reason === 'not-needed') return tOwn('notNeeded');
			return undefined;
		}

		/** 三条通路各自是否活着 —— 放进悬停提示，出问题时一眼看出是哪条腿断了。 */
		function summarize(snapshot, tOwn) {
			if (!snapshot || snapshot.enabled !== true) return undefined;
			const parts = [];
			const entries = Array.isArray(snapshot.currentEntries) ? snapshot.currentEntries.length : 0;
			if (snapshot.hostsApplied === true) parts.push(tOwn('pathsHosts') + ' ✓ ' + entries);
			if (Array.isArray(snapshot.listeners) && snapshot.listeners.some((l) => l.mode === 'proxy')) parts.push(tOwn('pathsProxy') + ' ✓');
			if (snapshot.pacActive === true) parts.push(tOwn('pathsPac') + ' ✓');
			const counter = snapshot.counters;
			if (counter && typeof counter.tunnels === 'number') parts.push('隧道 ' + counter.tunnels);
			return parts.length > 0 ? parts.join(' · ') : undefined;
		}

		function createButton(ctx) {
			const tOwn = ctx.locale.bind(NS);

			const fetchJson = async (url) => {
				const res = await fetch(url, { headers: { accept: 'application/json' }, cache: 'no-store' });
				if (!res.ok) throw new Error('HTTP ' + res.status);
				return res.json();
			};

			/* 两个席位共用一份状态：拨一次开关，两颗按钮和提示都同步。 */
			const store = {
				snapshot: undefined,
				busy: false,
				hint: undefined,
				listeners: new Set(),
				emit() {
					for (const fn of this.listeners) fn();
				},
				subscribe(fn) {
					this.listeners.add(fn);
					return () => this.listeners.delete(fn);
				},
				showHint(text) {
					this.hint = text;
					this.emit();
					if (this.hintTimer) clearTimeout(this.hintTimer);
					this.hintTimer = setTimeout(() => {
						this.hint = undefined;
						this.emit();
					}, 8000);
				},
				async refresh() {
					try {
						this.snapshot = await fetchJson(STATUS_URL);
					} catch (error) {
						this.snapshot = { enabled: false };
					}
					this.emit();
				},
				async toggle() {
					if (this.busy) return;
					const was = this.snapshot !== undefined && this.snapshot.enabled === true;
					this.busy = true;
					this.hint = undefined;
					this.emit();
					try {
						const next = await fetchJson(TOGGLE_URL + '?on=' + (was ? '0' : '1') + '&mode=both');
						this.snapshot = next;
						/* 状态没变 = 没生效，把原因说出来（缺权限、443 被占…）。 */
						if (next.enabled === was) this.showHint(explain(next.report, tOwn) || tOwn('failed'));
					} catch (error) {
						this.showHint(tOwn('failed'));
					} finally {
						this.busy = false;
						this.emit();
					}
				},
			};

			/** 订阅共享状态。 */
			function useAccel() {
				const [, force] = react.useReducer((n) => n + 1, 0);
				react.useEffect(() => store.subscribe(force), []);
				react.useEffect(() => {
					if (store.snapshot === undefined) void store.refresh();
				}, []);
				return store;
			}

			/** 一颗按钮；placement 决定它带哪个席位标记（CSS 靠这个仲裁）。 */
			function Button({ placement }) {
				const s = useAccel();
				const on = s.snapshot !== undefined && s.snapshot.enabled === true;
				const label = on ? tOwn('turnOff') : tOwn('turnOn');
				/* 悬停时把「哪几条通路活着」说清楚 —— 出问题时这是最快的定位手段。 */
				const summary = summarize(s.snapshot, tOwn);
				const tooltip = summary === undefined ? label : label + '\n' + summary;

				const attrs = {
					type: 'button',
					className: 'dsh-github-accel-btn',
					'data-on': on ? 'true' : 'false',
					'data-busy': s.busy ? 'true' : undefined,
					'aria-label': label,
					'aria-pressed': on,
					onClick: () => void s.toggle()
				};
				if (placement === 'header') attrs['data-github-accel-in-header'] = true;
				else attrs['data-github-accel-overlay'] = true;
				/* 有 Tooltip 组件时不要再挂原生 title，否则悬停会同时冒出两个提示。 */
				if (!Tooltip) attrs.title = s.busy ? tOwn('busy') : tooltip;

				const button = react.createElement(
					'button',
					attrs,
					react.createElement('span', { className: 'dsh-github-accel-dot' }),
					react.createElement('span', null, 'GitHub')
				);

				return react.createElement(
					react.Fragment,
					null,
					Tooltip ? react.createElement(Tooltip, { label: tooltip, side: 'bottom', delayMs: 500 }, button) : button,
					s.hint === undefined
						? null
						: react.createElement('div', { className: 'dsh-github-accel-hint', role: 'status' }, s.hint)
				);
			}

			/** 席位 1：会话 header 里（有会话、header 渲染时就在）。 */
			function InHeader() {
				return react.createElement(Button, { placement: 'header' });
			}

			/** 席位 2：空会话兜底；只在「会话界面」被选中时出现，免得飘在设置面板上。 */
			function InOverlay(props) {
				const usePanelInfo =
					props && typeof props.usePanelInfo === 'function'
						? props.usePanelInfo
						: (selector) => selector({ activePanelId: null });
				const conversationSelected = usePanelInfo((info) => info.activePanelId === null);
				if (conversationSelected === false) return null;
				return react.createElement(Button, { placement: 'overlay' });
			}

			return { InHeader, InOverlay };
		}

		const inject = ['slots', 'locale'];

		/**
		 * 实时把「右侧栏占的宽度」写进 CSS 变量 --dsh-accel-right-offset。
		 *
		 * 空会话页面上产品不渲染 session header，我们的按钮只能做浮层（fixed）。
		 * 固定定位是相对**视口**的，右侧栏一推出来就会盖住它的标签条。所以按右侧栏
		 * 面板的实际位置算偏移：面板在视口内就取它的宽度，被移出视口/宽度为 0（收起）
		 * 就归 0。这样浮层永远贴在**主栏**右边缘，和 header 里那份一致。
		 *
		 * 「不够丝滑」的原因与解法：产品的分栏动画是 `.pI_x6G_frame` 上的
		 * `transition: grid-template-columns var(--ds-transition-duration-slow) …`，
		 * MutationObserver 只能看到「开始」那一下（属性变了），**过渡过程看不见**。
		 * 所以这里在过渡窗口内**逐帧采样**（rAF），值稳定后自动停；再加一个 1s 的
		 * 兜底复检（拖动分栏把手之类没触发观察的情况）。
		 */
		function installRightOffset() {
			if (window.__dshAccelRightOffsetInstalled === true) return;
			window.__dshAccelRightOffsetInstalled = true;
			const root = document.documentElement;
			let last = -1;
			let raf = 0;
			let until = 0;
			let lastKick = 0;

			const measure = () => {
				let offset = 0;
				const panel = document.querySelector('[data-sidebar-right-panel]');
				/* 只在「确实展开」时才有偏移：收起时面板可能仍占着几何（被平移出视口），
				   别把浮层错误地推走。data-sidebar-right-open 是产品自己写的标记。 */
				if (panel !== null && panel.hasAttribute('data-sidebar-right-open')) {
					const rect = panel.getBoundingClientRect();
					const viewport = root.clientWidth;
					if (rect.width > 1 && rect.left < viewport) offset = Math.max(0, viewport - rect.left);
				}
				/* 保留一位小数：按整数像素走会看到 1px 的台阶，次像素能让过渡真正连续。 */
				const rounded = Math.round(offset * 10) / 10;
				if (rounded === last) return false;
				last = rounded;
				root.style.setProperty('--dsh-accel-right-offset', rounded + 'px');
				return true;
			};

			const tick = () => {
				raf = 0;
				const changed = measure();
				if (changed || performance.now() < until) raf = requestAnimationFrame(tick);
			};

			const kick = (ms = 600) => {
				const now = performance.now();
				until = now + ms;
				/* 高频属性变化（比如流式输出改 class）不要每次都重启一轮采样 */
				if (raf === 0 && now - lastKick > 120) {
					lastKick = now;
					raf = requestAnimationFrame(tick);
				}
			};

			measure();
			window.addEventListener('resize', () => kick(300), true);
			const mo = new MutationObserver(() => kick(600));
			mo.observe(document.body, {
				attributes: true,
				subtree: true,
				attributeFilter: ['style', 'class', 'data-sidebar-right-open', 'data-sidebar-right-panel'],
			});
			setInterval(measure, 1000);
		}

		function apply(ctx) {
			ensureStyles();
			installRightOffset();
			ctx.effect(() => ctx.locale.register(NS, { zh, en }), 'dsh-github-accel: dictionaries');
			const { InHeader, InOverlay } = createButton(ctx);
			ctx.effect(
				() =>
					ctx.slots.inject('conversation.session.header.utilities', () =>
						ctx.slots.register(
							{
								name: 'conversation.session.header.utilities',
								id: 'dsh-github-accel/toggle',
								order: 100,
								locale: NS
							},
							InHeader
						)
					),
				'dsh-github-accel: header seat'
			);
			ctx.effect(
				() =>
					ctx.slots.inject('shell.overlay', () =>
						ctx.slots.register(
							{
								name: 'shell.overlay',
								id: 'dsh-github-accel/overlay',
								order: 210,
								locale: NS
							},
							InOverlay
						)
					),
				'dsh-github-accel: blank-session overlay seat'
			);
		}

		exports.apply = apply;
		exports.inject = inject;
		return module.exports;
	}
});
