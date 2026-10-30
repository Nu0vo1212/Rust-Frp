/* ===========================================================================
   NFrp Docs · Application logic
   ---------------------------------------------------------------------------
   Zero dependencies.

   Highlights:
   - English URL slugs, bilingual content (zh / en) switchable at runtime
   - Sequential page handoff with staggered content animation
   - Sticky-header shadow on scroll, scroll progress bar
   - Sidebar active indicator that slides between items
   - Number count-up on the home stats
   - Scroll reveal, copy buttons, mobile drawer

   All motion touches transform / opacity only (GPU composited).
   prefers-reduced-motion is honoured throughout.
   =========================================================================== */

(function () {
  'use strict';

  /* ---------- Route table ----------
     Slugs are English in every language so URLs stay stable and readable. */
  const ROUTES = [
    { slug: 'overview',               page: 'home',          title: 'home' },
    { slug: 'installation',           page: 'install',       title: 'install' },
    { slug: 'quick-start',            page: 'quickstart',    title: 'quickstart' },
    { slug: 'server-configuration',   page: 'config-server', title: 'config-server' },
    { slug: 'client-configuration',   page: 'config-client', title: 'config-client' },
    { slug: 'proxy-types',            page: 'proxies',       title: 'proxies' },
    { slug: 'plugins',                page: 'plugins',       title: 'plugins' },
    { slug: 'transports',             page: 'transports',    title: 'transports' },
    { slug: 'wire-protocol',          page: 'protocol',      title: 'protocol' },
    { slug: 'protocol-v1',            page: 'protocol-v1',   title: 'protocol-v1' },
    { slug: 'protocol-v2',            page: 'protocol-v2',   title: 'protocol-v2' },
    { slug: 'message-types',          page: 'messages',      title: 'messages' },
  { slug: 'nlink',                  page: 'nlink',         title: 'nlink' },
    { slug: 'security-model',         page: 'security',      title: 'security' },
    { slug: 'acl-and-rbac',           page: 'acl-rbac',      title: 'acl-rbac' },
    { slug: 'audit-log',              page: 'audit',         title: 'audit' },
    { slug: 'security-history',       page: 'changes',       title: 'changes' },
    { slug: 'http-api',               page: 'api',           title: 'api' },
    { slug: 'use-as-library',         page: 'library',       title: 'library' },
    { slug: 'frp-interoperability',   page: 'compat',        title: 'compat' },
  ];

  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));

  const LANG_KEY = 'nfrp-doc-lang';
  const THEME_KEY = 'nfrp-doc-theme';

  const REDUCED = window.matchMedia
    ? window.matchMedia('(prefers-reduced-motion: reduce)').matches
    : false;

  let lang = 'zh';
  let activePage = null;
  let switchTimer = null;

  /* ---------- Language detection ---------- */
  function detectLang() {
    let saved = null;
    try { saved = localStorage.getItem(LANG_KEY); } catch (e) {}
    if (saved === 'zh' || saved === 'en') return saved;

    // Hash may carry an explicit override: #/installation?lang=en
    const m = /[?&]lang=(zh|en)/.exec(location.hash || '');
    if (m) return m[1];

    const nav = (navigator.language || 'zh').toLowerCase();
    return nav.startsWith('zh') ? 'zh' : 'en';
  }

  function t(key) {
    const table = (typeof I18N !== 'undefined' && I18N[lang]) || {};
    if (key in table) return table[key];
    const fallback = (typeof I18N !== 'undefined' && I18N.zh) || {};
    return fallback[key] || key;
  }

  /* ---------- Inject dynamic pages ---------- */
  function pageSource() {
    if (lang === 'en' && typeof PAGES_EN !== 'undefined') return PAGES_EN;
    if (lang === 'zh' && typeof PAGES_ZH !== 'undefined') return PAGES_ZH;
    if (typeof PAGES_ZH !== 'undefined') return PAGES_ZH;
    if (typeof PAGES_EN !== 'undefined') return PAGES_EN;
    return {};
  }

  function injectPages() {
    const host = $('#dynamicPages');
    if (!host) return;
    host.innerHTML = '';

    const src = pageSource();
    const frag = document.createDocumentFragment();
    Object.keys(src).forEach(function (id) {
      const sec = document.createElement('section');
      sec.className = 'page';
      sec.id = 'page-' + id;
      sec.hidden = true;
      sec.innerHTML = src[id];
      frag.appendChild(sec);
    });
    host.appendChild(frag);
  }

  /* ---------- Routing ---------- */
  function slugFromHash() {
    const h = (location.hash || '').replace(/^#\/?/, '').split('?')[0].trim();
    return (h || 'overview').replace(/\/$/, '') || 'overview';
  }

  function routeOf(slug) {
    return (
      ROUTES.find(function (r) { return r.slug === slug; }) ||
      ROUTES[0]
    );
  }

  /* ---------- Static shell translation ---------- */
  function applyLangToShell() {
    document.documentElement.setAttribute('lang', t('_htmlLang'));
    $$('[data-i18n]').forEach(function (el) {
      const key = el.getAttribute('data-i18n');
      const val = t(key);
      if (val && val !== key) el.textContent = val;
    });
    const lbl = $('#langLabel');
    // 只显示**目标**语言：按钮表达"点它会切到哪"，这是语言切换器的通行做法。
    // （原来显示"中文 → EN"，在 34px 的图标按钮组里放不下，会撑宽按钮、破坏对齐。）
    if (lbl) lbl.textContent = lang === 'zh' ? 'EN' : '中';
    const btn = $('#langBtn');
    if (btn) {
      btn.setAttribute(
        'aria-label',
        lang === 'zh' ? 'Switch to English' : '切换到中文'
      );
      btn.title = lang === 'zh' ? 'Switch to English' : '切换到中文';
    }
  }

  /* ---------- Page switching with staggered animation ---------- */
  function activate(slug) {
    const route = routeOf(slug);
    const target = $('#page-' + route.page) || $('#page-home');

    /* Sidebar: highlight immediately, and slide the indicator */
    $$('.nav-link').forEach(function (a) {
      const s = (a.getAttribute('href') || '').replace(/^#\/?/, '').split('?')[0];
      a.classList.toggle('active', s === route.slug);
    });
    moveIndicator();

    /* Scroll before animating so nothing jumps mid-transition */
    window.scrollTo({ top: 0, behavior: 'auto' });

    const old = activePage;
    activePage = target;

    document.title = t('t-' + route.title) + ' | NFrp Docs';

    if (old === target) {
      buildPager(route);
      animateContent(target, true);
      return;
    }

    clearTimeout(switchTimer);

    /* 先清空，避免旧位置的 pager 残影在新页面上闪一下 */
    clearPager();

    target.classList.remove('page-exit', 'page-enter');

    const reveal = function () {
      target.hidden = false;
      if (!REDUCED) {
        target.classList.add('page-enter');
        void target.offsetWidth;
        switchTimer = setTimeout(function () {
          target.classList.remove('page-enter');
        }, 420);
      }
      animateContent(target, false);
      /* ★ pager 必须等新页面真的显示出来再建。
         放在 activate() 末尾会导致"旧页面还在、pager 却已换成新内容"，
         于是条子先停在上面、随后才被新内容挤下去 —— 就是那个闪烁。 */
      buildPager(route);
    };

    if (old && !REDUCED) {
      /* Old page fades out and lifts, then the new one comes in.
         Not a cross fade: two structurally different pages overlapping
         reads as doubled text at the crossover. */
      old.classList.add('page-exit');
      old.hidden = false;
      switchTimer = setTimeout(function () {
        old.hidden = true;
        old.classList.remove('page-exit');
        reveal();
      }, 150);
    } else {
      if (old) {
        old.hidden = true;
        old.classList.remove('page-exit');
      }
      reveal();
    }

    decorateCodeBlocks(target);
    closeDrawer();
  }

  /* 清空 pager（切换期间用），并保持占位高度避免页面高度抖动 */
  function clearPager() {
    const slot = $('#pagerSlot');
    if (!slot) return;
    slot.classList.remove('pager-in');
    slot.innerHTML = '';
  }

  /* Stagger the headings / blocks inside a freshly shown page */
  function animateContent(host, repeat) {
    if (REDUCED) return;

    const items = $$(
      ':scope > h1, :scope > .lead, :scope > h2, :scope > h3, ' +
      ':scope > p, :scope > pre, :scope > .table-wrap, :scope > .callout, ' +
      ':scope > .cards, :scope > .stats, :scope > ul, :scope > ol, ' +
      ':scope > .hero > *, :scope > .card, :scope > .stat',
      host
    );

    items.forEach(function (el, i) {
      if (!repeat && el.dataset.animated === '1') return;
      el.dataset.animated = '1';
      el.classList.remove('anim-in');
      el.style.animationDelay = Math.min(i * 26, 340) + 'ms';
      void el.offsetWidth;
      el.classList.add('anim-in');
    });
  }

  /* ---------- Sliding sidebar indicator ---------- */
  function moveIndicator() {
    const bar = $('#navIndicator');
    const active = $('.nav-link.active');
    const sidebar = $('#sidebar');
    if (!bar || !active || !sidebar) return;

    const sr = sidebar.getBoundingClientRect();
    const ar = active.getBoundingClientRect();
    if (ar.height === 0) return; // drawer closed

    bar.style.transform = 'translateY(' + (ar.top - sr.top + sidebar.scrollTop) + 'px)';
    bar.style.height = ar.height + 'px';
    bar.style.opacity = '1';
  }

  /* ---------- Prev/next pager ---------- */
  function buildPager(route) {
    const slot = $('#pagerSlot');
    if (!slot) return;
    const idx = ROUTES.indexOf(route);
    const prev = ROUTES[idx - 1];
    const next = ROUTES[idx + 1];

    slot.innerHTML = '';
    if (!prev && !next) return;

    const nav = document.createElement('nav');
    nav.className = 'pager';

    if (prev) {
      nav.insertAdjacentHTML(
        'beforeend',
        '<a href="#/' + prev.slug + '">' +
          '<span class="dir">' +
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" ' +
          'stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>' +
          t('pager-prev') + '</span>' +
          '<span class="name">' + t('t-' + prev.title) + '</span></a>'
      );
    } else {
      nav.insertAdjacentHTML('beforeend', '<span class="spacer"></span>');
    }

    if (next) {
      nav.insertAdjacentHTML(
        'beforeend',
        '<a class="next" href="#/' + next.slug + '">' +
          '<span class="dir">' + t('pager-next') +
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" ' +
          'stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M12 5l7 7-7 7"/></svg>' +
          '</span>' +
          '<span class="name">' + t('t-' + next.title) + '</span></a>'
      );
    }

    slot.appendChild(nav);

    /* 淡入：让条子跟着页面一起出现，而不是硬插进去 */
    if (!REDUCED) {
      slot.classList.remove('pager-in');
      void slot.offsetWidth;
      slot.classList.add('pager-in');
    }
  }

  /* ---------- Copy buttons ---------- */
  const COPY_ICON =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" ' +
    'stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/>' +
    '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
  const CHECK_ICON =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" ' +
    'stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>';

  function decorateCodeBlocks(host) {
    $$('pre', host).forEach(function (pre) {
      if (pre.dataset.decorated) return;
      pre.dataset.decorated = '1';

      const btn = document.createElement('button');
      btn.className = 'copy-btn';
      btn.type = 'button';
      btn.setAttribute('aria-label', 'Copy');
      btn.innerHTML = COPY_ICON;
      btn.addEventListener('click', function () {
        const code = pre.querySelector('code');
        const text = code ? code.textContent : pre.textContent;
        const done = function () {
          btn.innerHTML = CHECK_ICON;
          btn.classList.add('copied');
          setTimeout(function () {
            btn.innerHTML = COPY_ICON;
            btn.classList.remove('copied');
          }, 1500);
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(done).catch(function () {
            legacyCopy(text) && done();
          });
        } else if (legacyCopy(text)) {
          done();
        }
      });
      pre.appendChild(btn);
    });
  }

  function legacyCopy(text) {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.cssText = 'position:fixed;top:-9999px;opacity:0';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      return ok;
    } catch (e) {
      return false;
    }
  }

  /* ---------- Scroll reveal ---------- */
  let io = null;
  let revealFailsafe = 0;
  function initReveal() {
    if (!('IntersectionObserver' in window)) return;
    io = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (e) {
          if (e.isIntersecting) {
            e.target.classList.add('in');
            io.unobserve(e.target);
          }
        });
      },
      { rootMargin: '0px 0px -6% 0px', threshold: 0.05 }
    );
  }

  function observeReveals(host) {
    const items = $$('.reveal', host).filter(function (el) {
      return !el.classList.contains('in');
    });
    if (!items.length) return;

    if (!io || REDUCED) {
      items.forEach(function (el) { el.classList.add('in'); });
      return;
    }
    items.forEach(function (el, i) {
      el.style.transitionDelay = Math.min(i * 50, 300) + 'ms';
      io.observe(el);
    });

    /* 兜底：IntersectionObserver 在无头渲染 / 后台标签页 / 极端慢设备上可能
       迟迟不回调，而 .reveal 是 opacity:0 —— 结果是**正文整段看不见**，
       比"没有动画"严重得多。1.2s 后把还没揭示的直接显示；
       正常页面此时 IO 早已处理完，等于空操作。 */
    clearTimeout(revealFailsafe);
    revealFailsafe = setTimeout(function () {
      $$('.reveal', host).forEach(function (el) {
        if (!el.classList.contains('in')) el.classList.add('in');
      });
    }, 1200);
  }

  /* ---------- Count-up numbers ---------- */
  function countUp() {
    $$('.stat[data-count]').forEach(function (el) {
      if (el.dataset.counted === '1') return;
      el.dataset.counted = '1';

      const target = parseFloat(el.dataset.count);
      const suffix = el.dataset.suffix || '';
      const out = $('.stat-value', el);
      if (!out || REDUCED || isNaN(target)) return;

      const decimals = (el.dataset.count.split('.')[1] || '').length;
      const dur = 900;
      const t0 = performance.now();

      const step = function (now) {
        const p = Math.min((now - t0) / dur, 1);
        // easeOutCubic
        const eased = 1 - Math.pow(1 - p, 3);
        const v = (target * eased).toFixed(decimals);
        out.textContent = v + suffix;
        if (p < 1) requestAnimationFrame(step);
        else out.textContent = target.toFixed(decimals) + suffix;
      };
      requestAnimationFrame(step);
    });
  }

  /* ---------- Scroll effects: header shadow + progress bar ---------- */
  function initScrollFx() {
    const header = $('.header');
    const bar = $('#progressBar');
    let ticking = false;

    const update = function () {
      const y = window.scrollY || document.documentElement.scrollTop;
      if (header) header.classList.toggle('scrolled', y > 8);

      if (bar) {
        const h = document.documentElement.scrollHeight - window.innerHeight;
        const p = h > 0 ? Math.min(y / h, 1) : 0;
        bar.style.transform = 'scaleX(' + p + ')';
      }
      ticking = false;
    };

    window.addEventListener(
      'scroll',
      function () {
        if (!ticking) {
          ticking = true;
          requestAnimationFrame(update);
        }
      },
      { passive: true }
    );
    update();
  }

  /* ---------- Theme ---------- */
  let themeTimer = 0;

  /* 真正把 --bg 等变量换掉，并同步按钮图标 */
  function commitTheme(th) {
    document.documentElement.setAttribute('data-theme', th);
    const moon = $('.ico-moon');
    const sun = $('.ico-sun');
    if (moon && sun) {
      const light = th === 'light';
      moon.style.display = light ? 'none' : '';
      sun.style.display = light ? '' : 'none';
    }
  }

  /* 切换主题。

     ★ 关键顺序（踩过坑）：挂过渡类 → **让出一帧** → 再切变量。
       浏览器的样式重算是按任务合并的：如果在同一个同步块里又加类又改变量，
       它只会看到最终状态，没有"旧值作为过渡起点"，结果不产生 transition
       （实测 Animation 域报告 0 个过渡）。
       让出一帧后，浏览器先把旧值记为起点，下一帧改变量才有东西可插值。 */
  function applyTheme(th, animate) {
    const root = document.documentElement;
    const doAnim = animate !== false && !REDUCED;

    if (!doAnim) {
      commitTheme(th);
      return;
    }

    /* 已经在过渡中：直接落到目标，避免连续点击堆叠出一堆半途状态 */
    if (root.classList.contains('theme-switching')) {
      commitTheme(th);
      return;
    }

    root.classList.add('theme-switching');
    /* 同步读一次计算样式，强制刷新样式缓存（rAF 不可靠时的双保险） */
    void getComputedStyle(document.body).color;

    const DUR_MS = 320;

    function start() {
      commitTheme(th);

      let removed = false;
      function done() {
        if (removed) return;
        removed = true;
        root.classList.remove('theme-switching');
        root.removeEventListener('transitionend', onEnd);
        clearTimeout(themeTimer);
      }
      function onEnd(e) {
        if (e.target === root || e.target === document.body) done();
      }
      root.addEventListener('transitionend', onEnd);
      /* 兜底：事件丢失时也要保证类被摘掉，否则页面会一直带着过渡 */
      clearTimeout(themeTimer);
      themeTimer = setTimeout(done, DUR_MS + 160);
    }

    /* 让出一帧再改变量 */
    if (typeof requestAnimationFrame === 'function') {
      requestAnimationFrame(function () {
        /* 有些环境 rAF 回调里紧接着改仍会被合并，再让一帧更稳 */
        requestAnimationFrame(start);
      });
    } else {
      setTimeout(start, 16);
    }
  }

  function initTheme() {
    let saved = null;
    try { saved = localStorage.getItem(THEME_KEY); } catch (e) {}
    /* 首次渲染不做过场：页面刚出来应该是稳定的，不该看到颜色渐入 */
    applyTheme(saved || 'dark', false);

    const btn = $('#themeBtn');
    if (btn) {
      btn.addEventListener('click', function () {
        const cur = document.documentElement.getAttribute('data-theme');
        const next = cur === 'light' ? 'dark' : 'light';
        applyTheme(next);
        try { localStorage.setItem(THEME_KEY, next); } catch (e) {}
      });
    }
  }

  /* ---------- Language switch ---------- */
  function setLang(next, persist) {
    lang = next;
    if (persist) {
      try { localStorage.setItem(LANG_KEY, next); } catch (e) {}
    }

    applyLangToShell();
    injectPages();

    // Re-render the current page in the new language
    const route = routeOf(slugFromHash());
    activePage = null;
    activate(route.slug);
    observeReveals($('#content'));
    countUp();
  }

  function initLang() {
    lang = detectLang();
    const btn = $('#langBtn');
    if (btn) {
      btn.addEventListener('click', function () {
        // 切换动画：标签上翻淡出 → 下翻淡入（CSS 里的 lang-swap）
        btn.classList.remove('switching');
        void btn.offsetWidth;
        btn.classList.add('switching');
        setLang(lang === 'zh' ? 'en' : 'zh', true);
      });
    }
  }

  /* ---------- Mobile drawer ---------- */
  function openDrawer() {
    const sb = $('#sidebar');
    const scrim = $('#scrim');
    const btn = $('#menuBtn');
    if (!sb) return;
    sb.classList.add('open');
    scrim && scrim.classList.add('show');
    btn && btn.setAttribute('aria-expanded', 'true');
    setTimeout(moveIndicator, 60);
  }

  function closeDrawer() {
    const sb = $('#sidebar');
    const scrim = $('#scrim');
    const btn = $('#menuBtn');
    if (!sb) return;
    sb.classList.remove('open');
    scrim && scrim.classList.remove('show');
    btn && btn.setAttribute('aria-expanded', 'false');
  }

  function initDrawer() {
    const btn = $('#menuBtn');
    const scrim = $('#scrim');
    btn && btn.addEventListener('click', function () {
      $('#sidebar').classList.contains('open') ? closeDrawer() : openDrawer();
    });
    scrim && scrim.addEventListener('click', closeDrawer);
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') closeDrawer();
    });
  }

  /* ---------- Boot ---------- */
  function boot() {
    initTheme();
    initReveal();
    initScrollFx();
    initDrawer();
    initLang();

    applyLangToShell();
    injectPages();

    window.addEventListener('hashchange', function () {
      activate(slugFromHash());
    });
    window.addEventListener('resize', moveIndicator);

    activate(slugFromHash());

    // Reveal anything already on screen and start the counters
    observeReveals($('#content'));
    countUp();
    setTimeout(moveIndicator, 120);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
