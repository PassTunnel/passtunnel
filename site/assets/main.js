/* PassTunnel website: theme button, mobile menu, copy buttons, format and palette pickers, and the
   live code demo. No dependencies. Everything the scripts show is in STRINGS (for translations). */
(function () {
  'use strict';

  var STRINGS = {
    themeNames: { auto: 'Auto', light: 'Light', dark: 'Dark' },
    themeLabel: 'Color theme: {current}. Switch to {next}.',
    copy: 'Copy',
    copied: 'Copied',
    copyFailed: 'Copy failed',
    copiedAnnounce: 'Copied to the clipboard.',
    copyFailedAnnounce: 'Could not copy to the clipboard.',
    demo: {
      idle: {
        state: 'Disconnected',
        button: 'Connect',
        status: 'Click Connect: your password and this code go out together.',
        statusLow: 'Under 8 seconds left. Connect would wait for the next code.'
      },
      waiting: {
        state: 'Waiting',
        button: 'Waiting for a fresh code · {secs} s',
        status: 'Under 8 seconds left in this window, so PassTunnel waits for a fresh code.',
        announce: 'Waiting for a fresh code before connecting.'
      },
      sending: {
        state: 'Connecting',
        button: 'Connecting…',
        status: 'Sending your password and the code to vpn.example.com…',
        announce: 'Connecting.'
      },
      connected: {
        state: 'Connected',
        button: 'Disconnect',
        status: 'Connected to Work. You did not type a thing.',
        announce: 'Connected to Work.'
      },
      disconnected: 'Disconnected.',
      sentNothing: 'nothing yet',
      sentWaiting: 'waiting…',
      mask: '••••••••'
    }
  };

  var root = document.documentElement;
  var announcer = document.querySelector('[data-announce]');

  function format(template, values) {
    return template.replace(/\{(\w+)\}/g, function (all, key) {
      return Object.prototype.hasOwnProperty.call(values, key) ? values[key] : all;
    });
  }

  function announce(region, text) {
    if (!region) return;
    // Clear first so the same message is announced again.
    region.textContent = '';
    window.setTimeout(function () { region.textContent = text; }, 60);
  }

  /* ---------- Theme: Auto -> Light -> Dark ---------- */

  var THEMES = ['auto', 'light', 'dark'];
  var themeButton = document.querySelector('[data-theme-toggle]');
  var themeColors = Array.prototype.slice.call(document.querySelectorAll('meta[name="theme-color"]'));
  var themeColorDefaults = themeColors.map(function (m) { return m.getAttribute('content'); });

  function currentTheme() {
    var t = root.getAttribute('data-theme');
    return THEMES.indexOf(t) === -1 ? 'auto' : t;
  }

  function applyTheme(theme) {
    root.setAttribute('data-theme', theme);
    themeColors.forEach(function (meta, i) {
      meta.setAttribute('content', theme === 'auto' ? themeColorDefaults[i] : (theme === 'dark' ? '#000000' : '#ffffff'));
    });
    if (themeButton) {
      var next = THEMES[(THEMES.indexOf(theme) + 1) % THEMES.length];
      var label = format(STRINGS.themeLabel, {
        current: STRINGS.themeNames[theme],
        next: STRINGS.themeNames[next]
      });
      themeButton.setAttribute('aria-label', label);
      themeButton.setAttribute('title', label);
    }
  }

  if (themeButton) {
    applyTheme(currentTheme());
    themeButton.addEventListener('click', function () {
      var theme = THEMES[(THEMES.indexOf(currentTheme()) + 1) % THEMES.length];
      applyTheme(theme);
      try {
        if (theme === 'auto') window.localStorage.removeItem('passtunnel-theme');
        else window.localStorage.setItem('passtunnel-theme', theme);
      } catch (e) {
        /* Storage blocked: the choice lasts until the page is closed. */
      }
    });
  }

  /* ---------- Mobile menu (disclosure) ---------- */

  var menuButton = document.querySelector('[data-menu-toggle]');
  var menu = menuButton && document.getElementById(menuButton.getAttribute('aria-controls'));

  function menuOpen() {
    return menuButton.getAttribute('aria-expanded') === 'true';
  }

  function setMenu(open, focusButton) {
    menuButton.setAttribute('aria-expanded', open ? 'true' : 'false');
    menu.classList.toggle('is-open', open);
    if (!open && focusButton) menuButton.focus();
  }

  if (menuButton && menu) {
    menuButton.addEventListener('click', function () {
      var open = !menuOpen();
      setMenu(open, false);
      if (open) {
        var first = menu.querySelector('a');
        if (first) first.focus();
      }
    });
    menu.addEventListener('click', function (event) {
      if (event.target.closest('a') && menuOpen()) setMenu(false, false);
    });
    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape' && menuOpen()) setMenu(false, true);
    });
    document.addEventListener('click', function (event) {
      if (menuOpen() && !menu.contains(event.target) && !menuButton.contains(event.target)) setMenu(false, false);
    });
    // Tabbing out of the open menu closes it.
    menu.addEventListener('focusout', function (event) {
      var to = event.relatedTarget;
      if (menuOpen() && to && !menu.contains(to) && to !== menuButton) setMenu(false, false);
    });
    // Widening the window past the breakpoint shows the links inline again.
    var wide = window.matchMedia('(min-width: 900px)');
    var onWide = function () { if (wide.matches && menuOpen()) setMenu(false, false); };
    if (wide.addEventListener) wide.addEventListener('change', onWide);
    else if (wide.addListener) wide.addListener(onWide);
  }

  /* ---------- Copy buttons ---------- */

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      var area = document.createElement('textarea');
      area.value = text;
      area.setAttribute('readonly', '');
      area.className = 'sr-only';
      document.body.appendChild(area);
      area.select();
      var ok = false;
      try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      document.body.removeChild(area);
      if (ok) resolve(); else reject(new Error('copy failed'));
    });
  }

  Array.prototype.forEach.call(document.querySelectorAll('[data-copy]'), function (button) {
    var label = button.querySelector('[data-copy-label]');
    var timer = 0;
    button.addEventListener('click', function () {
      var done = function (ok) {
        if (label) label.textContent = ok ? STRINGS.copied : STRINGS.copyFailed;
        announce(announcer, ok ? STRINGS.copiedAnnounce : STRINGS.copyFailedAnnounce);
        window.clearTimeout(timer);
        timer = window.setTimeout(function () { if (label) label.textContent = STRINGS.copy; }, 1800);
      };
      copyText(button.getAttribute('data-copy')).then(function () { done(true); }, function () { done(false); });
    });
  });

  /* ---------- Horizontal scrollers: fade the edge that cuts text ---------- */

  // Measured only after layout (ResizeObserver callbacks, scroll events, animation frames), never
  // during start-up, so reading the sizes does not force a synchronous layout.
  var scrollers = Array.prototype.slice.call(document.querySelectorAll('[data-scroller]'));

  function updateScroller(el) {
    var max = el.scrollWidth - el.clientWidth;
    el.classList.toggle('fade-start', max > 1 && el.scrollLeft > 1);
    el.classList.toggle('fade-end', max > 1 && el.scrollLeft < max - 1);
  }

  scrollers.forEach(function (el) {
    el.addEventListener('scroll', function () { updateScroller(el); }, { passive: true });
  });

  if ('ResizeObserver' in window) {
    // Called once after the first layout, then whenever a scroller changes size.
    var scrollerObserver = new ResizeObserver(function (entries) {
      entries.forEach(function (entry) { updateScroller(entry.target); });
    });
    scrollers.forEach(function (el) { scrollerObserver.observe(el); });
  } else if (scrollers.length) {
    var updateAll = function () { scrollers.forEach(updateScroller); };
    var pending = 0;
    window.addEventListener('resize', function () {
      if (!pending) pending = window.requestAnimationFrame(function () { pending = 0; updateAll(); });
    });
    window.requestAnimationFrame(updateAll);
  }

  /* ---------- Pickers: aria-pressed button groups ---------- */

  function picker(buttons, onPick) {
    buttons.forEach(function (button) {
      button.addEventListener('click', function () {
        buttons.forEach(function (b) { b.setAttribute('aria-pressed', b === button ? 'true' : 'false'); });
        onPick(button);
      });
    });
  }

  var formatButtons = Array.prototype.slice.call(document.querySelectorAll('[data-format]'));
  var formatPanels = Array.prototype.slice.call(document.querySelectorAll('[data-format-panel]'));
  picker(formatButtons, function (button) {
    var id = button.getAttribute('data-format');
    formatPanels.forEach(function (panel) { panel.hidden = panel.getAttribute('data-format-panel') !== id; });
  });

  var paletteImages = Array.prototype.slice.call(document.querySelectorAll('[data-palette-img]'));
  picker(Array.prototype.slice.call(document.querySelectorAll('[data-palette]')), function (button) {
    var palette = button.getAttribute('data-palette');
    paletteImages.forEach(function (img) {
      var base = 'assets/img/menubar-' + palette + '-' + img.getAttribute('data-palette-img');
      img.setAttribute('srcset', base + '.webp 1x, ' + base + '@2x.webp 2x');
      img.setAttribute('src', base + '.webp');
    });
  });

  /* ---------- Live code demo ---------- */

  var demo = document.querySelector('[data-demo]');
  if (!demo) return;

  var WINDOW = 30000;
  var MIN_LEFT = 8;        // seconds; with less, PassTunnel waits for the next window
  var CONNECTING = 1400;   // ms shown as "Connecting…"
  var CIRCUMFERENCE = 2 * Math.PI * 34;

  var el = {
    a: demo.querySelector('[data-code-a]'),
    b: demo.querySelector('[data-code-b]'),
    secs: demo.querySelector('[data-secs]'),
    ring: demo.querySelector('[data-ring]'),
    progress: demo.querySelector('[data-ring-progress]'),
    state: demo.querySelector('[data-demo-state]'),
    status: demo.querySelector('[data-demo-status]'),
    button: demo.querySelector('[data-demo-btn]'),
    mask: demo.querySelector('[data-sent-mask]'),
    sent: demo.querySelector('[data-sent-code]'),
    live: demo.querySelector('[data-demo-announce]')
  };

  var state = { phase: 'idle', waitWindow: 0, sendAt: 0, sent: '' };

  function windowOf(now) {
    return Math.floor(now / WINDOW);
  }

  // Not TOTP and not secret: a hash of the window number, so the page never holds a real code.
  function codeFor(win) {
    var x = (win ^ 0x5bd1e995) >>> 0;
    x = Math.imul(x ^ (x >>> 15), 0x2c1b3c6d) >>> 0;
    x = Math.imul(x ^ (x >>> 12), 0x297a2d39) >>> 0;
    x = (x ^ (x >>> 15)) >>> 0;
    return String(x % 1000000).padStart(6, '0');
  }

  function setText(node, text) {
    if (node && node.textContent !== text) node.textContent = text;
  }

  function setPhase(phase) {
    if (state.phase === phase) return;
    state.phase = phase;
    demo.setAttribute('data-phase', phase);
    var text = STRINGS.demo[phase] && STRINGS.demo[phase].announce;
    announce(el.live, text || STRINGS.demo.disconnected);
  }

  function render(now) {
    var left = (WINDOW - (now % WINDOW)) / 1000;
    var secs = Math.max(1, Math.ceil(left));
    var low = left < MIN_LEFT;
    var code = codeFor(windowOf(now));
    var strings = STRINGS.demo[state.phase];

    setText(el.a, code.slice(0, 3));
    setText(el.b, code.slice(3));
    setText(el.secs, String(secs));
    el.progress.setAttribute('stroke-dashoffset', (CIRCUMFERENCE * (1 - left / 30)).toFixed(2));
    el.ring.classList.toggle('is-low', low);

    setText(el.state, strings.state);
    setText(el.status, state.phase === 'idle' && low ? strings.statusLow : strings.status);
    setText(el.button, format(strings.button, { secs: secs }));

    var busy = state.phase === 'waiting' || state.phase === 'sending';
    if (busy) el.button.setAttribute('aria-disabled', 'true');
    else el.button.removeAttribute('aria-disabled');

    var hasSent = state.phase === 'sending' || state.phase === 'connected';
    setText(el.mask, hasSent ? STRINGS.demo.mask : '');
    setText(el.sent, hasSent ? state.sent : (state.phase === 'waiting' ? STRINGS.demo.sentWaiting : STRINGS.demo.sentNothing));
  }

  function tick() {
    var now = Date.now();
    if (state.phase === 'waiting' && windowOf(now) > state.waitWindow) {
      state.sendAt = now;
      state.sent = codeFor(windowOf(now));
      setPhase('sending');
    } else if (state.phase === 'sending' && now - state.sendAt > CONNECTING) {
      setPhase('connected');
    }
    render(now);
  }

  el.button.addEventListener('click', function () {
    var now = Date.now();
    if (state.phase === 'connected') {
      state.sent = '';
      setPhase('idle');
    } else if (state.phase === 'idle') {
      var left = (WINDOW - (now % WINDOW)) / 1000;
      if (left >= MIN_LEFT) {
        state.sendAt = now;
        state.sent = codeFor(windowOf(now));
        setPhase('sending');
      } else {
        state.waitWindow = windowOf(now);
        setPhase('waiting');
      }
    }
    // Waiting or connecting: the button is aria-disabled, so the click does nothing.
    render(now);
  });

  // Tick only while the demo is on screen and the tab is visible.
  var timer = 0;
  var onScreen = !('IntersectionObserver' in window);

  function sync() {
    var run = onScreen && !document.hidden;
    if (run && !timer) {
      tick();
      timer = window.setInterval(tick, 200);
    } else if (!run && timer) {
      window.clearInterval(timer);
      timer = 0;
    }
  }

  if (!onScreen) {
    new IntersectionObserver(function (entries) {
      onScreen = entries[entries.length - 1].isIntersecting;
      sync();
    }).observe(demo);
  }
  document.addEventListener('visibilitychange', sync);
  render(Date.now());
  sync();
})();
