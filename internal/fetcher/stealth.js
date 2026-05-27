// stealth.js: anti-detection patches for chromedp/headless Chrome. Injected
// via Page.addScriptToEvaluateOnNewDocument so every detection surface looks
// like a normal user-driven Chrome on Windows by the time page scripts run.
// Patterns derived from puppeteer-extra-plugin-stealth (MIT). Keep <5 KB.
(() => {
  'use strict';
  try {
    // 1. navigator.webdriver -> undefined (instead of true under CDP).
    try {
      Object.defineProperty(Navigator.prototype, 'webdriver', {
        get: () => undefined,
        configurable: true,
      });
    } catch (_) {}

    // 2. navigator.plugins -> non-empty plausible PluginArray.
    try {
      const mk = (name, filename, description) => {
        const p = Object.create(Plugin.prototype);
        Object.defineProperties(p, {
          name: { value: name },
          filename: { value: filename },
          description: { value: description },
          length: { value: 1 },
        });
        p[0] = { type: 'application/pdf', suffixes: 'pdf', description: description, enabledPlugin: p };
        return p;
      };
      const list = [
        mk('Chrome PDF Plugin', 'internal-pdf-viewer', 'Portable Document Format'),
        mk('Chrome PDF Viewer', 'mhjfbmdgcfjbbpaeojofohoefgiehjai', ''),
        mk('Native Client', 'internal-nacl-plugin', ''),
      ];
      const arr = Object.create(PluginArray.prototype);
      list.forEach((p, i) => { arr[i] = p; arr[p.name] = p; });
      Object.defineProperty(arr, 'length', { value: list.length });
      Object.defineProperty(Navigator.prototype, 'plugins', {
        get: () => arr,
        configurable: true,
      });
    } catch (_) {}

    // 3. navigator.languages -> ['en-US', 'en'].
    try {
      Object.defineProperty(Navigator.prototype, 'languages', {
        get: () => ['en-US', 'en'],
        configurable: true,
      });
    } catch (_) {}

    // 4. window.chrome -> populated runtime/app/loadTimes/csi stubs.
    try {
      if (!window.chrome) {
        Object.defineProperty(window, 'chrome', {
          value: {},
          writable: true,
          configurable: true,
        });
      }
      const c = window.chrome;
      if (!c.runtime) {
        c.runtime = {
          OnInstalledReason: {},
          OnRestartRequiredReason: {},
          PlatformArch: {},
          PlatformNaclArch: {},
          PlatformOs: {},
          RequestUpdateCheckStatus: {},
          connect: function () {},
          sendMessage: function () {},
        };
      }
      if (!c.app) {
        c.app = {
          isInstalled: false,
          InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' },
          RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' },
          getDetails: function () { return null; },
          getIsInstalled: function () { return false; },
          runningState: function () { return 'cannot_run'; },
        };
      }
      if (!c.loadTimes) {
        c.loadTimes = function () {
          return {
            requestTime: Date.now() / 1000 - 1,
            startLoadTime: Date.now() / 1000 - 1,
            commitLoadTime: Date.now() / 1000 - 0.9,
            finishDocumentLoadTime: Date.now() / 1000 - 0.5,
            finishLoadTime: Date.now() / 1000 - 0.4,
            firstPaintTime: Date.now() / 1000 - 0.3,
            firstPaintAfterLoadTime: 0,
            navigationType: 'Other',
            wasFetchedViaSpdy: true,
            wasNpnNegotiated: true,
            npnNegotiatedProtocol: 'h2',
            wasAlternateProtocolAvailable: false,
            connectionInfo: 'h2',
          };
        };
      }
      if (!c.csi) {
        c.csi = function () {
          return { startE: Date.now() - 1000, onloadT: Date.now() - 500, pageT: 500, tran: 15 };
        };
      }
    } catch (_) {}

    // 5. navigator.permissions.query -> reflect Notification.permission instead
    //    of returning state: 'prompt' for the notifications query (a known
    //    headless-Chrome tell).
    try {
      if (navigator.permissions && navigator.permissions.query) {
        const orig = navigator.permissions.query.bind(navigator.permissions);
        navigator.permissions.query = (params) => {
          if (params && params.name === 'notifications') {
            return Promise.resolve({ state: Notification.permission, onchange: null });
          }
          return orig(params);
        };
      }
    } catch (_) {}

    // 6. WebGL vendor/renderer -> non-SwiftShader. SwiftShader is the dead
    //    giveaway for headless; we masquerade as Intel integrated graphics.
    try {
      const patchGL = (proto) => {
        if (!proto || !proto.getParameter) return;
        const orig = proto.getParameter;
        proto.getParameter = function (parameter) {
          // UNMASKED_VENDOR_WEBGL = 0x9245, UNMASKED_RENDERER_WEBGL = 0x9246.
          if (parameter === 37445) return 'Intel Inc.';
          if (parameter === 37446) return 'Intel Iris OpenGL Engine';
          return orig.apply(this, arguments);
        };
      };
      patchGL(WebGLRenderingContext.prototype);
      if (typeof WebGL2RenderingContext !== 'undefined') {
        patchGL(WebGL2RenderingContext.prototype);
      }
    } catch (_) {}

    // 7. navigator.platform -> Win32, matching our default Chrome-Windows UA.
    try {
      Object.defineProperty(Navigator.prototype, 'platform', {
        get: () => 'Win32',
        configurable: true,
      });
    } catch (_) {}

    // 8. AudioBuffer.getChannelData -> add inaudible noise so audio
    //    fingerprinting yields a fresh value per session.
    try {
      const ab = AudioBuffer.prototype.getChannelData;
      AudioBuffer.prototype.getChannelData = function () {
        const data = ab.apply(this, arguments);
        // Tweak only the first 16 samples; imperceptible, breaks hash equality.
        for (let i = 0; i < Math.min(16, data.length); i++) {
          data[i] = data[i] + (Math.random() - 0.5) * 1e-7;
        }
        return data;
      };
    } catch (_) {}

    // 9. Canvas.toDataURL -> dither one pixel so per-session fingerprint differs.
    try {
      const td = HTMLCanvasElement.prototype.toDataURL;
      HTMLCanvasElement.prototype.toDataURL = function () {
        try {
          const ctx = this.getContext && this.getContext('2d');
          if (ctx && this.width > 0 && this.height > 0) {
            const img = ctx.getImageData(0, 0, 1, 1);
            img.data[0] = img.data[0] ^ 1;
            ctx.putImageData(img, 0, 0);
          }
        } catch (_) {}
        return td.apply(this, arguments);
      };
    } catch (_) {}

    // 10. Notification.permission -> 'denied' (real Chrome's headless default
    //     is 'denied', not 'default').
    try {
      if (typeof Notification !== 'undefined') {
        Object.defineProperty(Notification, 'permission', {
          get: () => 'denied',
          configurable: true,
        });
      }
    } catch (_) {}
  } catch (_) {
    // Never throw out of stealth: a single failure must not break page scripts.
  }
})();
