/*
 * PromptShield in-page block notification overlay.
 *
 * Injected by the mitmproxy detector addon into supported provider web-app
 * pages (see detector/overlay.py + addon.py). It monkey-patches fetch/XHR so
 * that when PromptShield blocks an outgoing prompt — returning a response with
 * the `X-PromptShield-Blocked: 1` header — the page shows a small, clearly
 * branded toast instead of the user being thrown into a new tab or seeing only
 * the provider UI's generic network error.
 *
 * Design constraints:
 *   - Idempotent: loading twice is a no-op (guarded by window.__promptShieldOverlay).
 *   - Self-contained: Shadow DOM + inline CSS, no external loads (nothing extra
 *     for CSP to block, no provider-CSS interference).
 *   - Non-intrusive: bottom-right toast, pointer-events only on itself, never
 *     touches inputs/keyboard shortcuts/page layout.
 *   - Safe: only ever renders metadata PromptShield put in response headers/body
 *     (provider, rule/category names) — never the matched sensitive value.
 *   - Harmless: every patch is wrapped in try/catch and always returns the
 *     original response unchanged, so it can never break the host app.
 */
(function () {
  "use strict";

  // --- Idempotency: bail out if an earlier injection already ran. -----------
  if (window.__promptShieldOverlay) {
    return;
  }
  window.__promptShieldOverlay = true;

  var BLOCKED_HEADER = "X-PromptShield-Blocked";
  var AUTO_HIDE_MS = 12000;

  // --- Shadow-DOM toast UI ---------------------------------------------------
  var shadowRoot = null;

  function ensureRoot() {
    if (shadowRoot) {
      return shadowRoot;
    }
    var host = document.createElement("div");
    host.id = "promptshield-overlay-root";
    // The host is a zero-footprint, click-through fixed layer; only the toast
    // inside the shadow root captures pointer events (see CSS below).
    host.style.position = "fixed";
    host.style.zIndex = "2147483647";
    host.style.top = "0";
    host.style.left = "0";
    host.style.width = "0";
    host.style.height = "0";
    host.style.pointerEvents = "none";
    (document.body || document.documentElement).appendChild(host);

    shadowRoot = host.attachShadow({ mode: "open" });
    var style = document.createElement("style");
    style.textContent = [
      ":host { all: initial; }",
      ".ps-stack {",
      "  position: fixed; right: 16px; bottom: 16px;",
      "  display: flex; flex-direction: column; gap: 10px;",
      "  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;",
      "}",
      ".ps-toast {",
      "  pointer-events: auto; box-sizing: border-box;",
      "  width: 340px; max-width: calc(100vw - 32px);",
      "  background: #161b22; color: #e6edf3;",
      "  border: 1px solid #30363d; border-left: 4px solid #f85149;",
      "  border-radius: 10px; padding: 14px 16px;",
      "  box-shadow: 0 8px 28px rgba(0,0,0,0.45);",
      "  animation: ps-in 160ms ease-out;",
      "}",
      "@keyframes ps-in { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }",
      ".ps-head { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }",
      ".ps-title { font-size: 13.5px; font-weight: 600; flex: 1; line-height: 1.3; }",
      ".ps-close {",
      "  pointer-events: auto; cursor: pointer; border: 0; background: transparent;",
      "  color: #8b949e; font-size: 16px; line-height: 1; padding: 2px 4px; border-radius: 6px;",
      "}",
      ".ps-close:hover { color: #e6edf3; background: rgba(255,255,255,0.06); }",
      ".ps-row { font-size: 12.5px; color: #c9d1d9; margin: 2px 0; }",
      ".ps-row b { color: #e6edf3; font-weight: 600; }",
      ".ps-note { font-size: 12px; color: #8b949e; margin-top: 8px; line-height: 1.4; }",
      ".ps-brand { font-size: 10.5px; color: #6e7681; margin-top: 8px; letter-spacing: 0.02em; }",
    ].join("\n");
    shadowRoot.appendChild(style);

    var stack = document.createElement("div");
    stack.className = "ps-stack";
    shadowRoot.appendChild(stack);
    shadowRoot.__stack = stack;
    return shadowRoot;
  }

  function row(label, value) {
    var div = document.createElement("div");
    div.className = "ps-row";
    var b = document.createElement("b");
    b.textContent = value;
    div.appendChild(document.createTextNode(label + ": "));
    div.appendChild(b);
    return div;
  }

  // meta: { provider, reason, rule, action }. All values are PromptShield-supplied
  // category/metadata strings — never raw matched content. We use textContent
  // everywhere, so values can never inject markup.
  function showToast(meta) {
    try {
      var root = ensureRoot();
      var stack = root.__stack;

      var toast = document.createElement("div");
      toast.className = "ps-toast";

      var head = document.createElement("div");
      head.className = "ps-head";
      var title = document.createElement("div");
      title.className = "ps-title";
      title.textContent = "🛡️ PromptShield blocked this prompt";
      var close = document.createElement("button");
      close.className = "ps-close";
      close.setAttribute("aria-label", "Dismiss");
      close.textContent = "×";
      head.appendChild(title);
      head.appendChild(close);
      toast.appendChild(head);

      if (meta.provider) {
        toast.appendChild(row("Provider", meta.provider));
      }
      if (meta.reason || meta.rule) {
        toast.appendChild(row("Reason", meta.reason || meta.rule));
      }
      toast.appendChild(row("Action", meta.action || "blocked"));

      var note = document.createElement("div");
      note.className = "ps-note";
      note.textContent = "The request was not sent to the provider.";
      toast.appendChild(note);

      var brand = document.createElement("div");
      brand.className = "ps-brand";
      brand.textContent = "Blocked locally by PromptShield";
      toast.appendChild(brand);

      var hideTimer = null;
      function dismiss() {
        if (hideTimer) {
          clearTimeout(hideTimer);
          hideTimer = null;
        }
        if (toast.parentNode) {
          toast.parentNode.removeChild(toast);
        }
      }
      close.addEventListener("click", dismiss);
      hideTimer = setTimeout(dismiss, AUTO_HIDE_MS);

      stack.appendChild(toast);
    } catch (e) {
      /* never let UI errors surface to the host app */
    }
  }

  // --- Metadata extraction ---------------------------------------------------
  function metaFromHeaders(getHeader) {
    return {
      provider: getHeader("X-PromptShield-Provider") || "",
      reason: getHeader("X-PromptShield-Reason") || "",
      rule: getHeader("X-PromptShield-Rule") || "",
      action: getHeader("X-PromptShield-Action") || "blocked",
    };
  }

  function metaFromBody(body) {
    // Body JSON is only a fallback when a header is missing.
    return {
      provider: body.provider || "",
      reason: body.reason || "",
      rule: body.rule || "",
      action: body.action || "blocked",
    };
  }

  // --- fetch patch -----------------------------------------------------------
  var origFetch = window.fetch;
  if (typeof origFetch === "function") {
    window.fetch = function () {
      var p = origFetch.apply(this, arguments);
      try {
        return p.then(function (res) {
          try {
            if (res && res.headers && res.headers.get(BLOCKED_HEADER) === "1") {
              var meta = metaFromHeaders(function (h) {
                return res.headers.get(h);
              });
              if (!meta.provider && !meta.reason && !meta.rule) {
                // Header metadata missing — fall back to the JSON body on a clone
                // so the original response stream is left intact for the app.
                res.clone().json().then(function (body) {
                  showToast(metaFromBody(body || {}));
                }, function () {
                  showToast(meta);
                });
              } else {
                showToast(meta);
              }
            }
          } catch (e) {
            /* swallow: never disturb the app's response handling */
          }
          return res; // always return the ORIGINAL response, untouched
        });
      } catch (e) {
        return p;
      }
    };
  }

  // --- XMLHttpRequest patch --------------------------------------------------
  var XHR = window.XMLHttpRequest;
  if (XHR && XHR.prototype) {
    var origOpen = XHR.prototype.open;
    var origSend = XHR.prototype.send;

    XHR.prototype.open = function () {
      try {
        this.__psWatch = true;
      } catch (e) {
        /* ignore */
      }
      return origOpen.apply(this, arguments);
    };

    XHR.prototype.send = function () {
      try {
        if (this.__psWatch && !this.__psHooked) {
          this.__psHooked = true;
          var xhr = this;
          xhr.addEventListener("load", function () {
            try {
              var blocked = xhr.getResponseHeader(BLOCKED_HEADER);
              if (blocked === "1") {
                var meta = metaFromHeaders(function (h) {
                  return xhr.getResponseHeader(h);
                });
                showToast(meta);
              }
            } catch (e) {
              /* ignore */
            }
          });
        }
      } catch (e) {
        /* ignore */
      }
      return origSend.apply(this, arguments);
    };
  }
})();
