/**
 * Minimal Browser API Polyfill
 * Ensures `chrome.*` APIs work seamlessly across Chrome and Firefox.
 * Firefox provides the `browser.*` namespace natively but also supports `chrome.*`
 * for compatibility. This polyfill normalises minor edge-case differences.
 */
(function () {
  'use strict';

  // Detect which browser we're running in
  const isFirefox = typeof browser !== 'undefined' && typeof browser.runtime !== 'undefined';
  const isChrome  = typeof chrome  !== 'undefined' && typeof chrome.runtime  !== 'undefined';

  // If neither is available, bail out (shouldn't happen inside an extension context)
  if (!isFirefox && !isChrome) return;

  // Firefox already maps `chrome.*` → `browser.*` for most APIs in MV3.
  // However, `browser.*` uses Promises while `chrome.*` uses callbacks.
  // Since the codebase is written with the `chrome.*` callback pattern,
  // we only patch when Firefox's `chrome.*` shim is incomplete or missing.

  if (isFirefox && typeof globalThis.chrome === 'undefined') {
    // Very rare edge-case: globalThis.chrome not defined
    globalThis.chrome = browser;
  }

  // Expose a helper so JS files can query the runtime:
  //   if (MagicFill.isFirefox) { ... }
  globalThis.MagicFill = globalThis.MagicFill || {};
  globalThis.MagicFill.isFirefox = isFirefox;
  globalThis.MagicFill.isChrome  = !isFirefox && isChrome;

  // Firefox MV3 fully supports chrome.storage.session,
  // but in some older builds it may require explicit setAccessLevel call.
  // We handle this gracefully by wrapping session calls.
  if (isFirefox && chrome.storage && chrome.storage.session) {
    try {
      // Ensure session storage is accessible to content scripts too
      chrome.storage.session.setAccessLevel?.({
        accessLevel: 'TRUSTED_AND_UNTRUSTED_CONTEXTS'
      });
    } catch (_) {
      // Silently ignore if setAccessLevel is not available
    }
  }
})();
