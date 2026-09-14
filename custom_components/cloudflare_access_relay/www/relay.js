/*
 * Cloudflare Access relay: frontend module.
 *
 * Loaded into the Home Assistant frontend by the integration. Inside the
 * companion app it asks the server how long the app's Access cookie is still
 * valid and, when there is none or it is about to expire, sends the WebView to
 * the connect page. In a plain browser it does nothing: Access renews the
 * browser's own cookie by itself.
 */
(() => {
  "use strict";

  const SESSION_API = "cloudflare_access_relay/session";
  const CONNECT_URL = "/cloudflare_access_relay/connect";
  const SNOOZE_KEY = "cloudflare_access_relay_snooze_until";
  const BANNER_ID = "cloudflare-access-relay-banner";

  const inApp = () =>
    !!(
      window.externalApp ||
      (window.webkit &&
        window.webkit.messageHandlers &&
        window.webkit.messageHandlers.getExternalAuth)
    );

  const storage = {
    get(key) {
      try {
        return window.localStorage.getItem(key);
      } catch (_e) {
        return null;
      }
    },
    set(key, value) {
      try {
        window.localStorage.setItem(key, value);
      } catch (_e) {
        /* private mode etc. */
      }
    },
  };

  const snoozed = () => Number(storage.get(SNOOZE_KEY) || 0) > Date.now();
  const snooze = (ms) => storage.set(SNOOZE_KEY, String(Date.now() + ms));

  async function getHass(timeoutMs = 60000) {
    await customElements.whenDefined("home-assistant");
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const el = document.querySelector("home-assistant");
      if (el && el.hass && el.hass.connection) return el.hass;
      await new Promise((r) => setTimeout(r, 500));
    }
    return null;
  }

  function removeBanner() {
    const old = document.getElementById(BANNER_ID);
    if (old) old.remove();
  }

  function showBanner(res) {
    removeBanner();
    const bar = document.createElement("div");
    bar.id = BANNER_ID;
    bar.setAttribute("role", "status");
    bar.style.cssText =
      "position:fixed;left:0;right:0;bottom:0;z-index:2147483000;" +
      "background:#1c2126;color:#fff;padding:12px 16px;font:14px system-ui,sans-serif;" +
      "display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center;" +
      "box-shadow:0 -1px 4px rgba(0,0,0,.3)";
    const text = document.createElement("span");
    text.style.flex = "1 1 200px";
    text.textContent =
      res.exp === null
        ? "This app has no Cloudflare Access session yet."
        : "The app's Cloudflare Access session expires on " +
          new Date(res.exp * 1000).toLocaleString() +
          ".";
    const connect = document.createElement("a");
    connect.href = CONNECT_URL;
    connect.textContent = "Connect";
    connect.style.cssText =
      "background:#03a9f4;color:#fff;padding:8px 14px;border-radius:6px;" +
      "text-decoration:none;font-weight:600";
    const later = document.createElement("button");
    later.type = "button";
    later.textContent = "Later";
    later.style.cssText =
      "background:transparent;color:#fff;border:1px solid #888;padding:8px 12px;border-radius:6px";
    later.addEventListener("click", () => {
      snooze(6 * 3600 * 1000);
      removeBanner();
    });
    bar.append(text, connect, later);
    document.body.appendChild(bar);
  }

  async function check() {
    const hass = await getHass();
    if (!hass) return 15 * 60 * 1000;
    let res;
    try {
      res = await hass.callApi("GET", SESSION_API + "?app=" + (inApp() ? "1" : "0"));
    } catch (err) {
      console.warn("[cloudflare_access_relay] session check failed", err);
      return 15 * 60 * 1000;
    }
    const interval = Math.max(1, Number(res.check_interval_min) || 60) * 60 * 1000;
    if (!inApp() || !res.cloudflare || !res.host_match) {
      removeBanner();
      return interval;
    }
    if (res.exp === null) {
      if (!snoozed()) {
        window.location.assign(res.connect_url || CONNECT_URL);
        return interval;
      }
      showBanner(res);
    } else if (res.renew) {
      if (!snoozed()) showBanner(res);
    } else {
      removeBanner();
    }
    return interval;
  }

  async function loop() {
    let delay = 60 * 60 * 1000;
    try {
      delay = await check();
    } catch (err) {
      console.warn("[cloudflare_access_relay] check failed", err);
    }
    setTimeout(loop, delay);
  }

  window.cloudflareAccessRelay = { check, inApp };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => loop(), { once: true });
  } else {
    loop();
  }
})();
