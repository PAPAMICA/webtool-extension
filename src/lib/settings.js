/* Shared settings: scan mode + URL blacklist. Stored in browser.storage.local. */
(() => {
  const KEY = "wtSettings";
  const DEFAULTS = Object.freeze({
    autoScan: true,
    blacklist: [],
  });

  let cache = null;
  let cacheAt = 0;
  const CACHE_MS = 2000;

  function normalize(raw) {
    const out = {
      autoScan: raw?.autoScan !== false,
      blacklist: Array.isArray(raw?.blacklist)
        ? [...new Set(raw.blacklist.map((x) => String(x).trim()).filter(Boolean))]
        : [],
    };
    return out;
  }

  async function get() {
    if (cache && Date.now() - cacheAt < CACHE_MS) return cache;
    try {
      const bag = await browser.storage.local.get(KEY);
      cache = normalize(bag[KEY]);
    } catch (e) {
      cache = { ...DEFAULTS, blacklist: [] };
    }
    cacheAt = Date.now();
    return cache;
  }

  async function set(partial) {
    const cur = await get();
    const next = normalize({ ...cur, ...partial });
    await browser.storage.local.set({ [KEY]: next });
    cache = next;
    cacheAt = Date.now();
    return next;
  }

  function invalidate() {
    cache = null;
    cacheAt = 0;
  }

  /**
   * Patterns:
   *   example.com          → host or subdomain
   *   *.example.com        → host or subdomain
   *   example.com/path     → host + path prefix
   *   https://example.com/ → URL prefix
   */
  function isBlacklisted(urlStr, list) {
    if (!urlStr || !list?.length) return false;
    let u;
    try {
      u = new URL(urlStr);
    } catch (e) {
      return false;
    }
    if (u.protocol !== "http:" && u.protocol !== "https:") return false;
    const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    const href = u.href.toLowerCase();
    const hostPath = `${host}${u.pathname}`.toLowerCase();

    for (const raw of list) {
      const p = String(raw).trim().toLowerCase();
      if (!p) continue;

      if (/^https?:\/\//i.test(p)) {
        if (href === p || href.startsWith(p.endsWith("/") ? p : p + "/") || href.startsWith(p)) return true;
        continue;
      }

      if (p.startsWith("*.")) {
        const base = p.slice(2);
        if (host === base || host.endsWith(`.${base}`)) return true;
        continue;
      }

      if (p.includes("/")) {
        const pathPat = p.replace(/^\/*/, "");
        if (hostPath === pathPat || hostPath.startsWith(pathPat.endsWith("/") ? pathPat : pathPat + "/") || hostPath.startsWith(pathPat)) {
          return true;
        }
        continue;
      }

      if (host === p || host.endsWith(`.${p}`)) return true;
    }
    return false;
  }

  if (typeof browser !== "undefined" && browser.storage?.onChanged) {
    browser.storage.onChanged.addListener((changes, area) => {
      if (area === "local" && changes[KEY]) invalidate();
    });
  }

  globalThis.WT_settings = { KEY, DEFAULTS, get, set, invalidate, isBlacklisted, normalize };
})();
