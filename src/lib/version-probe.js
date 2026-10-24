/* Active probes for WordPress / PHP versions when passive signals are insufficient. */
(() => {
  /* WP core: 3.0 – 9.x (semver-ish). Reject hashes, build ids, lib versions (e.g. jQuery 3.7.1 alone is OK shape but major check helps). */
  const WP_VER = /^(\d{1,2})\.(\d{1,2})(?:\.(\d{1,2}))?(?:-[a-zA-Z][\w.-]*)?$/;
  const PHP_VER = /\bPHP[\/ ]+v?(\d+\.\d+(?:\.\d+)?)/i;
  const PHP_BARE = /^(\d+\.\d+(?:\.\d+)?)$/;
  const PHP_HEADER_NAMES = ["x-powered-by", "server", "x-php-version", "x-powered-php", "php-version"];

  function okWp(v) {
    if (!v) return null;
    v = String(v).trim().replace(/^v/i, "");
    const m = WP_VER.exec(v);
    if (!m) return null;
    const major = Number(m[1]);
    if (major < 3 || major > 9) return null;
    if (/^[0-9a-f]{8,}$/i.test(v) || /^\d{4,}$/.test(v)) return null;
    return v;
  }

  function okPhp(v) {
    if (!v) return null;
    v = String(v).trim().replace(/^v/i, "");
    return /^\d+\.\d+(?:\.\d+)?$/.test(v) ? v : null;
  }

  function phpFromHeaders(headers) {
    if (!headers) return null;
    const get = (k) => {
      if (typeof headers.get === "function") return headers.get(k);
      return headers[k] || headers[k.toLowerCase()];
    };
    for (const name of PHP_HEADER_NAMES) {
      const value = get(name);
      if (!value) continue;
      const m = PHP_VER.exec(value);
      if (m) return okPhp(m[1]);
      if (/php-version|x-php-version|x-powered-php/i.test(name)) {
        const b = PHP_BARE.exec(String(value).trim());
        if (b) return okPhp(b[1]);
      }
    }
    return null;
  }

  async function fetchText(url, { timeout = 5000, method = "GET" } = {}) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeout);
    try {
      const r = await fetch(url, {
        method,
        signal: ctrl.signal,
        credentials: "omit",
        redirect: "follow",
        headers: { Accept: "application/rss+xml, application/atom+xml, text/xml, text/html;q=0.8,*/*;q=0.5" },
      });
      const text = method === "HEAD" ? "" : await r.text();
      return { ok: r.ok || r.status === 405, status: r.status, headers: r.headers, text: text.slice(0, 120000), url: r.url };
    } catch (e) {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  /** Only authoritative generator forms — never a loose number from the feed body. */
  function parseWpFromFeed(body) {
    if (!body) return null;
    let m = /<([a-z0-9:]*generator)[^>]*>\s*(?:<!\[CDATA\[\s*)?https?:\/\/wordpress\.org\/\?v=([\w.-]+)\s*(?:\]\]>)?\s*<\/\1>/i.exec(body);
    if (m) return okWp(m[2]);
    m = /<([a-z0-9:]*generator)[^>]*>\s*(?:<!\[CDATA\[\s*)?WordPress\s+([\w.-]+)\s*(?:\]\]>)?\s*<\/\1>/i.exec(body);
    if (m) return okWp(m[2]);
    return null;
  }

  function feedCandidates(pageUrl, feeds = []) {
    const out = [];
    const seen = new Set();
    const push = (u) => {
      try {
        const abs = new URL(u, pageUrl).href;
        if (seen.has(abs)) return;
        seen.add(abs);
        out.push(abs);
      } catch (e) {}
    };
    for (const f of feeds || []) push(f);
    try {
      const base = new URL(pageUrl);
      push(`${base.origin}/feed/`);
      push(`${base.origin}/?feed=rss2`);
      push(`${base.origin}/feed/atom/`);
      const parts = base.pathname.split("/").filter(Boolean);
      if (parts.length) push(`${base.origin}/${parts[0]}/feed/`);
    } catch (e) {}
    return out.slice(0, 4);
  }

  async function probeWordPressVersion(pageUrl, { feeds = [], html = "" } = {}) {
    const fromHtml = parseWpFromFeed(html);
    if (fromHtml) return { version: fromHtml, via: "feed" };

    for (const feed of feedCandidates(pageUrl, feeds)) {
      const res = await fetchText(feed, { timeout: 4000 });
      if (!res?.ok || !res.text) continue;
      /* Ignore HTML soft-404 / homepage mistaken for a feed. */
      if (!/<rss\b|<feed\b|wordpress\.org\/\?v=/i.test(res.text)) continue;
      const version = parseWpFromFeed(res.text);
      if (version) return { version, via: "feed", feed: res.url };
    }
    return null;
  }

  function phpPaths(pageUrl) {
    const out = [];
    try {
      const base = new URL(pageUrl);
      const origin = base.origin;
      out.push(`${origin}/wp-login.php`);
      out.push(`${origin}/wp-cron.php`);
      out.push(`${origin}/xmlrpc.php`);
      const parts = base.pathname.split("/").filter(Boolean);
      if (parts.length) out.push(`${origin}/${parts[0]}/wp-login.php`);
    } catch (e) {}
    return [...new Set(out)].slice(0, 4);
  }

  async function probePhpVersion(pageUrl, existingHeaders) {
    const fromExisting = phpFromHeaders(existingHeaders);
    if (fromExisting) return { version: fromExisting, via: "header" };

    for (const path of phpPaths(pageUrl)) {
      const res = await fetchText(path, { timeout: 4000, method: "GET" });
      if (!res) continue;
      const version = phpFromHeaders(res.headers);
      if (version) return { version, via: "probe", path: res.url };
    }
    return null;
  }

  globalThis.WT_versionProbe = {
    probeWordPressVersion,
    probePhpVersion,
    okWp,
    okPhp,
    phpFromHeaders,
  };
})();
