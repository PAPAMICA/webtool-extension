/* Active probes for WordPress / PHP versions when passive signals are insufficient. */
(() => {
  const WP_VER = /^(\d{1,2}\.\d{1,2}(?:\.\d{1,2})?(?:-[a-zA-Z][\w.-]*)?)$/;
  const PHP_VER = /\bPHP[\/ ]+v?(\d+\.\d+(?:\.\d+)?)/i;
  const PHP_BARE = /^(\d+\.\d+(?:\.\d+)?)$/;
  const PHP_HEADER_NAMES = ["x-powered-by", "server", "x-php-version", "x-powered-php", "php-version"];

  function okWp(v) {
    if (!v) return null;
    v = String(v).trim().replace(/^v/i, "");
    return WP_VER.test(v) ? v : null;
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
        headers: { Accept: "application/rss+xml, application/atom+xml, text/xml, text/html;q=0.9,*/*;q=0.8" },
      });
      const text = method === "HEAD" ? "" : await r.text();
      return { ok: r.ok || r.status === 405, status: r.status, headers: r.headers, text: text.slice(0, 120000), url: r.url };
    } catch (e) {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  function parseWpFromFeed(body) {
    if (!body) return null;
    /* <generator>https://wordpress.org/?v=6.9.10</generator> */
    let m = /wordpress\.org\/\?v=([\w.-]+)/i.exec(body);
    if (m) return okWp(m[1]);
    m = /<[a-z0-9:]*generator[^>]*>\s*(?:<!\[CDATA\[)?\s*WordPress\s+([\w.-]+)/i.exec(body);
    if (m) return okWp(m[1]);
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
      const root = `${base.origin}/`;
      push(`${base.origin}/feed/`);
      push(`${base.origin}/feed/rss/`);
      push(`${base.origin}/feed/atom/`);
      push(`${base.origin}/index.php/feed/`);
      push(`${base.origin}/?feed=rss2`);
      /* subdirectory installs: /blog/feed/ */
      const parts = base.pathname.split("/").filter(Boolean);
      if (parts.length) {
        push(`${base.origin}/${parts[0]}/feed/`);
        push(`${root}${parts.slice(0, -1).join("/")}/feed/`.replace(/([^:]\/)\/+/g, "$1"));
      }
    } catch (e) {}
    return out.slice(0, 6);
  }

  async function probeWordPressVersion(pageUrl, { feeds = [], html = "" } = {}) {
    const fromHtml = parseWpFromFeed(html);
    if (fromHtml) return { version: fromHtml, via: "html" };

    for (const feed of feedCandidates(pageUrl, feeds)) {
      const res = await fetchText(feed, { timeout: 4500 });
      if (!res?.text) continue;
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
      out.push(`${origin}/index.php`);
      const parts = base.pathname.split("/").filter(Boolean);
      if (parts.length) out.push(`${origin}/${parts[0]}/wp-login.php`);
      if (/\.php(?:$|\?)/i.test(base.pathname)) out.unshift(base.href);
    } catch (e) {}
    return [...new Set(out)].slice(0, 5);
  }

  async function probePhpVersion(pageUrl, existingHeaders) {
    const fromExisting = phpFromHeaders(existingHeaders);
    if (fromExisting) return { version: fromExisting, via: "header" };

    for (const path of phpPaths(pageUrl)) {
      /* Prefer GET: some stacks omit X-Powered-By on HEAD. */
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
