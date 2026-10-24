(() => {
  const PRIO = { js: 4, meta: 4, header: 4, cdn: 3, file: 3, html: 2, script: 2, cookie: 1, url: 1, "?ver": 1, certificate: 1 };

  const CDN_RES = [
    /cdnjs\.cloudflare\.com\/ajax\/libs\/([^/]+)\/([^/]+)\//,
    /cdn\.jsdelivr\.net\/npm\/((?:@[^/@]+\/)?[^/@]+)@([^/]+)/,
    /cdn\.jsdelivr\.net\/gh\/[^/]+\/([^/@]+)@([^/]+)/,
    /unpkg\.com\/((?:@[^/@]+\/)?[^/@]+)@([^/]+)/,
    /esm\.sh\/(?:v\d+\/)?((?:@[^/@]+\/)?[^/@]+)@([^/?&]+)/,
    /cdn\.skypack\.dev\/((?:@[^/@]+\/)?[^/@]+)@([^/?&]+)/,
    /ajax\.googleapis\.com\/ajax\/libs\/([^/]+)\/([^/]+)\//,
    /(?:stackpath|maxcdn|netdna)\.bootstrapcdn\.com\/([^/]+)\/v?([^/]+)\//,
    /code\.jquery\.com\/(jquery)-([\d.]+\d)/,
  ];
  const FILE_RE = /\/([a-z][a-z0-9_.-]*?)[.-]v?(\d+\.\d+(?:\.\d+)?(?:-(?:alpha|beta|rc)\.?\d*)?)(?:[.-](?:min|slim|bundle|umd|esm|prod|production|full|pack|all))*\.(?:m?js|css)(?:[?#]|$)/i;
  const QUERY_RE = /\/([a-z][a-z0-9_.-]*?)(?:[.-](?:min|slim|bundle|umd|esm|prod|production|full|pack|all))*\.(?:m?js|css)\?(?:[^#]*&)?(?:ver|v|version)=v?(\d+(?:\.\d+)+)/i;
  const WP_RE = /\/wp-content\/(plugins|themes|mu-plugins)\/([A-Za-z0-9_.-]+)\/[^?#]*(?:\?(?:[^#]*&)?ver=([\w.-]+))?/;
  const NO_ALIAS_CATS = new Set(["lang", "server", "proxy", "cdn", "paas", "os", "db", "ca", "panel", "security", "cms", "headless", "ecommerce", "ssg", "wpplugin", "wptheme"]);
  const GENERIC_HEADERS = { server: "server", "x-powered-by": "webfw", "x-generator": "cms", "x-server": "server" };
  /* Cache-busting hashes / build ids mistaken for versions (66c613f…, 4716, 20240101). */
  const HASHISH = /^(?:[0-9a-f]{8,}|[0-9]{2,}[a-f][0-9a-f]+)$/i;
  const SEMVERISH = /^\d+\.\d+/; /* real lib/CMS versions almost always have major.minor */
  /* Core WP only: 3.x–9.x. Plugins may use the same shape via cleanPluginVer. */
  const WP_CORE_VER = /^(\d{1,2})\.(\d{1,2})(?:\.(\d{1,2}))?(?:-[a-zA-Z][\w.-]*)?$/;

  function cleanVersion(v) {
    if (v == null) return null;
    v = String(v).trim().replace(/^v/i, "");
    if (!/^\d/.test(v) || v.length > 32 || !/^[\w.+-]+$/.test(v)) return null;
    if (/^\d{4,}$/.test(v) || /^\d{8,}/.test(v) || HASHISH.test(v)) return null;
    return v;
  }

  function okWpCore(v) {
    v = cleanVersion(v);
    if (!v) return null;
    const m = WP_CORE_VER.exec(v);
    if (!m) return null;
    const major = Number(m[1]);
    if (major < 3 || major > 9) return null;
    return v;
  }

  /** Plugin/theme ?ver= — semver-ish, not a hash. */
  function cleanWpVer(v) {
    v = cleanVersion(v);
    return v && SEMVERISH.test(v) ? v : null;
  }

  function norm(p) {
    if (p && typeof p === "object" && !(p instanceof RegExp)) return { re: p.v ?? null, c: p.c ?? 100, fixed: p.version ?? null };
    return { re: p ?? null, c: 100, fixed: null };
  }

  function test(p, value) {
    if (value == null) return null;
    const n = norm(p);
    if (n.re == null || n.re === "") return { version: n.fixed, c: n.c, raw: !!n.fixed };
    if (!(n.re instanceof RegExp)) return null;
    const m = n.re.exec(String(value));
    return m ? { version: n.fixed || m[1] || null, c: n.c, raw: !!n.fixed } : null;
  }

  function asList(v) {
    if (v == null) return [];
    return Array.isArray(v) ? v : [v];
  }

  let IDX = null;
  function index() {
    if (IDX) return IDX;
    const { technologies, wpSlugs = {} } = globalThis.WT_DB;
    const pkg = new Map();
    const headerPatterns = {};
    const metaGenerators = [];
    for (const [name, t] of Object.entries(technologies)) {
      for (const p of t.npm || []) pkg.set(p.toLowerCase(), name);
      if (!NO_ALIAS_CATS.has(t.cat)) {
        const alias = name.toLowerCase().replace(/\s+/g, "-");
        if (!pkg.has(alias)) pkg.set(alias, name);
      }
      for (const [h, p] of Object.entries(t.headers || {})) (headerPatterns[h] ||= []).push(p);
      if (t.meta?.generator) metaGenerators.push(t.meta.generator);
    }
    const lowerNames = new Map(Object.keys(technologies).map((n) => [n.toLowerCase(), n]));
    IDX = { pkg, headerPatterns, metaGenerators, lowerNames, wpSlugs };
    return IDX;
  }

  const prettify = (slug) =>
    slug.replace(/[-_]+/g, " ").replace(/\b([a-z])/g, (c) => c.toUpperCase()).trim();

  /**
   * @param {object} s collected signals
   *   headers : { name: value }        cookies : { name: value }
   *   meta    : { name: [values] }     js      : { key: value|"" }
   *   dom     : { selector: true }     src     : [urls]
   *   html    : string                 url     : string
   *   certIssuer : string
   */
  function detect(s) {
    const { technologies, categories } = globalThis.WT_DB;
    const idx = index();
    const headers = s.headers && typeof s.headers === "object" ? s.headers : {};
    const cookies = s.cookies && typeof s.cookies === "object" ? s.cookies : {};
    const meta = s.meta && typeof s.meta === "object" && !Array.isArray(s.meta) ? s.meta : {};
    const js = s.js && typeof s.js === "object" && !Array.isArray(s.js) ? s.js : {};
    const dom = s.dom && typeof s.dom === "object" && !Array.isArray(s.dom) ? s.dom : {};
    const src = Array.isArray(s.src) ? s.src : [];
    const html = typeof s.html === "string" ? s.html : "";
    const url = typeof s.url === "string" ? s.url : "";
    const cookieNames = Object.keys(cookies);
    const found = new Map();

    const add = (name, version, via, conf = 100, extra, raw = false) => {
      version = raw ? version : cleanVersion(version);
      /* WordPress core version is never taken from generic signature hits. */
      if (name === "WordPress") version = null;
      /* Non-semver labels (UA, GA4, …) are tags, not version numbers. */
      if (version && !SEMVERISH.test(version) && !/^\d{1,3}$/.test(version)) {
        extra = { ...(extra || {}), tag: version };
        version = null;
      }
      const prio = PRIO[via] || 1;
      let f = found.get(name);
      if (!f) {
        f = { name, version: null, vprio: 0, via: [], confidence: 0, ...extra };
        found.set(name, f);
      }
      f.confidence = Math.min(100, f.confidence + conf);
      if (!f.via.includes(via)) f.via.push(via);
      if (extra?.tag && !f.tag) f.tag = extra.tag;
      if (version) {
        const better =
          prio > f.vprio ||
          (prio === f.vprio && f.version && version.startsWith(f.version) && version.length > f.version.length);
        if (!f.version || better) {
          f.version = version;
          f.vprio = prio;
        }
      }
    };

    // ── Signatures ──
    for (const [name, t] of Object.entries(technologies)) {
      if (t.headers) {
        for (const [h, p] of Object.entries(t.headers)) {
          const r = test(p, headers[h]);
          if (r) add(name, r.version, "header", r.c, undefined, r.raw);
        }
      }
      if (t.cookies) {
        for (const [c, p] of Object.entries(t.cookies)) {
          const names = c.endsWith("*")
            ? cookieNames.filter((n) => n.startsWith(c.slice(0, -1)))
            : c in cookies ? [c] : [];
          for (const n of names) {
            const r = test(p, cookies[n]);
            if (r) { add(name, r.version, "cookie", r.c, undefined, r.raw); break; }
          }
        }
      }
      if (t.meta) {
        for (const [k, p] of Object.entries(t.meta)) {
          for (const v of asList(meta[k])) {
            if (typeof v !== "string") continue;
            const r = test(p, v);
            if (r) add(name, r.version, "meta", r.c, undefined, r.raw);
          }
        }
      }
      if (t.js) {
        for (const [k, p] of Object.entries(t.js)) {
          if (!(k in js)) continue;
          const n = norm(p);
          const m = n.re instanceof RegExp ? n.re.exec(js[k]) : null;
          add(name, n.fixed || (m && m[1]) || null, "js", n.c, undefined, !!n.fixed);
        }
      }
      if (t.dom) {
        for (const d of asList(t.dom)) {
          const n = norm(d);
          if (n.re && dom[n.re]) add(name, null, "dom", n.c);
        }
      }
      if (t.src) {
        for (const p of asList(t.src)) {
          for (const u of src) {
            const r = test(p, u);
            if (r) { add(name, r.version, "script", r.c, undefined, r.raw); break; }
          }
        }
      }
      if (t.html && html) {
        for (const p of asList(t.html)) {
          const r = test(p, html);
          if (r) add(name, r.version, "html", r.c, undefined, r.raw);
        }
      }
      if (t.url) {
        const r = test(t.url, url);
        if (r) add(name, r.version, "url", r.c, undefined, r.raw);
      }
      if (t.certIssuer && s.certIssuer) {
        const r = test(t.certIssuer, s.certIssuer);
        if (r) add(name, null, "certificate", r.c);
      }
    }

    // ── Versions and libraries from URLs (CDN, filenames, ?ver=) ──
    const wpAssets = new Map();
    for (const u of src) {
      let hit = false;
      for (const re of CDN_RES) {
        const m = re.exec(u);
        if (!m) continue;
        const name = idx.pkg.get(m[1].toLowerCase());
        if (name) { add(name, m[2], "cdn"); hit = true; }
        break;
      }
      if (!hit) {
        const m = FILE_RE.exec(u);
        const name = m && idx.pkg.get(m[1].toLowerCase());
        if (name) { add(name, m[2], "file"); hit = true; }
      }
      if (!hit) {
        const m = QUERY_RE.exec(u);
        const name = m && idx.pkg.get(m[1].toLowerCase());
        if (name && found.has(name)) add(name, m[2], "?ver", 0);
      }
      const wp = WP_RE.exec(u);
      if (wp) {
        const key = `${wp[1] === "themes" ? "theme" : "plugin"}:${wp[2]}`;
        if (!wpAssets.has(key)) wpAssets.set(key, new Map());
        const ver = cleanWpVer(wp[3]);
        if (ver) {
          const counts = wpAssets.get(key);
          counts.set(ver, (counts.get(ver) || 0) + 1);
        } else if (!wpAssets.get(key).size) {
          /* ensure the plugin/theme is still recorded even without a usable version */
          wpAssets.get(key);
        }
      }
    }

    // ── WordPress plugins and themes ──
    if (wpAssets.size) {
      const wpVersion = found.get("WordPress")?.version;
      for (const [key, counts] of wpAssets) {
        const [kind, slug] = key.split(":");
        let version = [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || null;
        if (version && (version === wpVersion || !cleanWpVer(version))) version = null;
        const display = idx.wpSlugs[slug] || prettify(slug);
        if (technologies[display]) {
          add(display, version, "script");
        } else {
          add(display, version, "script", 100, {
            cat: kind === "theme" ? "wptheme" : "wpplugin",
            website: `https://wordpress.org/${kind === "theme" ? "themes" : "plugins"}/${slug.toLowerCase()}/`,
            generic: true,
          });
        }
      }
    }

    // ── Unrecognized headers and meta generator ──
    const known = (name) => found.has(name) || idx.lowerNames.has(name.toLowerCase()) && found.has(idx.lowerNames.get(name.toLowerCase()));
    for (const [h, cat] of Object.entries(GENERIC_HEADERS)) {
      const value = headers[h];
      if (!value) continue;
      const tokens = h === "server" && value.includes("/")
        ? value.replace(/\([^)]*\)/g, " ").split(/\s+/)
        : value.split(/\s*[,\n]\s*/);
      for (let tok of tokens) {
        tok = tok.replace(/<[^>]*>|https?:\/\/\S+/g, "").trim();
        if (!tok || tok.length < 2 || tok.length > 50) continue;
        if ((idx.headerPatterns[h] || []).some((p) => test(p, tok))) continue;
        const m = /^(.+?)(?:[\/ ]v?(\d[\w.-]*))?$/.exec(tok.trim());
        if (!m || /^\d/.test(m[1]) || known(m[1])) continue;
        add(m[1], m[2], "header", 100, { cat, generic: true });
      }
    }
    for (const v of asList(meta.generator)) {
      if (typeof v !== "string" || v.length > 60 || idx.metaGenerators.some((p) => test(p, v))) continue;
      const m = /^(.+?)(?:\s+v?(\d[\w.-]*))?$/.exec(v.trim());
      if (!m || known(m[1])) continue;
      add(m[1], m[2], "meta", 100, { cat: "misc", generic: true });
    }

    // ── Implications ──
    const queue = [...found.keys()];
    while (queue.length) {
      const n = queue.shift();
      const parent = found.get(n);
      for (const imp of asList(technologies[n]?.implies)) {
        if (typeof imp !== "string" || !imp) continue;
        const existing = found.get(imp);
        if (existing) {
          if (existing.confidence < parent.confidence) {
            existing.confidence = parent.confidence;
            if (!existing.via.includes("implied")) existing.via.push("implied");
            queue.push(imp);
          }
          continue;
        }
        found.set(imp, { name: imp, version: null, via: ["implied"], confidence: parent.confidence, implied: true, impliedBy: n });
        queue.push(imp);
      }
    }

    enrichWordpressVersion(found, src, html, meta);
    enrichPhpVersion(found, headers, html);

    const order = Object.keys(categories);
    return [...found.values()]
      .filter((f) => f.confidence >= 25)
      .map((f) => {
        const t = technologies[f.name] || {};
        const cat = f.cat || t.cat || "misc";
        const { vprio, ...rest } = f;
        return {
          ...rest,
          cat,
          catLabel: categories[cat]?.[0] || cat,
          color: categories[cat]?.[1] || "#9ca3af",
          website: f.website || t.w || null,
        };
      })
      .sort((a, b) => order.indexOf(a.cat) - order.indexOf(b.cat) || a.name.localeCompare(b.name));
  }

  /**
   * WordPress core version — conservative.
   * Accept only:
   *   A) meta generator "WordPress X.Y.Z"
   *   B) RSS/Atom generator https://wordpress.org/?v=X.Y.Z (in page HTML if present)
   *   C) ≥2 distinct whitelisted /wp-includes/ core assets agreeing on the same ?ver=
   * Otherwise leave version empty (never guess from a single ?ver= / jQuery / plugin).
   */
  const WP_META_VER = /<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s+([\w.-]+)["']/i;
  const WP_META_VER_REV = /<meta[^>]+content=["']WordPress\s+([\w.-]+)["'][^>]+name=["']generator["']/i;
  const WP_GENERATOR_URL = /<(?:[a-z0-9:]*)generator[^>]*>\s*(?:<!\[CDATA\[\s*)?https?:\/\/wordpress\.org\/\?v=([\w.-]+)/i;
  const WP_GENERATOR_NAME = /<(?:[a-z0-9:]*)generator[^>]*>\s*(?:<!\[CDATA\[\s*)?WordPress\s+([\w.-]+)/i;
  /* Filenames that always ship with $wp_version — NOT jquery/tinymce/vendor libs. */
  const WP_CORE_ASSET =
    /\/wp-includes\/(?:js\/(?:wp-emoji-release|comment-reply|wp-embed|wp-util|wp-a11y|hoverintent-js|zxcvbn(?:-async)?)|css\/(?:dashicons|admin-bar|buttons|editor|jquery-ui-dialog|wp-auth-check)|css\/dist\/block-library\/style)(?:\.min)?\.(?:js|css)\?ver=([\w.-]+)/gi;

  function enrichWordpressVersion(found, src, html, meta) {
    if (!found.has("WordPress")) return;
    const wp = found.get("WordPress");
    wp.version = null;

    const set = (raw, via) => {
      const v = okWpCore(raw);
      if (!v) return false;
      wp.version = v;
      wp.vprio = Math.max(wp.vprio || 0, PRIO[via] || 1);
      if (!wp.via.includes(via)) wp.via.push(via);
      return true;
    };

    for (const g of asList(meta?.generator)) {
      if (typeof g !== "string") continue;
      const m = /^WordPress\s+([\w.-]+)/i.exec(g.trim());
      if (m && set(m[1], "meta")) return;
    }

    if (html) {
      for (const re of [WP_META_VER, WP_META_VER_REV, WP_GENERATOR_URL, WP_GENERATOR_NAME]) {
        const m = re.exec(html);
        if (m && set(m[1], "html")) return;
      }
    }

    /* Consensus across distinct core asset paths (path → version). */
    const byPath = new Map();
    const scan = (text) => {
      if (!text) return;
      WP_CORE_ASSET.lastIndex = 0;
      let m;
      while ((m = WP_CORE_ASSET.exec(text))) {
        const v = okWpCore(m[1]);
        if (!v) continue;
        const path = m[0].split("?")[0].replace(/^https?:\/\/[^/]+/i, "");
        byPath.set(path, v);
      }
    };
    for (const u of src || []) scan(u);
    scan(html);

    if (byPath.size < 2) return;
    const tallies = new Map();
    for (const v of byPath.values()) tallies.set(v, (tallies.get(v) || 0) + 1);
    const ranked = [...tallies.entries()].sort((a, b) => b[1] - a[1] || b[0].length - a[0].length);
    const [best, n] = ranked[0];
    /* Require at least 2 assets on the winning version; no ties. */
    if (n >= 2 && (ranked.length === 1 || ranked[1][1] < n)) set(best, "script");
  }

  /**
   * Pull a PHP version from every available signal.
   * Many hosts put it in Server / X-Powered-By / custom headers; CMS stacks often
   * only imply PHP with no version — this pass fills the gap when the server leaks it.
   */
  const PHP_VER = /\bPHP[\/ ]+v?(\d+\.\d+(?:\.\d+)?)/gi;
  const PHP_HEADER_KEYS = /^(?:x-powered-by|server|x-php-version|x-powered-php|php-version|x-cf-powered-by|x-generator|x-runtime|via)$/i;
  const PHP_BARE = /^(\d+\.\d+(?:\.\d+)?)$/;

  function betterPhpVersion(a, b) {
    if (!a) return b;
    if (!b) return a;
    if (b.startsWith(a + ".") || (b.startsWith(a) && b.length > a.length)) return b;
    if (a.startsWith(b + ".") || (a.startsWith(b) && a.length > b.length)) return a;
    const sa = a.split(".").length;
    const sb = b.split(".").length;
    if (sb !== sa) return sb > sa ? b : a;
    return a;
  }

  function enrichPhpVersion(found, headers, html) {
    let version = found.get("PHP")?.version || null;
    let via = null;

    for (const [name, value] of Object.entries(headers || {})) {
      if (value == null || value === "") continue;
      const text = String(value);
      if (PHP_HEADER_KEYS.test(name) || /php/i.test(text) || /php/i.test(name)) {
        PHP_VER.lastIndex = 0;
        let m;
        while ((m = PHP_VER.exec(text))) {
          const v = cleanVersion(m[1]);
          if (!v) continue;
          const next = betterPhpVersion(version, v);
          if (next !== version) {
            version = next;
            via = "header";
          }
        }
        if (/^(?:x-php-version|x-powered-php|php-version)$/i.test(name)) {
          const bare = PHP_BARE.exec(text.trim());
          if (bare) {
            const v = cleanVersion(bare[1]);
            const next = betterPhpVersion(version, v);
            if (next !== version) {
              version = next;
              via = "header";
            }
          }
        }
      }
    }

    if (html) {
      PHP_VER.lastIndex = 0;
      let m;
      while ((m = PHP_VER.exec(html.slice(0, 200000)))) {
        const v = cleanVersion(m[1]);
        if (!v) continue;
        const next = betterPhpVersion(version, v);
        if (next !== version) {
          version = next;
          via = via || "html";
        }
      }
    }

    if (!version && !found.has("PHP")) return;

    if (!found.has("PHP")) {
      found.set("PHP", { name: "PHP", version, via: [via || "header"], confidence: 100, vprio: PRIO[via] || 4 });
      return;
    }

    const php = found.get("PHP");
    if (version && (!php.version || betterPhpVersion(php.version, version) === version)) {
      php.version = version;
      php.vprio = Math.max(php.vprio || 0, PRIO[via] || 4);
      if (via && !php.via.includes(via)) php.via.push(via);
    }
  }

  globalThis.WT_detect = detect;
})();
