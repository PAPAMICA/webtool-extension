(() => {
  const PRIO = { js: 4, meta: 4, "en-tête": 4, cdn: 3, fichier: 3, html: 2, script: 2, cookie: 1, url: 1, "?ver": 1, certificat: 1 };

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
  const NO_ALIAS_CATS = new Set(["lang", "server", "proxy", "cdn", "paas", "os", "db", "ca", "panel", "security"]);
  const GENERIC_HEADERS = { server: "server", "x-powered-by": "webfw", "x-generator": "cms", "x-server": "server" };

  function cleanVersion(v) {
    if (v == null) return null;
    v = String(v).trim().replace(/^v/i, "");
    if (!/^\d/.test(v) || v.length > 24 || !/^[\w.+-]+$/.test(v)) return null;
    if (/^\d{5,}$/.test(v) || /^\d{8,}/.test(v)) return null;
    return v;
  }

  function norm(p) {
    if (p && typeof p === "object" && !(p instanceof RegExp)) return { re: p.v ?? null, c: p.c ?? 100, fixed: p.version ?? null };
    return { re: p ?? null, c: 100, fixed: null };
  }

  function test(p, value) {
    if (value == null) return null;
    const n = norm(p);
    if (n.re == null || n.re === "") return { version: n.fixed, c: n.c, raw: !!n.fixed };
    const m = n.re.exec(String(value));
    return m ? { version: n.fixed || m[1] || null, c: n.c, raw: !!n.fixed } : null;
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
   * @param {object} s signaux collectés
   *   headers : { nom: valeur }        cookies : { nom: valeur }
   *   meta    : { nom: [valeurs] }     js      : { clé: valeur|"" }
   *   dom     : { sélecteur: true }    src     : [urls]
   *   html    : string                 url     : string
   *   certIssuer : string
   */
  function detect(s) {
    const { technologies, categories } = globalThis.WT_DB;
    const idx = index();
    const headers = s.headers || {};
    const cookies = s.cookies || {};
    const meta = s.meta || {};
    const js = s.js || {};
    const dom = s.dom || {};
    const src = s.src || [];
    const html = s.html || "";
    const url = s.url || "";
    const cookieNames = Object.keys(cookies);
    const found = new Map();

    const add = (name, version, via, conf = 100, extra, raw = false) => {
      version = raw ? version : cleanVersion(version);
      const prio = PRIO[via] || 1;
      let f = found.get(name);
      if (!f) {
        f = { name, version: null, vprio: 0, via: [], confidence: 0, ...extra };
        found.set(name, f);
      }
      f.confidence = Math.min(100, f.confidence + conf);
      if (!f.via.includes(via)) f.via.push(via);
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
          if (r) add(name, r.version, "en-tête", r.c, undefined, r.raw);
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
          for (const v of meta[k] || []) {
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
        for (const d of t.dom) {
          const n = norm(d);
          if (dom[n.re]) add(name, null, "dom", n.c);
        }
      }
      if (t.src) {
        for (const p of t.src) {
          for (const u of src) {
            const r = test(p, u);
            if (r) { add(name, r.version, "script", r.c, undefined, r.raw); break; }
          }
        }
      }
      if (t.html && html) {
        for (const p of t.html) {
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
        if (r) add(name, null, "certificat", r.c);
      }
    }

    // ── Versions et bibliothèques depuis les URL (CDN, noms de fichiers, ?ver=) ──
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
        if (name) { add(name, m[2], "fichier"); hit = true; }
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
        if (wp[3]) {
          const counts = wpAssets.get(key);
          counts.set(wp[3], (counts.get(wp[3]) || 0) + 1);
        }
      }
    }

    // ── Plugins et thèmes WordPress ──
    if (wpAssets.size) {
      const wpVersion = found.get("WordPress")?.version;
      for (const [key, counts] of wpAssets) {
        const [kind, slug] = key.split(":");
        let version = [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || null;
        if (version && version === wpVersion) version = null;
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

    // ── En-têtes et meta generator non reconnus ──
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
        add(m[1], m[2], "en-tête", 100, { cat, generic: true });
      }
    }
    for (const v of meta.generator || []) {
      if (v.length > 60 || idx.metaGenerators.some((p) => test(p, v))) continue;
      const m = /^(.+?)(?:\s+v?(\d[\w.-]*))?$/.exec(v.trim());
      if (!m || known(m[1])) continue;
      add(m[1], m[2], "meta", 100, { cat: "misc", generic: true });
    }

    // ── Implications ──
    const queue = [...found.keys()];
    while (queue.length) {
      const n = queue.shift();
      const parent = found.get(n);
      for (const imp of technologies[n]?.implies || []) {
        const existing = found.get(imp);
        if (existing) {
          if (existing.confidence < parent.confidence) {
            existing.confidence = parent.confidence;
            if (!existing.via.includes("déduit")) existing.via.push("déduit");
            queue.push(imp);
          }
          continue;
        }
        found.set(imp, { name: imp, version: null, via: ["déduit"], confidence: parent.confidence, implied: true, impliedBy: n });
        queue.push(imp);
      }
    }

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

  globalThis.WT_detect = detect;
})();
