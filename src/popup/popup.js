const state = {
  tab: null,
  url: null,
  host: null,
  record: null,
  techs: null,
  scanning: false,
  dns: null,
  ips: {},
  selectedIp: null,
  domain: null,
  settings: { autoScan: true, blacklist: [] },
  blocked: false,
};

const SECURITY_HEADERS = [
  { h: "strict-transport-security", label: "Strict-Transport-Security", desc: "Enforces HTTPS (HSTS)", core: true },
  { h: "content-security-policy", label: "Content-Security-Policy", desc: "Restricts content sources (XSS, injection)", core: true },
  { h: "x-frame-options", label: "X-Frame-Options", desc: "Protects against clickjacking", core: true, alt: (hs) => /frame-ancestors/i.test(hs["content-security-policy"] || "") && "via CSP frame-ancestors" },
  { h: "x-content-type-options", label: "X-Content-Type-Options", desc: "Disables MIME sniffing", core: true, good: /nosniff/i },
  { h: "referrer-policy", label: "Referrer-Policy", desc: "Controls Referer information", core: true },
  { h: "permissions-policy", label: "Permissions-Policy", desc: "Restricts browser APIs (camera, geolocation…)", core: true },
  { h: "cross-origin-opener-policy", label: "Cross-Origin-Opener-Policy", desc: "Isolates the browsing context" },
  { h: "cross-origin-embedder-policy", label: "Cross-Origin-Embedder-Policy", desc: "Cross-origin resource isolation" },
  { h: "cross-origin-resource-policy", label: "Cross-Origin-Resource-Policy", desc: "Limits cross-origin loading" },
];
const LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-drupal-cache", "x-runtime", "via"];

/* Keep labels in the popup so Tech tab stays English even with a stale background cache. */
const CAT_LABELS = {
  cms: "CMS", headless: "Headless CMS", ecommerce: "Ecommerce", ssg: "Static site generator",
  wpplugin: "WordPress plugin", wptheme: "WordPress theme", jsfw: "JS framework", mobile: "Mobile / hybrid",
  jslib: "JS library", editor: "Rich editor", graphics: "Graphics / 3D", ui: "UI / CSS framework",
  webfw: "Web framework", lang: "Language", db: "Database", os: "Operating system", server: "Web server",
  proxy: "Reverse proxy / Load balancer", cdn: "CDN", paas: "Hosting / PaaS", panel: "Hosting panel",
  security: "Security / WAF", ca: "Certificate authority", analytics: "Analytics", tagmgr: "Tag manager",
  abtest: "A/B testing", ads: "Ads / pixels", marketing: "Marketing / CRM", chat: "Support / chat",
  consent: "Cookie consent", payment: "Payment", monitoring: "Monitoring / RUM", search: "Search",
  fonts: "Fonts / icons", media: "Video / media", maps: "Maps", build: "Build / bundler", misc: "Misc",
};
const catLabel = (t) => CAT_LABELS[t.cat] || t.catLabel || t.cat;
const VIA_LABELS = {
  "en-tête": "header", header: "header", meta: "meta", js: "js", script: "script", cookie: "cookie",
  html: "html", url: "url", cdn: "cdn", file: "file", fichier: "file", "?ver": "?ver",
  certificate: "certificate", certificat: "certificate", implied: "implied", déduit: "implied",
  dom: "dom", feed: "feed", probe: "probe",
};
const viaLabel = (v) => VIA_LABELS[v] || v;
const viaText = (t) => (t.via || []).map(viaLabel).join(", ");
const techBadge = (t) => t.version || t.tag || null;

// ───────────── DOM helpers ─────────────
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "style") el.style.cssText = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false || kid === "") continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

function toast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.remove("show"), 1400);
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast(`Copied: ${text.length > 60 ? text.slice(0, 60) + "…" : text}`);
  } catch (e) {
    toast("Unable to copy");
  }
}

const cp = (text, display, cls = "") =>
  text == null || text === ""
    ? h("span", { class: "faint" }, "—")
    : h("span", { class: `copy ${cls}`, title: "Click to copy", onclick: () => copy(String(text)) }, display ?? String(text));

function ext(href, label, cls) {
  return h("a", {
    href,
    class: cls,
    title: href,
    onclick: (e) => {
      e.preventDefault();
      browser.tabs.create({ url: href });
    },
  }, label);
}

function card(title, body, { extra, flush, ico } = {}) {
  return h("section", { class: "card" },
    h("header", { class: "card-h" }, h("span", { class: "card-t" }, ico ? h("span", { class: "ico" }, ico) : null, title), extra),
    h("div", { class: `card-b${flush ? " flush" : ""}` }, body)
  );
}

function kv(label, value, { mono, copyable = true, raw } = {}) {
  let v;
  if (raw) v = value;
  else if (value == null || value === "" || (Array.isArray(value) && !value.length)) v = h("span", { class: "faint" }, "—");
  else v = copyable ? cp(value, null, mono ? "mono" : "") : h("span", { class: mono ? "mono" : "" }, value);
  return h("div", { class: "kv" }, h("div", { class: "k" }, label), h("div", { class: "v" }, v));
}

const loading = (msg = "Loading…") => h("div", { class: "loading" }, h("span", { class: "spinner" }), msg);
const errorLine = (msg) => h("div", { class: "notice bad" }, msg);
const pill = (text, kind = "", title) => h("span", { class: `pill ${kind}`, title }, h("span", { class: "dot" }), text);

// ───────────── Formatting ─────────────
const DAY = 86400000;

function fmtDate(d) {
  if (!d) return null;
  const date = new Date(d);
  if (isNaN(date)) return String(d);
  return date.toLocaleDateString("en-US", { day: "2-digit", month: "short", year: "numeric" });
}

function fmtDateTime(d) {
  if (!d) return null;
  return new Date(d).toLocaleString("en-US", { dateStyle: "medium", timeStyle: "short" });
}

function relative(d) {
  if (!d) return "";
  const diff = new Date(d).getTime() - Date.now();
  const abs = Math.abs(diff);
  const days = Math.round(abs / DAY);
  let s;
  if (days < 1) s = "today";
  else if (days < 60) s = `${days}d`;
  else if (days < 730) s = `${Math.round(days / 30.4)} mo`;
  else s = `${(days / 365.25).toFixed(1).replace(".0", "")}y`;
  if (days < 1) return s;
  return diff > 0 ? `in ${s}` : `${s} ago`;
}

const daysLeft = (d) => Math.floor((new Date(d).getTime() - Date.now()) / DAY);

function flag(cc) {
  if (!cc || cc.length !== 2) return "";
  return String.fromCodePoint(...cc.toUpperCase().split("").map((c) => 0x1f1a5 + c.charCodeAt(0)));
}

function parseDN(dn) {
  const out = {};
  if (!dn) return out;
  const re = /\s*([A-Za-z0-9.]+)=("(?:[^"\\]|\\.)*"|(?:[^,\\]|\\.)*)\s*(?:,|$)/g;
  let m;
  while ((m = re.exec(dn)) && m[0]) {
    let v = m[2].trim();
    if (v.startsWith('"')) v = v.slice(1, -1);
    v = v.replace(/\\(.)/g, "$1");
    (out[m[1].toUpperCase()] ||= []).push(v);
  }
  return out;
}
const dnName = (dn) => {
  const p = parseDN(dn);
  return p.CN?.[0] || p.O?.[0] || p.OU?.[0] || dn;
};

function headersObj(list) {
  const out = {};
  for (const { name, value } of list || []) {
    const k = name.toLowerCase();
    out[k] = k in out ? `${out[k]}\n${value}` : value;
  }
  return out;
}

const isIP = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s) || s.includes(":");

function registrable(host) {
  return state.dns?.domain || state.domain?.data?.domain || host;
}

function currentGeo() {
  const info = state.ips[state.selectedIp];
  return info && !info.loading && !info.geo?.error ? info.geo : null;
}

// ───────────── Render: hero ─────────────
function renderHero() {
  const r = state.record;
  const pills = [];
  const sec = r?.security;
  if (sec) {
    if (sec.state === "secure") {
      const tip = sec.limited
        ? sec.note || "Live TLS details unavailable in this browser"
        : sec.cipherSuite;
      pills.push(pill(sec.protocolVersion || "HTTPS", "ok", tip));
    } else if (sec.state === "insecure") pills.push(pill("Unencrypted HTTP", "bad"));
    else pills.push(pill(`TLS ${sec.state}`, "warn", sec.errorMessage));
  } else if (state.url?.startsWith("http:")) {
    pills.push(pill("Unencrypted HTTP", "bad"));
  }
  const leaf = sec?.certificates?.[0];
  if (leaf?.validity?.end) {
    const left = daysLeft(leaf.validity.end);
    const kind = left < 15 ? "bad" : left < 30 ? "warn" : "ok";
    pills.push(pill(left < 0 ? `Cert. expired ${-left}d ago` : `Cert. expires in ${left}d`, kind, `Expires on ${fmtDate(leaf.validity.end)}`));
  }
  if (state.selectedIp) {
    const g = currentGeo();
    pills.push(pill(`${g ? flag(g.countryCode) + " " : ""}${state.selectedIp}`, "info", g ? `${g.city || ""} ${g.country || ""}` : ""));
    const ptr = state.ips[state.selectedIp]?.ptr;
    if (Array.isArray(ptr) && ptr.length) pills.push(pill(ptr[0], "info", "Reverse DNS (PTR)"));
    const org = g?.org || g?.isp;
    if (org) pills.push(pill(org, "", g.isp && g.isp !== org ? `ISP: ${g.isp}` : "Organization"));
  }
  if (r?.redirects?.length) pills.push(pill(`${r.redirects.length} redirect${r.redirects.length > 1 ? "s" : ""}`, "warn"));
  document.getElementById("pills").replaceChildren(...pills);
  document.getElementById("count-tech").textContent = state.techs?.length || "";
}

// ───────────── Render: overview ─────────────
function renderOverview() {
  const panel = document.getElementById("panel-overview");
  const g = currentGeo();
  const ipInfo = state.ips[state.selectedIp];
  const dom = state.domain;
  const sec = state.record?.security;
  const leaf = sec?.certificates?.[0];
  const hs = headersObj(state.record?.responseHeaders);

  const hosting = card("Hosting", [
    state.selectedIp
      ? h("div", { class: "ip-row" },
          h("div", { class: "big" }, cp(state.selectedIp, null, "mono")),
          g ? h("div", { class: "ip-loc" }, `${flag(g.countryCode)} ${[g.city, g.region, g.country].filter(Boolean).join(", ")}`) : null)
      : loading("Resolving DNS…"),
    ipInfo?.loading ? loading() : null,
    g ? kv("AS", g.asn ? `AS${g.asn}` : null, { mono: true }) : null,
    g ? kv("Organization", g.org || g.isp) : null,
    g && g.isp && g.isp !== g.org ? kv("ISP", g.isp) : null,
    ipInfo?.ptr && !ipInfo.ptr.error ? kv("Reverse DNS", ipInfo.ptr[0] || null, { mono: true }) : null,
  ], { ico: "🌍" });

  let domainBody;
  if (isIP(state.host)) domainBody = h("div", { class: "muted" }, "Direct IP access");
  else if (!dom) domainBody = loading("RDAP lookup…");
  else if (dom.error) domainBody = [h("div", { class: "muted small" }, dom.error), whoisFallbackLink()];
  else {
    const d = dom.data;
    const left = d.expires ? daysLeft(d.expires) : null;
    domainBody = [
      h("div", { class: "stat" }, h("div", { class: "big" }, cp(d.domain)), h("div", { class: "muted small" }, d.registrar?.name || "Unknown registrar")),
      kv("Created", d.created ? `${fmtDate(d.created)} (${relative(d.created)})` : null, { copyable: false }),
      kv("Expires", d.expires ? h("span", { class: left < 30 ? "bad" : left < 90 ? "warn" : "" }, `${fmtDate(d.expires)} (${relative(d.expires)})`) : null, { raw: !!d.expires }),
      kv("DNSSEC", d.dnssec == null ? null : d.dnssec ? h("span", { class: "ok" }, "Enabled") : h("span", { class: "muted" }, "Unsigned"), { raw: d.dnssec != null }),
    ];
  }
  const domainCard = card("Domain", domainBody, { ico: "🏷️" });

  let certBody;
  if (!state.record) certBody = h("div", { class: "muted small" }, "Reload the page to capture the certificate.");
  else if (sec?.state === "insecure" || state.url.startsWith("http:")) certBody = h("div", { class: "bad" }, "Unencrypted connection (HTTP)");
  else if (!leaf) certBody = h("div", { class: "muted small" }, state.record.securityError || "Certificate not captured — reload the page.");
  else {
    const left = daysLeft(leaf.validity.end);
    const issuer = parseDN(leaf.issuer);
    certBody = [
      h("div", { class: "stat" },
        h("div", { class: "big" }, dnName(leaf.subject)),
        h("div", { class: "muted small" }, `Issued by ${issuer.O?.[0] || dnName(leaf.issuer)}`)),
      kv("Expires", h("span", { class: left < 0 ? "bad" : left < 15 ? "bad" : left < 30 ? "warn" : "ok" }, `${fmtDate(leaf.validity.end)} (${left < 0 ? "expired" : left + "d"})`), { raw: true }),
      kv("Protocol", [sec.protocolVersion, sec.keaGroupName].filter(Boolean).join(" · "), { copyable: false }),
      kv("SAN", leaf.parsed?.san?.length ? `${leaf.parsed.san.length} name${leaf.parsed.san.length > 1 ? "s" : ""}` : null, { copyable: false }),
    ];
  }
  const certCard = card("Certificate", certBody, { ico: "🔒" });

  let techBody;
  if (state.techs == null) techBody = loading("Analyzing page…");
  else if (!state.techs.length) techBody = h("div", { class: "muted small" }, "No technologies detected.");
  else {
    const shown = state.techs.filter((t) => !t.implied).slice(0, 18);
    techBody = h("div", { class: "chips" },
      shown.map((t) => h("span", { class: "chip tech-chip", title: catLabel(t) },
        techIcon(t, "tech-chip-ico"),
        h("span", { class: "tech-chip-name" }, t.name),
        techBadge(t) ? h("span", { class: "ver" }, techBadge(t)) : null)),
      state.techs.length > shown.length ? h("span", { class: "chip click", onclick: () => switchTab("tech") }, `+${state.techs.length - shown.length} …`) : null);
  }
  const techCard = card("Technologies", techBody, {
    ico: "🧩",
    extra: state.techs?.length ? h("a", { onclick: () => switchTab("tech") }, "View all") : null,
  });

  let secCard = null;
  if (state.record?.responseHeaders) {
    const core = SECURITY_HEADERS.filter((s) => s.core);
    const present = core.filter((s) => hs[s.h] || s.alt?.(hs));
    const ratio = present.length / core.length;
    secCard = card("Security headers", [
      h("div", { class: "score" },
        h("span", { class: `big ${ratio >= 0.8 ? "ok" : ratio >= 0.5 ? "warn" : "bad"}` }, `${present.length}/${core.length}`),
        h("div", { class: "score-bar" }, core.map((s) => h("i", { class: present.includes(s) ? "on" : "", title: s.label })))),
      h("div", { class: "chips", style: "margin-top:8px" },
        core.filter((s) => !present.includes(s)).map((s) => h("span", { class: "chip", title: s.desc }, h("span", { class: "bad" }, "✕"), s.label))),
    ], { ico: "🛡️", extra: h("a", { onclick: () => switchTab("headers") }, "Details") });
  }

  const exportCard = card("Export report", [
    h("div", { class: "muted small", style: "margin-bottom:8px" },
      "Full scan as JSON, or printable HTML you can save as PDF from the browser print dialog."),
    h("div", { style: "display:flex;gap:6px;flex-wrap:wrap" },
      h("button", { class: "btn primary", onclick: () => exportReport("json") }, "Download JSON"),
      h("button", { class: "btn", onclick: () => exportReport("html") }, "Open HTML report"),
      h("button", { class: "btn", onclick: () => exportReport("html-print") }, "Print / PDF")),
  ], { ico: "📤" });

  panel.replaceChildren(
    hosting,
    techCard,
    certCard,
    domainCard,
    secCard || card("Security headers", h("div", { class: "muted small" }, "Reload the page to analyze headers."), { ico: "🛡️" }),
    exportCard,
    card("OSINT tools", quickLinks(), { ico: "🔎" })
  );
}

function buildReportData() {
  const r = state.record;
  const hs = headersObj(r?.responseHeaders);
  const sec = r?.security;
  const leaf = sec?.certificates?.[0];
  const g = currentGeo();
  const ipInfo = state.ips[state.selectedIp];
  const dom = state.domain?.data;
  const d = state.dns;

  const core = SECURITY_HEADERS.filter((s) => s.core);
  const present = core.filter((s) => hs[s.h] || s.alt?.(hs));

  const certs = (sec?.certificates || []).map((c, i) => {
    const p = c.parsed || {};
    const start = c.validity?.start;
    const end = c.validity?.end;
    return {
      index: i,
      subject: c.subject,
      issuer: c.issuer,
      validFrom: start ? fmtDateTime(start) : null,
      validTo: end ? fmtDateTime(end) : null,
      daysLeft: end != null ? daysLeft(end) : null,
      serialNumber: c.serialNumber || null,
      sha256: c.fingerprint?.sha256 || null,
      sha1: c.fingerprint?.sha1 || null,
      spkiSha256: c.spkiSha256 || null,
      san: p.san || [],
      publicKey: p.keyType
        ? `${p.keyType}${p.keySize ? " " + p.keySize + " bits" : ""}${p.keyCurve ? " " + p.keyCurve : ""}`
        : null,
      signatureAlgorithm: p.signatureAlgorithm || null,
      pem: c.pem || null,
      fromCt: !!c.fromCt,
      isBuiltInRoot: !!c.isBuiltInRoot,
    };
  });

  return {
    meta: {
      tool: "WebTool Inspector",
      extensionVersion: browser.runtime.getManifest?.()?.version || null,
      generatedAt: new Date().toISOString(),
      pageTitle: r?.pageTitle || state.tab?.title || null,
    },
    site: {
      host: state.host,
      url: state.url,
      registrableDomain: registrable(state.host),
    },
    summary: {
      pills: [...document.querySelectorAll("#pills .pill")].map((el) => el.textContent.replace(/\s+/g, " ").trim()),
      securityScore: r?.responseHeaders ? `${present.length}/${core.length} core headers` : null,
    },
    technologies: (state.techs || []).map((t) => ({
      name: t.name,
      version: t.version || null,
      tag: t.tag || null,
      category: catLabel(t),
      categoryKey: t.cat,
      via: t.via || [],
      confidence: t.confidence,
      implied: !!t.implied,
      impliedBy: t.impliedBy || null,
      website: t.website || null,
    })),
    ip: {
      selected: state.selectedIp || null,
      contacted: r?.ip || null,
      geo: g
        ? {
            ip: g.ip,
            country: g.country,
            countryCode: g.countryCode,
            region: g.region,
            city: g.city,
            postal: g.postal,
            lat: g.lat,
            lon: g.lon,
            timezone: g.timezone,
            asn: g.asn,
            org: g.org,
            isp: g.isp,
            asDomain: g.asDomain,
            source: g.source,
          }
        : ipInfo?.geo?.error
          ? { error: ipInfo.geo.error }
          : null,
      ptr: Array.isArray(ipInfo?.ptr) ? ipInfo.ptr : ipInfo?.ptr?.error ? { error: ipInfo.ptr.error } : null,
      rdap: ipInfo?.rdap && !ipInfo.rdap.error
        ? {
            name: ipInfo.rdap.name,
            range: ipInfo.rdap.range,
            cidr: ipInfo.rdap.cidr,
            org: ipInfo.rdap.org,
            handle: ipInfo.rdap.handle,
          }
        : ipInfo?.rdap?.error
          ? { error: ipInfo.rdap.error }
          : null,
    },
    dns: d
      ? {
          host: d.host,
          domain: d.domain,
          a: d.a,
          aaaa: d.aaaa,
          cname: d.cname,
          ns: d.ns,
          mx: d.mx,
          txt: d.txt,
          caa: d.caa,
          soa: d.soa,
          dmarc: d.dmarc,
        }
      : null,
    domain: state.domain?.error
      ? { error: state.domain.error }
      : dom
        ? {
            domain: dom.domain,
            registrar: dom.registrar?.name || null,
            registrarUrl: dom.registrar?.url || null,
            created: dom.created ? fmtDateTime(dom.created) : null,
            updated: dom.updated ? fmtDateTime(dom.updated) : null,
            expires: dom.expires ? fmtDateTime(dom.expires) : null,
            dnssec: dom.dnssec,
            nameservers: dom.nameservers || [],
            status: dom.status || [],
          }
        : null,
    certificate: sec
      ? {
          state: sec.state,
          protocolVersion: sec.protocolVersion || null,
          cipherSuite: sec.cipherSuite || null,
          keaGroupName: sec.keaGroupName || null,
          signatureSchemeName: sec.signatureSchemeName || null,
          hsts: !!sec.hsts,
          limited: !!sec.limited,
          note: sec.note || null,
          certificateTransparencyStatus: sec.certificateTransparencyStatus || null,
          certificates: certs,
        }
      : null,
    securityHeaders: SECURITY_HEADERS.map((s) => {
      const val = hs[s.h];
      const alt = !val && s.alt?.(hs);
      const weak = val && s.good && !s.good.test(val);
      let status = "missing";
      let statusClass = s.core ? "bad" : "muted";
      if (val && !weak) {
        status = "present";
        statusClass = "ok";
      } else if (alt) {
        status = "covered";
        statusClass = "ok";
      } else if (weak) {
        status = "weak";
        statusClass = "warn";
      }
      return {
        header: s.h,
        label: s.label,
        core: !!s.core,
        status,
        statusClass,
        value: val || null,
        note: alt || null,
        description: s.desc,
      };
    }),
    headers: {
      statusCode: r?.statusCode || null,
      statusLine: r?.statusLine || null,
      finalUrl: r?.url || state.url,
      redirects: (r?.redirects || []).map((x) => ({ status: x.status, url: x.url, ip: x.ip || null })),
      raw: (r?.responseHeaders || []).map(({ name, value }) => ({ name, value })),
      leaks: LEAK_HEADERS.filter((k) => hs[k]).map((k) => ({ name: k, value: hs[k] })),
    },
  };
}

async function exportReport(kind) {
  if (state.blocked) {
    toast("Site is blacklisted");
    return;
  }
  if (state.scanning) {
    toast("Wait for the scan to finish");
    return;
  }
  const report = buildReportData();
  try {
    if (kind === "json") {
      const name = WT_report.exportJson(report);
      toast(`Downloaded ${name}`);
    } else if (kind === "html-print") {
      await WT_report.exportHtml(report, { print: true });
      toast("Opening printable report…");
    } else {
      await WT_report.exportHtml(report, { print: false });
      toast("Report opened in a new tab");
    }
  } catch (e) {
    toast(e.message || "Export failed");
  }
}

function quickLinks() {
  const host = state.host;
  const dom = registrable(host);
  const ip = state.selectedIp;
  const asn = currentGeo()?.asn;
  const e = encodeURIComponent;
  const links = [
    ip && ["Shodan", `https://www.shodan.io/host/${ip}`],
    ip && ["Censys", `https://search.censys.io/hosts/${ip}`],
    ip && ["AbuseIPDB", `https://www.abuseipdb.com/check/${ip}`],
    asn && ["BGP.he.net", `https://bgp.he.net/AS${asn}`],
    ["VirusTotal", `https://www.virustotal.com/gui/domain/${e(host)}`],
    ["urlscan.io", `https://urlscan.io/domain/${e(host)}`],
    ["crt.sh", `https://crt.sh/?q=${e(dom)}`],
    ["SecurityTrails", `https://securitytrails.com/domain/${e(dom)}/dns`],
    ["Who.is", `https://who.is/whois/${e(dom)}`],
    ["MXToolbox", `https://mxtoolbox.com/SuperTool.aspx?action=mx%3a${e(dom)}`],
    ["SSL Labs", `https://www.ssllabs.com/ssltest/analyze.html?d=${e(host)}&hideResults=on`],
    ["Observatory", `https://developer.mozilla.org/en-US/observatory/analyze?host=${e(host)}`],
    ["SecurityHeaders", `https://securityheaders.com/?q=${e(state.url)}&followRedirects=on`],
    ["Wayback", `https://web.archive.org/web/*/${host}`],
    ["BuiltWith", `https://builtwith.com/${e(host)}`],
    ["PageSpeed", `https://pagespeed.web.dev/analysis?url=${e(state.url)}`],
  ].filter(Boolean);
  return h("div", { class: "links" }, links.map(([l, u]) => ext(u, l)));
}

function whoisFallbackLink() {
  return h("div", { style: "margin-top:6px" }, ext(`https://who.is/whois/${encodeURIComponent(registrable(state.host))}`, "View WHOIS on who.is ↗"));
}

// ───────────── Render: technologies ─────────────
function techIcon(t, sizeClass = "tech-widget-ico") {
  const initials = t.name.replace(/[^A-Za-z0-9]/g, "").slice(0, 2) || "?";
  const logos = globalThis.WT_logos?.getTechLogo(t) || {};
  const tint = `background:${t.color}18;color:${t.color}`;
  const wrap = h("div", { class: sizeClass, style: tint }, initials);

  if (!logos.primary) return wrap;

  const img = h("img", {
    class: "tech-logo",
    src: logos.primary,
    alt: "",
    loading: "lazy",
    referrerpolicy: "no-referrer",
  });
  img.addEventListener("error", () => {
    if (logos.fallback && img.dataset.fb !== "1") {
      img.dataset.fb = "1";
      img.src = logos.fallback;
      return;
    }
    img.remove();
    wrap.classList.remove("has-logo");
    wrap.classList.add("no-logo");
    wrap.style.cssText = tint;
    wrap.textContent = initials;
  });
  wrap.classList.add("has-logo");
  wrap.style.cssText = "";
  wrap.textContent = "";
  wrap.append(img);
  return wrap;
}

function techWidget(t) {
  const badge = techBadge(t);
  const tip = [
    catLabel(t),
    t.implied ? `implied by ${t.impliedBy}` : viaText(t) ? `via ${viaText(t)}` : null,
    t.confidence < 100 ? `likely ${t.confidence}%` : null,
  ].filter(Boolean).join(" · ");
  return h("div", {
    class: `tech-widget${t.implied ? " implied" : ""}`,
    title: tip,
    style: `--tech: ${t.color}`,
  },
    techIcon(t),
    h("div", { class: "tech-widget-body" },
      h("div", { class: "tech-widget-name" }, t.website ? ext(t.website, t.name) : t.name),
      h("div", { class: "tech-widget-sub" },
        t.implied ? `via ${t.impliedBy}` : viaText(t))),
    badge ? h("span", { class: `tech-widget-badge${t.tag && !t.version ? " tag" : ""}` }, badge) : null);
}

function renderTech() {
  const panel = document.getElementById("panel-tech");
  const actions = h("div", { style: "display:flex;gap:6px" },
    state.techs?.length ? h("button", {
      class: "btn",
      onclick: () => copy(state.techs.map((t) => `${t.name}${techBadge(t) ? " " + techBadge(t) : ""} — ${catLabel(t)}`).join("\n")),
    }, "Copy list") : null,
    h("button", { class: "btn", onclick: () => doRescan() }, state.scanning ? "Scanning…" : "Rescan"));

  if (state.techs == null || (state.scanning && !state.techs?.length)) {
    panel.replaceChildren(card("Technologies", loading("Analyzing page…"), { extra: actions }));
    return;
  }
  if (!state.techs.length) {
    panel.replaceChildren(card("Technologies", h("div", { class: "empty" }, "No technologies detected on this page."), { extra: actions }));
    return;
  }

  const groups = new Map();
  for (const t of state.techs) {
    if (!groups.has(t.cat)) groups.set(t.cat, []);
    groups.get(t.cat).push(t);
  }

  const body = [...groups.values()].map((items) =>
    h("div", { class: "tech-group" },
      h("div", { class: "tech-cat" },
        h("i", { style: `background:${items[0].color}` }),
        catLabel(items[0]),
        h("span", { class: "tech-cat-n" }, items.length)),
      h("div", { class: "tech-grid" }, items.map(techWidget))));

  panel.replaceChildren(card(`${state.techs.length} technologies`, body, { flush: true, extra: actions }));
}

// ───────────── Render: IP / ASN ─────────────
function renderIp() {
  const panel = document.getElementById("panel-ip");
  const d = state.dns;
  const ips = allIps();
  const out = [];

  const ipChips = ips.length
    ? h("div", { class: "chips" }, ips.map((x) =>
        h("span", { class: `chip click mono ${x.ip === state.selectedIp ? "sel" : ""}`, title: x.src, onclick: () => selectIp(x.ip) },
          x.ip, x.connected ? h("span", { class: "ver" }, "connected") : null)))
    : d ? h("div", { class: "muted" }, "No addresses resolved") : loading("Resolving DNS…");

  out.push(card("IP addresses", [
    ipChips,
    state.record?.ip ? h("div", { class: "small muted", style: "margin-top:6px" }, `IP actually contacted by Firefox: ${state.record.ip}`) : null,
    d?.cname && !d.cname.error && d.cname.length ? kv("CNAME chain", d.cname.join(" → "), { mono: true }) : null,
    d?.system?.isTRR != null ? kv("Resolver", d.system.isTRR ? "DNS over HTTPS (Firefox TRR)" : "System resolver", { copyable: false }) : null,
  ], { ico: "📍" }));

  const info = state.ips[state.selectedIp];
  if (!state.selectedIp) {
    panel.replaceChildren(...out);
    return;
  }
  if (!info || info.loading) {
    out.push(card(state.selectedIp, loading("Geolocation, ASN, RDAP…")));
    panel.replaceChildren(...out);
    return;
  }

  const g = info.geo;
  out.push(card("Location & operator", g.error ? errorLine(`Geolocation unavailable: ${g.error}`) : [
    kv("IP", g.ip, { mono: true }),
    kv("Country", g.country ? `${flag(g.countryCode)} ${g.country} (${g.countryCode})` : null),
    kv("Region / city", [g.region, g.city, g.postal].filter(Boolean).join(", ") || null),
    kv("Coordinates", g.lat != null && !isNaN(g.lat) ? ext(`https://www.openstreetmap.org/?mlat=${g.lat}&mlon=${g.lon}#map=10/${g.lat}/${g.lon}`, `${g.lat}, ${g.lon} ↗`) : null, { raw: g.lat != null && !isNaN(g.lat) }),
    kv("Timezone", g.timezone),
    kv("ASN", g.asn ? h("span", null, cp(`AS${g.asn}`, null, "mono"), " ", ext(`https://bgp.he.net/AS${g.asn}`, "↗")) : null, { raw: !!g.asn }),
    kv("AS name / Org", g.org),
    kv("ISP", g.isp),
    g.asDomain ? kv("Operator domain", g.asDomain, { mono: true }) : null,
    h("div", { class: "faint small", style: "margin-top:4px;text-align:right" }, `source: ${g.source}`),
  ], { ico: "🌍" }));

  out.push(card("Reverse DNS (PTR)", info.ptr.error ? errorLine(info.ptr.error)
    : info.ptr.length ? info.ptr.map((p) => kv("PTR", p, { mono: true }))
    : h("div", { class: "muted" }, "No PTR record"), { ico: "↩️" }));

  const r = info.rdap;
  out.push(card("Network block (RDAP / IP whois)", r.error ? errorLine(`RDAP unavailable: ${r.error}`) : [
    kv("Network name", r.name, { mono: true }),
    kv("Range", r.range, { mono: true }),
    r.cidr?.length ? kv("CIDR", r.cidr.join(", "), { mono: true }) : null,
    kv("Holder", r.org),
    kv("Handle", r.handle, { mono: true }),
    kv("Country", r.country ? `${flag(r.country)} ${r.country}` : null),
    kv("RIR", r.rir, { copyable: false }),
    kv("Abuse contact", r.abuseEmail, { mono: true }),
    r.registration ? kv("Registered", fmtDate(r.registration), { copyable: false }) : null,
    r.lastChanged ? kv("Updated", fmtDate(r.lastChanged), { copyable: false }) : null,
  ], { ico: "🗂️" }));

  panel.replaceChildren(...out);
}

function allIps() {
  const list = [];
  const seen = new Set();
  const push = (ip, src, connected) => {
    if (!ip) return;
    if (seen.has(ip)) {
      if (connected) list.find((x) => x.ip === ip).connected = true;
      return;
    }
    seen.add(ip);
    list.push({ ip, src, connected });
  };
  if (state.record?.ip) push(state.record.ip, "Contacted IP", true);
  if (isIP(state.host)) push(state.host.replace(/^\[|\]$/g, ""), "URL");
  const d = state.dns;
  if (d) {
    for (const a of Array.isArray(d.a) ? d.a : []) push(a.data, "A (DoH)");
    for (const a of Array.isArray(d.aaaa) ? d.aaaa : []) push(a.data, "AAAA (DoH)");
    for (const a of d.system?.addresses || []) push(a, "Firefox resolver");
  }
  return list;
}

// ───────────── Render: domain ─────────────
function renderDomain() {
  const panel = document.getElementById("panel-domain");
  const out = [];

  if (isIP(state.host)) {
    panel.replaceChildren(h("div", { class: "notice" }, "This site is accessed by IP address — no domain information."));
    return;
  }

  const dom = state.domain;
  if (!dom) out.push(card("Whois / RDAP", loading("RDAP lookup…"), { ico: "🏷️" }));
  else if (dom.error) out.push(card("Whois / RDAP", [errorLine(dom.error), whoisFallbackLink()], { ico: "🏷️" }));
  else {
    const d = dom.data;
    const left = d.expires ? daysLeft(d.expires) : null;
    out.push(card("Registration", [
      kv("Domain", d.domain, { mono: true }),
      kv("Registrar", d.registrar?.name ? h("span", null, cp(d.registrar.name), d.registrar.ianaId ? h("span", { class: "faint" }, ` · IANA ${d.registrar.ianaId}`) : null) : null, { raw: !!d.registrar?.name }),
      d.registrar?.url ? kv("Registrar site", ext(d.registrar.url, d.registrar.url.replace(/^https?:\/\//, "")), { raw: true }) : null,
      kv("Abuse contact", d.abuseEmail, { mono: true }),
      d.registrant && (d.registrant.org || d.registrant.name || d.registrant.country)
        ? kv("Holder", [d.registrant.org || d.registrant.name, d.registrant.country && `${flag(d.registrant.country)} ${d.registrant.country}`].filter(Boolean).join(" · "))
        : null,
      kv("Created", d.created ? `${fmtDate(d.created)} — ${relative(d.created)}` : null, { copyable: false }),
      kv("Last changed", d.updated ? `${fmtDate(d.updated)} — ${relative(d.updated)}` : null, { copyable: false }),
      kv("Expires", d.expires ? h("span", { class: left < 30 ? "bad" : left < 90 ? "warn" : "ok" }, `${fmtDate(d.expires)} — ${relative(d.expires)}`) : null, { raw: !!d.expires }),
      kv("DNSSEC", d.dnssec == null ? null : d.dnssec ? h("span", { class: "ok" }, "Delegation signed") : "Unsigned", { raw: d.dnssec === true, copyable: false }),
      kv("Statuses", d.status.length ? h("div", { class: "chips" }, d.status.map((s) => h("span", { class: "chip" }, s))) : null, { raw: d.status.length > 0 }),
      kv("Nameservers", d.nameservers.length ? h("div", null, d.nameservers.map((n) => h("div", null, cp(n, null, "mono")))) : null, { raw: d.nameservers.length > 0 }),
      d.whoisServer ? kv("WHOIS server", d.whoisServer, { mono: true }) : null,
      h("div", { class: "small", style: "margin-top:6px;text-align:right" }, ext(d.rdapUrl, "Raw RDAP response ↗")),
    ], { ico: "🏷️" }));
  }

  const d = state.dns;
  if (!d) out.push(card("DNS records", loading("DNS queries…"), { ico: "📡" }));
  else {
    const rec = (label, list, fmt = (x) => x.data) => {
      if (!list) return null;
      if (list.error) return kv(label, h("span", { class: "bad small" }, list.error), { raw: true });
      if (!list.length) return kv(label, null);
      return kv(label, h("div", null, list.map((x) => h("div", null, cp(fmt(x), null, "mono")))), { raw: true });
    };
    const txt = Array.isArray(d.txt) ? d.txt : [];
    const spf = txt.filter((t) => /v=spf1/i.test(t.data));
    const other = txt.filter((t) => !/v=spf1/i.test(t.data));
    const unq = (x) => x.data.replace(/^"|"$/g, "").replace(/"\s*"/g, "");
    out.push(card(`DNS records — ${d.domain || d.host}`, [
      rec("A", d.a),
      rec("AAAA", d.aaaa),
      rec("NS", d.ns, (x) => x.data.replace(/\.$/, "")),
      rec("MX", d.mx, (x) => x.data.replace(/\.$/, "")),
      rec("SPF", d.txt?.error ? d.txt : spf, unq),
      rec("DMARC", d.dmarc, unq),
      rec("CAA", d.caa),
      rec("SOA", d.soa),
      other.length ? h("details", null, h("summary", null, `Other TXT (${other.length})`), rec("TXT", other, unq)) : null,
    ], { ico: "📡" }));
  }

  panel.replaceChildren(...out);
}

// ───────────── Render: certificate ─────────────
function renderCert() {
  const panel = document.getElementById("panel-cert");
  const r = state.record;
  const sec = r?.security;

  if (!r || !sec) {
    const http = state.url.startsWith("http:");
    panel.replaceChildren(h("div", { class: `notice ${http ? "bad" : "warn"}` },
      h("span", { class: "grow" }, http ? "Unencrypted connection: no certificate." : r?.securityError || "TLS details are captured during page load. Reload the page to fetch them."),
      http ? null : h("button", { class: "btn primary", onclick: reloadTab }, "Reload")));
    return;
  }
  if (sec.state === "insecure") {
    panel.replaceChildren(h("div", { class: "notice bad" }, "Unencrypted connection (HTTP): no certificate."));
    return;
  }

  const certs = sec.certificates || [];
  const leaf = certs[0];
  const out = [];

  if (sec.limited) {
    out.push(h("div", { class: "notice warn" },
      h("span", { class: "grow" }, sec.note || "Live TLS handshake details are not available in Chrome. Certificate data below comes from public Certificate Transparency logs when found.")));
  }

  const ctLabels = {
    not_configured: "Not checked",
    policy_compliant: "Compliant (valid SCTs)",
    policy_not_enough_scts: "Non-compliant: not enough SCTs",
    policy_not_diverse_scts: "Non-compliant: SCTs not diverse",
    ct_log: "From CT logs (crt.sh) — may differ from the live cert",
  };
  out.push(card("Connection", [
    kv("State", h("span", { class: sec.state === "secure" ? "ok" : "warn" }, sec.state === "secure" ? "Secure" : sec.state), { raw: true }),
    kv("Protocol", sec.protocolVersion, { mono: true }),
    sec.cipherSuite ? kv("Cipher suite", sec.cipherSuite, { mono: true }) : null,
    sec.keaGroupName ? kv("Key exchange", sec.keaGroupName, { mono: true }) : null,
    sec.signatureSchemeName ? kv("Signature", sec.signatureSchemeName, { mono: true }) : null,
    kv("HSTS", sec.hsts ? h("span", { class: "ok" }, "Yes") : "No", { raw: !!sec.hsts, copyable: false }),
    sec.certificateTransparencyStatus
      ? kv("Cert. Transparency", ctLabels[sec.certificateTransparencyStatus] ?? sec.certificateTransparencyStatus, { copyable: false })
      : null,
    sec.usedEch ? kv("ECH", h("span", { class: "ok" }, "Encrypted Client Hello"), { raw: true }) : null,
    sec.isExtendedValidation ? kv("Validation", h("span", { class: "ok" }, "EV (Extended Validation)"), { raw: true }) : null,
    sec.weaknessReasons?.length ? kv("Weaknesses", sec.weaknessReasons.join(", ")) : null,
    sec.errorMessage ? kv("Error", h("span", { class: "bad" }, sec.errorMessage), { raw: true }) : null,
    sec.ctError ? kv("CT lookup", h("span", { class: "warn" }, sec.ctError), { raw: true }) : null,
  ].filter(Boolean), { ico: "🔐" }));

  if (sec.limited && !leaf) {
    out.push(card("Certificate", [
      h("div", { class: "muted small" }, "No Certificate Transparency entry loaded yet."),
      h("div", { style: "margin-top:8px;display:flex;gap:6px;flex-wrap:wrap" },
        h("button", {
          class: "btn",
          onclick: async () => {
            try {
              const security = await browser.runtime.sendMessage({ type: "certCt", tabId: state.tab.id });
              if (security && state.record) {
                state.record.security = security;
                renderAll();
              }
            } catch (e) {
              toast(e.message || "CT lookup failed");
            }
          },
        }, "Fetch from crt.sh"),
        ext(`https://crt.sh/?q=${encodeURIComponent(state.host)}`, "Open crt.sh ↗"),
        ext(`https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(state.host)}&hideResults=on`, "SSL Labs ↗")),
    ], { ico: "📜" }));
    panel.replaceChildren(...out);
    return;
  }

  if (leaf) {
    const p = leaf.parsed || {};
    const subj = parseDN(leaf.subject);
    const iss = parseDN(leaf.issuer);
    const start = leaf.validity.start;
    const end = leaf.validity.end;
    const left = daysLeft(end);
    const pct = Math.max(0, Math.min(100, ((Date.now() - start) / (end - start)) * 100));
    const key = p.keyType ? `${p.keyType}${p.keySize ? " " + p.keySize + " bits" : ""}${p.keyCurve ? " " + p.keyCurve : ""}` : null;
    const san = p.san || [];

    out.push(card(leaf.fromCt ? "Certificate (Transparency log)" : "Site certificate", [
      leaf.fromCt ? h("div", { class: "muted small", style: "margin-bottom:6px" }, "From public CT logs (crt.sh) — may not match the certificate currently served.") : null,
      kv("Common name (CN)", subj.CN?.[0], { mono: true }),
      subj.O ? kv("Organization", subj.O.join(", ")) : null,
      kv("Issuer", [iss.O?.[0], iss.CN?.[0]].filter(Boolean).join(" — ") || leaf.issuer),
      h("div", { class: "kv" }, h("div", { class: "k" }, "Validity"),
        h("div", { class: "v" },
          h("div", null, `${fmtDate(start)} → ${fmtDate(end)}`),
          h("div", { class: `progress ${left < 15 ? "bad" : left < 30 ? "warn" : ""}` }, h("i", { style: `width:${pct}%` })),
          h("div", { class: `small ${left < 0 ? "bad" : left < 30 ? "warn" : "muted"}` },
            left < 0 ? `Expired ${-left} days ago` : `${left} days left · lifetime ${Math.round((end - start) / DAY)} days`))),
      kv(`SAN (${san.length + (p.sanIps?.length || 0)})`, san.length || p.sanIps?.length
        ? h("div", null,
            h("div", { class: "chips" }, [...san, ...(p.sanIps || [])].slice(0, 24).map((n) => h("span", { class: "chip mono copy", onclick: () => copy(n) }, n))),
            san.length > 24 ? h("details", null, h("summary", null, `Show ${san.length - 24} more`),
              h("div", { class: "chips", style: "margin-top:6px" }, san.slice(24).map((n) => h("span", { class: "chip mono copy", onclick: () => copy(n) }, n)))) : null)
        : null, { raw: !!(san.length || p.sanIps?.length) }),
      kv("Public key", key, { mono: true }),
      kv("Signature algorithm", p.signatureAlgorithm, { mono: true }),
      p.policies?.length ? kv("Validation type", p.policies.join(", "), { copyable: false }) : null,
      p.eku?.length ? kv("Extended key usage", p.eku.join(", "), { copyable: false }) : null,
      kv("Serial number", leaf.serialNumber, { mono: true }),
      kv("SHA-256 fingerprint", leaf.fingerprint?.sha256, { mono: true }),
      kv("SHA-1 fingerprint", leaf.fingerprint?.sha1, { mono: true }),
      kv("SPKI SHA-256", leaf.spkiSha256, { mono: true }),
      p.ocsp?.length ? kv("OCSP", p.ocsp.join("\n"), { mono: true }) : null,
      p.crl?.length ? kv("CRL", p.crl.join("\n"), { mono: true }) : null,
      p.caIssuers?.length ? kv("Issuer certificate", p.caIssuers.join("\n"), { mono: true }) : null,
      h("div", { style: "display:flex;gap:6px;justify-content:flex-end;margin-top:8px" },
        leaf.pem ? h("button", { class: "btn", onclick: () => copy(leaf.pem) }, "Copy PEM") : null,
        leaf.pem ? h("button", { class: "btn", onclick: () => downloadPem(leaf.pem) }, "Download .pem") : null,
        h("button", { class: "btn", onclick: () => browser.tabs.create({ url: `https://crt.sh/?q=${encodeURIComponent(registrable(state.host))}` }) }, "crt.sh ↗")),
    ], { ico: "📜" }));
  }

  if (certs.length) {
    out.push(card("Certificate chain", h("div", { class: "chain" },
      certs.map((c, i) => {
        const end = c.validity?.end;
        const left = end ? daysLeft(end) : null;
        const root = c.isBuiltInRoot || i === certs.length - 1;
        return h("div", { class: `chain-item ${root ? "root" : ""}` },
          h("div", { class: "chain-dot" }, i),
          h("div", null,
            h("div", { style: "font-weight:600" }, dnName(c.subject)),
            h("div", { class: "small muted" },
              [i === 0 ? (c.fromCt ? "CT log entry" : "Site certificate") : root ? (c.isBuiltInRoot ? "Browser trust root" : "Root") : "Intermediate",
               end ? `expires ${fmtDate(end)}${left < 30 ? ` (${left}d)` : ""}` : null,
               c.parsed?.keyType ? `${c.parsed.keyType}${c.parsed.keySize ? " " + c.parsed.keySize : ""}${c.parsed.keyCurve ? " " + c.parsed.keyCurve : ""}` : null].filter(Boolean).join(" · "))));
      })), { ico: "⛓️" }));
  }

  panel.replaceChildren(...out);
}

function downloadPem(pem) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([pem], { type: "application/x-pem-file" }));
  a.download = `${state.host}.pem`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

// ───────────── Render: headers ─────────────
function renderHeaders() {
  const panel = document.getElementById("panel-headers");
  const r = state.record;
  if (!r?.responseHeaders) {
    panel.replaceChildren(h("div", { class: "notice warn" },
      h("span", { class: "grow" }, "Headers are captured during page load. Reload the page to fetch them."),
      h("button", { class: "btn primary", onclick: reloadTab }, "Reload")));
    return;
  }
  const hs = headersObj(r.responseHeaders);
  const out = [];

  if (r.redirects?.length) {
    out.push(card("Redirect chain", [
      ...r.redirects.map((x) => h("div", { class: "redirect" }, h("span", { class: "code" }, x.status), cp(x.url, null, "mono"))),
      h("div", { class: "redirect" }, h("span", { class: "code ok" }, r.statusCode), cp(r.url, null, "mono")),
    ], { ico: "↪️" }));
  }

  out.push(card("Security headers", SECURITY_HEADERS.map((s) => {
    const val = hs[s.h];
    const alt = !val && s.alt?.(hs);
    const weak = val && s.good && !s.good.test(val);
    const status = val && !weak ? "ok" : alt ? "ok" : s.core ? "bad" : "faint";
    const ico = val && !weak ? "✓" : alt ? "✓" : weak ? "!" : s.core ? "✕" : "–";
    return h("div", { class: "check" },
      h("div", { class: `check-ico ${weak ? "warn" : status}` }, ico),
      h("div", null,
        h("div", { class: "check-t" }, s.label, h("span", { class: "faint small" }, ` — ${s.desc}`)),
        val ? h("div", { class: "check-v copy", onclick: () => copy(val) }, val) : alt ? h("div", { class: "check-v" }, alt) : null));
  }), { ico: "🛡️" }));

  const leaks = LEAK_HEADERS.filter((k) => hs[k]);
  if (leaks.length) {
    out.push(card("Information disclosure", leaks.map((k) => kv(k, hs[k], { mono: true })), { ico: "👁️" }));
  }

  out.push(card(`Response — ${r.statusLine || r.statusCode}`, h("table", null,
    r.responseHeaders.map(({ name, value }) =>
      h("tr", null, h("td", { class: "hn" }, name), h("td", { class: "hv copy", onclick: () => copy(value) }, value)))),
  {
    flush: true,
    ico: "📄",
    extra: h("button", { class: "btn", onclick: () => copy(r.responseHeaders.map((x) => `${x.name}: ${x.value}`).join("\n")) }, "Copy all"),
  }));

  panel.replaceChildren(...out);
}

// ───────────── Navigation / actions ─────────────
function switchTab(name) {
  for (const b of document.querySelectorAll("#tabs button")) b.classList.toggle("active", b.dataset.tab === name);
  for (const p of document.querySelectorAll(".panel")) p.classList.toggle("active", p.id === `panel-${name}`);
  document.getElementById("main").scrollTop = 0;
}

function renderAll() {
  renderHero();
  if (state.blocked) {
    renderBlocked();
    renderSettings();
    return;
  }
  renderOverview();
  renderTech();
  renderIp();
  renderDomain();
  renderCert();
  renderHeaders();
  renderSettings();
}

function renderBlocked() {
  for (const id of ["panel-overview", "panel-tech", "panel-ip", "panel-domain", "panel-cert", "panel-headers"]) {
    const el = document.getElementById(id);
    if (!el) continue;
    el.replaceChildren(
      h("div", { class: "notice warn" },
        h("span", { class: "grow" }, "This site is on your blacklist. The extension does not collect data here."),
        h("button", {
          class: "btn",
          onclick: async () => {
            const host = state.host;
            const next = state.settings.blacklist.filter((p) => {
              const pl = p.toLowerCase();
              return pl !== host.toLowerCase() && pl !== `*.${host.toLowerCase()}`;
            });
            await saveSettings({ blacklist: next });
            state.blocked = false;
            for (const b of document.querySelectorAll("#tabs button")) {
              if (b.dataset.tab !== "settings") b.style.display = "";
            }
            document.getElementById("refresh").style.display = "";
            switchTab("overview");
            renderAll();
            doRescan();
          },
        }, "Unblock host"))
    );
  }
}

async function saveSettings(partial) {
  const next = await browser.runtime.sendMessage({ type: "setSettings", settings: { ...state.settings, ...partial } });
  state.settings = next || { ...state.settings, ...partial };
  toast("Settings saved");
  renderSettings();
  return state.settings;
}

function renderSettings() {
  const panel = document.getElementById("panel-settings");
  if (!panel) return;
  const s = state.settings || { autoScan: true, blacklist: [] };

  const mode = card("Data collection", h("div", { class: "settings-mode" },
    h("label", { class: `mode-opt${s.autoScan ? " on" : ""}` },
      h("input", {
        type: "radio",
        name: "scan-mode",
        checked: !!s.autoScan,
        onchange: () => saveSettings({ autoScan: true }),
      }),
      h("div", null,
        h("strong", null, "Automatic"),
        h("span", null, "Collect technologies, headers and lookups as soon as the page loads."))),
    h("label", { class: `mode-opt${!s.autoScan ? " on" : ""}` },
      h("input", {
        type: "radio",
        name: "scan-mode",
        checked: !s.autoScan,
        onchange: () => saveSettings({ autoScan: false }),
      }),
      h("div", null,
        h("strong", null, "Manual"),
        h("span", null, "Nothing is collected until you open the extension popup — then data loads automatically.")))),
  { ico: "⚡" });

  const list = s.blacklist.length
    ? h("div", { class: "bl-list" }, s.blacklist.map((p) =>
        h("div", { class: "bl-row" },
          h("code", null, p),
          h("button", {
            type: "button",
            onclick: () => saveSettings({ blacklist: s.blacklist.filter((x) => x !== p) }),
          }, "Remove"))))
    : h("div", { class: "muted small", style: "margin-top:8px" }, "No blacklisted sites yet.");

  const input = h("input", {
    type: "text",
    placeholder: "example.com or https://example.com/app",
    value: "",
  });
  const addPattern = async () => {
    const v = input.value.trim();
    if (!v) return;
    if (s.blacklist.some((x) => x.toLowerCase() === v.toLowerCase())) {
      toast("Already blacklisted");
      return;
    }
    input.value = "";
    await saveSettings({ blacklist: [...s.blacklist, v] });
    if (state.url && WT_settings.isBlacklisted(state.url, [...s.blacklist, v])) {
      state.blocked = true;
      renderAll();
    }
  };

  const blacklist = card("URL blacklist", [
    h("div", { class: "muted small" }, "The extension will not run or collect data on matching sites."),
    h("div", { class: "bl-add" },
      input,
      h("button", { class: "btn primary", type: "button", onclick: addPattern }, "Add"),
      state.host && !state.blocked
        ? h("button", {
            class: "btn",
            type: "button",
            title: "Blacklist current host",
            onclick: async () => {
              await saveSettings({ blacklist: [...s.blacklist, state.host] });
              state.blocked = true;
              for (const b of document.querySelectorAll("#tabs button")) {
                if (b.dataset.tab !== "settings") b.style.display = "none";
              }
              document.getElementById("refresh").style.display = "none";
              switchTab("settings");
              renderAll();
            },
          }, "This site")
        : null),
    list,
    h("div", { class: "bl-hint" },
      "Examples: ", h("code", null, "example.com"), " (host + subdomains), ",
      h("code", null, "*.example.com"), ", ",
      h("code", null, "example.com/admin"), ", ",
      h("code", null, "https://app.example.com/")),
  ], { ico: "🚫" });

  const exportCard = card("Export report", [
    h("div", { class: "muted small", style: "margin-bottom:8px" },
      "Export the current scan (also available on Overview)."),
    h("div", { style: "display:flex;gap:6px;flex-wrap:wrap" },
      h("button", { class: "btn primary", onclick: () => exportReport("json") }, "JSON"),
      h("button", { class: "btn", onclick: () => exportReport("html") }, "HTML"),
      h("button", { class: "btn", onclick: () => exportReport("html-print") }, "Print / PDF")),
  ], { ico: "📤" });

  panel.replaceChildren(mode, blacklist, exportCard);
}

function reloadTab() {
  browser.tabs.reload(state.tab.id);
  window.close();
}

async function doRescan() {
  if (state.scanning) return;
  state.scanning = true;
  document.getElementById("refresh").classList.add("spin");
  renderTech();
  try {
    const rec = await browser.runtime.sendMessage({ type: "rescan", tabId: state.tab.id });
    if (rec) {
      state.record = rec;
      state.techs = rec.techs || [];
    }
  } catch (e) {
    toast(e.message);
    state.techs ||= [];
  }
  state.scanning = false;
  document.getElementById("refresh").classList.remove("spin");
  renderAll();
}

async function selectIp(ip) {
  state.selectedIp = ip;
  if (!state.ips[ip]) {
    state.ips[ip] = { loading: true };
    renderAll();
    try {
      state.ips[ip] = await browser.runtime.sendMessage({ type: "ip", ip });
    } catch (e) {
      state.ips[ip] = { ip, geo: { error: e.message }, ptr: { error: e.message }, rdap: { error: e.message } };
    }
  }
  renderAll();
}

async function init() {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  state.tab = tab;
  let url;
  try {
    url = new URL(tab.url);
  } catch (e) {}

  document.getElementById("favicon").src = tab.favIconUrl || "../../icons/icon.svg";
  document.getElementById("favicon").onerror = (e) => (e.target.src = "../../icons/icon.svg");

  try {
    state.settings = (await browser.runtime.sendMessage({ type: "getSettings" })) || WT_settings.DEFAULTS;
  } catch (e) {
    state.settings = { autoScan: true, blacklist: [] };
  }

  for (const b of document.querySelectorAll("#tabs button")) b.addEventListener("click", () => switchTab(b.dataset.tab));

  if (!url || (url.protocol !== "http:" && url.protocol !== "https:")) {
    document.getElementById("host").textContent = tab.title || "Unsupported page";
    document.getElementById("url").textContent = tab.url || "";
    document.getElementById("refresh").style.display = "none";
    for (const b of document.querySelectorAll("#tabs button")) {
      if (b.dataset.tab !== "settings") b.style.display = "none";
    }
    switchTab("settings");
    renderSettings();
    return;
  }

  state.url = url.href;
  state.host = url.hostname.replace(/^\[|\]$/g, "");
  document.getElementById("host").textContent = url.hostname;
  document.getElementById("url").textContent = tab.title ? `${tab.title} — ${url.href}` : url.href;

  document.getElementById("refresh").addEventListener("click", () => {
    if (state.blocked) return;
    state.ips = {};
    doRescan();
    if (state.selectedIp) selectIp(state.selectedIp);
  });

  if (WT_settings.isBlacklisted(state.url, state.settings.blacklist)) {
    state.blocked = true;
    state.techs = [];
    for (const b of document.querySelectorAll("#tabs button")) {
      if (b.dataset.tab !== "settings") b.style.display = "none";
    }
    document.getElementById("refresh").style.display = "none";
    switchTab("settings");
    renderAll();
    return;
  }

  state.record = await browser.runtime.sendMessage({ type: "getTab", tabId: tab.id });
  if (state.record?.hasSignals && Array.isArray(state.record.techs)) state.techs = state.record.techs;
  renderAll();

  /* Auto: page already scanned on load. Manual: scan when the popup opens. */
  const needsScan = !state.record?.hasSignals || !state.techs?.length;
  if (needsScan || !state.settings.autoScan) doRescan();

  if (isIP(state.host)) {
    selectIp(state.host);
  } else {
    if (state.record?.ip) selectIp(state.record.ip);
    browser.runtime.sendMessage({ type: "dns", host: state.host }).then((d) => {
      state.dns = d;
      if (!state.selectedIp) {
        const first = allIps()[0];
        if (first) selectIp(first.ip);
      }
      renderAll();
    });
    browser.runtime.sendMessage({ type: "domain", host: state.host }).then((d) => {
      state.domain = d;
      renderAll();
    });
  }
}

init().catch((e) => {
  document.getElementById("main").replaceChildren(errorLine(`Error: ${e.message}`));
});
