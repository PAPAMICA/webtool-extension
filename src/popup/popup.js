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
};

const SECURITY_HEADERS = [
  { h: "strict-transport-security", label: "Strict-Transport-Security", desc: "Force l'usage de HTTPS (HSTS)", core: true },
  { h: "content-security-policy", label: "Content-Security-Policy", desc: "Restreint les sources de contenu (XSS, injection)", core: true },
  { h: "x-frame-options", label: "X-Frame-Options", desc: "Protège contre le clickjacking", core: true, alt: (hs) => /frame-ancestors/i.test(hs["content-security-policy"] || "") && "via CSP frame-ancestors" },
  { h: "x-content-type-options", label: "X-Content-Type-Options", desc: "Désactive le MIME sniffing", core: true, good: /nosniff/i },
  { h: "referrer-policy", label: "Referrer-Policy", desc: "Contrôle les informations du Referer", core: true },
  { h: "permissions-policy", label: "Permissions-Policy", desc: "Restreint les API navigateur (caméra, géoloc…)", core: true },
  { h: "cross-origin-opener-policy", label: "Cross-Origin-Opener-Policy", desc: "Isolation du contexte de navigation" },
  { h: "cross-origin-embedder-policy", label: "Cross-Origin-Embedder-Policy", desc: "Isolation cross-origin des ressources" },
  { h: "cross-origin-resource-policy", label: "Cross-Origin-Resource-Policy", desc: "Limite le chargement cross-origin" },
];
const LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-drupal-cache", "x-runtime", "via"];

// ───────────── Utilitaires DOM ─────────────
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
    toast(`Copié : ${text.length > 60 ? text.slice(0, 60) + "…" : text}`);
  } catch (e) {
    toast("Impossible de copier");
  }
}

const cp = (text, display, cls = "") =>
  text == null || text === ""
    ? h("span", { class: "faint" }, "—")
    : h("span", { class: `copy ${cls}`, title: "Cliquer pour copier", onclick: () => copy(String(text)) }, display ?? String(text));

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

const loading = (msg = "Chargement…") => h("div", { class: "loading" }, h("span", { class: "spinner" }), msg);
const errorLine = (msg) => h("div", { class: "notice bad" }, msg);
const pill = (text, kind = "", title) => h("span", { class: `pill ${kind}`, title }, h("span", { class: "dot" }), text);

// ───────────── Formatage ─────────────
const DAY = 86400000;

function fmtDate(d) {
  if (!d) return null;
  const date = new Date(d);
  if (isNaN(date)) return String(d);
  return date.toLocaleDateString("fr-FR", { day: "2-digit", month: "short", year: "numeric" });
}

function fmtDateTime(d) {
  if (!d) return null;
  return new Date(d).toLocaleString("fr-FR", { dateStyle: "medium", timeStyle: "short" });
}

function relative(d) {
  if (!d) return "";
  const diff = new Date(d).getTime() - Date.now();
  const abs = Math.abs(diff);
  const days = Math.round(abs / DAY);
  let s;
  if (days < 1) s = "aujourd'hui";
  else if (days < 60) s = `${days} j`;
  else if (days < 730) s = `${Math.round(days / 30.4)} mois`;
  else s = `${(days / 365.25).toFixed(1).replace(".0", "")} ans`;
  if (days < 1) return s;
  return diff > 0 ? `dans ${s}` : `il y a ${s}`;
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

// ───────────── Rendu : en-tête ─────────────
function renderHero() {
  const r = state.record;
  const pills = [];
  const sec = r?.security;
  if (sec) {
    if (sec.state === "secure") pills.push(pill(sec.protocolVersion || "TLS", "ok", sec.cipherSuite));
    else if (sec.state === "insecure") pills.push(pill("HTTP non chiffré", "bad"));
    else pills.push(pill(`TLS ${sec.state}`, "warn", sec.errorMessage));
  } else if (state.url?.startsWith("http:")) {
    pills.push(pill("HTTP non chiffré", "bad"));
  }
  const leaf = sec?.certificates?.[0];
  if (leaf?.validity?.end) {
    const left = daysLeft(leaf.validity.end);
    const kind = left < 15 ? "bad" : left < 30 ? "warn" : "ok";
    pills.push(pill(left < 0 ? `Cert. expiré depuis ${-left} j` : `Cert. expire dans ${left} j`, kind, `Expiration le ${fmtDate(leaf.validity.end)}`));
  }
  if (state.selectedIp) {
    const g = currentGeo();
    pills.push(pill(`${g ? flag(g.countryCode) + " " : ""}${state.selectedIp}`, "info", g ? `${g.city || ""} ${g.country || ""}` : ""));
    const ptr = state.ips[state.selectedIp]?.ptr;
    if (Array.isArray(ptr) && ptr.length) pills.push(pill(ptr[0], "info", "Reverse DNS (PTR)"));
    const org = g?.org || g?.isp;
    if (org) pills.push(pill(org, "", g.isp && g.isp !== org ? `FAI : ${g.isp}` : "Organisation"));
  }
  if (r?.redirects?.length) pills.push(pill(`${r.redirects.length} redirection${r.redirects.length > 1 ? "s" : ""}`, "warn"));
  document.getElementById("pills").replaceChildren(...pills);
  document.getElementById("count-tech").textContent = state.techs?.length || "";
}

// ───────────── Rendu : aperçu ─────────────
function renderOverview() {
  const panel = document.getElementById("panel-overview");
  const g = currentGeo();
  const ipInfo = state.ips[state.selectedIp];
  const dom = state.domain;
  const sec = state.record?.security;
  const leaf = sec?.certificates?.[0];
  const hs = headersObj(state.record?.responseHeaders);

  const hosting = card("Hébergement", [
    state.selectedIp
      ? h("div", { class: "ip-row" },
          h("div", { class: "big" }, cp(state.selectedIp, null, "mono")),
          g ? h("div", { class: "ip-loc" }, `${flag(g.countryCode)} ${[g.city, g.region, g.country].filter(Boolean).join(", ")}`) : null)
      : loading("Résolution DNS…"),
    ipInfo?.loading ? loading() : null,
    g ? kv("AS", g.asn ? `AS${g.asn}` : null, { mono: true }) : null,
    g ? kv("Organisation", g.org || g.isp) : null,
    g && g.isp && g.isp !== g.org ? kv("FAI", g.isp) : null,
    ipInfo?.ptr && !ipInfo.ptr.error ? kv("Reverse DNS", ipInfo.ptr[0] || null, { mono: true }) : null,
  ], { ico: "🌍" });

  let domainBody;
  if (isIP(state.host)) domainBody = h("div", { class: "muted" }, "Accès direct par IP");
  else if (!dom) domainBody = loading("Requête RDAP…");
  else if (dom.error) domainBody = [h("div", { class: "muted small" }, dom.error), whoisFallbackLink()];
  else {
    const d = dom.data;
    const left = d.expires ? daysLeft(d.expires) : null;
    domainBody = [
      h("div", { class: "stat" }, h("div", { class: "big" }, cp(d.domain)), h("div", { class: "muted small" }, d.registrar?.name || "Registrar inconnu")),
      kv("Création", d.created ? `${fmtDate(d.created)} (${relative(d.created)})` : null, { copyable: false }),
      kv("Expiration", d.expires ? h("span", { class: left < 30 ? "bad" : left < 90 ? "warn" : "" }, `${fmtDate(d.expires)} (${relative(d.expires)})`) : null, { raw: !!d.expires }),
      kv("DNSSEC", d.dnssec == null ? null : d.dnssec ? h("span", { class: "ok" }, "Activé") : h("span", { class: "muted" }, "Non signé"), { raw: d.dnssec != null }),
    ];
  }
  const domainCard = card("Domaine", domainBody, { ico: "🏷️" });

  let certBody;
  if (!state.record) certBody = h("div", { class: "muted small" }, "Rechargez la page pour capturer le certificat.");
  else if (sec?.state === "insecure" || state.url.startsWith("http:")) certBody = h("div", { class: "bad" }, "Connexion non chiffrée (HTTP)");
  else if (!leaf) certBody = h("div", { class: "muted small" }, state.record.securityError || "Certificat non capturé — rechargez la page.");
  else {
    const left = daysLeft(leaf.validity.end);
    const issuer = parseDN(leaf.issuer);
    certBody = [
      h("div", { class: "stat" },
        h("div", { class: "big" }, dnName(leaf.subject)),
        h("div", { class: "muted small" }, `Émis par ${issuer.O?.[0] || dnName(leaf.issuer)}`)),
      kv("Expire", h("span", { class: left < 0 ? "bad" : left < 15 ? "bad" : left < 30 ? "warn" : "ok" }, `${fmtDate(leaf.validity.end)} (${left < 0 ? "expiré" : left + " j"})`), { raw: true }),
      kv("Protocole", [sec.protocolVersion, sec.keaGroupName].filter(Boolean).join(" · "), { copyable: false }),
      kv("SAN", leaf.parsed?.san?.length ? `${leaf.parsed.san.length} nom${leaf.parsed.san.length > 1 ? "s" : ""}` : null, { copyable: false }),
    ];
  }
  const certCard = card("Certificat", certBody, { ico: "🔒" });

  let techBody;
  if (state.techs == null) techBody = loading("Analyse de la page…");
  else if (!state.techs.length) techBody = h("div", { class: "muted small" }, "Aucune technologie détectée.");
  else {
    const shown = state.techs.filter((t) => !t.implied).slice(0, 18);
    techBody = h("div", { class: "chips" },
      shown.map((t) => h("span", { class: "chip", title: t.catLabel },
        h("i", { style: `width:7px;height:7px;border-radius:2px;background:${t.color}` }), t.name, t.version ? h("span", { class: "ver" }, t.version) : null)),
      state.techs.length > shown.length ? h("span", { class: "chip click", onclick: () => switchTab("tech") }, `+${state.techs.length - shown.length} …`) : null);
  }
  const techCard = card("Technologies", techBody, {
    ico: "🧩",
    extra: state.techs?.length ? h("a", { onclick: () => switchTab("tech") }, "Tout voir") : null,
  });

  let secCard = null;
  if (state.record?.responseHeaders) {
    const core = SECURITY_HEADERS.filter((s) => s.core);
    const present = core.filter((s) => hs[s.h] || s.alt?.(hs));
    const ratio = present.length / core.length;
    secCard = card("En-têtes de sécurité", [
      h("div", { class: "score" },
        h("span", { class: `big ${ratio >= 0.8 ? "ok" : ratio >= 0.5 ? "warn" : "bad"}` }, `${present.length}/${core.length}`),
        h("div", { class: "score-bar" }, core.map((s) => h("i", { class: present.includes(s) ? "on" : "", title: s.label })))),
      h("div", { class: "chips", style: "margin-top:8px" },
        core.filter((s) => !present.includes(s)).map((s) => h("span", { class: "chip", title: s.desc }, h("span", { class: "bad" }, "✕"), s.label))),
    ], { ico: "🛡️", extra: h("a", { onclick: () => switchTab("headers") }, "Détails") });
  }

  panel.replaceChildren(
    hosting,
    techCard,
    certCard,
    domainCard,
    secCard || card("En-têtes de sécurité", h("div", { class: "muted small" }, "Rechargez la page pour analyser les en-têtes."), { ico: "🛡️" }),
    card("Outils OSINT", quickLinks(), { ico: "🔎" })
  );
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
  return h("div", { style: "margin-top:6px" }, ext(`https://who.is/whois/${encodeURIComponent(registrable(state.host))}`, "Voir le WHOIS sur who.is ↗"));
}

// ───────────── Rendu : technologies ─────────────
function renderTech() {
  const panel = document.getElementById("panel-tech");
  const actions = h("div", { style: "display:flex;gap:6px" },
    state.techs?.length ? h("button", {
      class: "btn",
      onclick: () => copy(state.techs.map((t) => `${t.name}${t.version ? " " + t.version : ""} — ${t.catLabel}`).join("\n")),
    }, "Copier la liste") : null,
    h("button", { class: "btn", onclick: () => doRescan() }, state.scanning ? "Analyse…" : "Relancer"));

  if (state.techs == null || (state.scanning && !state.techs?.length)) {
    panel.replaceChildren(card("Technologies", loading("Analyse de la page…"), { extra: actions }));
    return;
  }
  if (!state.techs.length) {
    panel.replaceChildren(card("Technologies", h("div", { class: "empty" }, "Aucune technologie détectée sur cette page."), { extra: actions }));
    return;
  }

  const groups = new Map();
  for (const t of state.techs) {
    if (!groups.has(t.cat)) groups.set(t.cat, []);
    groups.get(t.cat).push(t);
  }

  const body = [...groups.values()].map((items) =>
    h("div", { class: "tech-group" },
      h("div", { class: "tech-cat" }, h("i", { style: `background:${items[0].color}` }), items[0].catLabel),
      items.map((t) =>
        h("div", { class: "tech" },
          h("div", { class: "avatar", style: `background:${t.color}26;color:${t.color}` }, t.name.replace(/[^A-Za-z0-9]/g, "").slice(0, 2) || "?"),
          h("div", null,
            h("div", { class: "tech-name" }, t.website ? ext(t.website, t.name) : t.name),
            h("div", { class: "tech-meta" },
              t.confidence < 100 ? h("span", { class: "warn" }, `probable (${t.confidence} %) · `) : null,
              t.implied ? `déduit de ${t.impliedBy}` : `détecté via ${t.via.join(", ")}`)),
          t.version ? h("span", { class: "ver" }, t.version) : null))));

  panel.replaceChildren(card(`${state.techs.length} technologies`, body, { flush: true, extra: actions }));
}

// ───────────── Rendu : IP / ASN ─────────────
function renderIp() {
  const panel = document.getElementById("panel-ip");
  const d = state.dns;
  const ips = allIps();
  const out = [];

  const ipChips = ips.length
    ? h("div", { class: "chips" }, ips.map((x) =>
        h("span", { class: `chip click mono ${x.ip === state.selectedIp ? "sel" : ""}`, title: x.src, onclick: () => selectIp(x.ip) },
          x.ip, x.connected ? h("span", { class: "ver" }, "connectée") : null)))
    : d ? h("div", { class: "muted" }, "Aucune adresse résolue") : loading("Résolution DNS…");

  out.push(card("Adresses IP", [
    ipChips,
    state.record?.ip ? h("div", { class: "small muted", style: "margin-top:6px" }, `IP réellement contactée par Firefox : ${state.record.ip}`) : null,
    d?.cname && !d.cname.error && d.cname.length ? kv("Chaîne CNAME", d.cname.join(" → "), { mono: true }) : null,
    d?.system?.isTRR != null ? kv("Résolveur", d.system.isTRR ? "DNS over HTTPS (TRR Firefox)" : "Résolveur système", { copyable: false }) : null,
  ], { ico: "📍" }));

  const info = state.ips[state.selectedIp];
  if (!state.selectedIp) {
    panel.replaceChildren(...out);
    return;
  }
  if (!info || info.loading) {
    out.push(card(state.selectedIp, loading("Géolocalisation, ASN, RDAP…")));
    panel.replaceChildren(...out);
    return;
  }

  const g = info.geo;
  out.push(card("Localisation & opérateur", g.error ? errorLine(`Géolocalisation indisponible : ${g.error}`) : [
    kv("IP", g.ip, { mono: true }),
    kv("Pays", g.country ? `${flag(g.countryCode)} ${g.country} (${g.countryCode})` : null),
    kv("Région / ville", [g.region, g.city, g.postal].filter(Boolean).join(", ") || null),
    kv("Coordonnées", g.lat != null && !isNaN(g.lat) ? ext(`https://www.openstreetmap.org/?mlat=${g.lat}&mlon=${g.lon}#map=10/${g.lat}/${g.lon}`, `${g.lat}, ${g.lon} ↗`) : null, { raw: g.lat != null && !isNaN(g.lat) }),
    kv("Fuseau horaire", g.timezone),
    kv("ASN", g.asn ? h("span", null, cp(`AS${g.asn}`, null, "mono"), " ", ext(`https://bgp.he.net/AS${g.asn}`, "↗")) : null, { raw: !!g.asn }),
    kv("Nom AS / Org", g.org),
    kv("FAI (ISP)", g.isp),
    g.asDomain ? kv("Domaine opérateur", g.asDomain, { mono: true }) : null,
    h("div", { class: "faint small", style: "margin-top:4px;text-align:right" }, `source : ${g.source}`),
  ], { ico: "🌍" }));

  out.push(card("Reverse DNS (PTR)", info.ptr.error ? errorLine(info.ptr.error)
    : info.ptr.length ? info.ptr.map((p) => kv("PTR", p, { mono: true }))
    : h("div", { class: "muted" }, "Aucun enregistrement PTR"), { ico: "↩️" }));

  const r = info.rdap;
  out.push(card("Bloc réseau (RDAP / whois IP)", r.error ? errorLine(`RDAP indisponible : ${r.error}`) : [
    kv("Nom du réseau", r.name, { mono: true }),
    kv("Plage", r.range, { mono: true }),
    r.cidr?.length ? kv("CIDR", r.cidr.join(", "), { mono: true }) : null,
    kv("Titulaire", r.org),
    kv("Handle", r.handle, { mono: true }),
    kv("Pays", r.country ? `${flag(r.country)} ${r.country}` : null),
    kv("RIR", r.rir, { copyable: false }),
    kv("Contact abuse", r.abuseEmail, { mono: true }),
    r.registration ? kv("Enregistré", fmtDate(r.registration), { copyable: false }) : null,
    r.lastChanged ? kv("Modifié", fmtDate(r.lastChanged), { copyable: false }) : null,
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
  if (state.record?.ip) push(state.record.ip, "IP contactée", true);
  if (isIP(state.host)) push(state.host.replace(/^\[|\]$/g, ""), "URL");
  const d = state.dns;
  if (d) {
    for (const a of Array.isArray(d.a) ? d.a : []) push(a.data, "A (DoH)");
    for (const a of Array.isArray(d.aaaa) ? d.aaaa : []) push(a.data, "AAAA (DoH)");
    for (const a of d.system?.addresses || []) push(a, "Résolveur Firefox");
  }
  return list;
}

// ───────────── Rendu : domaine ─────────────
function renderDomain() {
  const panel = document.getElementById("panel-domain");
  const out = [];

  if (isIP(state.host)) {
    panel.replaceChildren(h("div", { class: "notice" }, "Le site est consulté directement via une adresse IP : pas d'informations de domaine."));
    return;
  }

  const dom = state.domain;
  if (!dom) out.push(card("Whois / RDAP", loading("Requête RDAP…"), { ico: "🏷️" }));
  else if (dom.error) out.push(card("Whois / RDAP", [errorLine(dom.error), whoisFallbackLink()], { ico: "🏷️" }));
  else {
    const d = dom.data;
    const left = d.expires ? daysLeft(d.expires) : null;
    out.push(card("Enregistrement", [
      kv("Domaine", d.domain, { mono: true }),
      kv("Registrar", d.registrar?.name ? h("span", null, cp(d.registrar.name), d.registrar.ianaId ? h("span", { class: "faint" }, ` · IANA ${d.registrar.ianaId}`) : null) : null, { raw: !!d.registrar?.name }),
      d.registrar?.url ? kv("Site registrar", ext(d.registrar.url, d.registrar.url.replace(/^https?:\/\//, "")), { raw: true }) : null,
      kv("Contact abuse", d.abuseEmail, { mono: true }),
      d.registrant && (d.registrant.org || d.registrant.name || d.registrant.country)
        ? kv("Titulaire", [d.registrant.org || d.registrant.name, d.registrant.country && `${flag(d.registrant.country)} ${d.registrant.country}`].filter(Boolean).join(" · "))
        : null,
      kv("Création", d.created ? `${fmtDate(d.created)} — ${relative(d.created)}` : null, { copyable: false }),
      kv("Dernière modif.", d.updated ? `${fmtDate(d.updated)} — ${relative(d.updated)}` : null, { copyable: false }),
      kv("Expiration", d.expires ? h("span", { class: left < 30 ? "bad" : left < 90 ? "warn" : "ok" }, `${fmtDate(d.expires)} — ${relative(d.expires)}`) : null, { raw: !!d.expires }),
      kv("DNSSEC", d.dnssec == null ? null : d.dnssec ? h("span", { class: "ok" }, "Délégation signée") : "Non signé", { raw: d.dnssec === true, copyable: false }),
      kv("Statuts", d.status.length ? h("div", { class: "chips" }, d.status.map((s) => h("span", { class: "chip" }, s))) : null, { raw: d.status.length > 0 }),
      kv("Serveurs de noms", d.nameservers.length ? h("div", null, d.nameservers.map((n) => h("div", null, cp(n, null, "mono")))) : null, { raw: d.nameservers.length > 0 }),
      d.whoisServer ? kv("Serveur WHOIS", d.whoisServer, { mono: true }) : null,
      h("div", { class: "small", style: "margin-top:6px;text-align:right" }, ext(d.rdapUrl, "Réponse RDAP brute ↗")),
    ], { ico: "🏷️" }));
  }

  const d = state.dns;
  if (!d) out.push(card("Enregistrements DNS", loading("Requêtes DNS…"), { ico: "📡" }));
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
    out.push(card(`Enregistrements DNS — ${d.domain || d.host}`, [
      rec("A", d.a),
      rec("AAAA", d.aaaa),
      rec("NS", d.ns, (x) => x.data.replace(/\.$/, "")),
      rec("MX", d.mx, (x) => x.data.replace(/\.$/, "")),
      rec("SPF", d.txt?.error ? d.txt : spf, unq),
      rec("DMARC", d.dmarc, unq),
      rec("CAA", d.caa),
      rec("SOA", d.soa),
      other.length ? h("details", null, h("summary", null, `Autres TXT (${other.length})`), rec("TXT", other, unq)) : null,
    ], { ico: "📡" }));
  }

  panel.replaceChildren(...out);
}

// ───────────── Rendu : certificat ─────────────
function renderCert() {
  const panel = document.getElementById("panel-cert");
  const r = state.record;
  const sec = r?.security;

  if (!r || !sec) {
    const http = state.url.startsWith("http:");
    panel.replaceChildren(h("div", { class: `notice ${http ? "bad" : "warn"}` },
      h("span", { class: "grow" }, http ? "Connexion non chiffrée : pas de certificat." : r?.securityError || "Les informations TLS sont capturées pendant le chargement. Rechargez la page pour les obtenir."),
      http ? null : h("button", { class: "btn primary", onclick: reloadTab }, "Recharger")));
    return;
  }
  if (sec.state === "insecure") {
    panel.replaceChildren(h("div", { class: "notice bad" }, "Connexion non chiffrée (HTTP) : pas de certificat."));
    return;
  }

  const certs = sec.certificates || [];
  const leaf = certs[0];
  const out = [];

  const ctLabels = {
    not_configured: "Non vérifiée",
    policy_compliant: "Conforme (SCT valides)",
    policy_not_enough_scts: "Non conforme : SCT insuffisants",
    policy_not_diverse_scts: "Non conforme : SCT non diversifiés",
  };
  out.push(card("Connexion", [
    kv("État", h("span", { class: sec.state === "secure" ? "ok" : "warn" }, sec.state === "secure" ? "Sécurisée" : sec.state), { raw: true }),
    kv("Protocole", sec.protocolVersion, { mono: true }),
    kv("Suite de chiffrement", sec.cipherSuite, { mono: true }),
    kv("Échange de clés", sec.keaGroupName, { mono: true }),
    kv("Signature", sec.signatureSchemeName, { mono: true }),
    kv("HSTS", sec.hsts ? h("span", { class: "ok" }, "Oui") : "Non", { raw: !!sec.hsts, copyable: false }),
    kv("Cert. Transparency", ctLabels[sec.certificateTransparencyStatus] ?? sec.certificateTransparencyStatus, { copyable: false }),
    sec.usedEch ? kv("ECH", h("span", { class: "ok" }, "Encrypted Client Hello"), { raw: true }) : null,
    sec.isExtendedValidation ? kv("Validation", h("span", { class: "ok" }, "EV (Extended Validation)"), { raw: true }) : null,
    sec.weaknessReasons?.length ? kv("Faiblesses", sec.weaknessReasons.join(", ")) : null,
    sec.errorMessage ? kv("Erreur", h("span", { class: "bad" }, sec.errorMessage), { raw: true }) : null,
  ], { ico: "🔐" }));

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

    out.push(card("Certificat du site", [
      kv("Nom commun (CN)", subj.CN?.[0], { mono: true }),
      subj.O ? kv("Organisation", subj.O.join(", ")) : null,
      kv("Émetteur", [iss.O?.[0], iss.CN?.[0]].filter(Boolean).join(" — ") || leaf.issuer),
      h("div", { class: "kv" }, h("div", { class: "k" }, "Validité"),
        h("div", { class: "v" },
          h("div", null, `${fmtDate(start)} → ${fmtDate(end)}`),
          h("div", { class: `progress ${left < 15 ? "bad" : left < 30 ? "warn" : ""}` }, h("i", { style: `width:${pct}%` })),
          h("div", { class: `small ${left < 0 ? "bad" : left < 30 ? "warn" : "muted"}` },
            left < 0 ? `Expiré depuis ${-left} jours` : `${left} jours restants · durée ${Math.round((end - start) / DAY)} jours`))),
      kv(`SAN (${san.length + (p.sanIps?.length || 0)})`, san.length || p.sanIps?.length
        ? h("div", null,
            h("div", { class: "chips" }, [...san, ...(p.sanIps || [])].slice(0, 24).map((n) => h("span", { class: "chip mono copy", onclick: () => copy(n) }, n))),
            san.length > 24 ? h("details", null, h("summary", null, `Voir les ${san.length - 24} autres`),
              h("div", { class: "chips", style: "margin-top:6px" }, san.slice(24).map((n) => h("span", { class: "chip mono copy", onclick: () => copy(n) }, n)))) : null)
        : null, { raw: !!(san.length || p.sanIps?.length) }),
      kv("Clé publique", key, { mono: true }),
      kv("Algorithme de signature", p.signatureAlgorithm, { mono: true }),
      p.policies?.length ? kv("Type de validation", p.policies.join(", "), { copyable: false }) : null,
      p.eku?.length ? kv("Usages étendus", p.eku.join(", "), { copyable: false }) : null,
      kv("Numéro de série", leaf.serialNumber, { mono: true }),
      kv("Empreinte SHA-256", leaf.fingerprint?.sha256, { mono: true }),
      kv("Empreinte SHA-1", leaf.fingerprint?.sha1, { mono: true }),
      kv("SPKI SHA-256", leaf.spkiSha256, { mono: true }),
      p.ocsp?.length ? kv("OCSP", p.ocsp.join("\n"), { mono: true }) : null,
      p.crl?.length ? kv("CRL", p.crl.join("\n"), { mono: true }) : null,
      p.caIssuers?.length ? kv("Certificat émetteur", p.caIssuers.join("\n"), { mono: true }) : null,
      h("div", { style: "display:flex;gap:6px;justify-content:flex-end;margin-top:8px" },
        leaf.pem ? h("button", { class: "btn", onclick: () => copy(leaf.pem) }, "Copier le PEM") : null,
        leaf.pem ? h("button", { class: "btn", onclick: () => downloadPem(leaf.pem) }, "Télécharger .pem") : null,
        h("button", { class: "btn", onclick: () => browser.tabs.create({ url: `https://crt.sh/?q=${encodeURIComponent(registrable(state.host))}` }) }, "crt.sh ↗")),
    ], { ico: "📜" }));
  }

  if (certs.length) {
    out.push(card("Chaîne de certification", h("div", { class: "chain" },
      certs.map((c, i) => {
        const end = c.validity?.end;
        const left = end ? daysLeft(end) : null;
        const root = c.isBuiltInRoot || i === certs.length - 1;
        return h("div", { class: `chain-item ${root ? "root" : ""}` },
          h("div", { class: "chain-dot" }, i),
          h("div", null,
            h("div", { style: "font-weight:600" }, dnName(c.subject)),
            h("div", { class: "small muted" },
              [i === 0 ? "Certificat du site" : root ? (c.isBuiltInRoot ? "Racine de confiance Firefox" : "Racine") : "Intermédiaire",
               end ? `expire le ${fmtDate(end)}${left < 30 ? ` (${left} j)` : ""}` : null,
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

// ───────────── Rendu : en-têtes ─────────────
function renderHeaders() {
  const panel = document.getElementById("panel-headers");
  const r = state.record;
  if (!r?.responseHeaders) {
    panel.replaceChildren(h("div", { class: "notice warn" },
      h("span", { class: "grow" }, "Les en-têtes sont capturés pendant le chargement. Rechargez la page pour les obtenir."),
      h("button", { class: "btn primary", onclick: reloadTab }, "Recharger")));
    return;
  }
  const hs = headersObj(r.responseHeaders);
  const out = [];

  if (r.redirects?.length) {
    out.push(card("Chaîne de redirection", [
      ...r.redirects.map((x) => h("div", { class: "redirect" }, h("span", { class: "code" }, x.status), cp(x.url, null, "mono"))),
      h("div", { class: "redirect" }, h("span", { class: "code ok" }, r.statusCode), cp(r.url, null, "mono")),
    ], { ico: "↪️" }));
  }

  out.push(card("En-têtes de sécurité", SECURITY_HEADERS.map((s) => {
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
    out.push(card("Divulgation d'informations", leaks.map((k) => kv(k, hs[k], { mono: true })), { ico: "👁️" }));
  }

  out.push(card(`Réponse — ${r.statusLine || r.statusCode}`, h("table", null,
    r.responseHeaders.map(({ name, value }) =>
      h("tr", null, h("td", { class: "hn" }, name), h("td", { class: "hv copy", onclick: () => copy(value) }, value)))),
  {
    flush: true,
    ico: "📄",
    extra: h("button", { class: "btn", onclick: () => copy(r.responseHeaders.map((x) => `${x.name}: ${x.value}`).join("\n")) }, "Copier tout"),
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
  renderOverview();
  renderTech();
  renderIp();
  renderDomain();
  renderCert();
  renderHeaders();
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

  if (!url || !/^https?:$/.test(url.protocol)) {
    document.getElementById("host").textContent = tab.title || "Page non analysable";
    document.getElementById("url").textContent = tab.url || "";
    document.getElementById("tabs").style.display = "none";
    document.getElementById("refresh").style.display = "none";
    document.getElementById("main").replaceChildren(h("div", { class: "empty" }, "Cette page ne peut pas être analysée.", h("br"), h("span", { class: "small faint" }, "Seules les pages http:// et https:// sont prises en charge.")));
    return;
  }

  state.url = url.href;
  state.host = url.hostname.replace(/^\[|\]$/g, "");
  document.getElementById("host").textContent = url.hostname;
  document.getElementById("url").textContent = tab.title ? `${tab.title} — ${url.href}` : url.href;

  for (const b of document.querySelectorAll("#tabs button")) b.addEventListener("click", () => switchTab(b.dataset.tab));
  document.getElementById("refresh").addEventListener("click", () => {
    state.ips = {};
    doRescan();
    if (state.selectedIp) selectIp(state.selectedIp);
  });

  state.record = await browser.runtime.sendMessage({ type: "getTab", tabId: tab.id });
  if (state.record?.hasSignals) state.techs = state.record.techs;
  renderAll();

  if (!state.record?.hasSignals) doRescan();

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
  document.getElementById("main").replaceChildren(errorLine(`Erreur : ${e.message}`));
});
