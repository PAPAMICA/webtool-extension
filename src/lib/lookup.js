/* Network lookups: DNS (DoH), geolocation / ASN, RDAP (modern whois). */
(() => {
  const TTL = 15 * 60 * 1000;
  const cache = new Map();
  const DOH = "https://cloudflare-dns.com/dns-query";
  const RDAP = "https://rdap.org";
  const DNS_TYPES = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, CAA: 257 };

  const MULTI_SUFFIXES = new Set([
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "net.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "co.kr", "or.kr",
    "com.br", "net.br", "org.br", "gov.br", "com.ar", "com.mx", "com.co", "com.pe",
    "com.cn", "net.cn", "org.cn", "gov.cn", "com.hk", "com.tw", "com.sg", "com.my",
    "co.in", "net.in", "org.in", "co.id", "co.th", "com.vn", "com.ph",
    "co.za", "com.ng", "co.ke", "com.eg", "co.il", "com.tr", "com.sa", "com.ua",
    "gouv.fr", "asso.fr", "nom.fr", "com.fr", "tm.fr", "com.es", "com.pl", "com.pt", "co.at", "or.at",
  ]);

  function cached(key, fn) {
    const c = cache.get(key);
    if (c && Date.now() - c.t < TTL) return c.p;
    const p = fn().catch((e) => {
      cache.delete(key);
      throw e;
    });
    cache.set(key, { t: Date.now(), p });
    return p;
  }

  async function fetchJSON(url, { accept = "application/json", timeout = 10000 } = {}) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeout);
    try {
      const r = await fetch(url, { headers: { accept }, signal: ctrl.signal, credentials: "omit" });
      if (!r.ok) {
        const e = new Error(`HTTP ${r.status}`);
        e.status = r.status;
        throw e;
      }
      return await r.json();
    } catch (e) {
      if (e.name === "AbortError") throw new Error("Timed out");
      throw e;
    } finally {
      clearTimeout(timer);
    }
  }

  const isIPv4 = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s);
  const isIP = (s) => isIPv4(s) || s.includes(":");

  function registrableDomain(host) {
    if (!host || isIP(host)) return null;
    const labels = host.replace(/\.$/, "").toLowerCase().split(".");
    if (labels.length <= 2) return labels.join(".");
    const last2 = labels.slice(-2).join(".");
    return MULTI_SUFFIXES.has(last2) ? labels.slice(-3).join(".") : last2;
  }

  // ───────────── DNS ─────────────
  async function doh(name, type) {
    const j = await fetchJSON(`${DOH}?name=${encodeURIComponent(name)}&type=${type}`, {
      accept: "application/dns-json",
      timeout: 6000,
    });
    return (j.Answer || []).filter((a) => a.type === DNS_TYPES[type]).map((a) => ({ data: a.data, ttl: a.TTL }));
  }

  async function dohChain(name) {
    const j = await fetchJSON(`${DOH}?name=${encodeURIComponent(name)}&type=A`, {
      accept: "application/dns-json",
      timeout: 6000,
    });
    return (j.Answer || []).filter((a) => a.type === 5).map((a) => a.data.replace(/\.$/, ""));
  }

  const settle = (p) => p.then((v) => v, (e) => ({ error: e.message || String(e) }));

  function dns(host) {
    return cached(`dns:${host}`, async () => {
      const domain = registrableDomain(host);
      const zone = domain || host;
      const systemDns =
        typeof browser.dns?.resolve === "function"
          ? settle(browser.dns.resolve(host, ["canonical_name"]))
          : Promise.resolve({ error: "unavailable" });
      const [system, a, aaaa, cname, ns, mx, txt, caa, soa, dmarc] = await Promise.all([
        systemDns,
        settle(doh(host, "A")),
        settle(doh(host, "AAAA")),
        settle(dohChain(host)),
        settle(doh(zone, "NS")),
        settle(doh(zone, "MX")),
        settle(doh(zone, "TXT")),
        settle(doh(zone, "CAA")),
        settle(doh(zone, "SOA")),
        settle(doh(`_dmarc.${zone}`, "TXT")),
      ]);
      return { host, domain, system, a, aaaa, cname, ns, mx, txt, caa, soa, dmarc };
    });
  }

  function reverseName(ip) {
    if (isIPv4(ip)) return ip.split(".").reverse().join(".") + ".in-addr.arpa";
    const [head, tail = ""] = ip.split("::");
    const h = head ? head.split(":") : [];
    const t = tail ? tail.split(":") : [];
    const full = [...h, ...Array(8 - h.length - t.length).fill("0"), ...t];
    return full.map((g) => g.padStart(4, "0")).join("").split("").reverse().join(".") + ".ip6.arpa";
  }

  async function ptr(ip) {
    const r = await doh(reverseName(ip), "PTR");
    return r.map((x) => x.data.replace(/\.$/, ""));
  }

  // ───────────── Geolocation / ASN ─────────────
  async function geo(ip) {
    try {
      const j = await fetchJSON(`https://ipwho.is/${encodeURIComponent(ip)}`, { timeout: 7000 });
      if (j.success === false) throw new Error(j.message || "ipwho.is: failed");
      return {
        source: "ipwho.is",
        ip: j.ip,
        type: j.type,
        country: j.country,
        countryCode: j.country_code,
        region: j.region,
        city: j.city,
        postal: j.postal,
        lat: j.latitude,
        lon: j.longitude,
        timezone: j.timezone?.id,
        asn: j.connection?.asn ? String(j.connection.asn) : null,
        org: j.connection?.org,
        isp: j.connection?.isp,
        asDomain: j.connection?.domain,
      };
    } catch (e) {
      const j = await fetchJSON(`https://ipinfo.io/${encodeURIComponent(ip)}/json`, { timeout: 7000 });
      const m = /^AS(\d+)\s+(.*)$/.exec(j.org || "");
      const [lat, lon] = (j.loc || ",").split(",").map(Number);
      return {
        source: "ipinfo.io",
        ip: j.ip,
        country: j.country,
        countryCode: j.country,
        region: j.region,
        city: j.city,
        postal: j.postal,
        lat,
        lon,
        timezone: j.timezone,
        asn: m ? m[1] : null,
        org: m ? m[2] : j.org,
        isp: m ? m[2] : j.org,
        hostname: j.hostname,
      };
    }
  }

  // ───────────── RDAP ─────────────
  function findEntity(entities, role) {
    for (const e of entities || []) {
      if (e.roles?.includes(role)) return e;
      const n = findEntity(e.entities, role);
      if (n) return n;
    }
    return null;
  }

  function vcard(entity, field) {
    const items = entity?.vcardArray?.[1] || [];
    const it = items.find((i) => i[0] === field);
    if (!it) return null;
    const v = it[3];
    if (field === "adr") return it[1]?.label || (Array.isArray(v) ? v.filter(Boolean).join(", ") : v) || null;
    return Array.isArray(v) ? v.filter(Boolean).join(" ") : v || null;
  }

  function vcardCountry(entity) {
    const items = entity?.vcardArray?.[1] || [];
    const adr = items.find((i) => i[0] === "adr");
    if (!adr) return null;
    return adr[1]?.cc || (Array.isArray(adr[3]) ? adr[3][6] : null) || null;
  }

  function events(j) {
    const out = {};
    for (const e of j.events || []) out[e.eventAction] = e.eventDate;
    return out;
  }

  const RIRS = { ripe: "RIPE NCC", arin: "ARIN", apnic: "APNIC", lacnic: "LACNIC", afrinic: "AFRINIC" };
  function rirOf(j) {
    const s = `${j.port43 || ""} ${j.links?.[0]?.href || ""}`.toLowerCase();
    return Object.entries(RIRS).find(([k]) => s.includes(k))?.[1] || null;
  }

  function rdapIp(ip) {
    return cached(`rdapip:${ip}`, async () => {
      const j = await fetchJSON(`${RDAP}/ip/${encodeURIComponent(ip)}`, {
        accept: "application/rdap+json, application/json",
      });
      const holder = findEntity(j.entities, "registrant") || findEntity(j.entities, "administrative");
      const abuse = findEntity(j.entities, "abuse");
      const ev = events(j);
      return {
        name: j.name,
        handle: j.handle,
        type: j.type,
        country: j.country,
        range: j.startAddress && j.endAddress ? `${j.startAddress} – ${j.endAddress}` : null,
        cidr: (j.cidr0_cidrs || []).map((c) => `${c.v4prefix || c.v6prefix}/${c.length}`),
        org: vcard(holder, "fn"),
        orgHandle: holder?.handle,
        abuseEmail: vcard(abuse, "email"),
        abusePhone: vcard(abuse, "tel"),
        rir: rirOf(j),
        registration: ev.registration,
        lastChanged: ev["last changed"],
        remarks: (j.remarks || []).flatMap((r) => r.description || []).slice(0, 4),
      };
    });
  }

  function parseDomainRdap(j, url) {
    const reg = findEntity(j.entities, "registrar");
    const registrant = findEntity(j.entities, "registrant");
    const abuse = reg ? findEntity(reg.entities, "abuse") : findEntity(j.entities, "abuse");
    const ev = events(j);
    const related = (j.links || []).find((l) => l.rel === "related" && /rdap/.test(l.type || l.href));
    return {
      domain: (j.ldhName || j.unicodeName || "").toLowerCase(),
      handle: j.handle,
      registrar: reg
        ? {
            name: vcard(reg, "fn") || reg.handle,
            ianaId: reg.publicIds?.find((p) => /iana/i.test(p.type))?.identifier || null,
            url: (reg.links || []).find((l) => l.rel === "about" || l.rel === "self")?.href || reg.url || null,
          }
        : null,
      abuseEmail: vcard(abuse, "email") || vcard(reg, "email"),
      abusePhone: vcard(abuse, "tel") || vcard(reg, "tel"),
      registrant: registrant
        ? {
            name: vcard(registrant, "fn"),
            org: vcard(registrant, "org"),
            country: vcardCountry(registrant),
          }
        : null,
      created: ev.registration,
      expires: ev.expiration,
      updated: ev["last changed"],
      status: j.status || [],
      nameservers: (j.nameservers || []).map((n) => (n.ldhName || "").toLowerCase()).filter(Boolean),
      dnssec: j.secureDNS ? !!j.secureDNS.delegationSigned : null,
      whoisServer: j.port43 || null,
      rdapUrl: url,
      relatedUrl: related?.href || null,
    };
  }

  function rdapDomain(host) {
    return cached(`rdapdom:${host}`, async () => {
      const base = registrableDomain(host);
      if (!base) throw new Error("Not a domain name");
      const labels = host.toLowerCase().split(".");
      const baseLen = base.split(".").length;
      const candidates = [base];
      if (labels.length > baseLen) candidates.push(labels.slice(-(baseLen + 1)).join("."));

      let lastErr;
      for (const d of candidates) {
        const url = `${RDAP}/domain/${encodeURIComponent(d)}`;
        try {
          const j = await fetchJSON(url, { accept: "application/rdap+json, application/json" });
          const res = parseDomainRdap(j, url);
          if (res.relatedUrl && (!res.registrant || !res.abuseEmail)) {
            try {
              const r2 = parseDomainRdap(
                await fetchJSON(res.relatedUrl, { accept: "application/rdap+json, application/json", timeout: 6000 }),
                res.relatedUrl
              );
              res.registrant = res.registrant || r2.registrant;
              res.abuseEmail = res.abuseEmail || r2.abuseEmail;
              res.abusePhone = res.abusePhone || r2.abusePhone;
              if (!res.registrar && r2.registrar) res.registrar = r2.registrar;
            } catch (e) {
              /* registrar RDAP is optional */
            }
          }
          return res;
        } catch (e) {
          lastErr = e;
          if (e.status !== 404) break;
        }
      }
      if (lastErr?.status === 404) throw new Error("Domain not found or TLD has no RDAP service");
      throw lastErr || new Error("RDAP unavailable");
    });
  }

  function ipInfo(ip) {
    return cached(`ip:${ip}`, async () => {
      const [g, p, r] = await Promise.all([settle(geo(ip)), settle(ptr(ip)), settle(rdapIp(ip))]);
      return { ip, geo: g, ptr: p, rdap: r };
    });
  }

  // ───────────── Site IP vs forward proxy ─────────────
  /* The TCP peer (webRequest `ip`) is the proxy when one is configured.
   * Geolocation / ASN / RDAP / PTR must describe the origin, never that peer. */

  function expandIPv6(s) {
    let v = s;
    const embedded = /^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/.exec(v);
    if (embedded) {
      const p = embedded[2].split(".").map((n) => Number(n));
      if (p.some((n) => !Number.isInteger(n) || n > 255)) return "";
      const hi = ((p[0] << 8) | p[1]).toString(16).padStart(4, "0");
      const lo = ((p[2] << 8) | p[3]).toString(16).padStart(4, "0");
      v = `${embedded[1]}${hi}:${lo}`;
    }
    const halves = v.split("::");
    if (halves.length > 2) return "";
    let groups;
    if (halves.length === 2) {
      const head = halves[0] ? halves[0].split(":") : [];
      const tail = halves[1] ? halves[1].split(":") : [];
      if (head.length + tail.length > 7) return "";
      groups = [...head, ...Array(8 - head.length - tail.length).fill("0"), ...tail];
    } else groups = v.split(":");
    if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return "";
    return groups.map((g) => g.padStart(4, "0")).join(":");
  }

  function canonicalIp(ip) {
    if (ip == null) return "";
    let s = String(ip).trim().toLowerCase().replace(/^\[|\]$/g, "").replace(/%.*/, "").replace(/\.$/, "");
    if (!s) return "";
    const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(s);
    if (mapped) s = mapped[1];
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) {
      const p = s.split(".").map((n) => Number(n));
      if (p.some((n) => !Number.isInteger(n) || n > 255)) return "";
      return p.join(".");
    }
    if (!s.includes(":")) return "";
    const expanded = expandIPv6(s);
    if (!expanded) return "";
    const v4map = /^0000:0000:0000:0000:0000:ffff:([0-9a-f]{4}):([0-9a-f]{4})$/.exec(expanded);
    if (!v4map) return expanded;
    const hi = parseInt(v4map[1], 16);
    const lo = parseInt(v4map[2], 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }

  function isPublicUnicast(ip) {
    const c = canonicalIp(ip);
    if (!c) return false;
    if (c.includes(":")) {
      if (c === "0000:0000:0000:0000:0000:0000:0000:0000" || c === "0000:0000:0000:0000:0000:0000:0000:0001") return false;
      const head = parseInt(c.slice(0, 4), 16);
      if ((head & 0xfe00) === 0xfc00) return false; /* fc00::/7 */
      if ((head & 0xffc0) === 0xfe80) return false; /* fe80::/10 */
      if ((head & 0xff00) === 0xff00) return false; /* multicast */
      if (c.startsWith("2001:0db8:")) return false;
      return true;
    }
    const p = c.split(".").map(Number);
    const a = p[0];
    const b = p[1];
    const o3 = p[2];
    if (a === 0 || a === 10 || a === 127) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 192 && b === 0 && (o3 === 0 || o3 === 2)) return false;
    if (a === 198 && (b === 18 || b === 19)) return false;
    if (a === 198 && b === 51 && o3 === 100) return false;
    if (a === 203 && b === 0 && o3 === 113) return false;
    if (a >= 224) return false;
    return true;
  }

  /* First public unicast, skipping proxy addresses. `publicOnly` false keeps a
   * private address when nothing public is left (split-horizon / intranet). */
  function pickOriginAddress(list, avoid, publicOnly) {
    const drop = new Set((avoid || []).map(canonicalIp).filter(Boolean));
    const kept = [];
    const seen = new Set();
    for (const raw of list || []) {
      const c = canonicalIp(raw);
      if (!c || drop.has(c) || seen.has(c)) continue;
      seen.add(c);
      kept.push({ display: c.includes(":") ? String(raw).trim().replace(/\.$/, "") : c, pub: isPublicUnicast(c) });
    }
    const chosen = kept.find((x) => x.pub) || (!publicOnly ? kept[0] : null);
    return chosen ? chosen.display : null;
  }

  function normalizeProxy(proxyInfo) {
    if (!proxyInfo || typeof proxyInfo !== "object") return null;
    const type = String(proxyInfo.type || "").toLowerCase();
    if (!type || type === "direct" || type === "none") return null;
    const host = proxyInfo.host ? String(proxyInfo.host).trim().replace(/^\[|\]$/g, "") : "";
    const port = Number(proxyInfo.port);
    return { type, host: host || null, port: Number.isFinite(port) && port > 0 ? port : null };
  }

  async function addressList(name, type) {
    const r = await settle(doh(name, type));
    return Array.isArray(r) ? r.map((x) => x.data) : null;
  }

  async function proxyAddresses(proxy, siteHost) {
    if (!proxy?.host) return [];
    const host = String(proxy.host).replace(/\.$/, "");
    if (siteHost && host.toLowerCase() === String(siteHost).toLowerCase()) return [];
    if (isIP(host)) return [host];
    const [a, aaaa] = await Promise.all([addressList(host, "A"), addressList(host, "AAAA")]);
    return [...(a || []), ...(aaaa || [])];
  }

  async function systemAddresses(host) {
    try {
      if (typeof browser === "undefined" || typeof browser.dns?.resolve !== "function") return [];
      const r = await browser.dns.resolve(host, ["canonical_name"]);
      return Array.isArray(r?.addresses) ? r.addresses : [];
    } catch (e) {
      return [];
    }
  }

  function siteIpResult(ip, ipSource, proxy, avoid) {
    const seen = new Set();
    const uniq = [];
    for (const raw of avoid || []) {
      if (!raw) continue;
      const c = canonicalIp(raw) || String(raw);
      if (seen.has(c)) continue;
      seen.add(c);
      uniq.push(raw);
    }
    return { ip: ip || null, viaProxy: !!proxy, ipSource: ipSource || null, proxy: proxy || null, avoid: uniq };
  }

  async function resolveSiteIpNow(host, connectionIp, proxy) {
    const bare = String(host || "").trim().replace(/\.$/, "").replace(/^\[|\]$/g, "");
    if (!bare) return siteIpResult(proxy ? null : connectionIp, !proxy && connectionIp ? "connection" : null, proxy, proxy ? [connectionIp] : []);
    if (isIP(bare)) {
      const ip = canonicalIp(bare) || bare;
      const avoid = [];
      if (proxy && connectionIp && canonicalIp(connectionIp) !== canonicalIp(ip)) avoid.push(connectionIp);
      if (proxy?.host && canonicalIp(proxy.host) !== canonicalIp(ip)) avoid.push(proxy.host);
      return siteIpResult(ip.includes(":") ? bare : ip, "url", proxy, avoid);
    }

    /* Nothing was contacted (memory cache): the popup already resolves DNS itself. */
    if (!proxy && !connectionIp) return siteIpResult(null, null, null, []);

    const [a, aaaa] = await Promise.all([addressList(bare, "A"), addressList(bare, "AAAA")]);
    const dohOk = a !== null || aaaa !== null;
    const answers = [...(a || []), ...(aaaa || [])];
    const peer = connectionIp ? canonicalIp(connectionIp) : "";
    const matched = !!(peer && answers.some((x) => canonicalIp(x) === peer));

    /* Direct connection whose peer is one of the DoH addresses: keep it. */
    if (!proxy && matched) return siteIpResult(connectionIp, "connection", null, []);
    /* DoH unreachable and no proxy signal: don't guess a mismatch. */
    if (!proxy && !dohOk) return siteIpResult(connectionIp, connectionIp ? "connection" : null, null, []);

    const avoid = [];
    if (connectionIp) avoid.push(connectionIp);
    if (proxy) avoid.push(...(await proxyAddresses(proxy, bare)));

    let picked = dohOk ? pickOriginAddress(answers, avoid, true) : null;
    /* Corporate proxy + internal name: public DoH can't see it. Firefox system DNS can. */
    if (!picked && proxy) picked = pickOriginAddress(await systemAddresses(bare), avoid, false);
    return siteIpResult(picked, picked ? "dns" : null, proxy, avoid);
  }

  function resolveSiteIp(host, opts = {}) {
    const connectionIp = opts.connectionIp || null;
    const proxy = normalizeProxy(opts.proxy || opts.proxyInfo);
    const key = `siteip:${String(host || "")}|${connectionIp || ""}|${proxy ? `${proxy.type}|${proxy.host}|${proxy.port}` : ""}`;
    return cached(key, () => resolveSiteIpNow(host, connectionIp, proxy));
  }

  function hostFromRecord(record) {
    try {
      return new URL(record?.signals?.url || record?.url || "").hostname.replace(/^\[|\]$/g, "");
    } catch (e) {
      return "";
    }
  }

  function commitSiteIp(record, result) {
    record.ip = result.ip || null;
    record.viaProxy = !!result.viaProxy;
    record.proxy = result.proxy || null;
    record.ipSource = result.ipSource || null;
    record.ignoreIps = result.viaProxy || result.ipSource === "dns" ? result.avoid.slice() : [];
    if (record.ignoreIps.length && record.redirects) {
      const drop = new Set(record.ignoreIps.map(canonicalIp).filter(Boolean));
      for (const hop of record.redirects) {
        if (hop.ip && drop.has(canonicalIp(hop.ip))) hop.ip = null;
      }
    }
    record.siteIpReady = true;
    return record;
  }

  const siteIpInflight = new WeakMap();

  function startSiteIp(record) {
    const gen = record.siteIpGen || 1;
    const job = resolveSiteIp(hostFromRecord(record), {
      connectionIp: record.connectionIp || null,
      proxy: record.proxy || null,
    }).then((res) => {
      if (record.siteIpGen !== gen) return record;
      return commitSiteIp(record, res);
    }).catch(() => {
      if (record.siteIpGen !== gen) return record;
      const proxy = record.proxy || null;
      return commitSiteIp(record, {
        ip: proxy ? null : record.connectionIp || null,
        viaProxy: !!proxy,
        ipSource: !proxy && record.connectionIp ? "connection" : null,
        proxy,
        avoid: proxy && record.connectionIp ? [record.connectionIp] : [],
      });
    });
    siteIpInflight.set(record, job);
    return job;
  }

  /* Record the TCP peer. `ip` is filled with the origin once DoH (or system DNS) returns. */
  function observeConnection(record, details) {
    if (!record) return Promise.resolve(null);
    record.connectionIp = details?.ip || null;
    record.proxy = normalizeProxy(details?.proxyInfo);
    record.viaProxy = !!record.proxy;
    record.siteIpReady = false;
    record.siteIpGen = (record.siteIpGen || 0) + 1;
    if (record.viaProxy) record.ip = null;
    return startSiteIp(record);
  }

  function ensureSiteIp(record) {
    if (!record) return Promise.resolve(null);
    if (record.siteIpReady) return Promise.resolve(record);
    const pending = siteIpInflight.get(record);
    if (pending) return pending;
    if (!record.completedAt && !record.connectionIp && !record.proxy && !record.viaProxy) return Promise.resolve(record);
    if (!record.connectionIp && record.ip && !record.viaProxy) record.connectionIp = record.ip;
    record.siteIpGen = (record.siteIpGen || 0) + 1;
    return startSiteIp(record);
  }

  globalThis.WT_lookup = {
    dns,
    ipInfo,
    rdapDomain,
    registrableDomain,
    isIP,
    canonicalIp,
    normalizeProxy,
    resolveSiteIp,
    observeConnection,
    ensureSiteIp,
  };
})();
