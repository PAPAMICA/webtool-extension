/* Requêtes réseau : DNS (DoH), géolocalisation / ASN, RDAP (whois moderne). */
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
      if (e.name === "AbortError") throw new Error("Délai dépassé");
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
      const [system, a, aaaa, cname, ns, mx, txt, caa, soa, dmarc] = await Promise.all([
        settle(browser.dns.resolve(host, ["canonical_name"])),
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

  // ───────────── Géolocalisation / ASN ─────────────
  async function geo(ip) {
    try {
      const j = await fetchJSON(`https://ipwho.is/${encodeURIComponent(ip)}`, { timeout: 7000 });
      if (j.success === false) throw new Error(j.message || "ipwho.is: échec");
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
      if (!base) throw new Error("Pas de nom de domaine");
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
              /* le RDAP du registrar est optionnel */
            }
          }
          return res;
        } catch (e) {
          lastErr = e;
          if (e.status !== 404) break;
        }
      }
      if (lastErr?.status === 404) throw new Error("Domaine introuvable ou TLD sans service RDAP");
      throw lastErr || new Error("RDAP indisponible");
    });
  }

  function ipInfo(ip) {
    return cached(`ip:${ip}`, async () => {
      const [g, p, r] = await Promise.all([settle(geo(ip)), settle(ptr(ip)), settle(rdapIp(ip))]);
      return { ip, geo: g, ptr: p, rdap: r };
    });
  }

  globalThis.WT_lookup = { dns, ipInfo, rdapDomain, registrableDomain, isIP };
})();
