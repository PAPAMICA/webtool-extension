/* Chrome MV3 service worker — same features as Firefox background, without getSecurityInfo. */
importScripts(
  "/src/lib/api.js",
  "/src/lib/settings.js",
  "/src/lib/technologies.js",
  "/src/lib/detector.js",
  "/src/lib/x509.js",
  "/src/lib/lookup.js",
  "/src/lib/version-probe.js"
);

const tabs = new Map();
const pendingScans = new Map();
const FILTER = { urls: ["<all_urls>"], types: ["main_frame"] };
const STORE_KEY = (id) => `tab:${id}`;

let settingsCache = { autoScan: true, blacklist: [] };
async function refreshSettings() {
  try {
    settingsCache = await WT_settings.get();
  } catch (e) {}
}
refreshSettings();
browser.storage?.onChanged?.addListener((changes, area) => {
  if (area === "local" && changes[WT_settings.KEY]) refreshSettings();
});
function blockedUrl(url) {
  return WT_settings.isBlacklisted(url, settingsCache.blacklist);
}

async function persist(tabId) {
  const r = tabs.get(tabId);
  if (!r) {
    await browser.storage.session.remove(STORE_KEY(tabId));
    return;
  }
  const { signals, ...rest } = r;
  const slim = {
    ...rest,
    signals: signals
      ? {
          url: signals.url,
          title: signals.title,
          feeds: signals.feeds || [],
          src: (signals.src || []).slice(0, 400),
          meta: signals.meta || {},
          js: signals.js || {},
          dom: signals.dom || {},
          html: typeof signals.html === "string" ? signals.html.slice(0, 120000) : "",
        }
      : null,
  };
  try {
    await browser.storage.session.set({ [STORE_KEY(tabId)]: slim });
  } catch (e) {
    /* quota — drop html */
    if (slim.signals) slim.signals.html = "";
    try {
      await browser.storage.session.set({ [STORE_KEY(tabId)]: slim });
    } catch (e2) {}
  }
}

async function loadTab(tabId) {
  if (tabs.has(tabId)) return tabs.get(tabId);
  try {
    const bag = await browser.storage.session.get(STORE_KEY(tabId));
    const r = bag[STORE_KEY(tabId)];
    if (r) {
      tabs.set(tabId, r);
      return r;
    }
  } catch (e) {}
  return null;
}

function headerMap(list) {
  const out = {};
  for (const { name, value } of list || []) {
    const k = name.toLowerCase();
    out[k] = k in out ? `${out[k]}\n${value}` : value;
  }
  return out;
}

function limitedSecurity(url, responseHeaders) {
  const https = /^https:/i.test(url || "");
  const hs = headerMap(responseHeaders);
  return {
    limited: true,
    source: "chrome",
    state: https ? "secure" : "insecure",
    protocolVersion: https ? "TLS" : null,
    hsts: !!hs["strict-transport-security"],
    note: "Chrome does not expose the live TLS handshake to extensions. Showing connection hints from the URL and headers; Certificate Transparency can fill certificate details.",
    certificates: [],
  };
}

/** Best-effort leaf cert from crt.sh (CT logs) — not the live connection cert. */
async function enrichCertTransparency(record) {
  if (!record || record.security?.state === "insecure") return;
  const host = (() => {
    try {
      return new URL(record.signals?.url || record.url).hostname;
    } catch (e) {
      return null;
    }
  })();
  if (!host || WT_lookup.isIP(host)) return;
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 8000);
    const r = await fetch(`https://crt.sh/?q=${encodeURIComponent(host)}&output=json`, {
      signal: ctrl.signal,
      credentials: "omit",
    });
    clearTimeout(timer);
    if (!r.ok) return;
    const rows = await r.json();
    if (!Array.isArray(rows) || !rows.length) return;
    const sorted = [...rows].sort((a, b) => String(b.not_before).localeCompare(String(a.not_before)));
    const best =
      sorted.find((x) =>
        String(x.name_value || "")
          .split(/\n/)
          .some((n) => n.trim().toLowerCase() === host.toLowerCase())
      ) || sorted[0];
    const names = String(best.name_value || "")
      .split(/\n/)
      .map((s) => s.trim())
      .filter(Boolean);
    const start = best.not_before ? Date.parse(best.not_before.replace(" ", "T") + "Z") : null;
    const end = best.not_after ? Date.parse(best.not_after.replace(" ", "T") + "Z") : null;
    record.security = {
      ...record.security,
      certificates: [
        {
          subject: `CN=${names[0] || host}`,
          issuer: best.issuer_name || "Certificate Transparency",
          validity: {
            start: Number.isFinite(start) ? start : Date.now(),
            end: Number.isFinite(end) ? end : Date.now(),
          },
          serialNumber: best.serial_number || null,
          fingerprint: null,
          parsed: { san: names, ct: true, id: best.id },
          pem: null,
          fromCt: true,
        },
      ],
      certificateTransparencyStatus: "ct_log",
    };
  } catch (e) {
    record.security = {
      ...record.security,
      ctError: e.message || String(e),
    };
  }
}

browser.webRequest.onBeforeRequest.addListener((d) => {
  if (d.tabId < 0) return;
  if (blockedUrl(d.url)) {
    tabs.delete(d.tabId);
    browser.storage.session.remove(STORE_KEY(d.tabId)).catch(() => {});
    return;
  }
  const r = tabs.get(d.tabId);
  if (r && r.requestId === d.requestId) {
    r.url = d.url;
    persist(d.tabId);
    return;
  }
  tabs.set(d.tabId, {
    requestId: d.requestId,
    url: d.url,
    startedAt: Date.now(),
    redirects: [],
    techs: [],
  });
  persist(d.tabId);
}, FILTER);

browser.webRequest.onBeforeRedirect.addListener((d) => {
  const r = tabs.get(d.tabId);
  if (!r || r.requestId !== d.requestId) return;
  r.redirects.push({ url: d.url, status: d.statusCode, ip: d.ip || null });
  r.url = d.redirectUrl;
  persist(d.tabId);
}, FILTER);

browser.webRequest.onHeadersReceived.addListener(
  (d) => {
    if (blockedUrl(d.url)) return;
    const r = tabs.get(d.tabId);
    if (!r || r.requestId !== d.requestId) return;
    r.statusCode = d.statusCode;
    r.statusLine = d.statusLine;
    r.responseHeaders = d.responseHeaders || [];
    r.security = limitedSecurity(d.url, r.responseHeaders);
    persist(d.tabId);
  },
  FILTER,
  ["responseHeaders", "extraHeaders"]
);

browser.webRequest.onResponseStarted.addListener((d) => {
  const r = tabs.get(d.tabId);
  if (!r || r.requestId !== d.requestId) return;
  r.ip = d.ip || null;
  r.fromCache = d.fromCache;
  r.completedAt = Date.now();
  persist(d.tabId);
}, FILTER);

browser.webRequest.onErrorOccurred.addListener((d) => {
  const r = tabs.get(d.tabId);
  if (r && r.requestId === d.requestId) {
    r.error = d.error;
    persist(d.tabId);
  }
}, FILTER);

browser.tabs.onRemoved.addListener((tabId) => {
  tabs.delete(tabId);
  browser.storage.session.remove(STORE_KEY(tabId)).catch(() => {});
});

async function runDetection(tabId) {
  const r = await loadTab(tabId);
  if (!r) return [];
  const s = r.signals || {};
  const headers = headerMap(r.responseHeaders);
  const cookies = {};
  for (const line of (headers["set-cookie"] || "").split("\n")) {
    const m = /^\s*([^=;\s]+)=([^;]*)/.exec(line);
    if (m) cookies[m[1]] = m[2];
  }
  try {
    const url = s.url || r.url;
    if (url) {
      for (const c of await browser.cookies.getAll({ url })) cookies[c.name] = c.value;
    }
  } catch (e) {}

  if (!r.security) r.security = limitedSecurity(s.url || r.url, r.responseHeaders);

  try {
    r.techs = WT_detect({
      ...s,
      url: s.url || r.url,
      headers,
      cookies,
      src: Array.isArray(s.src) ? s.src : [],
      meta: s.meta && typeof s.meta === "object" ? s.meta : {},
      js: s.js && typeof s.js === "object" ? s.js : {},
      dom: s.dom && typeof s.dom === "object" ? s.dom : {},
      html: typeof s.html === "string" ? s.html : "",
      certIssuer: r.security?.certificates?.[0]?.issuer,
    });
  } catch (e) {
    console.error("WT_detect failed", e);
    r.techs = [];
    r.detectError = e.message || String(e);
  }
  updateBadge(tabId, r.techs.length);
  persist(tabId);

  Promise.all([
    enrichVersions(r, headers),
    enrichCertTransparency(r),
  ])
    .then(() => {
      updateBadge(tabId, r.techs?.length || 0);
      persist(tabId);
    })
    .catch(() => {});

  return r.techs;
}

function findTech(techs, name) {
  return (techs || []).find((t) => t.name === name);
}

function setTechVersion(tech, version, via) {
  if (!tech || !version) return false;
  if (tech.version === version) {
    if (via && !tech.via.includes(via)) tech.via.push(via);
    return false;
  }
  tech.version = version;
  if (via && !tech.via.includes(via)) tech.via.push(via);
  return true;
}

async function enrichVersions(record, headers) {
  if (!record?.techs?.length) return;
  const pageUrl = record.signals?.url || record.url;
  if (!pageUrl || !/^https?:/i.test(pageUrl)) return;

  const wp = findTech(record.techs, "WordPress");
  const php = findTech(record.techs, "PHP");
  if (wp && !WT_versionProbe.okWp(wp.version)) wp.version = null;

  const tasks = [];
  if (wp && !wp.version) {
    tasks.push(
      WT_versionProbe
        .probeWordPressVersion(pageUrl, { feeds: record.signals?.feeds || [], html: record.signals?.html || "" })
        .then((hit) => {
          const v = hit && WT_versionProbe.okWp(hit.version);
          if (v) setTechVersion(wp, v, hit.via);
          else wp.version = null;
        })
    );
  }
  if (php && !WT_versionProbe.okPhp(php.version)) {
    tasks.push(
      WT_versionProbe.probePhpVersion(pageUrl, headers).then((hit) => {
        if (hit) setTechVersion(php, hit.version, hit.via);
      })
    );
  }
  if (tasks.length) await Promise.all(tasks);
}

function updateBadge(tabId, n) {
  const api = browser.action || browser.browserAction;
  api.setBadgeText({ tabId, text: n ? String(n) : "" }).catch?.(() => {});
  api.setBadgeBackgroundColor({ tabId, color: "#7c5cff" }).catch?.(() => {});
  api.setBadgeTextColor?.({ tabId, color: "#ffffff" })?.catch?.(() => {});
}

async function rescan(tabId) {
  await refreshSettings();
  let tabUrl = tabs.get(tabId)?.url;
  try {
    const t = await browser.tabs.get(tabId);
    tabUrl = t.url || tabUrl;
  } catch (e) {}
  if (tabUrl && blockedUrl(tabUrl)) {
    throw new Error("This site is on your blacklist. Remove it in Settings to scan.");
  }

  const wait = new Promise((resolve) => {
    const timer = setTimeout(() => {
      pendingScans.delete(tabId);
      resolve(false);
    }, 12000);
    pendingScans.set(tabId, () => {
      clearTimeout(timer);
      resolve(true);
    });
  });
  try {
    await browser.scripting.executeScript({
      target: { tabId },
      func: () => {
        globalThis.__wtForceCollect = true;
      },
    });
    await browser.scripting.executeScript({ target: { tabId }, files: ["/src/lib/api.js"] });
    await browser.scripting.executeScript({ target: { tabId }, files: ["/src/lib/settings.js"] });
    await browser.scripting.executeScript({ target: { tabId }, files: ["/src/lib/technologies.js"] });
    await browser.scripting.executeScript({ target: { tabId }, files: ["/src/content/collect.js"] });
  } catch (e) {
    pendingScans.delete(tabId);
    throw new Error("Unable to analyze this page: " + e.message);
  }
  await wait;
  return publicRecord(tabId);
}

async function publicRecord(tabId) {
  const r = await loadTab(tabId);
  if (!r) return null;
  const { signals, ...rest } = r;
  return {
    ...rest,
    hasSignals: !!signals,
    pageTitle: signals?.title,
  };
}

browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const reply = (p) => {
    Promise.resolve(p).then(sendResponse, (e) => sendResponse({ error: e.message || String(e) }));
    return true;
  };

  switch (msg.type) {
    case "signals": {
      const tabId = sender.tab?.id;
      if (tabId == null || (sender.frameId != null && sender.frameId !== 0)) return;
      if (msg.signals?.url && blockedUrl(msg.signals.url)) return;
      let r = tabs.get(tabId);
      if (!r) {
        r = { url: msg.signals.url, redirects: [], techs: [], partial: true };
        tabs.set(tabId, r);
      }
      r.signals = msg.signals;
      if (!r.security) r.security = limitedSecurity(msg.signals.url, r.responseHeaders);
      persist(tabId);
      return reply(
        runDetection(tabId).then((techs) => {
          pendingScans.get(tabId)?.();
          pendingScans.delete(tabId);
          return techs;
        })
      );
    }
    case "getTab":
      return reply(publicRecord(msg.tabId));
    case "rescan":
      return reply(rescan(msg.tabId));
    case "getSettings":
      return reply(refreshSettings().then(() => settingsCache));
    case "setSettings":
      return reply(
        WT_settings.set(msg.settings || {}).then((s) => {
          settingsCache = s;
          return s;
        })
      );
    case "dns":
      return reply(WT_lookup.dns(msg.host));
    case "ip":
      return reply(WT_lookup.ipInfo(msg.ip));
    case "domain":
      return reply(
        WT_lookup.rdapDomain(msg.host).then(
          (data) => ({ data }),
          (e) => ({ error: e.message || String(e) })
        )
      );
    case "certCt":
      return reply(
        loadTab(msg.tabId).then(async (r) => {
          if (!r) return null;
          await enrichCertTransparency(r);
          await persist(msg.tabId);
          return r.security;
        })
      );
  }
});
