/* Per-tab collection for the main navigation:
 * headers, contacted IP, redirect chain, TLS info,
 * and signals from the content script for technology detection. */

const tabs = new Map();
const pendingScans = new Map();
const FILTER = { urls: ["<all_urls>"], types: ["main_frame"] };

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

function headerMap(list) {
  const out = {};
  for (const { name, value } of list || []) {
    const k = name.toLowerCase();
    out[k] = k in out ? `${out[k]}\n${value}` : value;
  }
  return out;
}

function processSecurity(info) {
  const certs = (info.certificates || []).map((c, i) => {
    let parsed = null;
    let pem = null;
    if (c.rawDER) {
      try {
        parsed = WT_x509.parse(c.rawDER);
      } catch (e) {
        parsed = { error: e.message };
      }
      if (i === 0) pem = WT_x509.toPem(c.rawDER);
    }
    return {
      subject: c.subject,
      issuer: c.issuer,
      validity: c.validity,
      fingerprint: c.fingerprint,
      serialNumber: c.serialNumber,
      isBuiltInRoot: c.isBuiltInRoot,
      spkiSha256: c.subjectPublicKeyInfoDigest?.sha256,
      parsed,
      pem,
    };
  });
  return {
    state: info.state,
    protocolVersion: info.protocolVersion,
    cipherSuite: info.cipherSuite,
    keaGroupName: info.keaGroupName,
    signatureSchemeName: info.signatureSchemeName,
    secretKeyLength: info.secretKeyLength,
    isExtendedValidation: info.isExtendedValidation,
    certificateTransparencyStatus: info.certificateTransparencyStatus,
    hsts: info.hsts,
    usedEch: info.usedEch,
    usedOcsp: info.usedOcsp,
    usedPrivateDns: info.usedPrivateDns,
    weaknessReasons: info.weaknessReasons,
    errorMessage: info.errorMessage,
    certificates: certs,
  };
}

browser.webRequest.onBeforeRequest.addListener(
  (d) => {
    if (d.tabId < 0) return;
    if (blockedUrl(d.url)) {
      tabs.delete(d.tabId);
      return;
    }
    const r = tabs.get(d.tabId);
    if (r && r.requestId === d.requestId) {
      r.url = d.url;
      return;
    }
    tabs.set(d.tabId, {
      requestId: d.requestId,
      url: d.url,
      startedAt: Date.now(),
      redirects: [],
      techs: [],
    });
  },
  FILTER
);

browser.webRequest.onBeforeRedirect.addListener(
  (d) => {
    const r = tabs.get(d.tabId);
    if (!r || r.requestId !== d.requestId) return;
    r.redirects.push({ url: d.url, status: d.statusCode, ip: d.ip || null });
    r.url = d.redirectUrl;
  },
  FILTER
);

browser.webRequest.onHeadersReceived.addListener(
  async (d) => {
    if (blockedUrl(d.url)) return {};
    const r = tabs.get(d.tabId);
    if (!r || r.requestId !== d.requestId) return {};
    r.statusCode = d.statusCode;
    r.statusLine = d.statusLine;
    r.responseHeaders = d.responseHeaders || [];
    try {
      const info = await browser.webRequest.getSecurityInfo(d.requestId, { certificateChain: true, rawDER: true });
      r.security = processSecurity(info);
    } catch (e) {
      r.securityError = e.message;
    }
    return {};
  },
  FILTER,
  ["blocking", "responseHeaders"]
);

browser.webRequest.onResponseStarted.addListener(
  (d) => {
    const r = tabs.get(d.tabId);
    if (!r || r.requestId !== d.requestId) return;
    r.ip = d.ip || null;
    r.fromCache = d.fromCache;
    r.completedAt = Date.now();
  },
  FILTER
);

browser.webRequest.onErrorOccurred.addListener(
  (d) => {
    const r = tabs.get(d.tabId);
    if (r && r.requestId === d.requestId) r.error = d.error;
  },
  FILTER
);

browser.tabs.onRemoved.addListener((tabId) => tabs.delete(tabId));

async function runDetection(tabId) {
  const r = tabs.get(tabId);
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
  } catch (e) {
    /* URL not compatible with the cookies API */
  }
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
  /* Version probes must not block scan completion (feeds/PHP can take >20s). */
  enrichVersions(r, headers)
    .then(() => updateBadge(tabId, r.techs?.length || 0))
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

  /* Drop any WordPress version that isn't a trusted core semver. */
  if (wp && !WT_versionProbe.okWp(wp.version)) wp.version = null;

  const needsWp = wp && !wp.version;
  const needsPhp = php && !WT_versionProbe.okPhp(php.version);

  const tasks = [];
  if (needsWp) {
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
  if (needsPhp) {
    tasks.push(
      WT_versionProbe.probePhpVersion(pageUrl, headers).then((hit) => {
        if (hit) setTechVersion(php, hit.version, hit.via);
      })
    );
  }
  if (tasks.length) await Promise.all(tasks);
}

function updateBadge(tabId, n) {
  browser.browserAction.setBadgeText({ tabId, text: n ? String(n) : "" }).catch(() => {});
  browser.browserAction.setBadgeBackgroundColor({ tabId, color: "#7c5cff" }).catch(() => {});
  browser.browserAction.setBadgeTextColor?.({ tabId, color: "#ffffff" })?.catch?.(() => {});
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
    await browser.tabs.executeScript(tabId, { code: "globalThis.__wtForceCollect = true;" });
    await browser.tabs.executeScript(tabId, { file: "/src/lib/api.js" });
    await browser.tabs.executeScript(tabId, { file: "/src/lib/settings.js" });
    await browser.tabs.executeScript(tabId, { file: "/src/lib/technologies.js" });
    await browser.tabs.executeScript(tabId, { file: "/src/content/collect.js" });
  } catch (e) {
    pendingScans.delete(tabId);
    throw new Error("Unable to analyze this page: " + e.message);
  }
  await wait;
  return publicRecord(tabId);
}

function publicRecord(tabId) {
  const r = tabs.get(tabId);
  if (!r) return null;
  const { signals, ...rest } = r;
  return {
    ...rest,
    hasSignals: !!signals,
    pageTitle: signals?.title,
  };
}

browser.runtime.onMessage.addListener((msg, sender) => {
  switch (msg.type) {
    case "signals": {
      const tabId = sender.tab?.id;
      if (tabId == null || sender.frameId !== 0) return;
      if (msg.signals?.url && blockedUrl(msg.signals.url)) return;
      let r = tabs.get(tabId);
      if (!r) {
        r = { url: msg.signals.url, redirects: [], techs: [], partial: true };
        tabs.set(tabId, r);
      }
      r.signals = msg.signals;
      return runDetection(tabId).then((techs) => {
        pendingScans.get(tabId)?.();
        pendingScans.delete(tabId);
        return techs;
      });
    }
    case "getTab":
      return Promise.resolve(publicRecord(msg.tabId));
    case "rescan":
      return rescan(msg.tabId);
    case "getSettings":
      return refreshSettings().then(() => settingsCache);
    case "setSettings":
      return WT_settings.set(msg.settings || {}).then((s) => {
        settingsCache = s;
        return s;
      });
    case "dns":
      return WT_lookup.dns(msg.host);
    case "ip":
      return WT_lookup.ipInfo(msg.ip);
    case "domain":
      return WT_lookup.rdapDomain(msg.host).then(
        (data) => ({ data }),
        (e) => ({ error: e.message || String(e) })
      );
  }
});
