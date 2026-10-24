/* Collecte, par onglet, des informations sur la navigation principale :
 * en-têtes, IP réellement contactée, chaîne de redirection, infos TLS
 * et signaux transmis par le content script pour la détection des technos. */

const tabs = new Map();
const pendingScans = new Map();
const FILTER = { urls: ["<all_urls>"], types: ["main_frame"] };

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
    for (const c of await browser.cookies.getAll({ url: s.url || r.url })) cookies[c.name] = c.value;
  } catch (e) {
    /* URL non compatible avec l'API cookies */
  }
  r.techs = WT_detect({
    ...s,
    url: s.url || r.url,
    headers,
    cookies,
    certIssuer: r.security?.certificates?.[0]?.issuer,
  });
  updateBadge(tabId, r.techs.length);
  return r.techs;
}

function updateBadge(tabId, n) {
  browser.browserAction.setBadgeText({ tabId, text: n ? String(n) : "" }).catch(() => {});
  browser.browserAction.setBadgeBackgroundColor({ tabId, color: "#7c5cff" }).catch(() => {});
  browser.browserAction.setBadgeTextColor?.({ tabId, color: "#ffffff" })?.catch?.(() => {});
}

async function rescan(tabId) {
  const wait = new Promise((resolve) => {
    const timer = setTimeout(() => {
      pendingScans.delete(tabId);
      resolve(false);
    }, 5000);
    pendingScans.set(tabId, () => {
      clearTimeout(timer);
      resolve(true);
    });
  });
  try {
    await browser.tabs.executeScript(tabId, { file: "/src/lib/technologies.js" });
    await browser.tabs.executeScript(tabId, { file: "/src/content/collect.js" });
  } catch (e) {
    pendingScans.delete(tabId);
    throw new Error("Impossible d'analyser cette page : " + e.message);
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
      let r = tabs.get(tabId);
      if (!r) {
        r = { url: msg.signals.url, redirects: [], techs: [], partial: true };
        tabs.set(tabId, r);
      }
      r.signals = msg.signals;
      return runDetection(tabId).then(() => {
        pendingScans.get(tabId)?.();
        pendingScans.delete(tabId);
      });
    }
    case "getTab":
      return Promise.resolve(publicRecord(msg.tabId));
    case "rescan":
      return rescan(msg.tabId);
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
