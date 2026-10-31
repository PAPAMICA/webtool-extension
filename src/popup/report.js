/* Build and export full scan reports (JSON + printable HTML → PDF). */
(() => {
  function esc(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function downloadBlob(filename, blob) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
  }

  function slugHost(host) {
    return String(host || "report").replace(/[^a-z0-9.-]+/gi, "_").replace(/^\.+|\.+$/g, "") || "report";
  }

  function stamp() {
    const d = new Date();
    const p = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`;
  }

  function exportJson(report) {
    const name = `webtool-${slugHost(report.site?.host)}-${stamp()}.json`;
    downloadBlob(name, new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
    return name;
  }

  function section(title, inner) {
    if (!inner) return "";
    return `<section class="sec"><h2>${esc(title)}</h2>${inner}</section>`;
  }

  function table(rows) {
    const body = rows
      .filter((r) => r && r[1] != null && r[1] !== "")
      .map(([k, v]) => `<tr><th>${esc(k)}</th><td>${typeof v === "string" && v.includes("<") ? v : esc(v)}</td></tr>`)
      .join("");
    return body ? `<table class="kv">${body}</table>` : "";
  }

  function pre(text) {
    return `<pre>${esc(text)}</pre>`;
  }

  function buildHtml(report, { autoPrint = false } = {}) {
    const s = report.site || {};
    const techs = report.technologies || [];
    const byCat = new Map();
    for (const t of techs) {
      const cat = t.category || "Misc";
      if (!byCat.has(cat)) byCat.set(cat, []);
      byCat.get(cat).push(t);
    }
    const techHtml = [...byCat.entries()]
      .map(
        ([cat, items]) =>
          `<h3>${esc(cat)} <span class="n">${items.length}</span></h3>
           <table class="list"><thead><tr><th>Name</th><th>Version</th><th>Evidence</th><th>Confidence</th></tr></thead><tbody>
           ${items
             .map(
               (t) =>
                 `<tr><td>${esc(t.name)}${t.implied ? ` <em class="muted">(via ${esc(t.impliedBy)})</em>` : ""}</td>
                  <td class="mono">${esc(t.version || t.tag || "—")}</td>
                  <td class="muted">${esc((t.via || []).join(", "))}</td>
                  <td>${t.confidence != null ? esc(t.confidence) + "%" : "—"}</td></tr>`
             )
             .join("")}
           </tbody></table>`
      )
      .join("");

    const ip = report.ip || {};
    const geo = ip.geo || {};
    const dns = report.dns || {};
    const dom = report.domain || {};
    const cert = report.certificate || {};
    const leaf = (cert.certificates || [])[0];
    const secHeaders = report.securityHeaders || [];
    const headers = report.headers || {};

    const dnsRec = (label, arr, mapFn) => {
      if (!arr || arr.error) return [label, arr?.error ? `Error: ${arr.error}` : ""];
      if (!arr.length) return null;
      return [label, arr.map(mapFn || ((x) => x.data)).join("\n")];
    };

    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>WebTool Inspector — ${esc(s.host || "report")}</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 32px 40px 64px;
    font: 13px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    color: #1a1f2e; background: #fff;
  }
  header.top {
    display: flex; justify-content: space-between; align-items: flex-start; gap: 16px;
    border-bottom: 3px solid #7c5cff; padding-bottom: 16px; margin-bottom: 28px;
  }
  .brand { font-size: 11px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; color: #7c5cff; }
  h1 { margin: 4px 0 6px; font-size: 22px; letter-spacing: -.02em; }
  .sub { color: #5f6880; font-size: 12px; word-break: break-all; }
  .actions { display: flex; gap: 8px; flex-wrap: wrap; }
  button, .btn {
    font: inherit; font-weight: 600; font-size: 12px; padding: 8px 14px; border-radius: 8px;
    border: 1px solid #d0d5e2; background: #f4f5fa; color: #1a1f2e; cursor: pointer;
  }
  button.primary { background: #7c5cff; border-color: #7c5cff; color: #fff; }
  .sec { margin: 0 0 28px; break-inside: avoid; }
  h2 {
    margin: 0 0 10px; font-size: 13px; text-transform: uppercase; letter-spacing: .06em;
    color: #5f6880; border-bottom: 1px solid #e1e4ee; padding-bottom: 6px;
  }
  h3 { margin: 14px 0 6px; font-size: 12.5px; }
  h3 .n { color: #8a93a8; font-weight: 600; }
  table.kv, table.list { width: 100%; border-collapse: collapse; }
  table.kv th {
    width: 180px; text-align: left; vertical-align: top; padding: 5px 12px 5px 0;
    color: #5f6880; font-weight: 500; font-size: 12px;
  }
  table.kv td, table.list td, table.list th {
    vertical-align: top; padding: 5px 8px; border-top: 1px solid #eef0f6; font-size: 12.5px;
  }
  table.list th { text-align: left; color: #5f6880; font-weight: 600; font-size: 11px; border-top: 0; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11.5px; white-space: pre-wrap; word-break: break-all; }
  pre {
    margin: 0; padding: 10px 12px; background: #f5f6fa; border: 1px solid #e1e4ee; border-radius: 8px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 10.5px;
    white-space: pre-wrap; word-break: break-all; max-height: none;
  }
  .muted { color: #8a93a8; }
  .pill {
    display: inline-block; padding: 2px 8px; border-radius: 999px; background: #f0f1f7;
    border: 1px solid #e1e4ee; font-size: 11px; margin: 0 6px 6px 0;
  }
  .ok { color: #15803d; } .warn { color: #b45309; } .bad { color: #b91c1c; }
  footer { margin-top: 40px; padding-top: 12px; border-top: 1px solid #e1e4ee; color: #8a93a8; font-size: 11px; }
  @media print {
    body { padding: 12mm 14mm; }
    .actions, .no-print { display: none !important; }
    a { color: inherit; text-decoration: none; }
    .sec { break-inside: avoid; }
    pre { border: 1px solid #ccc; background: #fafafa; }
  }
</style>
</head>
<body>
<header class="top">
  <div>
    <div class="brand">WebTool Inspector</div>
    <h1>${esc(s.host || "Report")}</h1>
    <div class="sub">${esc(s.url || "")}</div>
    <div class="sub">Generated ${esc(report.meta?.generatedAt || "")}${report.meta?.pageTitle ? " · " + esc(report.meta.pageTitle) : ""}</div>
  </div>
  <div class="actions no-print">
    <button class="primary" onclick="window.print()">Print / Save as PDF</button>
  </div>
</header>

${section(
  "Summary",
  `<div>${(report.summary?.pills || []).map((p) => `<span class="pill">${esc(p)}</span>`).join("")}</div>
   ${table([
     ["Technologies", String(techs.length)],
     ["Selected IP", ip.selected || ""],
     ["Organization", geo.org || geo.isp || ""],
     ["Country", [geo.city, geo.country].filter(Boolean).join(", ")],
     ["TLS", cert.state || ""],
     ["Security headers", report.summary?.securityScore || ""],
   ])}`
)}

${section(
  "Technologies",
  techs.length
    ? techHtml
    : `<p class="muted">No technologies detected.</p>`
)}

${section(
  "IP / ASN",
  table([
    ["IP", ip.selected || ""],
    ["Contacted IP", ip.contacted || ""],
    ["Reverse DNS", (ip.ptr || []).join(", ")],
    ["Country", geo.country ? `${geo.country} (${geo.countryCode || ""})` : ""],
    ["Region / city", [geo.region, geo.city, geo.postal].filter(Boolean).join(", ")],
    ["Coordinates", geo.lat != null ? `${geo.lat}, ${geo.lon}` : ""],
    ["ASN", geo.asn != null ? `AS${geo.asn}` : ""],
    ["Organization", geo.org || ""],
    ["ISP", geo.isp || ""],
    ["Source", geo.source || ""],
    ["RDAP network", ip.rdap?.name || ""],
    ["RDAP range", ip.rdap?.range || ""],
    ["RDAP holder", ip.rdap?.org || ""],
  ])
)}

${section(
  "DNS",
  table([
    ["Host", dns.host || s.host || ""],
    ["Registrable domain", dns.domain || ""],
    dnsRec("A", dns.a),
    dnsRec("AAAA", dns.aaaa),
    dnsRec("CNAME", dns.cname, (x) => (typeof x === "string" ? x : x.data)),
    dnsRec("NS", dns.ns),
    dnsRec("MX", dns.mx),
    dnsRec("TXT", dns.txt),
    dnsRec("CAA", dns.caa),
    dnsRec("SOA", dns.soa),
    dnsRec("DMARC", dns.dmarc),
  ].filter(Boolean))
)}

${section(
  "Domain (RDAP)",
  dom.error
    ? `<p class="bad">${esc(dom.error)}</p>`
    : table([
        ["Domain", dom.domain || ""],
        ["Registrar", dom.registrar || ""],
        ["Created", dom.created || ""],
        ["Updated", dom.updated || ""],
        ["Expires", dom.expires || ""],
        ["DNSSEC", dom.dnssec == null ? "" : dom.dnssec ? "Enabled" : "Unsigned"],
        ["Nameservers", (dom.nameservers || []).join("\n")],
        ["Statuses", (dom.status || []).join("\n")],
      ])
)}

${section(
  "Certificate",
  table([
    ["State", cert.state || ""],
    ["Protocol", cert.protocolVersion || ""],
    ["Cipher", cert.cipherSuite || ""],
    ["Key exchange", cert.keaGroupName || ""],
    ["HSTS", cert.hsts == null ? "" : cert.hsts ? "Yes" : "No"],
    ["Note", cert.note || ""],
    leaf ? ["Subject", leaf.subject || ""] : null,
    leaf ? ["Issuer", leaf.issuer || ""] : null,
    leaf ? ["Valid from", leaf.validFrom || ""] : null,
    leaf ? ["Valid to", leaf.validTo || ""] : null,
    leaf ? ["Days left", leaf.daysLeft != null ? String(leaf.daysLeft) : ""] : null,
    leaf ? ["Serial", leaf.serialNumber || ""] : null,
    leaf ? ["SHA-256", leaf.sha256 || ""] : null,
    leaf ? ["SAN", (leaf.san || []).join("\n")] : null,
    leaf ? ["Public key", leaf.publicKey || ""] : null,
  ].filter(Boolean)) +
    (leaf?.pem ? `<h3>PEM</h3>${pre(leaf.pem)}` : "") +
    ((cert.certificates || []).length > 1
      ? `<h3>Chain</h3><ol>${cert.certificates
          .map((c, i) => `<li><strong>${esc(c.subject || "cert " + i)}</strong><div class="muted">${esc(c.issuer || "")}</div></li>`)
          .join("")}</ol>`
      : "")
)}

${section(
  "Security headers",
  `<table class="list"><thead><tr><th>Header</th><th>Status</th><th>Value</th></tr></thead><tbody>
   ${secHeaders
     .map(
       (x) =>
         `<tr><td>${esc(x.label)}</td><td class="${esc(x.statusClass || "")}">${esc(x.status)}</td>
          <td class="mono">${esc(x.value || x.note || "—")}</td></tr>`
     )
     .join("")}
   </tbody></table>`
)}

${section(
  "Response headers",
  (headers.redirects || []).length
    ? `<h3>Redirects</h3><ol>${headers.redirects
        .map((r) => `<li><span class="mono">${esc(r.status)}</span> ${esc(r.url)}</li>`)
        .join("")}</ol>
        <p><span class="mono">${esc(headers.statusLine || headers.statusCode || "")}</span> ${esc(headers.finalUrl || "")}</p>`
    : `<p><span class="mono">${esc(headers.statusLine || headers.statusCode || "")}</span></p>`
) +
  (headers.raw?.length
    ? section("Raw headers", pre(headers.raw.map((h) => `${h.name}: ${h.value}`).join("\n")))
    : "")
}

<footer>
  Generated by WebTool Inspector · ${esc(report.meta?.extensionVersion || "")} ·
  Report for local use — third-party lookups may have been used (DNS/RDAP/geo).
</footer>
${autoPrint ? "<script>setTimeout(function(){window.print();},400);</script>" : ""}
</body>
</html>`;
  }

  async function exportHtml(report, { print } = {}) {
    const html = buildHtml(report, { autoPrint: !!print });
    const name = `webtool-${slugHost(report.site?.host)}-${stamp()}.html`;
    const blob = new Blob([html], { type: "text/html;charset=utf-8" });
    const url = URL.createObjectURL(blob);

    try {
      await browser.tabs.create({ url });
    } catch (e) {
      downloadBlob(name, blob);
    }
    setTimeout(() => URL.revokeObjectURL(url), 120000);
    return name;
  }

  globalThis.WT_report = { exportJson, exportHtml, buildHtml, downloadBlob };
})();
