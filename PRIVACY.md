# Privacy Policy — WebTool Inspector

**Last updated:** 2026-10-24  
**Developer:** PAPAMICA  
**Contact:** https://papamica.com  
**Source:** https://github.com/PAPAMICA/webtool-extension

## Summary

WebTool Inspector helps you inspect the website currently open in your browser (technologies, IP / ASN, DNS, WHOIS / RDAP, TLS certificate, HTTP headers).  
It does **not** create user accounts, does **not** sell data, and does **not** use advertising or tracking SDKs.

## Data handled locally

The following stays in your browser (extension memory for the active tab / session):

- Page HTML signals used for technology detection (scripts, meta tags, cookies names, DOM hints)
- HTTP response headers and redirect chain captured during page load
- TLS certificate details obtained via Firefox `webRequest.getSecurityInfo`
- Technology match results shown in the popup

No browsing history database is built or synced by this extension.

## Data transmitted off-device

When you open the popup on a site, the extension may send **network lookups** so the Overview / IP / Domain tabs can work. Only technical identifiers needed for those lookups are sent:

| Destination | What is sent | Why |
| --- | --- | --- |
| `cloudflare-dns.com` (DNS-over-HTTPS) | Host / domain names of the current site | Resolve A / AAAA / NS / MX / TXT / CAA / SOA / DMARC |
| `rdap.org` (and related RDAP servers) | Domain or IP | WHOIS-like registration data |
| `ipwho.is` | Contacted IP address | Geolocation, ASN / ISP |
| `ipinfo.io` | Contacted IP address (fallback) | Geolocation / ASN if the primary provider fails |
| Same origin as the current tab | Public paths (e.g. WordPress feed / login) | Best-effort version probes |
| `cdn.simpleicons.org` | Technology icon slug | Display technology logos in the UI |
| `www.google.com/s2/favicons` | Technology website hostname | Favicon fallback when no Simple Icon exists |

These requests are made with `credentials: "omit"` where applicable. The extension does **not** attach your Firefox account, cookies from other sites, or form passwords to those requests.

OSINT quick links (Shodan, Censys, VirusTotal, crt.sh, SSL Labs, etc.) only open in a new tab when **you** click them; the extension does not call those APIs in the background.

## Permissions justification

- **Access your data for all websites** (`<all_urls>`, content scripts): read page signals for technology detection and run same-origin version probes.
- **webRequest / webRequestBlocking**: capture response headers, redirect chain, and TLS security info for the tab you inspect.
- **tabs**: know which tab / URL is being inspected.
- **dns**: reverse DNS / browser DNS helpers when available.
- **cookies**: detect technology signatures that rely on cookie **names** (values are not uploaded).

## Data collection categories (Firefox)

Declared in `manifest.json` as required:

- **Browsing activity** — domain / host / IP of the site you inspect, sent to the lookup services above
- **Website content** — page and header signals used for detection; public same-origin fetches for version probes

## Retention

The extension does not operate a backend that stores your lookups. Retention on third-party services (Cloudflare, RDAP operators, ipwho.is, ipinfo.io, Simple Icons / Google favicon CDN) is governed by **their** policies. Results may be cached briefly in memory inside the extension to avoid repeating the same request while the popup is open.

## Children

This extension is not directed at children and does not knowingly collect children’s personal information.

## Changes

Material changes to this policy will be reflected in this file and in the extension version notes on [addons.mozilla.org](https://addons.mozilla.org/).

## Contact

Questions about privacy: visit [papamica.com](https://papamica.com) or open an issue on the [GitHub repository](https://github.com/PAPAMICA/webtool-extension).
