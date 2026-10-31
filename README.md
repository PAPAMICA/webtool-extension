<p align="center">
  <a href="https://papamica.com">
    <img src="https://img.papamica.com/logo/papamica.png" width="140px" alt="PAPAMICA" />
  </a>
</p>

<p align="center">
  <a href="#"><img src="https://readme-typing-svg.herokuapp.com?center=true&vCenter=true&lines=WebTool+Inspector;"></a>
</p>
<p align="center">
    Firefox &amp; Chrome extension for everyday web investigation and development. </br>
Technologies, IP / ASN, WHOIS / RDAP, DNS, TLS certificate and HTTP headers — all in one popup.
</p>

![WebTool Inspector demo](demo.gif)

## Features

| Tab | What you get |
| --- | --- |
| **Overview** | Hosting, technologies, certificate, domain and security headers at a glance |
| **Tech** | 500+ technology signatures with versions when available |
| **IP / ASN** | Contacted IP, geolocation, ASN / ISP, reverse DNS, IP RDAP |
| **Domain** | Registrar, dates, DNSSEC, nameservers + A / AAAA / NS / MX / SPF / DMARC / CAA / SOA |
| **Certificate** | Firefox: live TLS + chain/PEM · Chrome: HTTPS/HSTS + Certificate Transparency (crt.sh) |
| **Headers** | Redirect chain, security header checklist, info-leak headers, raw response |
| **Export** | Full report as JSON or printable HTML (Save as PDF from the browser) |

Also includes quick links to OSINT tools (Shodan, Censys, VirusTotal, crt.sh, SSL Labs, and more), prefilled with the current host / IP / ASN.

## Install — Firefox (temporary)

1. Open `about:debugging#/runtime/this-firefox`
2. **Load Temporary Add-on…** → select `manifest.json` at the repo root
3. Reload open tabs — certificate and headers are captured during page load

## Install — Chrome (unpacked)

```bash
./scripts/package-chrome.sh
unzip -d /tmp/webtool-chrome web-ext-artifacts/webtool_inspector_chrome-1.4.0.zip
```

1. Open `chrome://extensions` → enable **Developer mode**
2. **Load unpacked** → select `/tmp/webtool-chrome`
3. Reload the tab, then open the popup

## Publish

| Store | Guide | Package command |
| --- | --- | --- |
| Firefox AMO | [`AMO.md`](AMO.md) | `./scripts/package.sh` → `webtool_inspector-1.4.0.zip` |
| Chrome Web Store | [`CHROME.md`](CHROME.md) | `./scripts/package-chrome.sh` → `webtool_inspector_chrome-1.4.0.zip` |

Privacy policy: [`PRIVACY.md`](PRIVACY.md).

## Privacy note

Lookups for IP geolocation / ASN, DNS-over-HTTPS and RDAP contact third-party services (Cloudflare DoH, ipwho.is, ipinfo.io, rdap.org). Chrome may query crt.sh for Certificate Transparency. Technology logos load from Simple Icons / favicon CDN. See [PRIVACY.md](PRIVACY.md).

## Stack

- Firefox: Manifest V2 (`webRequest.getSecurityInfo` for live TLS)
- Chrome: Manifest V3 service worker
- Shared UI + technology detector (headers, cookies, meta, JS globals, DOM, scripts, CDN URLs, WordPress assets)

## License

MIT
