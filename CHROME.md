# Chrome Web Store — submission kit

Package: `web-ext-artifacts/webtool_inspector_chrome-1.4.0.zip`  
Rebuild: `./scripts/package-chrome.sh`

## Differences vs Firefox

| Feature | Firefox | Chrome |
| --- | --- | --- |
| Manifest | V2 | V3 (required) |
| Live TLS handshake (cipher, chain DER, PEM) | Yes (`getSecurityInfo`) | Not available to extensions |
| Certificate tab | Full live cert | HTTPS/HSTS + Certificate Transparency via crt.sh |
| System DNS API | Yes | DoH only (Cloudflare) |
| Background | Persistent page | Service worker + `storage.session` |

UI, tech detection, IP/ASN, Domain, Headers and OSINT links are the same.

## 1. Developer account

1. Open https://chrome.google.com/webstore/devconsole  
2. Pay the one-time registration fee if needed  
3. Accept the developer agreement

## 2. Upload

1. **New item** → upload `webtool_inspector_chrome-1.4.0.zip`  
2. Fill the store listing (copy below)  
3. Privacy: declare remote lookups (see [PRIVACY.md](PRIVACY.md))  
4. Single purpose: “Inspect technologies, network and security metadata of the current tab”  
5. Permissions justification: host access for page signals + header capture; no selling of data

## 3. Listing copy

### Name
```
WebTool Inspector
```

### Summary
```
Inspect any site: technologies & versions, IP/ASN/geo, WHOIS/RDAP, DNS, TLS hints and HTTP security headers — in one popup.
```

### Description
```
WebTool Inspector is a toolkit for everyday web investigation and development.

Open the toolbar button on any http(s) page to get:

• Overview — hosting, technologies, certificate hints and security headers at a glance
• Tech — 500+ signatures (CMS, frameworks, CDNs, analytics…) with versions when available
• IP / ASN — contacted IP, geolocation, ASN/ISP, reverse DNS, IP RDAP
• Domain — registrar, dates, DNSSEC, nameservers + A/AAAA/NS/MX/SPF/DMARC/CAA/SOA
• Certificate — HTTPS/HSTS plus Certificate Transparency data (Chrome cannot expose the live TLS handshake; use Firefox for full live cert details)
• Headers — redirect chain, security-header checklist, info-leak headers, raw response

Also includes quick links to OSINT tools (Shodan, Censys, VirusTotal, crt.sh, SSL Labs, and more).

Privacy: DNS (Cloudflare DoH), RDAP, IP geo and optional crt.sh lookups contact third-party services. See the privacy policy. No accounts, no ads, no telemetry SDK.
```

### Category
Developer Tools (or Productivity)

### Language
English

### Official URL
```
https://github.com/PAPAMICA/webtool-extension
```

### Privacy policy URL
```
https://github.com/PAPAMICA/webtool-extension/blob/main/PRIVACY.md
```

## 4. Screenshots & graphic assets

Ready-made pack (exact Chrome sizes):

- Folder: [`store/chrome/`](store/chrome/)
- Zip: [`store/chrome-store-assets.zip`](store/chrome-store-assets.zip)

| File | Use |
| --- | --- |
| `store-icon-128.png` | Store icon (required) |
| `screenshot-1…5-1280x800.jpg` | Screenshots (required, up to 5) |
| `promo-small-440x280.jpg` | Small tile (recommended) |
| `promo-marquee-1400x560.jpg` | Marquee (recommended) |

## 5. Local test (before upload)

1. Open `chrome://extensions`  
2. Enable **Developer mode**  
3. **Load unpacked** → select the unzipped package folder, or load the repo with `chrome/manifest.json` temporarily at root by using the built ZIP extracted folder  
4. Open any https site → reload once → open the popup → Rescan

```bash
./scripts/package-chrome.sh
unzip -d /tmp/webtool-chrome web-ext-artifacts/webtool_inspector_chrome-1.4.0.zip
# Load /tmp/webtool-chrome in chrome://extensions
```

## 6. Permission justifications (paste in console)

- **Read and change all your data on websites you visit**: technology detection from page signals; same-origin version probes; capture main-frame response headers.  
- **webRequest**: observe main navigation headers, redirects and contacted IP.  
- **tabs / scripting**: identify the active tab and reinject collectors on Rescan.  
- **cookies**: cookie-name signatures only (values are not uploaded).  
- **storage**: keep per-tab scan results while the service worker sleeps.
