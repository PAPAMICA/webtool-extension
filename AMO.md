# Firefox Add-ons (AMO) — submission kit

Package ready to upload: `web-ext-artifacts/webtool_inspector-1.0.0.zip`  
Rebuild anytime: `./scripts/package.sh`

## 1. Account

1. Open https://addons.mozilla.org/developers/
2. Log in with a Mozilla Account
3. Accept the [Developer Agreement](https://extensionworkshop.com/documentation/publish/firefox-add-on-distribution-agreement/) and read the [Add-on Policies](https://extensionworkshop.com/documentation/publish/add-on-policies/)

## 2. Submit

1. https://addons.mozilla.org/developers/addon/submit/  
2. Choose distribution:
   - **On this site** — listed on AMO (recommended)
   - **On your own** — signed `.xpi` only, unlisted
3. Upload `web-ext-artifacts/webtool_inspector-1.0.0.zip`
4. Compatible platforms: **Firefox** (desktop). Skip Android unless you later add `gecko_android`.
5. Source code: **No** (this package is readable JS, not minified/obfuscated)

## 3. Listing copy (paste into AMO)

### Name
```
WebTool Inspector
```

### Summary (≤ 250 characters)
```
Inspect any site: detected technologies & versions, IP/ASN/geo, WHOIS/RDAP, DNS, TLS certificate and HTTP security headers — in one Firefox popup.
```

### Description
```
WebTool Inspector is a Firefox toolkit for everyday web investigation and development.

Open the toolbar button on any http(s) page to get:

• Overview — hosting, technologies, certificate and security headers at a glance
• Tech — 500+ signatures (CMS, frameworks, CDNs, analytics…) with versions when available
• IP / ASN — contacted IP, geolocation, ASN/ISP, reverse DNS, IP RDAP
• Domain — registrar, dates, DNSSEC, nameservers + A/AAAA/NS/MX/SPF/DMARC/CAA/SOA
• Certificate — TLS version, cipher, SAN, key, fingerprints, chain, PEM export
• Headers — redirect chain, security-header checklist, info-leak headers, raw response

Also includes quick links to OSINT tools (Shodan, Censys, VirusTotal, crt.sh, SSL Labs, and more), prefilled with the current host / IP / ASN.

Privacy: lookups for DNS (Cloudflare DoH), RDAP and IP geo contact third-party services. See the privacy policy. No accounts, no ads, no telemetry SDK.
```

### Categories (pick up to 2)
- Privacy & Security
- Web Development

### License
MIT

### Homepage / Support site
```
https://github.com/PAPAMICA/webtool-extension
```

### Support email
*(your email)*

### Privacy policy URL
```
https://github.com/PAPAMICA/webtool-extension/blob/main/PRIVACY.md
```
*(Push `PRIVACY.md` to GitHub before submitting, or host the same text on papamica.com.)*

### This add-on has a privacy policy
**Yes** — required (network lookups leave the device).

## 4. Screenshots (required for listed)

AMO expects images ≈ **1280×800** (PNG/JPG). Suggested shots:

1. Overview tab on a real site  
2. Tech tab with logos / versions  
3. Certificate or Headers tab  

Capture from a temporary load (`about:debugging`) before or after upload.

## 5. Notes for reviewers (paste)

```
Thank you for reviewing WebTool Inspector.

How to test
1. Install the add-on and open any https site (e.g. https://example.com or https://wordpress.org).
2. Reload the tab once so headers / TLS are captured during navigation.
3. Click the toolbar button → Overview, Tech, IP/ASN, Domain, Certificate, Headers.

Why these permissions
• <all_urls> + content script: technology detection from page signals; same-origin version probes.
• webRequest + webRequestBlocking: response headers, redirect chain, browser.webRequest.getSecurityInfo (Firefox MV2).
• tabs: identify the active tab URL/host.
• dns: reverse DNS helpers.
• cookies: cookie-name signatures only (values are not uploaded).

Third-party network calls (only when the popup runs lookups)
• https://cloudflare-dns.com/dns-query — DNS-over-HTTPS
• https://rdap.org (+ related RDAP) — domain/IP registration
• https://ipwho.is / https://ipinfo.io — IP geo / ASN
• https://cdn.simpleicons.org + Google favicon service — UI logos only
• Same-origin GETs for WordPress/PHP version probes

No remote code execution: all extension logic is local. Remote URLs are only used for JSON/DNS/image fetches.
No minification or obfuscation; source = uploaded package.
Manifest declares data_collection_permissions: browsingActivity, websiteContent (strict_min_version 140 for built-in consent).
```

## 6. After approval

- Listed: share the AMO URL  
- Unlisted: download the signed `.xpi` from the developer hub and install it (persists across restarts)

## Checklist before click Submit

- [ ] `PRIVACY.md` is on the public URL you declared  
- [ ] ZIP built with `./scripts/package.sh`  
- [ ] At least 1–3 screenshots ready (listed)  
- [ ] Support email filled  
- [ ] You can explain `<all_urls>` + `webRequestBlocking` if asked
