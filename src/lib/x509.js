/* Minimal DER parser to extract X.509 certificate details
 * that webRequest.getSecurityInfo() does not provide directly. */
(() => {
  const OIDS = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.10045.2.1": "ECDSA",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
    "1.2.840.10045.3.1.7": "P-256",
    "1.3.132.0.34": "P-384",
    "1.3.132.0.35": "P-521",
    "1.2.840.113549.1.1.5": "SHA1 with RSA",
    "1.2.840.113549.1.1.11": "SHA256 with RSA",
    "1.2.840.113549.1.1.12": "SHA384 with RSA",
    "1.2.840.113549.1.1.13": "SHA512 with RSA",
    "1.2.840.113549.1.1.10": "RSA-PSS",
    "1.2.840.10045.4.3.2": "ECDSA with SHA256",
    "1.2.840.10045.4.3.3": "ECDSA with SHA384",
    "1.2.840.10045.4.3.4": "ECDSA with SHA512",
    "1.3.6.1.5.5.7.3.1": "Server authentication",
    "1.3.6.1.5.5.7.3.2": "Client authentication",
    "1.3.6.1.5.5.7.3.3": "Code signing",
    "1.3.6.1.5.5.7.3.4": "E-mail",
    "1.3.6.1.5.5.7.3.9": "OCSP",
    "2.23.140.1.2.1": "DV (domain validated)",
    "2.23.140.1.2.2": "OV (organization validated)",
    "2.23.140.1.2.3": "IV (individual validated)",
    "2.23.140.1.1": "EV (extended validation)",
  };

  function tlv(b, off) {
    const tag = b[off];
    let len = b[off + 1];
    let hdr = 2;
    if (len & 0x80) {
      const n = len & 0x7f;
      len = 0;
      for (let i = 0; i < n; i++) len = len * 256 + b[off + 2 + i];
      hdr = 2 + n;
    }
    return { tag, start: off + hdr, end: off + hdr + len };
  }

  function kids(b, node) {
    const out = [];
    let o = node.start;
    while (o < node.end) {
      const c = tlv(b, o);
      out.push(c);
      o = c.end;
    }
    return out;
  }

  function oid(b, node) {
    const first = b[node.start];
    const parts = [Math.min(2, Math.floor(first / 40)), first - Math.min(2, Math.floor(first / 40)) * 40];
    let v = 0;
    for (let i = node.start + 1; i < node.end; i++) {
      v = v * 128 + (b[i] & 0x7f);
      if (!(b[i] & 0x80)) { parts.push(v); v = 0; }
    }
    return parts.join(".");
  }

  const ascii = (b, n) => String.fromCharCode(...b.subarray(n.start, n.end));

  function findTag(b, node, tag, out = []) {
    for (const c of kids(b, node)) {
      if (c.tag === tag) out.push(c);
      else if (c.tag & 0x20) findTag(b, c, tag, out);
    }
    return out;
  }

  function ipString(bytes) {
    if (bytes.length === 4) return Array.from(bytes).join(".");
    const parts = [];
    for (let i = 0; i < bytes.length; i += 2) parts.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
    return parts.join(":").replace(/(^|:)0(:0)+(:|$)/, "::");
  }

  function parse(der) {
    const b = der instanceof Uint8Array ? der : new Uint8Array(der);
    const out = { san: [], sanIps: [], eku: [], policies: [], ocsp: [], caIssuers: [], crl: [] };
    const cert = tlv(b, 0);
    const [tbs, sigAlg] = kids(b, cert);
    const t = kids(b, tbs);
    let i = t[0].tag === 0xa0 ? 1 : 0;
    out.version = i ? b[kids(b, t[0])[0].start] + 1 : 1;
    const spki = t[i + 5];
    out.signatureAlgorithm = name(oid(b, kids(b, sigAlg)[0]));

    const [alg, bits] = kids(b, spki);
    const algK = kids(b, alg);
    const keyOid = oid(b, algK[0]);
    out.keyType = name(keyOid);
    if (keyOid === "1.2.840.113549.1.1.1") {
      const rsa = tlv(b, bits.start + 1);
      const [n] = kids(b, rsa);
      let len = n.end - n.start;
      if (b[n.start] === 0) len--;
      out.keySize = len * 8;
    } else if (keyOid === "1.2.840.10045.2.1" && algK[1]?.tag === 0x06) {
      out.keyCurve = name(oid(b, algK[1]));
    }

    const extWrap = t.find((c) => c.tag === 0xa3);
    if (extWrap) {
      for (const ext of kids(b, kids(b, extWrap)[0])) {
        const c = kids(b, ext);
        const id = oid(b, c[0]);
        const val = c[c.length - 1];
        const inner = tlv(b, val.start);
        try {
          switch (id) {
            case "2.5.29.17":
              for (const gn of kids(b, inner)) {
                if (gn.tag === 0x82) out.san.push(ascii(b, gn));
                else if (gn.tag === 0x87) out.sanIps.push(ipString(b.subarray(gn.start, gn.end)));
              }
              break;
            case "2.5.29.19": {
              const bc = kids(b, inner);
              out.isCA = bc[0]?.tag === 0x01 && b[bc[0].start] !== 0;
              break;
            }
            case "2.5.29.37":
              out.eku = kids(b, inner).map((o) => name(oid(b, o)));
              break;
            case "2.5.29.32":
              out.policies = kids(b, inner)
                .map((p) => oid(b, kids(b, p)[0]))
                .filter((o) => OIDS[o])
                .map(name);
              break;
            case "1.3.6.1.5.5.7.1.1":
              for (const ad of kids(b, inner)) {
                const [m, loc] = kids(b, ad);
                if (loc.tag !== 0x86) continue;
                const method = oid(b, m);
                if (method === "1.3.6.1.5.5.7.48.1") out.ocsp.push(ascii(b, loc));
                if (method === "1.3.6.1.5.5.7.48.2") out.caIssuers.push(ascii(b, loc));
              }
              break;
            case "2.5.29.31":
              out.crl = findTag(b, inner, 0x86).map((n) => ascii(b, n));
              break;
            case "1.3.6.1.4.1.11129.2.4.2":
              out.hasSct = true;
              break;
          }
        } catch (e) {
          /* malformed extension: skip */
        }
      }
    }
    return out;
  }

  function name(o) {
    return OIDS[o] || o;
  }

  function toPem(der) {
    const b = der instanceof Uint8Array ? der : new Uint8Array(der);
    let bin = "";
    for (let i = 0; i < b.length; i += 0x8000) bin += String.fromCharCode(...b.subarray(i, i + 0x8000));
    const b64 = btoa(bin).replace(/.{64}/g, "$&\n");
    return `-----BEGIN CERTIFICATE-----\n${b64.trimEnd()}\n-----END CERTIFICATE-----\n`;
  }

  globalThis.WT_x509 = { parse, toPem };
})();
