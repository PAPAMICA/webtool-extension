/* Relève dans la page les signaux utiles à la détection des technologies
 * (variables globales, DOM, meta, scripts…) et les envoie au background. */
(() => {
  if (globalThis.__wtCollect) {
    globalThis.__wtCollect();
    return;
  }

  const page = window.wrappedJSObject || window;

  function resolvePath(path) {
    let cur = page;
    for (const part of path.split(".")) {
      try {
        cur = cur[part];
      } catch (e) {
        return undefined;
      }
      if (cur === undefined || cur === null) return undefined;
    }
    return cur;
  }

  function expandoKeys(el) {
    try {
      return Object.keys(el.wrappedJSObject || el);
    } catch (e) {
      return [];
    }
  }

  function candidates() {
    const list = [
      document.getElementById("root"),
      document.getElementById("app"),
      document.getElementById("__next"),
      document.getElementById("__nuxt"),
      document.querySelector("[data-v-app]"),
      document.querySelector("[data-reactroot]"),
      ...document.querySelectorAll("body > *"),
    ];
    return [...new Set(list.filter(Boolean))].slice(0, 40);
  }

  const probes = {
    "@react"() {
      for (const el of candidates()) {
        const keys = expandoKeys(el);
        if (keys.some((k) => k.startsWith("__reactFiber") || k.startsWith("__reactContainer") || k.startsWith("__reactInternalInstance") || k === "_reactRootContainer")) return "";
      }
    },
    "@vue"() {
      for (const el of candidates()) {
        const w = el.wrappedJSObject || el;
        try {
          if (w.__vue_app__) return String(w.__vue_app__.version || "");
          if (w.__vue__) return String(w.__vue__.$root?.constructor?.version || "");
        } catch (e) {}
      }
    },
    "@angular"() {
      const el = document.querySelector("[ng-version]");
      return el ? el.getAttribute("ng-version") || "" : undefined;
    },
    "@preact"() {
      for (const el of candidates()) {
        if (expandoKeys(el).some((k) => k === "__k" || k === "_prevVNode")) return "";
      }
    },
    "@nuxt"() {
      const el = document.getElementById("__nuxt");
      const app = el && (el.wrappedJSObject || el).__vue_app__;
      try {
        const v = app?.$nuxt?.versions?.nuxt || app?.config?.globalProperties?.$nuxt?.versions?.nuxt;
        if (v) return String(v);
      } catch (e) {}
    },
    "@svelte"() {
      try {
        const v = page.__svelte?.v;
        if (v) return String(Array.from(v).sort().pop() ?? "");
      } catch (e) {}
    },
    "@corejs"() {
      try {
        const versions = page["__core-js_shared__"]?.versions;
        if (versions?.length) return String(versions[versions.length - 1].version || "");
      } catch (e) {}
    },
    "@webpack"() {
      try {
        if (Object.keys(page).some((k) => k.startsWith("webpackChunk") || k === "webpackJsonp")) return "";
      } catch (e) {}
    },
    "@tailwind"() {
      for (const st of document.querySelectorAll("style")) {
        const text = st.textContent;
        const m = /tailwindcss v(\d[\d.]*)/.exec(text);
        if (m) return m[1];
        if (text.includes("--tw-")) return "";
      }
      for (const sheet of document.styleSheets) {
        let rules;
        try {
          rules = sheet.cssRules;
        } catch (e) {
          continue;
        }
        const max = Math.min(rules.length, 3000);
        for (let i = 0; i < max; i++) {
          if (rules[i].cssText.includes("--tw-")) return "";
        }
      }
    },
  };

  function collect() {
    const { technologies } = globalThis.WT_DB;
    const jsKeys = new Set();
    const selectors = new Set();
    for (const t of Object.values(technologies)) {
      if (t.js) for (const k of Object.keys(t.js)) jsKeys.add(k);
      if (t.dom) for (const s of t.dom) selectors.add(typeof s === "string" ? s : s.v);
    }

    const js = {};
    for (const k of jsKeys) {
      let v;
      try {
        v = k.startsWith("@") ? probes[k]?.() : resolvePath(k);
      } catch (e) {
        v = undefined;
      }
      if (v === undefined) continue;
      js[k] = typeof v === "string" || typeof v === "number" ? String(v) : "";
    }

    const dom = {};
    for (const s of selectors) {
      try {
        if (document.querySelector(s)) dom[s] = true;
      } catch (e) {}
    }

    const meta = {};
    for (const m of document.querySelectorAll("meta")) {
      const key = (m.getAttribute("name") || m.getAttribute("property") || m.getAttribute("http-equiv") || "").toLowerCase();
      const content = m.getAttribute("content");
      if (key && content) (meta[key] ||= []).push(content);
    }

    const src = new Set();
    for (const s of document.scripts) if (s.src) src.add(s.src);
    for (const l of document.querySelectorAll("link[href]")) src.add(l.href);
    try {
      for (const e of performance.getEntriesByType("resource").slice(0, 800)) src.add(e.name);
    } catch (e) {}

    const html = document.documentElement ? document.documentElement.outerHTML.slice(0, 400000) : "";

    browser.runtime
      .sendMessage({
        type: "signals",
        signals: { url: location.href, title: document.title, js, dom, meta, src: [...src], html },
      })
      .catch(() => {});
  }

  globalThis.__wtCollect = collect;
  collect();
  if (document.readyState !== "complete") window.addEventListener("load", () => setTimeout(collect, 300), { once: true });
  setTimeout(collect, 3000);
  setTimeout(collect, 8000);
})();
