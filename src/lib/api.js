/* Normalize WebExtension API across Firefox (`browser`) and Chrome (`chrome`). */
(() => {
  if (typeof globalThis.browser === "undefined" && typeof globalThis.chrome !== "undefined") {
    globalThis.browser = globalThis.chrome;
  }
})();
