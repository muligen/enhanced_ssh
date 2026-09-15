# GSAP runtime provenance

- Package: GSAP core (includes CSSPlugin), 3.15.0.
- Source actually returned by GitHub: https://github.com/greensock/GSAP/blob/master/dist/gsap.min.js
- Fetched Git blob: `3c73d761a9a7dbd166549451ba7afd62dc7121d0`.
- Local `gsap.min.js` retains that blob's runtime and license header; trailing whitespace and final blank lines are normalized for repository formatting.
- The version is vendored, not fetched at application runtime. No CDN requests, npm dependency changes, ScrollTrigger or other optional plugins.
- The complete original license header is retained. Runtime license terms: https://gsap.com/standard-license
- Do not confuse the skills repository's license with the GSAP runtime license.

The wrapper emitted by `scripts/build-ui-motion.mjs` supplies a writable `{window}` holder as its `this` value for the unmodified UMD export. This allows the original application's strict mode to remain enabled without assigning to the browser's read-only `Window.window` property. No `eval`, `new Function`, dynamic script injection or changes to the production CSP are used.
