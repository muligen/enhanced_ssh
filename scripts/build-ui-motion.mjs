#!/usr/bin/env node
/** Bundle the pinned local GSAP asset and motion source into the existing /app.js route. */
import {readFile, writeFile} from 'node:fs/promises';
const publicFile = new URL('../src/test-ui/public/app.js', import.meta.url);
const marker = '/* BEGIN GENERATED SSH MOTION BUNDLE */';
const source = (await readFile(publicFile, 'utf8')).split(marker)[0].trimEnd();
const vendor = (await readFile(new URL('../src/test-ui/motion/vendor/gsap.min.js', import.meta.url), 'utf8')).replace(/[\t ]+$/gm, '');
const motion = await readFile(new URL('../src/test-ui/motion/ui-motion.js', import.meta.url), 'utf8');
const guard = 'if (typeof window === "undefined" || typeof document === "undefined" || document.documentElement?.nodeType !== 1) return;';
await writeFile(publicFile, `${source}\n\n${marker}\n;(function(){\n${guard}\n${vendor}\n${motion}\n}).call(typeof window !== "undefined" ? {window} : {});\n/* END GENERATED SSH MOTION BUNDLE */\n`);
console.log('Bundled local GSAP + motion layer into public/app.js');
