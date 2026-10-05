// Deterministic client build: pinned lockfile, fixed esbuild options, no timestamps,
// no source maps, content-hashed file name. Prints the SHA-256 that CI publishes with the tag.
import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';

const out = new URL('../dist/web/', import.meta.url);
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

const result = await build({
  entryPoints: [new URL('../apps/web/src/main.ts', import.meta.url).pathname],
  bundle: true,
  format: 'iife',
  platform: 'browser',
  target: ['es2022'],
  minify: true,
  sourcemap: false,
  legalComments: 'none',
  charset: 'utf8',
  write: false,
  metafile: false,
  define: { 'process.env.NODE_ENV': '"production"' },
  logLevel: 'warning',
  tsconfig: new URL('../tsconfig.json', import.meta.url).pathname,
});

const js = result.outputFiles[0].contents;
const css = readFileSync(new URL('../apps/web/src/site.css', import.meta.url));
const sha256 = (b) => createHash('sha256').update(b).digest('hex');
const sri = (b) => 'sha384-' + createHash('sha384').update(b).digest('base64');

const jsFile = `app-${sha256(js).slice(0, 16)}.js`;
const cssFile = 'site.css';
writeFileSync(new URL(jsFile, out), js);
writeFileSync(new URL(cssFile, out), css);
const manifest = { jsFile, jsSha256Hex: sha256(js), jsSri: sri(js), cssFile, cssSri: sri(css) };
writeFileSync(new URL('manifest.json', out), JSON.stringify(manifest, null, 2) + '\n');
console.log(`client bundle ${jsFile} sha256=${manifest.jsSha256Hex}`);
