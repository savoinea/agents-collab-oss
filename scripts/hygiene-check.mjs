// Static hygiene checks. Fails CI on any finding.
//  - no analytics/telemetry/error-reporter dependencies or calls
//  - no third-party origins in client code
//  - no logging of request bodies, query strings, cookies or signatures
//  - no eval/new Function; innerHTML only in the reviewed constant-template helper
//  - private-tier copy never claims "standard" protocol or advertises before review
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const root = new URL('..', import.meta.url).pathname;
const findings = [];

function walk(dir, out = []) {
  for (const f of readdirSync(dir)) {
    if (f === 'node_modules' || f === 'dist' || f.startsWith('.')) continue;
    const p = join(dir, f);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.(ts|mjs|js)$/.test(f)) out.push(p);
  }
  return out;
}

const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const deps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
const banned = /sentry|datadog|newrelic|bugsnag|rollbar|segment|mixpanel|amplitude|posthog|google-analytics|gtag|plausible|logrocket|opentelemetry|honeycomb/i;
for (const d of deps) if (banned.test(d)) findings.push(`package.json: telemetry/error-reporting dependency ${d}`);

const sources = [...walk(join(root, 'apps')), ...walk(join(root, 'packages'))].filter((f) => !f.includes('/test/'));
for (const file of sources) {
  const src = readFileSync(file, 'utf8');
  const rel = file.slice(root.length);
  if (banned.test(src.replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, ''))) findings.push(`${rel}: mentions a telemetry/analytics service`);
  if (/\beval\s*\(|new Function\s*\(/.test(src)) findings.push(`${rel}: eval/new Function`);
  if (rel.startsWith('apps/web/')) {
    const inner = [...src.matchAll(/\.innerHTML\s*=/g)].length;
    if (inner > 1 || (inner === 1 && !src.includes('function formFrom('))) findings.push(`${rel}: innerHTML outside the reviewed constant-template helper`);
    if (/outerHTML\s*=|insertAdjacentHTML|document\.write/.test(src)) findings.push(`${rel}: raw HTML insertion`);
    const urls = [...src.matchAll(/https?:\/\/[^\s'"`)]+/g)].map((m) => m[0]);
    for (const u of urls) findings.push(`${rel}: third-party URL in client code: ${u}`);
    if (/sendBeacon|navigator\.sendBeacon/.test(src)) findings.push(`${rel}: sendBeacon`);
  }
  if (rel.startsWith('apps/server/')) {
    if (/log\.(info|warn|error|debug)\([^)]*req\.(body|query|headers|rawBody)/.test(src)) findings.push(`${rel}: logs request data`);
    if (/console\.log\([^)]*req\./.test(src)) findings.push(`${rel}: console.log of request data`);
  }
}

const copyFiles = ['apps/server/src/routes/pages.ts', 'apps/server/src/facts.ts', 'apps/server/src/html.ts'];
for (const f of copyFiles) {
  const src = readFileSync(join(root, f), 'utf8');
  if (/standard (E2E|end-to-end|encryption) protocol/i.test(src) && !/not a standard/i.test(src)) findings.push(`${f}: calls the private-tier protocol standard`);
}

if (findings.length) {
  console.error('Hygiene check failed:\n' + findings.map((f) => `  - ${f}`).join('\n'));
  process.exit(1);
}
console.log(`Hygiene check passed (${sources.length} source files).`);
