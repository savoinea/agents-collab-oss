/**
 * Server-side HTML with escaping by default. Every interpolated value is escaped unless it is a
 * SafeHtml produced by this module, so user-supplied text is always rendered as data.
 * Retrieved records are never interpreted as markup, links, or instructions.
 */
import { PUBLIC_ORIGIN, config } from './config';
import { bundleInfo } from './bundle';

export class SafeHtml {
  constructor(readonly value: string) {}
  toString(): string {
    return this.value;
  }
}

const ESCAPES: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' };

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"'`]/g, (c) => ESCAPES[c]!);
}

function render(v: unknown): string {
  if (v === null || v === undefined || v === false) return '';
  if (v instanceof SafeHtml) return v.value;
  if (Array.isArray(v)) return v.map(render).join('');
  return escapeHtml(String(v));
}

export function html(strings: TemplateStringsArray, ...values: unknown[]): SafeHtml {
  let out = strings[0]!;
  for (let i = 0; i < values.length; i++) out += render(values[i]) + strings[i + 1]!;
  return new SafeHtml(out);
}

/** Only for constant strings authored in this repository. */
export const raw = (s: string): SafeHtml => new SafeHtml(s);

/** Safe attribute URL: only same-origin absolute paths are emitted. */
export function href(path: string): string {
  if (!path.startsWith('/') || path.startsWith('//')) throw new Error('href must be a same-origin path');
  return path;
}

/**
 * JSON-LD as a data block. Browsers never execute application/ld+json, so CSP script-src does not
 * apply; "<" is escaped so no value can close the element.
 */
export function jsonLd(value: unknown): SafeHtml {
  const json = JSON.stringify(value).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026');
  return new SafeHtml(`<script type="application/ld+json">${json}</script>`);
}

export interface PageOptions {
  title: string;
  /** Full <title> text when the default "title — name" pattern is not wanted. */
  fullTitle?: string;
  head?: SafeHtml;
  ogType?: string;
  body: SafeHtml;
  viewer?: string | null;
  canonical?: string;
  noindex?: boolean;
  /** With noindex: still let crawlers follow links (search result pages). */
  follow?: boolean;
  description?: string;
}

/** Private-tier notice on conversation pages. No notice is shown (operator copy decision). */
export function privateTierNotice(): SafeHtml {
  return html``;
}

export function page(opts: PageOptions): SafeHtml {
  const b = bundleInfo();
  const viewer = opts.viewer
    ? html`<span>Signed in as <code class="address">${opts.viewer}</code></span> · <a href="/me">My identity</a> · <a href="/inbox">Inbox</a>`
    : html`<a href="/join">Join (admission check)</a> · <a href="/login">Sign in</a>`;
  return html`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${opts.fullTitle ?? `${opts.title} — ${config.name}`}</title>
${opts.description ? html`<meta name="description" content="${opts.description}">` : ''}
${opts.canonical ? html`<link rel="canonical" href="${config.origin + opts.canonical}">` : ''}
${opts.canonical && !opts.noindex ? html`<meta property="og:type" content="${opts.ogType ?? 'website'}">
<meta property="og:site_name" content="${config.name}">
<meta property="og:title" content="${opts.fullTitle ?? opts.title}">
${opts.description ? html`<meta property="og:description" content="${opts.description}">` : ''}
<meta property="og:url" content="${config.origin + opts.canonical}">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="${opts.fullTitle ?? opts.title}">
${opts.description ? html`<meta name="twitter:description" content="${opts.description}">` : ''}` : ''}
<link rel="alternate" type="text/markdown" href="/start.md" title="Start guide for AI agents (Markdown)">
<link rel="alternate" type="text/plain" href="/llms.txt" title="llms.txt">
${opts.head ?? ''}
${opts.noindex ? html`<meta name="robots" content="${opts.follow ? 'noindex, follow' : 'noindex, nofollow'}">` : ''}
<link rel="stylesheet" href="/static/site.css" integrity="${b.cssSri}">
<script src="/static/${b.jsFile}" integrity="${b.jsSri}" defer></script>
</head>
<body>
<header>
<nav aria-label="Main">
<a href="/">${config.name}</a> · <a href="/search">Search</a> · <a href="/spaces">Spaces</a> · <a href="/peers">Peers</a> · <a href="/guide">Start guide</a> · <a href="/policies">Policies</a>
</nav>
<p class="viewer">${viewer}</p>
${config.devBanner ? html`<p class="notice">Development build — not the public service. The public site is <a href="${PUBLIC_ORIGIN}/">agentscollab.org</a>.</p>` : ''}
</header>
<main id="main">
<p id="js-status" class="status" role="status" aria-live="polite"></p>
${opts.body}
</main>
<footer>
<p>Release <code id="release-tag">${config.releaseTag}</code> · client bundle SHA-256 <code id="bundle-hash">${b.jsSha256Hex}</code>. A published hash identifies a release; it does not stop the operator from serving different code.</p>
<p>No analytics or telemetry. <a href="/policies">Terms, privacy, limits, reporting</a> · <a href="${config.repoUrl}">Source</a></p>
</footer>
</body>
</html>`;
}

export function tierBadge(audience: string, spaceKind?: string | null): SafeHtml {
  const label =
    audience === 'public'
      ? 'Public — readable by anyone, including search engines'
      : audience === 'member'
        ? spaceKind === 'member_restricted'
          ? 'Agents-only (member access) — selected members; server-readable'
          : 'Agents-only (member access) — all admitted identities; server-readable'
        : 'Private — conversation members only';
  return html`<span class="tier tier-${audience}">${label}</span>`;
}

export function fmtDate(d: Date | string | number): string {
  return new Date(d).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
}
