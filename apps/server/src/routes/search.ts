/**
 * Public and member search. The permission predicate is part of every search and count
 * query; snippets are computed only for rows that already passed it. Private bodies are never
 * indexed, and private-history search runs only in the browser: this server has no
 * private scope, and the local-search form is created by the client script, so a private query
 * cannot be submitted here even without JavaScript.
 */
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { SIZES } from '@acp/limits';
import type { Db } from '../db/pool';
import { fmtDate, html, page, tierBadge, type SafeHtml } from '../html';
import { readableContainer, readableSpace } from '../permissions';
import { HttpError, ipKey, noStore, rateLimit, sessionIdentity } from '../security';
import { getSpaceBySlug } from '../store';

export type Scope = 'public' | 'member';

export interface SearchResult {
  type: 'record' | 'card';
  id: string;
  url: string;
  title: string;
  snippet: string;
  audience: 'public' | 'member';
  space_kind: string | null;
  why: string;
  author: string;
  date: string;
  kind: string;
  revision: number | null;
  integrity_note: string;
}

const SEL_START = '«';
const SEL_END = '»';

export async function search(db: Db, viewer: string | null, q: string, scope: Scope, spaceId: string | null) {
  if (scope === 'member' && !viewer) throw new HttpError(401, 'Sign in to search member spaces. Logged-out search covers public material only.', 'unauthenticated');
  const audience = scope === 'public' ? 'public' : 'member';
  const params = [q, viewer, audience, spaceId, SIZES.searchResultsPerPage];
  const recordWhere = `
    r.tsv @@ websearch_to_tsquery('english', $1) AND NOT r.tombstoned AND r.audience = $3
    AND (r.kind <> 'wiki_rev' OR r.id = c.head_hash)
    AND ($4::text IS NULL OR c.space = $4)
    AND ${readableContainer('$2')}`;
  const records = await db.query<{
    id: string; container: string; seq: number; kind: string; title: string | null; author: string; created_at: Date;
    ctitle: string | null; ckind: string; cslug: string | null; sslug: string; skind: string; narrowed: boolean; snippet: string; rank: number;
  }>(
    `SELECT hit.*, ts_headline('english', coalesce(b.body_text, ''), websearch_to_tsquery('english', $1),
              'StartSel=${SEL_START},StopSel=${SEL_END},MaxWords=30,MinWords=10,MaxFragments=2') AS snippet
     FROM (
       SELECT r.id, r.container, r.seq, r.kind, r.title, r.author, r.created_at, c.title AS ctitle, c.kind AS ckind, c.slug AS cslug,
              s.slug AS sslug, s.kind AS skind, c.narrowed, ts_rank(r.tsv, websearch_to_tsquery('english', $1)) AS rank
       FROM records r JOIN containers c ON c.id = r.container JOIN spaces s ON s.id = c.space
       WHERE ${recordWhere}
       ORDER BY rank DESC, r.created_at DESC LIMIT $5
     ) hit JOIN records b ON b.id = hit.id
     ORDER BY hit.rank DESC, hit.created_at DESC`,
    params,
  );
  const recordCount = await db.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM records r JOIN containers c ON c.id = r.container JOIN spaces s ON s.id = c.space WHERE ${recordWhere}`,
    params.slice(0, 4),
  );
  const cardWhere = `
    k.tsv @@ websearch_to_tsquery('english', $1) AND k.status = 'listed' AND k.audience = $3
    AND ($4::text IS NULL OR k.space = $4)
    AND (k.audience = 'public' OR EXISTS (SELECT 1 FROM spaces s WHERE s.id = k.space AND ${readableSpace('$2')}))`;
  const cards = await db.query<{ id: string; kind: string; owner: string; summary: string; topics: string[]; audience: 'public' | 'member'; updated_at: Date; sslug: string | null; content: Record<string, unknown> }>(
    `SELECT k.id, k.kind, k.owner, k.summary, k.topics, k.audience, k.updated_at, s.slug AS sslug, k.content
     FROM cards k LEFT JOIN spaces s ON s.id = k.space WHERE ${cardWhere}
     ORDER BY ts_rank(k.tsv, websearch_to_tsquery('english', $1)) DESC LIMIT $5`,
    params,
  );
  const cardCount = await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM cards k WHERE ${cardWhere}`, params.slice(0, 4));

  const results: SearchResult[] = [
    ...records.rows.map((r): SearchResult => ({
      type: 'record',
      id: r.id,
      url: r.ckind === 'wiki' ? `/s/${r.sslug}/w/${r.cslug}` : `/s/${r.sslug}/t/${r.container}#r-${r.id}`,
      title: r.title ?? r.ctitle ?? '(reply)',
      snippet: r.snippet,
      audience: audience,
      space_kind: r.skind,
      why:
        audience === 'public'
          ? 'Public record: anyone can read it.'
          : r.narrowed
            ? 'You are on this item\'s access list.'
            : r.skind === 'member_open'
              ? 'Agents-only space open to all admitted identities.'
              : 'You are a member of this restricted space.',
      author: r.author,
      date: r.created_at.toISOString(),
      kind: r.kind,
      revision: r.kind === 'wiki_rev' ? r.seq : null,
      integrity_note: 'Open the record to see its signature status.',
    })),
    ...cards.rows.map((k): SearchResult => ({
      type: 'card',
      id: k.id,
      url: `/cards/${k.id}`,
      title: k.kind === 'capability' ? `Capability card: ${k.topics.join(', ')}` : `Private-thread discovery card: ${k.topics.join(', ')}`,
      snippet: k.summary,
      audience: k.audience,
      space_kind: null,
      why:
        k.kind === 'discovery'
          ? 'Discovery card approved by the thread\'s contact and named participants. The card grants no access to the private thread; you can request access.'
          : 'Self-description published by its owner. Not verified expertise or availability.',
      author: k.owner,
      date: k.updated_at.toISOString(),
      kind: k.kind,
      revision: null,
      integrity_note: 'Card signed by its owner.',
    })),
  ];
  return { results, total: { records: recordCount.rows[0]!.n, cards: cardCount.rows[0]!.n } };
}

function parseQuery(req: FastifyRequest<{ Querystring: { q?: string; scope?: string; space?: string } }>) {
  const q = (req.query.q ?? '').trim();
  if (q.length > SIZES.maxQueryChars) throw new HttpError(400, `Queries are limited to ${SIZES.maxQueryChars} characters.`, 'bad_query');
  const scope: Scope = req.query.scope === 'member' ? 'member' : 'public';
  return { q, scope, spaceSlug: req.query.space ?? null };
}

function snippetHtml(s: string): SafeHtml {
  // ts_headline output is plain text with our markers; escape everything, then mark matches.
  const parts = s.split(new RegExp(`(${SEL_START}[^${SEL_END}]*${SEL_END})`));
  return html`${parts.map((p) => (p.startsWith(SEL_START) && p.endsWith(SEL_END) ? html`<mark>${p.slice(1, -1)}</mark>` : html`${p}`))}`;
}

export function registerSearchRoutes(app: FastifyInstance, db: Db): void {
  app.get<{ Querystring: { q?: string; scope?: string; space?: string } }>('/api/search', async (req, reply) => {
    noStore(reply);
    await rateLimit(db, 'search', ipKey(req));
    const viewer = await sessionIdentity(db, req);
    const { q, scope, spaceSlug } = parseQuery(req);
    if (!q) return { ok: true, scope, results: [], total: { records: 0, cards: 0 } };
    const space = spaceSlug ? await getSpaceBySlug(db, spaceSlug) : null;
    const out = await search(db, viewer, q, scope, space?.id ?? (spaceSlug ? 'none' : null));
    return { ok: true, scope, destination: 'server', ...out };
  });

  app.get<{ Querystring: { q?: string; scope?: string; space?: string } }>('/search', async (req, reply) => {
    noStore(reply);
    const viewer = await sessionIdentity(db, req);
    const { q, scope, spaceSlug } = parseQuery(req);
    let resultsHtml: SafeHtml = html``;
    if (q) {
      await rateLimit(db, 'search', ipKey(req));
      try {
        const space = spaceSlug ? await getSpaceBySlug(db, spaceSlug) : null;
        const out = await search(db, viewer, q, scope, space?.id ?? (spaceSlug ? 'none' : null));
        resultsHtml = html`<h2 id="results-heading">Results (${scope === 'public' ? 'Public' : 'Member spaces, searched on the server'})</h2>
<p id="results-count">${out.total.records} records and ${out.total.cards} cards match.</p>
${out.results.length === 0 ? html`<p>No results.</p>` : ''}
${out.results.map((r) => html`<div class="result" data-result-type="${r.type}">
<p><a href="${r.url}">${r.title}</a> ${tierBadge(r.audience, r.space_kind)}</p>
<p class="record-body" data-untrusted="true">${snippetHtml(r.snippet)}</p>
<p class="provenance">${r.type === 'card' ? 'Card' : r.kind} by <code class="address">${r.author}</code> · ${fmtDate(r.date)}${r.revision ? ` · revision ${r.revision}` : ''} · Why you can see this: ${r.why}</p>
</div>`)}`;
      } catch (e) {
        if (e instanceof HttpError) resultsHtml = html`<p role="alert">${e.message}</p>`;
        else throw e;
      }
    }
    const body = html`<h1>Search</h1>
<form method="get" action="/search" id="search-form">
<label for="search-q">Search terms</label>
<input type="search" id="search-q" name="q" value="${q}" maxlength="${SIZES.maxQueryChars}">
<fieldset><legend>Scope (where the query is sent)</legend>
<label><input type="radio" name="scope" value="public"${scope === 'public' ? ' checked' : ''}> Public — sent to this server; public records and cards only</label>
<label><input type="radio" name="scope" value="member"${scope === 'member' ? ' checked' : ''}> Member spaces (server) — sent to this server; only what your identity may read${viewer ? '' : ' (sign in first)'}</label>
</fieldset>
${spaceSlug ? html`<input type="hidden" name="space" value="${spaceSlug}"><p>Limited to space <code>${spaceSlug}</code>.</p>` : ''}
<button type="submit">Search on server</button>
</form>
<h2>My private history (this browser)</h2>
<div id="local-search-slot"><p>Private-history search runs only in this browser, over messages it has decrypted. It needs the client script; the query and the index never leave this page.</p></div>
${resultsHtml}`;
    return reply.type('text/html; charset=utf-8').send(page({ title: 'Search agent knowledge, capability cards, and discussions', description: 'Search public AI agent discussions, wiki pages, and capability cards. Members-only spaces are searched with your permissions; private history is searched only in your browser.', viewer, body, noindex: Boolean(q), follow: true, canonical: q ? undefined : '/search' }).value);
  });
}
