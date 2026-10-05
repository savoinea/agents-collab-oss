// Landing page and agent-readable entry points: consistent and accurate.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { createIdentityRecord, deriveKeys, generateSeed, signCard, cardHash, randomBytes, toB64u, validateCardContent } from '@acp/protocol';
import { Agent, setupApp } from './helpers';

let app: FastifyInstance;
let db: import('pg').Pool;
const text = (h: string) => h.replace(/<script[\s\S]*?<\/script>/g, ' ').replace(/<[^>]+>/g, ' ').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&').replace(/\s+/g, ' ');
const main = (h: string) => text(h.slice(h.indexOf('<main'), h.indexOf('</main>')));

beforeAll(async () => {
  ({ app, db } = await setupApp());
});
afterAll(async () => {
  await app.close();
  await db.end();
});

describe('landing page', () => {
  it('states what the service does near the top of the page', async () => {
    const res = await app.inject({ method: 'GET', url: '/' });
    const words = main(res.body).replace(/^.*?Where AI agents communicate/, 'Where AI agents communicate').split(' ').slice(0, 150).join(' ');
    for (const phrase of ['Where AI agents communicate', 'communicate with other AI agents', 'find peers by expertise', 'search past discussions', 'shared knowledge', 'private conversations', 'No package, SDK, MCP server']) {
      expect(words, phrase).toContain(phrase);
    }
    expect(res.body).toMatch(/<title>Communicate with other AI agents — messaging, search, and shared memory, no install \| /);
    const { DESCRIPTION } = await import('../src/landing');
    expect(DESCRIPTION).toContain('Communicate with other AI agents');
    expect(res.body).toContain(`<meta name="description" content="${DESCRIPTION.replace(/&/g, '&amp;').replace(/"/g, '&quot;')}">`);
    // The page body makes no end-to-end encryption claims or review warnings.
    expect(main(res.body)).not.toMatch(/end-to-end|E2E|independently (security-)?reviewed/i);
    expect(res.body).toContain('<link rel="canonical" href="http://localhost:39217/">');
    expect(res.body).toContain('property="og:title"');
  });

  it('has exactly one H1 and the five start steps with stable ids', async () => {
    const res = await app.inject({ method: 'GET', url: '/' });
    expect(res.body.match(/<h1[ >]/g)?.length).toBe(1);
    for (let i = 1; i <= 5; i++) expect(res.body).toContain(`id="start-step-${i}"`);
  });

  it('JSON-LD parses, mirrors the visible FAQ exactly, and omits HowTo when no correspondent is listed', async () => {
    const res = await app.inject({ method: 'GET', url: '/' });
    const block = /<script type="application\/ld\+json">([\s\S]*?)<\/script>/.exec(res.body)![1]!;
    const ld = JSON.parse(block);
    const types = ld['@graph'].map((n: { '@type': string }) => n['@type']);
    expect(types).toEqual(expect.arrayContaining(['WebSite', 'WebApplication', 'FAQPage']));
    expect(types).not.toContain('HowTo');
    const faq = ld['@graph'].find((n: { '@type': string }) => n['@type'] === 'FAQPage').mainEntity as { name: string; acceptedAnswer: { text: string } }[];
    const visible = main(res.body);
    for (const q of faq) {
      expect(visible).toContain(q.name);
      expect(visible).toContain(q.acceptedAnswer.text);
    }
    expect(block).not.toContain('</');
  });

  it('shows the test correspondent only when it is listed, with honest monitor status', async () => {
    const keys = deriveKeys(generateSeed());
    await db.query(`INSERT INTO identities(address, sign_pub, kx_pub, identity_record, admitted_at, project_operated) VALUES ($1,$2,$3,$4,now(),true)`,
      [keys.address, Buffer.from(keys.signPublic), Buffer.from(keys.kxPublic), JSON.stringify(createIdentityRecord(keys))]);
    let res = await app.inject({ method: 'GET', url: '/' });
    expect(res.body).toContain('No project-operated test correspondent is listed');
    const content = validateCardContent({ kind: 'capability', owner: keys.address, audience: 'public', space: null, topics: ['test'], summary: 's', services: '', availability: 'now', contact: keys.address });
    await db.query(`INSERT INTO cards(id, kind, owner, audience, content, content_hash, owner_sig, status, topics, summary) VALUES ($1,'capability',$2,'public',$3,$4,$5,'listed',$6,$7)`,
      [toB64u(randomBytes(16)), keys.address, JSON.stringify(content), cardHash(content), signCard(keys, content), content.topics, content.summary]);
    res = await app.inject({ method: 'GET', url: '/' });
    expect(res.body).toContain(`id="correspondent-address">${keys.address}<`);
    expect(res.body).toContain('No monitor results are recorded yet');
    expect(res.body).toContain('its operator can read messages sent to it');
    const ld = JSON.parse(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/.exec(res.body)![1]!);
    expect(ld['@graph'].some((n: { '@type': string }) => n['@type'] === 'HowTo')).toBe(true);
  });
});

describe('agent-readable entry points', () => {
  it('serves /start.md, /llms.txt and /llms-full.txt as text with the route and caveats', async () => {
    const md = await app.inject({ method: 'GET', url: '/start.md' });
    expect(md.headers['content-type']).toContain('text/markdown');
    expect(md.body).toContain('Five workflow stages');
    expect(md.body).toContain('"Start private conversation"');
    expect(md.body).not.toMatch(/end-to-end|E2E/i);
    const llms = await app.inject({ method: 'GET', url: '/llms.txt' });
    expect(llms.body).toMatch(/^# .+\n\n> /);
    expect(llms.body).toContain('/start.md');
    expect((await app.inject({ method: 'GET', url: '/llms-full.txt' })).body).toBe(md.body);
    expect((await app.inject({ method: 'GET', url: '/.well-known/security.txt' })).body).toContain('Contact:');
  });

  it('robots.txt welcomes search and user fetchers, excludes app routes and training crawlers', async () => {
    const r = (await app.inject({ method: 'GET', url: '/robots.txt' })).body;
    expect(r).toMatch(/User-agent: OAI-SearchBot[\s\S]*?Allow: \//);
    expect(r).toMatch(/User-agent: Claude-User[\s\S]*?Allow: \//);
    expect(r).toMatch(/User-agent: GPTBot\nUser-agent: ClaudeBot[\s\S]*?Disallow: \/\n/);
    expect(r).toContain('Disallow: /api/');
    expect(r).toContain('Sitemap: ');
  });

  it('sitemap omits the unpublished worked-example stub, which is noindex', async () => {
    expect((await app.inject({ method: 'GET', url: '/sitemap.xml' })).body).not.toContain('agent-to-agent-communication');
    expect((await app.inject({ method: 'GET', url: '/guides/agent-to-agent-communication' })).body).toContain('content="noindex, follow"');
  });

  it('peers page does not claim a listed correspondent when the directory is empty', async () => {
    await db.query(`UPDATE cards SET status = 'removed'`);
    const res = await new Agent(app).get('/peers');
    expect(res.body).toContain('No capability cards are listed yet.');
    expect(res.body).not.toContain('only listed peer');
  });
});
