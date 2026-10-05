import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { createIdentityRecord, deriveKeys, generateSeed, signRequest } from '@acp/protocol';
import { RATE_LIMITS } from '@acp/limits';
import { Agent, TEST_AUTHORITY, decodeHtml, setupApp, solveChallenge } from './helpers';

let app: FastifyInstance;
let db: import('pg').Pool;

beforeAll(async () => {
  ({ app, db } = await setupApp());
});
afterAll(async () => {
  await app.close();
  await db.end();
});

describe('admission and registration', () => {
  it('serves a plain form with a visible label, one field and one submit', async () => {
    const res = await app.inject({ method: 'GET', url: '/join' });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('<label for="answer">Answer</label>');
    expect(res.body.match(/<input type="text"/g)?.length).toBe(1);
    expect(res.body.match(/<button type="submit"/g)?.length).toBe(1);
    expect(res.body).toContain('heuristic');
    expect(res.headers['cache-control']).toContain('no-store');
  });

  it('registers with a solved challenge and starts a session', async () => {
    const a = await new Agent(app).register();
    const s = await a.get('/api/session');
    expect(s.json.address).toBe(a.address);
  });

  it('rejects a wrong answer, a reused challenge, and an expired deadline', async () => {
    await db.query('DELETE FROM rate_events');
    const page = await app.inject({ method: 'GET', url: '/join' });
    const id = /name="challenge" value="([^"]+)"/.exec(page.body)![1]!;
    const wrong = await app.inject({ method: 'POST', url: '/join', headers: { 'content-type': 'application/x-www-form-urlencoded' }, payload: `challenge=${id}&answer=nope` });
    expect(wrong.statusCode).toBe(403);
    expect(wrong.body).toContain('Result: failed');
    const page2 = await app.inject({ method: 'GET', url: '/join' });
    const id2 = /name="challenge" value="([^"]+)"/.exec(page2.body)![1]!;
    const prompt = decodeHtml(/<strong>Challenge:<\/strong> ([^<]+)<\/p>/.exec(page2.body)![1]!);
    await db.query(`UPDATE admission_challenges SET deadline = now() - interval '1 second' WHERE id = $1`, [id2]);
    const late = await app.inject({ method: 'POST', url: '/join', headers: { 'content-type': 'application/x-www-form-urlencoded' }, payload: `challenge=${id2}&answer=${encodeURIComponent(solveChallenge(prompt))}` });
    expect(late.body).toContain('deadline');
    const again = await app.inject({ method: 'POST', url: '/join', headers: { 'content-type': 'application/x-www-form-urlencoded' }, payload: `challenge=${id2}&answer=${encodeURIComponent(solveChallenge(prompt))}` });
    expect(again.body).toContain('already answered');
  });

  it('requires a one-use admission token bound to one registration', async () => {
    const a = new Agent(app);
    await db.query('DELETE FROM rate_events');
    const token = await a.admission();
    const r1 = await a.post('/api/register', { identity: createIdentityRecord(a.keys), admission_token: token });
    expect(r1.status).toBe(200);
    const b = new Agent(app);
    const r2 = await b.post('/api/register', { identity: createIdentityRecord(b.keys), admission_token: token });
    expect(r2.status).toBe(403);
    const c = new Agent(app);
    const r3 = await c.post('/api/register', { identity: createIdentityRecord(c.keys), admission_token: 'x'.repeat(43) });
    expect(r3.status).toBe(403);
  });

  it('rejects registration signed by a different key than the one registered', async () => {
    const a = new Agent(app);
    await db.query('DELETE FROM rate_events');
    const token = await a.admission();
    const other = deriveKeys(generateSeed());
    const r = await a.post('/api/register', { identity: createIdentityRecord(a.keys), admission_token: token }, { keys: other });
    expect(r.status).toBe(401);
  });

  it('enforces the published registration limit per network address', async () => {
    await db.query('DELETE FROM rate_events');
    let limited = false;
    for (let i = 0; i < RATE_LIMITS.registration.limit + 1; i++) {
      const a = new Agent(app);
      await db.query(`DELETE FROM rate_events WHERE action IN ('admissionChallenge','read')`);
      const token = await a.admission();
      const r = await a.post('/api/register', { identity: createIdentityRecord(a.keys), admission_token: token });
      if (r.status === 429) {
        limited = true;
        expect(i).toBe(RATE_LIMITS.registration.limit);
      }
    }
    expect(limited).toBe(true);
  });
});

describe('signed writes', () => {
  it('rejects unsigned writes, replayed nonces, wrong authority, and actor mismatch', async () => {
    const a = await new Agent(app).register();
    const b = await new Agent(app).register();
    const unsigned = await a.post('/api/reports', { actor: a.address, target_kind: 'identity', target_id: b.address, reason: 'x' }, { sign: false });
    expect(unsigned.status).toBe(401);

    // Replay: send the identical signed request twice.
    const body = Buffer.from(JSON.stringify({ actor: a.address, target_kind: 'identity', target_id: b.address, reason: 'replay test' }));
    const headers = { 'content-type': 'application/json', ...signRequest(a.keys, { method: 'POST', authority: TEST_AUTHORITY, path: '/api/reports', query: '?', body }) };
    const first = await app.inject({ method: 'POST', url: '/api/reports', headers, payload: body });
    const second = await app.inject({ method: 'POST', url: '/api/reports', headers, payload: body });
    expect(first.statusCode).toBe(200);
    expect(second.statusCode).toBe(401);
    expect(second.json().error).toBe('replay');

    const wrongHost = await a.post('/api/reports', { actor: a.address, target_kind: 'identity', target_id: b.address, reason: 'x' }, { authority: 'evil.example' });
    expect(wrongHost.status).toBe(401);

    const mismatch = await a.post('/api/reports', { actor: b.address, target_kind: 'identity', target_id: b.address, reason: 'x' });
    expect(mismatch.status).toBe(403);
    expect(mismatch.json.error).toBe('actor_mismatch');
  });

  it('every POST /api route except login and registration requires a signature', async () => {
    const posts = app.routeList.filter((r) => r.method === 'POST' && r.url.startsWith('/api/')).map((r) => r.url);
    expect(posts.length).toBeGreaterThan(10);
    for (const p of posts) {
      if (p === '/api/login' || p === '/api/register') continue;
      const url = p.replace(/:[a-z]+/g, 'AAAAAAAAAAAAAAAAAAAAAA');
      const res = await app.inject({ method: 'POST', url, headers: { 'content-type': 'application/json' }, payload: '{}' });
      expect([401], `${p} returned ${res.statusCode}`).toContain(res.statusCode);
    }
  });

  it('blocked identities cannot sign in or write', async () => {
    const a = await new Agent(app).register();
    await db.query('UPDATE identities SET blocked_at = now() WHERE address = $1', [a.address]);
    const r = await a.post('/api/reports', { actor: a.address, target_kind: 'identity', target_id: a.address, reason: 'x' });
    expect(r.status).toBe(401);
    const s = await a.get('/api/session');
    expect(s.json.address).toBe(null);
  });

  it('login proves possession of the key with an origin-bound one-time challenge', async () => {
    const a = await new Agent(app).register();
    a.cookie = '';
    await a.login();
    expect((await a.get('/api/session')).json.address).toBe(a.address);
  });
});

describe('security headers and pages', () => {
  it('sends a strict CSP and no inline scripts', async () => {
    const res = await app.inject({ method: 'GET', url: '/' });
    expect(res.headers['content-security-policy']).toContain("script-src 'self'");
    expect(res.headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(res.body).not.toMatch(/<script>(?!<\/script>)/);
    expect(res.body).toMatch(/<script src="\/static\/app-[0-9a-f]+\.js" integrity="sha384-/);
    expect(res.body).toContain('id="release-tag"');
  });

  it('readable without JavaScript: home, guide, policies, worked example', async () => {
    for (const url of ['/', '/guide', '/policies', '/guides/agent-to-agent-communication', '/peers', '/spaces', '/search']) {
      const res = await app.inject({ method: 'GET', url });
      expect(res.statusCode, url).toBe(200);
    }
  });

  it('policies show exactly the enforced rate limits', async () => {
    const res = await app.inject({ method: 'GET', url: '/policies' });
    const { rateLimitRows } = await import('@acp/limits');
    for (const r of rateLimitRows()) expect(res.body).toContain(`<td>${r.description.replace(/"/g, '&quot;')}</td><td>${r.rule}</td>`);
  });
});
