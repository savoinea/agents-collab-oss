import { execSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import type { FastifyInstance } from 'fastify';
import { AcpClient, type ClientStore, type LocalRecord, type Transport } from '@acp/client';
import {
  CTX, createIdentityRecord, deriveKeys, generateSeed, signDetached, signRequest, type IdentityKeys, type ThreadKeyState,
} from '@acp/protocol';

export const TEST_DB = process.env.TEST_DATABASE_URL ?? 'postgres://agents:agents_dev_only@localhost/agents_test';
process.env.DATABASE_URL = TEST_DB;
process.env.NODE_ENV = 'test';
export const TEST_PORT = 39217;
export const TEST_ORIGIN = `http://localhost:${TEST_PORT}`;
export const TEST_AUTHORITY = `localhost:${TEST_PORT}`;
process.env.ORIGIN = TEST_ORIGIN;

export async function setupApp(): Promise<{ app: FastifyInstance; db: import('pg').Pool }> {
  if (!existsSync(new URL('../../../dist/web/manifest.json', import.meta.url))) execSync('node scripts/build.mjs', { cwd: new URL('../../../', import.meta.url).pathname });
  const { migrate } = await import('../src/db/migrate');
  await migrate(TEST_DB, { reset: true });
  const { createPool } = await import('../src/db/pool');
  const { createApp } = await import('../src/app');
  const db = createPool(TEST_DB);
  const app = await createApp({ db });
  await app.ready();
  Agent.db = db;
  return { app, db };
}

export { solveChallenge } from './solve';
import { solveChallenge } from './solve';

export function decodeHtml(s: string): string {
  return s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
}

export class MemoryStore implements ClientStore {
  keys = new Map<string, ThreadKeyState>();
  local = new Map<string, LocalRecord>();
  async getThreadKeys(thread: string) {
    const s = this.keys.get(thread);
    return s ? { epochs: { ...s.epochs }, records: { ...s.records } } : { epochs: {}, records: {} };
  }
  async addThreadKeys(thread: string, add: Partial<ThreadKeyState>) {
    const s = await this.getThreadKeys(thread);
    let changed = false;
    for (const [k, v] of Object.entries(add.epochs ?? {})) if (s.epochs[k] !== v) { s.epochs[k] = v; changed = true; }
    for (const [k, v] of Object.entries(add.records ?? {})) if (s.records[k] !== v) { s.records[k] = v; changed = true; }
    this.keys.set(thread, s);
    return changed;
  }
  async putLocalRecord(r: LocalRecord) {
    this.local.set(r.record, r);
  }
}

export interface InjectResult {
  status: number;
  json: Record<string, unknown>;
  body: string;
  headers: Record<string, unknown>;
}

/** A test agent: real keys, real signed requests, a session cookie, and the shared client library. */
export class Agent {
  /** Tests share one network address, so per-address limits are reset between registrations. */
  static db: import('pg').Pool | null = null;
  cookie = '';
  client: AcpClient;
  store = new MemoryStore();

  constructor(readonly app: FastifyInstance, readonly keys: IdentityKeys = deriveKeys(generateSeed())) {
    this.client = new AcpClient(keys, this.transport(), this.store);
  }

  get address() {
    return this.keys.address;
  }

  transport(): Transport {
    return {
      get: async <T>(path: string) => {
        const r = await this.get(path);
        if (r.status >= 400) throw Object.assign(new Error(String(r.json.message)), { code: r.json.error, status: r.status });
        return r.json as T;
      },
      post: async <T>(path: string, body: unknown) => {
        const r = await this.post(path, body);
        if (r.status >= 400) throw Object.assign(new Error(String(r.json.message)), { code: r.json.error, status: r.status });
        return r.json as T;
      },
    };
  }

  private capture(res: { headers: Record<string, unknown> }) {
    const sc = res.headers['set-cookie'];
    const list = Array.isArray(sc) ? sc : sc ? [String(sc)] : [];
    for (const c of list) {
      const m = /^acp_session=([^;]*)/.exec(c);
      if (m) this.cookie = m[1] ? `acp_session=${m[1]}` : '';
    }
  }

  async get(path: string): Promise<InjectResult> {
    const res = await this.app.inject({ method: 'GET', url: path, headers: this.cookie ? { cookie: this.cookie } : {} });
    this.capture(res);
    let json: Record<string, unknown> = {};
    try { json = res.json(); } catch { /* html */ }
    return { status: res.statusCode, json, body: res.body, headers: res.headers };
  }

  async post(path: string, body: unknown, opts: { sign?: boolean; keys?: IdentityKeys; mutate?: (h: Record<string, string>) => void; authority?: string } = {}): Promise<InjectResult> {
    const bytes = Buffer.from(JSON.stringify(body));
    const url = new URL(path, TEST_ORIGIN);
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (opts.sign !== false) {
      Object.assign(headers, signRequest(opts.keys ?? this.keys, { method: 'POST', authority: opts.authority ?? TEST_AUTHORITY, path: url.pathname, query: url.search || '?', body: bytes }));
    }
    opts.mutate?.(headers);
    if (this.cookie) headers.cookie = this.cookie;
    const res = await this.app.inject({ method: 'POST', url: path, headers, payload: bytes });
    this.capture(res);
    let json: Record<string, unknown> = {};
    try { json = res.json(); } catch { /* html */ }
    return { status: res.statusCode, json, body: res.body, headers: res.headers };
  }

  async admission(): Promise<string> {
    const page = await this.app.inject({ method: 'GET', url: '/join' });
    const html = page.body;
    const id = /name="challenge" value="([^"]+)"/.exec(html)![1]!;
    const prompt = decodeHtml(/<strong>Challenge:<\/strong> ([^<]+)<\/p>/.exec(html)![1]!);
    const res = await this.app.inject({ method: 'POST', url: '/join', headers: { 'content-type': 'application/x-www-form-urlencoded' }, payload: `challenge=${encodeURIComponent(id)}&answer=${encodeURIComponent(solveChallenge(prompt))}` });
    const token = /id="admission-token" name="admission_token" value="([^"]+)"/.exec(res.body);
    if (!token) throw new Error('admission failed: ' + res.body.slice(0, 500));
    return token[1]!;
  }

  async register(): Promise<this> {
    await Agent.db?.query(`DELETE FROM rate_events WHERE action IN ('admissionChallenge', 'admissionFailure', 'registration', 'read', 'login')`);
    const token = await this.admission();
    const identity = createIdentityRecord(this.keys);
    const r = await this.post('/api/register', { identity, admission_token: token });
    if (r.status !== 200) throw new Error('register failed: ' + JSON.stringify(r.json));
    return this;
  }

  async login(): Promise<void> {
    const { signChallenge } = await import('@acp/protocol');
    const c = await this.get('/api/login/challenge');
    const r = await this.post('/api/login', { address: this.address, challenge: c.json.challenge, signature: signChallenge(this.keys, String(c.json.challenge), TEST_ORIGIN) }, { sign: false });
    if (r.status !== 200) throw new Error('login failed: ' + JSON.stringify(r.json));
  }

  async createSpace(slug: string, kind: 'public' | 'member_open' | 'member_restricted', wiki: 'all' | 'editors' = 'all'): Promise<string> {
    const { toB64u, randomBytes } = await import('@acp/protocol');
    const space = { id: toB64u(randomBytes(16)), slug, kind, name: `Space ${slug}`, description: `About ${slug}`, wiki_edit_policy: wiki, creator: this.address };
    const r = await this.post('/api/spaces', { actor: this.address, space, sig: signDetached(this.keys, CTX.space, space) });
    if (r.status !== 200) throw new Error('space failed: ' + JSON.stringify(r.json));
    return space.id;
  }

  async setMember(space: string, subject: string, perms: number): Promise<InjectResult> {
    const change = { space, subject, perms, by: this.address, ts: Date.now() };
    return this.post(`/api/spaces/${space}/members`, { actor: this.address, change, sig: signDetached(this.keys, CTX.membership, change) });
  }

  /** Posts a public/member record; opens a container when base is 0. */
  async postRecord(opts: {
    container?: string; space?: string; kind: 'thread' | 'question' | 'post' | 'wiki_rev' | 'tombstone' | 'audience_change';
    audience: 'public' | 'member'; value: Record<string, unknown>; slug?: string; target?: string; base_rev?: string;
  }): Promise<InjectResult & { container: string }> {
    const { signRecord, toB64u, randomBytes } = await import('@acp/protocol');
    let container = opts.container;
    let base_seq = 0;
    let prev: string | null = null;
    if (container) {
      const h = await this.get(`/api/containers/${container}`);
      if (h.status === 200) {
        const c = h.json.container as { head_seq: number; head_hash: string | null };
        base_seq = c.head_seq;
        prev = c.head_hash;
      }
    } else container = toB64u(randomBytes(16));
    const body = { type: 'json' as const, value: opts.value };
    const record = signRecord(this.keys, { container, base_seq, prev, audience: opts.audience, kind: opts.kind, body, target: opts.target, base_rev: opts.base_rev ?? (opts.kind === 'wiki_rev' && prev ? prev : undefined) });
    const create = base_seq === 0 ? { kind: opts.kind === 'wiki_rev' ? 'wiki' : 'thread', space: opts.space, slug: opts.slug } : undefined;
    const r = await this.post('/api/records', { actor: this.address, record, body, create });
    return { ...r, container };
  }
}
