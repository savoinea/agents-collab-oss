// Security regression tests: authorization, rate limits, sizes, and private-tier enforcement.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { RATE_LIMITS, SIZES } from '@acp/limits';
import { CTX, PERM, encryptRecord, fromB64u, randomBytes, signDetached, signRecord, toB64u } from '@acp/protocol';
import { Agent, TEST_AUTHORITY, setupApp } from './helpers';

let app: FastifyInstance;
let db: import('pg').Pool;
let owner: Agent, member: Agent, outsider: Agent;

beforeAll(async () => {
  ({ app, db } = await setupApp());
  owner = await new Agent(app).register();
  member = await new Agent(app).register();
  outsider = await new Agent(app).register();
});
afterAll(async () => {
  await app.close();
  await db.end();
});

describe('narrowed items cannot escape their space', () => {
  it('rejects access-list entries for identities that cannot read the space', async () => {
    const vault = await owner.createSpace('vault-a', 'member_restricted');
    await owner.setMember(vault, member.address, PERM.read | PERM.post);
    const r = await member.postRecord({ space: vault, kind: 'thread', audience: 'member', value: { title: 'x', text: 'zqescape', acl: [{ address: outsider.address, perms: PERM.read }] } });
    expect(r.status).toBe(400);
    expect(r.json.error).toBe('bad_acl');
  });

  it('a member removed from the space loses narrowed items that list them', async () => {
    const vault = await owner.createSpace('vault-b', 'member_restricted');
    await owner.setMember(vault, member.address, PERM.read);
    const t = await owner.postRecord({ space: vault, kind: 'thread', audience: 'member', value: { title: 'n', text: 'zqnarrowremoved', acl: [{ address: member.address, perms: PERM.read }] } });
    expect(t.status).toBe(200);
    expect((await member.get(`/api/containers/${t.container}`)).status).toBe(200);
    await owner.setMember(vault, member.address, 0);
    expect((await member.get(`/api/containers/${t.container}`)).status).toBe(404);
    await db.query(`DELETE FROM rate_events`);
    expect((await member.get('/api/search?q=zqnarrowremoved&scope=member')).json.total).toEqual({ records: 0, cards: 0 });
  });
});

describe('signature check cannot be bypassed by URL encoding', () => {
  it('percent-encoded paths to write routes still require a signature', async () => {
    for (const url of ['/%61pi/reports', '/api/%72eports', '/api//reports']) {
      const res = await app.inject({ method: 'POST', url, headers: { 'content-type': 'application/json' }, payload: JSON.stringify({ actor: outsider.address, target_kind: 'identity', target_id: owner.address, reason: 'x' }) });
      expect([401, 404], url).toContain(res.statusCode);
    }
  });
});

describe('private deletion is limited to messages', () => {
  it('commits and grants cannot be tombstoned', async () => {
    const t = await owner.client.createThread([member.address], 'hello');
    const recs = (await owner.get(`/api/private/${t}/records`)).json.records as { id: string; kind: string }[];
    const commit = recs.find((r) => r.kind === 'epoch_commit')!;
    const h = (await owner.get(`/api/private/${t}/records?after=99999`)).json.thread as { head_seq: number; head_hash: string };
    const secret = fromB64u((await owner.store.getThreadKeys(t)).epochs['0']!);
    const enc = encryptRecord(secret, { thread: t, epoch: 0, author: owner.address, kind: 'tombstone' }, { reason: 'x' });
    const rec = signRecord(owner.keys, { container: t, base_seq: h.head_seq, prev: h.head_hash, audience: 'private', kind: 'tombstone', epoch: 0, target: commit.id, body: { type: 'ciphertext', ct: enc.ct } });
    const r = await owner.post(`/api/private/${t}/records`, { actor: owner.address, record: rec, body: { type: 'ciphertext', ct: enc.ct } });
    expect(r.status).toBe(400);
    expect((await member.client.sync(t)).members.size).toBe(2);
  });
});

describe('operator blocking does not break other members\' history', () => {
  it('members still sync and can remove the blocked identity; nobody can add it', async () => {
    const victim = await new Agent(app).register();
    const t = await owner.client.createThread([member.address, victim.address], 'three');
    await db.query('UPDATE identities SET blocked_at = now() WHERE address = $1', [victim.address]);
    const view = await member.client.sync(t);
    expect(view.members.has(victim.address)).toBe(true);
    await owner.client.removeMember(t, victim.address);
    expect((await member.client.sync(t)).members.has(victim.address)).toBe(false);
    await expect(owner.client.addMember(t, victim.address, PERM.read)).rejects.toThrow(/blocked/);
  });
});

describe('displayed text is bound to the signature', () => {
  it('tampering only the indexed/displayed column is detected and the text is not shown', async () => {
    const pub = await owner.createSpace('agora', 'public');
    const t = await owner.postRecord({ space: pub, kind: 'thread', audience: 'public', value: { title: 'Bound', text: 'original text' } });
    await db.query(`UPDATE records SET body_text = 'zqinjectedtext' WHERE container = $1`, [t.container]);
    const page = await app.inject({ method: 'GET', url: `/s/agora/t/${t.container}` });
    expect(page.body).toContain('BODY DOES NOT MATCH SIGNED HASH');
    expect(page.body).not.toContain('zqinjectedtext');
  });
});

describe('client pages through long private histories', () => {
  it('reads beyond the 500-record page size', async () => {
    const t = await owner.client.createThread([member.address], undefined);
    const secret = fromB64u((await owner.store.getThreadKeys(t)).epochs['0']!);
    // Insert 520 signed, encrypted records directly to keep the test fast.
    let h = (await owner.get(`/api/private/${t}/records?after=99999`)).json.thread as { head_seq: number; head_hash: string };
    let seq = h.head_seq;
    let prev = h.head_hash;
    const { recordId } = await import('@acp/protocol');
    for (let i = 0; i < 520; i++) {
      const enc = encryptRecord(secret, { thread: t, epoch: 0, author: owner.address, kind: 'private_msg' }, { type: 'message', text: `bulk ${i}` });
      const rec = signRecord(owner.keys, { container: t, base_seq: seq, prev, audience: 'private', kind: 'private_msg', epoch: 0, body: { type: 'ciphertext', ct: enc.ct } });
      const id = recordId(rec);
      await db.query(
        `INSERT INTO records(id, container, seq, prev_hash, author, kind, audience, epoch, ciphertext, envelope, sig) VALUES ($1,$2,$3,$4,$5,'private_msg','private',0,$6,$7,$8)`,
        [id, t, seq + 1, prev, owner.address, Buffer.from(fromB64u(enc.ct)), JSON.stringify(rec.envelope), rec.sig],
      );
      seq++;
      prev = id;
    }
    await db.query('UPDATE containers SET head_seq = $2, head_hash = $3 WHERE id = $1', [t, seq, prev]);
    const view = await member.client.sync(t);
    expect(view.messages.filter((m) => m.text?.startsWith('bulk ')).length).toBe(520);
    void h;
  });
});

describe('rate limits match the published values', () => {
  it('post limit', async () => {
    const a = await new Agent(app).register();
    const sp = await a.createSpace(`rl-${toB64u(randomBytes(4)).toLowerCase().replace(/[^a-z0-9]/g, 'x')}`, 'public');
    const t = await a.postRecord({ space: sp, kind: 'thread', audience: 'public', value: { title: 't', text: 'x' } });
    let status = 200;
    let n = 1;
    while (status === 200 && n <= RATE_LIMITS.post.limit + 1) {
      status = (await a.postRecord({ container: t.container, kind: 'post', audience: 'public', value: { text: `p${n}` } })).status;
      n++;
    }
    expect(status).toBe(429);
    expect(n - 1).toBe(RATE_LIMITS.post.limit); // the opening thread record counts as the first post
  }, 60000);

  it('search limit per network address', async () => {
    await db.query(`DELETE FROM rate_events`);
    let status = 200;
    let n = 0;
    while (status === 200 && n <= RATE_LIMITS.search.limit + 1) {
      status = (await app.inject({ method: 'GET', url: `/api/search?q=x${n}` })).statusCode;
      n++;
    }
    expect(status).toBe(429);
    expect(n).toBe(RATE_LIMITS.search.limit + 1);
  }, 60000);

  it('access-request limit per identity', async () => {
    const a = await new Agent(app).register();
    const t = await a.client.createThread([owner.address]);
    const results: number[] = [];
    for (let i = 0; i < RATE_LIMITS.accessRequest.limit + 1; i++) {
      try {
        await a.client.sendRecord(t, 'access_request', { type: 'access_request', scope: 'excerpt', text: `r${i}`, card: null });
        results.push(200);
      } catch (e) {
        results.push((e as { status: number }).status);
      }
    }
    expect(results.filter((s) => s === 200).length).toBe(RATE_LIMITS.accessRequest.limit);
    expect(results.at(-1)).toBe(429);
  }, 60000);

  it('attachments up to the published size are accepted; larger are refused', async () => {
    const t = await owner.client.createThread([member.address]);
    const ok = await owner.post('/api/blobs', { actor: owner.address, thread: t, id: toB64u(randomBytes(16)), data: toB64u(new Uint8Array(SIZES.maxBlobBytes)) });
    expect(ok.status, JSON.stringify(ok.json)).toBe(200);
    const big = await owner.post('/api/blobs', { actor: owner.address, thread: t, id: toB64u(randomBytes(16)), data: toB64u(new Uint8Array(SIZES.maxBlobBytes + 1)) });
    expect(big.status).toBe(413);
  }, 60000);
});

void CTX; void signDetached; void TEST_AUTHORITY;
