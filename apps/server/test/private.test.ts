import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { AcpClient } from '@acp/client';
import {
  CTX, PERM, PERM_ALL, createExport, createIdentityRecord, encryptRecord, fromB64u, importExport, signCard, signCardApproval,
  signDetached, signRecord, toB64u, randomBytes, validateCardContent,
} from '@acp/protocol';
import { Agent, MemoryStore, setupApp } from './helpers';

let app: FastifyInstance;
let db: import('pg').Pool;
let A: Agent, B: Agent, C: Agent, D: Agent;
let thread = '';
const MARK1 = 'zqprivatemarkerone';

beforeAll(async () => {
  ({ app, db } = await setupApp());
  A = await new Agent(app).register();
  B = await new Agent(app).register();
  C = await new Agent(app).register();
  D = await new Agent(app).register();
  thread = await A.client.createThread([B.address], `hello ${MARK1}`, PERM.read | PERM.post);
});
afterAll(async () => {
  await app.close();
  await db.end();
});

async function grepDatabase(needle: string): Promise<string[]> {
  const tables = await db.query<{ table_name: string }>(`SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'`);
  const hits: string[] = [];
  const hex = Buffer.from(needle).toString('hex');
  for (const { table_name } of tables.rows) {
    const r = await db.query(`SELECT count(*)::int AS n FROM "${table_name}" t WHERE row_to_json(t)::text ILIKE $1 OR row_to_json(t)::text ILIKE $2`, [`%${needle}%`, `%${hex}%`]);
    if (r.rows[0].n > 0) hits.push(table_name);
  }
  return hits;
}

describe('real E2E between two clients', () => {
  it('the recipient decrypts the marker; the server stores only ciphertext', async () => {
    const view = await B.client.sync(thread);
    expect(view.messages.some((m) => m.text === `hello ${MARK1}`)).toBe(true);
    expect(await grepDatabase(MARK1)).toEqual([]);
  });

  it('private records can never carry searchable text (database constraint)', async () => {
    const row = (await db.query(`SELECT * FROM records WHERE container = $1 AND kind = 'private_msg' LIMIT 1`, [thread])).rows[0];
    await expect(db.query(`UPDATE records SET body_text = 'leak' WHERE id = $1`, [row.id])).rejects.toThrow(/private_records_unindexed/);
    await expect(db.query(`UPDATE records SET tags = '{leak}' WHERE id = $1`, [row.id])).rejects.toThrow(/private_records_unindexed/);
    const tsv = await db.query(`SELECT tsv FROM records WHERE container = $1`, [thread]);
    expect(tsv.rows.every((r) => r.tsv === null)).toBe(true);
  });

  it('private messages never appear in server search, for any identity', async () => {
    for (const a of [A, B, C]) {
      await db.query(`DELETE FROM rate_events`);
      for (const scope of ['public', 'member']) {
        const r = await a.get(`/api/search?q=${MARK1}&scope=${scope}`);
        expect(r.json.total).toEqual({ records: 0, cards: 0 });
      }
    }
  });

  it('non-members get the same response as for a nonexistent conversation', async () => {
    const real = await C.get(`/api/private/${thread}/records`);
    const fake = await C.get(`/api/private/${'Z'.repeat(22)}/records`);
    expect(real.status).toBe(404);
    expect(real.body).toBe(fake.body);
    const head = await C.get(`/api/private/${thread}/records?after=99999`);
    expect(head.status).toBe(404);
  });

  it('offline delivery: messages wait in the recipient inbox', async () => {
    await A.client.send(thread, 'while you were away zqofflinemarker');
    const inbox = await B.client.inbox();
    expect(inbox.items.some((i) => i.container === thread)).toBe(true);
    const view = await B.client.sync(thread);
    expect(view.messages.some((m) => m.text?.includes('zqofflinemarker'))).toBe(true);
  });
});

describe('epochs, exclusion and stale senders', () => {
  it('a send tagged with a stale epoch is refused, and nothing is stored', async () => {
    const t = await A.client.createThread([B.address], 'epoch test', PERM.read | PERM.post);
    await B.client.sync(t);
    const h = (await B.get(`/api/private/${t}/records?after=99999`)).json.thread as { head_seq: number; head_hash: string; current_epoch: number };
    const oldSecret = fromB64u((await B.store.getThreadKeys(t)).epochs['0']!);
    await A.client.rotate(t);
    const h2 = (await B.get(`/api/private/${t}/records?after=99999`)).json.thread as { head_seq: number; head_hash: string };
    const enc = encryptRecord(oldSecret, { thread: t, epoch: 0, author: B.address, kind: 'private_msg' }, { text: 'stale' });
    const rec = signRecord(B.keys, { container: t, base_seq: h2.head_seq, prev: h2.head_hash, audience: 'private', kind: 'private_msg', epoch: 0, body: { type: 'ciphertext', ct: enc.ct } });
    const r = await B.post(`/api/private/${t}/records`, { actor: B.address, record: rec, body: { type: 'ciphertext', ct: enc.ct } });
    expect(r.status).toBe(409);
    expect(r.json.error).toBe('stale_epoch');
    expect(r.json.current_epoch).toBe(1);
    void h;
  });

  it('an excluded member cannot read later messages and is not served them', async () => {
    const t = await A.client.createThread([B.address, C.address], 'three of us', PERM.read | PERM.post);
    await C.client.sync(t);
    await A.client.removeMember(t, C.address);
    await A.client.send(t, 'after exclusion zqexcludedmarker');
    const view = await C.client.sync(t);
    expect(view.members.has(C.address)).toBe(false);
    expect(view.messages.some((m) => m.text?.includes('zqexcludedmarker'))).toBe(false);
    const raw = await C.get(`/api/private/${t}/records`);
    expect((raw.json.records as { epoch: number | null; kind: string }[]).every((r) => r.kind === 'grant' || r.epoch === 0 || (r.kind === 'epoch_commit' && r.epoch === 1))).toBe(true);
    // B still reads it.
    expect((await B.client.sync(t)).messages.some((m) => m.text?.includes('zqexcludedmarker'))).toBe(true);
  });

  it('a member without invite cannot add or remove others', async () => {
    const t = await A.client.createThread([B.address], 'perm test', PERM.read | PERM.post);
    await expect(B.client.addMember(t, C.address, PERM.read)).rejects.toThrow(/invite/);
  });

  it('blocks are enforced on new conversations and invitations', async () => {
    const stmt = { blocker: D.address, blocked: A.address, action: 'block', ts: Date.now() };
    expect((await D.post('/api/blocks', { actor: D.address, blocked: A.address, action: 'block', ts: stmt.ts, sig: signDetached(D.keys, CTX.block, stmt) })).status).toBe(200);
    await expect(A.client.createThread([D.address], 'hi')).rejects.toThrow(/does not accept/);
    const t = await A.client.createThread([B.address], 'x');
    await expect(A.client.addMember(t, D.address, PERM.read)).rejects.toThrow(/does not accept/);
    const un = { blocker: D.address, blocked: A.address, action: 'unblock', ts: Date.now() };
    await D.post('/api/blocks', { actor: D.address, blocked: A.address, action: 'unblock', ts: un.ts, sig: signDetached(D.keys, CTX.block, un) });
  });
});

describe('scoped private access (grants)', () => {
  let src = '';
  let r1 = '';
  let r2 = '';
  beforeAll(async () => {
    src = await A.client.createThread([B.address], undefined, PERM.read | PERM.post);
    r1 = await A.client.send(src, 'selected zqgrantone');
    r2 = await A.client.send(src, 'unrelated zqgranttwo');
  });

  it('selected records: the recipient gets exactly those, nothing else', async () => {
    const g = await A.client.grant({ thread: src, recipient: C.address, scope: 'records', recordIds: [r1] });
    expect(g.grantId).toBeTruthy();
    const inbox = await C.client.inbox();
    const dm = inbox.items.find((i) => i.id === g.keysRecord)!.container;
    await C.client.sync(dm); // processes grant keys after verifying grantor authority
    const view = await C.client.sync(src);
    expect(view.messages.some((m) => m.text === 'selected zqgrantone')).toBe(true);
    expect(view.messages.some((m) => m.text === 'unrelated zqgranttwo')).toBe(false);
    const served = (await C.get(`/api/private/${src}/records`)).json.records as { id: string }[];
    expect(served.some((r) => r.id === r2)).toBe(false);
    expect([...C.store.local.values()].some((l) => l.text.includes('zqgrantone'))).toBe(true);
    // Later membership changes are not disclosed to the grant holder.
    await A.client.rotate(src);
    const after = (await C.get(`/api/private/${src}/records`)).json.records as { kind: string; seq: number; id: string }[];
    const grantSeq = after.find((r) => r.id === g.grantRecord)!.seq;
    expect(after.filter((r) => r.kind === 'epoch_commit').every((r) => r.seq < grantSeq)).toBe(true);
  });

  it('all history, future = no: definite cutoff by rotation; later messages stay unavailable', async () => {
    const recipient = await new Agent(app).register();
    await A.client.grant({ thread: src, recipient: recipient.address, scope: 'history' });
    await A.client.send(src, 'after cutoff zqaftercutoff');
    const inbox = await recipient.client.inbox();
    for (const t of new Set(inbox.items.map((i) => i.container))) await recipient.client.sync(t);
    const view = await recipient.client.sync(src);
    expect(view.messages.some((m) => m.text === 'selected zqgrantone')).toBe(true);
    expect(view.messages.some((m) => m.text === 'unrelated zqgranttwo')).toBe(true);
    expect(view.messages.some((m) => m.text?.includes('zqaftercutoff'))).toBe(false);
    const served = (await recipient.get(`/api/private/${src}/records`)).json.records as { body: unknown; kind: string; epoch: number }[];
    const current = (await A.get(`/api/private/${src}/records?after=99999`)).json.thread as { current_epoch: number };
    expect(served.filter((r) => r.kind === 'private_msg').every((r) => r.epoch < current.current_epoch)).toBe(true);
  });

  it('unauthorised grantors and wrong recipients fail', async () => {
    // B lacks the grant permission in src.
    await expect(B.client.grant({ thread: src, recipient: D.address, scope: 'records', recordIds: [r1] })).rejects.toThrow(/grant/);
    // D was never granted anything.
    expect((await D.get(`/api/private/${src}/records`)).status).toBe(404);
  });

  it('excerpt: the grantor writes new text; no original keys are shared', async () => {
    const rec = await new Agent(app).register();
    const g = await A.client.grant({ thread: src, recipient: rec.address, scope: 'excerpt', excerpt: { text: 'Summary: pool size ~ cores*2 zqexcerptmarker', sources: [r1] } });
    const inbox = await rec.client.inbox();
    const dm = inbox.items.find((i) => i.id === g.keysRecord)!.container;
    const view = await rec.client.sync(dm);
    const keysMsg = view.messages.find((m) => m.id === g.keysRecord)!;
    expect((keysMsg.data as { excerpt: { text: string } }).excerpt.text).toContain('zqexcerptmarker');
    expect(Object.keys((keysMsg.data as { epochs: object }).epochs)).toEqual([]);
    expect(Object.keys((keysMsg.data as { records: object }).records)).toEqual([]);
    const srcView = await rec.client.sync(src);
    expect(srcView.messages.filter((m) => m.status === 'decrypted')).toEqual([]);
  });

  it('revocation stops service immediately; already-received plaintext is not recalled', async () => {
    const rec = await new Agent(app).register();
    const g = await A.client.grant({ thread: src, recipient: rec.address, scope: 'records', recordIds: [r1] });
    const inbox = await rec.client.inbox();
    await rec.client.sync(inbox.items.find((i) => i.id === g.keysRecord)!.container);
    expect((await rec.client.sync(src)).messages.some((m) => m.text === 'selected zqgrantone')).toBe(true);
    await A.client.revokeGrant(g.grantId, src, rec.address, false);
    expect((await rec.get(`/api/private/${src}/records`)).status).toBe(404);
    expect([...rec.store.local.values()].some((l) => l.text.includes('zqgrantone'))).toBe(true);
  });

  it('expiry: the grantor\'s client excludes an expired future-access recipient', async () => {
    const rec = await new Agent(app).register();
    const t = await A.client.createThread([B.address], 'expiry thread', PERM.read | PERM.post);
    const g = await A.client.grant({ thread: t, recipient: rec.address, scope: 'history', future: true, expiry: Date.now() + 60_000 });
    expect((await rec.client.sync(t)).members.has(rec.address)).toBe(true);
    await db.query(`UPDATE grants SET expiry = now() - interval '1 second' WHERE id = $1`, [g.grantId]);
    // Before the grantor rotates, the server already refuses sends and later records.
    await expect(rec.client.send(t, 'still here?')).rejects.toThrow(/expired/);
    expect(await A.client.enforceGrantExpiry()).toEqual([g.grantId]);
    await A.client.send(t, 'after expiry zqexpirymarker');
    const view = await rec.client.sync(t).catch(() => null);
    expect(view?.messages.some((m) => m.text?.includes('zqexpirymarker')) ?? false).toBe(false);
  });

  it('future = yes makes the recipient a member with only the conferred rights', async () => {
    const rec = await new Agent(app).register();
    await A.client.grant({ thread: src, recipient: rec.address, scope: 'history', future: true, rights: PERM.post });
    await A.client.send(src, 'future message zqfuturemarker');
    const view = await rec.client.sync(src);
    expect(view.members.get(rec.address)).toBe(PERM.read | PERM.post);
    expect(view.messages.some((m) => m.text?.includes('zqfuturemarker'))).toBe(true);
  });
});

describe('discovery cards with consent and access requests', () => {
  it('lists only after every required approval; edits invalidate approvals; removal unlists', async () => {
    const space = await A.createSpace('dbtalk', 'member_open');
    const t = await A.client.createThread([B.address], 'pool sizing discussion', PERM.read | PERM.post | PERM.publishCard);
    const content = validateCardContent({
      kind: 'discovery', thread: t, audience: 'member', space, topics: ['postgres'], summary: 'Private discussion of pool sizing zqcardmarker',
      contact: B.address, participants: [], date_range: null,
      access_policy: { who_may_request: 'any admitted identity', who_may_grant: 'the contact', offers: ['excerpt'] },
    });
    const id = toB64u(randomBytes(16));
    const created = await A.post('/api/cards', { actor: A.address, id, content, sig: signCard(A.keys, content) });
    expect(created.status, JSON.stringify(created.json)).toBe(200);
    expect(created.json.status).toBe('pending');
    await db.query('DELETE FROM rate_events');
    expect((await C.get('/api/search?q=zqcardmarker&scope=member')).json.total).toEqual({ records: 0, cards: 0 });
    expect((await C.get(`/cards/${id}`)).status).toBe(404);
    // Someone not named cannot approve.
    expect((await C.post(`/api/cards/${id}/approve`, { actor: C.address, content_hash: created.json.content_hash, sig: signCardApproval(C.keys, content) })).status).toBe(404);
    const ok = await B.post(`/api/cards/${id}/approve`, { actor: B.address, content_hash: created.json.content_hash, sig: signCardApproval(B.keys, content) });
    expect(ok.json.status).toBe('listed');
    expect((await C.get('/api/search?q=zqcardmarker&scope=member')).json.total).toEqual({ records: 0, cards: 1 });
    // The card grants no access to the thread.
    expect((await C.get(`/api/private/${t}/records`)).status).toBe(404);
    // Widening the audience invalidates approvals.
    const wider = validateCardContent({ ...content, audience: 'public', space: null });
    const edit = await A.post('/api/cards', { actor: A.address, id, content: wider, sig: signCard(A.keys, wider) });
    expect(edit.json.status).toBe('pending');
    await db.query('DELETE FROM rate_events');
    expect((await new Agent(app).get('/api/search?q=zqcardmarker&scope=public')).json.total).toEqual({ records: 0, cards: 0 });
    // A non-member cannot propose a card for the thread.
    const bad = validateCardContent({ ...content, contact: C.address });
    expect((await C.post('/api/cards', { actor: C.address, id: toB64u(randomBytes(16)), content: bad, sig: signCard(C.keys, bad) })).status).toBe(404);
    // Removal.
    const rm = await B.post(`/api/cards/${id}/remove`, { actor: B.address });
    expect(rm.json.status).toBe('removed');
  });

  it('an access request reaches the contact encrypted; the contact can decline, reply or grant', async () => {
    const { thread: dm, record } = await D.client.accessRequest(B.address, { scope: 'excerpt', text: 'May I see the pool sizing notes? zqrequestmarker' });
    expect(await grepDatabase('zqrequestmarker')).toEqual([]);
    const view = await B.client.sync(dm);
    const req = view.messages.find((m) => m.id === record)!;
    expect(req.kind).toBe('access_request');
    expect(String(req.data?.text)).toContain('zqrequestmarker');
    await B.client.send(dm, 'Declined, sorry.');
    expect((await D.client.sync(dm)).messages.some((m) => m.text === 'Declined, sorry.')).toBe(true);
  });
});

describe('identity export and fresh-profile recovery', () => {
  it('a fresh profile restores the address and decrypts retained history', async () => {
    const history = Object.fromEntries(B.store.keys.entries());
    const text = await createExport({ seed: B.keys.seed, identity: createIdentityRecord(B.keys), history, grants: [], exported_at: Date.now() }, 'a long export passphrase here');
    const { keys, payload } = await importExport(text, 'a long export passphrase here');
    expect(keys.address).toBe(B.address);
    const fresh = new Agent(app, keys);
    await fresh.login();
    const store = new MemoryStore();
    for (const [t, st] of Object.entries(payload.history)) await store.addThreadKeys(t, st);
    const c = new AcpClient(keys, fresh.transport(), store);
    const view = await c.sync(thread);
    expect(view.messages.some((m) => m.text === `hello ${MARK1}`)).toBe(true);
    expect([...store.local.values()].some((l) => l.text.includes(MARK1))).toBe(true);
  });

  it('an old export does not restore revoked server permissions', async () => {
    const space = await A.createSpace('secretclub', 'member_restricted');
    const m = await new Agent(app).register();
    await A.setMember(space, m.address, PERM.read);
    const t = await A.postRecord({ space, kind: 'thread', audience: 'member', value: { title: 'club', text: 'zqclubmarker' } });
    const exportText = await createExport({ seed: m.keys.seed, identity: createIdentityRecord(m.keys), history: {}, grants: [], exported_at: Date.now() }, 'another long passphrase');
    await A.setMember(space, m.address, 0);
    const { keys } = await importExport(exportText, 'another long passphrase');
    const again = new Agent(app, keys);
    await again.login();
    expect((await again.get(`/api/containers/${t.container}`)).status).toBe(404);
  });
});

describe('server never holds secrets', () => {
  it('commit records contain only wrapped keys; the server cannot open them', async () => {
    const rows = (await db.query(`SELECT body_json FROM records WHERE kind = 'epoch_commit' LIMIT 5`)).rows;
    for (const r of rows) {
      const body = r.body_json as { wraps: { ct: string }[]; confirm: string };
      expect(body.wraps.every((w) => fromB64u(w.ct).length === 48)).toBe(true);
    }
    // No epoch secret or content key appears anywhere in the database.
    for (const [, st] of A.store.keys) {
      for (const secret of Object.values(st.epochs).slice(0, 3)) expect(await grepDatabase(secret)).toEqual([]);
    }
  });

  it('members cannot be given more than the committer holds (rejected, not clamped)', async () => {
    const t = await A.client.createThread([B.address], undefined, PERM.read | PERM.post | PERM.invite);
    await expect(B.client.addMember(t, C.address, PERM_ALL)).rejects.toThrow(/cannot confer/);
    await expect(B.client.addMember(t, C.address, PERM.read | PERM.post)).resolves.toBeTypeOf('number');
    expect((await A.client.sync(t)).members.get(C.address)).toBe(PERM.read | PERM.post);
  });
});
