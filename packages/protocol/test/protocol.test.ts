import { describe, expect, it } from 'vitest';
import {
  PERM, PERM_ALL, ProtocolError, buildCommit, canonicalString, checkGrantAuthority, createExport, createIdentityRecord,
  decryptBlob, decryptRecord, decryptRecordWithKey, deriveKeys, encryptBlob, encryptRecord, fromHex, importExport,
  isAddress, recordId, signChallenge, signRecord, signRequest, toB64u, unwrapEpochSecret, validateGrantBody,
  verifyChain, verifyChallenge, verifyCommitChain, verifyIdentityRecord, verifyRecord, verifyRequest, contentKeyForRecord,
  cardHash, signCardApproval, validateCardContent, verifyCardApproval, randomBytes, openCommit, wrapEpochSecret,
  type CommitBody, type GrantBody, type SignedRecord, type RequestParts,
} from '@acp/protocol';

const seedA = fromHex('00'.repeat(31) + '01');
const seedB = fromHex('00'.repeat(31) + '02');
const seedC = fromHex('00'.repeat(31) + '03');
const A = deriveKeys(seedA);
const B = deriveKeys(seedB);
const C = deriveKeys(seedC);
const THREAD = 'AAAAAAAAAAAAAAAAAAAAAA';
const kxAll = (a: string) => [A, B, C].find((k) => k.address === a)?.kxPublic;

describe('canonical bytes', () => {
  it('sorts keys by code unit and has no whitespace', () => {
    expect(canonicalString({ b: 1, a: [true, null, 'x'], é: 2, Z: 0 })).toBe('{"Z":0,"a":[true,null,"x"],"b":1,"é":2}');
  });
  it('rejects floats, unsafe integers, undefined, lone surrogates and class instances', () => {
    expect(() => canonicalString({ a: 1.5 })).toThrow(ProtocolError);
    expect(() => canonicalString({ a: 2 ** 60 })).toThrow(ProtocolError);
    expect(() => canonicalString({ a: undefined })).toThrow(ProtocolError);
    expect(() => canonicalString({ a: '\uD800' })).toThrow(ProtocolError);
    expect(() => canonicalString({ a: new Date() })).toThrow(ProtocolError);
  });
});

describe('identity', () => {
  it('derives independent keys and a self-authenticating address', () => {
    expect(isAddress(A.address)).toBe(true);
    expect(A.address).not.toBe(B.address);
    expect(toB64u(A.signSecret)).not.toBe(toB64u(A.kxSecret));
    expect(toB64u(A.signSecret)).not.toBe(toB64u(seedA));
  });
  it('verifies a binding record and rejects substituted encryption keys', () => {
    const rec = createIdentityRecord(A, 1700000000000);
    expect(verifyIdentityRecord(rec).address).toBe(A.address);
    expect(() => verifyIdentityRecord({ ...rec, kx_pub: toB64u(B.kxPublic) })).toThrow(/binding signature/);
    expect(() => verifyIdentityRecord({ ...rec, address: B.address })).toThrow(/address/);
    expect(() => verifyIdentityRecord({ ...rec, extra: 1 })).toThrow(/unexpected/);
  });
  it('rejects a low-order X25519 key even with a valid-looking record', () => {
    const rec = createIdentityRecord(A, 1700000000000);
    expect(() => verifyIdentityRecord({ ...rec, kx_pub: toB64u(new Uint8Array(32)) })).toThrow(/X25519/);
  });
  it('proves possession with an audience-bound challenge signature', () => {
    const sig = signChallenge(A, 'nonce-123', 'https://example.test');
    expect(verifyChallenge(A.signPublic, A.address, 'nonce-123', 'https://example.test', sig)).toBe(true);
    expect(verifyChallenge(A.signPublic, A.address, 'nonce-123', 'https://other.test', sig)).toBe(false);
    expect(verifyChallenge(B.signPublic, A.address, 'nonce-123', 'https://example.test', sig)).toBe(false);
  });
});

function chainOf(n: number): SignedRecord[] {
  const out: SignedRecord[] = [];
  let prev: string | null = null;
  for (let i = 0; i < n; i++) {
    const r = signRecord(A, {
      container: THREAD, base_seq: i, prev, audience: 'public', kind: i === 0 ? 'thread' : 'post',
      body: { type: 'json', value: { text: `post ${i}` } }, ts: 1700000000000 + i,
    });
    out.push(r);
    prev = recordId(r);
  }
  return out;
}

describe('signed records', () => {
  it('verifies signature and body hash; rejects tampering and impersonation', () => {
    const body = { type: 'json' as const, value: { title: 't', text: 'hello' } };
    const r = signRecord(A, { container: THREAD, base_seq: 0, prev: null, audience: 'public', kind: 'thread', body });
    expect(() => verifyRecord(r, A.signPublic, body)).not.toThrow();
    expect(() => verifyRecord(r, A.signPublic, { type: 'json', value: { title: 't', text: 'HELLO' } })).toThrow(/body_hash/);
    expect(() => verifyRecord({ ...r, envelope: { ...r.envelope, audience: 'member' } }, A.signPublic, body)).toThrow(/signature/);
    expect(() => verifyRecord(r, B.signPublic, body)).toThrow(/author/);
  });
  it('requires ciphertext bodies for private messages', () => {
    const r = signRecord(A, { container: THREAD, base_seq: 0, prev: null, audience: 'private', kind: 'private_msg', epoch: 0, body: { type: 'json', value: { text: 'plain' } } });
    expect(() => verifyRecord(r, A.signPublic, { type: 'json', value: { text: 'plain' } })).toThrow(/body type/);
  });
  it('detects reordering, gaps and substitution in a chain', () => {
    const chain = chainOf(4);
    expect(verifyChain(chain).ok).toBe(true);
    expect(verifyChain([chain[0]!, chain[2]!, chain[1]!, chain[3]!]).ok).toBe(false);
    expect(verifyChain([chain[0]!, chain[1]!, chain[3]!]).ok).toBe(false);
    const forged = signRecord(B, { container: THREAD, base_seq: 1, prev: 'x'.repeat(43), audience: 'public', kind: 'post', body: { type: 'json', value: { text: 'f' } } });
    expect(verifyChain([chain[0]!, forged]).ok).toBe(false);
  });
});

describe('HTTP message signatures', () => {
  const parts: RequestParts = { method: 'POST', authority: 'example.test', path: '/api/records', query: '?', body: new TextEncoder().encode('{"a":1}') };
  const lookup = async (addr: string) => (addr === A.address ? A.signPublic : addr === B.address ? B.signPublic : null);
  it('round-trips and rejects body, path, authority and time tampering', async () => {
    const now = 1_700_000_000;
    const h = signRequest(A, parts, now);
    const ok = await verifyRequest(parts, h, { now, maxSkewSeconds: 120, lookupKey: lookup });
    expect(ok.address).toBe(A.address);
    await expect(verifyRequest({ ...parts, body: new TextEncoder().encode('{"a":2}') }, h, { now, maxSkewSeconds: 120, lookupKey: lookup })).rejects.toThrow(/content-digest/);
    await expect(verifyRequest({ ...parts, path: '/api/other' }, h, { now, maxSkewSeconds: 120, lookupKey: lookup })).rejects.toThrow(/signature invalid/);
    await expect(verifyRequest({ ...parts, authority: 'evil.test' }, h, { now, maxSkewSeconds: 120, lookupKey: lookup })).rejects.toThrow(/signature invalid/);
    await expect(verifyRequest(parts, h, { now: now + 1000, maxSkewSeconds: 120, lookupKey: lookup })).rejects.toThrow(/window/);
  });
  it('rejects a signature-input naming a different key than the one that signed', async () => {
    const now = 1_700_000_000;
    const h = signRequest(A, parts, now);
    const swapped = { ...h, 'signature-input': h['signature-input'].replace(A.address, B.address) };
    await expect(verifyRequest(parts, swapped, { now, maxSkewSeconds: 120, lookupKey: lookup })).rejects.toThrow(/signature invalid/);
  });
  it('rejects any other component profile', async () => {
    const now = 1_700_000_000;
    const h = signRequest(A, parts, now);
    const weaker = { ...h, 'signature-input': h['signature-input'].replace(' "content-digest"', '') };
    await expect(verifyRequest(parts, weaker, { now, maxSkewSeconds: 120, lookupKey: lookup })).rejects.toThrow(/profile/);
  });
});

describe('identity export', () => {
  it('round-trips, and rejects wrong passphrase, truncation, tampering and short passphrases', async () => {
    const identity = createIdentityRecord(A, 1700000000000);
    const history = { [THREAD]: { epochs: { '0': toB64u(randomBytes(32)) }, records: {} } };
    const text = await createExport({ seed: seedA, identity, history, grants: [], exported_at: 1 }, 'correct horse battery staple');
    const back = await importExport(text, 'correct horse battery staple');
    expect(back.keys.address).toBe(A.address);
    expect(back.payload.history).toEqual(history);
    await expect(importExport(text, 'wrong passphrase value')).rejects.toThrow(/wrong passphrase/);
    await expect(importExport(text.slice(0, 120), 'correct horse battery staple')).rejects.toThrow(/incomplete/);
    const lines = text.split('\n');
    const mid = lines[2]!;
    lines[2] = (mid[5] === 'A' ? 'B' : 'A') + mid.slice(1);
    await expect(importExport(lines.join('\n'), 'correct horse battery staple')).rejects.toThrow(ProtocolError);
    await expect(createExport({ seed: seedA, identity, history: {}, grants: [], exported_at: 1 }, 'short')).rejects.toThrow(/at least/);
  }, 60000);
});

describe('private tier composition', () => {
  const members = [
    { address: A.address, perms: PERM_ALL, kxPublic: A.kxPublic },
    { address: B.address, perms: PERM.read | PERM.post, kxPublic: B.kxPublic },
  ];

  function commitRecord(keys: typeof A, body: CommitBody, base_seq: number, prev: string | null): SignedRecord {
    return signRecord(keys, { container: THREAD, base_seq, prev, audience: 'private', kind: 'epoch_commit', epoch: body.epoch, body: { type: 'json', value: body as unknown as Record<string, unknown> } });
  }

  it('wraps epoch secrets only to named members, bound to thread, epoch and committer', async () => {
    const { body, secret } = await buildCommit({ thread: THREAD, epoch: 0, prevCommit: null, committer: A.address, members, reason: 'create' });
    const wrapB = body.wraps.find((w) => w.to === B.address)!;
    const got = await unwrapEpochSecret(wrapB, { address: B.address, kxSecret: B.kxSecret }, THREAD, 0, A.address);
    expect(toB64u(got)).toBe(toB64u(secret));
    await expect(unwrapEpochSecret(wrapB, { address: B.address, kxSecret: B.kxSecret }, THREAD, 1, A.address)).rejects.toThrow();
    await expect(unwrapEpochSecret(wrapB, { address: B.address, kxSecret: B.kxSecret }, THREAD, 0, C.address)).rejects.toThrow();
    await expect(unwrapEpochSecret({ ...wrapB, to: C.address }, { address: C.address, kxSecret: C.kxSecret }, THREAD, 0, A.address)).rejects.toThrow();
  });

  it('detects split epoch secrets through key confirmation', async () => {
    const c0 = await buildCommit({ thread: THREAD, epoch: 0, prevCommit: null, committer: A.address, members, reason: 'create' });
    expect(toB64u(await openCommit(c0.body, A.address, { address: B.address, kxSecret: B.kxSecret }))).toBe(toB64u(c0.secret));
    // Committer gives B a different secret than A.
    const other = await wrapEpochSecret(randomBytes(32), { address: B.address, kxPublic: B.kxPublic }, THREAD, 0, A.address);
    const split = { ...c0.body, wraps: c0.body.wraps.map((w) => (w.to === B.address ? other : w)) };
    await expect(openCommit(split, A.address, { address: B.address, kxSecret: B.kxSecret })).rejects.toThrow(/confirmation/);
  });

  it('commits each ciphertext to one content key', () => {
    const secret = randomBytes(32);
    const ctx = { thread: THREAD, epoch: 0, author: A.address, kind: 'private_msg' };
    const enc = encryptRecord(secret, ctx, { text: 'x' });
    expect(() => decryptRecordWithKey(randomBytes(32), ctx, enc.ct)).toThrow(/commitment/);
  });

  it('rejects kinds outside their allowed audiences', () => {
    expect(() => signRecord(A, { container: THREAD, base_seq: 0, prev: null, audience: 'public', kind: 'private_msg', body: { type: 'json', value: { text: 'x' } } })).toThrow(/not allowed/);
  });

  it('encrypts records under per-record keys bound to author, kind, thread and epoch', () => {
    const secret = randomBytes(32);
    const ctx = { thread: THREAD, epoch: 0, author: A.address, kind: 'private_msg' };
    const enc = encryptRecord(secret, ctx, { text: 'marker-123' });
    expect(decryptRecord(secret, ctx, enc.ct).text).toBe('marker-123');
    expect(decryptRecordWithKey(contentKeyForRecord(secret, ctx, enc.ct), ctx, enc.ct).text).toBe('marker-123');
    expect(() => decryptRecord(secret, { ...ctx, author: B.address }, enc.ct)).toThrow();
    expect(() => decryptRecord(secret, { ...ctx, epoch: 1 }, enc.ct)).toThrow();
    const other = encryptRecord(secret, ctx, { text: 'other' });
    // A key for one record does not open another record in the same epoch.
    expect(() => decryptRecordWithKey(enc.contentKey, ctx, other.ct)).toThrow();
  });

  it('encrypts blobs with metadata kept out of the ciphertext header', () => {
    const { key, ct } = encryptBlob(THREAD, 'BBBBBBBBBBBBBBBBBBBBBB', new TextEncoder().encode('file'));
    expect(new TextDecoder().decode(decryptBlob(THREAD, 'BBBBBBBBBBBBBBBBBBBBBB', key, ct))).toBe('file');
    expect(() => decryptBlob(THREAD, 'CCCCCCCCCCCCCCCCCCCCCC', key, ct)).toThrow();
  });

  it('verifies the membership chain and rejects unauthorised commits', async () => {
    const c0 = await buildCommit({ thread: THREAD, epoch: 0, prevCommit: null, committer: A.address, members, reason: 'create' });
    const r0 = commitRecord(A, c0.body, 0, null);
    // B (no invite) tries to add C.
    const bad = await buildCommit({ thread: THREAD, epoch: 1, prevCommit: recordId(r0), committer: B.address, members: [...members, { address: C.address, perms: PERM.read, kxPublic: C.kxPublic }], reason: 'add' });
    const rBad = commitRecord(B, bad.body, 1, recordId(r0));
    expect(() => verifyCommitChain([{ record: r0, body: c0.body }, { record: rBad, body: bad.body }], kxAll)).toThrow(/invite/);
    // A committer cannot drop itself: it would know the secret of an epoch it is excluded from.
    await expect(buildCommit({ thread: THREAD, epoch: 1, prevCommit: recordId(r0), committer: B.address, members: [members[0]!], reason: 'remove' })).rejects.toThrow(/remain/);
    const forgedLeave = { ...c0.body, epoch: 1, prev_commit: recordId(r0), members: c0.body.members.filter((m) => m.address === A.address), wraps: c0.body.wraps.filter((w) => w.to === A.address), reason: 'remove' as const };
    expect(() => verifyCommitChain([{ record: r0, body: c0.body }, { record: commitRecord(B, forgedLeave, 1, recordId(r0)), body: forgedLeave }], kxAll)).toThrow(/remain/);
    // A excludes B: new epoch secret is not wrapped to B.
    const excl = await buildCommit({ thread: THREAD, epoch: 1, prevCommit: recordId(r0), committer: A.address, members: [members[0]!], reason: 'remove' });
    expect(excl.body.wraps.some((w) => w.to === B.address)).toBe(false);
    expect(toB64u(excl.secret)).not.toBe(toB64u(c0.secret));
    const rExcl = commitRecord(A, excl.body, 1, recordId(r0));
    const kx = new Map([[A.address, A.kxPublic], [B.address, B.kxPublic]]);
    expect(verifyCommitChain([{ record: r0, body: c0.body }, { record: rExcl, body: excl.body }], (a) => kx.get(a)).members.size).toBe(1);
    // Reason must match the change.
    const mislabelled = { ...excl.body, reason: 'rotate' as const };
    expect(() => verifyCommitChain([{ record: r0, body: c0.body }, { record: commitRecord(A, mislabelled, 1, recordId(r0)), body: mislabelled }], kxAll)).toThrow(/reason/);
    // Member keys must match identity records.
    expect(() => verifyCommitChain([{ record: r0, body: c0.body }], (a) => (a === B.address ? C.kxPublic : kx.get(a)))).toThrow(/identity record/);
  });

  it('checks the grantor holds the grant right and every conferred right', async () => {
    const c0 = await buildCommit({ thread: THREAD, epoch: 0, prevCommit: null, committer: A.address, members, reason: 'create' });
    const r0 = commitRecord(A, c0.body, 0, null);
    const state = verifyCommitChain([{ record: r0, body: c0.body }], kxAll);
    const grant: GrantBody = {
      ctx: 'acp/v1/grant', grant_id: 'GGGGGGGGGGGGGGGGGGGGGG', thread: THREAD, grantor: A.address, recipient: C.address,
      scope: 'history', record_ids: [], epoch_range: [0, 0], future: false, rights: 0, expiry: null, membership_head: recordId(r0),
    };
    validateGrantBody(grant);
    expect(() => checkGrantAuthority(grant, state)).not.toThrow();
    expect(() => checkGrantAuthority({ ...grant, grantor: B.address }, state)).toThrow(/grant permission/);
    expect(() => validateGrantBody({ ...grant, rights: PERM.post })).toThrow(/future/);
    expect(() => checkGrantAuthority({ ...grant, epoch_range: [0, 3] }, state)).toThrow(/beyond/);
  });
});

describe('cards', () => {
  it('requires a capability card contact to be its owner', () => {
    expect(() => validateCardContent({ kind: 'capability', owner: A.address, contact: B.address, audience: 'public', space: null, topics: ['x'], summary: 's', services: '', availability: 'now' })).toThrow(/owner/);
  });
  it('invalidates approvals when content or audience changes', () => {
    const card = validateCardContent({
      kind: 'discovery', thread: THREAD, audience: 'member', space: 'SSSSSSSSSSSSSSSSSSSSSS', topics: ['postgres'], summary: 'Pool sizing',
      contact: A.address, participants: [], date_range: null,
      access_policy: { who_may_request: 'any member', who_may_grant: 'contact', offers: ['excerpt'] },
    });
    const sig = signCardApproval(A, card);
    expect(verifyCardApproval(A.signPublic, A.address, card, sig)).toBe(true);
    const widened = validateCardContent({ ...card, audience: 'public', space: null });
    expect(cardHash(widened)).not.toBe(cardHash(card));
    expect(verifyCardApproval(A.signPublic, A.address, widened, sig)).toBe(false);
  });
});
