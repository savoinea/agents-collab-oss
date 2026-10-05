/**
 * Private tier: a composition of standard primitives with application-defined epochs.
 * THIS IS A NEW PROTOCOL COMPOSITION, NOT A STANDARD. It must pass external design and
 * implementation review before the Private tier is advertised.
 *
 * Primitives: HPKE base mode (RFC 9180; DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305)
 * for wrapping epoch secrets to members; HKDF-SHA256 for per-record content keys;
 * XChaCha20-Poly1305 for record and blob encryption; Ed25519 (via signed envelopes) for authenticity.
 *
 * Disclosed limits: no forward secrecy within an epoch; compromise of a member's long-term X25519
 * key or seed exposes every epoch secret ever wrapped to it; continued wrapping to a compromised
 * key gives no post-compromise recovery.
 */
import { CipherSuite, HkdfSha256 } from '@hpke/core';
import { Chacha20Poly1305 } from '@hpke/chacha20poly1305';
import { DhkemX25519HkdfSha256 } from '@hpke/dhkem-x25519';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ProtocolError, concat, ctEqual, decodeB64uExact, fromB64u, fromUtf8, randomBytes, taggedHash, toB64u } from './bytes';
import { canonicalBytes, canonicalString } from './canonical';
import { CTX, PERM, PROTOCOL_VERSION } from './constants';
import { isAddress } from './identity';
import { RECORD_ID_RE, isId, recordId, type SignedRecord } from './envelope';

const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Chacha20Poly1305(),
});

const RECORD_CT_VERSION = 2;
const RKID_LEN = 16;
const NONCE_LEN = 24;
const KC_LEN = 32;
export const MAX_PLAINTEXT_BYTES = 256 * 1024;

// ---------------------------------------------------------------------------------------------
// Epoch secret wrapping (HPKE base mode, single-shot)

export interface Wrap {
  to: string; // recipient address
  enc: string; // base64url HPKE encapsulated key (32 bytes)
  ct: string; // base64url HPKE ciphertext of the 32-byte epoch secret (+16 tag)
}

function wrapInfo(thread: string, epoch: number, to: string, committer: string): Uint8Array {
  return canonicalBytes({ ctx: CTX.epochWrap, v: PROTOCOL_VERSION, thread, epoch, to, committer });
}

export async function wrapEpochSecret(
  secret: Uint8Array,
  recipient: { address: string; kxPublic: Uint8Array },
  thread: string,
  epoch: number,
  committer: string,
): Promise<Wrap> {
  if (secret.length !== 32) throw new ProtocolError('epoch secret must be 32 bytes');
  const pk = await suite.kem.deserializePublicKey(recipient.kxPublic.slice().buffer);
  const sender = await suite.createSenderContext({ recipientPublicKey: pk, info: wrapInfo(thread, epoch, recipient.address, committer).slice().buffer });
  const ct = new Uint8Array(await sender.seal(secret.slice().buffer));
  return { to: recipient.address, enc: toB64u(new Uint8Array(sender.enc)), ct: toB64u(ct) };
}

export async function unwrapEpochSecret(
  wrap: Wrap,
  me: { address: string; kxSecret: Uint8Array },
  thread: string,
  epoch: number,
  committer: string,
): Promise<Uint8Array> {
  if (wrap.to !== me.address) throw new ProtocolError('wrap is addressed to someone else');
  const enc = decodeB64uExact(wrap.enc, 32, 'wrap.enc');
  const ct = decodeB64uExact(wrap.ct, 48, 'wrap.ct');
  const sk = await suite.kem.deserializePrivateKey(me.kxSecret.slice().buffer);
  try {
    const recipient = await suite.createRecipientContext({
      recipientKey: sk,
      enc: enc.slice().buffer,
      info: wrapInfo(thread, epoch, me.address, committer).slice().buffer,
    });
    return new Uint8Array(await recipient.open(ct.slice().buffer));
  } catch {
    throw new ProtocolError('epoch wrap could not be opened');
  }
}

export function newEpochSecret(): Uint8Array {
  return randomBytes(32);
}

// ---------------------------------------------------------------------------------------------
// Per-record content keys and record encryption

export interface RecordContext {
  thread: string;
  epoch: number;
  author: string;
  kind: string;
}

export function deriveContentKey(epochSecret: Uint8Array, thread: string, epoch: number, rkid: Uint8Array): Uint8Array {
  if (epochSecret.length !== 32) throw new ProtocolError('epoch secret must be 32 bytes');
  const info = canonicalBytes({ ctx: CTX.contentKey, thread, epoch, rkid: toB64u(rkid) });
  return hkdf(sha256, epochSecret, undefined, info, 32);
}

function recordAad(ctx: RecordContext, rkid: Uint8Array, kc: Uint8Array): Uint8Array {
  return canonicalBytes({
    ctx: 'acp/v1/record', v: RECORD_CT_VERSION, thread: ctx.thread, epoch: ctx.epoch, author: ctx.author, kind: ctx.kind,
    rkid: toB64u(rkid), kc: toB64u(kc),
  });
}

/** Key commitment: binds a ciphertext to exactly one content key (XChaCha20-Poly1305 alone does not). */
export function keyCommitment(contentKey: Uint8Array): Uint8Array {
  return taggedHash('acp/v1/key-commit', contentKey);
}

export interface EncryptedRecord {
  ct: string; // base64url: version(1) || rkid(16) || kc(32) || nonce(24) || aead ciphertext
  contentKey: Uint8Array; // kept by the author's client so it can later grant this one record
}

export function encryptRecord(epochSecret: Uint8Array, ctx: RecordContext, plaintext: Record<string, unknown>): EncryptedRecord {
  const pt = canonicalBytes(plaintext);
  if (pt.length > MAX_PLAINTEXT_BYTES) throw new ProtocolError('message too large');
  const rkid = randomBytes(RKID_LEN);
  const nonce = randomBytes(NONCE_LEN);
  const key = deriveContentKey(epochSecret, ctx.thread, ctx.epoch, rkid);
  const kc = keyCommitment(key);
  const sealed = xchacha20poly1305(key, nonce, recordAad(ctx, rkid, kc)).encrypt(pt);
  return { ct: toB64u(concat(new Uint8Array([RECORD_CT_VERSION]), rkid, kc, nonce, sealed)), contentKey: key };
}

export function parseRecordCiphertext(ct: string): { rkid: Uint8Array; kc: Uint8Array; nonce: Uint8Array; sealed: Uint8Array } {
  let raw: Uint8Array;
  try {
    raw = fromB64u(ct);
  } catch {
    throw new ProtocolError('ciphertext: not base64url');
  }
  const head = 1 + RKID_LEN + KC_LEN + NONCE_LEN;
  if (raw.length < head + 16 || raw[0] !== RECORD_CT_VERSION) throw new ProtocolError('ciphertext: bad header');
  return {
    rkid: raw.slice(1, 1 + RKID_LEN),
    kc: raw.slice(1 + RKID_LEN, 1 + RKID_LEN + KC_LEN),
    nonce: raw.slice(1 + RKID_LEN + KC_LEN, head),
    sealed: raw.slice(head),
  };
}

/** Content key for one record given its epoch secret (used by grantors to deliver selected records). */
export function contentKeyForRecord(epochSecret: Uint8Array, ctx: RecordContext, ct: string): Uint8Array {
  const { rkid } = parseRecordCiphertext(ct);
  return deriveContentKey(epochSecret, ctx.thread, ctx.epoch, rkid);
}

export function decryptRecordWithKey(contentKey: Uint8Array, ctx: RecordContext, ct: string): Record<string, unknown> {
  const { rkid, kc, nonce, sealed } = parseRecordCiphertext(ct);
  if (!ctEqual(kc, keyCommitment(contentKey))) throw new ProtocolError('record could not be decrypted: key does not match the commitment');
  let pt: Uint8Array;
  try {
    pt = xchacha20poly1305(contentKey, nonce, recordAad(ctx, rkid, kc)).decrypt(sealed);
  } catch {
    throw new ProtocolError('record could not be decrypted');
  }
  return parseCanonicalObject(pt, 'record plaintext');
}

export function decryptRecord(epochSecret: Uint8Array, ctx: RecordContext, ct: string): Record<string, unknown> {
  return decryptRecordWithKey(contentKeyForRecord(epochSecret, ctx, ct), ctx, ct);
}

/** Parses JSON and requires it to be exactly the canonical encoding (no duplicate keys, no variants). */
export function parseCanonicalObject(bytes: Uint8Array, what: string): Record<string, unknown> {
  let text: string;
  let value: unknown;
  try {
    text = fromUtf8(bytes);
    value = JSON.parse(text);
  } catch {
    throw new ProtocolError(`${what} is not valid JSON`);
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ProtocolError(`${what} is not an object`);
  let canon: string;
  try {
    canon = canonicalString(value);
  } catch {
    throw new ProtocolError(`${what} is not canonical`);
  }
  if (canon !== text) throw new ProtocolError(`${what} is not canonical`);
  return value as Record<string, unknown>;
}

// ---------------------------------------------------------------------------------------------
// Blobs (private attachments). Name, MIME type and preview live in the message plaintext.

export function encryptBlob(thread: string, blobId: string, data: Uint8Array): { key: Uint8Array; ct: Uint8Array } {
  const key = randomBytes(32);
  const nonce = randomBytes(NONCE_LEN);
  const aad = canonicalBytes({ ctx: 'acp/v1/blob', thread, blob: blobId });
  return { key, ct: concat(nonce, xchacha20poly1305(key, nonce, aad).encrypt(data)) };
}

export function decryptBlob(thread: string, blobId: string, key: Uint8Array, ct: Uint8Array): Uint8Array {
  if (ct.length < NONCE_LEN + 16) throw new ProtocolError('blob: truncated');
  const aad = canonicalBytes({ ctx: 'acp/v1/blob', thread, blob: blobId });
  try {
    return xchacha20poly1305(key, ct.slice(0, NONCE_LEN), aad).decrypt(ct.slice(NONCE_LEN));
  } catch {
    throw new ProtocolError('blob could not be decrypted');
  }
}

// ---------------------------------------------------------------------------------------------
// Epoch commits and the membership chain

export interface CommitMember {
  address: string;
  perms: number;
  kx: string; // base64url X25519 key the wrap was made to; must match the member's identity record
}

export interface CommitBody {
  ctx: 'acp/v1/epoch-commit';
  thread: string;
  epoch: number;
  prev_commit: string | null; // record id of the previous epoch commit
  members: CommitMember[]; // full membership after this commit, sorted by address
  wraps: Wrap[]; // exactly one per member, sorted by address
  confirm: string; // key confirmation: every member checks it after unwrapping (detects split secrets)
  reason: 'create' | 'add' | 'remove' | 'rotate' | 'history_grant' | 'expiry';
}

export function epochConfirmation(secret: Uint8Array, thread: string, epoch: number): string {
  return toB64u(hkdf(sha256, secret, undefined, canonicalBytes({ ctx: 'acp/v1/epoch-confirm', thread, epoch }), 32));
}

/** Unwraps this member's epoch secret and checks it against the commit's key confirmation. */
export async function openCommit(
  body: CommitBody,
  committer: string,
  me: { address: string; kxSecret: Uint8Array },
): Promise<Uint8Array> {
  const wrap = body.wraps.find((w) => w.to === me.address);
  if (!wrap) throw new ProtocolError('commit has no wrap for this identity');
  const secret = await unwrapEpochSecret(wrap, me, body.thread, body.epoch, committer);
  if (!ctEqual(fromB64u(body.confirm), fromB64u(epochConfirmation(secret, body.thread, body.epoch)))) {
    throw new ProtocolError('commit key confirmation failed: members may have been given different secrets');
  }
  return secret;
}

export function sortMembers(members: CommitMember[]): CommitMember[] {
  return [...members].sort((a, b) => (a.address < b.address ? -1 : a.address > b.address ? 1 : 0));
}

export async function buildCommit(params: {
  thread: string;
  epoch: number;
  prevCommit: string | null;
  committer: string;
  members: { address: string; perms: number; kxPublic: Uint8Array }[];
  reason: CommitBody['reason'];
}): Promise<{ body: CommitBody; secret: Uint8Array }> {
  if (!params.members.some((m) => m.address === params.committer)) {
    throw new ProtocolError('the committer must remain a member of the epoch it creates');
  }
  const secret = newEpochSecret();
  const sorted = [...params.members].sort((a, b) => (a.address < b.address ? -1 : a.address > b.address ? 1 : 0));
  const wraps: Wrap[] = [];
  for (const m of sorted) wraps.push(await wrapEpochSecret(secret, m, params.thread, params.epoch, params.committer));
  return {
    secret,
    body: {
      ctx: 'acp/v1/epoch-commit',
      thread: params.thread,
      epoch: params.epoch,
      prev_commit: params.prevCommit,
      members: sorted.map((m) => ({ address: m.address, perms: m.perms, kx: toB64u(m.kxPublic) })),
      wraps,
      confirm: epochConfirmation(secret, params.thread, params.epoch),
      reason: params.reason,
    },
  };
}

export function validateCommitBody(b: unknown): asserts b is CommitBody {
  if (!b || typeof b !== 'object') throw new ProtocolError('commit: not an object');
  const o = b as Record<string, unknown>;
  if (o.ctx !== 'acp/v1/epoch-commit') throw new ProtocolError('commit: bad ctx');
  if (!isId(o.thread)) throw new ProtocolError('commit: bad thread');
  if (typeof o.epoch !== 'number' || !Number.isSafeInteger(o.epoch) || o.epoch < 0) throw new ProtocolError('commit: bad epoch');
  if (o.epoch === 0 ? o.prev_commit !== null : typeof o.prev_commit !== 'string' || !RECORD_ID_RE.test(o.prev_commit)) {
    throw new ProtocolError('commit: prev_commit must be null exactly for epoch 0');
  }
  if (!Array.isArray(o.members) || o.members.length < 1 || o.members.length > 256) throw new ProtocolError('commit: bad members');
  if (!Array.isArray(o.wraps) || o.wraps.length !== o.members.length) throw new ProtocolError('commit: one wrap per member required');
  let last = '';
  for (let i = 0; i < o.members.length; i++) {
    const m = o.members[i] as CommitMember;
    const w = o.wraps[i] as Wrap;
    if (!m || !isAddress(m.address) || !Number.isSafeInteger(m.perms) || m.perms < 0 || m.perms > 63) throw new ProtocolError('commit: bad member');
    decodeB64uExact(m.kx, 32, 'commit.member.kx');
    if (Object.keys(m).length !== 3) throw new ProtocolError('commit: unexpected member fields');
    if (m.address <= last) throw new ProtocolError('commit: members must be sorted and unique');
    last = m.address;
    if (!w || w.to !== m.address) throw new ProtocolError('commit: wraps must align with members');
    if (Object.keys(w).length !== 3) throw new ProtocolError('commit: unexpected wrap fields');
    decodeB64uExact(w.enc, 32, 'commit.wrap.enc');
    decodeB64uExact(w.ct, 48, 'commit.wrap.ct');
  }
  decodeB64uExact(o.confirm, 32, 'commit.confirm');
  const reasons = ['create', 'add', 'remove', 'rotate', 'history_grant', 'expiry'];
  if (!reasons.includes(o.reason as string)) throw new ProtocolError('commit: bad reason');
  const allowed = new Set(['ctx', 'thread', 'epoch', 'prev_commit', 'members', 'wraps', 'confirm', 'reason']);
  for (const k of Object.keys(o)) if (!allowed.has(k)) throw new ProtocolError(`commit: unexpected field ${k}`);
}

export interface MembershipState {
  thread: string;
  epoch: number;
  head: string; // record id of the latest commit
  members: Map<string, number>;
}

/**
 * Verifies an ordered chain of epoch-commit records (signatures must already be verified with
 * verifyRecord). Rules:
 *  - epoch 0 ("create") is signed by a member who holds every permission;
 *  - each later commit links to the previous one and is signed by a member of the previous epoch;
 *  - the committer remains a member of the epoch it creates (otherwise it would know the secret
 *    of an epoch it is excluded from), so leaving is a request that a remaining member carries out;
 *  - adding, removing, or changing the permissions of any member requires invite;
 *  - no member may gain permissions the committer lacks;
 *  - an unchanged member keeps the same X25519 key unless it re-registers (never, in v1);
 *  - the reason matches the membership change.
 * `kxOf` returns the X25519 key from each member's verified identity record, so wraps are known to
 * target registered keys.
 */
export function verifyCommitChain(
  commits: { record: SignedRecord; body: CommitBody }[],
  kxOf: (address: string) => Uint8Array | undefined,
): MembershipState {
  if (commits.length === 0) throw new ProtocolError('commit chain is empty');
  let state: MembershipState | null = null;
  for (const { record, body } of commits) {
    validateCommitBody(body);
    const committer = record.envelope.author;
    if (record.envelope.kind !== 'epoch_commit' || record.envelope.epoch !== body.epoch || record.envelope.container !== body.thread) {
      throw new ProtocolError('commit: envelope does not match body');
    }
    const next = new Map(body.members.map((m) => [m.address, m.perms] as const));
    if (!next.has(committer)) throw new ProtocolError('commit: the committer must remain a member');
    for (const m of body.members) {
      const known = kxOf(m.address);
      if (!known || !ctEqual(known, fromB64u(m.kx))) throw new ProtocolError('commit: a member key does not match its identity record');
    }
    if (state === null) {
      if (body.epoch !== 0 || body.reason !== 'create') throw new ProtocolError('commit chain must start with epoch 0');
      if (next.get(committer) !== 63) throw new ProtocolError('creator must hold every permission');
    } else {
      if (body.thread !== state.thread) throw new ProtocolError('commit: thread changed');
      if (body.epoch !== state.epoch + 1) throw new ProtocolError('commit: epochs must be consecutive');
      if (body.prev_commit !== state.head) throw new ProtocolError('commit: prev_commit does not match');
      const committerPerms = state.members.get(committer);
      if (committerPerms === undefined) throw new ProtocolError('commit: committer was not a member');
      const canInvite = (committerPerms & PERM.invite) !== 0;
      let added = 0;
      let removed = 0;
      let changed = 0;
      for (const [addr, perms] of next) {
        const before = state.members.get(addr);
        if (before === perms) continue;
        if (before === undefined) added++;
        else changed++;
        if (!canInvite) throw new ProtocolError('commit: adding members or changing permissions requires invite');
        if ((perms & ~committerPerms & ~(before ?? 0)) !== 0) throw new ProtocolError('commit: cannot confer permissions the committer lacks');
      }
      for (const addr of state.members.keys()) {
        if (next.has(addr)) continue;
        removed++;
        if (!canInvite) throw new ProtocolError('commit: removing members requires invite');
      }
      const r = body.reason;
      const ok =
        r === 'create' ? false
        : added > 0 ? r === 'add'
        : removed > 0 ? r === 'remove' || r === 'expiry'
        : changed > 0 ? r === 'rotate' || r === 'add'
        : r === 'rotate' || r === 'history_grant' || r === 'expiry';
      if (!ok) throw new ProtocolError(`commit: reason "${r}" does not match the membership change`);
    }
    state = { thread: body.thread, epoch: body.epoch, head: recordId(record), members: next };
  }
  return state!;
}

// ---------------------------------------------------------------------------------------------
// Grants

export type GrantScope = 'excerpt' | 'records' | 'history';

export interface GrantBody {
  ctx: 'acp/v1/grant';
  grant_id: string;
  thread: string;
  grantor: string;
  recipient: string;
  scope: GrantScope;
  record_ids: string[]; // for 'records' (and provenance for 'excerpt')
  epoch_range: [number, number] | null; // for 'history': inclusive range of epochs delivered
  future: boolean; // recipient becomes a member and receives later epochs
  rights: number; // contribution rights (post/edit/invite/publishCard/grant bits) if future
  expiry: number | null; // unix ms
  membership_head: string; // commit record id at grant time (authority evidence)
}

export function validateGrantBody(b: unknown): asserts b is GrantBody {
  if (!b || typeof b !== 'object') throw new ProtocolError('grant: not an object');
  const o = b as Record<string, unknown>;
  if (o.ctx !== 'acp/v1/grant') throw new ProtocolError('grant: bad ctx');
  const fields = new Set(['ctx', 'grant_id', 'thread', 'grantor', 'recipient', 'scope', 'record_ids', 'epoch_range', 'future', 'rights', 'expiry', 'membership_head']);
  for (const k of Object.keys(o)) if (!fields.has(k)) throw new ProtocolError(`grant: unexpected field ${k}`);
  if (!isId(o.grant_id) || !isId(o.thread)) throw new ProtocolError('grant: bad ids');
  if (!isAddress(o.grantor) || !isAddress(o.recipient) || o.grantor === o.recipient) throw new ProtocolError('grant: bad parties');
  if (!['excerpt', 'records', 'history'].includes(o.scope as string)) throw new ProtocolError('grant: bad scope');
  if (!Array.isArray(o.record_ids) || o.record_ids.length > 1000 || !o.record_ids.every((r) => typeof r === 'string' && RECORD_ID_RE.test(r))) {
    throw new ProtocolError('grant: bad record_ids');
  }
  if (o.scope === 'records' && o.record_ids.length === 0) throw new ProtocolError('grant: records scope needs record ids');
  if (o.scope === 'history') {
    const r = o.epoch_range as unknown;
    if (!Array.isArray(r) || r.length !== 2 || !Number.isSafeInteger(r[0]) || !Number.isSafeInteger(r[1]) || r[0] < 0 || r[1] < r[0]) {
      throw new ProtocolError('grant: bad epoch_range');
    }
  } else if (o.epoch_range !== null) throw new ProtocolError('grant: epoch_range only for history scope');
  if (typeof o.future !== 'boolean') throw new ProtocolError('grant: bad future');
  if (!Number.isSafeInteger(o.rights) || (o.rights as number) < 0 || (o.rights as number) > 63) throw new ProtocolError('grant: bad rights');
  if (!o.future && o.rights !== 0) throw new ProtocolError('grant: contribution rights require future access');
  if (o.expiry !== null && (!Number.isSafeInteger(o.expiry) || (o.expiry as number) <= 0)) throw new ProtocolError('grant: bad expiry');
  if (typeof o.membership_head !== 'string' || !RECORD_ID_RE.test(o.membership_head)) throw new ProtocolError('grant: bad membership_head');
}

/** A grant record must live in the thread it names, be private, and be signed by its grantor. */
export function checkGrantPlacement(record: SignedRecord, grant: GrantBody): void {
  const e = record.envelope;
  if (e.kind !== 'grant' || e.audience !== 'private') throw new ProtocolError('grant: wrong record kind or audience');
  if (e.container !== grant.thread) throw new ProtocolError('grant: record is not in the thread it names');
  if (e.author !== grant.grantor) throw new ProtocolError('grant: record is not signed by the grantor');
}

/**
 * Checks that the grantor held the grant permission (and every conferred right) in the membership
 * state named by the grant. The caller verifies the commit chain up to membership_head first.
 */
export function checkGrantAuthority(grant: GrantBody, membership: MembershipState): void {
  if (membership.thread !== grant.thread) throw new ProtocolError('grant: membership is for another thread');
  if (membership.head !== grant.membership_head) throw new ProtocolError('grant: membership head mismatch');
  const perms = membership.members.get(grant.grantor);
  if (perms === undefined) throw new ProtocolError('grant: grantor is not a member');
  if ((perms & PERM.grant) === 0) throw new ProtocolError('grant: grantor lacks the grant permission');
  if ((grant.rights & ~perms) !== 0) throw new ProtocolError('grant: grantor cannot confer rights it lacks');
  if (grant.scope === 'history' && grant.epoch_range![1] > membership.epoch) throw new ProtocolError('grant: epoch range beyond current epoch');
}

/** Plaintext of a grant_keys record (delivered encrypted in the grantor↔recipient channel). */
export interface GrantKeysPayload {
  type: 'grant_keys';
  grant_id: string;
  grant_record: string; // record id of the signed grant
  thread: string;
  epochs: Record<string, string>; // epoch -> secret (history scope)
  records: Record<string, string>; // record id -> content key (records scope)
  excerpt: { text: string; sources: string[] } | null;
}

