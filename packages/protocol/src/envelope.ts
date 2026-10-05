/**
 * Signed records with a per-container hash chain.
 *
 * Every contribution is a signed envelope over canonical bytes. The envelope commits to the
 * author, container, base sequence, previous-record hash, time, audience, kind, a hash of the
 * body, and (for revisions/tombstones) the target record and base revision. The server assigns
 * the sequence number on accept and rejects a stale head with a conflict.
 *
 * Disclosed limits: the server can withhold or omit records; a fork is detectable only when two
 * clients compare heads; a selectively disclosed record proves authorship and its position, not
 * that the chain is complete; deletion is a signed tombstone and cannot recall copies.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { ProtocolError, decodeB64uExact, fromB64u, taggedHash, toB64u } from './bytes';
import { canonicalBytes, signingInput } from './canonical';
import { AUDIENCES, CTX, KIND_AUDIENCES, PROTOCOL_VERSION, RECORD_KINDS, type Audience, type RecordKind } from './constants';
import { addressFromSigningKey, isAddress, type IdentityKeys } from './identity';

export const ID_RE = /^[A-Za-z0-9_-]{22,43}$/;
export const RECORD_ID_RE = /^[A-Za-z0-9_-]{43}$/;

export function isId(s: unknown): s is string {
  return typeof s === 'string' && ID_RE.test(s);
}

export type Body = { type: 'json'; value: Record<string, unknown> } | { type: 'ciphertext'; ct: string };

export interface Envelope {
  v: number;
  author: string;
  container: string;
  base_seq: number; // sequence of the record this one follows; 0 for the first record
  prev: string | null; // record id of the previous record, null for the first
  ts: number;
  audience: Audience;
  kind: RecordKind;
  body_hash: string;
  target?: string;
  base_rev?: string;
  epoch?: number;
}

export interface SignedRecord {
  envelope: Envelope;
  sig: string;
}

/** Private-audience kinds whose bodies are signed JSON metadata rather than ciphertext. */
export const PRIVATE_JSON_KINDS: readonly RecordKind[] = ['grant', 'epoch_commit'];

export function bodyHash(body: Body): string {
  const normalized = body.type === 'json' ? { type: 'json', value: body.value } : { type: 'ciphertext', ct: body.ct };
  return toB64u(taggedHash('acp/v1/body', canonicalBytes(normalized)));
}

export function recordId(rec: SignedRecord): string {
  return toB64u(taggedHash(CTX.recordId, canonicalBytes({ envelope: rec.envelope, sig: rec.sig })));
}

export interface EnvelopeInput {
  container: string;
  base_seq: number;
  prev: string | null;
  audience: Audience;
  kind: RecordKind;
  body: Body;
  target?: string;
  base_rev?: string;
  epoch?: number;
  ts?: number;
}

export function signRecord(keys: IdentityKeys, input: EnvelopeInput): SignedRecord {
  const envelope: Envelope = {
    v: PROTOCOL_VERSION,
    author: keys.address,
    container: input.container,
    base_seq: input.base_seq,
    prev: input.prev,
    ts: input.ts ?? Date.now(),
    audience: input.audience,
    kind: input.kind,
    body_hash: bodyHash(input.body),
  };
  if (input.target !== undefined) envelope.target = input.target;
  if (input.base_rev !== undefined) envelope.base_rev = input.base_rev;
  if (input.epoch !== undefined) envelope.epoch = input.epoch;
  validateEnvelopeShape(envelope);
  const sig = toB64u(ed25519.sign(signingInput(CTX.envelope, envelope), keys.signSecret));
  return { envelope, sig };
}

const ENVELOPE_FIELDS = new Set([
  'v', 'author', 'container', 'base_seq', 'prev', 'ts', 'audience', 'kind', 'body_hash', 'target', 'base_rev', 'epoch',
]);

export function validateEnvelopeShape(e: unknown): asserts e is Envelope {
  if (!e || typeof e !== 'object' || Array.isArray(e)) throw new ProtocolError('envelope: not an object');
  const o = e as Record<string, unknown>;
  for (const k of Object.keys(o)) if (!ENVELOPE_FIELDS.has(k)) throw new ProtocolError(`envelope: unexpected field ${k}`);
  if (o.v !== PROTOCOL_VERSION) throw new ProtocolError('envelope: unsupported version');
  if (!isAddress(o.author)) throw new ProtocolError('envelope: bad author');
  if (!isId(o.container)) throw new ProtocolError('envelope: bad container');
  if (typeof o.base_seq !== 'number' || !Number.isSafeInteger(o.base_seq) || o.base_seq < 0) {
    throw new ProtocolError('envelope: bad base_seq');
  }
  if (o.base_seq === 0 ? o.prev !== null : typeof o.prev !== 'string' || !RECORD_ID_RE.test(o.prev)) {
    throw new ProtocolError('envelope: prev must be null exactly when base_seq is 0');
  }
  if (typeof o.ts !== 'number' || !Number.isSafeInteger(o.ts) || o.ts <= 0) throw new ProtocolError('envelope: bad ts');
  if (!AUDIENCES.includes(o.audience as Audience)) throw new ProtocolError('envelope: bad audience');
  if (!RECORD_KINDS.includes(o.kind as RecordKind)) throw new ProtocolError('envelope: bad kind');
  if (!KIND_AUDIENCES[o.kind as string]!.includes(o.audience as Audience)) throw new ProtocolError(`envelope: kind ${String(o.kind)} is not allowed in audience ${String(o.audience)}`);
  decodeB64uExact(o.body_hash, 32, 'envelope.body_hash');
  if (o.target !== undefined && (typeof o.target !== 'string' || !ID_RE.test(o.target))) throw new ProtocolError('envelope: bad target');
  if (o.base_rev !== undefined && (typeof o.base_rev !== 'string' || !RECORD_ID_RE.test(o.base_rev))) {
    throw new ProtocolError('envelope: bad base_rev');
  }
  if (o.epoch !== undefined && (typeof o.epoch !== 'number' || !Number.isSafeInteger(o.epoch) || o.epoch < 0)) {
    throw new ProtocolError('envelope: bad epoch');
  }
  if (o.audience === 'private' && o.epoch === undefined && o.kind !== 'grant') {
    // grant objects are metadata; every other private record (and every commit) names an epoch
    throw new ProtocolError('envelope: private records must name an epoch');
  }
}

/**
 * Verifies the envelope signature and that the body matches body_hash. The caller supplies the
 * author's signing key, fetched from (and checked against) the author's verified identity record.
 */
export function verifyRecord(rec: unknown, authorSignPublic: Uint8Array, body?: Body): SignedRecord {
  if (!rec || typeof rec !== 'object') throw new ProtocolError('record: not an object');
  const r = rec as Record<string, unknown>;
  for (const k of Object.keys(r)) if (k !== 'envelope' && k !== 'sig') throw new ProtocolError(`record: unexpected field ${k}`);
  validateEnvelopeShape(r.envelope);
  const envelope = r.envelope;
  if (addressFromSigningKey(authorSignPublic) !== envelope.author) throw new ProtocolError('record: key does not match author');
  const sig = decodeB64uExact(r.sig, 64, 'record.sig');
  if (!ed25519.verify(sig, signingInput(CTX.envelope, envelope), authorSignPublic, { zip215: false })) {
    throw new ProtocolError('record: signature invalid');
  }
  if (body !== undefined) {
    validateBody(body);
    if (bodyHash(body) !== envelope.body_hash) throw new ProtocolError('record: body does not match body_hash');
    const expectCiphertext = envelope.audience === 'private' && !PRIVATE_JSON_KINDS.includes(envelope.kind);
    if (expectCiphertext !== (body.type === 'ciphertext')) {
      throw new ProtocolError('record: body type does not match audience and kind');
    }
  }
  return { envelope, sig: r.sig as string };
}

export function validateBody(b: unknown): asserts b is Body {
  if (!b || typeof b !== 'object') throw new ProtocolError('body: not an object');
  const o = b as Record<string, unknown>;
  if (o.type === 'json') {
    if (Object.keys(o).length !== 2 || !o.value || typeof o.value !== 'object' || Array.isArray(o.value)) {
      throw new ProtocolError('body: bad json body');
    }
    canonicalBytes(o.value); // throws on non-canonical content
  } else if (o.type === 'ciphertext') {
    if (Object.keys(o).length !== 2 || typeof o.ct !== 'string') throw new ProtocolError('body: bad ciphertext body');
    try {
      fromB64u(o.ct);
    } catch {
      throw new ProtocolError('body: ciphertext not base64url');
    }
  } else {
    throw new ProtocolError('body: unknown type');
  }
}

export interface ChainResult {
  ok: boolean;
  head: string | null;
  length: number;
  error?: string;
}

/** Verifies continuity of an ordered list of records in one container (signatures checked separately). */
export function verifyChain(records: SignedRecord[]): ChainResult {
  let prev: string | null = null;
  let container: string | null = null;
  for (let i = 0; i < records.length; i++) {
    const e = records[i]!.envelope;
    if (container === null) container = e.container;
    if (e.container !== container) return { ok: false, head: prev, length: i, error: `record ${i + 1}: container changed` };
    if (e.base_seq !== i) return { ok: false, head: prev, length: i, error: `record ${i + 1}: base_seq ${e.base_seq}, expected ${i}` };
    if (e.prev !== prev) return { ok: false, head: prev, length: i, error: `record ${i + 1}: prev hash does not match` };
    prev = recordId(records[i]!);
  }
  return { ok: true, head: prev, length: records.length };
}
