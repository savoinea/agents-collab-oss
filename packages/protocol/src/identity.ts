/**
 * Identity: one 32-byte seed, two derived keys, and a signed binding between them.
 *
 * The seed is expanded with HKDF-SHA256 under distinct labels into an Ed25519 signing secret and
 * an X25519 key-agreement secret, so neither key is the raw seed and the two are independent.
 * The address is a multibase (base32, prefix "b") encoding of a tagged SHA-256 of the signing
 * public key. It verifies a key relationship, not profile claims or anyone's real-world identity.
 */
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ProtocolError, ctEqual, decodeB64uExact, randomBytes, taggedHash, toB32, toB64u, utf8 } from './bytes';
import { signingInput } from './canonical';
import { CTX, PROTOCOL_VERSION } from './constants';

export const ADDRESS_PREFIX = 'acp_b';
const ADDRESS_RE = /^acp_b[a-z2-7]{52}$/;

export interface IdentityKeys {
  seed: Uint8Array;
  signSecret: Uint8Array;
  signPublic: Uint8Array;
  kxSecret: Uint8Array;
  kxPublic: Uint8Array;
  address: string;
}

export interface IdentityRecord {
  v: number;
  kind: 'identity';
  address: string;
  sign_pub: string; // base64url, 32 bytes
  kx_pub: string; // base64url, 32 bytes
  created: number; // unix milliseconds
  binding_sig: string; // base64url Ed25519 over CTX.identityBinding
}

export function generateSeed(): Uint8Array {
  return randomBytes(32);
}

export function deriveKeys(seed: Uint8Array): IdentityKeys {
  if (seed.length !== 32) throw new ProtocolError('seed must be 32 bytes');
  const signSecret = hkdf(sha256, seed, undefined, utf8(CTX.seedSign), 32);
  const kxSecret = hkdf(sha256, seed, undefined, utf8(CTX.seedKx), 32);
  const signPublic = ed25519.getPublicKey(signSecret);
  const kxPublic = x25519.getPublicKey(kxSecret);
  return { seed, signSecret, signPublic, kxSecret, kxPublic, address: addressFromSigningKey(signPublic) };
}

export function addressFromSigningKey(signPublic: Uint8Array): string {
  if (signPublic.length !== 32) throw new ProtocolError('signing key must be 32 bytes');
  return ADDRESS_PREFIX + toB32(taggedHash(CTX.address, signPublic));
}

export function isAddress(s: unknown): s is string {
  return typeof s === 'string' && ADDRESS_RE.test(s);
}

function bindingBody(r: Omit<IdentityRecord, 'binding_sig'>) {
  return { v: r.v, kind: r.kind, address: r.address, sign_pub: r.sign_pub, kx_pub: r.kx_pub, created: r.created };
}

export function createIdentityRecord(keys: IdentityKeys, created: number = Date.now()): IdentityRecord {
  const base = {
    v: PROTOCOL_VERSION,
    kind: 'identity' as const,
    address: keys.address,
    sign_pub: toB64u(keys.signPublic),
    kx_pub: toB64u(keys.kxPublic),
    created,
  };
  const sig = ed25519.sign(signingInput(CTX.identityBinding, bindingBody(base)), keys.signSecret);
  return { ...base, binding_sig: toB64u(sig) };
}

export interface VerifiedIdentity {
  address: string;
  signPublic: Uint8Array;
  kxPublic: Uint8Array;
  created: number;
}

/**
 * Verifies an identity record offline: shape, address derivation, the key-binding signature, and
 * that the X25519 key is not a low-order point. A relay cannot substitute the encryption key
 * without breaking the binding signature.
 */
export function verifyIdentityRecord(input: unknown): VerifiedIdentity {
  if (!input || typeof input !== 'object') throw new ProtocolError('identity: not an object');
  const r = input as Record<string, unknown>;
  const allowed = new Set(['v', 'kind', 'address', 'sign_pub', 'kx_pub', 'created', 'binding_sig']);
  for (const k of Object.keys(r)) if (!allowed.has(k)) throw new ProtocolError(`identity: unexpected field ${k}`);
  if (r.v !== PROTOCOL_VERSION) throw new ProtocolError('identity: unsupported version');
  if (r.kind !== 'identity') throw new ProtocolError('identity: wrong kind');
  if (!isAddress(r.address)) throw new ProtocolError('identity: malformed address');
  if (typeof r.created !== 'number' || !Number.isSafeInteger(r.created) || r.created < 0) {
    throw new ProtocolError('identity: bad created');
  }
  const signPublic = decodeB64uExact(r.sign_pub, 32, 'identity.sign_pub');
  const kxPublic = decodeB64uExact(r.kx_pub, 32, 'identity.kx_pub');
  const sig = decodeB64uExact(r.binding_sig, 64, 'identity.binding_sig');
  if (!ctEqual(utf8(addressFromSigningKey(signPublic)), utf8(r.address))) {
    throw new ProtocolError('identity: address does not match signing key');
  }
  assertUsableX25519(kxPublic);
  const body = bindingBody(r as unknown as IdentityRecord);
  if (!ed25519.verify(sig, signingInput(CTX.identityBinding, body), signPublic, { zip215: false })) {
    throw new ProtocolError('identity: binding signature invalid');
  }
  return { address: r.address, signPublic, kxPublic, created: r.created };
}

/** Rejects low-order X25519 public keys, which would yield an all-zero shared secret. */
export function assertUsableX25519(pub: Uint8Array): void {
  try {
    // A fixed non-secret scalar; noble throws if the result is the all-zero point.
    x25519.getSharedSecret(sha256(utf8('acp/v1/x25519-check')), pub);
  } catch {
    throw new ProtocolError('identity: unusable X25519 key');
  }
}

/** Proof of possession: the holder signs a server- or peer-issued challenge. */
export function signChallenge(keys: IdentityKeys, challenge: string, audience: string): string {
  return toB64u(ed25519.sign(signingInput(CTX.challenge, { challenge, audience, address: keys.address }), keys.signSecret));
}

export function verifyChallenge(
  signPublic: Uint8Array,
  address: string,
  challenge: string,
  audience: string,
  signature: string,
): boolean {
  let sig: Uint8Array;
  try {
    sig = decodeB64uExact(signature, 64, 'challenge.sig');
  } catch {
    return false;
  }
  if (addressFromSigningKey(signPublic) !== address) return false;
  return ed25519.verify(sig, signingInput(CTX.challenge, { challenge, audience, address }), signPublic, { zip215: false });
}

export function signDetached(keys: IdentityKeys, context: string, value: unknown): string {
  return toB64u(ed25519.sign(signingInput(context, value), keys.signSecret));
}

export function verifyDetached(signPublic: Uint8Array, context: string, value: unknown, signature: unknown): boolean {
  let sig: Uint8Array;
  try {
    sig = decodeB64uExact(signature, 64, 'signature');
  } catch {
    return false;
  }
  try {
    return ed25519.verify(sig, signingInput(context, value), signPublic, { zip215: false });
  } catch {
    return false;
  }
}
