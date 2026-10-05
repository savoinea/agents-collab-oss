/**
 * RFC 9421 HTTP Message Signatures for every write, with RFC 9530 Content-Digest.
 *
 * This implements one fixed profile, and verifiers reject anything else:
 *   covered components: "@method" "@authority" "@path" "@query" "content-digest"
 *   parameters: created, nonce, keyid (the signer's address), alg="ed25519", tag="acp-write"
 * Unlike the Web Bot Auth minimum, the body is covered through content-digest.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ProtocolError, ctEqual, fromB64, randomBytes, toB64, toB64u, utf8 } from './bytes';
import { addressFromSigningKey, isAddress, type IdentityKeys } from './identity';

export const SIG_LABEL = 'sig1';
export const SIG_TAG = 'acp-write';
export const COMPONENTS = ['@method', '@authority', '@path', '@query', 'content-digest'] as const;

export interface RequestParts {
  method: string;
  authority: string; // host[:port], lowercase
  path: string; // absolute path, already percent-encoded as sent
  query: string; // "?..." or "?" when empty, per RFC 9421 §2.2.7
  body: Uint8Array;
}

export interface SignatureHeaders {
  'content-digest': string;
  'signature-input': string;
  signature: string;
}

export function contentDigest(body: Uint8Array): string {
  return `sha-256=:${toB64(sha256(body))}:`;
}

function paramsString(created: number, nonce: string, keyid: string): string {
  const comps = COMPONENTS.map((c) => `"${c}"`).join(' ');
  return `(${comps});created=${created};nonce="${nonce}";keyid="${keyid}";alg="ed25519";tag="${SIG_TAG}"`;
}

export function signatureBase(parts: RequestParts, digest: string, params: string): string {
  const lines = [
    `"@method": ${parts.method.toUpperCase()}`,
    `"@authority": ${parts.authority.toLowerCase()}`,
    `"@path": ${parts.path}`,
    `"@query": ${parts.query || '?'}`,
    `"content-digest": ${digest}`,
    `"@signature-params": ${params}`,
  ];
  return lines.join('\n');
}

export function signRequest(
  keys: IdentityKeys,
  parts: RequestParts,
  created = Math.floor(Date.now() / 1000),
  nonce = toB64u(randomBytes(18)),
): SignatureHeaders {
  const digest = contentDigest(parts.body);
  const params = paramsString(created, nonce, keys.address);
  const base = signatureBase(parts, digest, params);
  const sig = ed25519.sign(utf8(base), keys.signSecret);
  return {
    'content-digest': digest,
    'signature-input': `${SIG_LABEL}=${params}`,
    signature: `${SIG_LABEL}=:${toB64(sig)}:`,
  };
}

export interface ParsedSignatureInput {
  params: string;
  created: number;
  nonce: string;
  keyid: string;
}

const INPUT_RE =
  /^sig1=(\("@method" "@authority" "@path" "@query" "content-digest"\);created=(\d{1,12});nonce="([A-Za-z0-9_-]{16,64})";keyid="(acp_b[a-z2-7]{52})";alg="ed25519";tag="acp-write")$/;

/** Strict parse: exactly our profile, in our order. Anything else is rejected. */
export function parseSignatureInput(header: string | undefined): ParsedSignatureInput {
  if (typeof header !== 'string') throw new ProtocolError('signature-input missing');
  const m = INPUT_RE.exec(header.trim());
  if (!m) throw new ProtocolError('signature-input does not match the required profile');
  const created = Number(m[2]);
  if (!isAddress(m[4])) throw new ProtocolError('signature-input: bad keyid');
  return { params: m[1]!, created, nonce: m[3]!, keyid: m[4]! };
}

export function parseSignature(header: string | undefined): Uint8Array {
  if (typeof header !== 'string') throw new ProtocolError('signature missing');
  const m = /^sig1=:([A-Za-z0-9+/]{86}==):$/.exec(header.trim());
  if (!m) throw new ProtocolError('signature header malformed');
  return fromB64(m[1]!);
}

export interface VerifyOptions {
  now?: number; // unix seconds
  maxSkewSeconds: number;
  lookupKey: (address: string) => Promise<Uint8Array | null>;
}

export interface VerifiedRequest {
  address: string;
  nonce: string;
  created: number;
}

/**
 * Verifies a signed write. The caller must additionally (a) check the nonce has not been seen in
 * the replay window and record it, and (b) check that the verified address is the acting identity
 * named in the request body. Those are separate checks by design.
 */
export async function verifyRequest(
  parts: RequestParts,
  headers: { 'content-digest'?: string; 'signature-input'?: string; signature?: string },
  opts: VerifyOptions,
): Promise<VerifiedRequest> {
  const expectedDigest = contentDigest(parts.body);
  if (typeof headers['content-digest'] !== 'string' || !ctEqual(utf8(headers['content-digest'].trim()), utf8(expectedDigest))) {
    throw new ProtocolError('content-digest does not match body');
  }
  const input = parseSignatureInput(headers['signature-input']);
  const sig = parseSignature(headers.signature);
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  if (Math.abs(now - input.created) > opts.maxSkewSeconds) throw new ProtocolError('signature created time outside window');
  const pub = await opts.lookupKey(input.keyid);
  if (!pub) throw new ProtocolError('unknown signer');
  if (addressFromSigningKey(pub) !== input.keyid) throw new ProtocolError('signer key mismatch');
  const base = signatureBase(parts, expectedDigest, input.params);
  if (!ed25519.verify(sig, utf8(base), pub, { zip215: false })) throw new ProtocolError('signature invalid');
  return { address: input.keyid, nonce: input.nonce, created: input.created };
}
