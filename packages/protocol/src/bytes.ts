import { base32nopad, base64, base64urlnopad, hex } from '@scure/base';
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes as nobleRandomBytes } from '@noble/hashes/utils.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export const utf8 = (s: string): Uint8Array => encoder.encode(s);
export const fromUtf8 = (b: Uint8Array): string => decoder.decode(b);

export const toHex = (b: Uint8Array): string => hex.encode(b);
export const fromHex = (s: string): Uint8Array => hex.decode(s);

export const toB64 = (b: Uint8Array): string => base64.encode(b);
export const fromB64 = (s: string): Uint8Array => base64.decode(s);

export const toB64u = (b: Uint8Array): string => base64urlnopad.encode(b);
export const fromB64u = (s: string): Uint8Array => base64urlnopad.decode(s);

export const toB32 = (b: Uint8Array): string => base32nopad.encode(b).toLowerCase();
export const fromB32 = (s: string): Uint8Array => base32nopad.decode(s.toUpperCase());

export function concat(...parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Constant-time comparison for equal-length secrets/MACs. Length itself is not secret. */
export function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export const randomBytes = (n: number): Uint8Array => nobleRandomBytes(n);

export const sha256Bytes = (b: Uint8Array): Uint8Array => sha256(b);

/** Domain-separated hash: H(label || 0x00 || data). */
export function taggedHash(label: string, data: Uint8Array): Uint8Array {
  return sha256(concat(utf8(label), new Uint8Array([0]), data));
}

/** Strict base64url decode that also checks the decoded length. Throws ProtocolError on mismatch. */
export function decodeB64uExact(s: unknown, length: number, field: string): Uint8Array {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) throw new ProtocolError(`${field}: not base64url`);
  let out: Uint8Array;
  try {
    out = fromB64u(s);
  } catch {
    throw new ProtocolError(`${field}: not base64url`);
  }
  if (out.length !== length) throw new ProtocolError(`${field}: expected ${length} bytes`);
  return out;
}

export class ProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProtocolError';
  }
}
