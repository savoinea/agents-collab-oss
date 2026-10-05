/**
 * Identity and history-key export: a versioned, authenticated, passphrase-protected text block.
 *
 * Format:
 *   -----BEGIN ACP IDENTITY EXPORT-----
 *   <base64url(header JSON)>.<base64url(ciphertext)>   (wrapped at 64 columns)
 *   -----END ACP IDENTITY EXPORT-----
 *
 * The header (version, KDF id and parameters, salt, AEAD id, nonce) is bound as associated data,
 * so changing any parameter breaks authentication. KDF: Argon2id (audited @noble/hashes build,
 * pure JS, runs identically in every browser and Node). AEAD: XChaCha20-Poly1305.
 */
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { argon2idAsync } from '@noble/hashes/argon2.js';
import { ProtocolError, decodeB64uExact, fromB64u, fromUtf8, randomBytes, toB64u, utf8 } from './bytes';
import { canonicalBytes, canonicalString } from './canonical';
import { CTX } from './constants';
import { deriveKeys, verifyIdentityRecord, type IdentityKeys, type IdentityRecord } from './identity';

export const EXPORT_VERSION = 1;
export const KDF_PARAMS = { m: 19456, t: 2, p: 1 } as const; // KiB, iterations, lanes (OWASP 2023 minimum for Argon2id)
export const MIN_PASSPHRASE_LENGTH = 16;
const BEGIN = '-----BEGIN ACP IDENTITY EXPORT-----';
const END = '-----END ACP IDENTITY EXPORT-----';
const MAX_EXPORT_CHARS = 4 * 1024 * 1024;

export interface ThreadKeyState {
  epochs: Record<string, string>; // epoch number -> base64url 32-byte epoch secret
  records: Record<string, string>; // record id -> base64url 32-byte content key (selected-record grants)
}

export interface HeldGrant {
  grant_id: string;
  thread: string;
  grantor: string;
  scope: string;
}

export interface ExportPayload {
  seed: Uint8Array;
  identity: IdentityRecord;
  history: Record<string, ThreadKeyState>;
  grants: HeldGrant[];
  exported_at: number;
}

interface Header {
  v: number;
  kdf: 'argon2id';
  m: number;
  t: number;
  p: number;
  salt: string;
  aead: 'xchacha20poly1305';
  nonce: string;
}

function aad(header: Header): Uint8Array {
  return canonicalBytes({ ctx: CTX.exportAad, header });
}

async function deriveKey(passphrase: string, header: Header): Promise<Uint8Array> {
  return argon2idAsync(utf8(passphrase.normalize('NFC')), fromB64u(header.salt), {
    m: header.m,
    t: header.t,
    p: header.p,
    dkLen: 32,
    asyncTick: 25,
  });
}

/** A random passphrase an agent can store verbatim: 24 alphanumeric characters in groups (over 128 bits). */
export function generatePassphrase(): string {
  const raw = toB64u(randomBytes(18)).replace(/[-_]/g, 'x');
  return (raw.match(/.{1,6}/g) ?? []).join('-');
}

export async function createExport(payload: ExportPayload, passphrase: string): Promise<string> {
  if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new ProtocolError(`passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`);
  }
  const header: Header = {
    v: EXPORT_VERSION,
    kdf: 'argon2id',
    ...KDF_PARAMS,
    salt: toB64u(randomBytes(16)),
    aead: 'xchacha20poly1305',
    nonce: toB64u(randomBytes(24)),
  };
  const key = await deriveKey(passphrase, header);
  const plaintext = canonicalBytes({
    seed: toB64u(payload.seed),
    identity: payload.identity,
    history: payload.history,
    grants: payload.grants,
    exported_at: payload.exported_at,
  });
  const ct = xchacha20poly1305(key, fromB64u(header.nonce), aad(header)).encrypt(plaintext);
  key.fill(0);
  const body = `${toB64u(utf8(canonicalString(header)))}.${toB64u(ct)}`;
  const wrapped = body.match(/.{1,64}/g)!.join('\n');
  return `${BEGIN}\n${wrapped}\n${END}\n`;
}

export interface ImportResult {
  keys: IdentityKeys;
  payload: ExportPayload;
}

/**
 * Imports an export. Every failure throws a ProtocolError with a textual message suitable for
 * display: corrupt, truncated, wrong version, wrong passphrase, or inconsistent content.
 */
export async function importExport(text: string, passphrase: string): Promise<ImportResult> {
  if (typeof text !== 'string' || text.length > MAX_EXPORT_CHARS) throw new ProtocolError('Export text is missing or too large.');
  const start = text.indexOf(BEGIN);
  const end = text.indexOf(END);
  if (start < 0 || end < 0 || end < start) {
    throw new ProtocolError('Export text is incomplete: the BEGIN and END lines must both be included.');
  }
  const inner = text.slice(start + BEGIN.length, end).replace(/\s+/g, '');
  const parts = inner.split('.');
  if (parts.length !== 2) throw new ProtocolError('Export text is corrupt: expected a header and a ciphertext.');
  let header: Header;
  try {
    header = JSON.parse(fromUtf8(fromB64u(parts[0]!))) as Header;
  } catch {
    throw new ProtocolError('Export text is corrupt: the header cannot be read.');
  }
  if (!header || typeof header !== 'object' || Array.isArray(header)) throw new ProtocolError('Export text is corrupt: the header cannot be read.');
  const headerFields = new Set(['v', 'kdf', 'm', 't', 'p', 'salt', 'aead', 'nonce']);
  for (const k of Object.keys(header)) if (!headerFields.has(k)) throw new ProtocolError('Export header contains unknown fields.');
  if (header.v !== EXPORT_VERSION) throw new ProtocolError(`Export version ${String(header.v)} is not supported by this client.`);
  if (header.kdf !== 'argon2id' || header.aead !== 'xchacha20poly1305') throw new ProtocolError('Export uses an unsupported algorithm.');
  // Bound KDF parameters so a crafted export cannot exhaust memory or CPU.
  if (
    !Number.isSafeInteger(header.m) || header.m < 8192 || header.m > 262144 ||
    !Number.isSafeInteger(header.t) || header.t < 1 || header.t > 10 ||
    header.p !== 1
  ) {
    throw new ProtocolError('Export KDF parameters are outside the accepted range.');
  }
  decodeB64uExact(header.salt, 16, 'salt');
  decodeB64uExact(header.nonce, 24, 'nonce');
  const canonicalHeader: Header = {
    v: header.v, kdf: header.kdf, m: header.m, t: header.t, p: header.p, salt: header.salt, aead: header.aead, nonce: header.nonce,
  };
  let ct: Uint8Array;
  try {
    ct = fromB64u(parts[1]!);
  } catch {
    throw new ProtocolError('Export text is corrupt: the ciphertext cannot be read.');
  }
  const key = await deriveKey(passphrase, canonicalHeader);
  let plaintext: Uint8Array;
  try {
    plaintext = xchacha20poly1305(key, fromB64u(canonicalHeader.nonce), aad(canonicalHeader)).decrypt(ct);
  } catch {
    throw new ProtocolError('Export could not be opened: wrong passphrase, or the text was altered or truncated.');
  } finally {
    key.fill(0);
  }
  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(fromUtf8(plaintext));
  } catch {
    throw new ProtocolError('Export content is corrupt.');
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new ProtocolError('Export content is corrupt.');
  const seed = decodeB64uExact(raw.seed, 32, 'seed');
  const keys = deriveKeys(seed);
  const verified = verifyIdentityRecord(raw.identity);
  if (verified.address !== keys.address) throw new ProtocolError('Export is inconsistent: the identity record does not match the seed.');
  if (!Number.isSafeInteger(raw.exported_at)) throw new ProtocolError('Export content is corrupt: bad export time.');
  const history = validateHistory(raw.history);
  if (!Array.isArray(raw.grants)) throw new ProtocolError('Export content is corrupt: bad grants list.');
  const grants = raw.grants.map((g) => {
    const o = g as Record<string, unknown>;
    if (!o || typeof o.grant_id !== 'string' || typeof o.thread !== 'string' || typeof o.grantor !== 'string' || typeof o.scope !== 'string') {
      throw new ProtocolError('Export content is corrupt: bad grant entry.');
    }
    return { grant_id: o.grant_id, thread: o.thread, grantor: o.grantor, scope: o.scope };
  });
  return {
    keys,
    payload: { seed, identity: raw.identity as IdentityRecord, history, grants, exported_at: raw.exported_at as number },
  };
}

export function validateHistory(h: unknown): Record<string, ThreadKeyState> {
  if (!h || typeof h !== 'object' || Array.isArray(h)) throw new ProtocolError('Export content is corrupt: bad history.');
  const out: Record<string, ThreadKeyState> = {};
  for (const [thread, state] of Object.entries(h as Record<string, unknown>)) {
    if (!/^[A-Za-z0-9_-]{22}$/.test(thread)) throw new ProtocolError('Export content is corrupt: bad thread id.');
    const st = state as Record<string, unknown>;
    if (!st || typeof st !== 'object' || !st.epochs || typeof st.epochs !== 'object' || !st.records || typeof st.records !== 'object') {
      throw new ProtocolError('Export content is corrupt: bad thread key state.');
    }
    const epochs: Record<string, string> = {};
    for (const [n, v] of Object.entries(st.epochs as Record<string, unknown>)) {
      if (!/^\d{1,9}$/.test(n)) throw new ProtocolError('Export content is corrupt: bad epoch number.');
      decodeB64uExact(v, 32, `history ${thread} epoch`);
      epochs[n] = v as string;
    }
    const records: Record<string, string> = {};
    for (const [id, v] of Object.entries(st.records as Record<string, unknown>)) {
      if (!/^[A-Za-z0-9_-]{43}$/.test(id)) throw new ProtocolError('Export content is corrupt: bad record id.');
      decodeB64uExact(v, 32, `history ${thread} record key`);
      records[id] = v as string;
    }
    out[thread] = { epochs, records };
  }
  return out;
}
