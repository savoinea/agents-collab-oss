import { createHash, createHmac, randomBytes } from 'node:crypto';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { RATE_LIMITS, AUTH, type RateAction } from '@acp/limits';
import { ProtocolError, verifyRequest, isAddress } from '@acp/protocol';
import { authority, config } from './config';
import type { Db } from './db/pool';

// ---------------------------------------------------------------------------------------------
// Errors. Messages are textual and safe to show; internals never leak to clients.

export class HttpError extends Error {
  constructor(readonly status: number, message: string, readonly code = 'error', readonly extra?: Record<string, unknown>) {
    super(message);
  }
}
export const notFound = () => new HttpError(404, 'Not found.', 'not_found');

// ---------------------------------------------------------------------------------------------
// Security headers. Strict CSP: scripts only from our origin with SRI; no inline script or style.

export function securityHeaders(reply: FastifyReply): void {
  reply.header(
    'content-security-policy',
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
      "form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
  );
  reply.header('x-content-type-options', 'nosniff');
  reply.header('referrer-policy', 'no-referrer');
  reply.header('cross-origin-opener-policy', 'same-origin');
  reply.header('cross-origin-resource-policy', 'same-origin');
  reply.header('x-frame-options', 'DENY');
  reply.header('permissions-policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()');
  if (config.production) reply.header('strict-transport-security', 'max-age=63072000; includeSubDomains');
}

/** Member and private responses must never be cached by shared caches. */
export function noStore(reply: FastifyReply): void {
  reply.header('cache-control', 'private, no-store');
  reply.header('vary', 'cookie');
}

// ---------------------------------------------------------------------------------------------
// Network-address keying: raw addresses are never stored, only an HMAC under an operator key.

export function ipKey(req: FastifyRequest): string {
  return createHmac('sha256', config.ipHmacKey).update(req.ip).digest('base64url').slice(0, 22);
}

// ---------------------------------------------------------------------------------------------
// Rate limiting. Every limit comes from packages/limits.

export async function rateLimit(db: Db, action: RateAction, key: string): Promise<void> {
  const rule = RATE_LIMITS[action];
  const { rows } = await db.query<{ n: string }>(
    `WITH ins AS (INSERT INTO rate_events(action, key) VALUES ($1, $2) RETURNING 1)
     SELECT count(*)::text AS n FROM rate_events WHERE action = $1 AND key = $2 AND at > now() - make_interval(secs => $3)`,
    [action, key, rule.windowSeconds],
  );
  // The count excludes the row inserted in this statement (same snapshot), so compare with >=.
  if (Number(rows[0]!.n) >= rule.limit) {
    throw new HttpError(429, `Rate limit reached: ${rule.description} are limited to ${rule.limit} per ${rule.windowSeconds} seconds. Try again later.`, 'rate_limited');
  }
}

/** Counts without recording, for limits that apply only to failures. */
export async function rateCount(db: Db, action: RateAction, key: string): Promise<number> {
  const rule = RATE_LIMITS[action];
  const { rows } = await db.query<{ n: string }>(
    `SELECT count(*)::text AS n FROM rate_events WHERE action = $1 AND key = $2 AND at > now() - make_interval(secs => $3)`,
    [action, key, rule.windowSeconds],
  );
  return Number(rows[0]!.n);
}

export async function recordRateEvent(db: Db, action: RateAction, key: string): Promise<void> {
  await db.query('INSERT INTO rate_events(action, key) VALUES ($1, $2)', [action, key]);
}

// ---------------------------------------------------------------------------------------------
// Sessions (reads only). Cookie holds a random token; the database holds its SHA-256.

export const SESSION_COOKIE = 'acp_session';

export function sha256(b: Buffer | string): Buffer {
  return createHash('sha256').update(b).digest();
}

export function newToken(): string {
  return randomBytes(32).toString('base64url');
}

export async function createSession(db: Db, reply: FastifyReply, address: string): Promise<void> {
  const token = newToken();
  await db.query(`INSERT INTO sessions(token_hash, address, expires_at) VALUES ($1, $2, now() + make_interval(secs => $3))`, [
    sha256(token),
    address,
    AUTH.sessionSeconds,
  ]);
  reply.setCookie(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: config.production,
    sameSite: 'strict',
    path: '/',
    maxAge: AUTH.sessionSeconds,
  });
}

/** Returns the signed-in, non-blocked identity for this request, or null. */
export async function sessionIdentity(db: Db, req: FastifyRequest): Promise<string | null> {
  const token = req.cookies?.[SESSION_COOKIE];
  if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
  const { rows } = await db.query<{ address: string }>(
    `SELECT s.address FROM sessions s JOIN identities i ON i.address = s.address
     WHERE s.token_hash = $1 AND s.expires_at > now() AND i.blocked_at IS NULL`,
    [sha256(token)],
  );
  return rows[0]?.address ?? null;
}

export async function destroySession(db: Db, req: FastifyRequest, reply: FastifyReply): Promise<void> {
  const token = req.cookies?.[SESSION_COOKIE];
  if (token) await db.query('DELETE FROM sessions WHERE token_hash = $1', [sha256(token)]);
  reply.clearCookie(SESSION_COOKIE, { path: '/' });
}

// ---------------------------------------------------------------------------------------------
// Signed writes. Three separate checks: the RFC 9421 signature, the nonce replay window,
// and that the signer is the acting identity named by the request.

declare module 'fastify' {
  interface FastifyRequest {
    rawBody?: Buffer;
    signer?: string;
  }
}

export async function lookupSigningKey(db: Db, address: string): Promise<Uint8Array | null> {
  const { rows } = await db.query<{ sign_pub: Buffer; blocked_at: Date | null }>(
    'SELECT sign_pub, blocked_at FROM identities WHERE address = $1',
    [address],
  );
  const r = rows[0];
  if (!r || r.blocked_at) return null;
  return new Uint8Array(r.sign_pub);
}

export async function verifySignedWrite(
  db: Db,
  req: FastifyRequest,
  lookup: (address: string) => Promise<Uint8Array | null> = (a) => lookupSigningKey(db, a),
): Promise<string> {
  const rawBody = req.rawBody ?? Buffer.alloc(0);
  const url = new URL(req.url, 'http://placeholder');
  const header = (n: string) => {
    const v = req.headers[n];
    return Array.isArray(v) ? undefined : v; // duplicated headers are rejected
  };
  let verified;
  try {
    verified = await verifyRequest(
      {
        method: req.method,
        authority, // the configured origin, never the client-supplied Host header
        path: url.pathname,
        query: url.search || '?',
        body: new Uint8Array(rawBody),
      },
      { 'content-digest': header('content-digest'), 'signature-input': header('signature-input'), signature: header('signature') },
      { maxSkewSeconds: AUTH.signatureSkewSeconds, lookupKey: lookup },
    );
  } catch (e) {
    if (e instanceof ProtocolError) throw new HttpError(401, `Request signature rejected: ${e.message}.`, 'bad_signature');
    throw e;
  }
  // Nonce replay window: a primary-key conflict means this exact nonce was already used.
  const ins = await db.query(
    `INSERT INTO nonces(address, nonce, expires_at) VALUES ($1, $2, now() + make_interval(secs => $3)) ON CONFLICT DO NOTHING`,
    [verified.address, verified.nonce, AUTH.nonceWindowSeconds],
  );
  if (ins.rowCount !== 1) throw new HttpError(401, 'Request signature rejected: nonce already used (replay).', 'replay');
  req.signer = verified.address;
  return verified.address;
}

/** The acting identity named in the body must be the signer. */
export function assertActor(signer: string, actor: unknown): void {
  if (!isAddress(actor) || actor !== signer) {
    throw new HttpError(403, 'The acting identity in the request does not match the request signer.', 'actor_mismatch');
  }
}

export async function touchActivity(db: Db, address: string): Promise<void> {
  await db.query('UPDATE identities SET last_active_at = now() WHERE address = $1 AND last_active_at < now() - interval \'1 minute\'', [address]);
}
