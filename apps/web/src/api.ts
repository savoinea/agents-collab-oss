import { signRequest, verifyIdentityRecord, type IdentityKeys, type VerifiedIdentity } from '@acp/protocol';

export class ApiError extends Error {
  constructor(readonly status: number, message: string, readonly code: string, readonly data: Record<string, unknown>) {
    super(message);
  }
}

async function parse(res: Response): Promise<Record<string, unknown>> {
  let data: Record<string, unknown>;
  try {
    data = (await res.json()) as Record<string, unknown>;
  } catch {
    throw new ApiError(res.status, `The server returned status ${res.status}.`, 'bad_response', {});
  }
  if (!res.ok || data.ok === false) throw new ApiError(res.status, String(data.message ?? `Request failed (${res.status}).`), String(data.error ?? 'error'), data);
  return data;
}

export async function getJson<T = Record<string, unknown>>(path: string): Promise<T> {
  const res = await fetch(path, { credentials: 'same-origin', headers: { accept: 'application/json' } });
  return (await parse(res)) as T;
}

/** Every write is an RFC 9421 signed request over method, authority, path, query and body digest. */
export async function signedPost<T = Record<string, unknown>>(keys: IdentityKeys, path: string, body: unknown): Promise<T> {
  const bytes = new TextEncoder().encode(JSON.stringify(body));
  const url = new URL(path, location.origin);
  const headers = signRequest(keys, { method: 'POST', authority: location.host.toLowerCase(), path: url.pathname, query: url.search || '?', body: bytes });
  const res = await fetch(url.pathname + url.search, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'content-type': 'application/json', accept: 'application/json', ...headers },
    body: bytes,
  });
  return (await parse(res)) as T;
}

const peerCache = new Map<string, { verified: VerifiedIdentity; projectOperated: boolean }>();

/**
 * Peer-identity procedure: fetch the identity record and verify it offline — the address is
 * derived from the signing key, and the signing key signs the encryption key. A relay cannot
 * substitute the encryption key without breaking that signature.
 */
export async function verifiedPeer(address: string): Promise<{ verified: VerifiedIdentity; projectOperated: boolean }> {
  const hit = peerCache.get(address);
  if (hit) return hit;
  const data = await getJson<{ identity: unknown; project_operated: boolean; blocked: boolean }>(`/api/identities/${encodeURIComponent(address)}`);
  const verified = verifyIdentityRecord(data.identity);
  if (verified.address !== address) throw new Error('The identity record does not match the requested address.');
  if (data.blocked) throw new Error('This identity is blocked by the operator.');
  const out = { verified, projectOperated: data.project_operated };
  peerCache.set(address, out);
  return out;
}
