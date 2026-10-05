import { bodyHash, type Body, type Envelope } from '@acp/protocol';
import type { Db } from './db/pool';
import type { ContainerRow, SpaceRow } from './permissions';

export type Queryable = Pick<Db, 'query'>;

export async function getSpace(db: Queryable, id: string): Promise<SpaceRow | null> {
  const { rows } = await db.query<SpaceRow>('SELECT id, slug, kind, name, description, wiki_edit_policy, created_by FROM spaces WHERE id = $1', [id]);
  return rows[0] ?? null;
}

export async function getSpaceBySlug(db: Queryable, slug: string): Promise<SpaceRow | null> {
  if (!/^[a-z0-9][a-z0-9-]{1,62}$/.test(slug)) return null;
  const { rows } = await db.query<SpaceRow>('SELECT id, slug, kind, name, description, wiki_edit_policy, created_by FROM spaces WHERE slug = $1', [slug]);
  return rows[0] ?? null;
}

export async function getContainer(db: Queryable, id: string, forUpdate = false): Promise<ContainerRow | null> {
  if (!/^[A-Za-z0-9_-]{22}$/.test(id)) return null;
  const { rows } = await db.query<ContainerRow>(`SELECT * FROM containers WHERE id = $1${forUpdate ? ' FOR UPDATE' : ''}`, [id]);
  return rows[0] ?? null;
}

export interface RecordRow {
  id: string;
  container: string;
  seq: number;
  prev_hash: string | null;
  author: string;
  kind: string;
  audience: 'public' | 'member' | 'private';
  epoch: number | null;
  target: string | null;
  title: string | null;
  body_text: string | null;
  body_json: Record<string, unknown> | null;
  ciphertext: Buffer | null;
  tags: string[];
  envelope: Envelope;
  sig: string;
  tombstoned: boolean;
  created_at: Date;
}

/**
 * The searchable text is derived from the stored body, and the stored body is re-hashed
 * against the signed envelope on every read. A mismatch is reported, never silently shown.
 */
export function integrity(r: RecordRow): 'verified' | 'tombstoned' | 'mismatch' {
  if (r.tombstoned) return 'tombstoned';
  let body: Body;
  if (r.ciphertext) body = { type: 'ciphertext', ct: Buffer.from(r.ciphertext).toString('base64url') };
  else if (r.body_json) body = { type: 'json', value: r.body_json };
  else return 'mismatch';
  if (bodyHash(body) !== r.envelope.body_hash) return 'mismatch';
  // The displayed and indexed columns must be exactly what the signed body says.
  if (r.body_json && r.audience !== 'private') {
    const v = r.body_json as { title?: unknown; text?: unknown; reason?: unknown; tags?: unknown };
    const text = typeof v.text === 'string' ? v.text : typeof v.reason === 'string' ? v.reason : null;
    const title = typeof v.title === 'string' ? v.title : null;
    const tags = Array.isArray(v.tags) ? (v.tags as string[]).map((t) => String(t).trim().toLowerCase()) : [];
    if ((r.body_text ?? null) !== text || (r.title ?? null) !== title || JSON.stringify([...new Set(tags)]) !== JSON.stringify(r.tags ?? [])) return 'mismatch';
  }
  return 'verified';
}

export function bodyOf(r: RecordRow): Body | null {
  if (r.tombstoned) return null;
  if (r.ciphertext) return { type: 'ciphertext', ct: Buffer.from(r.ciphertext).toString('base64url') };
  if (r.body_json) return { type: 'json', value: r.body_json };
  return null;
}

/** Public JSON form of a record: the signed envelope, signature, body, and provenance. */
export function recordJson(r: RecordRow) {
  return {
    id: r.id,
    seq: r.seq,
    container: r.container,
    author: r.author,
    kind: r.kind,
    audience: r.audience,
    epoch: r.epoch,
    created_at: r.created_at.toISOString(),
    tombstoned: r.tombstoned,
    integrity: integrity(r),
    record: { envelope: r.envelope, sig: r.sig },
    body: bodyOf(r),
  };
}
