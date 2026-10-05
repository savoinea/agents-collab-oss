import type { FastifyInstance } from 'fastify';
import { PERM, PERM_ALL, ProtocolError, isId, recordId, validateBody, verifyRecord, type Body, type SignedRecord } from '@acp/protocol';
import { withTx, type Db } from '../db/pool';
import { parseContent } from '../content';
import { containerPerms, has, readableContainer, spacePerms, type SpaceRow } from '../permissions';
import { HttpError, assertActor, lookupSigningKey, noStore, notFound, rateLimit, sessionIdentity, touchActivity } from '../security';
import { getContainer, getSpace, recordJson, type Queryable, type RecordRow } from '../store';
import { dispatchQuestion } from './topics';

interface RecordSubmission {
  actor?: unknown;
  record?: unknown;
  body?: unknown;
  /** Required when the record opens a new container (base_seq 0). */
  create?: { kind?: unknown; space?: unknown; slug?: unknown };
}

/**
 * Inserts a verified record at the container head. The caller holds the container row lock.
 * Returns a 409 with the current head if the client's base is stale (never silently reorder).
 */
export async function appendRecord(
  tx: Queryable,
  container: { id: string; head_seq: number; head_hash: string | null },
  rec: SignedRecord,
  fields: { title?: string | null; text?: string | null; tags?: string[]; bodyJson?: Record<string, unknown> | null; ciphertext?: Buffer | null },
): Promise<{ id: string; seq: number }> {
  const e = rec.envelope;
  if (e.base_seq !== container.head_seq || e.prev !== container.head_hash) {
    throw new HttpError(409, `Conflict: the container head moved to sequence ${container.head_seq}. Re-sign against the new head.`, 'stale_head', {
      head: { seq: container.head_seq, hash: container.head_hash },
    });
  }
  const id = recordId(rec);
  const seq = container.head_seq + 1;
  await tx.query(
    `INSERT INTO records(id, container, seq, prev_hash, author, kind, audience, epoch, target, title, body_text, body_json, ciphertext, tags, envelope, sig)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
    [
      id, container.id, seq, e.prev, e.author, e.kind, e.audience, e.epoch ?? null, e.target ?? null,
      fields.title ?? null, fields.text ?? null, fields.bodyJson ? JSON.stringify(fields.bodyJson) : null, fields.ciphertext ?? null,
      fields.tags ?? [], JSON.stringify(e), rec.sig,
    ],
  );
  await tx.query('UPDATE containers SET head_seq = $2, head_hash = $3, last_activity = now() WHERE id = $1', [container.id, seq, id]);
  return { id, seq };
}

/** Verifies the record signature against the signer's registered key and checks authorship. */
export async function verifySubmittedRecord(db: Db, signer: string, record: unknown, body: unknown): Promise<{ rec: SignedRecord; body: Body }> {
  const key = await lookupSigningKey(db, signer);
  if (!key) throw new HttpError(403, 'Unknown or blocked identity.', 'unknown_identity');
  try {
    validateBody(body);
    const rec = verifyRecord(record, key, body);
    if (rec.envelope.author !== signer) throw new HttpError(403, 'The record author must be the request signer.', 'actor_mismatch');
    return { rec, body };
  } catch (e) {
    if (e instanceof ProtocolError) throw new HttpError(400, `Record rejected: ${e.message}.`, 'bad_record');
    throw e;
  }
}

/**
 * Writes an item access list. Every listed identity must already be able to read the space
 * (narrowing never widens), and nobody receives bits the writer lacks.
 */
async function writeAcl(
  db: Db, tx: Queryable, space: SpaceRow, container: string, creator: string, writerPerms: number, acl: { address: string; perms: number }[],
): Promise<void> {
  const entries = new Map(acl.map((a) => [a.address, a.perms & writerPerms]));
  entries.set(creator, PERM_ALL);
  for (const [address, p] of entries) {
    const readable = (await spacePerms(db, address, space)) & PERM.read;
    if (!readable) throw new HttpError(400, 'Every address on an access list must already be able to read this space.', 'bad_acl');
    await tx.query('INSERT INTO item_acl(container, identity, perms) VALUES ($1, $2, $3)', [container, address, p]);
  }
}

function audienceForSpace(kind: string): 'public' | 'member' {
  return kind === 'public' ? 'public' : 'member';
}

export function registerRecordRoutes(app: FastifyInstance, db: Db): void {
  app.post<{ Body: RecordSubmission }>('/api/records', async (req, reply) => {
    noStore(reply);
    const signer = req.signer!;
    assertActor(signer, req.body?.actor);
    const { rec, body } = await verifySubmittedRecord(db, signer, req.body?.record, req.body?.body);
    const e = rec.envelope;
    if (e.audience === 'private') throw new HttpError(400, 'Private records are submitted to the private conversation API.', 'wrong_endpoint');
    const content = parseContent(e.kind, body);
    await rateLimit(db, 'post', signer);
    if (e.kind === 'question') await rateLimit(db, 'topicQuestion', signer);

    const result = await withTx(db, async (tx) => {
      if (e.base_seq === 0) {
        // Opening a new container: thread, question thread, or wiki page.
        const create = req.body?.create ?? {};
        const ckind = e.kind === 'wiki_rev' ? 'wiki' : e.kind === 'thread' || e.kind === 'question' ? 'thread' : null;
        if (!ckind || create.kind !== ckind) throw new HttpError(400, 'Only a thread, question, or wiki revision can open a container.', 'bad_kind');
        if (!isId(create.space)) throw new HttpError(400, 'A space is required.', 'bad_request');
        const space = await getSpace(tx, create.space as string);
        if (!space) throw notFound();
        const perms = await spacePerms(db, signer, space);
        if (!has(perms, PERM.read)) throw notFound();
        const needed = ckind === 'wiki' && space.wiki_edit_policy === 'editors' ? PERM.edit : PERM.post;
        if (!has(perms, needed)) throw new HttpError(403, 'You do not have permission to create items in this space.', 'forbidden');
        if (e.audience !== audienceForSpace(space.kind)) {
          throw new HttpError(400, `Items in this space are ${audienceForSpace(space.kind)}; the record names ${e.audience}.`, 'audience_mismatch');
        }
        if (content.acl && space.kind === 'public') throw new HttpError(400, 'Public items cannot be narrowed; use a member space.', 'bad_acl');
        let slug: string | null = null;
        if (ckind === 'wiki') {
          if (typeof create.slug !== 'string' || !/^[a-z0-9][a-z0-9-]{1,62}$/.test(create.slug)) throw new HttpError(400, 'A wiki page needs a slug (lowercase letters, digits, hyphens).', 'bad_slug');
          slug = create.slug;
        }
        const ins = await tx.query(
          `INSERT INTO containers(id, kind, space, audience, title, slug, narrowed, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`,
          [e.container, ckind, space.id, e.audience, content.title, slug, content.acl !== null, signer],
        );
        if (ins.rowCount !== 1) throw new HttpError(409, 'A container with this id or slug already exists.', 'exists');
        if (content.acl) await writeAcl(db, tx, space, e.container, signer, perms, content.acl);
        const container = (await getContainer(tx, e.container, true))!;
        const out = await appendRecord(tx, container, rec, { title: content.title, text: content.text, tags: content.tags, bodyJson: body.type === 'json' ? body.value : null });
        return { ...out, space, container };
      }

      const container = await getContainer(tx, e.container, true);
      if (!container || container.kind === 'private') throw notFound();
      const space = (await getSpace(tx, container.space!))!;
      const perms = await containerPerms(db, signer, space, container);
      if (!has(perms, PERM.read)) throw notFound(); // unreadable is indistinguishable from nonexistent
      if (e.audience !== container.audience) throw new HttpError(400, 'Replies inherit their container\'s audience.', 'audience_mismatch');

      switch (e.kind) {
        case 'post':
          if (container.kind !== 'thread' || !has(perms, PERM.post)) throw new HttpError(403, 'You do not have permission to post here.', 'forbidden');
          break;
        case 'wiki_rev':
          if (container.kind !== 'wiki' || !has(perms, PERM.edit)) throw new HttpError(403, 'You do not have permission to edit this page.', 'forbidden');
          if (e.base_rev !== container.head_hash) throw new HttpError(409, 'Conflict: the page changed since your base revision.', 'stale_head');
          if (content.acl) throw new HttpError(400, 'Change a page\'s audience with an audience change record.', 'bad_acl');
          break;
        case 'tombstone': {
          if (!e.target) throw new HttpError(400, 'A tombstone names its target.', 'bad_request');
          const t = await tx.query<{ author: string; seq: number }>('SELECT author, seq FROM records WHERE id = $1 AND container = $2 AND NOT tombstoned', [e.target, container.id]);
          const targetsContainer = e.target === container.id;
          if (!targetsContainer && !t.rows[0]) throw notFound();
          const isAuthor = t.rows[0]?.author === signer || (targetsContainer && container.created_by === signer);
          if (!isAuthor && !has(perms, PERM.edit)) throw new HttpError(403, 'Only the author or an editor can delete this.', 'forbidden');
          break;
        }
        case 'audience_change':
          if (space.kind === 'public') throw new HttpError(400, 'Public items cannot change audience; they stay public.', 'bad_request');
          if (!has(perms, PERM.invite) && container.created_by !== signer) throw new HttpError(403, 'Changing an audience requires the invite permission.', 'forbidden');
          if (body.type !== 'json' || body.value.from !== (container.narrowed ? 'narrowed' : 'space')) {
            throw new HttpError(409, 'The audience changed since you looked; reload and review the disclosure again.', 'stale_audience');
          }
          break;
        default:
          throw new HttpError(400, `Record kind ${e.kind} cannot be added to an existing container.`, 'bad_kind');
      }

      const out = await appendRecord(tx, container, rec, { title: content.title, text: content.text, tags: content.tags, bodyJson: body.type === 'json' ? body.value : null });

      if (e.kind === 'tombstone') {
        if (e.target === container.id) {
          await tx.query('UPDATE containers SET tombstoned = true WHERE id = $1', [container.id]);
        } else {
          await tx.query('UPDATE records SET tombstoned = true, body_text = NULL, body_json = NULL, title = NULL, tags = \'{}\' WHERE id = $1', [e.target]);
          const first = await tx.query<{ id: string }>('SELECT id FROM records WHERE container = $1 AND seq = 1', [container.id]);
          if (first.rows[0]?.id === e.target && container.kind === 'thread') await tx.query('UPDATE containers SET tombstoned = true WHERE id = $1', [container.id]);
        }
      } else if (e.kind === 'wiki_rev') {
        await tx.query('UPDATE containers SET title = $2 WHERE id = $1', [container.id, content.title]);
      } else if (e.kind === 'audience_change') {
        await tx.query('DELETE FROM item_acl WHERE container = $1', [container.id]);
        if (content.acl) await writeAcl(db, tx, space, container.id, container.created_by, await spacePerms(db, signer, space), content.acl);
        await tx.query('UPDATE containers SET narrowed = $2 WHERE id = $1', [container.id, content.acl !== null]);
      }
      return { ...out, space, container };
    });

    await touchActivity(db, signer);
    if (e.kind === 'question') await dispatchQuestion(db, result.id);
    return { ok: true, id: result.id, seq: result.seq, container: e.container };
  });

  // Container head for re-signing. Same response for unreadable and nonexistent.
  app.get<{ Params: { id: string } }>('/api/containers/:id', async (req, reply) => {
    noStore(reply);
    const viewer = await sessionIdentity(db, req);
    const { rows } = await db.query(
      `SELECT c.id, c.kind, c.space, s.slug AS space_slug, s.kind AS space_kind, c.audience, c.title, c.slug, c.narrowed, c.head_seq, c.head_hash, c.created_by, c.created_at
       FROM containers c JOIN spaces s ON s.id = c.space WHERE c.id = $1 AND ${readableContainer('$2')}`,
      [req.params.id, viewer],
    );
    if (!rows[0]) throw notFound();
    return { ok: true, container: rows[0] };
  });

  app.get<{ Params: { id: string }; Querystring: { after?: string } }>('/api/containers/:id/records', async (req, reply) => {
    noStore(reply);
    const viewer = await sessionIdentity(db, req);
    const after = Math.max(0, Number.parseInt(req.query.after ?? '0', 10) || 0);
    const { rows } = await db.query<RecordRow>(
      `SELECT r.* FROM records r JOIN containers c ON c.id = r.container JOIN spaces s ON s.id = c.space
       WHERE r.container = $1 AND r.seq > $3 AND ${readableContainer('$2')} ORDER BY r.seq LIMIT 500`,
      [req.params.id, viewer, after],
    );
    if (rows.length === 0) {
      const visible = await db.query(`SELECT 1 FROM containers c JOIN spaces s ON s.id = c.space WHERE c.id = $1 AND ${readableContainer('$2')}`, [req.params.id, viewer]);
      if (!visible.rowCount) throw notFound();
    }
    return { ok: true, records: rows.map(recordJson) };
  });

  app.get<{ Params: { id: string } }>('/api/records/:id', async (req, reply) => {
    noStore(reply);
    const viewer = await sessionIdentity(db, req);
    if (!/^[A-Za-z0-9_-]{43}$/.test(req.params.id)) throw notFound();
    const { rows } = await db.query<RecordRow>(
      `SELECT r.* FROM records r JOIN containers c ON c.id = r.container JOIN spaces s ON s.id = c.space
       WHERE r.id = $1 AND ${readableContainer('$2')}`,
      [req.params.id, viewer],
    );
    if (!rows[0]) throw notFound();
    return { ok: true, record: recordJson(rows[0]) };
  });
}
