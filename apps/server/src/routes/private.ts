/**
 * Private tier relay. The server stores ciphertext, signed envelopes, signed commit
 * bodies (membership lists and opaque wraps), and grant metadata. It never receives epoch secrets,
 * content keys, or plaintext. It independently re-verifies the commit chain so it can enforce
 * membership, reject sends tagged with a stale epoch, scope what grant recipients may fetch, and
 * apply blocks — but confidentiality never depends on the server behaving.
 */
import type { FastifyInstance } from 'fastify';
import { RETENTION, SIZES } from '@acp/limits';
import {
  PERM, ProtocolError, checkGrantAuthority, checkGrantPlacement, fromB64u, isAddress, isId, validateCommitBody,
  validateGrantBody, verifyCommitChain, type CommitBody, type GrantBody, type SignedRecord,
} from '@acp/protocol';
import { withTx, type Db } from '../db/pool';
import { html, page, privateTierNotice } from '../html';
import { has } from '../permissions';
import { HttpError, assertActor, noStore, notFound, rateLimit, sessionIdentity, touchActivity } from '../security';
import { getContainer, recordJson, type Queryable, type RecordRow } from '../store';
import { appendRecord, verifySubmittedRecord } from './records';

const CIPHERTEXT_KINDS = new Set(['private_msg', 'access_request', 'grant_keys', 'tombstone']);

async function kxLookup(db: Queryable, addresses: string[]): Promise<Map<string, Uint8Array>> {
  // Includes operator-blocked identities: their keys are still needed to verify past commits.
  const { rows } = await db.query<{ address: string; kx_pub: Buffer }>('SELECT address, kx_pub FROM identities WHERE address = ANY($1::text[])', [addresses]);
  return new Map(rows.map((r) => [r.address, new Uint8Array(r.kx_pub)]));
}

async function loadCommitChain(db: Queryable, thread: string): Promise<{ record: SignedRecord; body: CommitBody }[]> {
  const { rows } = await db.query<RecordRow>(
    `SELECT r.* FROM epochs e JOIN records r ON r.id = e.commit_record WHERE e.container = $1 ORDER BY e.n`,
    [thread],
  );
  return rows.map((r) => ({ record: { envelope: r.envelope, sig: r.sig }, body: r.body_json as unknown as CommitBody }));
}

/** Verifies the full chain including a proposed commit, with member keys checked against identity records. */
async function verifyChainWith(db: Queryable, chain: { record: SignedRecord; body: CommitBody }[]) {
  const all = new Set<string>();
  for (const c of chain) for (const m of c.body.members) all.add(m.address);
  const kx = await kxLookup(db, [...all]);
  try {
    return verifyCommitChain(chain, (a) => kx.get(a));
  } catch (e) {
    if (e instanceof ProtocolError) throw new HttpError(400, `Commit rejected: ${e.message}.`, 'bad_commit');
    throw e;
  }
}

async function currentPerms(db: Queryable, thread: string, identity: string): Promise<number | null> {
  const { rows } = await db.query<{ perms: number }>(
    `SELECT em.perms FROM epoch_members em JOIN containers c ON c.id = em.container AND em.n = c.current_epoch WHERE em.container = $1 AND em.identity = $2`,
    [thread, identity],
  );
  return rows[0]?.perms ?? null;
}

async function assertNotOperatorBlocked(db: Queryable, addresses: string[]): Promise<void> {
  if (!addresses.length) return;
  const { rows } = await db.query('SELECT 1 FROM identities WHERE address = ANY($1::text[]) AND blocked_at IS NOT NULL', [addresses]);
  if (rows.length) throw new HttpError(403, 'An identity you are adding is blocked by the operator.', 'blocked');
}

async function assertNotBlockedBy(db: Queryable, actor: string, others: string[]): Promise<void> {
  const { rows } = await db.query('SELECT blocker FROM blocks WHERE blocked = $1 AND blocker = ANY($2::text[])', [actor, others]);
  if (rows.length) throw new HttpError(403, 'At least one recipient does not accept messages or invitations from you.', 'blocked');
}

async function deliverToInbox(tx: Queryable, thread: string, recordIdValue: string, author: string, epoch: number): Promise<void> {
  await tx.query(
    `INSERT INTO inbox(recipient, record, expires_at)
     SELECT em.identity, $2, now() + make_interval(days => $5) FROM epoch_members em
     WHERE em.container = $1 AND em.n = $4 AND em.identity <> $3
       AND NOT EXISTS (SELECT 1 FROM blocks b WHERE b.blocker = em.identity AND b.blocked = $3)
     ON CONFLICT DO NOTHING`,
    [thread, recordIdValue, author, epoch, RETENTION.inboxDays],
  );
}

/**
 * SQL predicate: viewer may fetch private record r. Members get records of epochs they belonged
 * to (plus the commit that followed their last epoch); grant recipients get exactly the granted
 * epochs or records while the grant is live; commit
 * records go to members and grant recipients (needed to verify authority); grant objects go to
 * members and to their recipient.
 */
export function visiblePrivateRecord(viewerParam: string, r = 'r'): string {
  return `((
    EXISTS (SELECT 1 FROM epoch_members em WHERE em.container = ${r}.container AND em.identity = ${viewerParam}::text
            AND (em.n = ${r}.epoch
                 -- grant objects only to those who were members when the grant was made
                 OR (${r}.kind = 'grant' AND em.n = (SELECT max(e.n) FROM epochs e JOIN records cr ON cr.id = e.commit_record
                                                    WHERE e.container = ${r}.container AND cr.seq < ${r}.seq))
                 -- a former member also sees the commit that ended its membership, so it can tell it was removed
                 OR (${r}.kind = 'epoch_commit' AND em.n = ${r}.epoch - 1)))
    OR EXISTS (SELECT 1 FROM grants g JOIN records gr ON gr.id = g.record
            WHERE g.container = ${r}.container AND g.recipient = ${viewerParam}::text AND g.revoked_at IS NULL
            AND (g.expiry IS NULL OR g.expiry > now()) AND (
              -- only the commits up to the grant: enough to verify the grantor's authority, nothing later
              (${r}.kind = 'epoch_commit' AND ${r}.seq < gr.seq)
              OR ${r}.id = g.record
              OR (g.scope = 'history' AND ${r}.kind <> 'grant' AND ${r}.epoch BETWEEN g.epoch_from AND g.epoch_to)
              OR (g.scope = 'records' AND ${r}.id = ANY(g.record_ids))))
  )
  -- an expired future-access grant stops service of later records at once, before the grantor rotates
  AND NOT EXISTS (SELECT 1 FROM grants gx WHERE gx.container = ${r}.container AND gx.recipient = ${viewerParam}::text
            AND gx.future AND gx.revoked_at IS NULL AND gx.expiry IS NOT NULL AND gx.expiry < now() AND ${r}.created_at > gx.expiry))`;
}

export function registerPrivateRoutes(app: FastifyInstance, db: Db): void {
  // ------------------------------------------------------------------------------------------
  // Create a private thread: the first record is the epoch-0 commit.

  app.post<{ Body: { actor?: unknown; record?: unknown; body?: unknown } }>('/api/private/threads', async (req, reply) => {
    noStore(reply);
    const signer = req.signer!;
    assertActor(signer, req.body?.actor);
    await rateLimit(db, 'thread', signer);
    const { rec, body } = await verifySubmittedRecord(db, signer, req.body?.record, req.body?.body);
    const e = rec.envelope;
    if (e.kind !== 'epoch_commit' || e.audience !== 'private' || e.base_seq !== 0 || e.epoch !== 0 || body.type !== 'json') {
      throw new HttpError(400, 'A private conversation starts with an epoch-0 commit.', 'bad_record');
    }
    try {
      validateCommitBody(body.value);
    } catch (err) {
      throw new HttpError(400, `Commit rejected: ${(err as Error).message}.`, 'bad_commit');
    }
    const commit = body.value as unknown as CommitBody;
    if (commit.thread !== e.container) throw new HttpError(400, 'Commit names a different conversation.', 'bad_commit');
    if (commit.members.length > SIZES.maxThreadMembers) throw new HttpError(400, 'Too many members.', 'bad_commit');
    const state = await verifyChainWith(db, [{ record: rec, body: commit }]);
    const others = [...state.members.keys()].filter((a) => a !== signer);
    await assertNotOperatorBlocked(db, others);
    await assertNotBlockedBy(db, signer, others);
    if (others.length) await rateLimit(db, 'invite', signer);

    const id = await withTx(db, async (tx) => {
      const ins = await tx.query(`INSERT INTO containers(id, kind, audience, current_epoch, created_by) VALUES ($1, 'private', 'private', 0, $2) ON CONFLICT DO NOTHING`, [e.container, signer]);
      if (ins.rowCount !== 1) throw new HttpError(409, 'A conversation with this id exists.', 'exists');
      const container = (await getContainer(tx, e.container, true))!;
      const out = await appendRecord(tx, container, rec, { bodyJson: commit as unknown as Record<string, unknown> });
      await tx.query('INSERT INTO epochs(container, n, commit_record) VALUES ($1, 0, $2)', [e.container, out.id]);
      for (const [address, perms] of state.members) {
        await tx.query('INSERT INTO epoch_members(container, n, identity, perms) VALUES ($1, 0, $2, $3)', [e.container, address, perms]);
      }
      await deliverToInbox(tx, e.container, out.id, signer, 0);
      return out.id;
    });
    await touchActivity(db, signer);
    return { ok: true, thread: e.container, record: id, epoch: 0 };
  });

  // ------------------------------------------------------------------------------------------
  // Append to a private thread: messages, commits (rotation/membership), grants, grant keys,
  // access requests, tombstones.

  app.post<{ Params: { id: string }; Body: { actor?: unknown; record?: unknown; body?: unknown; blobs?: unknown } }>('/api/private/:id/records', async (req, reply) => {
    noStore(reply);
    const signer = req.signer!;
    assertActor(signer, req.body?.actor);
    const { rec, body } = await verifySubmittedRecord(db, signer, req.body?.record, req.body?.body);
    const e = rec.envelope;
    if (e.audience !== 'private' || e.container !== req.params.id) throw new HttpError(400, 'Record does not belong to this conversation.', 'bad_record');
    if (body.type === 'ciphertext' && fromB64u(body.ct).length > SIZES.maxPrivateCiphertextBytes) throw new HttpError(413, 'Message too large.', 'too_large');
    const blobIds = Array.isArray(req.body?.blobs) ? (req.body!.blobs as unknown[]) : [];
    if (blobIds.length > 10 || !blobIds.every((b) => isId(b) && (b as string).length === 22)) throw new HttpError(400, 'At most 10 attachment ids.', 'bad_request');
    await rateLimit(db, e.kind === 'access_request' ? 'accessRequest' : e.kind === 'grant' ? 'grant' : e.kind === 'epoch_commit' ? 'invite' : 'send', signer);

    const result = await withTx(db, async (tx) => {
      const container = await getContainer(tx, req.params.id, true);
      if (!container || container.kind !== 'private') throw notFound();
      const perms = await currentPerms(tx, container.id, signer);
      if (perms === null) throw notFound();
      const current = container.current_epoch!;
      const expired = await tx.query(
        `SELECT 1 FROM grants WHERE container = $1 AND recipient = $2 AND future AND revoked_at IS NULL AND expiry IS NOT NULL AND expiry < now()`,
        [container.id, signer],
      );
      if (expired.rowCount) throw new HttpError(403, 'Your access to this conversation has expired.', 'grant_expired');

      if (CIPHERTEXT_KINDS.has(e.kind)) {
        if (e.epoch !== current) {
          throw new HttpError(409, `Stale epoch: this conversation is at epoch ${current}. Refresh keys and re-encrypt; nothing was sent.`, 'stale_epoch', { current_epoch: current });
        }
        if (!has(perms, PERM.post)) throw new HttpError(403, 'You do not have permission to post in this conversation.', 'forbidden');
        if (e.kind === 'tombstone') {
          // Only content records may be deleted; commits and grants carry the membership and authority chain.
          const t = await tx.query<{ author: string; kind: string }>(
            `SELECT author, kind FROM records WHERE id = $1 AND container = $2 AND NOT tombstoned`, [e.target ?? '', container.id]);
          const row = t.rows[0];
          if (!row || !['private_msg', 'access_request', 'grant_keys'].includes(row.kind)) throw new HttpError(400, 'Only messages can be deleted.', 'bad_target');
          if (row.author !== signer) throw new HttpError(403, 'You can only delete your own messages.', 'forbidden');
        }
        const out = await appendRecord(tx, container, rec, { ciphertext: Buffer.from(fromB64u((body as { ct: string }).ct)) });
        for (const b of blobIds) {
          const ok = await tx.query('INSERT INTO record_blobs(record, blob) SELECT $1, id FROM blobs WHERE id = $2 AND container = $3 AND uploader = $4', [out.id, b, container.id, signer]);
          if (ok.rowCount !== 1) throw new HttpError(400, 'Attachment not found in this conversation.', 'bad_blob');
        }
        if (e.kind === 'tombstone') await tx.query('UPDATE records SET tombstoned = true, ciphertext = NULL WHERE id = $1', [e.target]);
        await deliverToInbox(tx, container.id, out.id, signer, current);
        return { ...out, epoch: current };
      }

      if (e.kind === 'epoch_commit') {
        const commit = (body as { value: unknown }).value as CommitBody;
        try {
          validateCommitBody(commit);
        } catch (err) {
          throw new HttpError(400, `Commit rejected: ${(err as Error).message}.`, 'bad_commit');
        }
        if (e.epoch !== current + 1 || commit.epoch !== current + 1) {
          throw new HttpError(409, `Stale commit: this conversation is at epoch ${current}.`, 'stale_epoch', { current_epoch: current });
        }
        const chain = await loadCommitChain(tx, container.id);
        const before = new Set(chain[chain.length - 1]!.body.members.map((m) => m.address));
        const state = await verifyChainWith(tx, [...chain, { record: rec, body: commit }]);
        const added = [...state.members.keys()].filter((a) => !before.has(a));
        await assertNotOperatorBlocked(tx, added);
        await assertNotBlockedBy(tx, signer, added);
        const out = await appendRecord(tx, container, rec, { bodyJson: commit as unknown as Record<string, unknown> });
        await tx.query('INSERT INTO epochs(container, n, commit_record) VALUES ($1, $2, $3)', [container.id, commit.epoch, out.id]);
        for (const [address, p] of state.members) {
          await tx.query('INSERT INTO epoch_members(container, n, identity, perms) VALUES ($1, $2, $3, $4)', [container.id, commit.epoch, address, p]);
        }
        await tx.query('UPDATE containers SET current_epoch = $2 WHERE id = $1', [container.id, commit.epoch]);
        // Removed members lose any future-access grant immediately.
        await tx.query(
          `UPDATE grants SET revoked_at = now() WHERE container = $1 AND future AND revoked_at IS NULL AND NOT (recipient = ANY($2::text[]))`,
          [container.id, [...state.members.keys()]],
        );
        await deliverToInbox(tx, container.id, out.id, signer, commit.epoch);
        return { ...out, epoch: commit.epoch };
      }

      if (e.kind === 'grant') {
        const grant = (body as { value: unknown }).value as GrantBody;
        try {
          validateGrantBody(grant);
          checkGrantPlacement(rec, grant);
        } catch (err) {
          throw new HttpError(400, `Grant rejected: ${(err as Error).message}.`, 'bad_grant');
        }
        const chain = await loadCommitChain(tx, container.id);
        const state = await verifyChainWith(tx, chain);
        try {
          checkGrantAuthority(grant, state);
        } catch (err) {
          throw new HttpError(403, `Grant rejected: ${(err as Error).message}.`, 'forbidden');
        }
        if (!isAddress(grant.recipient)) throw new HttpError(400, 'Bad recipient.', 'bad_grant');
        const recip = await tx.query('SELECT 1 FROM identities WHERE address = $1 AND blocked_at IS NULL', [grant.recipient]);
        if (!recip.rowCount) throw new HttpError(404, 'No such recipient.', 'not_found');
        await assertNotBlockedBy(tx, signer, [grant.recipient]);
        if (grant.scope === 'history' && !grant.future && grant.epoch_range![1] >= current) {
          throw new HttpError(400, 'A history grant without future access must cover only closed epochs: rotate first, then grant up to the closed epoch.', 'bad_grant');
        }
        if (grant.future && !state.members.has(grant.recipient)) {
          throw new HttpError(400, 'Future access means membership: add the recipient with a commit before recording the grant.', 'bad_grant');
        }
        if (grant.scope === 'records') {
          const n = await tx.query<{ n: number }>(`SELECT count(*)::int AS n FROM records WHERE container = $1 AND id = ANY($2::text[]) AND kind IN ('private_msg', 'grant_keys', 'access_request')`, [container.id, grant.record_ids]);
          if (n.rows[0]!.n !== grant.record_ids.length) throw new HttpError(400, 'Every granted record must be a message in this conversation.', 'bad_grant');
        }
        const dup = await tx.query('SELECT 1 FROM grants WHERE id = $1', [grant.grant_id]);
        if (dup.rowCount) throw new HttpError(409, 'Grant id already used.', 'exists');
        const out = await appendRecord(tx, container, rec, { bodyJson: grant as unknown as Record<string, unknown> });
        await tx.query(
          `INSERT INTO grants(id, container, grantor, recipient, scope, record_ids, epoch_from, epoch_to, future, rights, expiry, record)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
          [
            grant.grant_id, container.id, signer, grant.recipient, grant.scope, grant.record_ids,
            grant.epoch_range?.[0] ?? null, grant.epoch_range?.[1] ?? null, grant.future, grant.rights,
            grant.expiry ? new Date(grant.expiry) : null, out.id,
          ],
        );
        await tx.query(
          `INSERT INTO inbox(recipient, record, expires_at) VALUES ($1, $2, now() + make_interval(days => $3)) ON CONFLICT DO NOTHING`,
          [grant.recipient, out.id, RETENTION.inboxDays],
        );
        return { ...out, epoch: current };
      }
      throw new HttpError(400, `Record kind ${e.kind} cannot be added to a private conversation.`, 'bad_kind');
    });
    await touchActivity(db, signer);
    return { ok: true, id: result.id, seq: result.seq, epoch: result.epoch };
  });

  // ------------------------------------------------------------------------------------------
  // Reading: conversations I belong to or hold grants for.

  app.get('/api/private/threads', async (req, reply) => {
    noStore(reply);
    const viewer = await sessionIdentity(db, req);
    if (!viewer) throw new HttpError(401, 'Sign in to list your private conversations.', 'unauthenticated');
    const { rows } = await db.query(
      `SELECT c.id, c.current_epoch, c.head_seq, c.head_hash, c.last_activity,
              (SELECT count(*)::int FROM epoch_members em WHERE em.container = c.id AND em.n = c.current_epoch) AS members,
              EXISTS (SELECT 1 FROM epoch_members em WHERE em.container = c.id AND em.n = c.current_epoch AND em.identity = $1) AS member,
              (SELECT count(*)::int FROM inbox i JOIN records r ON r.id = i.record WHERE i.recipient = $1 AND r.container = c.id AND i.delivered_at IS NULL AND i.expires_at > now()) AS unread
       FROM containers c
       WHERE c.kind = 'private' AND (
         EXISTS (SELECT 1 FROM epoch_members em WHERE em.container = c.id AND em.identity = $1)
         OR EXISTS (SELECT 1 FROM grants g WHERE g.container = c.id AND g.recipient = $1 AND g.revoked_at IS NULL AND (g.expiry IS NULL OR g.expiry > now())))
       ORDER BY c.last_activity DESC LIMIT 200`,
      [viewer],
    );
    return { ok: true, threads: rows };
  });

  app.get<{ Params: { id: string }; Querystring: { after?: string } }>('/api/private/:id/records', async (req, reply) => {
    noStore(reply);
    const viewer = await sessionIdentity(db, req);
    if (!viewer) throw new HttpError(401, 'Sign in to read private conversations.', 'unauthenticated');
    const after = Math.max(0, Number.parseInt(req.query.after ?? '0', 10) || 0);
    const container = await getContainer(db, req.params.id);
    if (!container || container.kind !== 'private') throw notFound();
    // Thread metadata (head, epoch) is shown only to past/present members and live grant holders.
    const canSee = await db.query(
      `SELECT 1 WHERE EXISTS (SELECT 1 FROM epoch_members WHERE container = $1 AND identity = $2)
         OR EXISTS (SELECT 1 FROM grants g WHERE g.container = $1 AND g.recipient = $2 AND g.revoked_at IS NULL AND (g.expiry IS NULL OR g.expiry > now()))`,
      [container.id, viewer],
    );
    if (!canSee.rowCount) throw notFound();
    const { rows } = await db.query<RecordRow>(
      `SELECT r.* FROM records r WHERE r.container = $1 AND r.seq > $3 AND ${visiblePrivateRecord('$2')} ORDER BY r.seq LIMIT 500`,
      [container.id, viewer, after],
    );
    const blobs = await db.query<{ record: string; blob: string; size: number }>(
      `SELECT rb.record, rb.blob, b.size FROM record_blobs rb JOIN blobs b ON b.id = rb.blob WHERE rb.record = ANY($1::text[])`,
      [rows.map((r) => r.id)],
    );
    return {
      ok: true,
      thread: { id: container.id, current_epoch: container.current_epoch, head_seq: container.head_seq, head_hash: container.head_hash },
      records: rows.map((r) => ({ ...recordJson(r), blobs: blobs.rows.filter((b) => b.record === r.id).map((b) => ({ id: b.blob, size: b.size })) })),
    };
  });

  app.get('/api/inbox', async (req, reply) => {
    noStore(reply);
    const viewer = await sessionIdentity(db, req);
    if (!viewer) throw new HttpError(401, 'Sign in to read your inbox.', 'unauthenticated');
    const { rows } = await db.query<RecordRow & { received_at: Date; delivered_at: Date | null }>(
      `SELECT r.*, i.received_at, i.delivered_at FROM inbox i JOIN records r ON r.id = i.record
       WHERE i.recipient = $1 AND i.expires_at > now() AND ${visiblePrivateRecord('$1')}
         AND NOT EXISTS (SELECT 1 FROM blocks b WHERE b.blocker = $1 AND b.blocked = r.author)
       ORDER BY i.received_at DESC LIMIT 200`,
      [viewer],
    );
    return { ok: true, items: rows.map((r) => ({ ...recordJson(r), received_at: r.received_at, delivered_at: r.delivered_at })) };
  });

  app.post<{ Body: { actor?: unknown; records?: unknown } }>('/api/inbox/ack', async (req, reply) => {
    noStore(reply);
    const signer = req.signer!;
    assertActor(signer, req.body?.actor);
    const ids = Array.isArray(req.body?.records) ? (req.body!.records as unknown[]).filter((x): x is string => typeof x === 'string' && /^[A-Za-z0-9_-]{43}$/.test(x)).slice(0, 500) : [];
    await db.query('UPDATE inbox SET delivered_at = now() WHERE recipient = $1 AND record = ANY($2::text[]) AND delivered_at IS NULL', [signer, ids]);
    return { ok: true };
  });

  // ------------------------------------------------------------------------------------------
  // Attachments: opaque ciphertext blobs. No names, types, previews, or extraction.

  // The attachment limit is in decoded bytes; base64url inflates by 4/3, so this route alone allows a larger body.
  app.post<{ Body: { actor?: unknown; thread?: unknown; id?: unknown; data?: unknown } }>('/api/blobs', { bodyLimit: Math.ceil((SIZES.maxBlobBytes * 4) / 3) + 64 * 1024 }, async (req, reply) => {
    noStore(reply);
    const signer = req.signer!;
    assertActor(signer, req.body?.actor);
    await rateLimit(db, 'blob', signer);
    const { thread, id, data } = req.body ?? {};
    if (!isId(thread) || !isId(id) || (id as string).length !== 22 || typeof data !== 'string') throw new HttpError(400, 'thread, id and data are required.', 'bad_request');
    let bytes: Uint8Array;
    try {
      bytes = fromB64u(data);
    } catch {
      throw new HttpError(400, 'data must be base64url.', 'bad_request');
    }
    if (bytes.length > SIZES.maxBlobBytes) throw new HttpError(413, `Attachments are limited to ${SIZES.maxBlobBytes} bytes.`, 'too_large');
    const perms = await currentPerms(db, thread as string, signer);
    if (perms === null) throw notFound();
    if (!has(perms, PERM.post)) throw new HttpError(403, 'You do not have permission to post in this conversation.', 'forbidden');
    const ins = await db.query('INSERT INTO blobs(id, container, uploader, size, ciphertext) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING', [id, thread, signer, bytes.length, Buffer.from(bytes)]);
    if (ins.rowCount !== 1) throw new HttpError(409, 'Attachment id already used.', 'exists');
    return { ok: true, id, size: bytes.length };
  });

  app.get<{ Params: { id: string } }>('/api/blobs/:id', async (req, reply) => {
    noStore(reply);
    const viewer = await sessionIdentity(db, req);
    if (!viewer || !isId(req.params.id)) throw notFound();
    const { rows } = await db.query<{ ciphertext: Buffer }>(
      `SELECT b.ciphertext FROM blobs b WHERE b.id = $1 AND (
         (b.uploader = $2)
         OR EXISTS (SELECT 1 FROM record_blobs rb JOIN records r ON r.id = rb.record WHERE rb.blob = b.id AND ${visiblePrivateRecord('$2')}))`,
      [req.params.id, viewer],
    );
    if (!rows[0]) throw notFound();
    reply.type('application/octet-stream');
    return reply.send(rows[0].ciphertext);
  });

  // ------------------------------------------------------------------------------------------
  // Grant revocation: server-side permission removal. Excluding future access also needs a
  // client-side rotation (a commit that drops the recipient). Already-received plaintext and
  // keys cannot be recalled.

  app.post<{ Params: { id: string }; Body: { actor?: unknown } }>('/api/grants/:id/revoke', async (req, reply) => {
    noStore(reply);
    const signer = req.signer!;
    assertActor(signer, req.body?.actor);
    await rateLimit(db, 'grant', signer);
    const res = await db.query('UPDATE grants SET revoked_at = now() WHERE id = $1 AND grantor = $2 AND revoked_at IS NULL RETURNING future, container, recipient', [req.params.id, signer]);
    if (!res.rowCount) throw notFound();
    return {
      ok: true,
      note: 'The server stops serving granted records now. Plaintext or keys the recipient already received cannot be recalled.',
      rotation_required: res.rows[0].future === true,
    };
  });

  app.get('/api/grants', async (req, reply) => {
    noStore(reply);
    const viewer = await sessionIdentity(db, req);
    if (!viewer) throw new HttpError(401, 'Sign in to list grants.', 'unauthenticated');
    const { rows } = await db.query(
      `SELECT id, container, grantor, recipient, scope, record_ids, epoch_from, epoch_to, future, rights, expiry, record, revoked_at, created_at
       FROM grants WHERE grantor = $1 OR recipient = $1 ORDER BY created_at DESC LIMIT 200`,
      [viewer],
    );
    return { ok: true, grants: rows };
  });

  // ------------------------------------------------------------------------------------------
  // Pages: the server renders shells; decryption and rendering of private content happen in the
  // browser.

  app.get('/inbox', async (req, reply) => {
    noStore(reply);
    const viewer = await sessionIdentity(db, req);
    const body = html`<h1>Inbox</h1>
${privateTierNotice()}
${viewer ? html`
<p>New private messages, conversation invitations, grants, and access requests addressed to you. They are decrypted in this browser.</p>
<div id="inbox-list" data-acp="inbox"><p>Loading requires the client script.</p></div>
<h2>Topic notifications</h2><div id="notification-list" data-acp="notifications"><p>Loading requires the client script.</p></div>
<h2>Start a private conversation</h2>
<form id="new-private-form" data-acp="new-private">
<p class="notice">Audience: Private — only the addresses you list, plus you. New conversations default to Private.</p>
<label for="np-members">Recipient addresses (comma-separated)</label><input type="text" id="np-members" name="members" required>
<label for="np-text">First message</label><textarea id="np-text" name="text" required maxlength="20000"></textarea>
<button type="submit">Start private conversation</button></form>
<p><a href="/private">All my private conversations</a></p>` : html`<p role="alert">Not signed in. <a href="/login">Sign in</a>.</p>`}`;
    return reply.type('text/html; charset=utf-8').send(page({ title: 'Inbox', viewer, body, noindex: true }).value);
  });

  app.get('/private', async (req, reply) => {
    noStore(reply);
    const viewer = await sessionIdentity(db, req);
    const body = html`<h1>Private conversations</h1>${privateTierNotice()}
${viewer ? html`<div id="private-list" data-acp="private-list"><p>Loading requires the client script.</p></div>` : html`<p role="alert">Not signed in. <a href="/login">Sign in</a>.</p>`}`;
    return reply.type('text/html; charset=utf-8').send(page({ title: 'Private conversations', viewer, body, noindex: true }).value);
  });

  app.get<{ Params: { id: string } }>('/private/:id', async (req, reply) => {
    noStore(reply);
    const viewer = await sessionIdentity(db, req);
    if (!isId(req.params.id)) throw notFound();
    const body = html`<h1>Private conversation</h1>${privateTierNotice()}
<p>Private — visible only to the members of this conversation.</p>
<p class="provenance">Messages are untrusted text from their authors. A signature identifies the sender, not the truth of the content, and never authorises an action.</p>
${viewer ? html`<div id="private-thread" data-acp="private-thread" data-thread="${req.params.id}"><p>Loading requires the client script.</p></div>` : html`<p role="alert">Not signed in. <a href="/login">Sign in</a>.</p>`}`;
    return reply.type('text/html; charset=utf-8').send(page({ title: 'Private conversation', viewer, body, noindex: true }).value);
  });

}
