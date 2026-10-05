/** Reporting and blocking. Blocks are enforced on sends, invitations, access requests, grants and notifications. */
import type { FastifyInstance } from 'fastify';
import { CTX, isAddress, verifyDetached } from '@acp/protocol';
import type { Db } from '../db/pool';
import { HttpError, assertActor, lookupSigningKey, noStore, rateLimit, sessionIdentity } from '../security';

export function registerAbuseRoutes(app: FastifyInstance, db: Db): void {
  app.post<{ Body: { actor?: unknown; target_kind?: unknown; target_id?: unknown; reason?: unknown } }>('/api/reports', async (req, reply) => {
    noStore(reply);
    const signer = req.signer!;
    assertActor(signer, req.body?.actor);
    await rateLimit(db, 'report', signer);
    const { target_kind, target_id, reason } = req.body ?? {};
    if (!['record', 'card', 'identity', 'space'].includes(target_kind as string)) throw new HttpError(400, 'target_kind must be record, card, identity or space.', 'bad_request');
    if (typeof target_id !== 'string' || target_id.length < 5 || target_id.length > 80 || !/^[A-Za-z0-9_-]+$/.test(target_id)) throw new HttpError(400, 'target_id is required.', 'bad_request');
    if (typeof reason !== 'string' || reason.trim().length === 0 || reason.length > 2000) throw new HttpError(400, 'A reason is required (max 2000 characters).', 'bad_request');
    const { rows } = await db.query<{ id: string }>('INSERT INTO reports(reporter, target_kind, target_id, reason) VALUES ($1,$2,$3,$4) RETURNING id', [signer, target_kind, target_id, reason]);
    return { ok: true, report: Number(rows[0]!.id), note: 'The operator reviews reports under the takedown policy on /policies.' };
  });

  app.post<{ Body: { actor?: unknown; blocked?: unknown; action?: unknown; ts?: unknown; sig?: unknown } }>('/api/blocks', async (req, reply) => {
    noStore(reply);
    const signer = req.signer!;
    assertActor(signer, req.body?.actor);
    await rateLimit(db, 'report', signer);
    const { blocked, action, ts, sig } = req.body ?? {};
    if (!isAddress(blocked) || blocked === signer) throw new HttpError(400, 'A valid address other than your own is required.', 'bad_request');
    if (action !== 'block' && action !== 'unblock') throw new HttpError(400, 'action must be block or unblock.', 'bad_request');
    if (!Number.isSafeInteger(ts) || Math.abs(Date.now() - (ts as number)) > 10 * 60 * 1000) throw new HttpError(400, 'Timestamp missing or too far from server time.', 'bad_request');
    const key = (await lookupSigningKey(db, signer))!;
    if (!verifyDetached(key, CTX.block, { blocker: signer, blocked, action, ts }, sig)) throw new HttpError(400, 'Block statement signature invalid.', 'bad_signature');
    if (action === 'block') {
      const exists = await db.query('SELECT 1 FROM identities WHERE address = $1', [blocked]);
      if (!exists.rowCount) throw new HttpError(404, 'No such identity.', 'not_found');
      await db.query('INSERT INTO blocks(blocker, blocked) VALUES ($1,$2) ON CONFLICT DO NOTHING', [signer, blocked]);
    } else {
      await db.query('DELETE FROM blocks WHERE blocker = $1 AND blocked = $2', [signer, blocked]);
    }
    return { ok: true, action };
  });

  // Off-box monitor results. Only project-operated identities may report (set by the operator CLI).
  app.post<{ Body: { actor?: unknown; ok?: unknown; latency_ms?: unknown; detail?: unknown } }>('/api/monitor/report', async (req, reply) => {
    noStore(reply);
    const signer = req.signer!;
    assertActor(signer, req.body?.actor);
    const op = await db.query('SELECT 1 FROM identities WHERE address = $1 AND project_operated', [signer]);
    if (!op.rowCount) throw new HttpError(403, 'Only project-operated identities may report monitor results.', 'forbidden');
    const { ok, latency_ms, detail } = req.body ?? {};
    if (typeof ok !== 'boolean' || !Number.isSafeInteger(latency_ms) || typeof detail !== 'string') throw new HttpError(400, 'ok, latency_ms and detail are required.', 'bad_request');
    await db.query('INSERT INTO monitor_runs(ok, latency_ms, detail) VALUES ($1, $2, $3)', [ok, latency_ms, detail.slice(0, 500)]);
    return { ok: true };
  });

  app.get('/api/blocks', async (req, reply) => {
    noStore(reply);
    const viewer = await sessionIdentity(db, req);
    if (!viewer) throw new HttpError(401, 'Sign in to list blocks.', 'unauthenticated');
    const { rows } = await db.query('SELECT blocked, created_at FROM blocks WHERE blocker = $1 ORDER BY created_at DESC', [viewer]);
    return { ok: true, blocks: rows };
  });
}
