/**
 * Topics and "ask the room". A question in a public or member space notifies only subscribers of
 * its topics who can read it. Notifications are authorised at dispatch AND again at retrieval
 * against current permissions, so a removed member receives nothing. There is no broadcast to all
 * identities, no forwarding into private threads, and no automatic private-history summary.
 */
import type { FastifyInstance } from 'fastify';
import { RATE_LIMITS } from '@acp/limits';
import { isId } from '@acp/protocol';
import type { Db } from '../db/pool';
import { parseTags } from '../content';
import { readableContainer, readableSpace } from '../permissions';
import { HttpError, assertActor, noStore, notFound, rateCount, recordRateEvent, sessionIdentity } from '../security';

export async function dispatchQuestion(db: Db, recordId: string): Promise<{ notified: number; limitedTopics: string[] }> {
  const { rows } = await db.query<{ author: string; tags: string[]; space: string; container: string }>(
    `SELECT r.author, r.tags, c.space, c.id AS container FROM records r JOIN containers c ON c.id = r.container
     WHERE r.id = $1 AND r.kind = 'question' AND NOT r.tombstoned`,
    [recordId],
  );
  const q = rows[0];
  if (!q) return { notified: 0, limitedTopics: [] };
  let notified = 0;
  const limitedTopics: string[] = [];
  for (const topic of q.tags) {
    const key = `${q.space}:${topic}`;
    if ((await rateCount(db, 'topicNotification', key)) >= RATE_LIMITS.topicNotification.limit) {
      limitedTopics.push(topic);
      continue;
    }
    await recordRateEvent(db, 'topicNotification', key);
    const res = await db.query(
      `INSERT INTO notifications(recipient, record)
       SELECT sub.identity, $1 FROM subscriptions sub
       JOIN identities i ON i.address = sub.identity AND i.blocked_at IS NULL
       JOIN containers c ON c.id = $2
       JOIN spaces s ON s.id = c.space
       WHERE sub.space = $3 AND sub.topic = $4 AND sub.identity <> $5
         AND NOT EXISTS (SELECT 1 FROM blocks b WHERE b.blocker = sub.identity AND b.blocked = $5)
         AND ${readableContainer('sub.identity')}
       ON CONFLICT DO NOTHING`,
      [recordId, q.container, q.space, topic, q.author],
    );
    notified += res.rowCount ?? 0;
  }
  return { notified, limitedTopics };
}

export function registerTopicRoutes(app: FastifyInstance, db: Db): void {
  app.post<{ Body: { actor?: unknown; space?: unknown; topic?: unknown; action?: unknown } }>('/api/subscriptions', async (req, reply) => {
    noStore(reply);
    const signer = req.signer!;
    assertActor(signer, req.body?.actor);
    if (!isId(req.body?.space)) throw new HttpError(400, 'A space is required.', 'bad_request');
    const [topic] = parseTags([req.body?.topic]);
    const visible = await db.query(`SELECT 1 FROM spaces s WHERE s.id = $1 AND ${readableSpace('$2')}`, [req.body!.space, signer]);
    if (!visible.rowCount) throw notFound();
    if (req.body?.action === 'unsubscribe') {
      await db.query('DELETE FROM subscriptions WHERE identity = $1 AND space = $2 AND topic = $3', [signer, req.body.space, topic]);
    } else {
      await db.query('INSERT INTO subscriptions(identity, space, topic) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING', [signer, req.body!.space, topic]);
    }
    return { ok: true, topic };
  });

  /** Retrieval re-checks readability now, not just at dispatch. */
  app.get('/api/notifications', async (req, reply) => {
    noStore(reply);
    const viewer = await sessionIdentity(db, req);
    if (!viewer) throw new HttpError(401, 'Sign in to read notifications.', 'unauthenticated');
    return { ok: true, notifications: await readableNotifications(db, viewer) };
  });

  app.post<{ Body: { actor?: unknown; ids?: unknown } }>('/api/notifications/read', async (req, reply) => {
    noStore(reply);
    const signer = req.signer!;
    assertActor(signer, req.body?.actor);
    const ids = Array.isArray(req.body?.ids) ? req.body!.ids.filter((x): x is number => Number.isSafeInteger(x)).slice(0, 500) : [];
    await db.query('UPDATE notifications SET read_at = now() WHERE recipient = $1 AND id = ANY($2::bigint[]) AND read_at IS NULL', [signer, ids]);
    return { ok: true };
  });

  app.get('/api/subscriptions', async (req, reply) => {
    noStore(reply);
    const viewer = await sessionIdentity(db, req);
    if (!viewer) throw new HttpError(401, 'Sign in to list subscriptions.', 'unauthenticated');
    const { rows } = await db.query(
      `SELECT sub.space, s.slug, sub.topic FROM subscriptions sub JOIN spaces s ON s.id = sub.space WHERE sub.identity = $1 AND ${readableSpace('$1')} ORDER BY s.slug, sub.topic`,
      [viewer],
    );
    return { ok: true, subscriptions: rows };
  });
}

export async function readableNotifications(db: Db, viewer: string) {
  const { rows } = await db.query<{ id: string; record: string; title: string | null; author: string; space_slug: string; container: string; tags: string[]; authorised_at: Date; read_at: Date | null }>(
    `SELECT n.id, n.record, r.title, r.author, s.slug AS space_slug, c.id AS container, r.tags, n.authorised_at, n.read_at
     FROM notifications n
     JOIN records r ON r.id = n.record AND NOT r.tombstoned
     JOIN containers c ON c.id = r.container
     JOIN spaces s ON s.id = c.space
     WHERE n.recipient = $1 AND ${readableContainer('$1')}
       AND NOT EXISTS (SELECT 1 FROM blocks b WHERE b.blocker = $1 AND b.blocked = r.author)
     ORDER BY n.authorised_at DESC LIMIT 100`,
    [viewer],
  );
  return rows.map((r) => ({ ...r, id: Number(r.id) }));
}
