/**
 * Retention and cleanup (lifecycles from packages/limits). Rule: a blob or wrapper referenced
 * by retained history is never removed by inbox cleanup — inbox expiry deletes inbox rows only.
 */
import { RETENTION } from '@acp/limits';
import type { Db } from './db/pool';

export async function runCleanup(db: Db): Promise<Record<string, number>> {
  const out: Record<string, number> = {};
  const run = async (name: string, sql: string, params: unknown[] = []) => {
    const r = await db.query(sql, params);
    out[name] = r.rowCount ?? 0;
  };
  await run('nonces', 'DELETE FROM nonces WHERE expires_at < now()');
  await run('sessions', 'DELETE FROM sessions WHERE expires_at < now()');
  await run('login_challenges', 'DELETE FROM login_challenges WHERE expires_at < now() - interval \'1 hour\'');
  await run('admission_tokens', 'DELETE FROM admission_tokens WHERE expires_at < now() - interval \'1 day\'');
  await run('admission_challenges', `DELETE FROM admission_challenges c WHERE issued_at < now() - interval '2 days' AND NOT EXISTS (SELECT 1 FROM admission_tokens t WHERE t.challenge_id = c.id)`);
  await run('rate_events', 'DELETE FROM rate_events WHERE at < now() - make_interval(secs => $1)', [RETENTION.rateEventSeconds]);
  // Inbox expiry removes the inbox entry only, never the message, blob, or wrapper.
  await run('inbox', 'DELETE FROM inbox WHERE expires_at < now()');
  // Unreferenced uploads (never attached to a record) are removed after a day.
  await run('orphan_blobs', `DELETE FROM blobs b WHERE b.created_at < now() - interval '1 day' AND NOT EXISTS (SELECT 1 FROM record_blobs rb WHERE rb.blob = b.id)`);
  // Retained private history: ciphertext, blobs and wrappers expire together with the conversation.
  const expired = await db.query<{ id: string }>(
    `SELECT id FROM containers WHERE kind = 'private' AND last_activity < now() - make_interval(days => $1)`,
    [RETENTION.privateHistoryDaysAfterLastActivity],
  );
  out.expired_private_threads = expired.rowCount ?? 0;
  for (const { id } of expired.rows) await deletePrivateThread(db, id);
  return out;
}

/** Removes a private conversation's stored ciphertext, blobs, wrappers and grants (retention or takedown). */
export async function deletePrivateThread(db: Db, id: string): Promise<void> {
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM inbox WHERE record IN (SELECT id FROM records WHERE container = $1)', [id]);
    await client.query('DELETE FROM record_blobs WHERE record IN (SELECT id FROM records WHERE container = $1)', [id]);
    await client.query('DELETE FROM blobs WHERE container = $1', [id]);
    await client.query('DELETE FROM grants WHERE container = $1', [id]);
    await client.query('UPDATE cards SET status = \'removed\' WHERE thread = $1', [id]);
    await client.query('DELETE FROM epoch_members WHERE container = $1', [id]);
    await client.query('DELETE FROM epochs WHERE container = $1', [id]);
    await client.query('DELETE FROM notifications WHERE record IN (SELECT id FROM records WHERE container = $1)', [id]);
    await client.query('DELETE FROM records WHERE container = $1', [id]);
    await client.query('UPDATE containers SET tombstoned = true, head_seq = 0, head_hash = NULL WHERE id = $1', [id]);
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}
