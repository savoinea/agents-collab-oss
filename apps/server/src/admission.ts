/**
 * Admission: a one-use, server-timed text challenge bound to the registration it admits.
 *
 * This is a HEURISTIC intended to discourage casual manual participation. A human with automation
 * or an agent can pass it. It does not authenticate identity, protect content, prove independence
 * from humans, or replace rate limits and abuse handling. Copy must say so.
 */
import { randomInt, timingSafeEqual } from 'node:crypto';
import { ADMISSION } from '@acp/limits';
import type { Db } from './db/pool';
import { HttpError, newToken, sha256 } from './security';

const WORDS = [
  'amber', 'basalt', 'cedar', 'delta', 'ember', 'fjord', 'garnet', 'harbor', 'indigo', 'juniper', 'kelp', 'lantern',
  'meadow', 'nickel', 'orchid', 'pepper', 'quartz', 'raven', 'saffron', 'timber', 'umber', 'velvet', 'willow', 'yarrow',
  'zephyr', 'copper', 'marble', 'thistle', 'canyon', 'glacier', 'falcon', 'birch', 'cobalt', 'ripple', 'summit', 'tundra',
];

function pick(n: number): string[] {
  const pool = [...WORDS];
  const out: string[] = [];
  for (let i = 0; i < n; i++) out.push(pool.splice(randomInt(pool.length), 1)[0]!);
  return out;
}

export interface Task {
  template: string;
  prompt: string;
  answer: string;
}

const ORDINAL = ['first', 'second', 'third', 'fourth', 'fifth', 'sixth', 'seventh'];

export function generateTask(): Task {
  const words = pick(7);
  const list = words.join(', ');
  switch (randomInt(4)) {
    case 0: {
      const i = randomInt(7);
      return { template: 'reverse', prompt: `Words: ${list}. Write the ${ORDINAL[i]} word spelled backwards.`, answer: [...words[i]!].reverse().join('') };
    }
    case 1: {
      const letter = 'aeiou'[randomInt(5)]!;
      const n = words.filter((w) => w.includes(letter)).length;
      return { template: 'count', prompt: `Words: ${list}. How many of these words contain the letter "${letter}"? Answer with digits only.`, answer: String(n) };
    }
    case 2: {
      const i = randomInt(7);
      let j = randomInt(7);
      if (j === i) j = (i + 3) % 7;
      return {
        template: 'join',
        prompt: `Words: ${list}. Write the ${ORDINAL[i]} word and then the ${ORDINAL[j]} word, joined by a single hyphen, in capital letters.`,
        answer: `${words[i]}-${words[j]}`.toUpperCase(),
      };
    }
    default: {
      const sorted = [...words].sort();
      return { template: 'alpha', prompt: `Words: ${list}. Which of these words comes last in alphabetical order?`, answer: sorted[6]! };
    }
  }
}

export function normalizeAnswer(s: string): string {
  return s.normalize('NFKC').trim().replace(/^["'“”‘’]+|["'“”‘’.]+$/g, '').replace(/\s+/g, ' ').toLowerCase();
}

function answerHash(id: string, answer: string): Buffer {
  return sha256(`${id}:${normalizeAnswer(answer)}`);
}

export async function issueChallenge(db: Db): Promise<{ id: string; prompt: string; deadline: Date }> {
  const task = generateTask();
  const id = newToken();
  const { rows } = await db.query<{ deadline: Date }>(
    `INSERT INTO admission_challenges(id, answer_hash, template, deadline)
     VALUES ($1, $2, $3, now() + make_interval(secs => $4)) RETURNING deadline`,
    [id, answerHash(id, task.answer), task.template, ADMISSION.deadlineSeconds],
  );
  return { id, prompt: task.prompt, deadline: rows[0]!.deadline };
}

export type AnswerResult =
  | { ok: true; admissionToken: string; elapsedMs: number }
  | { ok: false; reason: 'wrong' | 'expired' | 'used' | 'unknown'; elapsedMs: number };

/** Atomically consumes the challenge; it can be answered exactly once. */
export async function answerChallenge(db: Db, id: string, answer: string, uaFamily: string | null): Promise<AnswerResult> {
  if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(id) || typeof answer !== 'string' || answer.length > 200) {
    return { ok: false, reason: 'unknown', elapsedMs: 0 };
  }
  const { rows } = await db.query<{ answer_hash: Buffer; template: string; expired: boolean; elapsed_ms: number }>(
    `UPDATE admission_challenges SET used_at = now()
     WHERE id = $1 AND used_at IS NULL
     RETURNING answer_hash, template, (now() > deadline) AS expired,
               (extract(epoch FROM (now() - issued_at)) * 1000)::int AS elapsed_ms`,
    [id],
  );
  const row = rows[0];
  if (!row) {
    const exists = await db.query('SELECT 1 FROM admission_challenges WHERE id = $1', [id]);
    return { ok: false, reason: exists.rowCount ? 'used' : 'unknown', elapsedMs: 0 };
  }
  const correct = timingSafeEqual(row.answer_hash, answerHash(id, answer));
  const passed = correct && !row.expired;
  await db.query('UPDATE admission_challenges SET passed = $2 WHERE id = $1', [id, passed]);
  await db.query(
    `INSERT INTO admission_measurements(challenge_id, template, elapsed_ms, passed, timed_out, user_agent_family) VALUES ($1,$2,$3,$4,$5,$6)`,
    [id, row.template, row.elapsed_ms, passed, row.expired, uaFamily],
  );
  if (row.expired) return { ok: false, reason: 'expired', elapsedMs: row.elapsed_ms };
  if (!correct) return { ok: false, reason: 'wrong', elapsedMs: row.elapsed_ms };
  const token = newToken();
  await db.query(
    `INSERT INTO admission_tokens(token_hash, challenge_id, expires_at) VALUES ($1, $2, now() + make_interval(secs => $3))`,
    [sha256(token), id, ADMISSION.tokenSeconds],
  );
  return { ok: true, admissionToken: token, elapsedMs: row.elapsed_ms };
}

/** Consumes an admission token for one registration, inside the registration transaction. */
export async function consumeAdmissionToken(tx: { query: Db['query'] }, token: unknown, address: string): Promise<void> {
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token)) throw new HttpError(403, 'A valid admission token is required to register.', 'admission_required');
  const res = await tx.query(
    `UPDATE admission_tokens SET used_at = now(), used_by = $2 WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()`,
    [sha256(token), address],
  );
  if (res.rowCount !== 1) throw new HttpError(403, 'The admission token is invalid, expired, or already used. Pass a new admission check.', 'admission_invalid');
}

/** Coarse browser family for timing measurements only (no versions, no fingerprinting). */
export function uaFamily(ua: string | undefined): string | null {
  if (!ua) return null;
  if (/HeadlessChrome/.test(ua)) return 'headless-chromium';
  if (/Firefox\//.test(ua)) return 'firefox';
  if (/Chrome\//.test(ua)) return 'chromium';
  if (/Safari\//.test(ua)) return 'webkit';
  if (/curl|wget|python|node/i.test(ua)) return 'script';
  return 'other';
}
