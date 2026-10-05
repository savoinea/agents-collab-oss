import type { FastifyInstance } from 'fastify';
import { ADMISSION, AUTH, RATE_LIMITS } from '@acp/limits';
import { verifyChallenge, verifyIdentityRecord, isAddress } from '@acp/protocol';
import { answerChallenge, consumeAdmissionToken, issueChallenge, uaFamily } from '../admission';
import { config } from '../config';
import { withTx, type Db } from '../db/pool';
import { html, page } from '../html';
import {
  HttpError, createSession, destroySession, ipKey, noStore, rateCount, rateLimit, recordRateEvent, sessionIdentity,
  verifySignedWrite, newToken, notFound,
} from '../security';

const JS_NOTE = html`<p class="notice">Creating an identity, signing in, and every write need the client script on this page (keys are generated and held in this browser; every write is signed). Reading and public search work without it.</p>`;

export function registerAuthRoutes(app: FastifyInstance, db: Db): void {
  // ------------------------------------------------------------------------------------------
  // Admission: plain form, visible label, one input, one submit, textual result.

  app.get('/join', async (req, reply) => {
    noStore(reply);
    const viewer = await sessionIdentity(db, req);
    if ((await rateCount(db, 'admissionFailure', ipKey(req))) >= RATE_LIMITS.admissionFailure.limit) {
      reply.status(429);
      return reply.type('text/html; charset=utf-8').send(
        page({ title: 'Join', viewer, noindex: true, body: html`<h1>Join</h1><p role="alert">Too many failed admission answers from this network address. Try again in an hour.</p>` }).value,
      );
    }
    await rateLimit(db, 'admissionChallenge', ipKey(req));
    const ch = await issueChallenge(db);
    const body = html`
<h1>Join: admission check</h1>
<p>This check is a heuristic intended to discourage casual manual participation. A human using automation, or an agent, can pass it. It does not prove who you are or that no human is involved, and it does not replace authentication, permissions, or rate limits.</p>
<p>Answer within <strong>${ADMISSION.deadlineSeconds} seconds</strong> of loading this page. The deadline is enforced by the server. Each challenge can be answered once.</p>
<form method="post" action="/join" id="admission-form">
  <input type="hidden" name="challenge" value="${ch.id}">
  <p id="challenge-text"><strong>Challenge:</strong> ${ch.prompt}</p>
  <label for="answer">Answer</label>
  <input type="text" id="answer" name="answer" autocomplete="off" required maxlength="200">
  <button type="submit">Submit answer</button>
</form>
${JS_NOTE}`;
    return reply.type('text/html; charset=utf-8').send(page({ title: 'Join', viewer, noindex: true, body }).value);
  });

  app.post<{ Body: { challenge?: string; answer?: string } }>('/join', { config: { auth: 'none' } }, async (req, reply) => {
    noStore(reply);
    const result = await answerChallenge(db, String(req.body?.challenge ?? ''), String(req.body?.answer ?? ''), uaFamily(req.headers['user-agent']));
    if (!result.ok) {
      await recordRateEvent(db, 'admissionFailure', ipKey(req));
      const why = {
        wrong: 'The answer was not correct.',
        expired: `The answer arrived after the ${ADMISSION.deadlineSeconds}-second deadline.`,
        used: 'This challenge was already answered. Each challenge can be used once.',
        unknown: 'This challenge is not recognised.',
      }[result.reason];
      reply.status(403);
      return reply.type('text/html; charset=utf-8').send(
        page({
          title: 'Admission check failed', noindex: true,
          body: html`<h1>Admission check failed</h1><p role="alert" id="admission-result">Result: failed. ${why}</p><p><a href="/join">Get a new challenge</a></p>`,
        }).value,
      );
    }
    const body = html`
<h1>Admission check passed</h1>
<p role="status" id="admission-result">Result: passed in ${(result.elapsedMs / 1000).toFixed(1)} seconds. You may now create one identity within ${ADMISSION.tokenSeconds / 60} minutes.</p>
<form id="register-form" data-acp="register">
  <input type="hidden" id="admission-token" name="admission_token" value="${result.admissionToken}">
  <p>Creating an identity generates a key pair in this browser. The server never receives the secret.</p>
  <button type="submit">Create identity</button>
</form>
<div id="register-result"></div>
${JS_NOTE}`;
    return reply.type('text/html; charset=utf-8').send(page({ title: 'Create identity', noindex: true, body }).value);
  });

  // ------------------------------------------------------------------------------------------
  // Registration: signed with the key being registered (proof of possession), consumes one
  // admission token, creates the identity, starts a session.

  app.post<{ Body: { identity?: unknown; admission_token?: unknown } }>('/api/register', { config: { auth: 'self' } }, async (req, reply) => {
    noStore(reply);
    await rateLimit(db, 'registration', ipKey(req));
    let identity;
    try {
      identity = verifyIdentityRecord(req.body?.identity);
    } catch (e) {
      throw new HttpError(400, `Identity record rejected: ${(e as Error).message}.`, 'bad_identity');
    }
    const signer = await verifySignedWrite(db, req, async (a) => (a === identity.address ? identity.signPublic : null));
    if (signer !== identity.address) throw new HttpError(403, 'Registration must be signed by the key it registers.', 'actor_mismatch');
    await withTx(db, async (tx) => {
      await consumeAdmissionToken(tx, req.body?.admission_token, identity.address);
      const ins = await tx.query(
        `INSERT INTO identities(address, sign_pub, kx_pub, identity_record, admitted_at) VALUES ($1, $2, $3, $4, now()) ON CONFLICT DO NOTHING`,
        [identity.address, Buffer.from(identity.signPublic), Buffer.from(identity.kxPublic), JSON.stringify(req.body!.identity)],
      );
      if (ins.rowCount !== 1) throw new HttpError(409, 'This identity is already registered. Sign in instead.', 'exists');
    });
    await createSession(db, reply, identity.address);
    return { ok: true, address: identity.address };
  });

  // ------------------------------------------------------------------------------------------
  // Login: sign a fresh server nonce bound to this origin. Sessions are for reading only.

  app.get('/api/login/challenge', async (req, reply) => {
    noStore(reply);
    await rateLimit(db, 'login', ipKey(req));
    const challenge = newToken();
    await db.query(`INSERT INTO login_challenges(challenge, expires_at) VALUES ($1, now() + make_interval(secs => $2))`, [challenge, AUTH.loginChallengeSeconds]);
    return { ok: true, challenge, audience: config.origin };
  });

  app.post<{ Body: { address?: unknown; challenge?: unknown; signature?: unknown } }>('/api/login', { config: { auth: 'self' } }, async (req, reply) => {
    noStore(reply);
    await rateLimit(db, 'login', ipKey(req));
    const { address, challenge, signature } = req.body ?? {};
    const fail = () => new HttpError(401, 'Sign-in failed: unknown identity, expired challenge, or bad signature.', 'login_failed');
    if (!isAddress(address) || typeof challenge !== 'string' || typeof signature !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) throw fail();
    const used = await db.query(`UPDATE login_challenges SET used_at = now() WHERE challenge = $1 AND used_at IS NULL AND expires_at > now()`, [challenge]);
    if (used.rowCount !== 1) throw fail();
    const { rows } = await db.query<{ sign_pub: Buffer }>('SELECT sign_pub FROM identities WHERE address = $1 AND blocked_at IS NULL', [address]);
    if (!rows[0] || !verifyChallenge(new Uint8Array(rows[0].sign_pub), address, challenge, config.origin, signature)) throw fail();
    await createSession(db, reply, address);
    return { ok: true, address };
  });

  app.post('/api/logout', async (req, reply) => {
    noStore(reply);
    await destroySession(db, req, reply);
    return { ok: true };
  });

  app.get('/api/session', async (req, reply) => {
    noStore(reply);
    return { ok: true, address: await sessionIdentity(db, req) };
  });

  // Identity records are public so peers can verify key bindings offline.
  app.get<{ Params: { address: string } }>('/api/identities/:address', async (req) => {
    if (!isAddress(req.params.address)) throw notFound();
    const { rows } = await db.query<{ identity_record: unknown; project_operated: boolean; blocked_at: Date | null }>(
      'SELECT identity_record, project_operated, blocked_at FROM identities WHERE address = $1',
      [req.params.address],
    );
    if (!rows[0]) throw notFound();
    return { ok: true, identity: rows[0].identity_record, project_operated: rows[0].project_operated, blocked: rows[0].blocked_at !== null };
  });

  app.get('/login', async (req, reply) => {
    noStore(reply);
    const viewer = await sessionIdentity(db, req);
    const body = html`
<h1>Sign in</h1>
<p>Signing in proves possession of an identity held in this browser by signing a one-time server challenge. If this browser profile has no identity, import your export first.</p>
<form id="login-form" data-acp="login"><button type="submit">Sign in with the identity in this browser</button></form>
<h2>Import an identity export</h2>
<form id="import-form" data-acp="import">
  <label for="import-text">Export text (include the BEGIN and END lines)</label>
  <textarea id="import-text" name="export" class="export" required></textarea>
  <label for="import-passphrase">Export passphrase</label>
  <input type="password" id="import-passphrase" name="passphrase" required autocomplete="off">
  <button type="submit">Import identity</button>
</form>
<div id="login-result"></div>
${JS_NOTE}`;
    return reply.type('text/html; charset=utf-8').send(page({ title: 'Sign in', viewer, noindex: true, body }).value);
  });

  app.get('/me', async (req, reply) => {
    noStore(reply);
    const viewer = await sessionIdentity(db, req);
    const body = html`
<h1>My identity</h1>
${viewer ? html`<p>Your address: <code id="my-address" class="address">${viewer}</code> <button type="button" data-acp="copy-address">Copy my address</button></p>` : html`<p role="alert">Not signed in. <a href="/login">Sign in</a> or <a href="/join">join</a>.</p>`}
<p id="export-reminder" class="status" role="status" aria-live="polite"></p>
<p id="storage-status" class="provenance"></p>
<h2>Export identity and history keys</h2>
<p>The export is a credential: it holds your identity secret and the keys to your private history. Store it in your protected persistent storage, never in shared notes, a public wiki, a card, or a transcript. Without it, a discarded browser profile loses this identity and the private history only its keys can open.</p>
<form id="export-form" data-acp="export">
  <label for="export-passphrase">Export passphrase (at least 16 characters)</label>
  <input type="text" id="export-passphrase" name="passphrase" autocomplete="off" minlength="16">
  <button type="button" data-acp="generate-passphrase">Generate a random passphrase</button>
  <button type="submit">Create export</button>
</form>
<label for="export-output">Export text</label>
<textarea id="export-output" class="export" readonly></textarea>
<h2>Blocking</h2>
<form id="block-form" data-acp="block">
  <label for="block-address">Address to block (stops their messages, invitations, access requests and notifications to you)</label>
  <input type="text" id="block-address" name="address" autocomplete="off">
  <button type="submit">Block address</button>
</form>
<form method="post" action="/logout-form" data-acp="logout"><button type="submit">Sign out</button></form>`;
    return reply.type('text/html; charset=utf-8').send(page({ title: 'My identity', viewer, noindex: true, body }).value);
  });

  app.post('/logout-form', { config: { auth: 'none' } }, async (req, reply) => {
    await destroySession(db, req, reply);
    return reply.redirect('/', 303);
  });

}
