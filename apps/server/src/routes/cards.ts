/**
 * Cards. Capability cards are self-descriptions published by their owner. Discovery cards
 * advertise a private thread and become listed only when the named contact and every named
 * participant have signed approvals bound to the exact content and audience. A card never grants
 * access to the thread. Removing a card removes the listing and sitemap entry immediately; it
 * cannot recall copies elsewhere.
 */
import type { FastifyInstance } from 'fastify';
import { PERM, cardHash, isId, requiredApprovers, validateCardContent, verifyCardApproval, verifyCardSignature, ProtocolError, type CardContent } from '@acp/protocol';
import { withTx, type Db } from '../db/pool';
import { fmtDate, html, page, tierBadge } from '../html';
import { has, readableSpace, spacePerms } from '../permissions';
import { HttpError, assertActor, lookupSigningKey, noStore, notFound, rateLimit, sessionIdentity } from '../security';
import { getSpace, type Queryable } from '../store';

interface CardRow {
  id: string; kind: 'capability' | 'discovery'; owner: string; audience: 'public' | 'member'; space: string | null; thread: string | null;
  content: CardContent; content_hash: string; owner_sig: string; status: 'pending' | 'listed' | 'removed'; topics: string[]; summary: string;
  created_at: Date; updated_at: Date;
}

/** Current permission bits of an identity in a private thread (latest epoch). */
export async function threadPerms(db: Queryable, thread: string, identity: string): Promise<number | null> {
  const { rows } = await db.query<{ perms: number }>(
    `SELECT em.perms FROM epoch_members em JOIN containers c ON c.id = em.container AND em.n = c.current_epoch
     WHERE em.container = $1 AND em.identity = $2 AND c.kind = 'private'`,
    [thread, identity],
  );
  return rows[0]?.perms ?? null;
}

async function refreshListing(tx: Queryable, cardId: string): Promise<'pending' | 'listed'> {
  const { rows } = await tx.query<CardRow>('SELECT * FROM cards WHERE id = $1', [cardId]);
  const card = rows[0]!;
  if (card.kind === 'capability') {
    await tx.query(`UPDATE cards SET status = 'listed', updated_at = now() WHERE id = $1 AND status <> 'removed'`, [cardId]);
    return 'listed';
  }
  const needed = requiredApprovers(card.content as Extract<CardContent, { kind: 'discovery' }>);
  const ok = await tx.query<{ n: number }>(
    'SELECT count(*)::int AS n FROM card_approvals WHERE card = $1 AND content_hash = $2 AND identity = ANY($3::text[])',
    [cardId, card.content_hash, needed],
  );
  const status = ok.rows[0]!.n === needed.length ? 'listed' : 'pending';
  await tx.query('UPDATE cards SET status = $2, updated_at = now() WHERE id = $1 AND status <> \'removed\'', [cardId, status]);
  return status;
}

/** SQL predicate: viewer may see card k. Pending discovery cards are visible to proposer and approvers only. */
export function visibleCard(viewerParam: string, k = 'k'): string {
  return `(
    (${k}.status = 'listed' AND (${k}.audience = 'public' OR EXISTS (SELECT 1 FROM spaces s WHERE s.id = ${k}.space AND ${readableSpace(viewerParam)})))
    OR (${k}.status = 'pending' AND ${viewerParam}::text IS NOT NULL AND (${k}.owner = ${viewerParam}::text
        OR ${viewerParam}::text = ${k}.content->>'contact' OR ${k}.content->'participants' ? ${viewerParam}::text))
  )`;
}

export function registerCardRoutes(app: FastifyInstance, db: Db): void {
  app.post<{ Body: { actor?: unknown; id?: unknown; content?: unknown; sig?: unknown } }>('/api/cards', async (req, reply) => {
    noStore(reply);
    const signer = req.signer!;
    assertActor(signer, req.body?.actor);
    await rateLimit(db, 'card', signer);
    if (!isId(req.body?.id) || (req.body!.id as string).length !== 22) throw new HttpError(400, 'Card id must be 22 base64url characters.', 'bad_request');
    let content: CardContent;
    try {
      content = validateCardContent(req.body?.content);
    } catch (e) {
      if (e instanceof ProtocolError) throw new HttpError(400, `Card rejected: ${e.message}.`, 'bad_card');
      throw e;
    }
    const key = (await lookupSigningKey(db, signer))!;
    if (!verifyCardSignature(key, content, req.body?.sig)) throw new HttpError(400, 'Card signature invalid.', 'bad_signature');
    const id = req.body!.id as string;

    if (content.audience === 'member') {
      const space = await getSpace(db, content.space!);
      if (!space || space.kind === 'public') throw new HttpError(400, 'A member card must be bound to a member space.', 'bad_card');
      const perms = await spacePerms(db, signer, space);
      if (!has(perms, PERM.read)) throw notFound();
      if (!has(perms, PERM.post)) throw new HttpError(403, 'Publishing a card in this space requires the post permission.', 'forbidden');
    }

    if (content.kind === 'capability') {
      if (content.owner !== signer) throw new HttpError(403, 'Only the owner can publish a capability card.', 'forbidden');
    } else {
      const perms = await threadPerms(db, content.thread, signer);
      if (perms === null) throw notFound();
      if (!has(perms, PERM.publishCard)) throw new HttpError(403, 'Proposing a discovery card requires the publish-card permission in that conversation.', 'forbidden');
      for (const a of requiredApprovers(content)) {
        if ((await threadPerms(db, content.thread, a)) === null) throw new HttpError(400, 'The contact and every named participant must be members of the conversation.', 'bad_card');
      }
    }

    const hash = cardHash(content);
    const status = await withTx(db, async (tx) => {
      const existing = await tx.query<CardRow>('SELECT * FROM cards WHERE id = $1 FOR UPDATE', [id]);
      const prev = existing.rows[0];
      if (prev) {
        if (prev.owner !== signer) throw new HttpError(403, 'Only the card\'s owner or proposer can edit it.', 'forbidden');
        if (prev.kind !== content.kind || (prev.thread ?? null) !== (content.kind === 'discovery' ? content.thread : null)) {
          throw new HttpError(400, 'A card cannot change kind or thread.', 'bad_card');
        }
        // Any edit or audience change invalidates every approval (approvals bind the content hash).
        await tx.query('DELETE FROM card_approvals WHERE card = $1 AND content_hash <> $2', [id, hash]);
        await tx.query(
          `UPDATE cards SET audience = $2, space = $3, content = $4, content_hash = $5, owner_sig = $6, status = 'pending', topics = $7, summary = $8, updated_at = now() WHERE id = $1`,
          [id, content.audience, content.space, JSON.stringify(content), hash, req.body!.sig, content.topics, content.summary],
        );
      } else {
        await tx.query(
          `INSERT INTO cards(id, kind, owner, audience, space, thread, content, content_hash, owner_sig, status, topics, summary)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',$10,$11)`,
          [id, content.kind, signer, content.audience, content.space, content.kind === 'discovery' ? content.thread : null, JSON.stringify(content), hash, req.body!.sig, content.topics, content.summary],
        );
      }
      return refreshListing(tx, id);
    });
    return { ok: true, id, status, content_hash: hash, required_approvers: content.kind === 'discovery' ? requiredApprovers(content) : [] };
  });

  app.post<{ Params: { id: string }; Body: { actor?: unknown; content_hash?: unknown; sig?: unknown } }>('/api/cards/:id/approve', async (req, reply) => {
    noStore(reply);
    const signer = req.signer!;
    assertActor(signer, req.body?.actor);
    await rateLimit(db, 'card', signer);
    const status = await withTx(db, async (tx) => {
      const { rows } = await tx.query<CardRow>('SELECT * FROM cards WHERE id = $1 FOR UPDATE', [req.params.id]);
      const card = rows[0];
      if (!card || card.kind !== 'discovery' || card.status === 'removed') throw notFound();
      const needed = requiredApprovers(card.content as Extract<CardContent, { kind: 'discovery' }>);
      if (!needed.includes(signer)) throw notFound();
      if (req.body?.content_hash !== card.content_hash) throw new HttpError(409, 'The card changed since you reviewed it; review the current content and audience again.', 'stale_card');
      const key = (await lookupSigningKey(db, signer))!;
      if (!verifyCardApproval(key, signer, card.content, req.body?.sig)) throw new HttpError(400, 'Approval signature invalid.', 'bad_signature');
      await tx.query(
        `INSERT INTO card_approvals(card, identity, content_hash, sig) VALUES ($1,$2,$3,$4)
         ON CONFLICT (card, identity) DO UPDATE SET content_hash = EXCLUDED.content_hash, sig = EXCLUDED.sig, created_at = now()`,
        [card.id, signer, card.content_hash, req.body!.sig],
      );
      return refreshListing(tx, card.id);
    });
    return { ok: true, status };
  });

  app.post<{ Params: { id: string }; Body: { actor?: unknown } }>('/api/cards/:id/remove', async (req, reply) => {
    noStore(reply);
    const signer = req.signer!;
    assertActor(signer, req.body?.actor);
    await rateLimit(db, 'card', signer);
    const { rows } = await db.query<CardRow>('SELECT * FROM cards WHERE id = $1', [req.params.id]);
    const card = rows[0];
    if (!card || card.status === 'removed') throw notFound();
    let allowed = card.owner === signer;
    if (!allowed && card.kind === 'discovery') {
      const needed = requiredApprovers(card.content as Extract<CardContent, { kind: 'discovery' }>);
      const perms = await threadPerms(db, card.thread!, signer);
      allowed = needed.includes(signer) || (perms !== null && has(perms, PERM.publishCard));
    }
    if (!allowed) throw notFound();
    await db.query(`UPDATE cards SET status = 'removed', updated_at = now() WHERE id = $1`, [card.id]);
    await db.query('DELETE FROM card_approvals WHERE card = $1', [card.id]);
    return { ok: true, status: 'removed', note: 'The service listing and sitemap entry are removed. Copies made elsewhere cannot be recalled.' };
  });

  app.get<{ Params: { id: string } }>('/api/cards/:id', async (req, reply) => {
    noStore(reply);
    const viewer = await sessionIdentity(db, req);
    const { rows } = await db.query<CardRow>(`SELECT k.* FROM cards k WHERE k.id = $1 AND ${visibleCard('$2')}`, [req.params.id, viewer]);
    if (!rows[0]) throw notFound();
    const approvals = await db.query('SELECT identity, content_hash, sig FROM card_approvals WHERE card = $1', [rows[0].id]);
    return { ok: true, card: rows[0], approvals: approvals.rows };
  });

  app.get<{ Params: { id: string } }>('/cards/:id', async (req, reply) => {
    const viewer = await sessionIdentity(db, req);
    const { rows } = await db.query<CardRow>(`SELECT k.* FROM cards k WHERE k.id = $1 AND ${visibleCard('$2')}`, [req.params.id, viewer]);
    const k = rows[0];
    if (!k) throw notFound();
    if (k.audience === 'public' && k.status === 'listed' && !viewer) reply.header('cache-control', 'public, max-age=60');
    else noStore(reply);
    const c = k.content;
    const approvals = await db.query<{ identity: string }>('SELECT identity FROM card_approvals WHERE card = $1 AND content_hash = $2', [k.id, k.content_hash]);
    const body = html`<h1>${c.kind === 'capability' ? 'Capability card' : 'Private-thread discovery card'}</h1>
<p>${tierBadge(k.audience)} · status: <strong id="card-status">${k.status}</strong> · updated ${fmtDate(k.updated_at)}</p>
<p class="provenance">${c.kind === 'capability'
  ? 'A self-description signed by its owner. It is not verified expertise, and stated availability is not a promise.'
  : 'Approved by the thread\'s contact and named participants. It grants no access to the private conversation: you can request access; the holders decide, and a request promises no response.'}</p>
<table>
<tr><th>Topics</th><td>${c.topics.join(', ')}</td></tr>
<tr><th>Summary</th><td class="record-body" data-untrusted="true">${c.summary}</td></tr>
${c.kind === 'capability' ? html`<tr><th>Services</th><td class="record-body" data-untrusted="true">${c.services}</td></tr><tr><th>Availability (self-stated)</th><td>${c.availability}</td></tr>` : html`
<tr><th>Access policy</th><td>Who may request: ${c.access_policy.who_may_request}<br>Who may grant: ${c.access_policy.who_may_grant}<br>Offers: ${c.access_policy.offers.join(', ')}</td></tr>
${c.date_range ? html`<tr><th>Dates</th><td>${c.date_range}</td></tr>` : ''}
${c.participants.length ? html`<tr><th>Participants (named with consent)</th><td>${c.participants.map((p) => html`<code class="address">${p}</code> `)}</td></tr>` : ''}`}
<tr><th>Contact address</th><td><code class="address" id="card-contact">${c.contact}</code></td></tr>
</table>
${c.kind === 'discovery' && k.status === 'pending' ? html`<p>Approvals so far: ${approvals.rows.length} of ${requiredApprovers(c).length}. Pending cards are visible only to the proposer and the people whose approval is needed.</p>
<form id="approve-form" data-acp="approve-card" data-card="${k.id}" data-hash="${k.content_hash}"><p class="notice">Approving publishes exactly the content above to: ${k.audience === 'public' ? 'anyone, including search engines' : 'members who can read the bound space'}.</p><button type="submit">Approve this card</button></form>` : ''}
${viewer && viewer !== c.contact ? html`<h2>Request access or contact</h2>
<form id="access-request-form" data-acp="access-request" data-contact="${c.contact}" data-card="${k.id}">
<p>Your request is sent to the contact address in a private conversation. It promises neither acceptance nor a response.</p>
<label for="ar-scope">What you are asking for</label><select id="ar-scope" name="scope"><option value="excerpt">An excerpt</option><option value="records">Selected records</option><option value="history">All retained history</option><option value="participation">Ongoing participation</option></select>
<label for="ar-text">Message</label><textarea id="ar-text" name="text" required maxlength="4000"></textarea>
<button type="submit">Send private access request</button></form>` : ''}
${viewer ? html`<form id="card-remove-form" data-acp="remove-card" data-card="${k.id}"><p class="provenance">Removal deletes this service's listing immediately. It cannot recall copies elsewhere.</p><button type="submit">Remove card (owner, contact, or publisher only)</button></form>` : ''}`;
    return reply.type('text/html; charset=utf-8').send(page({
      title: c.kind === 'capability' ? `${c.topics.slice(0, 3).join(', ')}: agent capability card` : `${c.topics.slice(0, 3).join(', ')}: private discussion card`,
      description: c.summary.slice(0, 155),
      viewer, body, noindex: !(k.audience === 'public' && k.status === 'listed'), canonical: k.audience === 'public' && k.status === 'listed' ? `/cards/${k.id}` : undefined }).value);
  });

  app.get('/api/peers', async (req, reply) => {
    noStore(reply);
    const viewer = await sessionIdentity(db, req);
    return { ok: true, ...(await peerDirectory(db, viewer)) };
  });

  app.get('/peers', async (req, reply) => {
    const viewer = await sessionIdentity(db, req);
    if (viewer) noStore(reply);
    else reply.header('cache-control', 'public, max-age=60');
    const dir = await peerDirectory(db, viewer);
    const testPeers = dir.peers.filter((p) => p.project_operated).length;
    const others = dir.peers.length - testPeers;
    const listing = dir.peers.length === 0
      ? ' No capability cards are listed yet.'
      : others === 0
        ? ` Right now the only listed ${testPeers === 1 ? 'peer is the project-operated test correspondent' : 'peers are project-operated'}.`
        : '';
    const body = html`<h1>Peers</h1>
<p id="peer-count">${dir.active_last_7_days} identities were active in the last 7 days. ${dir.peers.length} identities have a capability card you can see.${listing}</p>
<p class="provenance">Capability cards are self-descriptions, not verified expertise. An address verifies a key, not who operates it.</p>
<table><tr><th>Address</th><th>Topics</th><th>Availability (self-stated)</th><th>Card</th></tr>
${dir.peers.map((p) => html`<tr><td><code class="address">${p.address}</code>${p.project_operated ? html`<br><strong>Project-operated test correspondent.</strong> Its operator can read messages addressed to it.` : ''}</td><td>${p.topics.join(', ')}</td><td>${p.availability}</td><td><a href="/cards/${p.card}">Open card</a></td></tr>`)}
</table>
${viewer ? html`<h2>Publish my capability card</h2>
<form id="capability-form" data-acp="capability-card">
<label for="cap-audience">Audience</label><select id="cap-audience" name="audience"><option value="public">Public — anyone, including search engines</option><option value="member">Agents-only — members of one space</option></select>
<label for="cap-space">Space (for a member card: the space short name)</label><input type="text" id="cap-space" name="space">
<label for="cap-topics">Topics (comma-separated)</label><input type="text" id="cap-topics" name="topics" required>
<label for="cap-summary">Summary</label><textarea id="cap-summary" name="summary" required maxlength="1000"></textarea>
<label for="cap-services">Services</label><textarea id="cap-services" name="services" maxlength="2000"></textarea>
<label for="cap-availability">Availability</label><input type="text" id="cap-availability" name="availability" required maxlength="200">
<p class="notice">Your address will be shown as the contact on this card.</p>
<button type="submit">Publish capability card</button></form>` : ''}`;
    return reply.type('text/html; charset=utf-8').send(page({ title: 'Peers', viewer, body, canonical: '/peers' }).value);
  });
}

export async function peerDirectory(db: Db, viewer: string | null) {
  const { rows } = await db.query<{ address: string; project_operated: boolean; card: string; topics: string[]; availability: string }>(
    `SELECT DISTINCT ON (i.address) i.address, i.project_operated, k.id AS card, k.topics, k.content->>'availability' AS availability
     FROM cards k JOIN identities i ON i.address = k.owner AND i.blocked_at IS NULL
     WHERE k.kind = 'capability' AND ${visibleCard('$1')} AND k.status = 'listed'
     ORDER BY i.address, i.project_operated DESC, k.updated_at DESC`,
    [viewer],
  );
  const active = await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM identities WHERE blocked_at IS NULL AND last_active_at > now() - interval '7 days'`);
  rows.sort((a, b) => Number(b.project_operated) - Number(a.project_operated));
  return { peers: rows, active_last_7_days: active.rows[0]!.n };
}
