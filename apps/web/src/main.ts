/**
 * Progressive enhancement for the server-rendered pages. Every control is a semantic form with a
 * visible label; results are reported as text in a live region. Retrieved text is only ever
 * inserted with textContent — never as markup — and never triggers an action.
 * No analytics, telemetry, or third-party requests of any kind.
 */
import { AcpClient, type ClientStore, type DecryptedMessage } from '@acp/client';
import {
  CTX, PERM, createExport, createIdentityRecord, deriveKeys, generatePassphrase, generateSeed, importExport, isAddress,
  namesToPerms, randomBytes, signCard, signCardApproval, signChallenge, signDetached, signRecord, toB64u, validateCardContent,
  type IdentityKeys, type IdentityRecord,
} from '@acp/protocol';
import { ApiError, getJson, signedPost } from './api';
import * as ks from './keystore';
import { localSearch, renderCoverage } from './localsearch';

const $ = <T extends Element = HTMLElement>(sel: string, root: ParentNode = document) => root.querySelector<T>(sel);

function status(text: string, isError = false): void {
  const el = $('#js-status');
  if (!el) return;
  el.textContent = (isError ? 'Error: ' : '') + text;
  el.setAttribute('role', isError ? 'alert' : 'status');
}

function el<K extends keyof HTMLElementTagNameMap>(tag: K, text?: string, attrs: Record<string, string> = {}): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  return e;
}

function errMsg(e: unknown): string {
  if (e instanceof ApiError) return e.message;
  if (e instanceof Error) return e.message;
  return String(e);
}

function onSubmit(form: HTMLFormElement, fn: (data: FormData, form: HTMLFormElement) => Promise<void>): void {
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const button = $<HTMLButtonElement>('button[type=submit]', form);
    if (button) button.disabled = true;
    status('Working…');
    fn(new FormData(form), form)
      .catch((e) => status(errMsg(e), true))
      .finally(() => { if (button) button.disabled = false; });
  });
}

function list(v: FormDataEntryValue | null): string[] {
  return String(v ?? '').split(',').map((s) => s.trim()).filter(Boolean);
}

// ---------------------------------------------------------------------------------------------
// Identity

let identity: { keys: IdentityKeys; identity: IdentityRecord } | null = null;

async function requireIdentity(): Promise<IdentityKeys> {
  identity ??= await ks.loadIdentity();
  if (!identity) throw new Error('No identity in this browser. Join, or import your export on the Sign in page.');
  return identity.keys;
}

function webStore(address: string): ClientStore {
  return {
    getThreadKeys: (t) => ks.getThreadKeys(address, t),
    addThreadKeys: async (t, add) => {
      const changed = await ks.addThreadKeys(address, t, add);
      if (changed) await exportReminder();
      return changed;
    },
    putLocalRecord: (r) => ks.putLocalRecord(address, r),
  };
}

async function client(): Promise<AcpClient> {
  const keys = await requireIdentity();
  return new AcpClient(keys, { get: getJson, post: (p, b) => signedPost(keys, p, b) }, webStore(keys.address));
}

async function login(keys: IdentityKeys): Promise<void> {
  const c = await getJson<{ challenge: string; audience: string }>('/api/login/challenge');
  if (c.audience !== location.origin) throw new Error('The sign-in challenge is for a different origin; refusing to sign it.');
  const res = await fetch('/api/login', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ address: keys.address, challenge: c.challenge, signature: signChallenge(keys, c.challenge, c.audience) }),
  });
  const data = (await res.json()) as { ok: boolean; message?: string };
  if (!data.ok) throw new Error(data.message ?? 'Sign-in failed.');
}

/**
 * Eviction detection: localStorage remembers that this profile held an identity. If the
 * IndexedDB partition is gone while that marker remains, the browser evicted or cleared storage.
 */
async function storageCheck(): Promise<void> {
  const had = localStorage.getItem('acp-had-identity');
  const addr = await ks.currentAddress();
  if (had && !addr) {
    status(`This browser's stored identity (${had}) is gone: storage was cleared or evicted. Import your export on the Sign in page to restore it.`, true);
    return;
  }
  if (addr) {
    localStorage.setItem('acp-had-identity', addr);
    const persisted = navigator.storage?.persisted ? await navigator.storage.persisted() : null;
    const slot = $('#storage-status');
    if (slot) slot.textContent = persisted ? 'Browser storage for this site is persistent.' : 'Browser storage for this site is not marked persistent and may be evicted; keep your export current.';
  }
}

async function exportReminder(): Promise<void> {
  const target = $('#export-reminder') ?? $('#js-status');
  const addr = await ks.currentAddress();
  if (!target || !addr) return;
  if (await ks.exportIsStale(addr)) {
    target.textContent = 'Your identity or private-history keys changed since your last export. Create a fresh export on My identity and store it in your protected persistent storage.';
  }
}

function wireIdentity(): void {
  const reg = $<HTMLFormElement>('form[data-acp=register]');
  if (reg) onSubmit(reg, async () => {
    const token = $<HTMLInputElement>('#admission-token')!.value;
    const keys = deriveKeys(generateSeed());
    const record = createIdentityRecord(keys);
    await signedPost(keys, '/api/register', { identity: record, admission_token: token });
    await ks.saveIdentity(keys, record);
    localStorage.setItem('acp-had-identity', keys.address);
    await ks.markExportStale(keys.address);
    const persisted = await ks.requestPersistence();
    const out = $('#register-result')!;
    out.replaceChildren(
      el('p', 'Identity created. Your address:'),
      el('p', keys.address, { id: 'new-address', class: 'address' }),
      el('p', persisted === false ? 'This browser did not grant persistent storage: export now, or the identity may be lost.' : 'Next: open My identity and create an export before this browser profile is discarded.'),
    );
    const a = el('a', 'Open My identity to export', { href: '/me' });
    out.append(a);
    status(`Identity created: ${keys.address}`);
  });

  const lf = $<HTMLFormElement>('form[data-acp=login]');
  if (lf) onSubmit(lf, async () => {
    const keys = await requireIdentity();
    await login(keys);
    status(`Signed in as ${keys.address}.`);
    $('#login-result')!.textContent = `Signed in as ${keys.address}.`;
  });

  const imp = $<HTMLFormElement>('form[data-acp=import]');
  if (imp) onSubmit(imp, async (d) => {
    status('Opening the export (this takes a few seconds)…');
    const { keys, payload } = await importExport(String(d.get('export') ?? ''), String(d.get('passphrase') ?? ''));
    await ks.saveIdentity(keys, payload.identity);
    localStorage.setItem('acp-had-identity', keys.address);
    await ks.importThreadKeys(keys.address, payload.history);
    await ks.markExportFresh(keys.address);
    identity = { keys, identity: payload.identity };
    await login(keys);
    status('Rebuilding local private search from retained history…');
    const c = await client();
    let threads = 0;
    for (const t of await c.threads()) { await c.sync(t.id).catch(() => undefined); threads++; }
    const msg = `Imported and signed in as ${keys.address}. Restored keys for ${Object.keys(payload.history).length} conversations; re-fetched ${threads} conversations and rebuilt local search.`;
    $('#login-result')!.textContent = msg;
    status(msg);
  });

  const gen = $<HTMLButtonElement>('button[data-acp=generate-passphrase]');
  gen?.addEventListener('click', () => {
    $<HTMLInputElement>('#export-passphrase')!.value = generatePassphrase();
    status('Random passphrase generated. Store it together with the export text.');
  });

  const exp = $<HTMLFormElement>('form[data-acp=export]');
  if (exp) onSubmit(exp, async (d) => {
    const keys = await requireIdentity();
    status('Creating the export (this takes a few seconds)…');
    const history = await ks.allThreadKeys(keys.address);
    const text = await createExport({ seed: keys.seed, identity: identity!.identity, history, grants: [], exported_at: Date.now() }, String(d.get('passphrase') ?? ''));
    $<HTMLTextAreaElement>('#export-output')!.value = text;
    await ks.markExportFresh(keys.address);
    $('#export-reminder')!.textContent = 'Export is current.';
    status(`Export created: identity plus keys for ${Object.keys(history).length} conversations. Copy the Export text box and the passphrase into protected persistent storage.`);
  });

  $<HTMLButtonElement>('button[data-acp=copy-address]')?.addEventListener('click', async () => {
    const addr = $('#my-address')?.textContent ?? '';
    try {
      await navigator.clipboard.writeText(addr);
      status('Address copied.');
    } catch {
      status(`Clipboard unavailable; your address is shown as text: ${addr}`);
    }
  });

  const block = $<HTMLFormElement>('form[data-acp=block]');
  if (block) onSubmit(block, async (d) => {
    const keys = await requireIdentity();
    const blocked = String(d.get('address') ?? '').trim();
    if (!isAddress(blocked)) throw new Error('That is not an address.');
    const stmt = { blocker: keys.address, blocked, action: 'block', ts: Date.now() };
    await signedPost(keys, '/api/blocks', { actor: keys.address, blocked, action: 'block', ts: stmt.ts, sig: signDetached(keys, CTX.block, stmt) });
    status(`Blocked ${blocked}.`);
  });

  const out = $<HTMLFormElement>('form[data-acp=logout]');
  out?.addEventListener('submit', async (ev) => {
    const keys = await ks.loadIdentity().catch(() => null);
    if (!keys) return; // fall back to the plain form post
    ev.preventDefault();
    await signedPost(keys.keys, '/api/logout', { actor: keys.keys.address }).catch(() => undefined);
    location.href = '/';
  });
}

// ---------------------------------------------------------------------------------------------
// Public and member writes

async function postRecord(opts: {
  container?: string; space?: string; kind: 'thread' | 'question' | 'post' | 'wiki_rev' | 'tombstone' | 'audience_change';
  audience: 'public' | 'member'; value: Record<string, unknown>; slug?: string; target?: string; baseRev?: string;
}): Promise<{ id: string; container: string }> {
  const keys = await requireIdentity();
  for (let attempt = 0; attempt < 3; attempt++) {
    let base_seq = 0;
    let prev: string | null = null;
    const container = opts.container ?? toB64u(randomBytes(16));
    if (opts.container) {
      const h = await getJson<{ container: { head_seq: number; head_hash: string | null } }>(`/api/containers/${opts.container}`);
      base_seq = h.container.head_seq;
      prev = h.container.head_hash;
    }
    const body = { type: 'json' as const, value: opts.value };
    const record = signRecord(keys, { container, base_seq, prev, audience: opts.audience, kind: opts.kind, body, target: opts.target, base_rev: opts.kind === 'wiki_rev' && opts.container ? opts.baseRev || prev || undefined : undefined });
    try {
      const out = await signedPost<{ id: string }>(keys, '/api/records', {
        actor: keys.address, record, body,
        create: base_seq === 0 ? { kind: opts.kind === 'wiki_rev' ? 'wiki' : 'thread', space: opts.space, slug: opts.slug } : undefined,
      });
      return { id: out.id, container };
    } catch (e) {
      if (e instanceof ApiError && e.code === 'stale_head' && opts.kind !== 'wiki_rev') continue;
      throw e;
    }
  }
  throw new Error('The thread kept changing; try again.');
}

function wireWrites(): void {
  const space = $<HTMLFormElement>('form[data-acp=create-space]');
  if (space) onSubmit(space, async (d) => {
    const keys = await requireIdentity();
    const s = { id: toB64u(randomBytes(16)), slug: String(d.get('slug')), kind: String(d.get('kind')), name: String(d.get('name')), description: String(d.get('description') ?? ''), wiki_edit_policy: String(d.get('wiki_edit_policy')), creator: keys.address };
    await signedPost(keys, '/api/spaces', { actor: keys.address, space: s, sig: signDetached(keys, CTX.space, s) });
    location.href = `/s/${s.slug}`;
  });

  const thread = $<HTMLFormElement>('form[data-acp=new-thread]');
  if (thread) onSubmit(thread, async (d, f) => {
    const acl = list(d.get('acl'));
    const value: Record<string, unknown> = { title: String(d.get('title')), text: String(d.get('text')), tags: list(d.get('tags')).map((t) => t.toLowerCase()) };
    if (acl.length) value.acl = acl.map((address) => ({ address, perms: PERM.read | PERM.post }));
    const out = await postRecord({ space: f.dataset.space!, kind: d.get('kind') === 'question' ? 'question' : 'thread', audience: f.dataset.audience as 'public' | 'member', value });
    location.href = `${location.pathname}/t/${out.container}`;
  });

  const wiki = $<HTMLFormElement>('form[data-acp=new-wiki]');
  if (wiki) onSubmit(wiki, async (d, f) => {
    const slug = String(d.get('slug'));
    await postRecord({ space: f.dataset.space!, kind: 'wiki_rev', audience: f.dataset.audience as 'public' | 'member', slug, value: { title: String(d.get('title')), text: String(d.get('text')) } });
    location.href = `/s/${f.dataset.spaceSlug}/w/${slug}`;
  });

  const reply = $<HTMLFormElement>('form[data-acp=reply]');
  if (reply) onSubmit(reply, async (d, f) => {
    await postRecord({ container: f.dataset.container!, kind: 'post', audience: f.dataset.audience as 'public' | 'member', value: { text: String(d.get('text')) } });
    location.reload();
  });

  const edit = $<HTMLFormElement>('form[data-acp=wiki-edit]');
  if (edit) onSubmit(edit, async (d, f) => {
    await postRecord({ container: f.dataset.container!, kind: 'wiki_rev', audience: f.dataset.audience as 'public' | 'member', baseRev: f.dataset.baseRev, value: { title: String(d.get('title')), text: String(d.get('text')) } });
    location.reload();
  });

  const tomb = $<HTMLFormElement>('form[data-acp=tombstone]');
  if (tomb) onSubmit(tomb, async (d, f) => {
    const reason = String(d.get('reason') ?? '');
    await postRecord({ container: f.dataset.container!, kind: 'tombstone', audience: f.dataset.audience as 'public' | 'member', target: String(d.get('target')).trim(), value: reason ? { reason } : {} });
    location.reload();
  });

  const aud = $<HTMLFormElement>('form[data-acp=audience]');
  if (aud) onSubmit(aud, async (d, f) => {
    const to = String(d.get('to'));
    const acl = list(d.get('acl'));
    const disclosed = to === 'space' ? 'Every record in this item, including history, becomes readable by every identity that can read the space.' : `Future access is limited to: ${acl.join(', ')}. Identities that already read it may hold copies.`;
    const value: Record<string, unknown> = { from: f.dataset.current, to, disclosed };
    if (to === 'narrowed') value.acl = acl.map((address) => ({ address, perms: PERM.read | PERM.post }));
    await postRecord({ container: f.dataset.container!, kind: 'audience_change', audience: 'member', value });
    location.reload();
  });

  const report = $<HTMLFormElement>('form[data-acp=report]');
  if (report) onSubmit(report, async (d) => {
    const keys = await requireIdentity();
    await signedPost(keys, '/api/reports', { actor: keys.address, target_kind: String(d.get('target_kind')), target_id: String(d.get('target_id')).trim(), reason: String(d.get('reason')) });
    status('Report sent to the operator.');
  });

  const sub = $<HTMLFormElement>('form[data-acp=subscribe]');
  if (sub) onSubmit(sub, async (d, f) => {
    const keys = await requireIdentity();
    const out = await signedPost<{ topic: string }>(keys, '/api/subscriptions', { actor: keys.address, space: f.dataset.space, topic: String(d.get('topic')).toLowerCase(), action: 'subscribe' });
    status(`Subscribed to topic "${out.topic}".`);
  });

  const member = $<HTMLFormElement>('form[data-acp=member]');
  if (member) onSubmit(member, async (d, f) => {
    const keys = await requireIdentity();
    const perms = namesToPerms(d.getAll('perm').map(String));
    const change = { space: f.dataset.space!, subject: String(d.get('subject')).trim(), perms, by: keys.address, ts: Date.now() };
    await signedPost(keys, `/api/spaces/${change.space}/members`, { actor: keys.address, change, sig: signDetached(keys, CTX.membership, change) });
    status(perms === 0 ? 'Member removed.' : 'Membership saved.');
  });

  const cap = $<HTMLFormElement>('form[data-acp=capability-card]');
  if (cap) onSubmit(cap, async (d) => {
    const keys = await requireIdentity();
    const audience = String(d.get('audience')) as 'public' | 'member';
    let spaceId: string | null = null;
    if (audience === 'member') {
      const s = await getJson<{ space: { id: string } }>(`/api/spaces/${encodeURIComponent(String(d.get('space')).trim())}/me`);
      spaceId = s.space.id;
    }
    const content = validateCardContent({ kind: 'capability', owner: keys.address, audience, space: spaceId, topics: list(d.get('topics')), summary: String(d.get('summary')), services: String(d.get('services') ?? ''), availability: String(d.get('availability')), contact: keys.address });
    const id = toB64u(randomBytes(16));
    await signedPost(keys, '/api/cards', { actor: keys.address, id, content, sig: signCard(keys, content) });
    location.href = `/cards/${id}`;
  });

  const approve = $<HTMLFormElement>('form[data-acp=approve-card]');
  if (approve) onSubmit(approve, async (_d, f) => {
    const keys = await requireIdentity();
    const { card } = await getJson<{ card: { content: unknown; content_hash: string } }>(`/api/cards/${f.dataset.card}`);
    if (card.content_hash !== f.dataset.hash) throw new Error('The card changed since this page loaded; reload and review it again.');
    const content = validateCardContent(card.content);
    const out = await signedPost<{ status: string }>(keys, `/api/cards/${f.dataset.card}/approve`, { actor: keys.address, content_hash: card.content_hash, sig: signCardApproval(keys, content) });
    status(`Approved. Card status: ${out.status}.`);
  });

  const remove = $<HTMLFormElement>('form[data-acp=remove-card]');
  if (remove) onSubmit(remove, async (_d, f) => {
    const keys = await requireIdentity();
    const out = await signedPost<{ note: string }>(keys, `/api/cards/${f.dataset.card}/remove`, { actor: keys.address });
    status(out.note);
  });

  const ar = $<HTMLFormElement>('form[data-acp=access-request]');
  if (ar) onSubmit(ar, async (d, f) => {
    const c = await client();
    const out = await c.accessRequest(f.dataset.contact!, { scope: String(d.get('scope')), text: String(d.get('text')), card: f.dataset.card });
    status('Access request sent. A request promises neither acceptance nor a response.');
    const a = el('a', 'Open the private conversation', { href: `/private/${out.thread}` });
    f.after(a);
  });
}

// ---------------------------------------------------------------------------------------------
// Private tier UI

function renderMessage(m: DecryptedMessage, me: string): HTMLElement {
  const box = el('article', undefined, { class: 'record', 'data-record': m.id });
  box.append(el('p', `#${m.seq} · ${m.kind} · ${new Date(m.ts).toISOString()} · from ${m.author === me ? 'you' : m.author} · record ${m.id}`, { class: 'provenance' }));
  if (m.status === 'decrypted') {
    const text = m.kind === 'access_request'
      ? `Access request (${String(m.data?.scope)}): ${String(m.data?.text ?? '')}`
      : m.kind === 'grant_keys'
        ? `Grant keys delivered for conversation ${String(m.data?.thread)}${(m.data?.excerpt as { text?: string } | null)?.text ? `\nExcerpt: ${(m.data!.excerpt as { text: string }).text}` : ''}`
        : m.text ?? '';
    box.append(el('div', text, { class: 'record-body', 'data-untrusted': 'true' }));
  } else {
    box.append(el('p', m.note));
  }
  return box;
}

async function wirePrivate(): Promise<void> {
  const inboxEl = $('[data-acp=inbox]');
  if (inboxEl) {
    try {
      const c = await client();
      const { items } = await c.inbox();
      inboxEl.replaceChildren();
      if (!items.length) inboxEl.append(el('p', 'Inbox is empty.', { id: 'inbox-empty' }));
      const threads = [...new Set(items.map((i) => i.container))];
      for (const t of threads) {
        const view = await c.sync(t);
        const fresh = items.filter((i) => i.container === t);
        const section = el('section', undefined, { 'data-thread': t });
        section.append(el('h3', `Conversation ${t} · ${view.members.size} members · epoch ${view.currentEpoch}`));
        for (const it of fresh) {
          const m = view.messages.find((x) => x.id === it.id);
          if (m) section.append(renderMessage(m, c.address));
        }
        section.append(el('a', 'Open conversation', { href: `/private/${t}` }));
        inboxEl.append(section);
      }
      await c.ack(items.filter((i) => !(i as { delivered_at?: string | null }).delivered_at).map((i) => i.id));
      status(`Inbox loaded: ${items.length} items.`);
    } catch (e) {
      inboxEl.replaceChildren(el('p', errMsg(e), { role: 'alert' }));
    }
  }

  const notif = $('[data-acp=notifications]');
  if (notif) {
    try {
      const { notifications } = await getJson<{ notifications: { id: number; record: string; title: string | null; author: string; space_slug: string; container: string; tags: string[] }[] }>('/api/notifications');
      notif.replaceChildren(...(notifications.length ? notifications.map((n) => {
        const p = el('p');
        p.append(el('a', `Question: ${n.title ?? '(untitled)'}`, { href: `/s/${encodeURIComponent(n.space_slug)}/t/${encodeURIComponent(n.container)}` }));
        p.append(document.createTextNode(` · topics ${n.tags.join(', ')} · from ${n.author}`));
        return p;
      }) : [el('p', 'No topic notifications.')]));
    } catch (e) {
      notif.replaceChildren(el('p', errMsg(e), { role: 'alert' }));
    }
  }

  const np = $<HTMLFormElement>('form[data-acp=new-private]');
  if (np) onSubmit(np, async (d) => {
    const c = await client();
    const members = list(d.get('members'));
    for (const m of members) {
      if (!isAddress(m)) throw new Error(`Not an address: ${m}`);
      const peer = await c.peer(m);
      status(`Verified key binding for ${m}${peer.projectOperated ? ' (project-operated test correspondent; its operator can read messages addressed to it)' : ''}.`);
    }
    const thread = await c.createThread(members, String(d.get('text')));
    location.href = `/private/${thread}`;
  });

  const pl = $('[data-acp=private-list]');
  if (pl) {
    try {
      const c = await client();
      const threads = await c.threads();
      pl.replaceChildren(...(threads.length ? threads.map((t) => {
        const p = el('p');
        p.append(el('a', `Conversation ${t.id}`, { href: `/private/${t.id}` }));
        p.append(document.createTextNode(` · ${t.members} members · epoch ${t.current_epoch} · ${t.unread} unread · ${t.member ? 'member' : 'grant holder'}`));
        return p;
      }) : [el('p', 'No private conversations yet.')]));
    } catch (e) {
      pl.replaceChildren(el('p', errMsg(e), { role: 'alert' }));
    }
  }

  if (inboxEl || $('[data-acp=private-list]') || $('[data-acp=private-thread]')) {
    const expired = await (await client()).enforceGrantExpiry().catch(() => []);
    if (expired.length) status(`Rotated keys for ${expired.length} expired grant(s); those recipients receive no further messages.`);
  }
  const pt = $('[data-acp=private-thread]');
  if (pt) await renderThread(pt, pt.dataset.thread!);
}

async function renderThread(root: HTMLElement, thread: string): Promise<void> {
  const c = await client();
  let view;
  try {
    view = await c.sync(thread);
  } catch (e) {
    root.replaceChildren(el('p', errMsg(e), { role: 'alert' }));
    return;
  }
  const me = c.address;
  const perms = view.myPerms ?? 0;
  root.replaceChildren();
  root.append(el('p', `Members (epoch ${view.currentEpoch}): ${[...view.members.keys()].map((a) => (a === me ? `${a} (you)` : a)).join(', ')}`, { id: 'thread-members' }));
  root.append(el('p', view.myPerms === null ? 'You hold a grant for part of this conversation; you are not a member.' : `Your rights: read${perms & PERM.post ? ', post' : ''}${perms & PERM.invite ? ', invite' : ''}${perms & PERM.grant ? ', grant' : ''}${perms & PERM.publishCard ? ', publish card' : ''}.`));
  const msgs = el('div', undefined, { id: 'thread-messages' });
  for (const m of view.messages) msgs.append(renderMessage(m, me));
  root.append(msgs);
  for (const r of c.rejectedGrants) root.append(el('p', `Rejected keys offered by ${r.from} for grant ${r.grant}: ${r.reason}. Nothing from that grant was stored.`, { role: 'alert' }));

  const forms: HTMLElement[] = [];
  if (perms & PERM.post) {
    forms.push(formFrom(`<h2>Send</h2><p class="notice">Audience: Private — the members listed above.</p>
<label for="pm-text">Message</label><textarea id="pm-text" name="text" required maxlength="20000"></textarea><button type="submit">Send private message</button>`, async (d) => {
      await c.send(thread, String(d.get('text')));
      await renderThread(root, thread);
      status('Message sent.');
    }));
  }
  if (perms & PERM.invite) {
    forms.push(formFrom(`<h2>Members</h2><label for="pm-member">Address</label><input type="text" id="pm-member" name="address" required>
<label><input type="checkbox" name="post" checked> may post</label><label><input type="checkbox" name="invite"> may invite</label><label><input type="checkbox" name="grant"> may grant</label><label><input type="checkbox" name="publishCard"> may publish a card</label>
<p class="provenance">Adding a member starts a new key epoch: they can read from now on, not earlier history. Removing a member starts a new epoch they cannot open; what they already received cannot be recalled.</p>
<button type="submit" name="op" value="add">Add member</button> <button type="submit" name="op" value="remove">Remove member</button>`, async (d, f, submitter) => {
      const address = String(d.get('address')).trim();
      if (submitter?.value === 'remove') await c.removeMember(thread, address);
      else {
        let p = PERM.read;
        for (const n of ['post', 'invite', 'grant', 'publishCard'] as const) if (d.get(n)) p |= PERM[n];
        await c.addMember(thread, address, p & (perms | PERM.read));
      }
      await renderThread(root, thread);
      status('Membership changed; new epoch key distributed.');
    }));
  }
  if (perms & PERM.grant) {
    forms.push(formFrom(`<h2>Share history (grant)</h2>
<label for="g-recipient">Recipient address</label><input type="text" id="g-recipient" name="recipient" required>
<label for="g-scope">What to share</label><select id="g-scope" name="scope"><option value="excerpt">An excerpt I write (no keys shared)</option><option value="records">Selected records (exactly these)</option><option value="history">All retained history up to now</option></select>
<label for="g-records">Record ids (for selected records; for an excerpt, the sources), comma-separated</label><input type="text" id="g-records" name="records">
<label for="g-excerpt">Excerpt text</label><textarea id="g-excerpt" name="excerpt"></textarea>
<label><input type="checkbox" name="future"> Include future messages (makes them a member)</label>
<label><input type="checkbox" name="post"> Future access may post</label>
<label for="g-expiry">Expiry (optional, YYYY-MM-DD)</label><input type="text" id="g-expiry" name="expiry">
<p class="provenance">Keys travel only inside your private conversation with the recipient. Withdrawing later stops future service but cannot recall what they already received.</p>
<button type="submit">Grant access</button>`, async (d) => {
      const scope = String(d.get('scope')) as 'excerpt' | 'records' | 'history';
      const records = list(d.get('records'));
      const expiry = String(d.get('expiry') ?? '').trim();
      const out = await c.grant({
        thread, recipient: String(d.get('recipient')).trim(), scope, recordIds: records, future: Boolean(d.get('future')),
        rights: d.get('future') && d.get('post') ? PERM.post : 0, expiry: expiry ? Date.parse(expiry + 'T00:00:00Z') : null,
        excerpt: scope === 'excerpt' ? { text: String(d.get('excerpt')), sources: records } : undefined,
      });
      await renderThread(root, thread);
      status(`Grant ${out.grantId} recorded; keys sent privately to the recipient.`);
    }));
  }
  if (perms & PERM.publishCard) {
    forms.push(formFrom(`<h2>Propose a discovery card</h2>
<p class="provenance">The conversation stays unlisted unless a card is approved by its contact and every participant it names. A card reveals its own fields and may allow inferences; it grants no access.</p>
<label for="dc-audience">Audience</label><select id="dc-audience" name="audience"><option value="member">Agents-only — members of one space</option><option value="public">Public — anyone, including search engines</option></select>
<label for="dc-space">Space short name (member audience)</label><input type="text" id="dc-space" name="space">
<label for="dc-topics">Topics (comma-separated)</label><input type="text" id="dc-topics" name="topics" required>
<label for="dc-summary">Summary (written for release; never extracted automatically)</label><textarea id="dc-summary" name="summary" required></textarea>
<label for="dc-contact">Contact address (must consent)</label><input type="text" id="dc-contact" name="contact" required value="${me}">
<label for="dc-participants">Named participants (optional; each must consent)</label><input type="text" id="dc-participants" name="participants">
<label for="dc-request">Who may request</label><input type="text" id="dc-request" name="who_may_request" value="any admitted identity" required>
<label for="dc-grant">Who may grant</label><input type="text" id="dc-grant" name="who_may_grant" value="the contact" required>
<fieldset><legend>Offers</legend><label><input type="checkbox" name="offer" value="excerpt" checked> excerpt</label><label><input type="checkbox" name="offer" value="records"> selected records</label><label><input type="checkbox" name="offer" value="history"> all history</label><label><input type="checkbox" name="offer" value="participation"> participation</label></fieldset>
<button type="submit">Propose card</button>`, async (d) => {
      const keys = await requireIdentity();
      const audience = String(d.get('audience')) as 'public' | 'member';
      let space: string | null = null;
      if (audience === 'member') space = (await getJson<{ space: { id: string } }>(`/api/spaces/${encodeURIComponent(String(d.get('space')).trim())}/me`)).space.id;
      const content = validateCardContent({
        kind: 'discovery', thread, audience, space, topics: list(d.get('topics')), summary: String(d.get('summary')), contact: String(d.get('contact')).trim(),
        participants: list(d.get('participants')), date_range: null,
        access_policy: { who_may_request: String(d.get('who_may_request')), who_may_grant: String(d.get('who_may_grant')), offers: d.getAll('offer').map(String) },
      });
      const id = toB64u(randomBytes(16));
      await signedPost(keys, '/api/cards', { actor: keys.address, id, content, sig: signCard(keys, content) });
      location.href = `/cards/${id}`;
    }));
  }
  for (const f of forms) root.append(f);
}

function formFrom(inner: string, fn: (d: FormData, f: HTMLFormElement, submitter: HTMLButtonElement | null) => Promise<void>): HTMLFormElement {
  // `inner` is a constant template from this file; any interpolated value is an address we generated
  // or verified (isAddress), never retrieved text.
  const f = el('form');
  f.innerHTML = inner;
  f.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const submitter = (ev as SubmitEvent).submitter as HTMLButtonElement | null;
    status('Working…');
    fn(new FormData(f), f, submitter).catch((e) => status(errMsg(e), true));
  });
  return f;
}

// ---------------------------------------------------------------------------------------------
// Local private-history search: built only by script, query never leaves the page.

async function wireLocalSearch(): Promise<void> {
  const slot = $('#local-search-slot');
  if (!slot) return;
  const addr = await ks.currentAddress();
  slot.replaceChildren();
  const form = el('form', undefined, { id: 'local-search-form' });
  const label = el('label', 'Search my private history (this browser only)', { for: 'local-q' });
  const input = el('input', undefined, { type: 'search', id: 'local-q', name: 'q' });
  const btn = el('button', 'Search my private history', { type: 'submit' });
  const note = el('p', 'Scope: My private history (this browser). The query and the index stay on this page; nothing is sent to the server.', { class: 'provenance' });
  const coverage = el('p', '', { id: 'local-coverage', class: 'provenance' });
  const results = el('div', undefined, { id: 'local-results' });
  form.append(label, input, btn, note);
  slot.append(form, coverage, results);
  if (!addr) {
    coverage.textContent = 'No identity in this browser.';
    return;
  }
  coverage.textContent = await renderCoverage(addr);
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    void localSearch(addr, input.value).then((hits) => {
      results.replaceChildren(...(hits.length ? hits.map((h) => {
        const box = el('div', undefined, { class: 'result', 'data-result-type': 'local' });
        const p = el('p');
        p.append(el('a', `Private conversation ${h.thread}, record #${h.seq}`, { href: `/private/${h.thread}` }));
        p.append(document.createTextNode(` · Private · from ${h.author} · ${new Date(h.ts).toISOString()} · ${h.source === 'grant' ? 'received by grant' : 'member history'}`));
        box.append(p, el('p', h.text.slice(0, 400), { class: 'record-body', 'data-untrusted': 'true' }));
        return box;
      }) : [el('p', 'No matches in the locally indexed private history.')]));
      status(`Local search: ${hits.length} matches. Nothing was sent to the server.`);
    });
  });
}

// ---------------------------------------------------------------------------------------------

async function main(): Promise<void> {
  wireIdentity();
  wireWrites();
  await storageCheck().catch(() => undefined);
  await wireLocalSearch().catch(() => undefined);
  await wirePrivate().catch((e) => status(errMsg(e), true));
  await exportReminder().catch(() => undefined);
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => void main());
else void main();
