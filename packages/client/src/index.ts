/**
 * Isomorphic Private-tier client: used by the browser bundle, the test correspondent, the
 * monitor, and the integration tests, so every one of them exercises the same protocol code.
 * Encryption and decryption happen here, at the endpoint; the transport only carries ciphertext.
 */
import {
  PERM, PERM_ALL, ProtocolError, buildCommit, checkGrantAuthority, checkGrantPlacement, contentKeyForRecord,
  decryptRecord, decryptRecordWithKey, encryptRecord, fromB64u, openCommit, randomBytes, recordId, signRecord, toB64u,
  validateCommitBody, validateGrantBody, verifyCommitChain, verifyIdentityRecord, verifyRecord,
  type Body, type CommitBody, type GrantBody, type GrantKeysPayload, type IdentityKeys, type SignedRecord, type ThreadKeyState,
  type VerifiedIdentity,
} from '@acp/protocol';

export interface Transport {
  get<T = Record<string, unknown>>(path: string): Promise<T>;
  post<T = Record<string, unknown>>(path: string, body: unknown): Promise<T>;
}

export interface LocalRecord {
  record: string;
  thread: string;
  seq: number;
  author: string;
  kind: string;
  ts: number;
  text: string;
  source: 'member' | 'grant';
}

export interface ClientStore {
  getThreadKeys(thread: string): Promise<ThreadKeyState>;
  addThreadKeys(thread: string, add: Partial<ThreadKeyState>): Promise<boolean>;
  putLocalRecord(r: LocalRecord): Promise<void>;
}

export interface ServerRecord {
  id: string;
  seq: number;
  container: string;
  author: string;
  kind: string;
  audience: string;
  epoch: number | null;
  created_at: string;
  tombstoned: boolean;
  record: SignedRecord;
  body: Body | null;
  blobs?: { id: string; size: number }[];
}

export interface DecryptedMessage {
  id: string;
  seq: number;
  author: string;
  kind: string;
  ts: number;
  epoch: number | null;
  text: string | null;
  data: Record<string, unknown> | null;
  status: 'decrypted' | 'no-key' | 'invalid' | 'metadata' | 'deleted';
  note: string;
}

export interface ThreadView {
  id: string;
  currentEpoch: number;
  headSeq: number;
  members: Map<string, number>;
  membershipHead: string | null;
  messages: DecryptedMessage[];
  myPerms: number | null;
}

const MAX_TEXT = 20000;

export class AcpClient {
  private peers = new Map<string, VerifiedIdentity & { projectOperated: boolean; blocked: boolean }>();
  /** Grant deliveries whose verification failed; shown to the user instead of silently dropped. */
  readonly rejectedGrants: { grant: string; from: string; reason: string }[] = [];

  constructor(readonly keys: IdentityKeys, readonly transport: Transport, readonly store: ClientStore) {}

  get address(): string {
    return this.keys.address;
  }

  /** Peer-identity procedure: fetch and verify the identity record offline before encrypting to it. */
  async peer(address: string): Promise<VerifiedIdentity & { projectOperated: boolean; blocked: boolean }> {
    const hit = this.peers.get(address);
    if (hit) return hit;
    const data = await this.transport.get<{ identity: unknown; project_operated: boolean; blocked: boolean }>(`/api/identities/${encodeURIComponent(address)}`);
    const v = verifyIdentityRecord(data.identity);
    if (v.address !== address) throw new ProtocolError('identity record does not match the requested address');
    // A blocked identity's keys still verify history; encrypting to it is refused in recipient().
    const out = { ...v, projectOperated: data.project_operated, blocked: data.blocked };
    this.peers.set(address, out);
    return out;
  }

  /** A peer we are about to encrypt new key material to: must not be operator-blocked. */
  async recipient(address: string) {
    const p = await this.peer(address);
    if (p.blocked) throw new ProtocolError(`${address} is blocked by the operator`);
    return p;
  }

  private async post(path: string, body: Record<string, unknown>) {
    return this.transport.post<{ id: string; seq: number; epoch: number; thread?: string }>(path, { actor: this.address, ...body });
  }

  // ------------------------------------------------------------------------------------------
  // Threads

  async createThread(memberAddresses: string[], firstText?: string, perms: number = PERM.read | PERM.post): Promise<string> {
    const unique = [...new Set(memberAddresses.filter((a) => a !== this.address))];
    const members = [{ address: this.address, perms: PERM_ALL, kxPublic: this.keys.kxPublic }];
    for (const a of unique) members.push({ address: a, perms, kxPublic: (await this.recipient(a)).kxPublic });
    const thread = toB64u(randomBytes(16));
    const { body, secret } = await buildCommit({ thread, epoch: 0, prevCommit: null, committer: this.address, members, reason: 'create' });
    const rec = signRecord(this.keys, { container: thread, base_seq: 0, prev: null, audience: 'private', kind: 'epoch_commit', epoch: 0, body: { type: 'json', value: body as unknown as Record<string, unknown> } });
    await this.post('/api/private/threads', { record: rec, body: { type: 'json', value: body } });
    await this.store.addThreadKeys(thread, { epochs: { '0': toB64u(secret) } });
    if (firstText !== undefined) await this.send(thread, firstText);
    return thread;
  }

  /** Finds an existing two-party conversation with a peer, or creates one. */
  async directThread(peer: string): Promise<string> {
    const { threads } = await this.transport.get<{ threads: { id: string; member: boolean; members: number }[] }>('/api/private/threads');
    for (const t of threads) {
      if (!t.member || t.members !== 2) continue;
      const view = await this.sync(t.id);
      if (view.members.has(peer) && view.members.has(this.address) && view.members.size === 2) return t.id;
    }
    return this.createThread([peer]);
  }

  private async head(thread: string): Promise<{ seq: number; hash: string | null; epoch: number }> {
    const data = await this.transport.get<{ thread: { current_epoch: number; head_seq: number; head_hash: string | null } }>(`/api/private/${thread}/records?after=999999999`);
    return { seq: data.thread.head_seq, hash: data.thread.head_hash, epoch: data.thread.current_epoch };
  }

  private async epochSecret(thread: string, epoch: number): Promise<Uint8Array> {
    let st = await this.store.getThreadKeys(thread);
    if (!st.epochs[String(epoch)]) {
      await this.sync(thread);
      st = await this.store.getThreadKeys(thread);
    }
    const s = st.epochs[String(epoch)];
    if (!s) throw new ProtocolError(`no key for epoch ${epoch} of this conversation`);
    return fromB64u(s);
  }

  /** Encrypts and appends a record; retries once on a moved head or a rotated epoch. */
  async sendRecord(thread: string, kind: 'private_msg' | 'access_request' | 'grant_keys', plaintext: Record<string, unknown>, blobs: string[] = []): Promise<string> {
    for (let attempt = 0; attempt < 3; attempt++) {
      const h = await this.head(thread);
      const secret = await this.epochSecret(thread, h.epoch);
      const enc = encryptRecord(secret, { thread, epoch: h.epoch, author: this.address, kind }, plaintext);
      const rec = signRecord(this.keys, { container: thread, base_seq: h.seq, prev: h.hash, audience: 'private', kind, epoch: h.epoch, body: { type: 'ciphertext', ct: enc.ct } });
      try {
        const out = await this.post(`/api/private/${thread}/records`, { record: rec, body: { type: 'ciphertext', ct: enc.ct }, blobs });
        await this.store.addThreadKeys(thread, { records: { [out.id]: toB64u(enc.contentKey) } });
        return out.id;
      } catch (e) {
        const code = (e as { code?: string }).code;
        if (code === 'stale_head' || code === 'stale_epoch') continue;
        throw e;
      }
    }
    throw new ProtocolError('the conversation kept changing; try again');
  }

  async send(thread: string, text: string): Promise<string> {
    if (typeof text !== 'string' || text.length === 0 || text.length > MAX_TEXT) throw new ProtocolError(`messages must be 1-${MAX_TEXT} characters`);
    return this.sendRecord(thread, 'private_msg', { type: 'message', text });
  }

  // ------------------------------------------------------------------------------------------
  // Membership changes (always a fresh epoch: exclusion and joining both rotate)

  async commit(thread: string, change: (members: Map<string, number>) => void, reason: CommitBody['reason']): Promise<number> {
    const view = await this.sync(thread);
    const next = new Map(view.members);
    change(next);
    const members = [];
    for (const [address, perms] of next) {
      members.push({ address, perms, kxPublic: address === this.address ? this.keys.kxPublic : (await this.recipient(address)).kxPublic });
    }
    const h = await this.head(thread);
    const epoch = h.epoch + 1;
    const { body, secret } = await buildCommit({ thread, epoch, prevCommit: view.membershipHead, committer: this.address, members, reason });
    const rec = signRecord(this.keys, { container: thread, base_seq: h.seq, prev: h.hash, audience: 'private', kind: 'epoch_commit', epoch, body: { type: 'json', value: body as unknown as Record<string, unknown> } });
    await this.post(`/api/private/${thread}/records`, { record: rec, body: { type: 'json', value: body } });
    await this.store.addThreadKeys(thread, { epochs: { [String(epoch)]: toB64u(secret) } });
    return epoch;
  }

  addMember(thread: string, address: string, perms: number) {
    return this.commit(thread, (m) => m.set(address, perms | PERM.read), 'add');
  }

  removeMember(thread: string, address: string) {
    return this.commit(thread, (m) => m.delete(address), 'remove');
  }

  rotate(thread: string) {
    return this.commit(thread, () => undefined, 'rotate');
  }

  // ------------------------------------------------------------------------------------------
  // Grants (scope model)

  async grant(params: {
    thread: string;
    recipient: string;
    scope: 'excerpt' | 'records' | 'history';
    recordIds?: string[];
    excerpt?: { text: string; sources: string[] };
    future?: boolean;
    rights?: number;
    expiry?: number | null;
  }): Promise<{ grantId: string; grantRecord: string; keysRecord: string }> {
    const future = params.future ?? false;
    const rights = params.rights ?? 0;
    await this.recipient(params.recipient);
    let view = await this.sync(params.thread);
    let epochRange: [number, number] | null = null;
    if (params.scope === 'history' && !future) {
      // Definite cutoff: rotate first, then deliver every epoch up to and including the closed one.
      await this.commit(params.thread, () => undefined, 'history_grant');
      view = await this.sync(params.thread);
      epochRange = [0, view.currentEpoch - 1];
    }
    if (future) {
      if (!view.members.has(params.recipient)) await this.addMember(params.thread, params.recipient, rights | PERM.read);
      view = await this.sync(params.thread);
      if (params.scope === 'history') epochRange = [0, view.currentEpoch];
    }
    const st = await this.store.getThreadKeys(params.thread);
    const recordKeys: Record<string, string> = {};
    if (params.scope === 'records') {
      for (const id of params.recordIds ?? []) {
        const known = st.records[id];
        if (known) { recordKeys[id] = known; continue; }
        const msg = view.messages.find((m) => m.id === id);
        if (!msg || msg.epoch === null || !st.epochs[String(msg.epoch)]) throw new ProtocolError(`no key available for record ${id}`);
        const raw = await this.rawRecord(params.thread, id);
        recordKeys[id] = toB64u(contentKeyForRecord(fromB64u(st.epochs[String(msg.epoch)]!), { thread: params.thread, epoch: msg.epoch, author: msg.author, kind: msg.kind }, (raw.body as { ct: string }).ct));
      }
    }
    const epochs: Record<string, string> = {};
    if (epochRange) {
      for (let n = epochRange[0]; n <= epochRange[1]; n++) {
        const s = st.epochs[String(n)];
        if (s) epochs[String(n)] = s;
      }
    }
    const grantId = toB64u(randomBytes(16));
    const grant: GrantBody = {
      ctx: 'acp/v1/grant', grant_id: grantId, thread: params.thread, grantor: this.address, recipient: params.recipient,
      scope: params.scope, record_ids: params.scope === 'records' ? params.recordIds ?? [] : params.scope === 'excerpt' ? params.excerpt?.sources ?? [] : [],
      epoch_range: params.scope === 'history' ? epochRange : null, future, rights, expiry: params.expiry ?? null, membership_head: view.membershipHead!,
    };
    validateGrantBody(grant);
    const h = await this.head(params.thread);
    const rec = signRecord(this.keys, { container: params.thread, base_seq: h.seq, prev: h.hash, audience: 'private', kind: 'grant', body: { type: 'json', value: grant as unknown as Record<string, unknown> } });
    const out = await this.post(`/api/private/${params.thread}/records`, { record: rec, body: { type: 'json', value: grant } });
    // Key material travels only inside the private channel with the recipient (never cards, URLs, search, logs).
    const dm = await this.directThread(params.recipient);
    const payload: GrantKeysPayload = {
      type: 'grant_keys', grant_id: grantId, grant_record: out.id, thread: params.thread, epochs, records: recordKeys,
      excerpt: params.scope === 'excerpt' ? params.excerpt ?? null : null,
    };
    const keysRecord = await this.sendRecord(dm, 'grant_keys', payload as unknown as Record<string, unknown>);
    return { grantId, grantRecord: out.id, keysRecord };
  }

  async revokeGrant(grantId: string, thread: string, recipient: string, future: boolean): Promise<void> {
    await this.post(`/api/grants/${grantId}/revoke`, {});
    if (future) {
      const view = await this.sync(thread);
      if (view.members.has(recipient)) await this.removeMember(thread, recipient);
    }
  }

  /**
   * Expiry: the server stops serving granted records at expiry, but a future-access recipient
   * is a member until a commit drops it. The grantor's client performs that rotation.
   */
  async enforceGrantExpiry(): Promise<string[]> {
    const { grants } = await this.transport.get<{ grants: { id: string; container: string; grantor: string; recipient: string; future: boolean; expiry: string | null; revoked_at: string | null }[] }>('/api/grants');
    const done: string[] = [];
    for (const g of grants) {
      if (g.grantor !== this.address || !g.future || !g.expiry || Date.parse(g.expiry) > Date.now()) continue;
      const view = await this.sync(g.container);
      if (!view.members.has(g.recipient) || ((view.myPerms ?? 0) & PERM.invite) === 0) continue;
      await this.commit(g.container, (m) => m.delete(g.recipient), 'expiry');
      done.push(g.id);
    }
    return done;
  }

  async accessRequest(contact: string, request: { scope: string; text: string; card?: string }): Promise<{ thread: string; record: string }> {
    const thread = await this.directThread(contact);
    const record = await this.sendRecord(thread, 'access_request', { type: 'access_request', scope: request.scope, text: request.text, card: request.card ?? null });
    return { thread, record };
  }

  /** Pages through the whole visible history: the server returns at most 500 records per request. */
  private async fetchAll(thread: string): Promise<{ thread: { id: string; current_epoch: number; head_seq: number }; records: ServerRecord[] }> {
    type Page = { thread: { id: string; current_epoch: number; head_seq: number }; records: ServerRecord[] };
    let page = await this.transport.get<Page>(`/api/private/${thread}/records`);
    const records = [...page.records];
    while (page.records.length === 500) {
      page = await this.transport.get<Page>(`/api/private/${thread}/records?after=${records[records.length - 1]!.seq}`);
      records.push(...page.records);
    }
    return { thread: page.thread, records };
  }

  private async rawRecord(thread: string, id: string): Promise<ServerRecord> {
    const { records } = await this.fetchAll(thread);
    const r = records.find((x) => x.id === id);
    if (!r) throw new ProtocolError('record not available');
    return r;
  }

  // ------------------------------------------------------------------------------------------
  // Sync: verify, unwrap, decrypt, index locally.

  async sync(thread: string): Promise<ThreadView> {
    const data = await this.fetchAll(thread);
    const records = data.records;
    // 1. Verify signatures of everything we received, against verified identity records.
    for (const r of records) {
      const author = await this.peer(r.author);
      try {
        verifyRecord(r.record, author.signPublic, r.body ?? undefined);
        if (recordId(r.record) !== r.id) throw new ProtocolError('record id mismatch');
      } catch {
        (r as ServerRecord & { invalid?: boolean }).invalid = true;
      }
    }
    const valid = (r: ServerRecord) => !(r as ServerRecord & { invalid?: boolean }).invalid;
    // 2. Membership chain: verify, with member keys checked against identity records.
    const commits = records.filter((r) => r.kind === 'epoch_commit' && valid(r) && r.body?.type === 'json');
    const chain = commits.map((r) => ({ record: r.record, body: (r.body as { value: unknown }).value as CommitBody }));
    for (const c of chain) validateCommitBody(c.body);
    for (const c of chain) for (const m of c.body.members) await this.peer(m.address);
    const state = chain.length ? verifyCommitChain(chain, (a) => this.peers.get(a)?.kxPublic) : null;
    // 3. Unwrap our epoch secrets (with key confirmation).
    const known = await this.store.getThreadKeys(thread);
    const newEpochs: Record<string, string> = {};
    for (const c of chain) {
      if (known.epochs[String(c.body.epoch)]) continue;
      if (!c.body.wraps.some((w) => w.to === this.address)) continue;
      const secret = await openCommit(c.body, c.record.envelope.author, { address: this.address, kxSecret: this.keys.kxSecret });
      newEpochs[String(c.body.epoch)] = toB64u(secret);
    }
    if (Object.keys(newEpochs).length) await this.store.addThreadKeys(thread, { epochs: newEpochs });
    const keys = await this.store.getThreadKeys(thread);
    const isMember = state?.members.has(this.address) ?? false;
    // 4. Decrypt messages.
    const messages: DecryptedMessage[] = [];
    for (const r of records) {
      const e = r.record.envelope;
      const base = { id: r.id, seq: r.seq, author: r.author, kind: r.kind, ts: e.ts, epoch: r.epoch };
      if (!valid(r)) { messages.push({ ...base, text: null, data: null, status: 'invalid', note: 'Signature or body check failed; not shown.' }); continue; }
      if (r.tombstoned) { messages.push({ ...base, text: null, data: null, status: 'deleted', note: 'Deleted by its author. Earlier readers may hold copies.' }); continue; }
      if (r.kind === 'epoch_commit') {
        const b = (r.body as unknown as { value: CommitBody }).value;
        messages.push({ ...base, text: null, data: { members: b.members.map((m) => m.address), reason: b.reason, epoch: b.epoch }, status: 'metadata', note: `Membership ${b.reason}: epoch ${b.epoch}, ${b.members.length} members.` });
        continue;
      }
      if (r.kind === 'grant') {
        const g = (r.body as unknown as { value: GrantBody }).value;
        messages.push({ ...base, text: null, data: g as unknown as Record<string, unknown>, status: 'metadata', note: `Grant ${g.scope} to ${g.recipient}${g.future ? ' with future access' : ''}.` });
        continue;
      }
      const ct = (r.body as { ct: string } | null)?.ct;
      if (!ct || r.epoch === null) continue;
      const ctx = { thread, epoch: r.epoch, author: r.author, kind: r.kind };
      let pt: Record<string, unknown> | null = null;
      let source: 'member' | 'grant' = 'member';
      try {
        const es = keys.epochs[String(r.epoch)];
        if (es) pt = decryptRecord(fromB64u(es), ctx, ct);
        else if (keys.records[r.id]) { pt = decryptRecordWithKey(fromB64u(keys.records[r.id]!), ctx, ct); source = 'grant'; }
      } catch {
        messages.push({ ...base, text: null, data: null, status: 'invalid', note: 'Could not be decrypted with the keys held for it.' });
        continue;
      }
      if (!pt) { messages.push({ ...base, text: null, data: null, status: 'no-key', note: 'No key held for this record.' }); continue; }
      if (!isMember && !keys.records[r.id]) source = 'grant';
      const text = typeof pt.text === 'string' ? pt.text : null;
      messages.push({ ...base, text, data: pt, status: 'decrypted', note: '' });
      if (r.kind === 'grant_keys' && r.author !== this.address) await this.acceptGrantKeys(pt as unknown as GrantKeysPayload, r.author);
      await this.store.putLocalRecord({
        record: r.id, thread, seq: r.seq, author: r.author, kind: r.kind, ts: e.ts, source,
        text: r.kind === 'grant_keys' ? `Grant keys for conversation ${(pt as { thread?: string }).thread ?? ''}` + ((pt as { excerpt?: { text?: string } }).excerpt?.text ? `\n${(pt as { excerpt: { text: string } }).excerpt.text}` : '') : r.kind === 'access_request' ? `Access request (${String(pt.scope)}): ${String(pt.text ?? '')}` : text ?? '',
      });
    }
    return {
      id: thread,
      currentEpoch: data.thread.current_epoch,
      headSeq: data.thread.head_seq,
      members: state?.members ?? new Map(),
      membershipHead: state?.head ?? null,
      messages,
      myPerms: state?.members.get(this.address) ?? null,
    };
  }

  /**
   * Accepts keys delivered for a grant only after verifying: the grant record is signed by the
   * grantor who sent the keys, lives in the thread it names, names us as recipient, and the
   * grantor held the grant right in the thread's verified membership chain.
   */
  private async acceptGrantKeys(p: GrantKeysPayload, sender: string): Promise<void> {
    if (p.type !== 'grant_keys' || typeof p.thread !== 'string') return;
    const reject = (reason: string) => {
      if (!this.rejectedGrants.some((x) => x.grant === p.grant_id)) this.rejectedGrants.push({ grant: p.grant_id, from: sender, reason });
    };
    const data = await this.fetchAll(p.thread).catch(() => null);
    if (!data) return reject('the granted conversation is not available (revoked, expired, or never granted)');
    const grantRec = data.records.find((r) => r.id === p.grant_record);
    if (!grantRec || grantRec.body?.type !== 'json') return reject('the grant record was not found');
    const grant = grantRec.body.value as unknown as GrantBody;
    try {
      validateGrantBody(grant);
      checkGrantPlacement(grantRec.record, grant);
      verifyRecord(grantRec.record, (await this.peer(grant.grantor)).signPublic, grantRec.body);
      if (grant.grantor !== sender || grant.recipient !== this.address || grant.grant_id !== p.grant_id) return reject('the grant does not match its sender or recipient');
      const commits = data.records.filter((r) => r.kind === 'epoch_commit' && r.body?.type === 'json');
      const upTo: { record: SignedRecord; body: CommitBody }[] = [];
      for (const c of commits) {
        verifyRecord(c.record, (await this.peer(c.author)).signPublic, c.body!);
        const body = (c.body as unknown as { value: CommitBody }).value;
        for (const m of body.members) await this.peer(m.address);
        upTo.push({ record: c.record, body });
        if (c.id === grant.membership_head) break;
      }
      const state = verifyCommitChain(upTo, (a) => this.peers.get(a)?.kxPublic);
      checkGrantAuthority(grant, state);
    } catch (e) {
      return reject(`verification failed: ${(e as Error).message}`);
    }
    const epochs: Record<string, string> = {};
    if (grant.scope === 'history' && grant.epoch_range) {
      for (const [n, v] of Object.entries(p.epochs ?? {})) {
        const k = Number(n);
        if (k >= grant.epoch_range[0] && k <= grant.epoch_range[1] && typeof v === 'string') epochs[n] = v;
      }
    }
    const recordsOut: Record<string, string> = {};
    if (grant.scope === 'records') {
      for (const [id, v] of Object.entries(p.records ?? {})) if (grant.record_ids.includes(id) && typeof v === 'string') recordsOut[id] = v;
    }
    await this.store.addThreadKeys(p.thread, { epochs, records: recordsOut });
    if (Object.keys(epochs).length || Object.keys(recordsOut).length) await this.sync(p.thread).catch(() => undefined);
  }

  async inbox(): Promise<{ items: ServerRecord[] }> {
    return this.transport.get<{ items: ServerRecord[] }>('/api/inbox');
  }

  async ack(records: string[]): Promise<void> {
    if (records.length) await this.post('/api/inbox/ack', { records });
  }

  async threads() {
    return (await this.transport.get<{ threads: { id: string; current_epoch: number; head_seq: number; members: number; member: boolean; unread: number; last_activity: string }[] }>('/api/private/threads')).threads;
  }
}

export { PERM, PERM_ALL };
