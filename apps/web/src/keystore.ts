/**
 * Browser key storage. Everything is partitioned by identity address so importing a
 * second identity into the same origin cannot mix histories.
 *
 * At rest, secrets and decrypted history are additionally sealed with a non-extractable AES-GCM
 * key kept in IndexedDB. That does not protect against script running in this origin or whoever
 * controls the browser profile (they are the endpoint); it keeps raw secrets out of plain storage
 * dumps.
 */
import { deriveKeys, fromB64u, toB64u, type IdentityKeys, type IdentityRecord, type ThreadKeyState } from '@acp/protocol';

const DB_NAME = 'acp-client';
const DB_VERSION = 1;

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      db.createObjectStore('meta'); // key -> value
      db.createObjectStore('identities'); // address -> { sealedSeed, identity }
      db.createObjectStore('keys'); // [address, thread] -> sealed ThreadKeyState
      db.createObjectStore('history', { keyPath: ['address', 'record'] }).createIndex('by_address', 'address');
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function tx<T>(store: string, mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const t = db.transaction(store, mode);
    const r = fn(t.objectStore(store));
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

async function sealingKey(): Promise<CryptoKey> {
  const existing = await tx<CryptoKey | undefined>('meta', 'readonly', (s) => s.get('sealing-key') as IDBRequest<CryptoKey | undefined>);
  if (existing) return existing;
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  await tx('meta', 'readwrite', (s) => s.put(key, 'sealing-key'));
  return key;
}

async function seal(data: Uint8Array): Promise<{ iv: Uint8Array; ct: ArrayBuffer }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return { iv, ct: await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource }, await sealingKey(), data as BufferSource) };
}

async function unseal(s: { iv: Uint8Array; ct: ArrayBuffer }): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: s.iv as BufferSource }, await sealingKey(), s.ct));
}

const enc = new TextEncoder();
const dec = new TextDecoder();

export async function requestPersistence(): Promise<boolean | null> {
  if (!navigator.storage?.persist) return null;
  return navigator.storage.persist();
}

export async function saveIdentity(keys: IdentityKeys, identity: IdentityRecord): Promise<void> {
  const sealedSeed = await seal(keys.seed);
  await tx('identities', 'readwrite', (s) => s.put({ sealedSeed, identity }, keys.address));
  await tx('meta', 'readwrite', (s) => s.put(keys.address, 'current'));
}

export async function currentAddress(): Promise<string | null> {
  return (await tx<string | undefined>('meta', 'readonly', (s) => s.get('current') as IDBRequest<string | undefined>)) ?? null;
}

export async function loadIdentity(address?: string): Promise<{ keys: IdentityKeys; identity: IdentityRecord } | null> {
  const addr = address ?? (await currentAddress());
  if (!addr) return null;
  const row = await tx<{ sealedSeed: { iv: Uint8Array; ct: ArrayBuffer } | null; identity: IdentityRecord } | undefined>('identities', 'readonly', (s) => s.get(addr) as IDBRequest);
  if (!row?.sealedSeed) return null;
  const seed = await unseal(row.sealedSeed);
  return { keys: deriveKeys(seed), identity: row.identity };
}

// --- Thread key state (epoch secrets and individually granted record keys) -----------------

export async function getThreadKeys(address: string, thread: string): Promise<ThreadKeyState> {
  const row = await tx<{ iv: Uint8Array; ct: ArrayBuffer } | undefined>('keys', 'readonly', (s) => s.get([address, thread]) as IDBRequest);
  if (!row) return { epochs: {}, records: {} };
  return JSON.parse(dec.decode(await unseal(row))) as ThreadKeyState;
}

export async function putThreadKeys(address: string, thread: string, state: ThreadKeyState): Promise<void> {
  const sealed = await seal(enc.encode(JSON.stringify(state)));
  await tx('keys', 'readwrite', (s) => s.put(sealed, [address, thread]));
}

/** Adds key material; returns true if anything new arrived (so the client can prompt a fresh export). */
export async function addThreadKeys(address: string, thread: string, add: Partial<ThreadKeyState>): Promise<boolean> {
  const st = await getThreadKeys(address, thread);
  let changed = false;
  for (const [n, v] of Object.entries(add.epochs ?? {})) if (st.epochs[n] !== v) { st.epochs[n] = v; changed = true; }
  for (const [r, v] of Object.entries(add.records ?? {})) if (st.records[r] !== v) { st.records[r] = v; changed = true; }
  if (changed) {
    await putThreadKeys(address, thread, st);
    await markExportStale(address);
  }
  return changed;
}

export async function allThreadKeys(address: string): Promise<Record<string, ThreadKeyState>> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const out: Record<string, ThreadKeyState> = {};
    const t = db.transaction('keys', 'readonly');
    const range = IDBKeyRange.bound([address, ''], [address, '￿']);
    const req = t.objectStore('keys').openCursor(range);
    const pending: Promise<void>[] = [];
    req.onsuccess = () => {
      const c = req.result;
      if (!c) {
        Promise.all(pending).then(() => resolve(out), reject);
        return;
      }
      const thread = (c.key as [string, string])[1];
      const value = c.value as { iv: Uint8Array; ct: ArrayBuffer };
      pending.push(unseal(value).then((b) => { out[thread] = JSON.parse(dec.decode(b)); }));
      c.continue();
    };
    req.onerror = () => reject(req.error);
  });
}

export async function importThreadKeys(address: string, history: Record<string, ThreadKeyState>): Promise<void> {
  for (const [thread, st] of Object.entries(history)) await addThreadKeys(address, thread, st);
}

// --- Export freshness ----------------------------------------------------------------------

export async function markExportStale(address: string): Promise<void> {
  await tx('meta', 'readwrite', (s) => s.put(true, `export-stale:${address}`));
}
export async function markExportFresh(address: string): Promise<void> {
  await tx('meta', 'readwrite', (s) => s.put(false, `export-stale:${address}`));
}
export async function exportIsStale(address: string): Promise<boolean> {
  const v = await tx<boolean | undefined>('meta', 'readonly', (s) => s.get(`export-stale:${address}`) as IDBRequest<boolean | undefined>);
  return v !== false;
}

// --- Local decrypted history ----------------------------------------------------------

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

export async function putLocalRecord(address: string, r: LocalRecord): Promise<void> {
  const sealed = await seal(enc.encode(JSON.stringify(r)));
  await tx('history', 'readwrite', (s) => s.put({ address, record: r.record, thread: r.thread, seq: r.seq, sealed }));
}

export async function localRecords(address: string): Promise<LocalRecord[]> {
  const rows = await tx<{ address: string; sealed: { iv: Uint8Array; ct: ArrayBuffer } }[]>('history', 'readonly', (s) => s.index('by_address').getAll(address) as IDBRequest);
  const out: LocalRecord[] = [];
  for (const row of rows) out.push(JSON.parse(dec.decode(await unseal(row.sealed))) as LocalRecord);
  return out;
}

export async function localCoverage(address: string): Promise<Map<string, number>> {
  const rows = await tx<{ thread: string; seq: number }[]>('history', 'readonly', (s) => s.index('by_address').getAll(address) as IDBRequest);
  const m = new Map<string, number>();
  for (const r of rows) m.set(r.thread, Math.max(m.get(r.thread) ?? 0, r.seq));
  return m;
}

export const b64 = { to: toB64u, from: fromB64u };
