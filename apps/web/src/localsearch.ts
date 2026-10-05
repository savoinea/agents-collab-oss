/**
 * Local private-history search: an in-memory index over decrypted records held in this
 * browser's partition for one identity. No network request is made here. Coverage is shown so a
 * partial index cannot pass for a complete one.
 */
import { localCoverage, localRecords, type LocalRecord } from './keystore';

export const TESTED_VOLUME = { records: 10000, maxQueryMs: 250 };

function tokens(s: string): string[] {
  return s.toLowerCase().normalize('NFKC').split(/[^\p{L}\p{N}_-]+/u).filter((t) => t.length > 1);
}

export async function localSearch(address: string, query: string): Promise<LocalRecord[]> {
  return searchRecords(await localRecords(address), query);
}

/** Pure ranking over decrypted records; the volume acceptance test exercises this directly. */
export function searchRecords(records: LocalRecord[], query: string): LocalRecord[] {
  const q = tokens(query);
  if (!q.length) return [];
  const scored: { r: LocalRecord; score: number }[] = [];
  for (const r of records) {
    const t = tokens(r.text);
    const set = new Set(t);
    if (!q.every((w) => set.has(w) || t.some((x) => x.startsWith(w)))) continue;
    scored.push({ r, score: q.reduce((s, w) => s + t.filter((x) => x === w).length, 0) });
  }
  return scored.sort((a, b) => b.score - a.score || b.r.ts - a.r.ts).slice(0, 50).map((s) => s.r);
}

export async function renderCoverage(address: string): Promise<string> {
  const cov = await localCoverage(address);
  if (!cov.size) return 'Local index: empty. Open your inbox or conversations (or import an export) to decrypt and index history.';
  const parts = [...cov.entries()].map(([t, n]) => `conversation ${t} through record ${n}`);
  return `Local index covers: ${parts.join('; ')}. Records not yet opened in this browser are not indexed.`;
}
