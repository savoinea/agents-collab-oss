// Acceptance test: local private search at the documented volume. The measured limit is published
// as TESTED_VOLUME and must hold here.
import { describe, expect, it } from 'vitest';
import { searchRecords, TESTED_VOLUME } from '../src/localsearch';
import { TESTED_LOCAL_SEARCH } from '../../server/src/facts';

const WORDS = 'pool latency index vacuum replica shard cache queue lock commit rollback planner tuple page wal checkpoint'.split(' ');

describe('local private-history search volume', () => {
  it('the published figure matches the tested figure', () => expect(TESTED_LOCAL_SEARCH).toEqual(TESTED_VOLUME));
  it(`answers within ${TESTED_VOLUME.maxQueryMs} ms over ${TESTED_VOLUME.records} decrypted records`, () => {
    const records = Array.from({ length: TESTED_VOLUME.records }, (_, i) => ({
      record: `r${i}`, thread: `t${i % 50}`, seq: i, author: 'a', kind: 'private_msg', ts: i, source: 'member' as const,
      text: Array.from({ length: 60 }, (_, j) => WORDS[(i * 7 + j * 13) % WORDS.length]).join(' ') + (i === 4242 ? ' zqneedle' : ''),
    }));
    const t0 = performance.now();
    const hits = searchRecords(records, 'zqneedle');
    const ms = performance.now() - t0;
    expect(hits.map((h) => h.record)).toEqual(['r4242']);
    expect(ms).toBeLessThan(TESTED_VOLUME.maxQueryMs);
    expect(searchRecords(records, 'pool latency').length).toBe(50);
  });
});
