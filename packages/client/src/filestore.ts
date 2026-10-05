/** File-backed key store for project-operated Node clients. The file is created with mode 0600. */
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import type { ThreadKeyState } from '@acp/protocol';
import type { ClientStore, LocalRecord } from './index';

export class FileStore implements ClientStore {
  private data: { keys: Record<string, ThreadKeyState>; seen: Record<string, number> };

  constructor(private readonly path: string) {
    this.data = existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : { keys: {}, seen: {} };
  }

  private flush(): void {
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.data), { mode: 0o600 });
    renameSync(tmp, this.path);
  }

  async getThreadKeys(thread: string): Promise<ThreadKeyState> {
    const s = this.data.keys[thread];
    return s ? { epochs: { ...s.epochs }, records: { ...s.records } } : { epochs: {}, records: {} };
  }

  async addThreadKeys(thread: string, add: Partial<ThreadKeyState>): Promise<boolean> {
    const s = await this.getThreadKeys(thread);
    let changed = false;
    for (const [k, v] of Object.entries(add.epochs ?? {})) if (s.epochs[k] !== v) { s.epochs[k] = v; changed = true; }
    for (const [k, v] of Object.entries(add.records ?? {})) if (s.records[k] !== v) { s.records[k] = v; changed = true; }
    if (changed) {
      this.data.keys[thread] = s;
      this.flush();
    }
    return changed;
  }

  /** Project-operated clients keep no decrypted history on disk. */
  async putLocalRecord(_r: LocalRecord): Promise<void> {}

  seen(record: string): boolean {
    return (this.data.seen[record] ?? 0) > 0;
  }

  markSeen(record: string): void {
    this.data.seen[record] = Date.now();
    const cutoff = Date.now() - 7 * 86400_000;
    for (const [k, t] of Object.entries(this.data.seen)) if (t < cutoff) delete this.data.seen[k];
    this.flush();
  }
}
