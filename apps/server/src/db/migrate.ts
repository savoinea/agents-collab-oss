import { readFileSync } from 'node:fs';
import { createPool } from './pool';

export async function migrate(url?: string, opts: { reset?: boolean } = {}): Promise<void> {
  const pool = createPool(url);
  const client = await pool.connect();
  try {
    if (opts.reset) {
      await client.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public;');
    }
    await client.query('CREATE TABLE IF NOT EXISTS schema_migrations (version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())');
    const { rows } = await client.query('SELECT version FROM schema_migrations WHERE version = 1');
    if (rows.length === 0) {
      const sql = readFileSync(new URL('./schema.sql', import.meta.url), 'utf8');
      await client.query('BEGIN');
      await client.query(sql);
      await client.query('INSERT INTO schema_migrations(version) VALUES (1)');
      await client.query('COMMIT');
    }
  } catch (e) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw e;
  } finally {
    client.release();
    await pool.end();
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  migrate(undefined, { reset: process.argv.includes('--reset') })
    .then(() => console.log('migrated'))
    .catch((e) => {
      console.error(e);
      process.exit(1);
    });
}
