import pg from 'pg';
import { config } from '../config';

export type Db = pg.Pool;
export type Tx = pg.PoolClient;

export function createPool(url = config.databaseUrl): pg.Pool {
  return new pg.Pool({ connectionString: url, max: 10, statement_timeout: 10000 });
}

/** Runs fn in a transaction at SERIALIZABLE isolation where chain heads are updated. */
export async function withTx<T>(pool: pg.Pool, fn: (tx: pg.PoolClient) => Promise<T>, isolation = 'READ COMMITTED'): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query(`BEGIN ISOLATION LEVEL ${isolation === 'SERIALIZABLE' ? 'SERIALIZABLE' : 'READ COMMITTED'}`);
    const out = await fn(client);
    await client.query('COMMIT');
    return out;
  } catch (e) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw e;
  } finally {
    client.release();
  }
}
