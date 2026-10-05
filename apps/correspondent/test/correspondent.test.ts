import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { FileStore } from '@acp/client/filestore';
import { createIdentityRecord, deriveKeys, generateSeed } from '@acp/protocol';
import { Agent, TEST_ORIGIN, TEST_PORT, setupApp } from '../../server/test/helpers';
import { createCorrespondent } from '../src/main';

let app: FastifyInstance;
let db: import('pg').Pool;

beforeAll(async () => {
  ({ app, db } = await setupApp());
  await app.listen({ port: TEST_PORT, host: '127.0.0.1' });
});
afterAll(async () => {
  await app.close();
  await db.end();
});

describe('test correspondent over real HTTP (signed requests, cookie session)', () => {
  it('a newcomer reaches the correspondent, which replies with the marker', async () => {
    const keys = deriveKeys(generateSeed());
    await db.query(
      `INSERT INTO identities(address, sign_pub, kx_pub, identity_record, admitted_at, project_operated) VALUES ($1,$2,$3,$4,now(),true)`,
      [keys.address, Buffer.from(keys.signPublic), Buffer.from(keys.kxPublic), JSON.stringify(createIdentityRecord(keys))],
    );
    const corr = createCorrespondent(TEST_ORIGIN, keys, new FileStore(join(mkdtempSync(join(tmpdir(), 'acp-corr-')), 'store.json')));
    await corr.transport.login();

    const newcomer = await new Agent(app).register();
    const peer = await newcomer.client.peer(keys.address);
    expect(peer.projectOperated).toBe(true);
    const thread = await newcomer.client.createThread([keys.address], 'marker-zq42');
    expect(await corr.tick()).toBe(1);
    const view = await newcomer.client.sync(thread);
    const reply = view.messages.find((m) => m.author === keys.address);
    expect(reply?.text).toContain('marker-zq42');
    expect(reply?.text).toContain('Its operator can read messages');
    expect(await corr.tick()).toBe(0);
  });

  it('monitor reports are accepted only from project-operated identities', async () => {
    const a = await new Agent(app).register();
    const r = await a.post('/api/monitor/report', { actor: a.address, ok: true, latency_ms: 5, detail: 'x' });
    expect(r.status).toBe(403);
    await db.query('UPDATE identities SET project_operated = true WHERE address = $1', [a.address]);
    const r2 = await a.post('/api/monitor/report', { actor: a.address, ok: true, latency_ms: 5, detail: 'x' });
    expect(r2.status).toBe(200);
    const home = await app.inject({ method: 'GET', url: '/' });
    expect(home.body).toContain('last success');
  });
});
