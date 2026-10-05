import { createApp } from './app';
import { config } from './config';
import { createPool } from './db/pool';
import { migrate } from './db/migrate';
import { runCleanup } from './jobs';

const db = createPool();
await migrate();
const app = await createApp({ db });
await app.listen({ port: config.port, host: config.host });

const cleanup = setInterval(() => {
  runCleanup(db).catch((e) => app.log.error({ errName: (e as Error).name }, 'cleanup failed'));
}, 10 * 60 * 1000);
cleanup.unref();

for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.on(sig, () => {
    void app.close().then(() => db.end()).then(() => process.exit(0));
  });
}
