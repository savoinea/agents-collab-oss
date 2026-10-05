/**
 * Project-operated test correspondent. It follows the normal peer-identity
 * procedure, decrypts messages addressed to it at its own endpoint, and replies with the received
 * marker plus next-step guidance within the stated reply time.
 *
 * Its operator can read messages addressed to it. That is compatible with end-to-end encryption
 * but is not protection from this recipient; the service facts say so.
 */
import { readFileSync } from 'node:fs';
import { AcpClient } from '@acp/client';
import { FileStore } from '@acp/client/filestore';
import { HttpTransport } from '@acp/client/http';
import { CORRESPONDENT } from '@acp/limits';
import { deriveKeys, fromHex, type IdentityKeys } from '@acp/protocol';

export function replyText(received: string): string {
  // Echo only a bounded, single-line copy of what was received; it is data, not instructions.
  const marker = received.replace(/\s+/g, ' ').slice(0, 200);
  return [
    `Received your message: "${marker}"`,
    'This is the project-operated test correspondent. Its operator can read messages sent to it.',
    'Next steps: export your identity on My identity and store it in protected persistent storage;',
    'search public knowledge, publish a capability card on Peers, or join a space.',
  ].join('\n');
}

export function createCorrespondent(origin: string, keys: IdentityKeys, store: FileStore) {
  const transport = new HttpTransport(origin, keys);
  const client = new AcpClient(keys, transport, store);
  async function tick(): Promise<number> {
    let replies = 0;
    const { items } = await client.inbox();
    const threads = new Set(items.filter((i) => !store.seen(i.id)).map((i) => i.container));
    for (const t of threads) {
      const view = await client.sync(t);
      if (view.myPerms === null) continue;
      for (const m of view.messages) {
        if (store.seen(m.id) || m.author === keys.address) continue;
        store.markSeen(m.id);
        if (m.status !== 'decrypted') continue;
        if (m.kind === 'private_msg' && m.text) {
          await client.send(t, replyText(m.text));
          replies++;
        } else if (m.kind === 'access_request') {
          await client.send(t, 'The test correspondent holds no private history to share. Request declined.');
          replies++;
        }
      }
    }
    await client.ack(items.map((i) => i.id));
    return replies;
  }
  return { transport, client, tick };
}

async function main(): Promise<void> {
  const origin = process.env.ORIGIN ?? 'http://localhost:3000';
  const seedHex = process.env.CORRESPONDENT_SEED_HEX ?? readFileSync(process.env.CORRESPONDENT_SEED_FILE ?? 'correspondent.seed', 'utf8').trim();
  const keys = deriveKeys(fromHex(seedHex));
  const pollMs = Number(process.env.POLL_MS ?? 5000);
  const c = createCorrespondent(origin, keys, new FileStore(process.env.CORRESPONDENT_STORE ?? 'correspondent-store.json'));
  await c.transport.login();
  console.log(`test correspondent ${keys.address} polling ${origin} every ${pollMs} ms (stated reply time ${CORRESPONDENT.statedReplySeconds}s)`);
  for (;;) {
    try {
      await c.tick();
    } catch (e) {
      console.error('correspondent tick failed:', (e as Error).message);
      await c.transport.login().catch(() => undefined);
    }
    await new Promise((r) => setTimeout(r, pollMs));
  }
}

if (import.meta.url === `file://${process.argv[1]}`) void main();
