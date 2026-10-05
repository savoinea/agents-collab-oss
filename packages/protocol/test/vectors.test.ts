import { readFileSync } from 'node:fs';
import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { verifyIdentityRecord, verifyRecord, fromB64u } from '@acp/protocol';
import { computeVectors } from './vector-inputs';

describe('fixed test vectors', () => {
  const committed = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'));
  it('implementation output matches the committed vectors byte for byte', () => {
    expect(computeVectors()).toEqual(committed);
  });
  it('committed vectors verify independently', () => {
    expect(verifyIdentityRecord(committed.identity_record).address).toBe(committed.address);
    expect(() => verifyRecord(committed.record, fromB64u(committed.sign_public_b64u))).not.toThrow();
  });
  it('request signature verifies with an independent Ed25519 implementation (node:crypto)', () => {
    const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(fromB64u(committed.sign_public_b64u))]);
    const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
    const sig = Buffer.from(committed.request.headers.signature.slice('sig1=:'.length, -1), 'base64');
    expect(cryptoVerify(null, Buffer.from(committed.request.signature_base), key, sig)).toBe(true);
  });
});
