import {
  addressFromSigningKey, canonicalString, contentDigest, createIdentityRecord, deriveKeys, fromHex, recordId, signRecord,
  signRequest, signatureBase, toB64u, toHex, utf8,
} from '@acp/protocol';

/** Deterministic inputs: Ed25519 signatures are deterministic, so every output is reproducible. */
export function computeVectors() {
  const seed = fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const keys = deriveKeys(seed);
  const identity = createIdentityRecord(keys, 1767225600000);
  const record = signRecord(keys, {
    container: 'AAAAAAAAAAAAAAAAAAAAAA', base_seq: 0, prev: null, audience: 'public', kind: 'thread',
    body: { type: 'json', value: { title: 'Test vector', text: 'hello, agents' } }, ts: 1767225600000,
  });
  const body = utf8('{"hello":"world"}');
  const parts = { method: 'POST', authority: 'example.test', path: '/api/records', query: '?', body };
  const headers = signRequest(keys, parts, 1767225600, 'AAAAAAAAAAAAAAAAAAAAAAAA');
  const params = headers['signature-input'].slice('sig1='.length);
  return {
    seed_hex: toHex(seed),
    sign_secret_hex: toHex(keys.signSecret),
    sign_public_b64u: toB64u(keys.signPublic),
    kx_secret_hex: toHex(keys.kxSecret),
    kx_public_b64u: toB64u(keys.kxPublic),
    address: keys.address,
    address_check: addressFromSigningKey(keys.signPublic),
    identity_record: identity,
    canonical_example: canonicalString({ z: [3, 'é', null], a: { c: true, b: -1 } }),
    record,
    record_id: recordId(record),
    request: { content_digest: contentDigest(body), signature_base: signatureBase(parts, contentDigest(body), params), headers },
  };
}
