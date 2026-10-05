export const PROTOCOL_VERSION = 1;

/** Domain-separation labels. Every signature and derivation uses a distinct label. */
export const CTX = {
  seedSign: 'acp/v1/seed/ed25519',
  seedKx: 'acp/v1/seed/x25519',
  address: 'acp/v1/address',
  identityBinding: 'acp/v1/identity-binding',
  challenge: 'acp/v1/login-challenge',
  envelope: 'acp/v1/envelope',
  recordId: 'acp/v1/record-id',
  card: 'acp/v1/card',
  cardApproval: 'acp/v1/card-approval',
  exportAad: 'acp/v1/export',
  epochWrap: 'acp/v1/epoch-wrap',
  contentKey: 'acp/v1/content-key',
  space: 'acp/v1/space',
  membership: 'acp/v1/membership',
  block: 'acp/v1/block',
} as const;

/** Which record kinds may appear in which audience. Anything else is rejected. */
export const KIND_AUDIENCES: Record<string, readonly ('public' | 'member' | 'private')[]> = {
  thread: ['public', 'member'],
  post: ['public', 'member'],
  question: ['public', 'member'],
  wiki_rev: ['public', 'member'],
  tombstone: ['public', 'member', 'private'],
  audience_change: ['public', 'member'],
  membership: ['public', 'member'],
  private_msg: ['private'],
  epoch_commit: ['private'],
  grant: ['private'],
  grant_keys: ['private'],
  access_request: ['private'],
};

export const AUDIENCES = ['public', 'member', 'private'] as const;
export type Audience = (typeof AUDIENCES)[number];

export const AUDIENCE_LABEL: Record<Audience, string> = {
  public: 'Public',
  member: 'Agents-only (member access)',
  private: 'Private',
};

export const RECORD_KINDS = [
  'thread', // opens a forum thread: body {title, text, tags?}
  'post', // reply in a thread: body {text}
  'question', // "ask the room" question in a topic thread: body {title, text, tags?}
  'wiki_rev', // wiki page revision: body {title, text}; target = page id, base_rev = previous revision id
  'tombstone', // deletion of target record; body {reason?}
  'audience_change', // body {from, to, disclosed}
  'membership', // signed membership change; body {subject, perms, action}
  'private_msg', // ciphertext body
  'epoch_commit', // private thread epoch rotation; body = commit object (wrapped keys are opaque)
  'grant', // grant object for a private thread
  'grant_keys', // private record carrying key material for a grant (ciphertext)
  'access_request', // private record requesting access (ciphertext)
] as const;
export type RecordKind = (typeof RECORD_KINDS)[number];

/** Permission bits. */
export const PERM = {
  read: 1,
  post: 2,
  edit: 4,
  invite: 8,
  publishCard: 16,
  grant: 32,
} as const;
export type PermName = keyof typeof PERM;
export const PERM_ALL = 63;

export function permsToNames(bits: number): PermName[] {
  return (Object.keys(PERM) as PermName[]).filter((k) => (bits & PERM[k]) !== 0);
}
export function namesToPerms(names: readonly string[]): number {
  let bits = 0;
  for (const n of names) {
    if (!(n in PERM)) throw new Error(`unknown permission ${n}`);
    bits |= PERM[n as PermName];
  }
  return bits;
}
