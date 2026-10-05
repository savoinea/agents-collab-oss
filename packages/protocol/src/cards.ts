/**
 * Capability cards (self-descriptions) and discovery cards for private threads.
 *
 * A capability card is signed by its owner alone. A discovery card is proposed by a member with
 * the publish-card right and becomes publishable only with signed approvals from the named contact
 * and every named participant. Each approval binds the hash of the card content and audience, so
 * any edit or audience widening invalidates every approval.
 */
import { ProtocolError, taggedHash, toB64u } from './bytes';
import { canonicalBytes } from './canonical';
import { CTX } from './constants';
import { isId } from './envelope';
import { isAddress, signDetached, verifyDetached, type IdentityKeys } from './identity';

export type CardAudience = 'public' | 'member';
export const CARD_OFFERS = ['excerpt', 'records', 'history', 'participation'] as const;

export interface CapabilityCardContent {
  kind: 'capability';
  owner: string;
  audience: CardAudience;
  space: string | null; // required for member audience
  topics: string[];
  summary: string;
  services: string;
  availability: string;
  contact: string; // address
}

export interface DiscoveryCardContent {
  kind: 'discovery';
  thread: string;
  audience: CardAudience;
  space: string | null;
  topics: string[];
  summary: string;
  contact: string;
  participants: string[]; // omitted (empty) by default
  date_range: string | null;
  access_policy: { who_may_request: string; who_may_grant: string; offers: (typeof CARD_OFFERS)[number][] };
}

export type CardContent = CapabilityCardContent | DiscoveryCardContent;

const TEXT_LIMITS = { topic: 48, topics: 12, summary: 1000, services: 2000, availability: 200, policy: 300, date: 40 };

function str(v: unknown, max: number, field: string, allowEmpty = false): string {
  if (typeof v !== 'string') throw new ProtocolError(`card: ${field} must be text`);
  if (!allowEmpty && v.trim().length === 0) throw new ProtocolError(`card: ${field} is required`);
  if (v.length > max) throw new ProtocolError(`card: ${field} is longer than ${max} characters`);
  // Reject control characters other than newline and tab.
  if (/[\u0000-\u0008\u000B-\u001F\u007F]/.test(v)) throw new ProtocolError(`card: ${field} contains control characters`);
  return v;
}

function topics(v: unknown): string[] {
  if (!Array.isArray(v) || v.length === 0 || v.length > TEXT_LIMITS.topics) throw new ProtocolError(`card: 1-${TEXT_LIMITS.topics} topics required`);
  return v.map((t, i) => str(t, TEXT_LIMITS.topic, `topic ${i + 1}`).trim().toLowerCase());
}

export function validateCardContent(c: unknown): CardContent {
  if (!c || typeof c !== 'object') throw new ProtocolError('card: not an object');
  const o = c as Record<string, unknown>;
  if (o.audience !== 'public' && o.audience !== 'member') throw new ProtocolError('card: audience must be public or member');
  if (o.audience === 'member' ? !isId(o.space) : o.space !== null) {
    throw new ProtocolError('card: member cards are bound to one space; public cards to none');
  }
  if (!isAddress(o.contact)) throw new ProtocolError('card: contact must be an address');
  if (o.kind === 'capability') {
    if (!isAddress(o.owner)) throw new ProtocolError('card: bad owner');
    // The contact on a self-description is the owner; naming someone else would publish them without consent.
    if (o.contact !== o.owner) throw new ProtocolError('card: a capability card\'s contact must be its owner');
    return {
      kind: 'capability',
      owner: o.owner,
      audience: o.audience,
      space: (o.space as string | null) ?? null,
      topics: topics(o.topics),
      summary: str(o.summary, TEXT_LIMITS.summary, 'summary'),
      services: str(o.services, TEXT_LIMITS.services, 'services', true),
      availability: str(o.availability, TEXT_LIMITS.availability, 'availability'),
      contact: o.contact,
    };
  }
  if (o.kind === 'discovery') {
    if (!isId(o.thread)) throw new ProtocolError('card: bad thread');
    if (!Array.isArray(o.participants) || o.participants.length > 64 || !o.participants.every(isAddress)) {
      throw new ProtocolError('card: bad participants');
    }
    const p = o.access_policy as Record<string, unknown> | undefined;
    if (!p || typeof p !== 'object') throw new ProtocolError('card: access policy required');
    if (!Array.isArray(p.offers) || !p.offers.every((x) => (CARD_OFFERS as readonly string[]).includes(x as string))) {
      throw new ProtocolError('card: bad offers');
    }
    return {
      kind: 'discovery',
      thread: o.thread,
      audience: o.audience,
      space: (o.space as string | null) ?? null,
      topics: topics(o.topics),
      summary: str(o.summary, TEXT_LIMITS.summary, 'summary'),
      contact: o.contact,
      participants: [...new Set(o.participants as string[])].sort(),
      date_range: o.date_range === null ? null : str(o.date_range, TEXT_LIMITS.date, 'date range'),
      access_policy: {
        who_may_request: str(p.who_may_request, TEXT_LIMITS.policy, 'who may request'),
        who_may_grant: str(p.who_may_grant, TEXT_LIMITS.policy, 'who may grant'),
        offers: [...new Set(p.offers as (typeof CARD_OFFERS)[number][])],
      },
    };
  }
  throw new ProtocolError('card: unknown kind');
}

/** Hash binding content and audience; approvals and the owner signature cover this value. */
export function cardHash(content: CardContent): string {
  return toB64u(taggedHash(CTX.card, canonicalBytes(content)));
}

export function signCard(keys: IdentityKeys, content: CardContent): string {
  return signDetached(keys, CTX.card, { hash: cardHash(content) });
}

export function verifyCardSignature(signPublic: Uint8Array, content: CardContent, sig: unknown): boolean {
  return verifyDetached(signPublic, CTX.card, { hash: cardHash(content) }, sig);
}

export function signCardApproval(keys: IdentityKeys, content: CardContent): string {
  return signDetached(keys, CTX.cardApproval, { hash: cardHash(content), audience: content.audience, approver: keys.address });
}

export function verifyCardApproval(signPublic: Uint8Array, approver: string, content: CardContent, sig: unknown): boolean {
  return verifyDetached(signPublic, CTX.cardApproval, { hash: cardHash(content), audience: content.audience, approver }, sig);
}

/** Addresses whose approval a discovery card requires before it may be listed. */
export function requiredApprovers(content: DiscoveryCardContent): string[] {
  return [...new Set([content.contact, ...content.participants])].sort();
}
