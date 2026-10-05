/** Validation of public/member record bodies by kind. Text is stored and rendered as data only. */
import { SIZES } from '@acp/limits';
import { isAddress, type Body } from '@acp/protocol';
import { HttpError } from './security';

export interface ParsedContent {
  title: string | null;
  text: string | null;
  tags: string[];
  acl: { address: string; perms: number }[] | null;
}

const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/;

function text(v: unknown, max: number, field: string, required = true): string | null {
  if (v === undefined || v === null) {
    if (required) throw new HttpError(400, `${field} is required.`, 'bad_body');
    return null;
  }
  if (typeof v !== 'string') throw new HttpError(400, `${field} must be text.`, 'bad_body');
  if (required && v.trim().length === 0) throw new HttpError(400, `${field} is required.`, 'bad_body');
  if (v.length > max) throw new HttpError(400, `${field} is longer than ${max} characters.`, 'bad_body');
  if (CONTROL.test(v)) throw new HttpError(400, `${field} contains control characters.`, 'bad_body');
  return v;
}

export function parseTags(v: unknown): string[] {
  if (v === undefined) return [];
  if (!Array.isArray(v) || v.length > 8) throw new HttpError(400, 'Tags must be a list of at most 8 topics.', 'bad_body');
  return [...new Set(v.map((t) => {
    if (typeof t !== 'string' || !/^[a-z0-9][a-z0-9 .+#-]{0,47}$/.test(t.trim().toLowerCase())) {
      throw new HttpError(400, 'Each tag must be 1-48 characters: letters, digits, space, . + # -', 'bad_body');
    }
    return t.trim().toLowerCase();
  }))];
}

function parseAcl(v: unknown): { address: string; perms: number }[] | null {
  if (v === undefined || v === null) return null;
  if (!Array.isArray(v) || v.length === 0 || v.length > 256) throw new HttpError(400, 'An access list must name 1-256 identities.', 'bad_body');
  return v.map((e) => {
    const o = e as Record<string, unknown>;
    if (!o || !isAddress(o.address) || !Number.isSafeInteger(o.perms) || (o.perms as number) < 1 || (o.perms as number) > 63) {
      throw new HttpError(400, 'Each access list entry needs an address and permission bits.', 'bad_body');
    }
    return { address: o.address, perms: o.perms as number };
  });
}

const ALLOWED_FIELDS: Record<string, string[]> = {
  thread: ['title', 'text', 'tags', 'acl'],
  question: ['title', 'text', 'tags', 'acl'],
  post: ['text'],
  wiki_rev: ['title', 'text', 'acl'],
  tombstone: ['reason'],
  audience_change: ['from', 'to', 'acl', 'disclosed'],
};

export function parseContent(kind: string, body: Body): ParsedContent {
  if (body.type !== 'json') throw new HttpError(400, 'Public and member records carry plain JSON bodies.', 'bad_body');
  const v = body.value;
  const allowed = ALLOWED_FIELDS[kind];
  if (!allowed) throw new HttpError(400, `Record kind ${kind} cannot be posted here.`, 'bad_kind');
  for (const k of Object.keys(v)) if (!allowed.includes(k)) throw new HttpError(400, `Unexpected field ${k} for ${kind}.`, 'bad_body');
  switch (kind) {
    case 'thread':
    case 'question':
      return { title: text(v.title, SIZES.maxTitleChars, 'Title'), text: text(v.text, SIZES.maxPublicTextChars, 'Text'), tags: parseTags(v.tags), acl: parseAcl(v.acl) };
    case 'post':
      return { title: null, text: text(v.text, SIZES.maxPublicTextChars, 'Text'), tags: [], acl: null };
    case 'wiki_rev':
      return { title: text(v.title, SIZES.maxTitleChars, 'Title'), text: text(v.text, SIZES.maxPublicTextChars, 'Text'), tags: [], acl: parseAcl(v.acl) };
    case 'tombstone':
      return { title: null, text: text(v.reason, 500, 'Reason', false), tags: [], acl: null };
    case 'audience_change': {
      if (!['space', 'narrowed'].includes(v.from as string) || !['space', 'narrowed'].includes(v.to as string) || v.from === v.to) {
        throw new HttpError(400, 'An audience change moves an item between its whole space and a narrowed access list.', 'bad_body');
      }
      if (typeof v.disclosed !== 'string' || v.disclosed.length > 1000) throw new HttpError(400, 'The disclosure statement is required.', 'bad_body');
      return { title: null, text: null, tags: [], acl: v.to === 'narrowed' ? parseAcl(v.acl) : null };
    }
    default:
      throw new HttpError(400, `Record kind ${kind} cannot be posted here.`, 'bad_kind');
  }
}
