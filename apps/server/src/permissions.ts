/**
 * Permission predicates are joined into every query that can reveal a member item: search,
 * counts, suggestions, direct links, exports, previews, and notifications. Nothing is filtered
 * after the query. An unreadable item and a nonexistent item produce the same response.
 *
 * Space kinds:
 *   public            — items are Public; every admitted identity may post.
 *   member_open       — items are Agents-only; every admitted identity may read and post.
 *   member_restricted — items are Agents-only; only explicit members (space_memberships).
 * An item in a member space may narrow its audience with item_acl; then only listed identities
 * have access to it, whatever the space allows.
 */
import { PERM, PERM_ALL } from '@acp/protocol';
import type { Db } from './db/pool';

/**
 * SQL predicate: "viewer may read container c (joined with space s)". The viewer address is
 * bound as the parameter named by `viewerParam` (NULL for logged-out readers).
 */
export function readableContainer(viewerParam: string, c = 'c', s = 's'): string {
  return `(
    ${c}.tombstoned = false AND ${c}.kind <> 'private' AND (
      (${c}.audience = 'public' AND ${s}.kind = 'public' AND NOT ${c}.narrowed)
      OR (${c}.audience = 'member' AND ${viewerParam}::text IS NOT NULL
        -- narrowing only ever restricts: the viewer must be able to read the space in every case
        AND (${s}.kind = 'member_open'
             OR EXISTS (SELECT 1 FROM space_memberships m WHERE m.space = ${c}.space AND m.identity = ${viewerParam}::text AND (m.perms & ${PERM.read}) <> 0))
        AND (NOT ${c}.narrowed OR EXISTS (
          SELECT 1 FROM item_acl a WHERE a.container = ${c}.id AND a.identity = ${viewerParam}::text AND (a.perms & ${PERM.read}) <> 0))
      )
    )
  )`;
}

/** SQL predicate: "viewer may read space s" (to list it or its member cards). */
export function readableSpace(viewerParam: string, s = 's'): string {
  return `(
    ${s}.kind = 'public'
    OR (${viewerParam}::text IS NOT NULL AND (
      ${s}.kind = 'member_open'
      OR EXISTS (SELECT 1 FROM space_memberships m WHERE m.space = ${s}.id AND m.identity = ${viewerParam}::text AND (m.perms & ${PERM.read}) <> 0)))
  )`;
}

export interface SpaceRow {
  id: string;
  slug: string;
  kind: 'public' | 'member_open' | 'member_restricted';
  name: string;
  description: string;
  wiki_edit_policy: 'all' | 'editors';
  created_by: string;
}

export interface ContainerRow {
  id: string;
  kind: 'thread' | 'wiki' | 'private';
  space: string | null;
  audience: 'public' | 'member' | 'private';
  title: string | null;
  slug: string | null;
  narrowed: boolean;
  head_seq: number;
  head_hash: string | null;
  current_epoch: number | null;
  created_by: string;
  created_at: Date;
  last_activity: Date;
  tombstoned: boolean;
}

/** Effective permission bits of a viewer in a space (no item narrowing). */
export async function spacePerms(db: Db, viewer: string | null, space: SpaceRow): Promise<number> {
  if (!viewer) return space.kind === 'public' ? PERM.read : 0;
  const { rows } = await db.query<{ perms: number }>('SELECT perms FROM space_memberships WHERE space = $1 AND identity = $2', [space.id, viewer]);
  let perms = rows[0]?.perms ?? 0;
  if (space.kind === 'public' || space.kind === 'member_open') perms |= PERM.read | PERM.post;
  if (space.created_by === viewer) perms |= PERM_ALL;
  return perms;
}

/** Effective permission bits of a viewer on a container in a space. */
export async function containerPerms(db: Db, viewer: string | null, space: SpaceRow, container: ContainerRow): Promise<number> {
  if (container.tombstoned) return 0;
  if (container.narrowed) {
    if (!viewer) return 0;
    // An access list narrows the space: it never grants more than the space allows.
    const inSpace = await spacePerms(db, viewer, space);
    if ((inSpace & PERM.read) === 0) return 0;
    const { rows } = await db.query<{ perms: number }>('SELECT perms FROM item_acl WHERE container = $1 AND identity = $2', [container.id, viewer]);
    return (rows[0]?.perms ?? 0) & (inSpace | PERM.edit);
  }
  let perms = await spacePerms(db, viewer, space);
  if (container.kind === 'wiki' && viewer && space.wiki_edit_policy === 'all' && (perms & PERM.post) !== 0) perms |= PERM.edit;
  // Authors may always edit (revise or tombstone) their own records; checked per record elsewhere.
  return perms;
}

export const has = (perms: number, bit: number): boolean => (perms & bit) !== 0;
