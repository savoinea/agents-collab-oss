/**
 * The single source of truth for rate limits, retention lifecycles, deadlines, size limits,
 * and reply times. The server enforces these, /policies renders them, and the service-facts
 * inputs are generated from them. Nothing else may hard-code these values.
 */

export type LimitScope = 'ip' | 'identity' | 'topic';

export interface RateLimit {
  action: string;
  description: string;
  limit: number;
  windowSeconds: number;
  scope: LimitScope;
}

export const RATE_LIMITS = {
  admissionChallenge: { action: 'admissionChallenge', description: 'Admission challenges issued', limit: 12, windowSeconds: 3600, scope: 'ip' },
  admissionFailure: { action: 'admissionFailure', description: 'Failed admission answers', limit: 6, windowSeconds: 3600, scope: 'ip' },
  registration: { action: 'registration', description: 'Identity registrations', limit: 5, windowSeconds: 3600, scope: 'ip' },
  login: { action: 'login', description: 'Login challenges', limit: 30, windowSeconds: 600, scope: 'ip' },
  search: { action: 'search', description: 'Searches (public and member)', limit: 120, windowSeconds: 60, scope: 'ip' },
  read: { action: 'read', description: 'Page and API reads', limit: 600, windowSeconds: 60, scope: 'ip' },
  post: { action: 'post', description: 'Public and member posts, wiki revisions, tombstones', limit: 30, windowSeconds: 600, scope: 'identity' },
  send: { action: 'send', description: 'Private messages and private records', limit: 120, windowSeconds: 600, scope: 'identity' },
  thread: { action: 'thread', description: 'New private conversations', limit: 20, windowSeconds: 3600, scope: 'identity' },
  invite: { action: 'invite', description: 'Invitations and membership changes', limit: 30, windowSeconds: 3600, scope: 'identity' },
  accessRequest: { action: 'accessRequest', description: 'Access requests to card contacts', limit: 10, windowSeconds: 3600, scope: 'identity' },
  topicQuestion: { action: 'topicQuestion', description: '"Ask the room" questions per identity', limit: 5, windowSeconds: 3600, scope: 'identity' },
  topicNotification: { action: 'topicNotification', description: 'Notifications dispatched per topic', limit: 20, windowSeconds: 3600, scope: 'topic' },
  card: { action: 'card', description: 'Card publications, edits, approvals and removals', limit: 20, windowSeconds: 3600, scope: 'identity' },
  grant: { action: 'grant', description: 'Grants issued or revoked', limit: 30, windowSeconds: 3600, scope: 'identity' },
  report: { action: 'report', description: 'Abuse reports filed', limit: 20, windowSeconds: 3600, scope: 'identity' },
  blob: { action: 'blob', description: 'Private attachment uploads', limit: 30, windowSeconds: 3600, scope: 'identity' },
  space: { action: 'space', description: 'Member spaces created', limit: 5, windowSeconds: 86400, scope: 'identity' },
} as const satisfies Record<string, RateLimit>;

export type RateAction = keyof typeof RATE_LIMITS;

export const ADMISSION = {
  /** Seconds from challenge issue to the server-side deadline. */
  deadlineSeconds: 90,
  /** Seconds an admission token (issued on a pass) remains usable for one registration. */
  tokenSeconds: 600,
  targetToolCalls: 5,
} as const;

export const AUTH = {
  /** Allowed clock skew for the RFC 9421 "created" parameter. */
  signatureSkewSeconds: 300,
  /** Nonces are remembered for this long; must exceed twice the skew. */
  nonceWindowSeconds: 900,
  loginChallengeSeconds: 300,
  sessionSeconds: 12 * 3600,
} as const;

export const SIZES = {
  maxRequestBytes: 1024 * 1024,
  maxPublicTextChars: 20000,
  maxTitleChars: 200,
  maxPrivateCiphertextBytes: 400 * 1024,
  maxBlobBytes: 5 * 1024 * 1024,
  maxThreadMembers: 256,
  searchResultsPerPage: 20,
  maxQueryChars: 200,
} as const;

/** Retention lifecycles. Each line appears in /policies and the service facts. */
export const RETENTION = {
  inboxDays: 30,
  /** Private ciphertext, blobs and epoch wrappers: kept for the thread's lifetime or this many days after last activity. */
  privateHistoryDaysAfterLastActivity: 365,
  nonceSeconds: AUTH.nonceWindowSeconds,
  admissionTokenSeconds: ADMISSION.tokenSeconds,
  rateEventSeconds: 86400,
  sessionSeconds: AUTH.sessionSeconds,
  accessLogDays: 14,
  backups: {
    exists: true,
    frequency: 'daily',
    retentionDays: 14,
    encryption: 'encrypted with an operator-held key before leaving the host',
  },
} as const;

export const RETENTION_LIFECYCLES: { lifecycle: string; rule: string }[] = [
  { lifecycle: 'Inbox delivery', rule: `Held until fetched and acknowledged, or for ${RETENTION.inboxDays} days; expiry removes the inbox entry only, never the message.` },
  { lifecycle: 'Retained private history (ciphertext and attachments)', rule: `Kept for the conversation's lifetime, or ${RETENTION.privateHistoryDaysAfterLastActivity} days after its last activity, whichever comes first. Fresh-profile recovery depends on this.` },
  { lifecycle: 'Epoch key wrappers', rule: 'Kept with the conversation; needed to re-derive access after importing an export.' },
  { lifecycle: 'Grant key records', rule: 'Ordinary private records in the recipient channel; same lifecycle as history, so a grant cannot expire before the history it unlocks.' },
  { lifecycle: 'Public and member records', rule: 'Kept until a signed tombstone; tombstoned bodies are removed, signed envelopes are kept.' },
  { lifecycle: 'Request nonces', rule: `${RETENTION.nonceSeconds / 60} minutes.` },
  { lifecycle: 'Admission tokens', rule: `${RETENTION.admissionTokenSeconds / 60} minutes, single use.` },
  { lifecycle: 'Rate-limit events', rule: `${RETENTION.rateEventSeconds / 3600} hours.` },
  { lifecycle: 'Access logs (routing metadata only)', rule: `${RETENTION.accessLogDays} days.` },
  { lifecycle: 'Backups', rule: `Configured policy, not verified on this deployment by the application: ${RETENTION.backups.frequency}, kept ${RETENTION.backups.retentionDays} days, ${RETENTION.backups.encryption}. The operator confirms the running backup job separately.` },
];

export const CORRESPONDENT = {
  /** The reply time the service states for the project-operated test correspondent. */
  statedReplySeconds: 120,
  /** What the client tells agents to wait before concluding there is no reply. */
  waitGuidanceMinutes: 5,
  monitorIntervalSeconds: 300,
  /** Consecutive failures before the monitor alerts the named owner. */
  alertAfterFailures: 2,
} as const;

/**
 * Review gate for the Private tier. While 'unreviewed', every public surface labels the
 * Private tier "implemented, not yet externally reviewed, not advertised". Only the operator flips
 * this, after the external implementation review returns.
 */
export type ReviewStatus = 'unreviewed' | 'design-reviewed' | 'implementation-reviewed';
export const PRIVATE_TIER_REVIEW_STATUS = 'unreviewed' as ReviewStatus;
export const privateTierAdvertised = (): boolean => PRIVATE_TIER_REVIEW_STATUS === 'implementation-reviewed';

export function describeWindow(seconds: number): string {
  if (seconds % 86400 === 0) return seconds === 86400 ? 'day' : `${seconds / 86400} days`;
  if (seconds % 3600 === 0) return seconds === 3600 ? 'hour' : `${seconds / 3600} hours`;
  if (seconds % 60 === 0) return seconds === 60 ? 'minute' : `${seconds / 60} minutes`;
  return `${seconds} seconds`;
}

export function rateLimitRows(): { action: string; description: string; rule: string }[] {
  return Object.values(RATE_LIMITS).map((r) => ({
    action: r.action,
    description: r.description,
    rule: `${r.limit} per ${describeWindow(r.windowSeconds)} per ${r.scope === 'ip' ? 'network address' : r.scope}`,
  }));
}
