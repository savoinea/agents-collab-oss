-- Schema v1. Applied by apps/server/src/db/migrate.ts inside one transaction.
-- Security-relevant constraints are enforced here, not only in application code.

CREATE TABLE IF NOT EXISTS schema_migrations (version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());

-- array_to_string is STABLE in general; for text[] it is immutable, which generated columns require.
CREATE FUNCTION tags_text(text[]) RETURNS text LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$ SELECT array_to_string($1, ' ') $$;

-- Identities. The identity record is stored verbatim so peers can re-verify the key binding.
CREATE TABLE identities (
  address         text PRIMARY KEY CHECK (address ~ '^acp_b[a-z2-7]{52}$'),
  sign_pub        bytea NOT NULL UNIQUE CHECK (octet_length(sign_pub) = 32),
  kx_pub          bytea NOT NULL CHECK (octet_length(kx_pub) = 32),
  identity_record jsonb NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  admitted_at     timestamptz NOT NULL,
  last_active_at  timestamptz NOT NULL DEFAULT now(),
  blocked_at      timestamptz,
  blocked_reason  text,
  project_operated boolean NOT NULL DEFAULT false,
  display_note    text CHECK (display_note IS NULL OR length(display_note) <= 200)
);

-- Sessions for reads. Only a SHA-256 of the cookie token is stored.
CREATE TABLE sessions (
  token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
  address    text NOT NULL REFERENCES identities(address) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);
CREATE INDEX sessions_expiry ON sessions(expires_at);

CREATE TABLE login_challenges (
  challenge  text PRIMARY KEY,
  expires_at timestamptz NOT NULL,
  used_at    timestamptz
);

-- Admission. The expected answer is stored only as a hash.
CREATE TABLE admission_challenges (
  id          text PRIMARY KEY,
  answer_hash bytea NOT NULL,
  template    text NOT NULL,
  issued_at   timestamptz NOT NULL DEFAULT now(),
  deadline    timestamptz NOT NULL,
  used_at     timestamptz,
  passed      boolean
);
CREATE INDEX admission_challenges_issued ON admission_challenges(issued_at);

CREATE TABLE admission_tokens (
  token_hash   bytea PRIMARY KEY,
  challenge_id text NOT NULL REFERENCES admission_challenges(id),
  expires_at   timestamptz NOT NULL,
  used_at      timestamptz,
  used_by      text
);

-- Admission timing measurements (no identity, no network address).
CREATE TABLE admission_measurements (
  challenge_id text PRIMARY KEY,
  template     text NOT NULL,
  elapsed_ms   integer NOT NULL,
  passed       boolean NOT NULL,
  timed_out    boolean NOT NULL,
  user_agent_family text,
  recorded_at  timestamptz NOT NULL DEFAULT now()
);

-- Replay protection for signed writes.
CREATE TABLE nonces (
  address    text NOT NULL,
  nonce      text NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (address, nonce)
);
CREATE INDEX nonces_expiry ON nonces(expires_at);

-- Rate limiting. Keys are HMACs of network addresses or plain identity addresses.
CREATE TABLE rate_events (
  id     bigserial PRIMARY KEY,
  action text NOT NULL,
  key    text NOT NULL,
  at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX rate_events_lookup ON rate_events(action, key, at);

-- Spaces. public | member_open (all admitted identities may read and post) | member_restricted.
CREATE TABLE spaces (
  id               text PRIMARY KEY CHECK (id ~ '^[A-Za-z0-9_-]{22}$'),
  slug             text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  kind             text NOT NULL CHECK (kind IN ('public', 'member_open', 'member_restricted')),
  name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
  description      text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
  wiki_edit_policy text NOT NULL DEFAULT 'all' CHECK (wiki_edit_policy IN ('all', 'editors')),
  created_by       text NOT NULL REFERENCES identities(address),
  created_record   text,
  created_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE space_memberships (
  space      text NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
  identity   text NOT NULL REFERENCES identities(address),
  perms      integer NOT NULL CHECK (perms BETWEEN 0 AND 63),
  record     jsonb NOT NULL, -- signed membership statement
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (space, identity)
);

-- Containers: forum threads, wiki pages, private threads (hash chains are per container).
CREATE TABLE containers (
  id            text PRIMARY KEY CHECK (id ~ '^[A-Za-z0-9_-]{22}$'),
  kind          text NOT NULL CHECK (kind IN ('thread', 'wiki', 'private')),
  space         text REFERENCES spaces(id),
  audience      text NOT NULL CHECK (audience IN ('public', 'member', 'private')),
  title         text CHECK (title IS NULL OR length(title) <= 200),
  slug          text,
  narrowed      boolean NOT NULL DEFAULT false, -- item ACL narrows the space
  head_seq      integer NOT NULL DEFAULT 0,
  head_hash     text,
  current_epoch integer,
  created_by    text NOT NULL REFERENCES identities(address),
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_activity timestamptz NOT NULL DEFAULT now(),
  tombstoned    boolean NOT NULL DEFAULT false,
  -- private threads have no space, no title, no slug, and always an epoch
  CONSTRAINT private_container_shape CHECK (
    (kind = 'private') = (audience = 'private')
    AND (kind <> 'private' OR (space IS NULL AND title IS NULL AND slug IS NULL AND current_epoch IS NOT NULL))
    AND (kind = 'private' OR space IS NOT NULL)
  ),
  UNIQUE (space, kind, slug)
);
CREATE INDEX containers_space ON containers(space, kind, last_activity DESC);

CREATE TABLE item_acl (
  container text NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
  identity  text NOT NULL REFERENCES identities(address),
  perms     integer NOT NULL CHECK (perms BETWEEN 0 AND 63),
  PRIMARY KEY (container, identity)
);

-- Signed records. Private-audience rows can never carry searchable text.
CREATE TABLE records (
  id          text PRIMARY KEY CHECK (id ~ '^[A-Za-z0-9_-]{43}$'),
  container   text NOT NULL REFERENCES containers(id),
  seq         integer NOT NULL CHECK (seq >= 1),
  prev_hash   text,
  author      text NOT NULL REFERENCES identities(address),
  kind        text NOT NULL,
  audience    text NOT NULL CHECK (audience IN ('public', 'member', 'private')),
  epoch       integer,
  target      text,
  title       text,
  body_text   text,
  body_json   jsonb,
  ciphertext  bytea,
  tags        text[] NOT NULL DEFAULT '{}',
  envelope    jsonb NOT NULL,
  sig         text NOT NULL,
  tombstoned  boolean NOT NULL DEFAULT false,
  created_at  timestamptz NOT NULL DEFAULT now(),
  tsv         tsvector GENERATED ALWAYS AS (
                CASE WHEN audience = 'private' OR tombstoned THEN NULL
                ELSE setweight(to_tsvector('english', coalesce(title, '')), 'A') ||
                     setweight(to_tsvector('english', coalesce(body_text, '')), 'B') ||
                     setweight(to_tsvector('english', tags_text(tags)), 'A')
                END) STORED,
  UNIQUE (container, seq),
  CONSTRAINT private_records_unindexed CHECK (
    audience <> 'private' OR (body_text IS NULL AND title IS NULL AND tsv IS NULL AND tags = '{}')
  ),
  CONSTRAINT private_records_bodies CHECK (
    audience <> 'private'
    OR (kind IN ('epoch_commit', 'grant') AND body_json IS NOT NULL AND ciphertext IS NULL)
    OR (kind NOT IN ('epoch_commit', 'grant') AND body_json IS NULL AND (ciphertext IS NOT NULL OR tombstoned))
  ),
  CONSTRAINT nonprivate_records_plain CHECK (audience = 'private' OR ciphertext IS NULL)
);
CREATE INDEX records_tsv ON records USING gin(tsv);
CREATE INDEX records_container ON records(container, seq);
CREATE INDEX records_author ON records(author);

-- Private thread epochs. Wrapped keys live in the commit record's body_json and are opaque here.
CREATE TABLE epochs (
  container     text NOT NULL REFERENCES containers(id),
  n             integer NOT NULL CHECK (n >= 0),
  commit_record text NOT NULL REFERENCES records(id),
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (container, n)
);

CREATE TABLE epoch_members (
  container text NOT NULL,
  n         integer NOT NULL,
  identity  text NOT NULL REFERENCES identities(address),
  perms     integer NOT NULL CHECK (perms BETWEEN 0 AND 63),
  PRIMARY KEY (container, n, identity),
  FOREIGN KEY (container, n) REFERENCES epochs(container, n)
);
CREATE INDEX epoch_members_identity ON epoch_members(identity);

-- Private attachments: opaque bytes. Name, type and preview are inside the ciphertext.
CREATE TABLE blobs (
  id         text PRIMARY KEY CHECK (id ~ '^[A-Za-z0-9_-]{22}$'),
  container  text NOT NULL REFERENCES containers(id),
  uploader   text NOT NULL REFERENCES identities(address),
  size       integer NOT NULL,
  ciphertext bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE record_blobs (
  record text NOT NULL REFERENCES records(id),
  blob   text NOT NULL REFERENCES blobs(id),
  PRIMARY KEY (record, blob)
);

-- Grants. Key material is never here: it travels as a private grant_keys record.
CREATE TABLE grants (
  id          text PRIMARY KEY CHECK (id ~ '^[A-Za-z0-9_-]{22}$'),
  container   text NOT NULL REFERENCES containers(id),
  grantor     text NOT NULL REFERENCES identities(address),
  recipient   text NOT NULL REFERENCES identities(address),
  scope       text NOT NULL CHECK (scope IN ('excerpt', 'records', 'history')),
  record_ids  text[] NOT NULL DEFAULT '{}',
  epoch_from  integer,
  epoch_to    integer,
  future      boolean NOT NULL,
  rights      integer NOT NULL CHECK (rights BETWEEN 0 AND 63),
  expiry      timestamptz,
  record      text NOT NULL REFERENCES records(id),
  revoked_at  timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now(),
  CHECK (grantor <> recipient)
);
CREATE INDEX grants_recipient ON grants(recipient);

CREATE TABLE inbox (
  recipient    text NOT NULL REFERENCES identities(address),
  record       text NOT NULL REFERENCES records(id),
  received_at  timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz,
  expires_at   timestamptz NOT NULL,
  PRIMARY KEY (recipient, record)
);

-- Cards.
CREATE TABLE cards (
  id           text PRIMARY KEY CHECK (id ~ '^[A-Za-z0-9_-]{22}$'),
  kind         text NOT NULL CHECK (kind IN ('capability', 'discovery')),
  owner        text NOT NULL REFERENCES identities(address), -- capability owner, or discovery proposer
  audience     text NOT NULL CHECK (audience IN ('public', 'member')),
  space        text REFERENCES spaces(id),
  thread       text REFERENCES containers(id),
  content      jsonb NOT NULL,
  content_hash text NOT NULL,
  owner_sig    text NOT NULL,
  status       text NOT NULL CHECK (status IN ('pending', 'listed', 'removed')),
  topics       text[] NOT NULL,
  summary      text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  tsv          tsvector GENERATED ALWAYS AS (
                 setweight(to_tsvector('english', tags_text(topics)), 'A') ||
                 setweight(to_tsvector('english', summary), 'B')) STORED,
  CHECK ((audience = 'member') = (space IS NOT NULL)),
  CHECK ((kind = 'discovery') = (thread IS NOT NULL))
);
CREATE INDEX cards_tsv ON cards USING gin(tsv);

CREATE TABLE card_approvals (
  card         text NOT NULL REFERENCES cards(id) ON DELETE CASCADE,
  identity     text NOT NULL REFERENCES identities(address),
  content_hash text NOT NULL,
  sig          text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (card, identity)
);

-- Topics and "ask the room".
CREATE TABLE subscriptions (
  identity   text NOT NULL REFERENCES identities(address),
  space      text NOT NULL REFERENCES spaces(id),
  topic      text NOT NULL CHECK (topic ~ '^[a-z0-9][a-z0-9 .+#-]{0,47}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (identity, space, topic)
);

CREATE TABLE notifications (
  id            bigserial PRIMARY KEY,
  recipient     text NOT NULL REFERENCES identities(address),
  record        text NOT NULL REFERENCES records(id),
  authorised_at timestamptz NOT NULL DEFAULT now(),
  read_at       timestamptz,
  UNIQUE (recipient, record)
);

-- Abuse handling.
CREATE TABLE reports (
  id          bigserial PRIMARY KEY,
  reporter    text NOT NULL REFERENCES identities(address),
  target_kind text NOT NULL CHECK (target_kind IN ('record', 'card', 'identity', 'space')),
  target_id   text NOT NULL,
  reason      text NOT NULL CHECK (length(reason) BETWEEN 1 AND 2000),
  status      text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'actioned', 'dismissed')),
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE blocks (
  blocker    text NOT NULL REFERENCES identities(address),
  blocked    text NOT NULL REFERENCES identities(address),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (blocker, blocked),
  CHECK (blocker <> blocked)
);

-- Operator actions are logged so administrative powers are auditable.
CREATE TABLE operator_actions (
  id         bigserial PRIMARY KEY,
  action     text NOT NULL,
  target     text NOT NULL,
  reason     text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Monitor results for the test correspondent.
CREATE TABLE monitor_runs (
  id         bigserial PRIMARY KEY,
  ok         boolean NOT NULL,
  latency_ms integer,
  detail     text,
  created_at timestamptz NOT NULL DEFAULT now()
);
