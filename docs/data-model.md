# Data model

**Status:** Phase 0 — awaiting sign-off
**Database:** PostgreSQL 16
**Access:** EF Core 8 (Npgsql), code-first migrations

---

## Conventions

- Primary keys are `uuid` (v7 where available — time-ordered, so index locality is good
  and inserts do not fragment the B-tree the way v4 does). The two exceptions are
  `messages.seq` and `audit_log.id`, which need dense monotonic ordering and use `bigint`.
- All timestamps are `timestamptz`, stored UTC. There is no `timestamp` column anywhere in
  the schema; that ambiguity is not worth the fight later.
- Soft delete via `deleted_at` on entities with history value. Hard delete is reserved for
  retention enforcement and explicit purges.
- Ciphertext is `bytea`. Nonces and tags are stored in dedicated columns, never
  concatenated into an opaque blob — an opaque blob makes key rotation and forensic
  inspection needlessly painful.
- Every table an admin can mutate has `created_at`, `created_by`, `updated_at`,
  `updated_by`.

---

## 1. Identity

### `users`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid PK | |
| `username` | citext UNIQUE NOT NULL | login name |
| `source` | text NOT NULL | `local` \| `ad` |
| `ad_object_guid` | uuid UNIQUE | AD `objectGUID`; the stable join key |
| `ad_dn` | text | current DN, informational only — DNs move |
| `ad_upn` | citext | |
| `sam_account_name` | citext | |
| `display_name` | text NOT NULL | |
| `email` | citext | |
| `title`, `department`, `phone` | text | synced from AD, shown in directory |
| `password_hash` | text | PHC string; NULL for AD-sourced users |
| `password_updated_at` | timestamptz | |
| `must_change_password` | boolean NOT NULL DEFAULT false | |
| `status` | text NOT NULL | `active` \| `disabled` \| `locked` |
| `failed_login_count` | int NOT NULL DEFAULT 0 | |
| `lockout_until` | timestamptz | soft backoff, not permanent lockout |
| `last_login_at` | timestamptz | |
| `deleted_at` | timestamptz | |

`citext` for `username` and `email` because case-sensitive usernames are a support burden
and AD is case-insensitive anyway; making the database enforce it beats normalising in
application code and hoping every path remembers.

**Indexes:** `username` (unique), `ad_object_guid` (unique, partial `WHERE ad_object_guid
IS NOT NULL`), `status WHERE deleted_at IS NULL`, GIN trigram on `display_name` for
directory search.

### `password_history`

`(id, user_id FK, password_hash, created_at)` — enforces "no reuse of last N passwords".
Retains hashes only, capped at N rows per user.

### `groups`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid PK | |
| `name` | citext NOT NULL | unique per `parent_ou_id` |
| `description` | text | |
| `type` | text NOT NULL | `chat` \| `security` \| `distribution` |
| `source` | text NOT NULL | `local` \| `ad` |
| `ad_object_guid` | uuid UNIQUE | |
| `parent_ou_id` | uuid FK → `org_units` | |
| `status` | text NOT NULL | `active` \| `disabled` |
| `deleted_at` | timestamptz | |

### `group_members`

`(group_id, user_id)` composite PK, plus `added_at`, `added_by`, `role` (`member` |
`owner`). Moving a user between groups is a delete + insert in one transaction, both
audited.

### `org_units`

`(id, name, distinguished_name, parent_id FK self, source, ad_object_guid, deleted_at)` —
a self-referencing tree mirroring the AD OU hierarchy. Depth is bounded and shallow in
practice; recursive CTEs handle traversal without needing a closure table.

### `roles`, `permissions`, `role_permissions`, `user_roles`

Standard RBAC join tables. `roles.scope` ∈ `owner` | `server` | `client` and is enforced at
assignment time — a server-scope role cannot be granted owner-tier permissions, which
prevents privilege escalation across tiers by way of a mis-seeded row.
`permissions.key` is a stable string (`users.create`, `audit.read`, `sessions.kill`).
`roles.is_builtin` protects the seeded roles from deletion.

---

## 2. Conversations and messages

### `conversations`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid PK | |
| `type` | text NOT NULL | `direct` \| `group` |
| `group_id` | uuid FK → `groups` | set when `type = 'group'` |
| `direct_key` | text UNIQUE | sorted `"{smaller_uuid}:{larger_uuid}"` for direct chats |
| `title` | text | group conversations only |
| `created_at`, `created_by` | | |
| `last_message_at` | timestamptz | denormalised, drives conversation-list sort |
| `next_seq` | bigint NOT NULL DEFAULT 1 | sequence allocator |
| `status` | text NOT NULL | `active` \| `archived` |

`direct_key` with a unique constraint is what makes "open a chat with Bob" idempotent under
concurrency: two clients racing to create the same 1:1 conversation cannot produce two
rows, because the database refuses the second. Doing this check in application code would
be a race.

`next_seq` is allocated with `UPDATE … RETURNING` inside the message-insert transaction,
which serialises sequence allocation per conversation without a global lock. Contention is
per-conversation and therefore negligible.

### `conversation_participants`

| Column | Type | Notes |
| --- | --- | --- |
| `conversation_id`, `user_id` | uuid, composite PK | |
| `joined_at`, `left_at` | timestamptz | `left_at` preserves history for departed members |
| `last_read_seq` | bigint NOT NULL DEFAULT 0 | drives unread counts |
| `notification_pref` | text | `all` \| `mentions` \| `none` |
| `is_muted` | boolean | |

**Index:** `(user_id) WHERE left_at IS NULL` — the hot path for "my conversations".

### `messages`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid PK | |
| `conversation_id` | uuid FK NOT NULL | |
| `seq` | bigint NOT NULL | monotonic within conversation |
| `sender_id` | uuid FK → `users` | |
| `client_message_id` | uuid NOT NULL | idempotency key from the client |
| `content_type` | text NOT NULL | `text` \| `file` \| `system` |
| `ciphertext` | bytea NOT NULL | AES-256-GCM |
| `nonce` | bytea(12) NOT NULL | |
| `auth_tag` | bytea(16) NOT NULL | |
| `key_id` | uuid FK → `conversation_keys` | |
| `aad_version` | smallint NOT NULL | AAD construction version |
| `sent_at` | timestamptz NOT NULL | client-claimed, display only |
| `server_received_at` | timestamptz NOT NULL | authoritative for ordering |
| `edited_at`, `deleted_at` | timestamptz | |
| `search_tsv` | tsvector | see below |

**Indexes:**
- `(conversation_id, seq)` unique — the primary read path, and the ordering guarantee.
- `(conversation_id, sender_id, client_message_id)` unique — makes retries idempotent.
- `(conversation_id, server_received_at DESC)` — recent-history pagination.
- GIN on `search_tsv`.

**Search, and an honest note about it.** Message bodies are encrypted at rest, and
encrypted text is not searchable. Full-text search therefore requires a plaintext-derived
index — `search_tsv` — which materially weakens the at-rest protection: an attacker with
database read access can recover a great deal from a tsvector even without the ciphertext.
Three options, and this needs an explicit decision at Phase 1:

1. **Server-side plaintext tsvector** (proposed default). Best search quality. Accepts that
   the search index is roughly as sensitive as the messages.
2. **Client-side search over locally cached history only.** No server index at all;
   strongest at-rest posture; search covers only what the client has synced.
3. **Blind/deterministic keyword index.** Keyword hashes rather than plaintext. Resists
   casual dumping but is vulnerable to frequency analysis, and it breaks stemming, prefix
   matching, and phrase search.

Option 1 is consistent with the confirmed "admin-recoverable, compliance-first" model — if
an admin can already export all history, a search index is not the weak link. It is called
out here rather than buried because it is exactly the kind of decision that should not be
made silently.

### `message_recipients`

| Column | Type | Notes |
| --- | --- | --- |
| `message_id`, `user_id` | composite PK | |
| `state` | text NOT NULL | `pending` \| `delivered` \| `read` |
| `delivered_at`, `read_at` | timestamptz | |

**Index:** `(user_id, state) WHERE state = 'pending'` — partial, so the store-and-forward
backlog query touches only genuinely undelivered rows. This table is the largest in the
schema (participants × messages); the partial index keeps the hot query cheap regardless
of total size.

### `conversation_keys`

`(id, conversation_id, version, wrapped_dek bytea, kek_id, algorithm, created_at,
retired_at, message_count)`. Unique on `(conversation_id, version)`. `message_count` drives
the rotation trigger described in the architecture doc.

---

## 3. Files

### `files`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid PK | |
| `conversation_id`, `message_id` | uuid FK | |
| `uploader_id` | uuid FK | |
| `file_name` | text NOT NULL | stored as given, **never** used to build a path |
| `content_type` | text | client-declared, treated as untrusted |
| `size_bytes` | bigint NOT NULL | |
| `sha256_plaintext` | bytea(32) NOT NULL | integrity + duplicate detection |
| `storage_key` | text NOT NULL | server-generated opaque key |
| `wrapped_dek` | bytea NOT NULL | |
| `kek_id` | uuid | |
| `nonce_prefix` | bytea(4) NOT NULL | chunk nonce = prefix ‖ counter |
| `chunk_size`, `chunk_count` | int | |
| `chunk_manifest` | bytea NOT NULL | digests of every chunk |
| `upload_state` | text NOT NULL | `pending` \| `complete` \| `failed` \| `expired` |
| `av_state` | text NOT NULL | `not_scanned` \| `scanning` \| `clean` \| `infected` \| `error` |
| `av_detail` | text | |
| `expires_at`, `deleted_at` | timestamptz | |

`storage_key` is server-generated and the on-disk path is derived only from it — the
user-supplied `file_name` never touches the filesystem path. Path traversal via a crafted
filename is thereby structurally impossible rather than filtered.

### `file_chunks`

`(file_id, chunk_index)` composite PK, plus `byte_length`, `auth_tag`, `received_at`.
Present so resumable uploads know exactly which chunks landed, and so a partial upload can
be resumed rather than restarted.

---

## 4. Sessions, devices, presence

### `sessions`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid PK | |
| `user_id` | uuid FK | |
| `token_hash` | bytea(32) UNIQUE NOT NULL | SHA-256 of the bearer token |
| `device_id` | uuid FK → `devices` | |
| `ip_address` | inet | |
| `auth_method` | text | `kerberos` \| `ntlm` \| `password` |
| `created_at`, `last_activity_at`, `expires_at` | timestamptz | |
| `revoked_at` | timestamptz | |
| `revoke_reason` | text | `logout` \| `idle` \| `admin` \| `password_change` \| `license` \| `deactivated` |

Only the hash is stored, so a database compromise does not yield replayable sessions.

**Index:** `(user_id) WHERE revoked_at IS NULL AND expires_at > now()` — this is the exact
query the license concurrent-session check runs on every login, so it must be an index
lookup, not a scan.

### `devices`

`(id, user_id, fingerprint UNIQUE, name, os_version, app_version, first_seen_at,
last_seen_at, is_blocked)`. Enables "sign out my other machines" and blocking a lost device.

### `presence`

`(user_id PK, status, status_message, changed_at, is_auto_away, updated_at)`. Authoritative
copy is in memory; this table is the restart-recovery mirror and the source for offline
users' last-known state.

---

## 5. Audit

### `audit_log`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | bigserial PK | dense, monotonic — the chain order |
| `occurred_at` | timestamptz NOT NULL | |
| `actor_user_id` | uuid | NULL for system actions |
| `actor_tier` | text | `owner` \| `admin` \| `client` \| `system` |
| `actor_ip` | inet | |
| `action` | text NOT NULL | `user.create`, `session.revoke`, `license.load`, … |
| `target_type`, `target_id` | text, uuid | |
| `outcome` | text NOT NULL | `success` \| `denied` \| `error` |
| `detail` | jsonb | structured context, **never** message content |
| `prev_hash` | bytea(32) NOT NULL | |
| `entry_hash` | bytea(32) NOT NULL | |

Insert-only. `UPDATE` and `DELETE` are revoked from the application role at the database
level, so an application-layer bug cannot rewrite history even if it tries.

### `audit_checkpoints`

`(id, up_to_audit_id, head_hash, signature, signing_key_id, created_at, anchored_at,
anchor_reference)`. `anchor_reference` records where the checkpoint was externally
anchored, if anchoring is enabled.

---

## 6. Directory sync, licensing, configuration

### `ad_sync_configs`

`(id, name, ldap_url, base_dn, bind_account, bind_secret_encrypted, use_gmsa,
user_filter, group_filter, ou_scope, schedule_cron, is_enabled, last_usn_changed,
last_full_sync_at)`. The bind secret is encrypted under the root KEK; with gMSA it is NULL.
`last_usn_changed` is the incremental sync watermark.

### `ad_sync_runs`

`(id, config_id, started_at, finished_at, status, mode, users_added, users_updated,
users_deactivated, groups_added, groups_updated, ous_synced, error_count, errors jsonb)` —
the per-run report surfaced in the console.

### `licenses`

`(id, license_blob jsonb, raw_signed_document text, signature bytea, is_active,
installed_at, installed_by, activated_at, last_heartbeat_at, validation_state,
validation_detail)`. The raw signed document is kept verbatim: re-verifying a signature
against a re-serialised JSON object is a well-known way to get intermittent, maddening
failures.

### `license_usage_snapshots`

`(id, captured_at, seats_used, sessions_active, peak_sessions_24h)` — evidence for renewal
conversations and for showing headroom trends in the console.

### `server_settings`

`(key PK, value jsonb, updated_at, updated_by, is_secret)`. Runtime-changeable settings.
Values with `is_secret` are encrypted under the root KEK and are redacted in every API
response and log.

---

## 7. Retention and deletion

Retention is policy-driven per data class and enforced by a scheduled job:

| Class | Default | Mechanism |
| --- | --- | --- |
| Messages | indefinite | policy-driven purge by age |
| Files | 90 days after last access | hard delete + crypto-shred the per-file DEK |
| Sessions | 30 days after expiry | hard delete |
| Operational logs | 30 days | file rotation |
| Audit log | 7 years | **never** auto-purged; archived to signed cold storage |

Crypto-shredding files by destroying the per-file DEK means a backup restored later cannot
resurrect deleted content — which is precisely why files get their own key rather than
sharing the conversation key.

Audit retention deliberately exceeds every other class. If an organisation's own policy
requires shorter audit retention, that is a configuration change they must make knowingly;
the default will not quietly discard the evidence trail.

---

## 8. Migrations

EF Core code-first migrations, applied by the installer or by an explicit
`Messenger.Server migrate` command — **never** automatically on service start. Automatic
migration at startup means an unattended upgrade can silently reshape a production database
during a restart, with no backup checkpoint and no operator watching.

Rules: every migration is forward-only and idempotent; destructive changes land as
two-phase deploys (add new, backfill, switch reads, drop old in a later release); the
installer takes a database backup checkpoint before applying anything; and each migration
carries a schema-version row so the server refuses to start against a database it does not
recognise (`SRV-104`).
