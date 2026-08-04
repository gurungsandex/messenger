# Architecture

**Status:** Phase 0 — awaiting sign-off
**Scope:** v1, single-server, Windows clients

---

## 1. System overview

Four deployable components across three trust tiers.

```
  VENDOR INFRASTRUCTURE (Owner tier)
  ┌──────────────────────────────────────────────┐
  │  Messenger.Owner                             │
  │   • issues signed license files              │
  │   • license activation + revocation          │
  │   • telemetry intake (opt-in)                │
  │   • live support chat endpoint               │
  │   • optional audit-checkpoint anchoring      │
  └──────────────────────────────────────────────┘
        ▲  HTTPS (TLS 1.3, mTLS)      ▲  WSS support chat
        │  outbound only              │
════════╪═════════════════════════════╪══════════════════ internet boundary
        │                             │
  CUSTOMER INFRASTRUCTURE            │
        │                             │
  ┌─────┴──────────────────────┐      │
  │  Communication Server      │      │
  │  (Windows Service)         │      │
  │                            │      │
  │  ASP.NET Core 8            │      │
  │   • SignalR hub (chat)     │      │
  │   • REST admin API         │      │
  │   • auth + session mgmt    │      │
  │   • store-and-forward      │      │
  │   • file relay             │      │
  │   • envelope encryption    │      │
  │   • signed audit log       │      │
  │   • license enforcement    │      │
  └──┬────────┬────────┬───────┘      │
     │        │        │              │
     │        │        └── LDAPS 636 / Kerberos 88 ──► Domain Controller
     │        │                       │
     │        └── file store (local NTFS or SMB)
     │                                │
     └── PostgreSQL 16 (TLS)          │
                                      │
  ┌──────────────────┐   ┌────────────┴─────┐
  │  Client.exe      │   │  Admin.exe       │
  │  WPF end-user    │   │  WPF IT console  │
  └──────────────────┘   └──────────────────┘
     WSS + cert pinning     HTTPS + cert pinning
```

### 1.1 Component responsibilities

| Component | Runs on | Responsibility |
| --- | --- | --- |
| **Messenger.Owner** | Vendor infrastructure | Issues Ed25519-signed license files. Handles activation, heartbeat, and revocation. Terminates admin support chat. Never receives message content. |
| **Communication Server** | Customer Windows Server | Authentication, message routing, persistence, store-and-forward, file relay, presence, audit logging, AD sync, license enforcement. |
| **Admin Console** | IT admin workstation | User/group/OU lifecycle, AD import + re-sync scheduling, server health, session view, audit log review, license status, support chat. |
| **Client App** | End-user workstation | 1:1 and group chat, file send/receive, presence, history + search, receipts, idle auto-logout. |

---

## 2. Protocols and ports

| Link | Protocol | Port | Notes |
| --- | --- | --- | --- |
| Client → Server | HTTPS + WebSocket (SignalR) | 8443/tcp | TLS 1.3 only, certificate pinned |
| Admin → Server | HTTPS REST | 8443/tcp | Same listener, `/api/admin/*`, RBAC-gated |
| Server → PostgreSQL | PostgreSQL wire | 5432/tcp | `sslmode=verify-full` |
| Server → Domain Controller | LDAPS | 636/tcp | Certificate validated; plain LDAP refused |
| Server → Domain Controller | Kerberos | 88/tcp+udp | SSO ticket validation |
| Server → Owner | HTTPS | 443/tcp | Outbound only, mTLS, no inbound hole |
| Admin → Owner | HTTPS + WSS | 443/tcp | Support chat, outbound only |

**Firewall summary for IT:** one inbound port on the server (8443). Everything vendor-facing
is outbound-only. A fully air-gapped deployment is supported with offline license files;
only telemetry and support chat are lost.

### 2.1 Transport security

- **TLS 1.3 only.** TLS 1.2 and below are refused. Cipher suites limited to
  `TLS_AES_256_GCM_SHA384` and `TLS_CHACHA20_POLY1305_SHA256`.
- **Certificate pinning.** Clients pin the server's SPKI (SHA-256 of the
  SubjectPublicKeyInfo), not the leaf certificate — so certificate renewal with the same
  key pair does not break clients. Two pins are held: current and next, to allow key
  rollover. Pins are provisioned at install time via MSI property or Group Policy, and
  rotated through a signed pin-set update delivered over the authenticated channel.
- **Pin failure is fatal and non-overridable in the client UI.** A user cannot click
  through a pin mismatch; this closes the on-path-attacker path that a "proceed anyway"
  button would open. Recovery is an IT action (`NET-104`).

---

## 3. Authentication and sessions

### 3.1 Mechanisms

Three, in priority order:

1. **Kerberos SSO (Negotiate).** Domain-joined client, domain-joined server. The client
   obtains a service ticket for the server's SPN; the server validates it. No password
   ever crosses the wire. Preferred path.
2. **NTLM (Negotiate fallback).** Only where Kerberos is unavailable. Disabled by default;
   an admin must explicitly enable it, because NTLM is relay-attackable. Enabling it
   raises a warning in the console and writes an audit event.
3. **Local account, Argon2id.** For non-domain deployments, service accounts, and
   break-glass admin access.

### 3.2 Password storage (local accounts)

Argon2id via `Konscious.Security.Cryptography`, parameters:

| Parameter | Value | Rationale |
| --- | --- | --- |
| Memory | 64 MiB | OWASP-recommended floor for Argon2id |
| Iterations | 3 | With 64 MiB, meets the ~500 ms server-side target |
| Parallelism | 4 | Tuned to server core count at install |
| Salt | 16 bytes, CSPRNG, per-password | |
| Output | 32 bytes | |

Parameters are stored **alongside each hash** in PHC string format
(`$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`) so they can be raised later without
invalidating existing credentials — on next successful login, a hash below current policy
is transparently upgraded.

Passwords are compared in constant time. Failed logins are rate-limited per account and
per source IP with exponential backoff, and lockout is *soft* (backoff) rather than hard,
to avoid handing an attacker a trivial account-lockout DoS.

### 3.3 Sessions

Sessions are **server-side and opaque**, not self-contained JWTs. This is a deliberate
choice: the license enforces *concurrent sessions* and *idle timeout*, and revocation must
be immediate. A stateless token cannot be counted or revoked without a server-side
registry anyway, so the registry is the source of truth.

- Token: 256 bits from a CSPRNG, transmitted as a bearer credential, stored in the
  database as SHA-256 only. A database reader cannot replay a session.
- Each session row records device, IP, creation time, last activity, and expiry.
- **Idle timeout** comes from the license policy. The server enforces it authoritatively;
  the client also enforces it locally for a responsive lock-screen, but the client's
  opinion is never trusted.
- **Absolute lifetime** caps a session regardless of activity (default 12 h).
- Revocation is immediate: admin action, password change, user deactivation, or license
  violation all mark sessions revoked, and the hub connection is dropped on the next
  message or heartbeat.

### 3.4 Authorization (RBAC)

Permissions are fine-grained and roles are sets of permissions. Roles are scoped to a tier
so a customer admin role can never grant vendor-tier capability.

| Tier | Built-in roles | Notable permissions |
| --- | --- | --- |
| Owner | `VendorAdmin`, `VendorSupport` | issue/revoke licenses, view telemetry, join support chat |
| Server | `ServerAdmin`, `UserAdmin`, `Auditor`, `HelpDesk` | server config, user/group CRUD, audit read, session kill |
| Client | `User` | send messages, transfer files |

`Auditor` is intentionally separable from `ServerAdmin`: an organisation that wants
separation of duties can grant audit-log read without granting user management. Note the
limits of this — see the [threat model](threat-model.md#tb3--server--database).

Every authorization decision is a single call into a policy service; there is no
permission logic scattered through controllers. Denials are audited.

---

## 4. Messaging

### 4.1 Delivery semantics

**At-least-once delivery with client-side idempotent de-duplication**, producing
effectively-once display.

1. Client assigns a `client_message_id` (UUID) and sends.
2. Server persists the message, assigns a per-conversation monotonic `seq`, and ACKs with
   `(server_id, seq)`. Persistence happens *before* the ACK — an ACK means durable.
3. Client marks the message sent on ACK. No ACK within timeout → retry with the **same**
   `client_message_id`; the server's unique index on `(conversation_id, sender_id,
   client_message_id)` makes the retry a no-op returning the original ACK.
4. Server fans out to online participants and writes a `pending` delivery row for every
   participant, online or not.
5. Recipient ACKs delivery → row becomes `delivered`. Recipient displays it → `read`.

Ordering is by server-assigned `seq` within a conversation. There is no global order across
conversations, and none is needed. Server timestamps are authoritative for display;
client-supplied timestamps are stored but never trusted for ordering (a client with a skewed
or hostile clock cannot reorder a conversation).

### 4.2 Store-and-forward

Offline delivery falls out of the model above rather than needing a separate queue: a
message for an offline user is simply a `pending` row. On login the client sends its last
seen `seq` per conversation and the server streams the gap, oldest first, in bounded
batches with backpressure. Because the backlog is a query over persisted state rather than
an in-memory queue, a server restart loses nothing.

Retention of undelivered messages is policy-driven (default: forever, subject to the
global retention policy).

### 4.3 Presence

Statuses: `Online`, `Busy`, `Away`, `Offline`.

- Explicit status is set by the user and persisted.
- **Auto-away** is detected client-side from OS input idle time (`GetLastInputInfo`) and
  reported to the server. Threshold is configurable, default 10 minutes.
- Presence is held in memory and mirrored to the database for restart recovery. It is
  broadcast only to users who share a conversation or group with the subject — presence is
  not a directory-wide broadcast, both for privacy and to bound fan-out.
- Connection loss transitions to `Offline` after a grace period, so a brief network blip
  does not flap the user's contacts list.

### 4.4 Receipts

Delivery and read receipts are per-recipient rows. In group conversations the client shows
an aggregate ("read by 4 of 7") and can expand to the per-user list. Read receipts are
configurable at organisation level, because some organisations treat them as surveillance;
if disabled, the server does not record `read_at` at all rather than merely hiding it.

---

## 5. File transfer

Files are **relayed through the server**, never peer-to-peer. Peer-to-peer would defeat
audit logging, AV scanning, and the "no third-party relay" guarantee, and would fail across
segmented networks.

Flow:

1. Client requests an upload slot with filename, size, and SHA-256 of the plaintext.
2. Server checks the license file-size cap, the organisation's extension policy, and quota.
   Rejection here is cheap — before any bytes move (`FILE-101`, `FILE-102`).
3. Client uploads in chunks (default 4 MiB) over TLS; uploads are resumable by chunk index.
4. Server encrypts each chunk with the file's DEK (§6.3) and writes to the file store.
5. On completion the server verifies the plaintext SHA-256 against the declared value,
   rejecting a mismatch (`FILE-106`).
6. If AV scanning is enabled, the file is scanned before it is made available. Until the
   scan completes the attachment is visible but not downloadable, with clear status.
7. Recipients download by chunk, with the server enforcing conversation membership on every
   request — a file ID alone is never sufficient authority.

Large-file integrity uses per-chunk AEAD tags plus a manifest covering the chunk digests,
so truncation and chunk-reordering are both detectable, not just per-chunk corruption.

---

## 6. Cryptography

### 6.1 Model

**Server-side encryption with admin-recoverable keys**, as confirmed. The server sees
plaintext. This enables compliance archiving, eDiscovery, admin search, and AV scanning,
and it means a compromised server or malicious administrator can read everything. That
trade-off is recorded as an accepted risk in the
[threat model](threat-model.md#5-accepted-risks) and in [ADR-0002](adr/0002-encryption-model.md).

Everything here uses vetted primitives from .NET's `System.Security.Cryptography` and
Bouncy Castle. No custom cryptographic construction.

### 6.2 Key hierarchy

```
  Root KEK  (AES-256, never leaves its provider)
  provider: DPAPI-NG | Windows CNG/TPM | PKCS#11 HSM
      │
      │  AES-KW (RFC 3394) key wrapping
      ▼
  ┌────────────────────┬────────────────────┬──────────────────────┐
  │ Conversation DEK   │ File DEK           │ Audit signing key    │
  │ AES-256, per       │ AES-256, per file  │ Ed25519 private key  │
  │ conversation,      │                    │                      │
  │ versioned          │                    │                      │
  └────────────────────┴────────────────────┴──────────────────────┘
```

A note on refinement from the initial sketch: the design uses a **per-conversation** DEK
with versioned rotation rather than a per-message DEK. A per-message key would add a
wrapped key, its metadata, and a wrap operation to every single message for no security
gain over rotation — the compromise domain is the KEK either way, since the KEK unwraps
all of it. Per-conversation keying with enforced rotation gives the same recovery
properties at a fraction of the storage and CPU cost. Files keep a **per-file** DEK,
because files have independent lifecycles: they are individually shared, scanned,
retained, exported, and deleted, and a per-file key makes crypto-shredding a single file
possible.

### 6.3 Content encryption

| Data | Algorithm | Nonce | AAD |
| --- | --- | --- | --- |
| Message body | AES-256-GCM | 96-bit random per message | `conversation_id ‖ message_id ‖ sender_id ‖ key_version ‖ schema_version` |
| File chunk | AES-256-GCM | 96-bit: 32-bit random prefix ‖ 64-bit chunk counter | `file_id ‖ chunk_index ‖ chunk_count ‖ key_version` |

Binding the identifiers into the AAD means a ciphertext cannot be silently moved to another
message, conversation, or chunk position by someone with database write access — the tag
check fails. This is what turns "encrypted at rest" into something that also resists
tampering rather than only disclosure.

**Nonce management.** Random 96-bit nonces under a single key have a birthday bound; the
safe ceiling is well under 2^32 messages per key. Conversation keys therefore rotate on
whichever comes first: 2^24 messages (~16.7 M, a wide margin), 90 days, or an explicit
admin action. Old key versions are retained so history stays readable; `key_version` is
stored per message. File chunk nonces use a counter rather than randomness, which
eliminates the collision question entirely within a file.

### 6.4 Tamper-evident audit log

Every audited action appends an entry chained to its predecessor:

```
entry_hash = SHA-256( canonical_json(entry) ‖ prev_hash )
```

Periodically (every 1 000 entries or 60 seconds, whichever first) the server signs the
current head with an **Ed25519** key and stores a checkpoint. Verification recomputes the
chain and checks the checkpoint signatures; any insertion, deletion, or edit breaks the
chain at that point and every checkpoint after it.

**This is tamper-*evident*, not tamper-*proof*, and the distinction matters.** An attacker
who holds both database write access and the audit signing key can rewrite history and
re-sign it, and no purely local mechanism can prevent that. Two optional controls close
the gap, and at least one should be enabled in any environment where the administrator is
inside the threat model:

- **Keep the signing key out of reach** — TPM or HSM-backed, so it can be used but not
  extracted, meaning re-signing a forged chain requires live server compromise rather than
  a database dump.
- **Anchor checkpoints externally** — ship checkpoint hashes to an append-only sink
  (syslog/SIEM) and/or to the Owner tier. A rewritten local chain then contradicts a copy
  the customer's admin never controlled.

Canonical JSON serialisation is pinned and versioned, because verification years later
must reproduce byte-identical input; a serialiser change that reorders keys would
otherwise invalidate the whole archive.

---

## 7. Active Directory integration

A single `IDirectoryProvider` abstraction with an LDAPS implementation and a test double,
so directory logic is unit-testable without a domain controller.

- **Connection:** LDAPS on 636 with full certificate validation. Plain LDAP with StartTLS
  is *not* offered — an enterprise directory bind is not something to make optional.
- **Service account:** read-only, least privilege. It needs to read user and group objects
  and, for incremental sync, the `uSNChanged` attribute. It does **not** need write access,
  and the deployment guide will say so explicitly.
- **Credential storage:** the bind password is stored encrypted under the root KEK, never
  in a configuration file. Group Managed Service Accounts (gMSA) are supported and
  preferred, removing the stored password entirely.
- **Import:** users, groups, and OUs, mapped by `objectGUID` — the only stable identifier.
  Renaming a user or moving them between OUs in AD does not create a duplicate.
- **Scheduled re-sync:** cron-style schedule. Incremental via `uSNChanged` watermark, with
  a periodic full reconcile to catch tombstoned objects the incremental pass misses.
- **Deletion is never destructive.** An object that vanishes from AD results in a
  *deactivated* local user, not a deleted one, so message history and audit trail survive.
  Purging is a separate, explicit admin action.
- **Sync is transactional per batch** and every run writes a report — added, updated,
  deactivated, errors — visible in the console and audited.

---

## 8. Licensing

License files are JSON, Ed25519-signed by the vendor. The vendor's public key is embedded
in the server binary, so validation is fully offline.

```jsonc
{
  "license_id": "…", "customer": "…",
  "issued_at": "…", "not_before": "…", "not_after": "…",
  "max_seats": 500,
  "max_file_bytes": 104857600,
  "max_concurrent_sessions_per_user": 3,
  "max_concurrent_sessions_total": 750,
  "idle_timeout_seconds": 900,
  "features": ["ad_sync", "file_transfer", "support_chat"],
  "signature": "ed25519:…"
}
```

Enforcement points and their error codes:

| Check | When | Code |
| --- | --- | --- |
| Signature / tampering | Load, and every 24 h | `LIC-101` |
| Expiry | Load, and every login | `LIC-102` |
| Seat count | Activating a user | `LIC-103` |
| Per-user concurrent sessions | Login | `LIC-104` |
| Total concurrent sessions | Login | `LIC-105` |
| File size cap | Upload slot request | `FILE-101` |
| Feature not licensed | Feature invocation | `LIC-107` |

**Grace behaviour is deliberately not "hard stop".** An expired license puts the server
into a read-only grace mode for a configurable window (default 14 days): existing users can
read history, but new sessions and new messages are refused. Silently bricking a
corporation's internal communications at midnight on the expiry date is a worse outcome
than a loud, degraded mode, and administrators get escalating warnings from 30 days out.

Online activation and heartbeat to the Owner tier are **optional** and enable revocation
and seat telemetry. Air-gapped deployments run offline indefinitely. Telemetry is opt-in
and carries counts only — never usernames, message content, or metadata about who talks to
whom.

---

## 9. Cross-cutting concerns

**Configuration.** Layered: defaults in code, `appsettings.json`, environment variables,
then database-held settings which win for anything an admin can change at runtime. Secrets
never live in configuration files.

**Logging vs. auditing.** Two separate streams. Operational logs (Serilog, structured, to
file + Windows Event Log) are for diagnosis and are freely rotatable. The audit log is a
database table with the hash chain, and is *not* rotatable. Message content never appears
in operational logs at any level, including `Trace` — that is enforced by a redacting
serialiser rather than developer discipline.

**Health and observability.** `/health/live` and `/health/ready` endpoints, plus a metrics
endpoint (Prometheus format) covering connections, message throughput, queue depth, sync
status, and license headroom. The admin console reads these.

**Error handling.** Every user-visible failure carries a code from the
[error catalogue](error-codes.md). Codes are stable across versions, are shown in the UI
alongside plain-language text, and appear in logs — so a helpdesk call starts with a code
rather than "it says it didn't work". Internal exception details are never surfaced to
clients; they go to the operational log with a correlation ID that the user's error message
also carries.

**Backpressure and abuse limits.** Per-user rate limits on messages, uploads, and searches.
Bounded per-connection send queues; a client that cannot keep up is disconnected rather than
allowed to grow the server's memory without limit.

---

## 10. Deferred to post-v1

Recorded here so the boundary is explicit rather than implied: HA/clustering and the Redis
backplane; non-Windows clients; mobile; federation between deployments; voice and video;
message editing beyond a short window; optional per-conversation E2EE mode.
