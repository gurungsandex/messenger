# Production-readiness review — 2026-08-05

A second review pass over the server-side implementation, after the
[security review](security-review.md). That review looked for ways in; this one looked for
the ways a correct-on-paper server behaves badly once real traffic, a real proxy, and a real
load balancer are in front of it.

Twelve findings, all fixed. Each fix carries a regression test, and the concurrency test was
confirmed to fail against the unfixed code.

**Suite: 307 tests, all passing** (was 284). Release build clean under `-warnaserror`;
migrations apply to an empty database and the model has no uncaptured changes.

---

## Correctness

### PR-1 · HIGH · Concurrent sends to one conversation returned 500

**Location:** `src/Messenger.Data/MessageService.cs`

Sequence numbers are allocated by reading `conversations.next_seq` and are made unique by
the index on `(conversation_id, seq)`. Two users sending at the same moment in the same
conversation both read the same value and both insert it; the loser's insert violated the
index, and the `DbUpdateException` reached the caller as an opaque 500 on an ordinary
message.

Nothing about this needs an attacker — it is two colleagues replying at once, and the
busier the conversation the likelier it is. It is also invisible in a single-threaded test
suite, and in the SQLite suite specifically, which runs over one shared connection and
therefore serialises writers.

**Fix.** The index stays the arbiter; the loser re-reads and retries onto the next free
number, bounded at eight attempts so a genuine write failure still surfaces as itself. This
is the pattern that already guarded the direct-conversation create a few lines above. The
idempotency key is re-checked at the top of each attempt, so a retry that races with the
original returns the first ack rather than a second message.

**Test.** `PostgresIntegrationTests.Concurrent_senders_each_get_a_distinct_sequence_number`
fires eight senders through eight separate `DbContext`s — one each, as the server has — and
asserts a gapless run of sequence numbers with all eight bodies intact. Setting the retry
bound to zero reproduces the original `DbUpdateException`.

### PR-2 · HIGH · A rejected password left a real account behind

**Location:** `src/Messenger.Server/AdminApi.cs`

`POST /api/admin/users` committed the user row, then called `SetPasswordAsync`, which
validates the password policy and throws on a short password. The row was already durable,
so a rejected request left an account with no password hash, no role, and a consumed licence
seat — reported to the administrator as a failure, and invisible afterwards except as a seat
count that did not add up.

**Fix.** Every rejectable condition is checked before the first write: password policy,
required fields, and field lengths.

**Test.** `A_rejected_password_leaves_no_account_behind` asserts the user does not exist
after the failed call.

### PR-3 · MEDIUM · Invalid input reached the caller as a 500

**Location:** `src/Messenger.Server/AdminApi.cs`

Two paths turned bad input into a server error:

- `POST /users/{id}/status` parsed the status with `Enum.Parse`, so any unrecognised value
  threw `ArgumentException`.
- `POST /users` passed username and display name straight to the database, so anything over
  the 256-character column became a `DbUpdateException`.

Both reached the caller as a 500 with a correlation ID and no indication of what to fix,
and both wrote an error to the server log for what was a client mistake.

**Fix.** `TryParse` with the valid values named in the message, and length and
required-field validation before the write.

**Tests.** `An_unrecognised_status_is_a_bad_request_not_a_server_error`,
`An_over_long_username_is_a_bad_request_not_a_server_error`,
`Creating_a_user_rejects_a_missing_name`.

### PR-4 · MEDIUM · Audit detail could be written as invalid JSON

**Location:** `src/Messenger.Data/AuthService.cs`

The failed-login entry for an unknown username built its `detail_json` by hand, escaping
quote and backslash. JSON also forbids raw control characters, so a username containing a
newline or a tab produced a detail field no parser accepts.

That field is hashed into the audit chain, so the malformed entry is permanent: it cannot be
corrected without breaking the chain it is part of. The username is attacker-chosen and the
endpoint is reachable without a credential, so producing one takes a single request.

**Fix.** `JsonSerializer.Serialize`, which every other audit call site in the codebase
already used.

**Test.** `An_unknown_username_is_audited_as_valid_json` round-trips five hostile usernames
through `JsonDocument.Parse`.

---

## Authorization

### PR-5 · MEDIUM · File deletion checked nothing

**Location:** `src/Messenger.Data/FileTransferService.cs`

`DeleteAsync(actorId, fileId)` looked the file up and destroyed it. It did not check the
actor against the file, and `actorId` was used only for the audit entry — so the parameter
that looked like an authorization check was decoration.

Not currently reachable: no route calls it. That is the whole reason it is worth fixing now.
Every other entry point in the service — upload, download, resume — checks the caller, so
the first route wired to this one would inherit no check at all and look consistent with its
neighbours while doing so. The operation is irreversible: the key is destroyed, so no backup
brings the content back.

**Fix.** The uploader may delete their own file. Any other caller must pass
`asAdministrator: true`, which a future retention or moderation route would set after
checking a permission — an explicit opt-in rather than a silent default. Refusals are
audited.

**Tests.** `A_peer_cannot_delete_someone_elses_upload` (and asserts the file is still
downloadable afterwards — a refusal must not leave it half-shredded),
`A_refused_deletion_is_audited`, `An_administrative_caller_may_delete_another_users_upload`.

---

## Performance

### PR-6 · HIGH · File transfers held three copies of the file in memory

**Location:** `src/Messenger.Data/FileTransferService.cs`

Both transfer paths reassembled the entire plaintext into a `MemoryStream` and then called
`ToArray()`. That is two full copies live at once, and because a `MemoryStream` doubles as
it grows, the first of them reserved up to twice the file size — roughly 3x the file per
transfer, in the large-object heap, at the default 100 MB cap.

The whole point of chunking is that a 100 MB transfer never needs 100 MB of server memory,
and this gave that back. A handful of concurrent transfers was enough to put real pressure
on the process.

**Fix.**

- **Completion** hashes a chunk at a time through `IncrementalHash`, so the digest check
  never holds more than one chunk.
- **Scanning** reassembles only when a scanner is actually configured. The shipped default
  is the no-op, so the largest allocation in the upload path existed to feed something that
  ignored it.
- **Download** allocates one exactly-sized buffer, sized from the chunk rows rather than the
  declared file size so a disagreement between the two is a caught error rather than an
  overflow.
- **`DownloadToAsync`** is a new streaming path that decrypts straight into a caller's
  stream. Peak memory is one chunk however large the file is. It shares its authorization
  and integrity gate with the buffered path, so the two cannot drift apart on what they
  enforce.

**Tests.** `Streaming_a_download_yields_the_same_bytes`,
`Streaming_a_download_enforces_access`,
`Detects_chunk_lengths_that_disagree_with_the_recorded_size`.

### PR-7 · MEDIUM · Every upload walked the entire file store

**Location:** `src/Messenger.Data/FileTransferService.cs`

`BeginUploadAsync` measured used storage on every call. The local store measures by
enumerating every file it holds, and the default capacity is unbounded — so each upload paid
for a full recursive directory walk and then discarded the answer. Cost grew with the number
of files stored, on a code path that runs before a single byte moves.

**Fix.** Only measured when a capacity is actually configured.

### PR-8 · MEDIUM · The backlog index covered the whole history

**Location:** `src/Messenger.Data/MessengerDbContext.cs`, migration
`20260805143222_PartialPendingDeliveryIndex`

`message_recipients` holds a row per recipient per message and is kept forever — it grows
past every other table. Its index on `(user_id, state)` was documented in the code as
partial but was not filtered, so it indexed the entire history to serve a set that in a
healthy deployment is nearly empty.

Every query that reaches this table by user filters on `Pending`: the backlog on reconnect,
the discard on group removal, the console's pending count. Everything else reaches a row by
its primary key. So the index grew without bound and the query it exists for got slower
every day the server ran.

**Fix.** `HasFilter("state = 0")`, with a migration. The index now covers only undelivered
rows, which is what the comment claimed all along.

---

## Deployment

### PR-9 · MEDIUM · No client address behind a reverse proxy

**Location:** `src/Messenger.Server/Program.cs`

Every client address came from `RemoteIpAddress`. Behind a reverse proxy — the documented
deployment — that is the proxy for every request, which has two consequences:

- The audit log records the proxy's address on every entry, so the log cannot answer *where
  from*, which is much of what it is for.
- The per-IP login rate limiter partitions the entire organisation into one bucket. Ten
  failed sign-ins from anyone locks out everyone.

**Fix.** `ForwardedHeaders`, **opt-in**, because the opposite failure is worse: honouring
`X-Forwarded-For` with no proxy in front lets any caller choose their own apparent address
and walk past both the audit trail and the rate limiter. Only proxies the operator names are
trusted — the ASP.NET defaults trusting loopback are cleared — and enabling the feature
without naming one logs a warning at startup, because that combination looks configured and
does nothing.

**Test.** `A_spoofed_forwarded_address_does_not_reach_the_audit_log` asserts the header is
ignored by default.

### PR-10 · MEDIUM · No readiness probe

**Location:** `src/Messenger.Server/Program.cs`

Only `/health/live` existed, and it checked nothing. A load balancer had no way to ask
whether an instance could actually serve a request, so it would keep routing traffic to one
whose every request was failing.

**Fix.** `/health/ready` checks database reachability and returns 503 when it is gone.
`/health/live` still deliberately checks nothing: an orchestrator restarts what fails
liveness, and restarting the server does not bring a database back — it adds an outage on
top of one.

**Test.** `Readiness_fails_when_the_database_goes_away` drops the database out from under a
running host, then asserts readiness reports 503 while liveness stays 200.

### PR-11 · LOW · Key escrow file was world-readable

**Location:** `src/Messenger.Crypto/KeyStore.cs`

The escrow blob was created at the default mode — 0644 on Unix — so any local account could
copy the file holding the root key of every message and file in the deployment and attack
the passphrase offline at leisure.

**Fix.** `0600`, set on the temporary file before it is moved into place so the blob is
never briefly readable at its final name. Unix only; on Windows a new file inherits the
directory ACL, which is what the deployment guide covers. Best-effort — a file system that
cannot express permissions is a reason to warn, not to refuse to start and leave the server
with no key store at all.

**Tests.** `A_created_escrow_file_is_readable_only_by_its_owner`,
`Reopening_an_escrow_returns_the_same_kek`.

### PR-12 · LOW · Sign-out was not rate limited

**Location:** `src/Messenger.Server/Program.cs`

`POST /api/auth/logout` does a session-token lookup before it knows who is calling, so it
was the cheapest unauthenticated way to put database load on the server.

**Fix.** Rate limited alongside the rest of the authenticated surface.

---

## Not fixed

| Item | Why |
| --- | --- |
| Audit appends serialise the whole process | `AuditService` holds a process-wide lock across the append so the hash chain stays consistent, which caps server throughput at the rate of one audit write. Correct for the single-server topology (ADR-0003) and called out in the code; the fix is batching or a chain-per-partition, which is a design change, not a repair. |
| Org-wide read-receipt policy is not configurable | `PresenceService.ReadReceiptsEnabled` is a property on a scoped service, so setting it cannot persist and it is always true. OD-2 in [ADR-0005](adr/0005-phase1-open-decisions.md) is provisional; wiring it to `server_settings` is the feature, and this review did not add features. |
| Hub methods are not rate limited | Rate limiting is HTTP middleware; SignalR hub invocations bypass it. Per-connection throttling is new work rather than a repair. |
| Everything in the security review's own "not fixed" table | Unchanged — TPM key store, external audit anchoring, penetration test, dependency scanning. |
