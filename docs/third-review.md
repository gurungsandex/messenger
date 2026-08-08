# Third review — 2026-08-08

A follow-up pass over the server-side implementation, after the
[security review](security-review.md) and [production review](production-review.md). Both
prior passes are still holding: this review re-ran their entire regression suite against a
real build and a real PostgreSQL instance rather than re-auditing what they already covered,
then looked for defect classes those reviews had fixed in one place but not swept for
elsewhere.

**Suite: 312 tests, all passing** (was 307). Release build clean under `-warnaserror`;
migrations apply to an empty database and the model has no uncaptured changes. All three
findings below repeat a bug class the prior reviews already named and fixed at a different
call site — the fix pattern was correct, it just hadn't been applied everywhere the pattern
applies.

---

## Findings, fixed

### TR-1 · MEDIUM · A hostile licence id could corrupt the audit chain

**Location:** `src/Messenger.Data/LicenseEnforcementService.cs`

`InstallAsync` hand-built its success audit entry's `detail_json` by string interpolation:
`$"{{\"license_id\":\"{status.Payload.LicenseId}\"..."`. `LicenseId` comes from the signed
licence payload with no escaping — the same defect class PR-4 (see production-review.md)
fixed for usernames in `AuthService`, but that fix was never applied here.

A licence is vendor-signed, but the signature only proves who issued it, not that its fields
are well-formed — and P7 (a malicious or compromised vendor) is explicitly in the threat
model. A licence whose `license_id` contains a quote or control character produces a
`detail_json` value no parser accepts, and because it is hashed into the audit chain, the
malformed entry is permanent.

**Fix.** `JsonSerializer.Serialize` for both fields, matching every other audit call site in
the codebase.

**Test.** `A_hostile_licence_id_is_audited_as_valid_json` round-trips a licence id containing
a quote and a newline through `JsonDocument.Parse`.

### TR-2 · LOW/MEDIUM · Concurrent duplicate creation surfaced as a bare 500

**Location:** `src/Messenger.Server/AdminApi.cs` (username), `src/Messenger.Data/GroupService.cs`
(group name)

Both check-then-insert against a real unique index (`Users.Username`,
`Groups.Name` filtered on `deleted_at IS NULL`) with no `catch` around the insert. Two callers
racing to create the same username or group name have the loser's `SaveChangesAsync` throw
`DbUpdateException` uncaught — an opaque 500 with a correlation ID, exactly the class of
defect PR-3 was written to eliminate, and the same race `MessageService
.GetOrCreateDirectConversationAsync` already retries correctly. It just hadn't been applied to
these two call sites.

**Fix.** Both now catch `DbUpdateException` on the losing insert and report the same
`UserAlreadyExists` / `GroupAlreadyExists` conflict the upfront check reports, rather than an
unhandled exception.

**Tests.** `Concurrent_creation_of_the_same_username_gives_a_clean_conflict_to_the_loser` and
`Concurrent_group_creation_with_the_same_name_gives_a_clean_conflict_to_the_loser` fire two
callers at the real database and assert exactly one wins, the loser gets the named error code,
and only one row exists afterward. Both need PostgreSQL for the same reason PR-1's regression
test does: the unit suite runs SQLite over one shared connection, which serialises writers and
cannot produce the race.

### TR-3 · LOW (latent) · `BeginUploadAsync` divided by an unvalidated chunk size

**Location:** `src/Messenger.Data/FileTransferService.cs`

`ChunkCount = (sizeBytes + chunkSize - 1) / chunkSize`, with `chunkSize` an unchecked
caller-supplied parameter. Zero throws `DivideByZeroException`; negative values produce a
negative chunk count and nonsensical length math downstream. Not currently reachable — no
HTTP or hub route wires into `FileTransferService` yet — which is the same reasoning that made
the unreachable `DeleteAsync` gap (PR-5) worth fixing now rather than when a route makes it
live.

**Fix.** Rejected as `ErrorCode.MalformedRequest` before anything else runs.

**Test.** `Rejects_a_non_positive_chunk_size` covers zero and a negative value.

---

## Not fixed

| Item | Why |
| --- | --- |
| Licence seat and concurrent-session limits can be exceeded by simultaneous admin requests | `EnsureSeatAvailableAsync` and the total-session check in `AuthoriseLoginAsync` count-then-write with no locking and no backing DB constraint (unlike the username/group-name races above, there is no unique index that could catch this one). Two administrators activating accounts, or two logins, at the instant exactly one seat or session remains can both pass the check. Investigated: a correct fix needs the count and the eventual write serialised across the multi-step, multi-service flow that consumes the seat (user creation touches `AdminApi`, `AuthService`, and `AuthorizationService` across several `SaveChangesAsync` calls), which is a transactional restructuring of that flow, not a repair of the check. The exposure is licence over-use, self-correcting on the next check, gated behind an admin action or the existing login rate limiter (PR-12) — not a security boundary. Flagged for the next pass rather than rushed. |
| Everything in the prior two reviews' own "Not fixed" tables | Unchanged — audit-append serialisation (ADR-0003), org-wide read-receipt policy, hub methods not rate limited, TPM key store, external audit anchoring, penetration test, dependency scanning. |
