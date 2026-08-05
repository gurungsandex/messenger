# Security review — 2026-08-05

Review of the full server-side implementation before merge. Four findings, all fixed and
covered by regression tests that were confirmed to fail when the fix is reverted.

---

## SR-1 · HIGH · Missing authorization on every admin endpoint

**Category:** privilege escalation
**Location:** `src/Messenger.Server/AdminApi.cs`

`AdminAuthFilter` validated the session but never checked a role or permission. Any
authenticated account — including the lowest-privilege end user — could create and disable
users, revoke anyone's sessions, read the **entire audit log**, install licences, and
trigger directory synchronisation.

The architecture specified tier-scoped RBAC ([§3.4](architecture.md#34-authorization-rbac))
and the data model specified `roles`, `permissions`, and `user_roles`. None had been built.
The design was correct; the implementation simply omitted it, which is the most ordinary
way this class of hole appears.

**Exploit.** Any user signs in normally, then issues `GET /api/admin/audit` with their own
session token and receives the organisation's complete activity record — who spoke to whom,
when, from which address. The same token drives `POST /api/admin/users` to create an account
and `DELETE /api/admin/sessions/{id}` to sign out an executive.

**Fix.** `Role`, `RolePermission`, and `UserRole` entities; a `Permissions` catalogue; five
seeded roles; `AuthorizationService` as the single decision point; and a
`RequirePermissionFilter` on all sixteen admin routes. Permissions are re-read per request,
so revoking a role takes effect on the next call rather than at session expiry. Denials are
audited.

Two additional protections that fall out of doing this properly:

- **Cross-tier escalation is refused at assignment.** A server-scope role carrying an
  owner-tier permission cannot be granted, so a hand-edited or mis-seeded role row is not a
  path from the customer tier to the vendor tier.
- **The last server administrator cannot be demoted**, which would otherwise leave a
  deployment unmanageable with no route back short of database surgery.

**Tests.** `AuthorizationTests.cs` (24 tests) and eleven end-to-end tests asserting that an
ordinary user receives `403 AUTH-301` from every admin route. Disabling the permission check
fails all ten targeted tests.

---

## SR-2 · HIGH · Root key regenerated on every process start

**Category:** cryptographic key management / total data loss
**Location:** `src/Messenger.Server/Program.cs`

`PassphraseKeyStoreProvider.Create()` minted a fresh random KEK at every startup. Every
message and file encrypted before a restart became permanently unreadable.

This is worse than an ordinary bug because it is silent. Nothing fails at restart; the
server comes up healthy and accepts traffic. The damage only surfaces when someone opens an
older conversation, by which time the key that could have read it no longer exists anywhere.
A routine patch reboot destroys all history.

**Fix.** `FileBackedKeyStore.OpenOrCreate` loads the KEK from a durable escrow file, creating
it on first run. Writes go to a temporary file and are moved into place, so an interrupted
first run cannot leave a truncated escrow. The blob is read back and re-opened before use, so
an unreadable escrow fails at first start rather than at first restore. The server now
**refuses to start** without `KeyStore:Passphrase` — refusing to boot beats booting with a
key that will be gone in an hour.

**Tests.** `KeyStorePersistenceTests` — the decisive one wraps a key, disposes the provider,
reopens from disk, and asserts the pre-restart ciphertext still unwraps.

---

## SR-3 · MEDIUM-HIGH · File download bypassed group history visibility

**Category:** unauthorised data access
**Location:** `src/Messenger.Data/FileTransferService.cs`

Download checked conversation membership only. Phase 2 introduced visibility windows so a
member added to a group cannot read discussion predating their membership — but that boundary
was enforced for messages and not for their attachments. A user added today could download
every file ever shared in the group.

This is the characteristic shape of an access-control gap: the control exists, is correct,
and is simply not applied on one of the paths that reaches the same data.

**Fix.** `CanAccessFileAsync` applies the same window to files, anchored to the message that
carried the file. The uploader always retains access to their own upload. An upload with no
attached message requires current membership *and* that the participant's window was already
open when the file was created.

**Test.** `A_member_added_later_cannot_download_files_shared_before_they_joined`, confirmed
to fail when the check is reverted to a membership-only test.

---

## SR-4 · MEDIUM · No transport hardening

**Category:** transport security
**Location:** `src/Messenger.Server/Program.cs`

The architecture mandates TLS 1.3 only ([§2.1](architecture.md#21-transport-security)). No
TLS configuration, HSTS, or security headers existed, so a deployment would accept whatever
the host defaulted to — including TLS 1.0/1.1 on an older Windows Server.

**Fix.** In production: Kestrel restricted to TLS 1.3, HSTS with a one-year max-age,
HTTPS redirection, and the server header suppressed. On all environments: `nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a `default-src 'none'` CSP, and
`Cache-Control: no-store`.

**Test.** `Security_headers_are_present`.

---

## Correctness defects fixed alongside

Not security findings, but each would have caused a production incident.

**Unhandled service exceptions returned bare 500s.** A permission denial, licence limit, or
integrity failure thrown below the endpoint surfaced as an unhandled exception, losing the
error code the whole catalogue exists to provide — and, in a misconfigured environment,
potentially returning a stack trace. `ErrorHandling.cs` now maps every `MessengerException`
to its catalogue code and an appropriate status, logs operator detail server-side only, and
returns a correlation ID.

**Audit appends raced.** The chain is a linked list; two concurrent appends read the same
head and computed the same predecessor hash and id. One would lose, and because audit writes
are fail-closed, an ordinary concurrent request would be *refused*. Appends are now
serialised. This is correct for the single-server topology; a second server needs a
database-level advisory lock, noted in the code at the point it matters.

**Licence grace was not enforced on send.** Grace is defined as "history readable, no new
sessions and no new messages", but only logins were checked. Already-connected clients kept
sending indefinitely, so a deployment could run for weeks past expiry unnoticed. Sends now
consult licence state.

**Rate limiting was catalogued but absent.** `NET-204` existed with no implementation. Sign-in
is limited per source address (10/minute) and admin traffic per session (300/minute). Sign-in
is deliberately tighter — it is the endpoint that is actually attacked, and the only one
reachable without a credential.

---

## Accepted risks unchanged

The [threat model](threat-model.md#5-accepted-risks) register is unaffected by this review.
**AR-1 remains the dominant risk**: an administrator with server access can read all message
and file content, by design, because the customer chose compliance archiving over E2EE.

RBAC narrows *who* holds that access — an `Auditor` can now read evidence without managing
accounts, and a `HelpDesk` operator can end a session without reading message content — but it
does not change the fact that a `ServerAdmin` and anyone who compromises the server host can
read everything. That is inherent to the encryption model and is documented for customers.

---

## Not fixed — requires work outside this environment

| Item | Why |
| --- | --- |
| TPM / DPAPI-NG key store | The KEK is now durable but still held in process memory. A TPM-backed store makes it usable-but-not-extractable, materially improving AR-1 and AR-2. Needs Windows. |
| External audit anchoring | AR-6 stands: an attacker with database write access *and* the signing key can rewrite and re-sign. Anchoring checkpoints to an append-only sink closes it. |
| Penetration test | No substitute for an adversarial review by someone who did not write the code. |
| Dependency scanning / SBOM | Supply chain is listed as out of scope for v1 in the threat model. |
