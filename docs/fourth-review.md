# Fourth review — 2026-08-11

A deployment-readiness pass over the server-side implementation, after the
[security review](security-review.md), [production review](production-review.md), and
[third review](third-review.md). The prior three passes are still holding: their regression
suites were re-run against a real Release build and a real PostgreSQL instance rather than
re-audited.

This pass asked a different question from its predecessors. They asked whether the code is
correct; this one asked whether the code **survives being deployed and operated** — restarted,
restored from backup, run as a managed service. That framing found one finding the earlier
passes could not have, because it is invisible to a test suite that never restarts the process.

**Suite: 321 tests, all passing** (was 312). Release build clean under `-warnaserror`;
migrations apply to an empty database and the model has no uncaptured changes. The container
image builds, starts, reports ready against a real database, and survives a restart with its
keys intact.

---

## Findings, fixed

### FR-1 · HIGH · The audit signing key was regenerated on every start

**Location:** `src/Messenger.Data/AuditService.cs`, `src/Messenger.Server/Program.cs`

`InMemoryAuditSigningKeyProvider` generates its Ed25519 pair in its constructor, and
`Program.cs` registered it as the singleton `IAuditSigningKeyProvider` — in production as
well as development. The key therefore lived exactly as long as the process.

Every checkpoint stores the `SigningKeyId` it was signed under. After a restart the new
provider holds a new key id and has never seen the old one, and the old public key was never
persisted anywhere, so `GetPublicKey` throws `Unknown signing key` for every checkpoint
written before the restart. Those signatures remain in the database and can never be checked
again.

This is precisely the defect class the security review already fixed for the root KEK, where
the reasoning was recorded verbatim in `FileBackedKeyStore`: *"generating a KEK per process is
catastrophic... A key store must outlive the process that uses it."* The audit signing key was
the one key that never got the same treatment.

Two things made it worse than an ordinary durability bug:

1. **It is silent.** Nothing fails at restart. The server starts, signs new checkpoints
   happily, and only an audit years later discovers that everything before the last restart is
   unverifiable — at the moment the evidence is actually needed.
2. **Nothing ever verified a checkpoint anyway.** `VerifyAsync` recomputed the hash chain and
   never looked at a signature, and no other call site read one. So the Ed25519 checkpoints —
   listed as *Built, tested* in the README and as *Implemented and tested* in the deployment
   guide — contributed nothing to a running deployment. The hash chain alone proves only that
   the log is internally consistent, which is exactly what an attacker who rewrites it and
   recomputes the hashes also achieves.

**Fix.** Two parts, because either alone leaves the feature inert.

`FileBackedAuditSigningKeyProvider` holds the key ring in a passphrase-sealed file, created on
first run and re-read on every subsequent start, mirroring `FileBackedKeyStore`. Superseded
keys are retained rather than replaced, so a rotation does not orphan the checkpoints signed
before it. It is sealed under the same passphrase as the KEK escrow: both are root secrets
provisioned and backed up together, and a second secret to manage is a second secret to lose.
A wrong passphrase is refused rather than silently reseeding — reseeding would be the worst
available behaviour, orphaning every existing checkpoint without saying anything.

`AuditService.VerifyCheckpointsAsync` verifies every stored signature against the chain head it
names, and `/api/admin/audit/verify` now reports both halves. A checkpoint signed by a key this
server does not hold is reported as *unverifiable* rather than *invalid*: missing evidence and
contradicted evidence are different facts to an auditor, and the first is the expected state
after restoring a database without its key ring.

The shared passphrase/atomic-write handling is factored into `PassphraseSealedFile`. It
deliberately does **not** re-implement the KEK escrow — that blob's layout is already on disk
in existing deployments, and changing how it is read would strand them.

**Tests.** `AuditSigningKeyTests`, eight cases. The load-bearing one is
`A_rewritten_chain_passes_the_hash_check_and_fails_the_signature`: it rewrites an audit entry
and re-chains every hash after it, exactly as an attacker with database write access would,
then asserts that `VerifyAsync` reports the forgery **clean** and only the checkpoint signature
catches it. That test fails against the old code in the most informative way possible — there
is no signature left to catch anything with.
`The_in_memory_provider_loses_its_key_across_a_restart` pins the original defect.
`Audit_verification_reports_the_checkpoint_signatures` covers it end-to-end through HTTP.

### FR-2 · MEDIUM · No deployment path existed for the server that is finished

**Location:** repository root, `deploy/`, `.github/workflows/ci.yml`

The README stated the server was usable today for non-domain deployments, and the deployment
guide described a Windows Service and MSI that are not built. Between those two, there was no
supported way to actually run the thing: no container image, no service unit, no worked
configuration, and nothing in CI that started the server at all. "Runs on my machine via
`dotnet run`" was the whole deployment story.

**Fix.** A multi-stage `Dockerfile` (non-root user, both state directories declared as volumes,
readiness-based `HEALTHCHECK`), a `docker-compose.yml` for a single-host deployment with the
database unpublished and secrets taken from the environment, a hardened
`deploy/messenger-server.service` systemd unit, and worked `.env` / `messenger.env` examples
that say plainly which values are unrecoverable if lost.

`builder.Host.UseSystemd()` was added so the unit's `Type=notify` is honest — without it
systemd would report the service started the instant `exec` succeeded, rather than when the
server is listening.

Migrations are deliberately **not** run by the image or the unit, preserving the existing rule
that an unattended restart must not reshape a production database.

**CI.** A `container` job builds the image, starts it against a real PostgreSQL, and waits for
`/health/ready` to report healthy. It then restarts the container and **fails the build if
either key was regenerated** — FR-1's failure mode is silent at runtime, so it is asserted
where it cannot be silent.

### FR-3 · LOW · The audit signing escrow defaulted into the test binary's directory

**Location:** `tests/Messenger.Server.Tests/AdminApiTests.cs`

The test host set `KeyStore:EscrowPath` into a per-test temporary directory but, once FR-1
introduced a second key file, left `AuditSigningKey:EscrowPath` at its default under
`AppContext.BaseDirectory`. That path outlives the run and is shared by every test class, so a
checkpoint written by one run could be verified against a key ring left behind by another —
a test that passes or fails depending on what a previous run left on disk.

**Fix.** Scoped to the same per-test directory as the KEK escrow, and removed with it.

---

## Not fixed

| Item | Why |
| --- | --- |
| Licence seat and concurrent-session limits can be exceeded by simultaneous requests | Unchanged from the third review, and still correctly deferred. `EnsureSeatAvailableAsync` and the total-session check count-then-write with no locking and no backing constraint. A correct fix serialises the count and the write across a multi-service flow spanning several `SaveChangesAsync` calls — a transactional restructuring, not a repair of the check. Exposure is licence over-use, self-correcting on the next check and gated behind an admin action or the login rate limiter. Not a security boundary. |
| Session token accepted in the `access_token` query string by the hub | `ChatHub` falls back to a query parameter because the WebSocket handshake cannot always carry headers. Query strings are logged by reverse proxies and access logs, so this writes live session tokens into files with different retention and access rules than the session store. Not changed here because removing the fallback without a client to test against risks breaking the transport outright; the mitigation is that tokens are opaque, device-bound, and instantly revocable. Flagged for the client work, which is where it can be verified. |
| `FileTransferService` is complete and tested but reachable from no route | Unchanged from the third review. The service is fully covered, but nothing wires it to HTTP or the hub, so file transfer is not usable in a deployment despite being listed as built. Wiring it is feature work with its own authorization surface, not a review fix. |
| Hub methods are not rate limited | Unchanged. The rate limiter covers HTTP endpoints; SignalR methods are reachable by any authenticated session without one. |
| Everything in the prior three reviews' own "Not fixed" tables | Unchanged — audit-append serialisation (ADR-0003), org-wide read-receipt policy, TPM key store, external audit anchoring, penetration test, dependency scanning. |
