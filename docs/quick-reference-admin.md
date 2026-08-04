# Administrator quick reference

One page for the things you do often, and the three that matter most when something is wrong.

---

## The three that matter most

**1. Export the KEK escrow before first use.** A machine-bound key with no escrow means a
dead server is unrecoverable message history — the database restores perfectly and nothing
can read it. There is no warning until someone attempts the restore.

```powershell
Messenger.Server.exe keystore export-escrow --out \\secure\messenger-kek.escrow
Messenger.Server.exe keystore verify-escrow --in \\secure\messenger-kek.escrow
```

**2. A certificate pin mismatch (`NET-104`) is a possible on-path attack until proven
otherwise.** Users cannot click through it, by design. If the server key legitimately
changed, distribute the new pin set by Group Policy or MSI property.

**3. An audit chain failure (`SRV-305`) is a security incident,** not a data-quality
problem. The verification report names the first bad entry. Compare against externally
anchored checkpoints before concluding anything.

---

## Daily operations

| Task | Where |
| --- | --- |
| Create / disable a user | Console → Users, or `POST /api/admin/users` |
| Create a group | Console → Groups |
| Add, remove, or move members | Console → Groups → Members |
| See who is connected | Console → Sessions |
| Force a user off | Console → Sessions → Revoke |
| Run a directory sync | Console → Directory → Sync now |
| Review the audit log | Console → Audit |
| Check licence headroom | Console → Licence |

---

## Health at a glance

```
GET /api/admin/health
```

Alert on: licence expiry approaching, seats above 90%, growing pending-delivery backlog,
checkpoint signing failures (`SRV-306`), any chain verification failure (`SRV-305`).

---

## Common situations

**"I can't sign in."** Check the audit log — it holds the specific reason, which the sign-in
screen deliberately does not show. `AUTH-104` is soft backoff after repeated failures and
clears itself; a burst of them across many accounts suggests password spraying.

**"Everyone was signed out."** Look for licence state (`LIC-102` grace, `LIC-110` grace
expired) or a bulk revocation in the audit log.

**"New users can't be created."** `LIC-103` — seats are enforced at provisioning, not at
login. Deactivate unused accounts or raise the licence.

**"Directory sync isn't working."** `AD-101` currently also means the LDAPS provider is not
yet implemented — see the deployment guide's status table. Otherwise check LDAPS on 636,
certificate trust, and clock skew (`AD-104`, must be under ~5 minutes).

**"A file won't download."** `FILE-203` scan in progress, `FILE-204` flagged as malware,
`FILE-205` scanner unavailable and the file is withheld fail-closed by design.

**"Someone left the company."** Deactivate the account. Sessions are revoked immediately,
and message history is preserved for compliance. Never delete — deletion destroys the audit
trail along with the account.

---

## Things the system will not let you do, and why

| Refused | Reason |
| --- | --- |
| Disable your own account | You would lock yourself out with no route back short of database surgery |
| Remove the last administrator | Same, at deployment scale |
| Rename an AD-synced group | The next sync would overwrite it |
| Click through a pin mismatch | It converts a cryptographic guarantee into a user-education problem |
| Auto-migrate the database at startup | An unattended restart must not reshape a production schema |
| Serve an unscanned file when scanning is on | Fail-closed beats assuming it is probably fine |

---

## Error-code prefixes

`AUTH` sign-in, sessions, permissions · `NET` connectivity and TLS · `LIC` licensing ·
`AD` directory · `FILE` transfers · `SRV` server, storage, cryptography

Full catalogue with causes and remediation: [`docs/error-codes.md`](error-codes.md).

---

## Before you call support

Have ready: the **error code**, the **correlation ID** from the user's error message, the
approximate time, and the affected username. A code and a correlation ID together usually
identify the exact audit entry and log line.

Support chat never receives message content, and no diagnostics are uploaded automatically.
