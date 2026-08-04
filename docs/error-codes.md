# Error-code catalogue

**Status:** Phase 0 — awaiting sign-off
**Stability contract:** Codes are permanent. A code is never reused for a different
meaning and never renumbered. A retired code is marked deprecated and left in place.

---

## How codes are used

Every user-visible failure carries a code. Codes appear in the client UI, the admin
console, operational logs, and the audit log, so a support call starts with a code rather
than a paraphrase of a dialog box.

**Format:** `CATEGORY-NNN` — e.g. `AUTH-104`.

| Category | Domain |
| --- | --- |
| `AUTH` | Authentication, sessions, authorization |
| `NET` | Connectivity, TLS, certificate pinning, protocol |
| `LIC` | Licensing and enforcement |
| `AD` | Active Directory connection and synchronisation |
| `FILE` | File upload, download, scanning, quota |
| `SRV` | Server startup, configuration, storage, cryptography |

**Number ranges** within a category group related failures (1xx, 2xx, 3xx …), described at
the head of each section.

**Audience** column: **U** = shown to end users, **A** = shown to administrators,
**L** = log/audit only.

### A deliberate constraint on authentication errors

Login failures return a **generic message to the end user** and the specific code only to
the log and the admin console. Telling an unauthenticated caller the difference between
"no such user", "wrong password", and "account disabled" hands an attacker a free account
enumeration oracle. The codes below are therefore precise for diagnostics but are not all
individually surfaced at the login prompt — the `Audience` column marks which ones are.

---

## AUTH — Authentication and authorization

`1xx` credentials · `2xx` sessions · `3xx` authorization · `4xx` account state

| Code | Meaning | Cause | Remediation | Audience |
| --- | --- | --- | --- | --- |
| `AUTH-101` | Invalid credentials | Username or password incorrect | Re-enter credentials. Generic "sign-in failed" is shown to the user; the specific reason appears in the admin console. | U (generic) / A |
| `AUTH-102` | Account not found | No local or synced user matches | Verify the username. If AD-sourced, confirm the user is in the sync scope and the last sync succeeded. | A |
| `AUTH-103` | Account disabled | Deactivated by an admin, or deactivated by AD sync | Reactivate in the console, or re-enable in AD and re-sync. | U / A |
| `AUTH-104` | Account temporarily locked | Too many failed attempts; soft backoff active | Wait for `lockout_until`, or clear the lockout in the console. Review the audit log for a possible password-spraying attempt. | U / A |
| `AUTH-105` | Password expired | Exceeds the configured maximum age | User must set a new password at next sign-in. | U |
| `AUTH-106` | Password change required | `must_change_password` is set | Complete the forced password change. | U |
| `AUTH-107` | New password rejected by policy | Fails length, complexity, or reuse rules | Choose a password meeting the policy shown. Policy is configurable in the console. | U |
| `AUTH-108` | Password reuse rejected | Matches one of the last N passwords | Choose a password not in recent history. | U |
| `AUTH-109` | Kerberos ticket validation failed | Clock skew, wrong SPN, or no ticket obtainable | Verify the server SPN is registered (`setspn -L`), the server is domain-joined, and clock skew is under 5 minutes. See `AD-104`. | A |
| `AUTH-110` | NTLM authentication refused | NTLM fallback disabled (default) | Use Kerberos. If NTLM is genuinely required, enable it explicitly in the console — note it is relay-attackable and doing so is audited. | A |
| `AUTH-111` | Authentication method not permitted | The method is disabled for this account or tenant policy | Use a permitted method, or adjust policy. | A |
| `AUTH-112` | MFA required but not satisfied | `ServerAdmin` sign-in without MFA | Complete the MFA challenge. MFA is mandatory for server-admin roles where the IdP supports it. | U / A |
| `AUTH-113` | Argon2id verification error | Malformed or truncated stored hash | Indicates data corruption. Reset the affected password and check database integrity. | L / A |
| `AUTH-201` | Session expired (idle) | Idle longer than the license idle timeout | Sign in again. The timeout comes from license policy and is enforced server-side. | U |
| `AUTH-202` | Session expired (absolute) | Exceeded the maximum session lifetime | Sign in again. | U |
| `AUTH-203` | Session revoked by administrator | An admin terminated the session | Contact IT if unexpected. | U / A |
| `AUTH-204` | Session revoked (password changed) | Password change invalidates all sessions | Sign in with the new password. | U |
| `AUTH-205` | Session token invalid | Malformed, unknown, or already-revoked token | Sign in again. Repeated occurrences from one source may indicate token-replay attempts — check the audit log. | U / L |
| `AUTH-206` | Session bound to a different device | Token presented from a device other than the one it was issued to | Sign in again on this device. Investigate as possible token theft. | U / A |
| `AUTH-207` | Device blocked | The device is marked blocked (e.g. reported lost) | Unblock in the console if appropriate. | U / A |
| `AUTH-208` | Concurrent session limit reached | See `LIC-104` | Sign out elsewhere, or raise the license limit. | U / A |
| `AUTH-301` | Permission denied | The role lacks the required permission | Grant the permission via a role, or perform the action as a suitably privileged user. The specific permission is named in the audit entry. | U / A |
| `AUTH-302` | Not a conversation participant | The caller is not a member of the target conversation | This is an authorization failure, not a routing error. Repeated occurrences suggest ID enumeration — review the audit log. | L / A |
| `AUTH-303` | Cross-tier privilege escalation refused | An attempt to assign an owner-tier permission to a server-scope role | Structurally disallowed. Investigate — legitimate workflows do not produce this. | A / L |
| `AUTH-304` | Role is built-in and cannot be modified | Attempt to edit or delete a seeded role | Clone the role and modify the copy. | A |
| `AUTH-305` | Cannot remove the last server administrator | Would leave the deployment unmanageable | Assign another `ServerAdmin` first. | A |
| `AUTH-401` | User already exists | Duplicate username or `objectGUID` | Choose another username, or reconcile the duplicate AD object. | A |
| `AUTH-402` | Cannot modify an AD-sourced attribute | The attribute is directory-owned and would be overwritten at next sync | Change it in Active Directory instead. | A |
| `AUTH-403` | Self-modification refused | An admin attempting to deactivate or de-privilege their own account | Have another administrator perform the action. | A |

---

## NET — Connectivity, TLS, protocol

`1xx` transport and TLS · `2xx` protocol and framing

| Code | Meaning | Cause | Remediation | Audience |
| --- | --- | --- | --- | --- |
| `NET-101` | Cannot reach server | Host unresolvable, or nothing listening | Verify the server address and that TCP/8443 is open. Check the service is running. | U / A |
| `NET-102` | Connection timed out | Network path blocked or congested | Check firewall rules between client subnet and server on 8443. | U / A |
| `NET-103` | TLS handshake failed | No shared TLS 1.3 cipher suite, or protocol downgrade attempt | The server requires TLS 1.3. Verify the client OS supports it (Windows 10 1809+) and that no TLS-inspecting middlebox is downgrading the connection. | A |
| `NET-104` | **Certificate pin mismatch** | The presented key does not match a pinned SPKI | **Treat as a possible on-path attack until proven otherwise.** If the server key legitimately changed, distribute the updated pin set via MSI property or Group Policy. This is not user-overridable by design. | U / A |
| `NET-105` | Server certificate invalid | Expired, wrong hostname, or untrusted chain | Renew or reissue the certificate; ensure the issuing CA is trusted on client machines. | A |
| `NET-106` | Server certificate expired | Past `notAfter` | Renew before expiry; the console warns from 30 days out. | A |
| `NET-107` | TLS version refused | Client offered TLS 1.2 or lower | Enable TLS 1.3 on the client. Downgrade is refused deliberately. | A |
| `NET-108` | Connection lost | Transport dropped mid-session | The client reconnects automatically with backoff and replays the backlog. Persistent recurrence points to network instability. | U |
| `NET-109` | Reconnect backoff in progress | Repeated failures; client is waiting | Wait, or retry manually. Backoff prevents a reconnect storm after a server restart. | U |
| `NET-110` | Proxy authentication required | An intervening proxy demands credentials | Configure proxy settings, or exempt the server address from proxying. | A |
| `NET-201` | Protocol version unsupported | Client and server versions incompatible | Upgrade the client. The minimum supported client version is shown in the console. | U / A |
| `NET-202` | Message too large | Exceeds the maximum message size | Send as a file attachment instead. | U |
| `NET-203` | Malformed request | Payload failed schema validation | Usually a client bug or a tampered request. Report with the correlation ID. | L / A |
| `NET-204` | Rate limit exceeded | Per-user or per-IP limit hit | Slow down; the retry-after interval is returned. Persistent hits may indicate a misbehaving client or abuse. | U / A |
| `NET-205` | Send queue overflow | The client is not consuming messages fast enough | The connection is dropped to bound server memory. The client reconnects and replays from its last `seq`. | L / A |
| `NET-206` | Request correlation ID missing | Internal contract violation | Report as a defect. | L |

---

## LIC — Licensing

`1xx` validation and enforcement · `2xx` activation and vendor connectivity

| Code | Meaning | Cause | Remediation | Audience |
| --- | --- | --- | --- | --- |
| `LIC-101` | License signature invalid | Tampered, corrupted, or not vendor-signed | Reinstall the original license file exactly as supplied. Do not edit it — any modification, including reformatting the JSON, invalidates the signature. | A |
| `LIC-102` | License expired | Past `not_after` | Renew with the vendor. The server enters read-only grace mode (default 14 days) rather than stopping: history remains readable; new sessions and new messages are refused. | U / A |
| `LIC-103` | Seat limit reached | Activating a user would exceed `max_seats` | Deactivate unused accounts or purchase additional seats. Current usage and headroom are on the console dashboard. | A |
| `LIC-104` | Per-user session limit reached | Exceeds `max_concurrent_sessions_per_user` | Sign out another device, or raise the limit with the vendor. | U / A |
| `LIC-105` | Total session limit reached | Exceeds `max_concurrent_sessions_total` | Wait for sessions to free, or increase the license. Peak-session history is in the console. | U / A |
| `LIC-106` | License not yet valid | Current time precedes `not_before` | Check the server clock; if correct, wait for the start date. | A |
| `LIC-107` | Feature not licensed | The feature is absent from `features[]` | Purchase the feature. Named features: `ad_sync`, `file_transfer`, `support_chat`. | U / A |
| `LIC-108` | No license installed | First run, or the license was removed | Install a license file via the console. The server refuses logins until one is present. | A |
| `LIC-109` | License revoked by vendor | Revocation received during heartbeat | Contact the vendor. Applies only to deployments with online activation enabled. | A |
| `LIC-110` | Grace period expired | Read-only grace window elapsed | Install a valid license. The server now refuses all logins. | U / A |
| `LIC-111` | License malformed | Not parseable as the expected document | Re-obtain the file from the vendor; it may have been corrupted in transit or altered by an email gateway. | A |
| `LIC-201` | Activation failed | Cannot reach the Owner tier | Verify outbound HTTPS/443 to the vendor endpoint. Activation is optional — offline operation is fully supported. | A |
| `LIC-202` | Heartbeat failed | Transient vendor connectivity failure | Informational. Operation continues on the locally validated license; the server retries with backoff. | A / L |
| `LIC-203` | Vendor certificate pin mismatch | The Owner endpoint's certificate did not match its pin | Do not bypass. Contact the vendor; this may indicate interception of vendor traffic. | A |
| `LIC-204` | Telemetry submission failed | Vendor endpoint unreachable | Informational. Telemetry is opt-in and never blocks operation. | L |

---

## AD — Active Directory

`1xx` connection and binding · `2xx` synchronisation

| Code | Meaning | Cause | Remediation | Audience |
| --- | --- | --- | --- | --- |
| `AD-101` | Cannot reach domain controller | DC unreachable on LDAPS/636 | Verify DNS resolution, network path, and that the DC accepts LDAPS. | A |
| `AD-102` | LDAPS certificate validation failed | Untrusted, expired, or wrong-name DC certificate | Install the issuing CA in the server's trust store, or fix the DC certificate. Plain LDAP is deliberately not offered as a fallback. | A |
| `AD-103` | Bind failed | Wrong service-account credentials, or the account is locked/expired | Verify the credential; check the account is not expired or locked in AD. | A |
| `AD-104` | Clock skew too large | Server and DC differ by more than the Kerberos tolerance | Synchronise time. Both must track the same authoritative source; skew over ~5 minutes breaks Kerberos entirely. | A |
| `AD-105` | Service account lacks read permission | Cannot read the configured base DN | Grant read on the target OUs. Write access is **not** required and should not be granted. | A |
| `AD-106` | Service account has write permission | Detected during configuration validation | Warning, not a failure. Reduce to read-only — the product never writes to the directory. | A |
| `AD-107` | Base DN not found | The configured DN does not exist | Correct the base DN. Verify with `dsquery` or ADSI Edit. | A |
| `AD-108` | gMSA retrieval failed | The server cannot retrieve the group Managed Service Account password | Confirm the host is permitted under `PrincipalsAllowedToRetrieveManagedPassword`. | A |
| `AD-109` | Referral chasing refused | The DC returned a referral | Referral chasing is disabled deliberately — an attacker-controlled referral can redirect a bind. Configure the correct DC or base DN explicitly. | A / L |
| `AD-201` | Sync failed | The run aborted; see the run report | Inspect the error detail in the run report and re-run. The previous state is unchanged; sync is transactional per batch. | A |
| `AD-202` | Sync partially completed | Some objects failed | Review per-object errors in the run report. Successfully processed objects are retained. | A |
| `AD-203` | Duplicate objectGUID | Two local users claim the same directory object | Reconcile manually — usually the result of a restored or migrated AD object. | A |
| `AD-204` | Attribute mapping error | A required attribute is missing or unmappable | Adjust the mapping, or populate the attribute in AD. Users missing a display name are skipped rather than imported blank. | A |
| `AD-205` | Sync scope too large | The result set exceeds the configured safety cap | Narrow the base DN or filter. The cap exists so an over-broad filter cannot import an entire forest by accident. | A |
| `AD-206` | Invalid LDAP filter | Filter syntax error | Correct the filter. Values are escaped per RFC 4515 automatically; do not pre-escape them. | A |
| `AD-207` | Incremental watermark lost | `uSNChanged` watermark invalid, or the DC was restored from backup | A full reconcile runs automatically. Expect one longer sync. | A / L |
| `AD-208` | Object removed from directory | A synced object no longer exists in AD | The local user is **deactivated, not deleted**, preserving history and audit trail. Purge explicitly if intended. | A |
| `AD-209` | Sync schedule overlap | A run started while the previous was still going | The new run is skipped. Lengthen the interval or narrow the scope. | A / L |

---

## FILE — File transfer

`1xx` upload · `2xx` download and scanning

| Code | Meaning | Cause | Remediation | Audience |
| --- | --- | --- | --- | --- |
| `FILE-101` | File exceeds license size limit | Larger than `max_file_bytes` | Send a smaller file or raise the limit with the vendor. Checked before any bytes transfer. | U / A |
| `FILE-102` | File type blocked by policy | The extension or detected type is on the block list | Use a permitted type. The block list is configurable in the console. | U / A |
| `FILE-103` | Quota exceeded | The user's storage quota is full | Delete old attachments or request a larger quota. | U / A |
| `FILE-104` | Server storage full | The file store has insufficient space | Free space or extend the volume. The console warns at configurable thresholds. | A |
| `FILE-105` | Upload session expired | The upload was not completed within the allowed window | Restart the upload. Partial chunks are reaped automatically. | U |
| `FILE-106` | Integrity check failed | The plaintext SHA-256 does not match the declared value | Retry. Persistent failure indicates corruption in transit or a faulty client. | U / A |
| `FILE-107` | Chunk sequence error | Missing, duplicated, or out-of-order chunk at completion | Retry the upload. Resumable uploads reuse the chunks already accepted. | U / L |
| `FILE-108` | Upload cancelled | Cancelled by the user or the connection dropped | Retry; the upload resumes from the last accepted chunk. | U |
| `FILE-109` | Filename invalid | Contains characters rejected by policy | Rename the file. Note that the stored name never influences the storage path, so this is a policy check, not a security control. | U |
| `FILE-201` | File not found | Deleted, expired, or never completed | Ask the sender to resend. | U |
| `FILE-202` | Access denied | The requester is not a participant in the conversation carrying the file | Expected for unauthorised access attempts. A file ID alone conveys no authority. | U / L |
| `FILE-203` | Scan in progress | AV scanning has not completed | Wait; the client shows scan status and enables download when clean. | U |
| `FILE-204` | File failed malware scan | The scanner flagged the content | Download is blocked. The detection detail is in the audit log; notify security. | U / A |
| `FILE-205` | Scanner unavailable | The AV engine is not responding | Depending on policy, downloads are blocked (fail-closed, default) or permitted with a warning. Fail-closed is the recommended setting. | A |
| `FILE-206` | Decryption failed | Wrong key version, or ciphertext corruption | Check the key store and `conversation_keys` / `files` key references. Escalate — this may indicate data corruption. | A / L |
| `FILE-207` | File expired under retention policy | Past its retention window | Retrieve from backup if required. The per-file key is crypto-shredded on expiry, so an expired file cannot be recovered from a later restore of the file store alone. | U / A |
| `FILE-208` | Chunk manifest mismatch | The manifest does not match the stored chunks | Tampering or corruption. Escalate; do not serve the file. | A / L |

---

## SRV — Server, configuration, storage, cryptography

`1xx` startup and configuration · `2xx` dependencies and runtime · `3xx` cryptography and data

| Code | Meaning | Cause | Remediation | Audience |
| --- | --- | --- | --- | --- |
| `SRV-101` | Service failed to start | See the accompanying code and the Windows Event Log | Address the specific underlying failure. | A |
| `SRV-102` | Configuration invalid | Malformed or missing required settings | Correct `appsettings.json`. The validation error names the offending key. | A |
| `SRV-103` | Listener port unavailable | TCP/8443 already in use | Free the port or reconfigure. `netstat -ano` identifies the holder. | A |
| `SRV-104` | Database schema version mismatch | The schema does not match the binary | Run `Messenger.Server migrate`. Migrations never run automatically at startup — an unattended restart must not reshape a production database. | A |
| `SRV-105` | Server certificate not found | The configured certificate is absent from the store | Install the certificate and confirm the service account can read its private key. | A |
| `SRV-106` | Private key not accessible | The service account lacks read rights on the key | Grant the service account read access to the private key. | A |
| `SRV-107` | Insufficient privileges | The service account cannot perform a required operation | Review the required rights in the deployment guide. | A |
| `SRV-108` | Data directory not writable | Permissions or a missing path | Create the directory and grant the service account modify rights. | A |
| `SRV-201` | Database unreachable | PostgreSQL down, or the network path is blocked | Verify the service, connection string, and `pg_hba.conf`. | A |
| `SRV-202` | Database authentication failed | Bad credentials, or a rejected TLS mode | Verify credentials and that `sslmode=verify-full` can be satisfied. | A |
| `SRV-203` | Database connection pool exhausted | Load exceeds the pool, or connections are leaking | Raise the pool size, or investigate long-running queries. Sustained occurrence is a defect signal. | A |
| `SRV-204` | Query timeout | A statement exceeded its timeout | Check database health, index bloat, and load. | A / L |
| `SRV-205` | File store unreachable | Local path missing or SMB share unavailable | Verify the path and the service account's access to it. | A |
| `SRV-206` | Health check failed | A dependency is unhealthy | Inspect `/health/ready` for the failing component. | A |
| `SRV-207` | Background job failure | A scheduled job (retention, sync, checkpoint) failed | Review the job log. Failures are retried with backoff. | A |
| `SRV-208` | Shutdown timeout exceeded | Connections did not drain within the grace period | Informational. Clients reconnect and replay their backlog; no messages are lost, since ACK implies durable. | A / L |
| `SRV-301` | Key store unavailable | DPAPI, TPM, or HSM/PKCS#11 provider not responding | **Messages cannot be encrypted or decrypted while this persists.** Verify the provider and the service account's access. Escalate immediately. | A |
| `SRV-302` | Key unwrap failed | Wrong KEK, or a corrupted wrapped key | Restore the key store from backup. Content encrypted under an unrecoverable KEK is unrecoverable — this is why key-store backup is a first-class step in the deployment guide. | A |
| `SRV-303` | Key rotation failed | Interrupted during rotation | Old key versions are retained, so history remains readable. Re-run rotation. | A |
| `SRV-304` | Message decryption failed | Tag mismatch — corruption or tampering | The AAD binds conversation, message, sender, and key version; a mismatch means the ciphertext was altered or relocated. Escalate as a potential integrity incident. | A / L |
| `SRV-305` | Audit chain verification failed | `entry_hash` chain broken at a known entry | **Treat as a security incident.** The verification report names the first bad entry. Compare against externally anchored checkpoints. | A |
| `SRV-306` | Audit checkpoint signing failed | Signing key unavailable | Audit entries still append and chain, but are unsigned until resolved. Restore signing-key access promptly. | A |
| `SRV-307` | Audit write failed | The audit log could not be written | **Fail-closed:** the audited operation is refused. An unauditable privileged action is not permitted to proceed. | A / L |
| `SRV-308` | Backup verification failed | A backup could not be validated | Investigate before relying on it. Untested backups are not backups. | A |
| `SRV-309` | Retention job aborted | Failure during retention enforcement | Review the log; the job is idempotent and safe to re-run. | A |
| `SRV-310` | Clock anomaly detected | System time moved backwards significantly | Sequence numbers and audit ordering rely on monotonicity. Investigate NTP configuration. | A / L |

---

## Reserved ranges

Left free so future work does not disturb the numbering above:

| Category | Reserved | Intended for |
| --- | --- | --- |
| `AUTH` | 500–599 | Federation and external identity providers |
| `NET` | 300–399 | HA backplane and clustering |
| `LIC` | 300–399 | Metered and consumption-based licensing |
| `AD` | 300–399 | Non-AD directories (generic LDAP, Entra ID) |
| `FILE` | 300–399 | External object storage backends |
| `SRV` | 400–499 | Clustering, replication, failover |
