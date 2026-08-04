# Threat model

**Status:** Phase 0 — awaiting sign-off
**Method:** STRIDE per trust boundary, with an explicit accepted-risk register
**Scope:** v1 — single server, Windows clients, server-side encryption with admin-recoverable keys

---

## 1. Assets

Ranked by consequence of loss.

| # | Asset | Why it matters |
| --- | --- | --- |
| A1 | Message content and history | The product's reason to exist. Often commercially or legally sensitive. |
| A2 | Transferred files | Frequently the most sensitive payload in the system. |
| A3 | Root KEK and derived keys | Compromise exposes A1 and A2 wholesale, including from backups. |
| A4 | AD service-account credential | A foothold into the customer's directory, i.e. beyond this product. |
| A5 | User credentials and session tokens | Impersonation of any user. |
| A6 | Audit log integrity | The only evidence of what happened; also a compliance obligation. |
| A7 | Social graph and presence metadata | Who talks to whom, and when. Sensitive even without content. |
| A8 | License file and signing key | Vendor revenue integrity. |
| A9 | Service availability | An internal IM outage halts organisational communication. |

Note that A7 is listed as an asset in its own right. Communication metadata is not
protected by content encryption at all, and in some contexts — legal, HR, journalistic — it
is more revealing than the messages.

---

## 2. Attacker profiles

| # | Attacker | Capability | In scope? |
| --- | --- | --- | --- |
| P1 | External network attacker | On-path on the LAN/WAN; can reach the server's listener | Yes |
| P2 | Malicious internal user | Valid low-privilege account, can craft arbitrary protocol traffic | Yes |
| P3 | Compromised client endpoint | Full control of one user's machine, including its local cache | Yes |
| P4 | Malicious or compromised IT admin | Console access, server OS access, database access | **Partially — see accepted risks** |
| P5 | Compromised server | Full control of the Communication Server host | Partially |
| P6 | Database-only access | A stolen backup, or read access to storage | Yes |
| P7 | Malicious vendor (Owner tier) | Controls licensing and support-chat infrastructure | Yes |
| P8 | Lost/stolen unlocked device | Physical access to a logged-in workstation | Yes |

P4 is the profile that the confirmed encryption model deliberately does **not** fully
defend against. That is stated up front rather than discovered later.

---

## 3. Trust boundaries

```
  TB6 ┌──────────────── Owner tier (vendor) ─────────────────┐
      │                                                       │
══════╪═══════════════════ internet ═════════════════════════╪══════
      │                                                       │
  TB1 │  Client ──► Comm Server        TB5  Server ──► AD DC  │
  TB2 │  Admin  ──► Comm Server        TB3  Server ──► DB     │
  TB7 │  Client local cache            TB4  Server ──► files  │
      └───────────────────────────────────────────────────────┘
```

---

## 4. STRIDE by boundary

### TB1 — Client ↔ Communication Server

| Threat | Vector | Mitigation |
| --- | --- | --- |
| **S**poofing (server) | On-path attacker presents a rogue certificate; internal CAs are often sloppily managed | TLS 1.3 + **SPKI pinning**, two pins for rollover, **no user override** on mismatch (`NET-104`) |
| **S**poofing (client) | Stolen session token replayed | Tokens are 256-bit CSPRNG, stored hashed; bound to device fingerprint; short idle timeout |
| **T**ampering | Message mutation in flight | TLS 1.3 AEAD; server timestamps and `seq` are authoritative, never client-supplied |
| **R**epudiation | "I never sent that" | Server-side attribution at ingress, immutable hash-chained audit log |
| **I**nformation disclosure | Traffic interception | TLS 1.3 only; TLS ≤1.2 refused outright |
| **D**enial of service | Message/connection flooding | Per-user and per-IP rate limits, bounded per-connection send queues, connection caps |
| **E**levation | Client requests another user's conversation or file | Every hub and REST call re-checks membership server-side; a resource ID is never treated as authority |

The pin-mismatch decision deserves emphasis: a "connect anyway?" button converts a hard
cryptographic guarantee into a user-education problem, and user education loses. Recovery
from a genuine certificate change is an IT action, not an end-user click.

### TB2 — Admin Console ↔ Communication Server

| Threat | Vector | Mitigation |
| --- | --- | --- |
| **S** | Admin impersonation | Same auth as clients plus mandatory MFA for `ServerAdmin` where the IdP supports it; separate admin permission scope |
| **T** | Unauthorised config change | Every mutation audited with actor, before/after values, and outcome |
| **R** | Admin denies an action | Hash-chained audit; `Auditor` role separable from `ServerAdmin` |
| **I** | Bulk export of user data | Export is a discrete permission, rate-limited, and loudly audited |
| **D** | Admin API abuse | Admin endpoints rate-limited independently of client traffic |
| **E** | Admin grants themselves owner-tier rights | `roles.scope` enforced at assignment; owner-tier permissions are not representable in a server-scope role |

### TB3 — Server ↔ Database

| Threat | Vector | Mitigation |
| --- | --- | --- |
| **S** | Rogue client connects to Postgres | `sslmode=verify-full`, certificate auth or strong scram credential, `pg_hba` restricted to the server host |
| **T** | Direct row edits to forge or move messages | AAD binds `conversation_id ‖ message_id ‖ sender_id ‖ key_version` — relocated or edited ciphertext fails its tag check |
| **T** | Audit log rewriting | Hash chain + Ed25519 checkpoints; `UPDATE`/`DELETE` revoked from the application role |
| **R** | — | Audit chain as above |
| **I** | Stolen backup (P6) | Content is AES-256-GCM encrypted; the KEK lives outside the database, in DPAPI-NG/TPM/HSM |
| **D** | Connection exhaustion | Bounded pool, statement timeouts, health checks |
| **E** | SQL injection | EF Core parameterised queries throughout; no string-built SQL; the application role holds no DDL rights |

Keeping the KEK out of the database is the control that makes TB3 meaningfully different
from "the data is in the clear". A backup tape, a replica, or a stolen disk yields
ciphertext and nothing else.

### TB4 — Server ↔ File store

| Threat | Vector | Mitigation |
| --- | --- | --- |
| **T** | Chunk substitution, reordering, truncation | Per-chunk AEAD with the chunk index in the AAD, plus a signed chunk manifest |
| **I** | Reading files off the share | Chunks encrypted at rest under a per-file DEK |
| **E** | Path traversal via crafted filename | Paths derive solely from a server-generated `storage_key`; the user-supplied name never reaches the filesystem |
| **D** | Disk exhaustion | Per-user quota, license file-size cap, orphaned-upload reaper |
| — | Malware distribution via the relay | Optional AV scan before a file is downloadable; unscanned files are not served |

### TB5 — Server ↔ Active Directory

| Threat | Vector | Mitigation |
| --- | --- | --- |
| **S** | Rogue DC / LDAP referral chasing | LDAPS with full certificate validation; referral chasing disabled |
| **T** | Injected sync data | LDAP filters parameterised and escaped (RFC 4515); sync never grants roles, only identity attributes |
| **I** | Bind credential theft | gMSA preferred (no stored secret); otherwise encrypted under the root KEK, never in a config file |
| **E** | Over-privileged service account | Read-only account documented and validated at configuration time, with a warning if it holds write rights |
| **D** | Sync storm against the DC | Incremental `uSNChanged` sync, backoff, bounded page size |

LDAP injection is a real and under-appreciated path here: a user-controlled attribute
interpolated into a filter can widen a query's scope. Filters are built through an escaping
API, never by concatenation.

### TB6 — Customer ↔ Owner tier (vendor)

| Threat | Vector | Mitigation |
| --- | --- | --- |
| **S** | Forged license | Ed25519 signature, vendor public key compiled into the server binary |
| **S** | Impersonated Owner endpoint | mTLS with pinned vendor certificate |
| **T** | License tampering | Signature covers the exact bytes; the raw signed document is retained verbatim |
| **I** | **Vendor over-collection (P7)** | Telemetry is opt-in, aggregate counts only — no usernames, no content, no social graph. Wire format documented so a customer can verify with a proxy. |
| **I** | Support chat leaking internal data | Support chat is admin-initiated, scoped to a session, transcript retained locally and audited; no automatic diagnostic upload |
| **D** | Vendor outage bricks the customer | **Offline-first licensing.** Signature and dates validate locally; heartbeat is optional; air-gapped operation is fully supported |
| **E** | Vendor reaches into the customer server | No inbound path from Owner to customer. All vendor-facing traffic is outbound-only. |

The "no inbound path" property is worth stating plainly to prospective customers: the
vendor cannot reach into a deployment even if the vendor wanted to, or were compelled to.

### TB7 — Client endpoint (local cache)

| Threat | Vector | Mitigation |
| --- | --- | --- |
| **I** | Cached history read from disk (P3, P8) | Local cache encrypted with a DPAPI-protected per-user key; cleared on logout when policy requires |
| **I** | Screen left unlocked (P8) | Idle auto-logout per license policy, enforced server-side too |
| **T** | Local database edited to fake history | Local cache is a cache, not a record; the server is authoritative and re-syncs |
| **E** | Malware scraping process memory (P3) | Out of scope — see below |

---

## 5. Accepted risks

These are deliberate decisions, not oversights. Each should be understood by whoever signs
off, and each belongs in customer-facing security documentation.

| # | Risk | Rationale | Compensating controls |
| --- | --- | --- | --- |
| **AR-1** | **A server administrator can read all message and file content.** | Direct consequence of the confirmed admin-recoverable model. E2EE would block compliance archiving, eDiscovery, and AV scanning — the customer chose archiving. | KEK in TPM/HSM so keys can be *used* but not *extracted*; every bulk export and key access is audited; `Auditor` role separable from `ServerAdmin`; external audit anchoring |
| **AR-2** | **A full server compromise (P5) exposes all content.** | The server necessarily holds the keys in order to encrypt, index, scan, and archive. | Hardening guide, least-privilege service account, network segmentation, TPM-bound keys, alerting on anomalous export volume |
| **AR-3** | **Communication metadata (A7) is not encrypted at rest.** | Sender, recipients, timing, and sizes must be queryable for routing, delivery, and retention. | Documented explicitly; metadata access is audited; presence visibility is scoped to shared conversations |
| **AR-4** | **A plaintext-derived search index weakens at-rest protection.** | Encrypted text is not searchable; server-side search was chosen for quality. See [data model §2](data-model.md#messages). | Flagged for explicit Phase 1 decision; alternatives (client-side, blind index) documented |
| **AR-5** | **A compromised endpoint (P3) exposes that user's messages.** | No server-side control can protect a machine the attacker already owns. | Local cache encryption, device blocking, session revocation, idle logout |
| **AR-6** | **Audit is tamper-*evident*, not tamper-*proof*.** | An attacker holding both database write access and the signing key can rewrite and re-sign. | TPM/HSM-held signing key; external anchoring to SIEM and/or Owner tier so a local rewrite contradicts an uncontrolled copy |
| **AR-7** | **NTLM, if enabled, is relay-attackable.** | Some environments genuinely cannot use Kerberos. | Disabled by default; enabling requires explicit admin action, raises a console warning, and is audited |
| **AR-8** | **Single-server v1 has no HA.** | Confirmed scope decision. | Documented backup/restore with RTO/RPO targets; graceful client reconnect with backlog replay |

---

## 6. Explicitly out of scope for v1

Stated so the boundary is a decision rather than an omission:

- Endpoint malware and memory scraping on a compromised client.
- Physical attacks on the server host (evil maid, DMA, cold boot).
- Supply-chain compromise of .NET, NuGet dependencies, or the build toolchain. *(Partially
  mitigated in Phase 7 by dependency pinning, lockfiles, and SBOM generation.)*
- Traffic-analysis resistance — message sizes and timing are observable to a network
  attacker even under TLS.
- Denial of service originating from the customer's own network at volumes requiring
  network-layer scrubbing.
- Coercion of the vendor to issue a malicious update. *(Partially mitigated by signed
  installers and update verification.)*

---

## 7. Security requirements traceability

| Requirement | Where it is satisfied |
| --- | --- |
| TLS 1.3 everywhere | [Architecture §2.1](architecture.md#21-transport-security) |
| Certificate pinning | [Architecture §2.1](architecture.md#21-transport-security) |
| Encryption at rest | [Architecture §6](architecture.md#6-cryptography), `conversation_keys`, `files` |
| Argon2id | [Architecture §3.2](architecture.md#32-password-storage-local-accounts) |
| Signed, tamper-evident audit log | [Architecture §6.4](architecture.md#64-tamper-evident-audit-log), `audit_log`, `audit_checkpoints` |
| RBAC across three tiers | [Architecture §3.4](architecture.md#34-authorization-rbac), `roles.scope` |
| License enforcement | [Architecture §8](architecture.md#8-licensing) |
| AD integration | [Architecture §7](architecture.md#7-active-directory-integration) |

---

## 8. Review triggers

This document is re-reviewed when any of the following occurs: the encryption model
changes; a new trust boundary appears (federation, mobile, HA backplane); an authentication
mechanism is added or removed; the search-index decision (AR-4) is settled; or a
penetration test is completed. Each review is versioned in git rather than edited in place,
so the reasoning history survives.
