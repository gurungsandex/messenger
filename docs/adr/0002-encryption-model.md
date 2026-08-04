# ADR-0002 — Encryption model: server-side with admin-recoverable keys

**Status:** Accepted
**Date:** 2026-08-04
**Decision made by:** Product owner, confirmed against the build spec's `[CONFIRM]` gate

> This is the most consequential decision in the project. It is deliberately irreversible
> in one direction: history encrypted under this model cannot retroactively gain E2EE's
> guarantees.

## Context

The build spec required messages and files to be encrypted at rest, and flagged that
server-side encryption with admin-recoverable keys and true end-to-end encryption are
mutually exclusive — E2EE blocks compliance archiving. The spec asked for an explicit
decision rather than a silent one.

## Decision

**Server-side encryption with admin-recoverable keys.** The Communication Server handles
plaintext and holds the key hierarchy.

Key hierarchy:

```
Root KEK (AES-256; DPAPI-NG, Windows CNG/TPM, or PKCS#11 HSM — never in the database)
  └─ AES-KW (RFC 3394) wrapping
       ├─ Conversation DEK  (AES-256, per conversation, versioned, rotating)
       ├─ File DEK          (AES-256, per file)
       └─ Audit signing key (Ed25519)
```

Content encryption is AES-256-GCM. Identifiers are bound into the AAD so ciphertext cannot
be silently relocated between messages, conversations, or chunk positions by an attacker
with database write access.

## Rationale

The requirement set decides this. The spec asks for compliance archiving, admin-visible
audit logs, server-side message search, and AV scanning of transferred files. Every one of
those needs server-side plaintext access. True E2EE would make all four impossible — not
harder, impossible — and no amount of engineering reconciles them.

The secondary costs of E2EE reinforce the choice for a v1 enterprise product: device key
enrolment and verification UX, multi-device sender-key fan-out, key backup and recovery,
and the reality that losing all devices means losing all history. Each is a substantial
subsystem in its own right.

### Two refinements made during design

**Per-conversation DEKs, not per-message.** The original sketch proposed a per-message DEK.
That adds a wrapped key, its metadata, and a wrap operation to every message for no
security gain: the compromise domain is the KEK either way, because the KEK unwraps
everything beneath it. Per-conversation keying with enforced rotation gives identical
recovery properties at a fraction of the storage and CPU cost.

**Files keep per-file DEKs.** Files have independent lifecycles — individually shared,
scanned, retained, exported, and deleted. A per-file key makes crypto-shredding a single
file possible: destroy the key and the content is unrecoverable even from a restored
backup of the file store.

### Nonce management

Random 96-bit GCM nonces carry a birthday bound, so conversation keys rotate at 2^24
messages, 90 days, or on admin action — whichever comes first. File chunk nonces use a
32-bit random prefix plus a 64-bit counter, removing collision risk within a file entirely.

## Consequences

**Accepted, and recorded as [AR-1](../threat-model.md#5-accepted-risks):** an administrator
with server access can read all message and file content. A full server compromise
(AR-2) exposes everything. These are inherent, not incidental.

**Compensating controls:**

- The KEK lives in a TPM or HSM where possible, so keys can be *used* but not *extracted* —
  a database dump, a backup tape, or a stolen disk yields ciphertext only.
- Every bulk export and key access is audited.
- The `Auditor` role is separable from `ServerAdmin`, enabling separation of duties.
- Audit checkpoints can be anchored externally, so a local rewrite contradicts a copy the
  customer's admin never controlled.

**Unresolved and deferred to Phase 1:** server-side full-text search requires a
plaintext-derived index, which is roughly as sensitive as the messages themselves. Three
options are documented in the [data model](../data-model.md#messages) and recorded as
[AR-4](../threat-model.md#5-accepted-risks). This needs an explicit decision before Phase 1
schema work lands.

**Customer-facing obligation:** this model must be stated plainly in security
documentation. Customers evaluating the product will ask whether it is end-to-end
encrypted. The answer is no, and the reason is that they asked for archiving. Any marketing
that implies otherwise would be false.

## Alternatives rejected

**True E2EE (libsignal or MLS).** Rejected because it is incompatible with the stated
archiving, search, and scanning requirements.

**Server-side now with an E2EE-capable envelope.** Genuinely attractive — a common envelope
format (`{alg, key_id, recipients[], ciphertext}`) whose `recipients[]` could later hold
device public keys, letting E2EE be enabled per-conversation by policy. Rejected for v1 as
scope, but the envelope design deliberately does not foreclose it: the message schema
carries `aad_version` and `key_id` indirection precisely so a future mode can be added
without a data migration. Worth revisiting for v2.
