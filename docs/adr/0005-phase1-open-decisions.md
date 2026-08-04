# ADR-0005 — Phase 1 decisions: search index, read receipts, key store

**Status:** Accepted (provisional — see below)
**Date:** 2026-08-04
**Supersedes:** OD-1, OD-2, OD-3 in the open-decisions register

## Context

Three decisions were left open at the end of Phase 0 and were blocking Phase 1 schema work.
They were put to the product owner, who did not select an option and instructed the team to
proceed without approval. They are recorded here as **decisions made by the engineering
team under a stated assumption**, not as decisions signed off by the product owner.

That distinction matters for OD-1 in particular, which weakens a security property. If any
of these is wrong, this ADR is the place to reverse it — and OD-1 is materially more
expensive to reverse after data exists.

## OD-1 — Message search index: server-side plaintext tsvector

**Decision:** search will use a PostgreSQL `tsvector` column derived from message plaintext,
with a GIN index.

**Rationale:** the confirmed encryption model (ADR-0002) already gives an administrator
access to all message content for archiving and eDiscovery. A search index derived from
that same plaintext does not hand an administrator anything they did not already have, so
it is not the weakest link in the design. The alternatives each cost something real:
client-side-only search cannot find history a device has not synced, and a blind keyword
index breaks stemming, prefix, and phrase matching while remaining vulnerable to frequency
analysis.

**Consequence, restated plainly:** a reader with database access recovers a great deal of
message content from the search index alone, without touching the ciphertext. This is
recorded as [AR-4](../threat-model.md#5-accepted-risks) and belongs in customer-facing
security documentation alongside AR-1.

**Not yet implemented.** Phase 1 ships message storage and retrieval; the `search_tsv`
column and its GIN index land with the search feature. The column is deliberately absent
from the initial migration rather than added unused, so that reversing this decision before
search is built costs nothing.

## OD-2 — Read receipts: admin-configurable, on by default

**Decision:** an organisation-wide setting, defaulting to enabled.

**Rationale:** users arriving from consumer messengers expect receipts, so on-by-default
matches expectation. Organisations that treat read tracking as surveillance — and in some
jurisdictions must consult a works council before enabling it — can switch it off wholesale.

**Implementation note:** when disabled, `read_at` is never written, rather than written and
hidden. `MessageService.MarkReadAsync` takes the policy and downgrades the recipient state
to `Delivered` instead of `Read`. "Recorded but not displayed" would not satisfy an
organisation that objects to the recording itself, and this is covered by a test.

Per-user opt-out was rejected for v1: it is reciprocal (disabling sending must disable
receiving, or it is a one-way mirror), which needs UI explanation and per-user state on
every receipt write.

## OD-3 — Key store: provider abstraction, portable default, mandatory escrow

**Decision:** `IKeyStoreProvider` with wrap/unwrap/escrow. Phase 1 ships
`PassphraseKeyStoreProvider`; DPAPI-NG, TPM, and PKCS#11 providers follow with the Windows
service work.

**Rationale:** the abstraction costs almost nothing now and avoids rewrapping every DEK on
live deployments later. The portable provider is what lets the server and its test suite run
on non-Windows build agents at all.

**The escrow requirement is the substantive part.** `ExportEscrow` wraps the KEK under an
administrator passphrase using PBKDF2-HMAC-SHA256 at 600 000 iterations, then AES-256-GCM.
The installer must require this export, verify it can be re-imported, and only then permit
first use.

The reason is a failure mode that is total and silent until the day it matters: a
machine-bound KEK with no escrow means **a dead server is unrecoverable message history even
with perfect database backups.** The ciphertext restores fine and nothing can read it. No
error appears until the restore is attempted, typically during an incident. Escrow is
therefore an installer gate, not a documented recommendation.

`PassphraseKeyStoreProvider` holds the KEK in process memory and is **not** a production
provider. It is documented as such in the type's own summary, so the distinction survives
contact with a developer who has not read this ADR.

## Status of this ADR

Marked provisional because the product owner declined to choose. Any of the three can be
revisited. Reversal cost, roughly:

| Decision | Cost to reverse |
| --- | --- |
| OD-2 receipts | Trivial — a setting, already implemented both ways |
| OD-3 key store | Low before deployment; a KEK migration afterwards |
| OD-1 search | Low until search ships; high once a plaintext index exists over real history |
