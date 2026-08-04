# Architecture decision records

Each ADR captures one decision, the context that forced it, and the consequences accepted
along with it. ADRs are immutable once accepted — a decision that changes gets a new ADR
that supersedes the old one, so the reasoning history stays intact.

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](0001-stack.md) | .NET 8, ASP.NET Core + SignalR, WPF, PostgreSQL 16 | Accepted |
| [0002](0002-encryption-model.md) | Server-side encryption with admin-recoverable keys | Accepted |
| [0003](0003-topology.md) | Single-server topology for v1 | Accepted |
| [0004](0004-client-platform.md) | Windows-only WPF clients for v1 | Accepted |

## Open decisions

Recorded here so they are not lost between phases.

| # | Decision needed | Blocking | Reference |
| --- | --- | --- | --- |
| OD-1 | Message search index strategy — server-side plaintext tsvector, client-side only, or blind keyword index | Phase 1 schema | [data model §2](../data-model.md#messages), [AR-4](../threat-model.md#5-accepted-risks) |
| OD-2 | Read receipts default — on, off, or admin-configurable at first install | Phase 1 | [architecture §4.4](../architecture.md#44-receipts) |
| OD-3 | Key-store provider priority — DPAPI-NG vs. TPM vs. HSM as the shipped default | Phase 1 | [architecture §6.2](../architecture.md#62-key-hierarchy) |
| OD-4 | Whether audit checkpoint anchoring to the Owner tier is offered, given it implies vendor connectivity | Phase 6 | [AR-6](../threat-model.md#5-accepted-risks) |
