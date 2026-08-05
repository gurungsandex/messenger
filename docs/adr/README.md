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
| [0005](0005-phase1-open-decisions.md) | Search index, read receipts, key store | Accepted (provisional) |

## Open decisions

Recorded here so they are not lost between phases.

| # | Decision needed | Blocking | Reference |
| --- | --- | --- | --- |
| OD-4 | Whether audit checkpoint anchoring to the Owner tier is offered, given it implies vendor connectivity | Phase 6 | [AR-6](../threat-model.md#5-accepted-risks) |

### Resolved

OD-1 (search index), OD-2 (read receipts), and OD-3 (key store) are settled in
[ADR-0005](0005-phase1-open-decisions.md). That ADR is marked **provisional**: the decisions
were made by the engineering team after the product owner declined to choose and instructed
work to continue. OD-1 in particular weakens a security property and is the one worth
revisiting — it is cheap to reverse until search actually ships.
