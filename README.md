# Messenger — Self-Hosted Enterprise Instant Messenger

A private, self-hosted corporate IM platform for LAN/WAN/enterprise networks. Internal
1:1 chat, group chat, file transfer, and presence, with no cloud dependency and no
third-party message relay. All customer data stays on customer infrastructure.

> **Status: server-side complete, security- and production-reviewed; Windows packaging not
> started.** 307 tests pass, including end-to-end HTTP tests and a PostgreSQL-backed
> integration suite. The security-critical core is built and tested; the LDAPS binding, SSO,
> WPF clients, Windows Service host, and installers are **not implemented**. See
> [What is and isn't built](#what-is-and-isnt-built).

## Confirmed decisions

The four decisions flagged for confirmation in the build spec have been settled:

| Decision | Choice |
| --- | --- |
| Encryption at rest | **Server-side with admin-recoverable keys.** Enables compliance archiving, eDiscovery, admin search, and server-side AV scanning. Explicitly *not* E2EE. See [ADR-0002](docs/adr/0002-encryption-model.md). |
| Stack | **.NET 8 / C#**, ASP.NET Core + SignalR server, WPF clients, **PostgreSQL 16**. See [ADR-0001](docs/adr/0001-stack.md). |
| Client platforms | **Windows-only for v1**, WPF. Windows 10 1809+ / 11 / Server 2019+. |
| Topology | **Single server for v1.** HA/clustering deferred. In-process SignalR, no backplane. See [ADR-0003](docs/adr/0003-topology.md). |

The encryption choice is the consequential one: **an administrator with server access can
read all message and file history.** That is the deliberate trade-off made to keep
compliance archiving possible. It is documented as an accepted risk in the
[threat model](docs/threat-model.md#5-accepted-risks).

## Documents

| Document | Purpose |
| --- | --- |
| [Architecture](docs/architecture.md) | Tiers, components, protocols, trust boundaries, auth, crypto, licensing, delivery semantics. |
| [Data model](docs/data-model.md) | PostgreSQL schema, indexes, retention, migration strategy. |
| [Threat model](docs/threat-model.md) | Assets, attacker profiles, STRIDE per boundary, mitigations, accepted risks. |
| [Security review](docs/security-review.md) | Findings from the pre-merge review, fixes, and what remains. |
| [Production review](docs/production-review.md) | Concurrency, memory, and deployment findings from the follow-up pass. |
| [Error codes](docs/error-codes.md) | Numbered catalog — AUTH/NET/LIC/AD/FILE/SRV — with cause and remediation. |
| [Deployment guide](docs/deployment.md) | Prerequisites, ports, AD service account, certificates, backup/restore, upgrades, and current status. |
| [Admin quick reference](docs/quick-reference-admin.md) | One page for daily operations and incidents. |
| [User quick reference](docs/quick-reference-user.md) | One page for end users. |
| [ADRs](docs/adr/) | Architecture decision records. |

## Repository layout

Projects marked *(not built)* are named here as the target structure; everything else
exists and is tested.

```
messenger/
├── docs/                          Architecture, data model, threat model, error codes, ADRs
├── src/
│   ├── Messenger.Contracts/       Wire DTOs, hub interfaces, error codes (shared by all tiers)
│   ├── Messenger.Core/            Domain model, business rules, no I/O dependencies
│   ├── Messenger.Crypto/          Envelope encryption, key hierarchy, audit hash chain
│   ├── Messenger.Data/            EF Core context, entities, migrations
│   ├── Messenger.Server/          ASP.NET Core host, SignalR hubs, REST admin API
│   ├── Messenger.Licensing/       Licence parsing, Ed25519 verification, grace handling
│   ├── Messenger.Server.Service/  Windows Service wrapper            (not built)
│   ├── Messenger.Client.Wpf/      End-user Windows app               (not built)
│   ├── Messenger.Admin.Wpf/       IT admin management console        (not built)
│   └── Messenger.Owner/           Vendor licensing/telemetry service (not built)
├── tests/                         Unit, integration, and end-to-end test projects
└── deploy/                        WiX installers, service config     (not built)
```

## Build phases

| Phase | Scope | State |
| --- | --- | --- |
| 0 | Architecture, data model, threat model | **Complete** |
| 1 | Server + auth + 1:1 chat | **Complete** |
| 2 | Groups + presence | **Complete** |
| 3 | File transfer | **Complete** |
| 4 | Active Directory integration | **Partial** — sync engine complete and tested; LDAPS binding not written |
| 5 | Admin console | **Partial** — REST API complete and tested; WPF UI not written |
| 6 | Licensing + support chat | **Partial** — licensing complete and tested; Owner tier not written |
| 7 | Installers + documentation | **Partial** — docs complete; installers and service host not written |

Each phase delivers runnable code with tests. Nothing is marked complete while it is a stub.

## What is and isn't built

| Area | Status |
| --- | --- |
| AES-256-GCM message sealing, identifiers bound into the AAD | Built, tested |
| AES-KW (RFC 3394) key wrapping, verified against the published vector | Built, tested |
| Per-conversation DEKs with versioned rotation; per-file DEKs; KEK escrow | Built, tested |
| Argon2id (PHC format, transparent cost upgrade, soft backoff, timing-equalised) | Built, tested |
| Opaque server-side sessions: idle + absolute expiry, device binding, instant revocation | Built, tested |
| 1:1 and group chat, at-least-once delivery, idempotent retry, store-and-forward | Built, tested |
| Group history visibility windows (no retroactive access on join) | Built, tested |
| Presence with auto-away, scoped to conversation peers | Built, tested |
| File transfer: chunked, resumable, per-chunk AEAD, manifest, crypto-shred delete | Built, tested |
| Audit log: SHA-256 chain, Ed25519 checkpoints, fail-closed writes | Built, tested |
| Directory sync engine, reconciliation rules, RFC 4515/4514 escaping | Built, tested |
| Licensing: Ed25519 signing, offline validation, read-only grace, enforcement | Built, tested |
| Admin REST API + SignalR hub | Built, tested |
| RBAC: five seeded roles, per-route permissions, cross-tier escalation refused | Built, tested |
| Durable root key store with escrow; server refuses to start without a passphrase | Built, tested |
| TLS 1.3 enforcement, HSTS, security headers, rate limiting | Built, tested |
| **LDAPS wire binding** | **Not built** — engine is complete behind `IDirectoryProvider`; needs a domain controller |
| **Kerberos / NTLM SSO** | **Not built** — local Argon2id auth works |
| **DPAPI-NG / TPM / PKCS#11 key stores** | **Not built** — abstraction and escrow complete; shipped provider is development-only |
| **WPF client and admin console** | **Not built** — all admin logic sits behind the tested REST API |
| **Windows Service host, MSI installers, code signing** | **Not built** |
| **Owner tier** (activation, telemetry, support chat) | **Not built** — offline licence validation is complete and is all that operation requires |

The server is usable today for **non-domain deployments with local accounts**, driven
through the REST API and SignalR hub. It is **not a turnkey Windows product**: no installer,
no service host, no GUI, no working AD binding. The remaining work is Windows-specific
integration and packaging, not architecture.

## Running it

```bash
# Requires .NET 8 SDK and PostgreSQL 16
dotnet build
dotnet test                        # 259 tests; database-backed tests skip without a connection

# Include the PostgreSQL-backed suites (48 more: integration + end-to-end HTTP)
export MESSENGER_TEST_CONNECTION='Host=localhost;Port=5432;Database=messenger;Username=postgres;Password=postgres'
dotnet test                        # 307 tests

# Apply the schema. Migrations never run automatically at startup — an unattended
# restart must not reshape a production database.
export MESSENGER_CONNECTION='Host=localhost;Port=5432;Database=messenger;Username=messenger;Password=messenger'
dotnet ef database update --project src/Messenger.Data --startup-project src/Messenger.Server
```

## Project status

Three environment constraints shape what remains:

1. **Code-signing certificates.** Signed MSI/EXE installers need an OV or EV certificate on
   an HSM or token. It cannot be provisioned from this repository — supply it in the release
   pipeline.
2. **Active Directory.** LDAPS, Kerberos, and NTLM cannot be exercised without a domain
   controller. The sync engine is fully covered by tests through a provider abstraction, but
   the wire binding needs a real domain to build against.
3. **Windows build agent.** WPF targets `net8.0-windows` and will not compile on Linux. The
   CI job exists in `.github/workflows/ci.yml`, disabled until the client work lands.

### Decisions made without sign-off

Three decisions that were open at the end of Phase 0 were settled by the engineering team
after the product owner declined to choose and asked for work to continue. They are recorded
in [ADR-0005](docs/adr/0005-phase1-open-decisions.md), which is marked **provisional**.

The one worth a second look is **OD-1**: server-side search will use a `tsvector` derived
from message plaintext, which means a reader with database access recovers much of the
message content from the index alone. It is consistent with the already-confirmed
admin-recoverable model, and it is cheap to reverse — but only until search actually ships.

## Licence

Proprietary. All rights reserved.
