# Messenger — Self-Hosted Enterprise Instant Messenger

A private, self-hosted corporate IM platform for LAN/WAN/enterprise networks. Internal
1:1 chat, group chat, file transfer, and presence, with no cloud dependency and no
third-party message relay. All customer data stays on customer infrastructure.

> **Status: design phase.** This repository currently contains the architecture, data
> model, and threat model for sign-off. No application code has been written yet — by
> design, per the project's working agreement. See [Project status](#project-status).

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
| [Error codes](docs/error-codes.md) | Numbered catalog — AUTH/NET/LIC/AD/FILE/SRV — with cause and remediation. |
| [ADRs](docs/adr/) | Architecture decision records. |

## Repository layout

The layout below is the target structure. Directories are created as each phase lands;
only `docs/` is populated today.

```
messenger/
├── docs/                          Architecture, data model, threat model, error codes, ADRs
├── src/
│   ├── Messenger.Contracts/       Wire DTOs, hub interfaces, error codes (shared by all tiers)
│   ├── Messenger.Core/            Domain model, business rules, no I/O dependencies
│   ├── Messenger.Crypto/          Envelope encryption, key hierarchy, audit hash chain
│   ├── Messenger.Data/            EF Core context, entities, migrations
│   ├── Messenger.Server/          ASP.NET Core host, SignalR hubs, REST admin API
│   ├── Messenger.Server.Service/  Windows Service wrapper
│   ├── Messenger.DirectorySync/   LDAPS / Kerberos / AD import + scheduled re-sync
│   ├── Messenger.Licensing/       License file parsing, signature verification, enforcement
│   ├── Messenger.Client.Core/     Client transport, local store, sync, presence (no UI)
│   ├── Messenger.Client.Wpf/      End-user Windows app
│   ├── Messenger.Admin.Wpf/       IT admin management console
│   └── Messenger.Owner/           Vendor-side licensing/telemetry service + support chat
├── tests/                         Unit, integration, and end-to-end test projects
└── deploy/                        WiX installers, service config, deployment guide assets
```

## Build phases

| Phase | Scope | State |
| --- | --- | --- |
| 0 | Architecture, data model, threat model | **Ready for sign-off** |
| 1 | Server + auth + 1:1 chat | Not started |
| 2 | Groups + presence | Not started |
| 3 | File transfer | Not started |
| 4 | Active Directory integration | Not started |
| 5 | Admin console | Not started |
| 6 | Licensing + support chat | Not started |
| 7 | Installers + documentation | Not started |

Each phase delivers runnable code with tests. Nothing is marked complete while it is a stub.

## Project status

Phase 0 is complete and awaiting sign-off. Two environment constraints affect later
phases and are worth knowing about now:

1. **Code-signing certificates.** Deliverable 2 calls for *signed* MSI/EXE installers.
   The installer projects and the signing pipeline can be built here, but signing
   requires an organization-validated or EV code-signing certificate held by the vendor,
   typically on an HSM or token. That certificate cannot be provisioned from this
   repository — plan to supply it in the release pipeline.
2. **Active Directory testing.** LDAPS, Kerberos, and NTLM SSO paths cannot be fully
   exercised without a domain controller. Phase 4 will ship with an abstracted directory
   provider plus a test double so logic is covered by automated tests, but final
   verification needs a real domain.

## Licence

Proprietary. All rights reserved.
