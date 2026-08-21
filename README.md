# Messenger — Self-Hosted Enterprise Instant Messenger

A private, self-hosted corporate IM platform for LAN/WAN/enterprise networks. Internal
1:1 chat, group chat, file transfer, and presence, with no cloud dependency and no
third-party message relay. All customer data stays on customer infrastructure.

> **Status: server-side complete, reviewed, and deployable; Owner tier and both WPF apps now
> written against the tested API; Windows packaging not started.** Tests pass, including
> end-to-end HTTP tests and a PostgreSQL-backed integration suite. The server ships with a
> container image and a systemd unit, both smoke-tested in CI against a real database. The
> Owner tier (vendor licensing/telemetry/support) is a runnable, cross-platform ASP.NET Core
> service, built and smoke-tested end to end. The Admin console and end-user client are
> complete WPF applications written against the real REST/SignalR contracts — but WPF only
> builds and runs on Windows, so **neither has been compiled, run, or exercised by hand**;
> that verification still needs to happen on a Windows machine. LDAPS binding, Kerberos/NTLM
> SSO, TPM/DPAPI-NG key stores, the Windows Service host, and MSI installers remain **not
> implemented**. See [What is and isn't built](#what-is-and-isnt-built).

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
| **[Getting started](docs/getting-started.md)** | **Start here.** Install, run, log in, and a checklist that shows which features work and which are not built. |
| [Architecture](docs/architecture.md) | Tiers, components, protocols, trust boundaries, auth, crypto, licensing, delivery semantics. |
| [Data model](docs/data-model.md) | PostgreSQL schema, indexes, retention, migration strategy. |
| [Threat model](docs/threat-model.md) | Assets, attacker profiles, STRIDE per boundary, mitigations, accepted risks. |
| [Security review](docs/security-review.md) | Findings from the pre-merge review, fixes, and what remains. |
| [Production review](docs/production-review.md) | Concurrency, memory, and deployment findings from the follow-up pass. |
| [Third review](docs/third-review.md) | A third pass repeating the security and production reviews' own bug classes at call sites they missed. |
| [Fourth review](docs/fourth-review.md) | A deployment-readiness pass: what breaks when the process is restarted, restored, or run as a service. |
| [Fifth review](docs/fifth-review.md) | Merging the Owner/WPF work with upstream's bootstrap tool, a security review of the merged surface, and closing the user-lookup gap. |
| [Error codes](docs/error-codes.md) | Numbered catalog — AUTH/NET/LIC/AD/FILE/SRV — with cause and remediation. |
| [Deployment guide](docs/deployment.md) | Prerequisites, ports, AD service account, certificates, backup/restore, upgrades, and current status. |
| [Admin quick reference](docs/quick-reference-admin.md) | One page for daily operations and incidents. |
| [User quick reference](docs/quick-reference-user.md) | One page for end users. |
| [ADRs](docs/adr/) | Architecture decision records. |

## Repository layout

Projects marked *(not built)* are named here as the target structure; everything else
exists. Projects marked *(untested)* build and were written against the real, tested API,
but have not themselves been run or exercised — see the status note above.

```
messenger/
├── docs/                          Architecture, data model, threat model, error codes, ADRs
├── src/
│   ├── Messenger.Contracts/       Wire DTOs, hub interfaces, error codes (shared by all tiers)
│   ├── Messenger.Core/            Domain model, business rules, no I/O dependencies
│   ├── Messenger.Crypto/          Envelope encryption, key hierarchy, audit hash chain
│   ├── Messenger.Data/            EF Core context, entities, migrations
│   ├── Messenger.Server/          ASP.NET Core host, SignalR hubs, REST admin + conversation + file APIs
│   ├── Messenger.Licensing/       Licence parsing, Ed25519 verification, grace handling
│   ├── Messenger.Owner/           Vendor licensing/telemetry/support service (cross-platform, smoke-tested)
│   ├── Messenger.Server.Service/  Windows Service wrapper            (not built)
│   ├── Messenger.Client.Wpf/      End-user Windows app               (written, untested — Windows-only)
│   └── Messenger.Admin.Wpf/       IT admin management console        (written, untested — Windows-only)
├── tests/                         Unit, integration, and end-to-end test projects
├── tools/Messenger.Bootstrap/     First-run provisioning: evaluation licence, first admin
├── deploy/                        systemd unit and config examples   (WiX installers not built)
├── Dockerfile                     Container image for the server
└── docker-compose.yml             Single-host deployment: server, database, volumes
```

Two solutions cover different build targets:
- `Messenger.sln` — everything, including the two WPF projects. Needs a Windows machine.
- `Messenger.CrossPlatform.slnf` — everything except the WPF projects. Builds and tests on
  Linux/macOS; this is what `dotnet build`/`dotnet test` below use.

## Build phases

| Phase | Scope | State |
| --- | --- | --- |
| 0 | Architecture, data model, threat model | **Complete** |
| 1 | Server + auth + 1:1 chat | **Complete** |
| 2 | Groups + presence | **Complete** |
| 3 | File transfer | **Complete** |
| 4 | Active Directory integration | **Partial** — sync engine complete and tested; LDAPS binding not written |
| 5 | Admin console | **Partial** — REST API complete and tested; WPF console written, untested on Windows |
| 6 | Licensing + support chat | **Partial** — licensing complete and tested; Owner tier written and smoke-tested |
| 7 | Installers + documentation | **Partial** — docs complete; container image and systemd unit shipped; MSI installers and Windows service host not written |

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
| Audit log: SHA-256 chain, Ed25519 checkpoints (durable signing key, verified on demand), fail-closed writes | Built, tested |
| Directory sync engine, reconciliation rules, RFC 4515/4514 escaping | Built, tested |
| Licensing: Ed25519 signing, offline validation, read-only grace, enforcement | Built, tested |
| Admin REST API + SignalR hub | Built, tested |
| Conversation listing, user directory search, self-service password change, file transfer REST API, group lifecycle routes | Built, tested |
| RBAC: five seeded roles, per-route permissions, cross-tier escalation refused | Built, tested |
| Durable root key store with escrow; server refuses to start without a passphrase | Built, tested |
| Container image and systemd unit, both smoke-tested in CI against a real database | Built, tested |
| TLS 1.3 enforcement, HSTS, security headers, rate limiting | Built, tested |
| **Owner tier**: licence issuance/revocation, telemetry ingest, support chat hub | **Built, smoke-tested** — cross-platform ASP.NET Core service (`Messenger.Owner`); own database, own escrowed vendor Ed25519 keypair. First operator account is bootstrapped from `OWNER_BOOTSTRAP_USERNAME`/`OWNER_BOOTSTRAP_PASSWORD` on first start, the same non-network-reachable pattern `tools/Messenger.Bootstrap` uses for the customer server's first admin. |
| **WPF client** (`Messenger.Client.Wpf`) | **Written, compiles cross-targeted; not run** — login, conversation list, chat, file transfer, presence, forced password change. Starting a direct conversation searches `GET /api/users`, a non-admin directory endpoint added in this pass. |
| **WPF admin console** (`Messenger.Admin.Wpf`) | **Written, compiles cross-targeted; not run** — dashboard, users, groups (including rename/enable-disable/delete), sessions, audit + chain verification, licence install, directory sync trigger. |
| **LDAPS wire binding** | **Not built** — engine is complete behind `IDirectoryProvider`; needs a domain controller |
| **Kerberos / NTLM SSO** | **Not built** — local Argon2id auth works |
| **DPAPI-NG / TPM / PKCS#11 key stores** | **Not built** — abstraction and escrow complete; shipped provider is development-only |
| **Windows Service host, MSI installers, code signing** | **Not built** — the server runs as a managed service on Linux via `deploy/messenger-server.service` or the container image |

The server is usable today for **non-domain deployments with local accounts**, driven
through the REST API, SignalR hub, or either WPF app, and it can be deployed and operated as
a service — see [section 8.1 of the deployment guide](docs/deployment.md). Compiling the WPF
apps still requires a Windows machine, and neither has been run — see the status note above.
It is **not a turnkey Windows product**: no MSI, no Windows service host, no working AD
binding. The remaining work is Windows-specific integration and packaging, not architecture.

## Running it

```bash
# Requires .NET 8 SDK and PostgreSQL 16. Use the cross-platform solution filter on
# Linux/macOS — the full Messenger.sln includes the Windows-only WPF projects.
dotnet build Messenger.CrossPlatform.slnf
dotnet test Messenger.CrossPlatform.slnf              # skips database-backed tests without a connection

# Include the PostgreSQL-backed suites (integration + end-to-end HTTP)
export MESSENGER_TEST_CONNECTION='Host=localhost;Port=5432;Database=messenger;Username=postgres;Password=postgres'
dotnet test Messenger.CrossPlatform.slnf

# Apply the server's schema. Migrations never run automatically at startup — an unattended
# restart must not reshape a production database.
export MESSENGER_CONNECTION='Host=localhost;Port=5432;Database=messenger;Username=messenger;Password=messenger'
dotnet ef database update --project src/Messenger.Data --startup-project src/Messenger.Server

# Apply the Owner tier's schema (a separate database — vendor infrastructure, not part of
# any customer deployment).
export MESSENGER_OWNER_CONNECTION='Host=localhost;Port=5432;Database=messenger_owner;Username=messenger;Password=messenger'
dotnet ef database update --project src/Messenger.Owner --startup-project src/Messenger.Owner
```

On Windows, with the full solution and the WPF workload installed:

```powershell
dotnet build Messenger.sln
dotnet run --project src/Messenger.Client.Wpf     # $env:MESSENGER_SERVER_URL if not https://localhost:8443
dotnet run --project src/Messenger.Admin.Wpf
```

### Deploying it

```bash
cp deploy/.env.example .env        # fill in; .env is gitignored
docker compose up -d --build
curl -fsS http://127.0.0.1:8443/health/ready
```

Migrations are not run by the image — apply them as above first. The `keystore` and
`filestore` volumes hold state that cannot be rebuilt: **back them up with the database.** A
systemd unit for non-container hosts is in [`deploy/`](deploy/).

> **A new install cannot let you in.** A freshly migrated database has five roles and no
> users, and the server refuses every login until a licence is installed — and both fixes sit
> behind the authenticated admin API. `tools/Messenger.Bootstrap` breaks that cycle by
> writing the first administrator and an evaluation licence directly. The
> [getting-started guide](docs/getting-started.md) walks through it.

Full procedure, including backup and restore, is in the [deployment guide](docs/deployment.md).

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
