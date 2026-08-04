# ADR-0001 — Implementation stack

**Status:** Accepted
**Date:** 2026-08-04
**Decision made by:** Product owner, confirmed against the build spec's `[CONFIRM]` gate

## Context

The build spec proposed .NET 8 / C# with WPF or WinUI 3 clients, ASP.NET Core + SignalR on
the server, and either PostgreSQL or SQL Server, and asked for confirmation. The product is
a self-hosted Windows-centric enterprise IM platform shipped to customers as installers.

## Decision

- **.NET 8 (LTS)** across all components.
- **ASP.NET Core 8** hosting the Communication Server, run as a Windows Service.
- **SignalR** over WebSockets for real-time client transport.
- **WPF** for both Windows clients (see [ADR-0004](0004-client-platform.md)).
- **PostgreSQL 16** as the database, via EF Core 8 with Npgsql.
- **Argon2id** via `Konscious.Security.Cryptography.Argon2` for password hashing.
- **AES-256-GCM** and **Ed25519** from `System.Security.Cryptography` / Bouncy Castle for
  content encryption and audit signing.

## Rationale

**.NET 8 over .NET 9+:** LTS matters for a product installed in enterprises on multi-year
upgrade cycles. Support through November 2026 with a clear upgrade path beats a shorter
STS window.

**PostgreSQL over SQL Server:** the deciding factor is licensing. This product is shipped
to customers who must run the database themselves. Requiring a SQL Server licence adds cost
and a procurement conversation to every sale. PostgreSQL adds neither, and Npgsql is a
mature, well-supported EF Core provider. Postgres also gives `citext`, `jsonb`, trigram
indexes, and partial indexes — all of which the data model uses directly.

**Not supporting both databases:** an option was considered and rejected. Supporting two
providers doubles the migration tree and the CI matrix, and forces the schema down to the
intersection of both feature sets — losing `citext`, `inet`, and partial-index behaviour
the design relies on. If a large customer later requires SQL Server, that is a scoped
project with a known cost, not a permanent tax on every release.

**SignalR over raw WebSockets:** it supplies reconnection, backpressure, transport
fallback, and a typed hub contract that would otherwise be written by hand. Its clustering
story (a Redis backplane) is also the natural path if HA is added later.

## Consequences

- Single-language codebase; domain logic is shared between server and clients through
  `Messenger.Contracts` and `Messenger.Core`, so wire types cannot drift.
- The server itself is cross-platform even though v1 targets Windows, which keeps a Linux
  server deployment open without a rewrite.
- **The WPF projects cannot be compiled on non-Windows build agents.** CI needs a Windows
  runner for the client and admin projects; server-side projects build anywhere.
- PostgreSQL becomes a documented prerequisite in the deployment guide, including its
  backup and restore procedure.
