# ADR-0003 — Single-server topology for v1

**Status:** Accepted
**Date:** 2026-08-04
**Decision made by:** Product owner, confirmed against the build spec's `[CONFIRM]` gate

## Context

The build spec proposed a single-server deployment for v1 with HA and clustering deferred,
and asked for confirmation.

## Decision

**Single Communication Server per deployment.** One Windows Service, one PostgreSQL
database, one file store. SignalR runs in-process with no backplane. HA and clustering are
deferred.

## Rationale

Clustering is not a feature that can be bolted on late, but neither is it free to carry
early. Active-active SignalR requires a Redis backplane, a distributed connection registry,
distributed presence, shared file storage, and either sticky sessions or full message
fan-out across nodes — plus a test matrix that has to cover partition and failover
behaviour. That is a large fraction of the total v1 effort spent on a property most target
deployments do not need on day one.

For the scale this product targets — an organisation's internal IM on a LAN or WAN — a
single well-provisioned server handles the load comfortably. In-process SignalR is also
materially simpler to reason about for presence and ordering, which reduces the number of
places a subtle correctness bug can hide.

## Consequences

**The server is a single point of failure.** Recorded as
[AR-8](../threat-model.md#5-accepted-risks). Mitigations that ship in v1:

- Documented backup and restore with stated RTO and RPO targets.
- Graceful client reconnect with exponential backoff and automatic backlog replay, so a
  restart is a pause rather than data loss.
- Persistence-before-ACK, so an ACK always means durable — a crash cannot lose an
  acknowledged message.
- Store-and-forward is a query over persisted state rather than an in-memory queue, so
  a restart loses no pending delivery.
- Health and metrics endpoints for external monitoring.

**Design seams left deliberately open.** Even though v1 ships single-node, the components
that would need to become distributed are placed behind interfaces —
`IConnectionRegistry`, `IPresenceStore`, and the file store abstraction. A Redis-backed
implementation can be added later without reshaping call sites. This costs little now and
avoids a rewrite.

**Deferred, with reserved error-code ranges:** `NET-3xx` and `SRV-4xx` are reserved for
clustering and failover conditions so a future HA release does not disturb the existing
numbering.

## Alternatives rejected

**Cluster-ready seams with a Redis implementation shipped but disabled.** Rejected as
untested code carrying maintenance cost. The interfaces are enough; a Redis implementation
that nobody runs would rot.

**Full HA in v1.** Rejected as scope. It would delay every other phase and expand the test
burden substantially for a property that can be added in a v2 without breaking deployed
customers.
