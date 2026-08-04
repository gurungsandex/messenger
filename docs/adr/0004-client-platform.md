# ADR-0004 — Windows-only WPF clients for v1

**Status:** Accepted
**Date:** 2026-08-04
**Decision made by:** Product owner, confirmed against the build spec's `[CONFIRM]` gate

## Context

The build spec called for Windows end-user and admin applications delivered as `.exe`
installers, proposed WPF or WinUI 3, and asked for confirmation of both the platform scope
and the UI framework.

## Decision

**Windows-only for v1**, both clients built with **WPF** on .NET 8.

Target platforms: Windows 10 1809+, Windows 11, Windows Server 2019+.

## Rationale

**WPF over WinUI 3** — the deciding factor is deployment, not visuals. WinUI 3 requires the
Windows App SDK runtime, and unpackaged MSI distribution needs a bootstrapper. In
locked-down enterprise environments, where deployment happens through Group Policy, SCCM, or
Intune and the desktop team scrutinises every dependency, that is a real obstacle. WPF has
no runtime prerequisite beyond .NET itself, which can be published self-contained, and it
supports Windows 10 1809 without qualification.

WinUI 3 buys a more modern Fluent look. For an internal corporate messenger evaluated by IT
departments rather than consumers, frictionless deployment is worth more than contemporary
visuals. WPF's control set is mature and its theming is sufficient to produce a clean,
modern interface.

**Windows-only** matches the stated market: AD-integrated corporate networks with Windows
endpoints. Kerberos SSO — the preferred authentication path — is most natural there.

## Consequences

- **CI needs a Windows runner.** WPF projects target `net8.0-windows` and cannot be
  compiled on Linux or macOS agents. Server-side projects build anywhere; the client and
  admin projects do not. This is a build-infrastructure requirement, not an inconvenience —
  it must be provisioned before Phase 5.
- Two WPF applications share presentation concerns; common controls, theming, and view-model
  infrastructure live in a shared library to avoid divergence.
- MSI packaging via WiX, with self-contained .NET publishing so no framework install is
  required on endpoints.

## A hedge that was considered and partly adopted

A third option was on the table: Windows clients now, but with the client core extracted
into a platform-neutral library so a macOS, Linux, or mobile UI could be added later
without a rewrite.

The full option was not selected, but **the repository layout adopts its central idea
anyway.** `Messenger.Client.Core` holds transport, local store, sync, presence, and crypto
with no UI dependency; `Messenger.Client.Wpf` holds only the Windows presentation layer.
This costs essentially nothing — it is good layering regardless — and means a future
cross-platform client is a UI project rather than a rewrite.

This is worth being precise about: the *decision* is Windows-only WPF for v1. The layering
is not a commitment to cross-platform support, and no cross-platform work is in scope.

## Alternatives rejected

**WinUI 3** — rejected on enterprise deployment friction, as above.

**Cross-platform UI framework (Avalonia, MAUI) in v1** — rejected as scope. It would trade a
known-good Windows experience for a broader but shallower one, against a requirement that
explicitly asks for Windows.
