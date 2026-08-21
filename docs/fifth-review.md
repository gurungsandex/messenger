# Fifth review — 2026-08-21

A merge-and-ship pass: reconciling two lines of independent work (the Owner tier, both WPF
apps, and the server-side REST gaps they depend on, against upstream's durable audit signing
key, Docker/CI, and first-run bootstrap tool), then a security review of the newly-merged
surface, then closing the one product gap both branches had flagged but neither had fixed.

**Suite: 332 tests, all passing** against a real PostgreSQL instance (237 + 33 + 62, up from
320 — three tests added for the new user-directory endpoint and the login fix below). Full
solution, including both WPF projects, builds clean under
`dotnet build Messenger.sln -p:EnableWindowsTargeting=true` with zero warnings.

---

## Findings, fixed

### VR-0 · HIGH · Every account created through the admin API was permanently unable to log in

**Location:** `src/Messenger.Data/AuthService.cs` (`AuthenticateAsync`),
`src/Messenger.Server/Program.cs` (`/api/auth/login`)

`POST /api/admin/users` creates accounts with `MustChangePassword = true`. `AuthenticateAsync`
refused to authenticate — returning `Succeeded = false` — for any account with that flag set,
even with the correct password, and the login endpoint mapped that straight to a 401. That
account therefore never receives a session token, and the *only* route that can clear the
flag, `POST /api/auth/change-password`, requires one. Every account created through the admin
API (the getting-started guide's own worked example among them) was locked out from its first
login onward, with no path back in short of writing directly to the database.

`LoginResponse.MustChangePassword`, and the WPF client's `ShellViewModel.OnLoggedIn` branch
that reacts to it by showing the forced-change screen, both already existed — this is exactly
the flow they were built for, and it could never run, because login never returned success
with the flag set.

**Fix:** `AuthenticateAsync` now returns success whenever the password is correct, regardless
of `MustChangePassword`; the flag flows through in `LoginResponse` as originally intended.
`AdminAuthFilter` — which gates every route in `AdminApi.cs`, `ConversationApi.cs`, and
`FileApi.cs` — now rejects with `AUTH-106` for any session whose user still has the flag set,
so nothing beyond `/api/auth/login` and `/api/auth/change-password` is reachable until the
password is changed. Covered by
`An_account_flagged_must_change_password_can_log_in_and_is_blocked_everywhere_except_change_password`
in `ClientApiTests.cs`, and the pre-existing unit test that asserted the old (broken) behaviour
was corrected to assert the new one.

### VR-1 · MEDIUM · Telemetry ingest accepted events for any licence id, issued or not

**Location:** `src/Messenger.Owner/OwnerApi.cs`, `MapTelemetryIngest`

`POST /api/owner/telemetry` is deliberately unauthenticated — a customer server has no vendor
credential to present, and identifies itself by the licence id it was issued. That is a
reasonable trust model for an opt-in heartbeat, but the implementation went further than the
model: it never checked the posted licence id against `CustomerLicenses` at all. Anyone who
could reach the endpoint could post fabricated events under a real customer's licence id
(visible in support tickets and the licence file itself), or for a licence id that was never
issued.

**Fix:** ingest now requires the licence id to match an active, non-revoked
`CustomerLicenseRecord`; unknown or revoked licence ids are rejected with 404. This keeps the
credential-free design intact while closing the gap between the stated trust model and what
the code actually checked.

## Findings, not exploitable

A background review of the full new/changed server-side surface (`FileApi.cs`,
`ConversationApi.cs`, the new self-service change-password route, the new `AdminApi.cs` group
routes, and all of `Messenger.Owner`) traced every access path from an actor id to the
resource it reaches. No IDOR, path traversal, or authentication-bypass was found — file and
conversation access is re-derived from `http.ActorId()` on every call, never taken from a
client-supplied field, and `Messenger.Bootstrap` opens no network listener so it cannot be
reached by anything other than an operator with a direct database connection string.

---

## Product gap closed: starting a direct conversation required knowing a GUID

Both the Owner/WPF work and the upstream bootstrap-tool work had independently flagged the
same gap: an ordinary client had no way to look up another user to start a 1:1 chat, short of
`GET /api/admin/users` (which needs `users.read`, an admin-only permission, and returns more
than an ordinary user should be able to enumerate about a colleague).

**Fix:** `GET /api/users?q=` — a minimal, session-only (no permission beyond being signed in)
directory search, returning only id, username, and display name, excluding the caller and
excluding disabled/deleted accounts, capped at 50 results. `Messenger.Client.Wpf`'s "start
direct chat" UI now searches this endpoint and picks from real results instead of taking a
pasted id. Covered by two new end-to-end tests
(`User_directory_excludes_the_caller_and_matches_by_name`,
`User_directory_requires_authentication`) in `ClientApiTests.cs`.

## Merge notes

`Messenger.sln`, `README.md`, `.gitignore`, `src/Messenger.Server/AdminApi.cs`, and
`src/Messenger.Server/Program.cs` all had concurrent changes from the two lines of work.
Every conflict was additive on both sides (new solution entries, new README status rows, new
routes in different parts of the same file) — nothing was dropped or overwritten; both sets of
changes are present after the merge, verified by diffing the merged result against each parent
individually.

## Deployment status

Unchanged from the [deployment guide](deployment.md): the container image, systemd unit, and
`tools/Messenger.Bootstrap` first-run path are all still current. The WPF apps compile
cross-targeted on this pass's build machine (Linux, via `-p:EnableWindowsTargeting=true`) but,
as before, have not been run — that verification needs a Windows machine and is the only
remaining item before the client/admin tiers can be called done rather than written.
