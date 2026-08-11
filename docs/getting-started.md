# Getting started — install, run, and see what works

**Audience:** anyone who wants to stand this up and try it, including for the first time.
**Time:** about 20 minutes.
**Result:** a running server, an administrator account you can log in as, and a checklist you
can run yourself to see exactly which features are finished and which are not.

This is the evaluation path. For production deployment — TLS, backups, hardening — read the
[deployment guide](deployment.md) instead.

---

## Read this first: a new install cannot let you in

A freshly migrated database has **five roles and zero users**, and the server **refuses every
login until a licence is installed**. Both of the ways out of that state sit behind the
authenticated admin API, which you cannot reach without logging in:

- Creating the first administrator needs a session.
- Installing the licence that would permit a session needs a session.

So a new deployment cannot reach its own first login. Step 4 breaks the cycle with a
bootstrap tool that writes both directly to the database. **You cannot skip it**, and nothing
in the earlier steps will appear broken — the server starts, reports healthy, and rejects
every credential you try.

This is a real gap in the product, not a quirk of this guide. See
[What is not finished](#what-is-not-finished).

---

## Step 1 — Prerequisites

| You need | Check it with | Notes |
| --- | --- | --- |
| Docker with Compose v2 | `docker compose version` | For the container path. |
| .NET 8 SDK | `dotnet --version` → `8.0.x` | Needed for migrations and the bootstrap tool even on the container path. |
| `dotnet-ef` 8.0.10 | `dotnet ef --version` | Install: `dotnet tool install --global dotnet-ef --version 8.0.10` |
| A free TCP port 8443 | `ss -lnt \| grep 8443` | The server publishes here on loopback. |

If port **5432** is already used by a local PostgreSQL, stop it for the duration or change
the published port in step 3 — otherwise the container's database silently loses the race and
your tools connect to the wrong server.

```bash
git clone https://github.com/gurungsandex/messenger.git
cd messenger
```

---

## Step 2 — Prove the code is sound before deploying it

Run the test suite first. It takes about 90 seconds and tells you whether the problem is your
environment or the code, which is worth knowing before anything is containerised.

```bash
dotnet build
dotnet test
```

Expect **270 passing, 51 skipped**. The skipped ones need a database and are covered in
step 7.

---

## Step 3 — Configure and start

```bash
cp deploy/.env.example .env
```

Edit `.env` and fill in three values:

```bash
POSTGRES_PASSWORD=<openssl rand -base64 24>
KEYSTORE_PASSPHRASE=<openssl rand -base64 32>
VENDOR_PUBLIC_KEY=PLACEHOLDER
```

> `VENDOR_PUBLIC_KEY` is deliberately a placeholder for now. Step 4 generates the real one;
> the server cannot validate a licence until it matches, and until then every login is
> refused with `LIC-101`.
>
> `KEYSTORE_PASSPHRASE` protects the root encryption key and the audit signing key. **It is
> not rotatable.** Lose it and every message and file is permanently unreadable — database
> backups will not save you.

Start the stack with the database published to loopback, which the setup steps need:

```bash
docker compose -f docker-compose.yml -f deploy/docker-compose.setup.yml up -d --build
```

The base compose file does not publish PostgreSQL at all — the overlay is only for setup, and
step 6 puts it back.

Confirm the server is up. It will start even though nothing is provisioned yet:

```bash
curl -fsS http://127.0.0.1:8443/health/ready    # → Healthy
```

Not healthy? Jump to [Troubleshooting](#troubleshooting).

---

## Step 4 — Apply the schema, then bootstrap

**Migrations never run automatically**, by design — an unattended restart must not reshape a
production database. Apply them yourself:

```bash
export MESSENGER_CONNECTION='Host=127.0.0.1;Port=5432;Database=messenger;Username=messenger;Password=<POSTGRES_PASSWORD>'

dotnet ef database update \
  --project src/Messenger.Data \
  --startup-project src/Messenger.Server
```

Six migrations apply, ending in `Done.`

> An `SRV-102: 'KeyStore:Passphrase' is not configured` line appears here. **This is normal.**
> The tool builds the app to read its model and does not get the server's environment. The
> migrations still apply — the last line is what matters.

Restart the server once so it seeds the five built-in roles, which the bootstrap needs:

```bash
docker compose restart server
sleep 10
```

Now break the cycle. This issues an evaluation licence, installs it, and creates the first
administrator:

```bash
dotnet run --project tools/Messenger.Bootstrap -- \
  --connection "$MESSENGER_CONNECTION" \
  --admin-username admin \
  --admin-password 'choose-a-long-password' \
  --customer 'Your Company' \
  --seats 25 \
  --days 90
```

It prints a line like:

```
Licensing__VendorPublicKey=7LBtI1ZLDRwm58vb7D1sd7TS1jX3tEL1UI8iZim2wpQ=
```

Put that value into `.env` as `VENDOR_PUBLIC_KEY`, replacing `PLACEHOLDER`, and restart:

```bash
docker compose -f docker-compose.yml -f deploy/docker-compose.setup.yml up -d
```

The licence is signed by a key pair the tool generated on your machine. That is fine for
evaluation and is **not** how a real licence works — a production licence is vendor-signed
and you are given the public key.

---

## Step 5 — Log in and confirm it works

```bash
curl -s -X POST http://127.0.0.1:8443/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"choose-a-long-password",
       "deviceFingerprint":"laptop-01","deviceName":"CLI"}'
```

A working response:

```json
{"sessionToken":"401rhf01DTDW...","userId":"38dd3fbe-...","displayName":"admin",
 "expiresAt":"2026-08-12T07:37:06Z","idleTimeoutSeconds":900,"mustChangePassword":false}
```

Save the token — **every** authenticated call needs both headers, and the device fingerprint
must match the one you logged in with:

```bash
export TOKEN='401rhf01DTDW...'
export AUTH=(-H "X-Session-Token: $TOKEN" -H "X-Device-Fingerprint: laptop-01" -H "Content-Type: application/json")
```

Getting `AUTH-101`? The account or password is wrong. `LIC-101`? `VENDOR_PUBLIC_KEY` does not
match the licence — recheck step 4.

---

## Step 6 — Close the database again

Setup is done, so stop publishing PostgreSQL:

```bash
docker compose up -d
```

The database is now reachable only from the compose network. Re-add the overlay whenever you
need host access again.

---

## Step 7 — See what actually works

Each command below either works or fails in a specific, informative way. Run them in order.

### Works: licence and server state

```bash
curl -s "${AUTH[@]}" http://127.0.0.1:8443/api/admin/license
curl -s "${AUTH[@]}" http://127.0.0.1:8443/api/admin/health
```

Expect `"state": "Valid"`, your seat count, and live counts of users, groups, and messages.

### Works: user and group management

```bash
curl -s -X POST "${AUTH[@]}" \
  -d '{"username":"alice","displayName":"Alice","email":"alice@example.test",
       "initialPassword":"alice-long-password-1"}' \
  http://127.0.0.1:8443/api/admin/users        # → 201 Created

curl -s -X POST "${AUTH[@]}" \
  -d '{"name":"Engineering","description":"Eng team"}' \
  http://127.0.0.1:8443/api/admin/groups       # → 201 Created

curl -s "${AUTH[@]}" http://127.0.0.1:8443/api/admin/users
```

### Works: role-based access control

Make an ordinary user and confirm they are refused an admin route:

```bash
dotnet run --project tools/Messenger.Bootstrap -- \
  --connection "$MESSENGER_CONNECTION" --skip-license \
  --admin-username bob --admin-password 'bob-long-password-99' --role User

BOB=$(curl -s -X POST http://127.0.0.1:8443/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"bob","password":"bob-long-password-99","deviceFingerprint":"bob-pc"}' \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["sessionToken"])')

curl -s -H "X-Session-Token: $BOB" -H "X-Device-Fingerprint: bob-pc" \
  http://127.0.0.1:8443/api/admin/users
```

Expected — this is the system working:

```json
{"code":"AUTH-301","message":"This action requires the 'users.read' permission."}
```

### Works: audit log and its tamper evidence

```bash
curl -s "${AUTH[@]}" 'http://127.0.0.1:8443/api/admin/audit?limit=10'
curl -s -X POST "${AUTH[@]}" http://127.0.0.1:8443/api/admin/audit/verify
```

`verify` returns `"valid": true`. `checkpointsVerified` counts signed checkpoints proven
genuine; `checkpointsUnverifiable` counts any whose signing key this server no longer holds —
after a correct restore that must be `0`. Both are `0` on a new install, because a checkpoint
is only written every 1000 audit entries.

### Works: keys survive a restart

The single most important property to confirm, because failing it is silent:

```bash
docker compose restart server && sleep 10
docker compose logs server | grep 'was created'
```

**Expect no output.** Any "A new root key was created" or "A new audit signing key was
created" after the first start means the key store volume is not persisting, and every
message encrypted before the restart is already unreadable.

### Works: real-time chat hub responds

```bash
curl -s -X POST "http://127.0.0.1:8443/hubs/chat/negotiate?negotiateVersion=1" "${AUTH[@]}"
```

Returns a connection token and the available transports. Sending messages needs a SignalR
client — there is no shipped client, so this confirms the endpoint is live, not that you can
chat from a UI.

### Not built: everything below fails on purpose

```bash
curl -s -X POST "${AUTH[@]}" http://127.0.0.1:8443/api/admin/directory/sync
# → 502  AD-101 "the LDAPS provider is not yet implemented"

curl -s -o /dev/null -w '%{http_code}\n' -X POST "${AUTH[@]}" http://127.0.0.1:8443/api/files
# → 404  file transfer has no HTTP route

curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8443/api/auth/password
# → 404  no password-change endpoint
```

---

## What is not finished

Three of these will bite you during evaluation. They are limitations of the product today,
not of this guide.

### Will affect you immediately

| Gap | What you see | Workaround |
| --- | --- | --- |
| **No first-admin provisioning** | A new install rejects every login, with nothing indicating why | The bootstrap tool in step 4 |
| **Users created via the API cannot log in** | `POST /api/admin/users` returns 201, then that user's login fails with `AUTH-106` | Accounts are flagged must-change-password and **no password-change endpoint exists**. Create usable accounts with the bootstrap tool and `--role User` |
| **No client application** | Nothing to click | The REST API and SignalR hub are the only interfaces. WPF clients are not built |

### Built and tested, but not reachable

| Gap | Status |
| --- | --- |
| **File transfer** | The service is complete and tested — chunked, resumable, encrypted, crypto-shred delete — but no HTTP or hub route reaches it, so it cannot be used |
| **Hub rate limiting** | HTTP endpoints are rate limited; SignalR methods are not |

### Not implemented

| Gap | Status |
| --- | --- |
| **LDAPS / Active Directory** | The sync engine is complete and tested behind an interface; the wire binding needs a real domain controller. Returns `AD-101` |
| **Kerberos / NTLM SSO** | Local password auth only |
| **TPM / DPAPI-NG / HSM key store** | The shipped file-backed store is durable and correct but keeps the key in process memory. It is a development provider |
| **Windows Service host, MSI installers** | Not built. Linux container and systemd unit are the supported ways to run it |
| **Owner tier** (activation, telemetry, support chat) | Not built. Offline licence validation is complete and is all that operation requires |

### Known issues carried forward

Recorded with reasoning in the [fourth review](fourth-review.md):

- **Licence seat and session limits can be exceeded** by simultaneous requests — the checks
  count-then-write with no locking. Self-correcting, and not a security boundary.
- **Session tokens are accepted in the `access_token` query string** by the hub, so they can
  land in reverse-proxy access logs.
- **`/hubs/chat/negotiate` answers unauthenticated callers.** The connection is aborted at
  authentication, but the negotiate step itself is open and unmetered.

### The deliberate design decision to be aware of

**An administrator with server access can read all message and file history.** This is not a
flaw — encryption is server-side with admin-recoverable keys, chosen so compliance archiving,
eDiscovery, and server-side malware scanning are possible. It is explicitly **not**
end-to-end encrypted. See [ADR-0002](adr/0002-encryption-model.md) and the
[threat model](threat-model.md#5-accepted-risks).

---

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `/health/ready` never returns `Healthy` | The database is unreachable. `docker compose logs server \| grep -i error`. If migrations have not been applied, the server starts but role seeding fails |
| `SRV-102: 'KeyStore:Passphrase' is not configured` during `dotnet ef` | **Normal.** The tool has no server environment. Migrations still apply — check for `Done.` |
| Every login gives `LIC-101` | `VENDOR_PUBLIC_KEY` does not match the installed licence. Re-run step 4 and restart the server |
| Every login gives `LIC-108` | No licence installed. Run the bootstrap tool without `--skip-license` |
| Login gives `AUTH-106` | The account is flagged must-change-password. There is no endpoint to clear it — recreate the account with the bootstrap tool |
| Admin call gives `AUTH-205` | Missing, expired, or mismatched session. Both headers are required and the device fingerprint must match the login. Sessions idle out after 15 minutes |
| Admin call gives `AUTH-301` | Authenticated but not permitted. Expected for non-admin accounts |
| `dotnet ef` cannot connect | The setup overlay is not applied, or a local PostgreSQL is occupying 5432 |
| Server logs "A new root key was created" on every start | The key store volume is not persisting. **Stop and fix this** — data encrypted before each restart is already unrecoverable |

Full catalogue with causes and remediation: [error codes](error-codes.md).

---

## Removing it

```bash
docker compose down -v     # -v also deletes the volumes
```

`-v` destroys the key store. On a real deployment that makes every message and file
permanently unreadable, whatever your database backups say.

---

## Where to go next

| If you want to | Read |
| --- | --- |
| Deploy for real — TLS, backups, hardening | [Deployment guide](deployment.md) |
| Understand the design | [Architecture](architecture.md) · [ADRs](adr/) |
| Know what was reviewed and fixed | [Fourth review](fourth-review.md) and the three before it |
| Look up an error code | [Error codes](error-codes.md) |
| Run day-to-day operations | [Admin quick reference](quick-reference-admin.md) |
