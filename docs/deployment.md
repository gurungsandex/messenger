# Deployment and installation guide

**Audience:** IT administrators deploying the Communication Server
**Scope:** v1 — single server, PostgreSQL 16, Windows clients

> **Read [Current implementation status](#12-current-implementation-status) first.** Parts of
> this guide describe components that are not yet built. They are marked, not omitted, so
> you can plan around them.

---

## 1. Prerequisites

### Server

| Requirement | Minimum | Notes |
| --- | --- | --- |
| OS | Windows Server 2019 | 2022 recommended |
| CPU | 4 cores | Argon2id is deliberately CPU- and memory-hard |
| RAM | 8 GB | 64 MiB per concurrent password verification |
| Disk | 100 GB | Sized by file-transfer retention, not messages |
| .NET | 8.0 Runtime (ASP.NET Core) | Or deploy self-contained |
| Database | PostgreSQL 16 | Same host or dedicated |
| TPM | 2.0, recommended | Lets the KEK be used but not extracted |

### Clients

Windows 10 1809+, Windows 11, or Windows Server 2019+. TLS 1.3 support is required — this
is why 1809 is the floor.

---

## 2. Firewall ports

| Direction | Port | Protocol | Purpose |
| --- | --- | --- | --- |
| **Inbound** to server | 8443/tcp | HTTPS + WSS | The only inbound port required |
| Outbound from server | 5432/tcp | PostgreSQL | If the database is on another host |
| Outbound from server | 636/tcp | LDAPS | Directory sync |
| Outbound from server | 88/tcp+udp | Kerberos | SSO ticket validation |
| Outbound from server | 443/tcp | HTTPS | Vendor licensing, **optional** |
| Outbound from admin console | 443/tcp | HTTPS + WSS | Support chat, **optional** |

**One inbound port. Everything vendor-facing is outbound-only** — there is no path from
vendor infrastructure into a deployment. An air-gapped installation works indefinitely with
an offline licence file; only telemetry and support chat are lost.

---

## 3. Active Directory service account

The account needs **read access only**. The product never writes to the directory, and the
server reports an over-privileged account as a warning (`AD-106`) at every sync.

**Group Managed Service Account (gMSA) is strongly preferred** — it removes the stored
password entirely.

```powershell
New-ADServiceAccount -Name svc-messenger `
  -DNSHostName messenger.corp.local `
  -PrincipalsAllowedToRetrieveManagedPassword "MessengerServers"

# On the server
Install-ADServiceAccount -Identity svc-messenger
Test-ADServiceAccount -Identity svc-messenger
```

Required rights: read `user`, `group`, and `organizationalUnit` objects within the base DN,
and read `uSNChanged` for incremental sync. Nothing else. If a plain account is used
instead, its password is encrypted under the root KEK and never written to a configuration
file.

Register the SPN for Kerberos SSO:

```powershell
setspn -S HTTP/messenger.corp.local CORP\svc-messenger
```

**Clock skew above ~5 minutes breaks Kerberos entirely** (`AD-104`). Both server and domain
controller must track the same authoritative time source.

---

## 4. Certificate setup

The server needs a TLS certificate whose subject or SAN matches the name clients connect to.

1. Issue from your internal CA, or use a public certificate.
2. Import into `LocalMachine\My` with its private key.
3. Grant the service account **read** access to the private key — not full control.
4. Compute the SPKI pin for client deployment:

```powershell
$cert = Get-ChildItem Cert:\LocalMachine\My\<thumbprint>
$spki = $cert.PublicKey.EncodedKeyValue.RawData
[Convert]::ToBase64String([System.Security.Cryptography.SHA256]::Create().ComputeHash($spki))
```

Clients pin the **SPKI**, not the certificate, so renewing with the same key pair does not
break clients. Two pins are held — current and next — so you can roll a key over by
publishing the next pin before switching.

**A pin mismatch is fatal and cannot be clicked through** (`NET-104`). This is deliberate: a
"connect anyway" button turns a cryptographic guarantee into a user-education problem, and
user education loses. Recovery is an IT action.

---

## 5. Database setup

```sql
CREATE ROLE messenger LOGIN PASSWORD '<strong password>';
CREATE DATABASE messenger OWNER messenger;
```

Restrict `pg_hba.conf` to the server host and require TLS:

```
hostssl  messenger  messenger  10.0.0.5/32  scram-sha-256
```

The server connects with `sslmode=verify-full`.

Apply the schema explicitly:

```powershell
$env:MESSENGER_CONNECTION = "Host=db;Port=5432;Database=messenger;Username=messenger;Password=..."
dotnet ef database update --project src/Messenger.Data --startup-project src/Messenger.Server
```

**Migrations never run automatically at startup.** An unattended restart must not reshape a
production database with no backup checkpoint and no operator watching. The server refuses
to start against a schema it does not recognise (`SRV-104`).

---

## 6. Key store and escrow — do not skip this

The root KEK protects every message and file. Where it lives is set by
`KeyStore:Provider`: `DpapiNg`, `Tpm`, or `Pkcs11`. TPM is recommended, because the key can
be *used* but not *extracted* — a stolen disk or database backup yields ciphertext only.

> ### A machine-bound key with no escrow means a dead server is unrecoverable history.
>
> The database restores perfectly and nothing can read it. There is no error until the day
> someone attempts the restore, usually during an incident. **Export the escrow blob before
> first use, verify it re-imports, and store it separately from the server and its backups.**

```powershell
Messenger.Server.exe keystore export-escrow --out \\secure-share\messenger-kek.escrow
Messenger.Server.exe keystore verify-escrow --in \\secure-share\messenger-kek.escrow
```

The escrow blob is the KEK wrapped under an administrator passphrase (PBKDF2-HMAC-SHA256,
600 000 iterations, then AES-256-GCM). Treat the passphrase as you would a domain admin
credential — split it across two custodians if your policy calls for that.

---

## 7. Licence installation

The licence is an Ed25519-signed file from the vendor. Validation is entirely offline.

Install it via the admin console, or:

```powershell
Messenger.Server.exe license install --file contoso.lic
```

**Do not edit the file.** Any modification — including reformatting the JSON or an email
gateway rewriting line endings — invalidates the signature (`LIC-101`).

**Expiry behaviour:** the server enters read-only grace for a configurable window (default
14 days). History stays readable; new sessions and messages are refused. Warnings escalate
from 30 days out. After grace, all logins are refused (`LIC-110`).

---

## 8. Configuration

`appsettings.Production.json`:

```jsonc
{
  "ConnectionStrings": { "Messenger": "Host=db;Database=messenger;Username=messenger;Password=...;SslMode=VerifyFull" },
  "Licensing": { "VendorPublicKey": "<base64>" },
  "KeyStore": {
    "EscrowPath": "D:\\MessengerKeys\\root.escrow",   // REQUIRED — back this file up
    "Passphrase": "<from environment, never this file>"  // REQUIRED — server refuses to start without it
  },
  "FileStore": { "RootPath": "D:\\MessengerFiles" },
  "Kestrel": { "Endpoints": { "Https": { "Url": "https://0.0.0.0:8443" } } }
}
```

**`KeyStore:Passphrase` is mandatory and the server will not start without it.** That is
deliberate: the alternative was a key generated per process, which silently made all history
unreadable at the first restart. Supply it as an environment variable
(`KeyStore__Passphrase`) or via Windows-protected configuration, never in this file.

On first start the server creates the escrow at `KeyStore:EscrowPath` and logs a warning.
**Back up that file and its passphrase before putting the server into service** — see
section 9.

The file is created restricted to its owner (`0600` on Unix). Windows has no equivalent mode
bits and a new file inherits the directory's ACL, so **restrict the key store directory
itself** — the service account and administrators only. The passphrase is what actually
protects the blob, but a file holding the root key of every message and file in the
deployment should not be one that any local account can copy and attack offline at leisure.

### Roles

Five roles are seeded automatically at every start and reconciled to the current definition,
so a permission added in a new release reaches existing deployments on upgrade:

| Role | Grants |
| --- | --- |
| `ServerAdmin` | Everything server-side, including licence installation and directory sync |
| `UserAdmin` | Users and groups; **not** licence, server settings, or directory sync |
| `Auditor` | Reads and verifies the audit log; manages nobody |
| `HelpDesk` | Views users and sessions, can sign a user out |
| `User` | Chat and file transfer only — no administrative access whatsoever |

New accounts receive `User` automatically. **An account with no role can do nothing at all**,
which is the intended failure mode for administration but would be an outage for an ordinary
user, so account creation and directory sync both assign it.

`Auditor` exists so an organisation can separate duties: read the evidence without the
ability to change what it records. The last `ServerAdmin` cannot be demoted.

Secrets never belong in configuration files in production — use environment variables or
Windows-protected configuration. The server refuses to start with a named key if required
configuration is missing (`SRV-102`).

---

## 9. Backup and restore

Four things must be backed up. **Three of the four are useless without the fourth.**

| What | How | Frequency |
| --- | --- | --- |
| Database | `pg_dump` or PITR with WAL archiving | Daily full, continuous WAL |
| File store | Filesystem or snapshot backup | Daily |
| **KEK escrow blob** | Copied once, stored offline | On creation and each rotation |
| Configuration | With change control | On change |

### Restore

1. Restore PostgreSQL.
2. Restore the file store.
3. **Restore or re-import the KEK.** Without it the first two are ciphertext.
4. Start the service and verify the audit chain:

```powershell
Messenger.Server.exe audit verify
```

Recommended targets: **RPO ≤ 15 minutes** with WAL archiving, **RTO ≤ 2 hours**.

**Test the restore.** An untested backup is not a backup (`SRV-308`), and the KEK step is
exactly the one people discover they skipped at the worst moment.

---

## 10. Upgrade path

1. Read the release notes for breaking changes.
2. Back up the database, file store, and configuration.
3. Stop the service and let connections drain.
4. Install the new build.
5. Apply migrations explicitly with `dotnet ef database update`.
6. Start the service and check `/health/ready`.
7. Verify the audit chain.

Clients reconnect automatically with backoff and replay their backlog, so a brief server
restart is a pause rather than data loss — an acknowledged message is always durable.

Roll back by reinstalling the previous build and restoring the database. Destructive schema
changes land as two-phase deploys (add, backfill, switch, drop in a later release)
specifically so a single-version rollback stays possible.

---

## 11. Health monitoring

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `/health/live` | none | Process is running. Checks nothing else, deliberately. |
| `/health/ready` | none | Database reachable. `200` ready, `503` not. |
| `/api/admin/health` | `server.health` | Sessions, users, messages, pending deliveries, licence state |

**Point the load balancer at `/health/ready`, and an orchestrator's restart policy at
`/health/live`.** They are not interchangeable. Liveness answers "is this process up" and
checks nothing beyond that, because the response to a failed liveness check is a restart —
and restarting the server does not bring back a database that has gone away, it just adds an
outage on top of one. Readiness answers "can this instance serve a request", which is the
question that should decide whether traffic is sent here.

Neither probe requires authentication, and both return only a status word — no version, no
dependency detail, nothing that helps someone who should not be reaching them. Restrict
them at the reverse proxy if they need not be public.

Worth alerting on: licence expiry approaching, seat usage above 90%, pending-delivery
backlog growth, audit checkpoint signing failures (`SRV-306`), and any audit chain
verification failure (`SRV-305` — treat as a security incident).

### Running behind a reverse proxy

If anything terminates TLS or forwards traffic in front of the server — IIS ARR, nginx,
HAProxy, a hardware load balancer — configure this. Without it every connection appears to
come from the proxy, which has two consequences worth understanding:

- **The audit log records the proxy's address on every entry**, so it cannot answer "where
  from", which is much of what it is for.
- **The per-source login rate limiter collapses into a single bucket** shared by the whole
  organisation. Ten failed sign-ins from anyone locks out everyone.

```jsonc
{
  "ForwardedHeaders": {
    "Enabled": true,
    // At least one of these must name the proxy, or the headers are ignored.
    "KnownProxies": ["10.20.0.5"],
    "KnownNetworks": ["10.20.0.0/24"]
  }
}
```

**Leave `Enabled` false when there is no proxy.** Honouring `X-Forwarded-For` with nothing
in front lets any client choose its own apparent address and walk straight past both the
audit trail and the rate limiter — the failure it would cause is worse than the one it
fixes, which is why it is opt-in rather than on by default.

Only the hops named above are trusted; the framework defaults that trust loopback are
cleared. Enabling the feature and naming no proxy logs a warning at startup — that
combination looks configured and does nothing.

---

## 12. Current implementation status

Stated plainly so you can plan. Nothing below is a stub presented as finished.

| Component | Status |
| --- | --- |
| Server: auth, sessions, 1:1 and group chat, presence | **Implemented and tested** |
| File transfer: chunked, encrypted, resumable, AV hook | **Implemented and tested** |
| Encryption, key hierarchy, KEK escrow | **Implemented and tested** |
| Audit log with hash chain and Ed25519 checkpoints | **Implemented and tested** |
| Directory sync engine, reconciliation, LDAP escaping | **Implemented and tested** |
| Licensing: signing, validation, grace, enforcement | **Implemented and tested** |
| Admin REST API | **Implemented and tested** |
| **LDAPS wire implementation** | **Not implemented.** The sync engine is complete and tested behind `IDirectoryProvider`, but the `System.DirectoryServices.Protocols` binding is not written and needs a domain controller to develop against. The server currently returns `AD-101` from the sync endpoint rather than silently reporting success. |
| **Kerberos / NTLM SSO** | **Not implemented.** Local Argon2id authentication works. |
| **DPAPI-NG / TPM / PKCS#11 key stores** | **Not implemented.** The provider abstraction and escrow are complete; the shipped provider holds the KEK in process memory and is a development provider, not a production one. |
| **WPF client and admin console** | **Not implemented.** All admin logic exists behind the tested REST API. WPF targets `net8.0-windows` and needs a Windows build agent. |
| **Windows Service host** | **Not implemented.** Runs as a console/Kestrel application today. |
| **MSI installers and code signing** | **Not implemented.** Signing additionally requires an OV or EV certificate on an HSM or token, which must be supplied in the release pipeline. |
| **Owner tier: activation, telemetry, support chat** | **Not implemented.** Offline licence validation is complete and is the only part required for operation. |

### What this means in practice

The server is functional for **non-domain deployments using local accounts**, driven through
the REST API and SignalR hub. It is **not yet deployable as a turnkey Windows product**:
there is no installer, no service host, no GUI, and no working AD binding.

The remaining work is integration against Windows-specific APIs and packaging, not
architecture. The security-critical core — cryptography, authentication, authorization,
audit integrity, licence enforcement — is built and tested, including against a real
PostgreSQL instance.
