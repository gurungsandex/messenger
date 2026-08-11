using Messenger.Contracts;
using Messenger.Crypto;
using Messenger.Data;
using Messenger.Licensing;
using Messenger.Core;
using Messenger.Server;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);
var isProduction = builder.Environment.IsProduction();

// A no-op unless the process is actually running under systemd. When it is, this is what
// makes `Type=notify` honest: systemd is told the server is ready once it is listening,
// rather than assuming so the instant exec succeeds, and log output picks up the journal's
// priority prefixes instead of arriving as undifferentiated text.
builder.Host.UseSystemd();

builder.Services.AddSignalR();
builder.Services.AddSingleton<IConnectionRegistry, InMemoryConnectionRegistry>();
builder.Services.AddSingleton<MessageCipher>();
builder.Services.AddSingleton<PasswordHasher>();
builder.Services.AddSingleton(TimeProvider.System);

// The root KEK must outlive the process. Generating one per start would make every
// message and file encrypted before a restart permanently unreadable -- a routine service
// restart would silently destroy all history -- so the key is loaded from a durable escrow
// file, created on first run.
//
// On Windows the DPAPI-NG or TPM provider is preferred, because it keeps the key outside
// the process entirely. That provider is not yet implemented; this one is durable and
// correct, and is what makes non-Windows deployment possible at all.
var keyStorePath = builder.Configuration["KeyStore:EscrowPath"]
    ?? Path.Combine(AppContext.BaseDirectory, "keystore", "root.escrow");
var keyStorePassphrase = builder.Configuration["KeyStore:Passphrase"];

if (string.IsNullOrWhiteSpace(keyStorePassphrase))
{
    // Refusing to start beats starting with an ephemeral key. The failure mode of the
    // latter is silent and total, and only surfaces at the first restart.
    throw new InvalidOperationException(
        $"{ErrorCode.ConfigurationInvalid}: 'KeyStore:Passphrase' is not configured. "
        + "The root key protects all message and file content and must be durable; "
        + "see docs/deployment.md section 6.");
}

var (keyStore, keyStoreCreated) = FileBackedKeyStore.OpenOrCreate(keyStorePath, keyStorePassphrase);
builder.Services.AddSingleton<IKeyStoreProvider>(keyStore);

// The audit checkpoint signing key has to outlive the process for the same reason the KEK
// does, and was previously the one key that did not. A per-process key means every
// checkpoint signed before a restart names a key id the new process has never held, and its
// public half is gone -- the signatures stay in the database and can never be checked again.
// The audit chain would quietly lose its tamper evidence at the first routine restart.
//
// Sealed under the same passphrase as the KEK escrow: both are root secrets, provisioned and
// backed up together, and a second secret to manage is a second secret to lose.
var auditKeyPath = builder.Configuration["AuditSigningKey:EscrowPath"]
    ?? Path.Combine(AppContext.BaseDirectory, "keystore", "audit-signing.escrow");

var (auditSigningKeys, auditKeyCreated) =
    FileBackedAuditSigningKeyProvider.OpenOrCreate(auditKeyPath, keyStorePassphrase);
builder.Services.AddSingleton<IAuditSigningKeyProvider>(auditSigningKeys);

// Fail fast at startup rather than at the first request. A server that accepts a
// connection and only then discovers it has no database is far harder to diagnose than
// one that refuses to start with a named configuration key (SRV-102).
var connectionString = builder.Configuration.GetConnectionString("Messenger");
if (string.IsNullOrWhiteSpace(connectionString))
{
    throw new InvalidOperationException(
        $"{ErrorCode.ConfigurationInvalid}: connection string 'ConnectionStrings:Messenger' is not configured.");
}

builder.Services.AddDbContext<MessengerDbContext>(o => o.UseNpgsql(connectionString));

builder.Services.AddScoped<AuditService>();
builder.Services.AddScoped<SessionService>();
builder.Services.AddScoped<AuthService>();
builder.Services.AddScoped(sp =>
{
    var service = new MessageService(
        sp.GetRequiredService<MessengerDbContext>(),
        sp.GetRequiredService<IKeyStoreProvider>(),
        sp.GetRequiredService<MessageCipher>(),
        sp.GetRequiredService<TimeProvider>());

    // Grace mode means "history readable, no new sessions and no new messages". Enforcing
    // it only at login would leave already-connected clients sending indefinitely.
    var license = sp.GetRequiredService<LicenseEnforcementService>();
    service.LicenseGate = async ct =>
    {
        var status = await license.GetStatusAsync(ct);
        return status.AllowsNewSessions
            ? SendGateState.Allowed
            : new SendGateState(false, status.ErrorCode ?? ErrorCode.NoLicenseInstalled,
                status.Detail ?? "The licence does not permit sending messages.");
    };

    return service;
});
builder.Services.AddScoped<GroupService>();
builder.Services.AddScoped<FileTransferService>();
builder.Services.AddScoped<DirectorySyncService>();

// The LDAPS wire implementation is not yet written (see UnconfiguredDirectoryProvider).
// Registering it explicitly means the sync endpoint returns AD-101 with a clear message
// rather than failing at startup or silently reporting a successful no-op sync.
builder.Services.AddSingleton<IDirectoryProvider, UnconfiguredDirectoryProvider>();
builder.Services.AddScoped<LicenseEnforcementService>();
builder.Services.AddScoped<AdminAuthFilter>();
builder.Services.AddScoped<AuthorizationService>();

// The vendor public key is compiled in so licence validation is fully offline: a
// customer's internal messaging must not stop because the vendor is unreachable.
builder.Services.AddSingleton(sp => new LicenseValidator(
    Convert.FromBase64String(builder.Configuration["Licensing:VendorPublicKey"]
        ?? throw new InvalidOperationException(
            $"{ErrorCode.ConfigurationInvalid}: 'Licensing:VendorPublicKey' is not configured.")),
    sp.GetRequiredService<TimeProvider>()));
builder.Services.AddSingleton<FileCipher>();
builder.Services.AddSingleton<IMalwareScanner, NoOpMalwareScanner>();
builder.Services.AddSingleton<IFileStore>(_ => new LocalFileStore(
    builder.Configuration["FileStore:RootPath"]
    ?? Path.Combine(AppContext.BaseDirectory, "filestore")));
builder.Services.AddScoped<PresenceService>();

// Liveness answers "is this process up"; readiness answers "can it actually serve a
// request", which for this server means the database is reachable. A load balancer given
// only the first will keep sending traffic to an instance whose every request 500s.
builder.Services.AddHealthChecks()
    .AddCheck<DatabaseHealthCheck>("database", tags: ["ready"]);

// Behind a reverse proxy every connection appears to come from the proxy. Left uncorrected
// that puts the proxy's address on every audit entry and collapses the per-IP login rate
// limiter into a single bucket shared by the whole organisation — so ten failed logins from
// anyone locks out everyone.
//
// Opt-in, because the opposite failure is worse: honouring X-Forwarded-For with no proxy in
// front lets any caller set their own apparent address and walk straight past both.
if (builder.Configuration.GetValue("ForwardedHeaders:Enabled", false))
{
    builder.Services.Configure<ForwardedHeadersOptions>(options =>
    {
        options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;

        // Cleared because the defaults trust loopback unconditionally. Only the proxies an
        // operator names are trusted; naming none means the headers are ignored, which is
        // the safe reading of an incomplete configuration.
        options.KnownProxies.Clear();
        options.KnownNetworks.Clear();

        foreach (var proxy in builder.Configuration.GetSection("ForwardedHeaders:KnownProxies").Get<string[]>() ?? [])
        {
            if (System.Net.IPAddress.TryParse(proxy, out var address)) options.KnownProxies.Add(address);
            else throw new InvalidOperationException(
                $"{ErrorCode.ConfigurationInvalid}: 'ForwardedHeaders:KnownProxies' contains '{proxy}', "
                + "which is not an IP address.");
        }

        foreach (var network in builder.Configuration.GetSection("ForwardedHeaders:KnownNetworks").Get<string[]>() ?? [])
        {
            var parts = network.Split('/');
            if (parts.Length == 2 && System.Net.IPAddress.TryParse(parts[0], out var prefix)
                                  && int.TryParse(parts[1], out var length))
            {
                options.KnownNetworks.Add(new Microsoft.AspNetCore.HttpOverrides.IPNetwork(prefix, length));
            }
            else
            {
                throw new InvalidOperationException(
                    $"{ErrorCode.ConfigurationInvalid}: 'ForwardedHeaders:KnownNetworks' contains '{network}', "
                    + "which is not CIDR notation such as '10.0.0.0/8'.");
            }
        }
    });
}

// Per-user and per-IP limits. Sign-in is limited far more tightly than ordinary traffic:
// it is the endpoint an attacker actually attacks, and unlike the rest it is reachable
// without a credential.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    options.AddPolicy("login", context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 10, Window = TimeSpan.FromMinutes(1) }));

    options.AddPolicy("admin", context => RateLimitPartition.GetFixedWindowLimiter(
        context.Request.Headers["X-Session-Token"].FirstOrDefault()
            ?? context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 300, Window = TimeSpan.FromMinutes(1) }));

    options.OnRejected = async (context, ct) =>
    {
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        await context.HttpContext.Response.WriteAsJsonAsync(
            new ErrorDto(ErrorCode.RateLimitExceeded, "Too many requests. Try again shortly.", null), ct);
    };
});

if (isProduction)
{
    // The architecture mandates TLS 1.3 only. Enforced here rather than left to the host,
    // so a deployment cannot silently accept a downgraded connection.
    builder.WebHost.ConfigureKestrel(kestrel =>
    {
        kestrel.ConfigureHttpsDefaults(https =>
            https.SslProtocols = System.Security.Authentication.SslProtocols.Tls13);
        kestrel.AddServerHeader = false;
    });

    builder.Services.AddHsts(o =>
    {
        o.MaxAge = TimeSpan.FromDays(365);
        o.IncludeSubDomains = true;
    });
}

var app = builder.Build();

// First in the pipeline: everything downstream that reads the client address — the audit
// log, the rate limiter, HTTPS redirection — must see the corrected value, not the proxy's.
if (builder.Configuration.GetValue("ForwardedHeaders:Enabled", false))
{
    app.UseForwardedHeaders();

    var forwardedOptions = app.Services
        .GetRequiredService<Microsoft.Extensions.Options.IOptions<ForwardedHeadersOptions>>().Value;

    // Enabling the feature and naming no proxy is the one combination that looks configured
    // and does nothing: the headers arrive, no hop is trusted, and every audit entry keeps
    // the proxy's address. Silence here reads as "working", so it is said out loud.
    if (forwardedOptions.KnownProxies.Count == 0 && forwardedOptions.KnownNetworks.Count == 0)
    {
        app.Logger.LogWarning(
            "'ForwardedHeaders:Enabled' is set but neither 'KnownProxies' nor 'KnownNetworks' names "
            + "a trusted hop, so forwarded headers are ignored and the client address on every audit "
            + "entry will be the proxy's. List the reverse proxy under one of them.");
    }
}

app.UseMessengerErrorHandling();

if (isProduction)
{
    app.UseHsts();
    app.UseHttpsRedirection();
}

// Conservative security headers. The server has no browser UI of its own, so a restrictive
// CSP costs nothing and blocks content injection through any future admin web surface.
app.Use(async (context, next) =>
{
    var headers = context.Response.Headers;
    headers["X-Content-Type-Options"] = "nosniff";
    headers["X-Frame-Options"] = "DENY";
    headers["Referrer-Policy"] = "no-referrer";
    headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'";
    headers["Cache-Control"] = "no-store";
    await next();
});

app.UseRateLimiter();

// Roles must exist before the first request. A user with no roles can do nothing at all,
// so seeding is part of startup rather than a migration the operator might skip.
using (var scope = app.Services.CreateScope())
{
    var authorization = scope.ServiceProvider.GetRequiredService<AuthorizationService>();
    await authorization.SeedBuiltInRolesAsync();

    if (keyStoreCreated)
    {
        app.Logger.LogWarning(
            "A new root key was created at {Path}. Back up this file and its passphrase now. "
            + "Without them, a restore of the database and file store yields unreadable ciphertext.",
            keyStorePath);
    }

    if (auditKeyCreated)
    {
        app.Logger.LogWarning(
            "A new audit signing key was created at {Path}. Back it up with the root key. "
            + "Without it, existing audit checkpoints cannot be verified and the audit chain "
            + "keeps only its internal consistency, not its proof of origin.",
            auditKeyPath);
    }
}

// Liveness deliberately checks nothing: an orchestrator restarts a container that fails it,
// and restarting the server does not fix an unreachable database — it just adds an outage.
app.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false });

// Readiness is the one a load balancer should use to decide whether to send traffic here.
app.MapHealthChecks("/health/ready", new HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("ready"),
});
app.MapHub<ChatHub>("/hubs/chat");
app.MapAdminApi();

app.MapPost("/api/auth/login", async (
    LoginRequest request, AuthService auth, SessionService sessions,
    LicenseEnforcementService license, HttpContext http, CancellationToken ct) =>
{
    var ip = http.Connection.RemoteIpAddress?.ToString();
    var result = await auth.AuthenticateAsync(request.Username, request.Password, ip, ct);

    if (!result.Succeeded)
    {
        // Every AUTH-1xx collapses to one generic message here. The precise code is in the
        // audit log and the admin console; returning it to an unauthenticated caller would
        // be a free account-enumeration oracle.
        var code = result.ErrorCode == ErrorCode.PasswordChangeRequired
            ? ErrorCode.PasswordChangeRequired
            : ErrorCode.InvalidCredentials;

        return Results.Json(
            new ErrorDto(code, "Sign-in failed. Check your username and password.", null),
            statusCode: StatusCodes.Status401Unauthorized);
    }

    var user = result.User!;

    // Licence limits are applied only after the credential check passes. Checking first
    // would let an unauthenticated caller probe the deployment's seat and session usage.
    SessionPolicy policy;
    try
    {
        policy = await license.AuthoriseLoginAsync(user.Id, ct);
    }
    catch (MessengerException ex)
    {
        return Results.Json(new ErrorDto(ex.Code, ex.Message, null),
            statusCode: StatusCodes.Status403Forbidden);
    }

    var (token, session) = await sessions.CreateAsync(
        user, request.DeviceFingerprint, request.DeviceName, ip,
        AuthMethod.Password, policy, ct);

    return Results.Ok(new LoginResponse(
        token, user.Id, user.DisplayName, session.ExpiresAt,
        policy.IdleTimeoutSeconds, user.MustChangePassword));
}).RequireRateLimiting("login");

app.MapPost("/api/auth/logout", async (
    HttpContext http, SessionService sessions, CancellationToken ct) =>
{
    var token = http.Request.Headers["X-Session-Token"].FirstOrDefault();
    var device = http.Request.Headers["X-Device-Fingerprint"].FirstOrDefault();
    if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(device))
        return Results.Unauthorized();

    var validation = await sessions.ValidateAsync(token, device, SessionPolicy.Default, ct);
    if (validation.Session is not null)
        await sessions.RevokeAsync(validation.Session, "logout", ct);

    return Results.NoContent();
})
// Rate-limited like the rest of the authenticated surface. It does a token lookup before it
// knows who is calling, so leaving it open makes it the cheapest unauthenticated way to put
// load on the database.
.RequireRateLimiting("admin");

app.Run();

/// <summary>
/// Readiness: can this instance actually serve a request?
///
/// Every endpoint but the health checks themselves needs the database, so its reachability
/// is the whole of the answer. Reported as Unhealthy rather than thrown, so the probe
/// returns a 503 an orchestrator understands instead of a 500 that looks like a bug.
/// </summary>
public sealed class DatabaseHealthCheck(MessengerDbContext db) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context, CancellationToken ct = default)
    {
        try
        {
            return await db.Database.CanConnectAsync(ct)
                ? HealthCheckResult.Healthy("Database reachable.")
                : HealthCheckResult.Unhealthy($"{ErrorCode.DatabaseUnreachable}: database is not reachable.");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy($"{ErrorCode.DatabaseUnreachable}: {ex.Message}");
        }
    }
}

/// <summary>Exposed so the integration-test host can reference this assembly.</summary>
public partial class Program;
