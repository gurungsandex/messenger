using Messenger.Contracts;
using Messenger.Crypto;
using Messenger.Data;
using Messenger.Server;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSignalR();
builder.Services.AddSingleton<IConnectionRegistry, InMemoryConnectionRegistry>();
builder.Services.AddSingleton<MessageCipher>();
builder.Services.AddSingleton<PasswordHasher>();
builder.Services.AddSingleton<IAuditSigningKeyProvider, InMemoryAuditSigningKeyProvider>();
builder.Services.AddSingleton(TimeProvider.System);

// Development key store. Production uses the DPAPI-NG or TPM provider, which keeps the KEK
// outside the process; this one holds it in memory and is not a substitute.
builder.Services.AddSingleton<IKeyStoreProvider>(_ => PassphraseKeyStoreProvider.Create());

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
builder.Services.AddScoped<MessageService>();
builder.Services.AddScoped<PresenceService>();

builder.Services.AddHealthChecks();

var app = builder.Build();

app.MapHealthChecks("/health/live");
app.MapHub<ChatHub>("/hubs/chat");

app.MapPost("/api/auth/login", async (
    LoginRequest request, AuthService auth, SessionService sessions,
    HttpContext http, CancellationToken ct) =>
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
    var (token, session) = await sessions.CreateAsync(
        user, request.DeviceFingerprint, request.DeviceName, ip,
        AuthMethod.Password, SessionPolicy.Default, ct);

    return Results.Ok(new LoginResponse(
        token, user.Id, user.DisplayName, session.ExpiresAt,
        SessionPolicy.Default.IdleTimeoutSeconds, user.MustChangePassword));
});

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
});

app.Run();

/// <summary>Exposed so the integration-test host can reference this assembly.</summary>
public partial class Program;
