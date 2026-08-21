using Messenger.Licensing;
using Microsoft.EntityFrameworkCore;

namespace Messenger.Owner;

public sealed record LoginRequest(string Username, string Password, string DeviceFingerprint);
public sealed record LoginResponse(string SessionToken, Guid OperatorId, string DisplayName, DateTimeOffset ExpiresAt);

public sealed record IssueLicenseRequest(
    string Customer, int MaxSeats, long MaxFileBytes, int MaxSessionsPerUser, int MaxSessionsTotal,
    int IdleTimeoutSeconds, int GracePeriodDays, int ValidDays, List<string> Features);

public sealed record LicenseIssuedResponse(string LicenseId, string LicenseFile);

public sealed record CustomerLicenseSummary(
    Guid Id, string LicenseId, string Customer, DateTimeOffset NotBefore,
    DateTimeOffset NotAfter, bool Revoked);

public sealed record TelemetryIngestRequest(string LicenseId, string EventType, string? PayloadJson);

/// <summary>
/// Authenticates a call against the owner session registry. Separate from the customer
/// server's <c>AdminAuthFilter</c> because it validates against <see cref="OwnerDbContext"/>,
/// a different database entirely -- an owner operator credential must never be checked
/// against, or reachable from, any customer's deployment.
/// </summary>
public sealed class OwnerAuthFilter(OwnerAuthService auth) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var http = context.HttpContext;
        var token = http.Request.Headers["X-Session-Token"].FirstOrDefault();
        var device = http.Request.Headers["X-Device-Fingerprint"].FirstOrDefault();

        if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(device))
            return Results.Json(new { code = "OWNER-AUTH-101", message = "Authentication required." },
                statusCode: StatusCodes.Status401Unauthorized);

        var validation = await auth.ValidateAsync(token, device, http.RequestAborted);
        if (!validation.IsValid || validation.Operator is null)
            return Results.Json(new { code = "OWNER-AUTH-102", message = "Authentication failed." },
                statusCode: StatusCodes.Status401Unauthorized);

        http.Items["OperatorId"] = validation.Operator.Id;
        return await next(context);
    }
}

public static class OwnerApiExtensions
{
    public static Guid OperatorId(this HttpContext http)
        => http.Items.TryGetValue("OperatorId", out var v) && v is Guid id ? id : Guid.Empty;
}

/// <summary>
/// The four owner-tier capabilities named in the README and reserved as permissions in
/// <c>Permissions.OwnerTierOnly</c> since before this project existed: licence issuance,
/// licence revocation, telemetry, and support chat (the last is <see cref="SupportHub"/>).
/// Deliberately not permission-gated per capability -- every seeded owner operator can do
/// all four, because this vendor-side console has a handful of staff accounts, not the kind
/// of org chart the customer server's five-role RBAC exists for.
/// </summary>
public static class OwnerApi
{
    public static void MapOwnerAuth(this WebApplication app)
    {
        app.MapPost("/api/owner/auth/login", async (
            LoginRequest request, OwnerAuthService auth, CancellationToken ct) =>
        {
            var result = await auth.AuthenticateAsync(request.Username, request.Password, ct);
            if (!result.Succeeded)
                return Results.Json(new { code = "OWNER-AUTH-101", message = "Sign-in failed." },
                    statusCode: StatusCodes.Status401Unauthorized);

            var (token, session) = await auth.CreateSessionAsync(result.Operator!.Id, request.DeviceFingerprint, ct);
            return Results.Ok(new LoginResponse(token, result.Operator.Id, result.Operator.DisplayName, session.ExpiresAt));
        });
    }

    public static void MapOwnerApi(this WebApplication app)
    {
        var owner = app.MapGroup("/api/owner").AddEndpointFilter<OwnerAuthFilter>();

        // ---- Licence issuance and revocation ------------------------------------------

        owner.MapPost("/licenses", async (
            IssueLicenseRequest request, OwnerDbContext db, VendorKeyProvider keys,
            TimeProvider time, HttpContext http, CancellationToken ct) =>
        {
            var now = time.GetUtcNow();
            var licenseId = $"LIC-{Guid.NewGuid():N}"[..16].ToUpperInvariant();

            var payload = new LicensePayload
            {
                LicenseId = licenseId,
                Customer = request.Customer,
                IssuedAt = now,
                NotBefore = now,
                NotAfter = now.AddDays(request.ValidDays),
                MaxSeats = request.MaxSeats,
                MaxFileBytes = request.MaxFileBytes,
                MaxSessionsPerUser = request.MaxSessionsPerUser,
                MaxSessionsTotal = request.MaxSessionsTotal,
                IdleTimeoutSeconds = request.IdleTimeoutSeconds,
                GracePeriodDays = request.GracePeriodDays,
                Features = request.Features,
            };

            var document = LicenseDocument.Issue(payload, keys.PrivateKey);
            var fileContent = document.ToFileFormat();

            db.CustomerLicenses.Add(new CustomerLicenseRecord
            {
                LicenseId = licenseId,
                Customer = request.Customer,
                RawDocument = fileContent,
                IssuedAt = now,
                NotBefore = payload.NotBefore,
                NotAfter = payload.NotAfter,
                IssuedBy = http.OperatorId(),
            });
            await db.SaveChangesAsync(ct);

            return Results.Created($"/api/owner/licenses/{licenseId}",
                new LicenseIssuedResponse(licenseId, fileContent));
        });

        owner.MapGet("/licenses", async (OwnerDbContext db, CancellationToken ct) =>
            Results.Ok(await db.CustomerLicenses
                .OrderByDescending(l => l.IssuedAt)
                .Select(l => new CustomerLicenseSummary(l.Id, l.LicenseId, l.Customer, l.NotBefore, l.NotAfter, l.Revoked))
                .ToListAsync(ct)));

        // Offline validation means this cannot un-validate a file already handed to a
        // customer -- see License.cs's design note. It only marks this vendor's own record
        // so revocation shows up here; enforcing it against a deployment requires either a
        // shorter validity window renewed via online activation, or the customer choosing to
        // install a new licence.
        owner.MapPost("/licenses/{id:guid}/revoke", async (
            Guid id, OwnerDbContext db, TimeProvider time, CancellationToken ct) =>
        {
            var record = await db.CustomerLicenses.FirstOrDefaultAsync(l => l.Id == id, ct);
            if (record is null) return Results.NotFound();

            record.Revoked = true;
            record.RevokedAt = time.GetUtcNow();
            await db.SaveChangesAsync(ct);
            return Results.NoContent();
        });

        // ---- Telemetry -----------------------------------------------------------------

        // Read is permissioned; ingest is not. A customer server posts here outbound-only
        // and holds no vendor credential to authenticate with -- it identifies itself by the
        // licence id it was issued, which is exactly as much trust as an opt-in heartbeat
        // needs.
        owner.MapGet("/telemetry", async (string? licenseId, OwnerDbContext db, CancellationToken ct) =>
        {
            var query = db.TelemetryEvents.AsQueryable();
            if (!string.IsNullOrEmpty(licenseId)) query = query.Where(t => t.LicenseId == licenseId);
            return Results.Ok(await query.OrderByDescending(t => t.ReceivedAt).Take(200).ToListAsync(ct));
        });
    }

    public static void MapTelemetryIngest(this WebApplication app)
    {
        app.MapPost("/api/owner/telemetry", async (
            TelemetryIngestRequest request, OwnerDbContext db, CancellationToken ct) =>
        {
            // Ingest carries no vendor credential (see the type's doc comment), but a licence
            // id is not a secret either -- it appears in support tickets and the licence file
            // itself. Without this check, anyone could post fabricated events under a real
            // customer's licence id, or for a licence id that was never issued at all.
            var known = await db.CustomerLicenses
                .AnyAsync(l => l.LicenseId == request.LicenseId && !l.Revoked, ct);
            if (!known) return Results.NotFound();

            db.TelemetryEvents.Add(new TelemetryEvent
            {
                LicenseId = request.LicenseId,
                EventType = request.EventType,
                PayloadJson = request.PayloadJson,
            });
            await db.SaveChangesAsync(ct);
            return Results.NoContent();
        });
    }
}
