using Messenger.Contracts;
using Messenger.Core;
using Messenger.Data;
using Messenger.Licensing;
using Microsoft.EntityFrameworkCore;

namespace Messenger.Server;

/// <summary>
/// The server-side half of the admin console. The WPF console is a client of these
/// endpoints, so all management logic lives here and is testable without a UI.
/// </summary>
public static class AdminApi
{
    public static void MapAdminApi(this WebApplication app)
    {
        var admin = app.MapGroup("/api/admin")
            .AddEndpointFilter<AdminAuthFilter>()
            .RequireRateLimiting("admin");

        // Every route below declares the permission it needs. Authentication alone is not
        // authorization: without this, any authenticated end user could manage accounts,
        // revoke sessions, and read the entire audit log.
        RouteHandlerBuilder Require(RouteHandlerBuilder route, string permission)
            => route.AddEndpointFilter(new RequirePermissionFilter(permission));

        // ---- Users -------------------------------------------------------------------

        // Paging parameters are optional. Declared as required non-nullable ints, minimal-API
        // binding fails before the auth filter runs, so an unauthenticated caller would get a
        // 400 instead of a 401 -- an inconsistency that also tells them the endpoint exists.
        Require(admin.MapGet("/users", async (MessengerDbContext db, int? page, int? pageSize, CancellationToken ct) =>
        {
            var size = Math.Clamp(pageSize ?? 50, 1, 200);
            var users = await db.Users
                .Where(u => u.DeletedAt == null)
                .OrderBy(u => u.Username)
                .Skip(Math.Max(page ?? 0, 0) * size).Take(size)
                .Select(u => new UserSummary(u.Id, u.Username, u.DisplayName, u.Email,
                    u.Source.ToString(), u.Status.ToString(), u.LastLoginAt))
                .ToListAsync(ct);
            return Results.Ok(users);
        }), Permissions.UsersRead);

        Require(admin.MapPost("/users", async (
            CreateUserRequest request, MessengerDbContext db, AuthService auth,
            LicenseEnforcementService license, AuditService audit,
            AuthorizationService authorization, SessionService sessions,
            HttpContext http, CancellationToken ct) =>
        {
            var actorId = http.ActorId();

            // Every rejectable condition is checked before the first write. Creating the row
            // first and validating afterwards left a failed request behind as a real account:
            // no password, no role, and a consumed licence seat, invisible until an
            // administrator wondered why the seat count was wrong.
            if (Invalid(request.Username, 256, out var usernameError))
                return Problem(ErrorCode.MalformedRequest, $"Username {usernameError}");
            if (Invalid(request.DisplayName, 256, out var displayNameError))
                return Problem(ErrorCode.MalformedRequest, $"Display name {displayNameError}");
            if (request.Email is { Length: > 320 })
                return Problem(ErrorCode.MalformedRequest, "Email address is too long.");

            AuthService.ValidatePasswordPolicy(request.InitialPassword);

            // Seat enforcement happens at provisioning, not at login: an administrator must
            // learn they are out of seats when creating the account, not when the user is
            // turned away days later.
            await license.EnsureSeatAvailableAsync(ct: ct);

            if (await db.Users.AnyAsync(u => u.Username == request.Username && u.DeletedAt == null, ct))
                return Problem(ErrorCode.UserAlreadyExists, "A user with that name already exists.");

            var user = new User
            {
                Username = request.Username,
                DisplayName = request.DisplayName,
                Email = request.Email,
                Source = UserSource.Local,
                MustChangePassword = true,
            };
            db.Users.Add(user);

            try
            {
                await db.SaveChangesAsync(ct);
            }
            catch (DbUpdateException)
            {
                // Lost the race against a concurrent create of the same username; the unique
                // index did its job. Report it as the same conflict the upfront check
                // reports, rather than an opaque 500.
                return Problem(ErrorCode.UserAlreadyExists, "A user with that name already exists.");
            }

            await auth.SetPasswordAsync(user, request.InitialPassword, sessions, ct);
            user.MustChangePassword = true;
            await db.SaveChangesAsync(ct);

            // Without a role a new account can do nothing at all -- not even chat. Failing
            // closed is right for administration but would be an outage for ordinary users.
            await authorization.EnsureDefaultRoleAsync(user.Id, ct);

            await audit.AppendAsync("user.create", "success", actorId, "admin",
                http.ClientIp(), "user", user.Id, null, ct);

            return Results.Created($"/api/admin/users/{user.Id}", new { user.Id });
        }), Permissions.UsersCreate);

        Require(admin.MapPost("/users/{id:guid}/status", async (
            Guid id, SetStatusRequest request, MessengerDbContext db,
            LicenseEnforcementService license, SessionService sessions,
            AuditService audit, HttpContext http, CancellationToken ct) =>
        {
            var actorId = http.ActorId();

            // An administrator disabling their own account would lock themselves out of the
            // console with no way back short of database surgery.
            if (id == actorId)
                return Problem(ErrorCode.SelfModificationRefused,
                    "Have another administrator change your own account status.");

            // Parsed before the lookup so an unrecognised status is a 400 naming the valid
            // values, not an unhandled ArgumentException surfacing as an opaque 500.
            if (!Enum.TryParse<UserStatus>(request.Status, ignoreCase: true, out var target)
                || !Enum.IsDefined(target))
            {
                return Problem(ErrorCode.MalformedRequest,
                    $"Status must be one of: {string.Join(", ", Enum.GetNames<UserStatus>())}.");
            }

            var user = await db.Users.FirstOrDefaultAsync(u => u.Id == id && u.DeletedAt == null, ct);
            if (user is null) return Problem(ErrorCode.AccountNotFound, "User not found.");
            if (target == UserStatus.Active && user.Status != UserStatus.Active)
                await license.EnsureSeatAvailableAsync(user.Id, ct);

            user.Status = target;
            await db.SaveChangesAsync(ct);

            // Deactivation must take effect now, not when the user's session happens to
            // expire. Revoking is the difference between a policy and an enforcement.
            if (target != UserStatus.Active)
                await sessions.RevokeAllForUserAsync(user.Id, "deactivated", ct);

            await audit.AppendAsync("user.set_status", "success", actorId, "admin",
                http.ClientIp(), "user", user.Id, $"{{\"status\":\"{target}\"}}", ct);

            return Results.NoContent();
        }), Permissions.UsersSetStatus);

        // ---- Groups ------------------------------------------------------------------

        Require(admin.MapGet("/groups", async (MessengerDbContext db, CancellationToken ct) =>
            Results.Ok(await db.Groups
                .Where(g => g.DeletedAt == null)
                .OrderBy(g => g.Name)
                .Select(g => new GroupSummary(g.Id, g.Name, g.Description, g.Type.ToString(),
                    g.Source.ToString(), g.Status.ToString(), g.Members.Count))
                .ToListAsync(ct))), Permissions.GroupsRead);

        Require(admin.MapPost("/groups", async (
            CreateGroupRequest request, GroupService groups, HttpContext http, CancellationToken ct) =>
        {
            var group = await groups.CreateAsync(request.Name, request.Description, http.ActorId(), ct: ct);
            return Results.Created($"/api/admin/groups/{group.Id}", new { group.Id, group.ConversationId });
        }), Permissions.GroupsManage);

        Require(admin.MapPost("/groups/{id:guid}/members/{userId:guid}", async (
            Guid id, Guid userId, GroupService groups, HttpContext http, CancellationToken ct) =>
        {
            await groups.AddMemberAsync(id, userId, http.ActorId(), ct: ct);
            return Results.NoContent();
        }), Permissions.GroupsMembership);

        Require(admin.MapDelete("/groups/{id:guid}/members/{userId:guid}", async (
            Guid id, Guid userId, GroupService groups, HttpContext http, CancellationToken ct) =>
        {
            await groups.RemoveMemberAsync(id, userId, http.ActorId(), ct);
            return Results.NoContent();
        }), Permissions.GroupsMembership);

        Require(admin.MapPost("/groups/{id:guid}/move/{userId:guid}/to/{targetId:guid}", async (
            Guid id, Guid userId, Guid targetId, GroupService groups, HttpContext http, CancellationToken ct) =>
        {
            await groups.MoveMemberAsync(id, targetId, userId, http.ActorId(), ct);
            return Results.NoContent();
        }), Permissions.GroupsMembership);

        // ---- Directory sync ----------------------------------------------------------

        Require(admin.MapPost("/directory/sync", async (
            DirectorySyncService sync, LicenseEnforcementService license,
            MessengerDbContext db, CancellationToken ct) =>
        {
            await license.EnsureFeatureAsync(LicenseFeature.AdSync, ct);

            var watermark = await db.ServerSettings
                .Where(s => s.Key == "directory.watermark")
                .Select(s => s.Value).FirstOrDefaultAsync(ct);

            var report = await sync.SyncAsync(long.TryParse(watermark, out var usn) ? usn : 0, ct: ct);

            var setting = await db.ServerSettings.FirstOrDefaultAsync(s => s.Key == "directory.watermark", ct);
            if (setting is null)
                db.ServerSettings.Add(new ServerSetting { Key = "directory.watermark", Value = report.HighestUsn.ToString() });
            else
                setting.Value = report.HighestUsn.ToString();

            await db.SaveChangesAsync(ct);
            return Results.Ok(report);
        }), Permissions.DirectorySync);

        // ---- Sessions ----------------------------------------------------------------

        Require(admin.MapGet("/sessions", async (MessengerDbContext db, TimeProvider time, CancellationToken ct) =>
        {
            var now = time.GetUtcNow();
            return Results.Ok(await db.Sessions
                .Where(s => s.RevokedAt == null && s.ExpiresAt > now)
                .OrderByDescending(s => s.LastActivityAt)
                .Select(s => new SessionSummary(s.Id, s.UserId, s.User.Username, s.DeviceName,
                    s.IpAddress, s.AuthMethod.ToString(), s.CreatedAt, s.LastActivityAt))
                .ToListAsync(ct));
        }), Permissions.SessionsRead);

        Require(admin.MapDelete("/sessions/{id:guid}", async (
            Guid id, MessengerDbContext db, SessionService sessions,
            AuditService audit, HttpContext http, CancellationToken ct) =>
        {
            var session = await db.Sessions.FirstOrDefaultAsync(s => s.Id == id, ct);
            if (session is null) return Problem(ErrorCode.SessionTokenInvalid, "Session not found.");

            await sessions.RevokeAsync(session, "admin", ct);
            await audit.AppendAsync("session.revoke", "success", http.ActorId(), "admin",
                http.ClientIp(), "session", id, null, ct);

            return Results.NoContent();
        }), Permissions.SessionsRevoke);

        // ---- Licence -----------------------------------------------------------------

        Require(admin.MapGet("/license", async (LicenseEnforcementService license, CancellationToken ct) =>
        {
            var usage = await license.GetUsageAsync(ct);
            return Results.Ok(new
            {
                state = usage.Status.State.ToString(),
                code = usage.Status.ErrorCode,
                detail = usage.Status.Detail,
                customer = usage.Status.Payload?.Customer,
                expires = usage.Status.Payload?.NotAfter,
                graceEndsAt = usage.Status.GraceEndsAt,
                seatsUsed = usage.SeatsUsed,
                seatsAllowed = usage.SeatsAllowed,
                sessionsActive = usage.SessionsActive,
                sessionsAllowed = usage.SessionsAllowed,
                nearSeatLimit = usage.IsNearSeatLimit,
                features = usage.Status.Payload?.Features ?? [],
            });
        }), Permissions.LicenseRead);

        Require(admin.MapPost("/license", async (
            InstallLicenseRequest request, LicenseEnforcementService license,
            HttpContext http, CancellationToken ct) =>
        {
            var status = await license.InstallAsync(request.LicenseFile, http.ActorId(), ct);
            return Results.Ok(new { state = status.State.ToString(), detail = status.Detail });
        }), Permissions.LicenseInstall);

        // ---- Audit -------------------------------------------------------------------

        Require(admin.MapGet("/audit", async (MessengerDbContext db, long? fromId, int? limit, CancellationToken ct) =>
        {
            var take = Math.Clamp(limit ?? 100, 1, 500);
            var from = fromId ?? 0;
            return Results.Ok(await db.AuditLog
                .Where(e => e.Id >= from)
                .OrderBy(e => e.Id).Take(take)
                .Select(e => new AuditEntrySummary(e.Id, e.OccurredAt, e.ActorUserId, e.ActorTier,
                    e.ActorIp, e.Action, e.TargetType, e.TargetId, e.Outcome, e.DetailJson))
                .ToListAsync(ct));
        }), Permissions.AuditRead);

        // Both halves are reported. The hash chain proves the entries are internally
        // consistent; the checkpoint signatures prove the chain is the one this server
        // actually wrote. A rewritten chain with recomputed hashes passes the first and fails
        // the second, so reporting only the first would call a forged log valid.
        Require(admin.MapPost("/audit/verify", async (AuditService audit, CancellationToken ct) =>
        {
            var result = await audit.VerifyAsync(ct: ct);
            var checkpoints = await audit.VerifyCheckpointsAsync(ct);
            var valid = result.IsValid && checkpoints.IsValid;

            return Results.Ok(new
            {
                valid,
                firstInvalidEntryId = result.FirstInvalidEntryId,
                checkpointsVerified = checkpoints.Verified,
                checkpointsUnverifiable = checkpoints.Unverifiable,
                firstInvalidCheckpointId = checkpoints.FirstInvalidCheckpointId,
                checkpointDetail = checkpoints.Detail,
                code = valid ? null : ErrorCode.AuditChainVerificationFailed,
            });
        }), Permissions.AuditVerify);

        // ---- Health ------------------------------------------------------------------

        Require(admin.MapGet("/health", async (
            MessengerDbContext db, IConnectionRegistry registry,
            LicenseEnforcementService license, TimeProvider time, CancellationToken ct) =>
        {
            var now = time.GetUtcNow();
            return Results.Ok(new
            {
                databaseReachable = await db.Database.CanConnectAsync(ct),
                activeSessions = await db.Sessions.CountAsync(s => s.RevokedAt == null && s.ExpiresAt > now, ct),
                users = await db.Users.CountAsync(u => u.DeletedAt == null, ct),
                groups = await db.Groups.CountAsync(g => g.DeletedAt == null, ct),
                messages = await db.Messages.CountAsync(ct),
                pendingDeliveries = await db.MessageRecipients.CountAsync(r => r.State == DeliveryState.Pending, ct),
                license = (await license.GetStatusAsync(ct)).State.ToString(),
                serverTime = now,
            });
        }), Permissions.ServerHealth);
    }

    private static IResult Problem(string code, string message)
        => Results.Json(new ErrorDto(code, message, null), statusCode: StatusCodes.Status400BadRequest);

    /// <summary>
    /// Rejects a required string that is missing, blank, or longer than the column that has
    /// to hold it. Length is checked here rather than left to the database, where an
    /// over-long value becomes a DbUpdateException and reaches the caller as a 500.
    /// </summary>
    private static bool Invalid(string? value, int maxLength, out string reason)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            reason = "is required.";
            return true;
        }

        if (value.Length > maxLength)
        {
            reason = $"must be {maxLength} characters or fewer.";
            return true;
        }

        reason = string.Empty;
        return false;
    }
}

public sealed record UserSummary(Guid Id, string Username, string DisplayName, string? Email,
    string Source, string Status, DateTimeOffset? LastLoginAt);

public sealed record GroupSummary(Guid Id, string Name, string? Description, string Type,
    string Source, string Status, int MemberCount);

public sealed record SessionSummary(Guid Id, Guid UserId, string Username, string? DeviceName,
    string? IpAddress, string AuthMethod, DateTimeOffset CreatedAt, DateTimeOffset LastActivityAt);

public sealed record AuditEntrySummary(long Id, DateTimeOffset OccurredAt, Guid? ActorUserId,
    string ActorTier, string? ActorIp, string Action, string? TargetType, Guid? TargetId,
    string Outcome, string? DetailJson);

public sealed record CreateUserRequest(string Username, string DisplayName, string? Email, string InitialPassword);
public sealed record SetStatusRequest(string Status);
public sealed record CreateGroupRequest(string Name, string? Description);
public sealed record InstallLicenseRequest(string LicenseFile);

/// <summary>
/// Authenticates every admin call against the session registry and requires an admin role.
///
/// Re-validating per request rather than trusting a long-lived credential is what makes
/// revocation immediate — an administrator stripped of rights loses them on their next
/// call, not when their session happens to expire.
/// </summary>
public sealed class AdminAuthFilter(SessionService sessions) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var http = context.HttpContext;
        var token = http.Request.Headers["X-Session-Token"].FirstOrDefault();
        var device = http.Request.Headers["X-Device-Fingerprint"].FirstOrDefault();

        if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(device))
            return Results.Json(new ErrorDto(ErrorCode.SessionTokenInvalid, "Authentication required.", null),
                statusCode: StatusCodes.Status401Unauthorized);

        var validation = await sessions.ValidateAsync(token, device, SessionPolicy.Default);
        if (!validation.IsValid || validation.Session is null)
            return Results.Json(new ErrorDto(validation.ErrorCode ?? ErrorCode.SessionTokenInvalid,
                    "Authentication failed.", null),
                statusCode: StatusCodes.Status401Unauthorized);

        http.Items["ActorId"] = validation.Session.UserId;
        return await next(context);
    }
}

/// <summary>
/// Enforces a single permission on a route. Runs after <see cref="AdminAuthFilter"/>, so an
/// actor is always present by the time it executes.
///
/// The permission is re-checked per request rather than cached in the session, so removing
/// a role takes effect on the actor's very next call rather than whenever their session
/// happens to expire.
/// </summary>
public sealed class RequirePermissionFilter(string permission) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var http = context.HttpContext;
        var actorId = http.ActorId();

        if (actorId == Guid.Empty)
        {
            return Results.Json(new ErrorDto(ErrorCode.SessionTokenInvalid, "Authentication required.", null),
                statusCode: StatusCodes.Status401Unauthorized);
        }

        var authorization = http.RequestServices.GetRequiredService<AuthorizationService>();

        if (!await authorization.HasPermissionAsync(actorId, permission, http.RequestAborted))
        {
            var audit = http.RequestServices.GetRequiredService<AuditService>();
            await audit.AppendAsync("authz.deny", "denied", actorId, "admin", http.ClientIp(),
                null, null, $"{{\"permission\":\"{permission}\"}}", http.RequestAborted);

            // 403 rather than 404: the caller is authenticated, and pretending the endpoint
            // does not exist would not hide anything they cannot already infer.
            return Results.Json(
                new ErrorDto(ErrorCode.PermissionDenied,
                    $"This action requires the '{permission}' permission.", null),
                statusCode: StatusCodes.Status403Forbidden);
        }

        return await next(context);
    }
}

public static class HttpContextExtensions
{
    public static Guid ActorId(this HttpContext http)
        => http.Items.TryGetValue("ActorId", out var v) && v is Guid id ? id : Guid.Empty;

    public static string? ClientIp(this HttpContext http)
        => http.Connection.RemoteIpAddress?.ToString();
}
