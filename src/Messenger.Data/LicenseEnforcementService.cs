using Messenger.Contracts;
using Messenger.Core;
using Messenger.Licensing;
using Microsoft.EntityFrameworkCore;

namespace Messenger.Data;

/// <summary>
/// Applies licence limits at the points where they bite: login, user activation, feature
/// invocation, and file upload.
///
/// Enforcement is centralised here rather than scattered through the services it
/// constrains, so the limits a customer is subject to can be read in one place — and so a
/// new call site cannot quietly bypass one.
/// </summary>
public sealed class LicenseEnforcementService(
    MessengerDbContext db,
    LicenseValidator validator,
    AuditService audit,
    TimeProvider? timeProvider = null)
{
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    public async Task<LicenseStatus> GetStatusAsync(CancellationToken ct = default)
    {
        var record = await db.Licenses
            .Where(l => l.IsActive)
            .OrderByDescending(l => l.InstalledAt)
            .FirstOrDefaultAsync(ct);

        if (record is null) return validator.Validate(null);

        LicenseDocument document;
        try
        {
            document = LicenseDocument.Parse(record.RawDocument);
        }
        catch (MessengerException ex)
        {
            return new LicenseStatus(LicenseState.Invalid, null, ex.Code, ex.Message, null);
        }

        return validator.Validate(document);
    }

    public async Task<LicenseStatus> InstallAsync(string fileContent, Guid actorId, CancellationToken ct = default)
    {
        var document = LicenseDocument.Parse(fileContent);
        var status = validator.Validate(document);

        // An invalid licence is never stored. Storing it would leave the server in a state
        // where the installed licence and the enforced licence disagree.
        if (status.State is LicenseState.Invalid)
        {
            await audit.AppendAsync("license.install", "denied", actorId, "admin", null, null, null,
                $"{{\"code\":\"{status.ErrorCode}\"}}", ct);
            throw new MessengerException(status.ErrorCode!, status.Detail!);
        }

        foreach (var existing in await db.Licenses.Where(l => l.IsActive).ToListAsync(ct))
            existing.IsActive = false;

        db.Licenses.Add(new LicenseRecord
        {
            RawDocument = fileContent.Trim(),
            LicenseId = status.Payload!.LicenseId,
            Customer = status.Payload.Customer,
            NotBefore = status.Payload.NotBefore,
            NotAfter = status.Payload.NotAfter,
            IsActive = true,
            InstalledAt = _time.GetUtcNow(),
            InstalledBy = actorId,
        });

        await db.SaveChangesAsync(ct);
        await audit.AppendAsync("license.install", "success", actorId, "admin", null, null, null,
            $"{{\"license_id\":\"{status.Payload.LicenseId}\",\"state\":\"{status.State}\"}}", ct);

        return status;
    }

    /// <summary>
    /// Login-time enforcement. Returns the session policy the licence dictates, or throws
    /// with the specific code so the administrator sees which limit was hit.
    /// </summary>
    public async Task<SessionPolicy> AuthoriseLoginAsync(Guid userId, CancellationToken ct = default)
    {
        var status = await GetStatusAsync(ct);

        switch (status.State)
        {
            case LicenseState.Missing:
                throw new MessengerException(ErrorCode.NoLicenseInstalled,
                    "No licence is installed. Install one via the admin console.");
            case LicenseState.Invalid:
                throw new MessengerException(status.ErrorCode!, status.Detail!);
            case LicenseState.NotYetValid:
                throw new MessengerException(ErrorCode.LicenseNotYetValid, status.Detail!);
            case LicenseState.Grace:
                throw new MessengerException(ErrorCode.LicenseExpired, status.Detail!);
            case LicenseState.Expired:
                throw new MessengerException(ErrorCode.GracePeriodExpired, status.Detail!);
        }

        var payload = status.Payload!;
        var now = _time.GetUtcNow();

        var totalActive = await db.Sessions.CountAsync(
            s => s.RevokedAt == null && s.ExpiresAt > now, ct);
        if (totalActive >= payload.MaxSessionsTotal)
        {
            await audit.AppendAsync("license.enforce", "denied", userId, "system", null, null, null,
                $"{{\"code\":\"{ErrorCode.TotalSessionLimit}\",\"active\":{totalActive}}}", ct);
            throw new MessengerException(ErrorCode.TotalSessionLimit,
                $"The licence permits {payload.MaxSessionsTotal} concurrent sessions and {totalActive} are active.");
        }

        return new SessionPolicy(
            payload.IdleTimeoutSeconds,
            SessionPolicy.Default.AbsoluteLifetimeSeconds,
            payload.MaxSessionsPerUser);
    }

    /// <summary>
    /// Seat enforcement, checked when activating a user rather than at login. A seat is a
    /// provisioned account, so the limit belongs where accounts are provisioned — failing at
    /// login would let an administrator over-provision and only discover it when users
    /// started being turned away.
    /// </summary>
    public async Task EnsureSeatAvailableAsync(Guid? activatingUserId = null, CancellationToken ct = default)
    {
        var status = await GetStatusAsync(ct);
        if (status.Payload is null) return;

        var activeSeats = await db.Users.CountAsync(
            u => u.Status == UserStatus.Active && u.DeletedAt == null
                 && (activatingUserId == null || u.Id != activatingUserId), ct);

        if (activeSeats >= status.Payload.MaxSeats)
        {
            throw new MessengerException(ErrorCode.SeatLimitReached,
                $"The licence permits {status.Payload.MaxSeats} seats and {activeSeats} are in use. "
                + "Deactivate unused accounts or purchase more seats.");
        }
    }

    public async Task EnsureFeatureAsync(string feature, CancellationToken ct = default)
    {
        var status = await GetStatusAsync(ct);

        if (status.Payload is null || !status.Payload.Features.Contains(feature))
            throw new MessengerException(ErrorCode.FeatureNotLicensed,
                $"The feature '{feature}' is not included in this licence.");
    }

    /// <summary>Current usage against the licence, for the console dashboard and renewal conversations.</summary>
    public async Task<LicenseUsage> GetUsageAsync(CancellationToken ct = default)
    {
        var status = await GetStatusAsync(ct);
        var now = _time.GetUtcNow();

        return new LicenseUsage(
            status,
            SeatsUsed: await db.Users.CountAsync(u => u.Status == UserStatus.Active && u.DeletedAt == null, ct),
            SeatsAllowed: status.Payload?.MaxSeats ?? 0,
            SessionsActive: await db.Sessions.CountAsync(s => s.RevokedAt == null && s.ExpiresAt > now, ct),
            SessionsAllowed: status.Payload?.MaxSessionsTotal ?? 0);
    }
}

public sealed record LicenseUsage(
    LicenseStatus Status,
    int SeatsUsed,
    int SeatsAllowed,
    int SessionsActive,
    int SessionsAllowed)
{
    public bool IsNearSeatLimit => SeatsAllowed > 0 && SeatsUsed >= SeatsAllowed * 0.9;
}
