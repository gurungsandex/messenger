using System.Security.Cryptography;
using Messenger.Contracts;
using Messenger.Core;
using Microsoft.EntityFrameworkCore;

namespace Messenger.Data;

public sealed record SessionPolicy(
    int IdleTimeoutSeconds,
    int AbsoluteLifetimeSeconds,
    int MaxConcurrentSessionsPerUser)
{
    /// <summary>Defaults used until a licence supplies the real limits (LIC-104, AUTH-201).</summary>
    public static readonly SessionPolicy Default = new(900, 43200, 3);
}

public sealed record SessionValidation(bool IsValid, Session? Session, string? ErrorCode);

/// <summary>
/// Server-side opaque sessions. Deliberately not self-contained JWTs: the licence enforces
/// concurrent-session counts and idle timeout, and revocation must take effect immediately.
/// A stateless token cannot be counted or revoked without a server-side registry anyway.
/// </summary>
public sealed class SessionService(MessengerDbContext db, TimeProvider? timeProvider = null)
{
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    /// <summary>
    /// Issues a session and returns the plaintext token, which is the only time it exists.
    /// Only its SHA-256 is persisted, so a database reader cannot replay a session.
    /// </summary>
    public async Task<(string Token, Session Session)> CreateAsync(
        User user, string deviceFingerprint, string? deviceName, string? ip,
        AuthMethod authMethod, SessionPolicy policy, CancellationToken ct = default)
    {
        var now = _time.GetUtcNow();
        await EnforceConcurrencyLimitAsync(user.Id, policy, now, ct);

        var tokenBytes = RandomNumberGenerator.GetBytes(32);
        var token = Convert.ToBase64String(tokenBytes);

        var session = new Session
        {
            UserId = user.Id,
            TokenHash = SHA256.HashData(tokenBytes),
            DeviceFingerprint = deviceFingerprint,
            DeviceName = deviceName,
            IpAddress = ip,
            AuthMethod = authMethod,
            CreatedAt = now,
            LastActivityAt = now,
            ExpiresAt = now.AddSeconds(policy.AbsoluteLifetimeSeconds),
        };

        db.Sessions.Add(session);
        await db.SaveChangesAsync(ct);
        return (token, session);
    }

    /// <summary>
    /// Validates a bearer token and slides the idle window. Ordering matters here: the
    /// distinct expiry reasons are separate codes (AUTH-201 idle vs AUTH-202 absolute)
    /// because they mean different things to an administrator reading the log.
    /// </summary>
    public async Task<SessionValidation> ValidateAsync(
        string token, string deviceFingerprint, SessionPolicy policy, CancellationToken ct = default)
    {
        byte[] hash;
        try
        {
            hash = SHA256.HashData(Convert.FromBase64String(token));
        }
        catch (FormatException)
        {
            return new SessionValidation(false, null, Contracts.ErrorCode.SessionTokenInvalid);
        }

        var session = await db.Sessions.Include(s => s.User).FirstOrDefaultAsync(s => s.TokenHash == hash, ct);
        if (session is null)
            return new SessionValidation(false, null, Contracts.ErrorCode.SessionTokenInvalid);

        if (session.RevokedAt is not null)
        {
            var code = session.RevokeReason switch
            {
                "admin" => Contracts.ErrorCode.SessionRevokedByAdmin,
                "password_change" => Contracts.ErrorCode.SessionRevokedPasswordChange,
                _ => Contracts.ErrorCode.SessionTokenInvalid,
            };
            return new SessionValidation(false, session, code);
        }

        var now = _time.GetUtcNow();

        if (now >= session.ExpiresAt)
        {
            await RevokeAsync(session, "expired", ct);
            return new SessionValidation(false, session, Contracts.ErrorCode.SessionExpiredAbsolute);
        }

        if ((now - session.LastActivityAt).TotalSeconds >= policy.IdleTimeoutSeconds)
        {
            await RevokeAsync(session, "idle", ct);
            return new SessionValidation(false, session, Contracts.ErrorCode.SessionExpiredIdle);
        }

        // Binding the token to its device turns a stolen token into a much narrower problem.
        if (!string.Equals(session.DeviceFingerprint, deviceFingerprint, StringComparison.Ordinal))
            return new SessionValidation(false, session, Contracts.ErrorCode.SessionDeviceMismatch);

        if (session.User.Status != UserStatus.Active || session.User.DeletedAt is not null)
        {
            await RevokeAsync(session, "deactivated", ct);
            return new SessionValidation(false, session, Contracts.ErrorCode.AccountDisabled);
        }

        session.LastActivityAt = now;
        await db.SaveChangesAsync(ct);
        return new SessionValidation(true, session, null);
    }

    public async Task RevokeAsync(Session session, string reason, CancellationToken ct = default)
    {
        session.RevokedAt = _time.GetUtcNow();
        session.RevokeReason = reason;
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Revokes every live session for a user — password change, deactivation, admin action.</summary>
    public async Task<int> RevokeAllForUserAsync(Guid userId, string reason, CancellationToken ct = default)
    {
        var now = _time.GetUtcNow();
        var sessions = await db.Sessions
            .Where(s => s.UserId == userId && s.RevokedAt == null)
            .ToListAsync(ct);

        foreach (var s in sessions)
        {
            s.RevokedAt = now;
            s.RevokeReason = reason;
        }

        await db.SaveChangesAsync(ct);
        return sessions.Count;
    }

    /// <summary>
    /// Enforces the per-user concurrent-session cap. Rather than refusing the new login, the
    /// oldest session is displaced — refusing would let a user lock themselves out by leaving
    /// a session open on a machine they no longer have access to.
    /// </summary>
    private async Task EnforceConcurrencyLimitAsync(
        Guid userId, SessionPolicy policy, DateTimeOffset now, CancellationToken ct)
    {
        // Ordering happens client-side: the live set is bounded by the concurrency limit
        // plus a handful, so materialising it costs nothing, and it keeps this query free
        // of provider-specific timestamp ordering support.
        var live = (await db.Sessions
                .Where(s => s.UserId == userId && s.RevokedAt == null && s.ExpiresAt > now)
                .ToListAsync(ct))
            .OrderBy(s => s.LastActivityAt)
            .ToList();

        var excess = live.Count - policy.MaxConcurrentSessionsPerUser + 1;
        for (int i = 0; i < excess && i < live.Count; i++)
        {
            live[i].RevokedAt = now;
            live[i].RevokeReason = "concurrent_limit";
        }

        if (excess > 0) await db.SaveChangesAsync(ct);
    }
}
