using System.Security.Cryptography;
using Messenger.Crypto;
using Microsoft.EntityFrameworkCore;

namespace Messenger.Owner;

public sealed record OwnerAuthResult(bool Succeeded, OwnerOperator? Operator);

public sealed record OwnerSessionValidation(bool IsValid, OwnerOperator? Operator);

/// <summary>
/// Local-account auth and opaque sessions for vendor operators. Deliberately simpler than
/// the customer server's <c>AuthService</c>/<c>SessionService</c> pair -- no licence-driven
/// idle/absolute policy, no lockout backoff schedule, no directory sync -- because the owner
/// tier has a handful of vendor staff accounts, not an enterprise's user base. Same
/// primitives underneath: Argon2id via the shared <see cref="PasswordHasher"/>, and a
/// bearer token whose SHA-256 (never the token itself) is what gets persisted.
/// </summary>
public sealed class OwnerAuthService(
    OwnerDbContext db, PasswordHasher hasher, TimeProvider? timeProvider = null)
{
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;
    private static readonly TimeSpan SessionLifetime = TimeSpan.FromHours(12);

    public async Task<OwnerAuthResult> AuthenticateAsync(string username, string password, CancellationToken ct = default)
    {
        var op = await db.Operators.FirstOrDefaultAsync(o => o.Username == username, ct);
        if (op is null)
        {
            _ = hasher.Verify(password, DummyHash);
            return new OwnerAuthResult(false, null);
        }

        var verification = hasher.Verify(password, op.PasswordHash);
        return verification.Succeeded ? new OwnerAuthResult(true, op) : new OwnerAuthResult(false, null);
    }

    public async Task<(string Token, OwnerSession Session)> CreateSessionAsync(
        Guid operatorId, string deviceFingerprint, CancellationToken ct = default)
    {
        var now = _time.GetUtcNow();
        var tokenBytes = RandomNumberGenerator.GetBytes(32);
        var token = Convert.ToBase64String(tokenBytes);

        var session = new OwnerSession
        {
            OperatorId = operatorId,
            TokenHash = SHA256.HashData(tokenBytes),
            DeviceFingerprint = deviceFingerprint,
            CreatedAt = now,
            LastActivityAt = now,
            ExpiresAt = now + SessionLifetime,
        };

        db.Sessions.Add(session);
        await db.SaveChangesAsync(ct);
        return (token, session);
    }

    public async Task<OwnerSessionValidation> ValidateAsync(
        string token, string deviceFingerprint, CancellationToken ct = default)
    {
        byte[] hash;
        try
        {
            hash = SHA256.HashData(Convert.FromBase64String(token));
        }
        catch (FormatException)
        {
            return new OwnerSessionValidation(false, null);
        }

        var session = await db.Sessions.FirstOrDefaultAsync(s => s.TokenHash == hash, ct);
        if (session is null || session.RevokedAt is not null || session.DeviceFingerprint != deviceFingerprint)
            return new OwnerSessionValidation(false, null);

        var now = _time.GetUtcNow();
        if (now >= session.ExpiresAt)
            return new OwnerSessionValidation(false, null);

        session.LastActivityAt = now;
        await db.SaveChangesAsync(ct);

        var op = await db.Operators.FirstAsync(o => o.Id == session.OperatorId, ct);
        return new OwnerSessionValidation(true, op);
    }

    private static readonly string DummyHash =
        new PasswordHasher().Hash(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
}
