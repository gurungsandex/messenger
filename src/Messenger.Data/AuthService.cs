using Messenger.Contracts;
using Messenger.Core;
using Messenger.Crypto;
using Microsoft.EntityFrameworkCore;

namespace Messenger.Data;

public sealed record AuthResult(bool Succeeded, User? User, string? ErrorCode);

/// <summary>
/// Local-account authentication with Argon2id.
///
/// Failure handling here is deliberately shaped by the account-enumeration concern in
/// docs/error-codes.md: the caller receives a precise code for the log and the admin
/// console, but the transport layer must collapse every AUTH-1xx into one generic message
/// for the end user. Telling an unauthenticated caller the difference between "no such
/// user", "wrong password", and "disabled" is a free enumeration oracle.
/// </summary>
public sealed class AuthService(
    MessengerDbContext db,
    PasswordHasher hasher,
    AuditService audit,
    TimeProvider? timeProvider = null)
{
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    /// <summary>Soft backoff schedule. Capped, and never a permanent lockout.</summary>
    private static readonly TimeSpan[] BackoffSchedule =
    [
        TimeSpan.Zero, TimeSpan.Zero, TimeSpan.Zero,
        TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(60),
        TimeSpan.FromMinutes(5),
    ];

    public async Task<AuthResult> AuthenticateAsync(
        string username, string password, string? ip = null, CancellationToken ct = default)
    {
        var now = _time.GetUtcNow();
        var user = await db.Users.FirstOrDefaultAsync(
            u => u.Username == username && u.DeletedAt == null, ct);

        if (user is null)
        {
            // Hash anyway so a missing account is not distinguishable by response time.
            // Without this, timing alone enumerates valid usernames.
            _ = hasher.Verify(password, DummyHash);
            await audit.AppendAsync("auth.login", "denied", null, "client", ip,
                "user", null, $"{{\"username\":\"{Sanitize(username)}\",\"reason\":\"not_found\"}}", ct);
            return new AuthResult(false, null, ErrorCode.AccountNotFound);
        }

        if (user.Status == UserStatus.Disabled)
        {
            await audit.AppendAsync("auth.login", "denied", user.Id, "client", ip,
                "user", user.Id, "{\"reason\":\"disabled\"}", ct);
            return new AuthResult(false, user, ErrorCode.AccountDisabled);
        }

        if (user.LockoutUntil is { } until && until > now)
        {
            await audit.AppendAsync("auth.login", "denied", user.Id, "client", ip,
                "user", user.Id, "{\"reason\":\"backoff\"}", ct);
            return new AuthResult(false, user, ErrorCode.AccountLocked);
        }

        if (user.Source == UserSource.ActiveDirectory || user.PasswordHash is null)
        {
            await audit.AppendAsync("auth.login", "denied", user.Id, "client", ip,
                "user", user.Id, "{\"reason\":\"no_local_password\"}", ct);
            return new AuthResult(false, user, ErrorCode.InvalidCredentials);
        }

        var verification = hasher.Verify(password, user.PasswordHash);
        if (!verification.Succeeded)
        {
            user.FailedLoginCount++;
            user.LockoutUntil = now + BackoffFor(user.FailedLoginCount);
            await db.SaveChangesAsync(ct);
            await audit.AppendAsync("auth.login", "denied", user.Id, "client", ip,
                "user", user.Id, $"{{\"reason\":\"bad_password\",\"attempt\":{user.FailedLoginCount}}}", ct);
            return new AuthResult(false, user, ErrorCode.InvalidCredentials);
        }

        // Cost parameters travel with the hash, so raising policy silently upgrades users
        // as they log in rather than forcing a reset.
        if (verification.NeedsUpgrade)
        {
            user.PasswordHash = hasher.Hash(password);
            user.PasswordUpdatedAt = now;
        }

        user.FailedLoginCount = 0;
        user.LockoutUntil = null;
        user.LastLoginAt = now;
        await db.SaveChangesAsync(ct);

        await audit.AppendAsync("auth.login", "success", user.Id, "client", ip, "user", user.Id, null, ct);

        return user.MustChangePassword
            ? new AuthResult(false, user, ErrorCode.PasswordChangeRequired)
            : new AuthResult(true, user, null);
    }

    public async Task SetPasswordAsync(
        User user, string newPassword, SessionService sessions, CancellationToken ct = default)
    {
        ValidatePolicy(newPassword);

        user.PasswordHash = hasher.Hash(newPassword);
        user.PasswordUpdatedAt = _time.GetUtcNow();
        user.MustChangePassword = false;
        user.FailedLoginCount = 0;
        user.LockoutUntil = null;
        await db.SaveChangesAsync(ct);

        // A password change invalidates every existing session — otherwise a stolen token
        // outlives the credential the user just rotated away from.
        var revoked = await sessions.RevokeAllForUserAsync(user.Id, "password_change", ct);

        await audit.AppendAsync("auth.password_change", "success", user.Id, "client", null,
            "user", user.Id, $"{{\"sessions_revoked\":{revoked}}}", ct);
    }

    private static void ValidatePolicy(string password)
    {
        if (string.IsNullOrEmpty(password) || password.Length < 12)
            throw new MessengerException(ErrorCode.PasswordPolicyRejected,
                "Password must be at least 12 characters.");
    }

    private static TimeSpan BackoffFor(int failedCount)
    {
        var index = Math.Min(failedCount, BackoffSchedule.Length - 1);
        return BackoffSchedule[index];
    }

    private static string Sanitize(string value)
        => value.Replace("\\", "\\\\").Replace("\"", "\\\"");

    /// <summary>A real Argon2id hash of a random value, used only to equalise timing.</summary>
    private static readonly string DummyHash =
        new PasswordHasher().Hash(Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)));
}
