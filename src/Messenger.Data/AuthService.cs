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
                "user", null,
                $"{{\"username\":{JsonString(username)},\"reason\":\"not_found\"}}", ct);
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

        // A correct password is a successful login even when MustChangePassword is set --
        // the caller needs a session to reach POST /api/auth/change-password at all, so
        // refusing to issue one here would leave every account created via the admin API
        // permanently unable to sign in. LoginResponse.MustChangePassword is how the caller
        // is told to change it, and every other authenticated route refuses the session
        // until they do -- see AdminAuthFilter.
        return new AuthResult(true, user, null);
    }

    public async Task SetPasswordAsync(
        User user, string newPassword, SessionService sessions, CancellationToken ct = default)
    {
        ValidatePasswordPolicy(newPassword);

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

    /// <summary>
    /// The password policy, exposed so a caller can check it *before* committing side
    /// effects. Account creation provisions a row, a role, and a licence seat; discovering
    /// the password is too short only once <see cref="SetPasswordAsync"/> throws would
    /// leave all three behind with no password ever set.
    /// </summary>
    public static void ValidatePasswordPolicy(string password)
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

    /// <summary>
    /// Encodes a value as a JSON string literal, quotes included.
    ///
    /// Hand-rolled escaping of quote and backslash is not enough: JSON forbids raw control
    /// characters, so a username containing a newline or a NUL would produce a detail field
    /// that no parser accepts — and that field is hashed into the audit chain, so the
    /// malformed entry is permanent. The serialiser handles the whole escape set, and is
    /// what every other audit call site in this codebase already uses.
    /// </summary>
    private static string JsonString(string value)
        => System.Text.Json.JsonSerializer.Serialize(value);

    /// <summary>A real Argon2id hash of a random value, used only to equalise timing.</summary>
    private static readonly string DummyHash =
        new PasswordHasher().Hash(Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)));
}
