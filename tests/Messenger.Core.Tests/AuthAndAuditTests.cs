using Messenger.Contracts;
using Messenger.Core;
using Messenger.Crypto;
using Messenger.Data;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace Messenger.Core.Tests;

public class AuthenticationTests
{
    private const string GoodPassword = "correct horse battery staple";

    [Fact]
    public async Task Accepts_valid_credentials()
    {
        using var h = new TestHarness();
        h.AddUser("alice", GoodPassword);

        var result = await h.Auth.AuthenticateAsync("alice", GoodPassword);

        Assert.True(result.Succeeded);
        Assert.Null(result.ErrorCode);
    }

    [Fact]
    public async Task Rejects_a_wrong_password()
    {
        using var h = new TestHarness();
        h.AddUser("alice", GoodPassword);

        var result = await h.Auth.AuthenticateAsync("alice", "wrong");

        Assert.False(result.Succeeded);
        Assert.Equal(ErrorCode.InvalidCredentials, result.ErrorCode);
    }

    [Fact]
    public async Task Distinguishes_a_missing_account_for_the_log_only()
    {
        using var h = new TestHarness();

        var result = await h.Auth.AuthenticateAsync("nobody", GoodPassword);

        // The service returns a precise code so the audit log and admin console are useful.
        // Collapsing it to a generic message is the transport layer's job — see the login
        // endpoint. Both halves are needed to avoid an enumeration oracle.
        Assert.Equal(ErrorCode.AccountNotFound, result.ErrorCode);
    }

    [Fact]
    public async Task Refuses_a_disabled_account()
    {
        using var h = new TestHarness();
        h.AddUser("alice", GoodPassword, UserStatus.Disabled);

        var result = await h.Auth.AuthenticateAsync("alice", GoodPassword);

        Assert.False(result.Succeeded);
        Assert.Equal(ErrorCode.AccountDisabled, result.ErrorCode);
    }

    [Fact]
    public async Task Refuses_password_login_for_an_ad_sourced_user()
    {
        using var h = new TestHarness();
        var user = h.AddUser("alice", GoodPassword);
        user.Source = UserSource.ActiveDirectory;
        await h.Db.SaveChangesAsync();

        var result = await h.Auth.AuthenticateAsync("alice", GoodPassword);

        Assert.False(result.Succeeded);
        Assert.Equal(ErrorCode.InvalidCredentials, result.ErrorCode);
    }

    /// <summary>
    /// A correct password succeeds even when MustChangePassword is set -- the caller needs a
    /// session to reach the change-password route at all. It is on the caller (the login
    /// endpoint's response, then AdminAuthFilter on every other route) to act on the flag,
    /// not on AuthenticateAsync to refuse the login outright.
    /// </summary>
    [Fact]
    public async Task Succeeds_but_leaves_the_forced_password_change_flag_for_the_caller_to_act_on()
    {
        using var h = new TestHarness();
        var user = h.AddUser("alice", GoodPassword);
        user.MustChangePassword = true;
        await h.Db.SaveChangesAsync();

        var result = await h.Auth.AuthenticateAsync("alice", GoodPassword);

        Assert.True(result.Succeeded);
        Assert.True(result.User!.MustChangePassword);
    }

    [Fact]
    public async Task Applies_backoff_after_repeated_failures()
    {
        using var h = new TestHarness();
        h.AddUser("alice", GoodPassword);

        for (int i = 0; i < 4; i++)
            await h.Auth.AuthenticateAsync("alice", "wrong");

        // Backoff, not lockout — even the correct password waits, but the account is never
        // permanently locked, which would hand an attacker a trivial account-DoS.
        var blocked = await h.Auth.AuthenticateAsync("alice", GoodPassword);
        Assert.Equal(ErrorCode.AccountLocked, blocked.ErrorCode);

        h.Time.Advance(TimeSpan.FromMinutes(10));
        var afterWait = await h.Auth.AuthenticateAsync("alice", GoodPassword);
        Assert.True(afterWait.Succeeded);
    }

    [Fact]
    public async Task Successful_login_clears_the_failure_counter()
    {
        using var h = new TestHarness();
        h.AddUser("alice", GoodPassword);

        await h.Auth.AuthenticateAsync("alice", "wrong");
        await h.Auth.AuthenticateAsync("alice", GoodPassword);

        var user = await h.Db.Users.SingleAsync(u => u.Username == "alice");
        Assert.Equal(0, user.FailedLoginCount);
        Assert.Null(user.LockoutUntil);
    }

    [Fact]
    public async Task Password_change_revokes_every_existing_session()
    {
        using var h = new TestHarness();
        var user = h.AddUser("alice", GoodPassword);
        await h.Sessions.CreateAsync(user, "device-1", "laptop", null, AuthMethod.Password, SessionPolicy.Default);

        await h.Auth.SetPasswordAsync(user, "a brand new passphrase", h.Sessions);

        // A stolen token must not outlive the credential the user just rotated away from.
        Assert.Empty(await h.Db.Sessions.Where(s => s.RevokedAt == null).ToListAsync());
        Assert.Equal("password_change", await h.Db.Sessions.Select(s => s.RevokeReason).SingleAsync());
    }

    [Fact]
    public async Task Rejects_a_password_below_policy()
    {
        using var h = new TestHarness();
        var user = h.AddUser("alice", GoodPassword);

        var ex = await Assert.ThrowsAsync<MessengerException>(
            () => h.Auth.SetPasswordAsync(user, "short", h.Sessions));
        Assert.Equal(ErrorCode.PasswordPolicyRejected, ex.Code);
    }

    [Fact]
    public async Task Writes_an_audit_entry_for_success_and_failure()
    {
        using var h = new TestHarness();
        h.AddUser("alice", GoodPassword);

        await h.Auth.AuthenticateAsync("alice", "wrong");
        await h.Auth.AuthenticateAsync("alice", GoodPassword);

        var entries = await h.Db.AuditLog.OrderBy(e => e.Id).ToListAsync();
        Assert.Equal(2, entries.Count);
        Assert.Equal("denied", entries[0].Outcome);
        Assert.Equal("success", entries[1].Outcome);
    }

    [Fact]
    public async Task Audit_detail_never_contains_the_password()
    {
        using var h = new TestHarness();
        h.AddUser("alice", GoodPassword);

        await h.Auth.AuthenticateAsync("alice", GoodPassword);
        await h.Auth.AuthenticateAsync("alice", "hunter2");

        foreach (var entry in await h.Db.AuditLog.ToListAsync())
        {
            Assert.DoesNotContain(GoodPassword, entry.DetailJson ?? "");
            Assert.DoesNotContain("hunter2", entry.DetailJson ?? "");
        }
    }
}

public class SessionTests
{
    [Fact]
    public async Task Issues_a_token_that_validates()
    {
        using var h = new TestHarness();
        var user = h.AddUser("alice");

        var (token, _) = await h.Sessions.CreateAsync(user, "device-1", null, null, AuthMethod.Password, SessionPolicy.Default);
        var validation = await h.Sessions.ValidateAsync(token, "device-1", SessionPolicy.Default);

        Assert.True(validation.IsValid);
    }

    [Fact]
    public async Task Stores_only_the_token_hash()
    {
        using var h = new TestHarness();
        var user = h.AddUser("alice");

        var (token, _) = await h.Sessions.CreateAsync(user, "device-1", null, null, AuthMethod.Password, SessionPolicy.Default);

        // A database reader must not be able to replay a session.
        var stored = await h.Db.Sessions.SingleAsync();
        Assert.Equal(32, stored.TokenHash.Length);
        Assert.NotEqual(token, Convert.ToBase64String(stored.TokenHash));
    }

    [Fact]
    public async Task Rejects_an_unknown_token()
    {
        using var h = new TestHarness();
        var validation = await h.Sessions.ValidateAsync(
            Convert.ToBase64String(new byte[32]), "device-1", SessionPolicy.Default);

        Assert.False(validation.IsValid);
        Assert.Equal(ErrorCode.SessionTokenInvalid, validation.ErrorCode);
    }

    [Fact]
    public async Task Rejects_a_malformed_token_without_throwing()
    {
        using var h = new TestHarness();
        var validation = await h.Sessions.ValidateAsync("not base64 at all!!", "device-1", SessionPolicy.Default);

        Assert.False(validation.IsValid);
        Assert.Equal(ErrorCode.SessionTokenInvalid, validation.ErrorCode);
    }

    [Fact]
    public async Task Rejects_a_token_presented_from_another_device()
    {
        using var h = new TestHarness();
        var user = h.AddUser("alice");
        var (token, _) = await h.Sessions.CreateAsync(user, "device-1", null, null, AuthMethod.Password, SessionPolicy.Default);

        var validation = await h.Sessions.ValidateAsync(token, "device-2", SessionPolicy.Default);

        Assert.False(validation.IsValid);
        Assert.Equal(ErrorCode.SessionDeviceMismatch, validation.ErrorCode);
    }

    [Fact]
    public async Task Expires_an_idle_session()
    {
        using var h = new TestHarness();
        var user = h.AddUser("alice");
        var policy = SessionPolicy.Default with { IdleTimeoutSeconds = 900 };
        var (token, _) = await h.Sessions.CreateAsync(user, "device-1", null, null, AuthMethod.Password, policy);

        h.Time.Advance(TimeSpan.FromSeconds(901));
        var validation = await h.Sessions.ValidateAsync(token, "device-1", policy);

        Assert.False(validation.IsValid);
        Assert.Equal(ErrorCode.SessionExpiredIdle, validation.ErrorCode);
    }

    [Fact]
    public async Task Activity_slides_the_idle_window()
    {
        using var h = new TestHarness();
        var user = h.AddUser("alice");
        var policy = SessionPolicy.Default with { IdleTimeoutSeconds = 900 };
        var (token, _) = await h.Sessions.CreateAsync(user, "device-1", null, null, AuthMethod.Password, policy);

        for (int i = 0; i < 5; i++)
        {
            h.Time.Advance(TimeSpan.FromSeconds(800));
            Assert.True((await h.Sessions.ValidateAsync(token, "device-1", policy)).IsValid);
        }
    }

    [Fact]
    public async Task Enforces_the_absolute_lifetime_regardless_of_activity()
    {
        using var h = new TestHarness();
        var user = h.AddUser("alice");
        var policy = new SessionPolicy(IdleTimeoutSeconds: 900, AbsoluteLifetimeSeconds: 3600, MaxConcurrentSessionsPerUser: 3);
        var (token, _) = await h.Sessions.CreateAsync(user, "device-1", null, null, AuthMethod.Password, policy);

        // Stay active throughout, so only the absolute cap can end this session.
        for (int i = 0; i < 4; i++)
        {
            h.Time.Advance(TimeSpan.FromSeconds(800));
            await h.Sessions.ValidateAsync(token, "device-1", policy);
        }

        h.Time.Advance(TimeSpan.FromSeconds(800));
        var validation = await h.Sessions.ValidateAsync(token, "device-1", policy);

        Assert.False(validation.IsValid);
        Assert.Equal(ErrorCode.SessionExpiredAbsolute, validation.ErrorCode);
    }

    [Fact]
    public async Task Revocation_takes_effect_immediately()
    {
        using var h = new TestHarness();
        var user = h.AddUser("alice");
        var (token, session) = await h.Sessions.CreateAsync(user, "device-1", null, null, AuthMethod.Password, SessionPolicy.Default);

        await h.Sessions.RevokeAsync(session, "admin");
        var validation = await h.Sessions.ValidateAsync(token, "device-1", SessionPolicy.Default);

        Assert.False(validation.IsValid);
        Assert.Equal(ErrorCode.SessionRevokedByAdmin, validation.ErrorCode);
    }

    [Fact]
    public async Task Deactivating_a_user_invalidates_their_live_session()
    {
        using var h = new TestHarness();
        var user = h.AddUser("alice");
        var (token, _) = await h.Sessions.CreateAsync(user, "device-1", null, null, AuthMethod.Password, SessionPolicy.Default);

        user.Status = UserStatus.Disabled;
        await h.Db.SaveChangesAsync();

        var validation = await h.Sessions.ValidateAsync(token, "device-1", SessionPolicy.Default);
        Assert.False(validation.IsValid);
        Assert.Equal(ErrorCode.AccountDisabled, validation.ErrorCode);
    }

    [Fact]
    public async Task Concurrent_session_limit_displaces_the_least_recently_active()
    {
        using var h = new TestHarness();
        var user = h.AddUser("alice");
        var policy = SessionPolicy.Default with { MaxConcurrentSessionsPerUser = 2 };

        var (first, _) = await h.Sessions.CreateAsync(user, "device-1", null, null, AuthMethod.Password, policy);
        h.Time.Advance(TimeSpan.FromSeconds(1));
        var (second, _) = await h.Sessions.CreateAsync(user, "device-2", null, null, AuthMethod.Password, policy);
        h.Time.Advance(TimeSpan.FromSeconds(1));
        var (third, _) = await h.Sessions.CreateAsync(user, "device-3", null, null, AuthMethod.Password, policy);

        // Displacing rather than refusing: refusing would let a user lock themselves out by
        // leaving a session open on a machine they no longer have.
        Assert.False((await h.Sessions.ValidateAsync(first, "device-1", policy)).IsValid);
        Assert.True((await h.Sessions.ValidateAsync(second, "device-2", policy)).IsValid);
        Assert.True((await h.Sessions.ValidateAsync(third, "device-3", policy)).IsValid);
    }

    [Fact]
    public async Task Revoking_all_for_a_user_leaves_other_users_alone()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        await h.Sessions.CreateAsync(alice, "d1", null, null, AuthMethod.Password, SessionPolicy.Default);
        var (bobToken, _) = await h.Sessions.CreateAsync(bob, "d2", null, null, AuthMethod.Password, SessionPolicy.Default);

        Assert.Equal(1, await h.Sessions.RevokeAllForUserAsync(alice.Id, "admin"));
        Assert.True((await h.Sessions.ValidateAsync(bobToken, "d2", SessionPolicy.Default)).IsValid);
    }
}

public class AuditChainTests
{
    [Fact]
    public async Task Chains_entries_to_their_predecessor()
    {
        using var h = new TestHarness();

        var first = await h.Audit.AppendAsync("user.create", "success");
        var second = await h.Audit.AppendAsync("user.update", "success");

        Assert.Equal(AuditChain.GenesisHash, first.PrevHash);
        Assert.Equal(first.EntryHash, second.PrevHash);
    }

    [Fact]
    public async Task Verifies_an_untouched_chain()
    {
        using var h = new TestHarness();
        for (int i = 0; i < 10; i++)
            await h.Audit.AppendAsync($"action.{i}", "success");

        Assert.True((await h.Audit.VerifyAsync()).IsValid);
    }

    /// <summary>
    /// The point of the chain: an edit made directly in the database must be detectable, and
    /// must name where it happened.
    /// </summary>
    [Fact]
    public async Task Detects_a_tampered_entry_and_names_it()
    {
        using var h = new TestHarness();
        for (int i = 0; i < 5; i++)
            await h.Audit.AppendAsync($"action.{i}", "success");

        var victim = await h.Db.AuditLog.OrderBy(e => e.Id).Skip(2).FirstAsync();
        victim.Outcome = "denied";
        await h.Db.SaveChangesAsync();

        var result = await h.Audit.VerifyAsync();

        Assert.False(result.IsValid);
        Assert.Equal(victim.Id, result.FirstInvalidEntryId);
    }

    [Fact]
    public async Task Detects_a_deleted_entry()
    {
        using var h = new TestHarness();
        for (int i = 0; i < 5; i++)
            await h.Audit.AppendAsync($"action.{i}", "success");

        h.Db.AuditLog.Remove(await h.Db.AuditLog.OrderBy(e => e.Id).Skip(2).FirstAsync());
        await h.Db.SaveChangesAsync();

        // The successor's prev_hash no longer matches its actual predecessor.
        Assert.False((await h.Audit.VerifyAsync()).IsValid);
    }

    /// <summary>
    /// The failed-login entry embeds the attempted username in its detail field. Escaping
    /// only quote and backslash left raw control characters in place, which JSON forbids —
    /// so a username containing a newline produced a detail field no parser accepts, and
    /// because the field is hashed into the chain the malformed entry is permanent.
    /// </summary>
    [Theory]
    [InlineData("bob\nadmin")]
    [InlineData("bob\"; DROP--")]
    [InlineData("bob\\admin")]
    [InlineData("bob admin")]
    [InlineData("bob\tadmin")]
    public async Task An_unknown_username_is_audited_as_valid_json(string username)
    {
        using var h = new TestHarness();

        await h.Auth.AuthenticateAsync(username, "irrelevant");

        var entry = await h.Db.AuditLog.SingleAsync(e => e.Action == "auth.login");
        using var parsed = System.Text.Json.JsonDocument.Parse(entry.DetailJson!);
        Assert.Equal(username, parsed.RootElement.GetProperty("username").GetString());
        Assert.Equal("not_found", parsed.RootElement.GetProperty("reason").GetString());
    }

    [Fact]
    public async Task Verification_throws_with_the_catalogue_code()
    {
        using var h = new TestHarness();
        await h.Audit.AppendAsync("action", "success");

        var entry = await h.Db.AuditLog.SingleAsync();
        entry.Action = "tampered";
        await h.Db.SaveChangesAsync();

        var ex = Assert.Throws<MessengerException>(() => (h.Audit.VerifyAsync().Result).EnsureValid());
        Assert.Equal(ErrorCode.AuditChainVerificationFailed, ex.Code);
    }

    [Fact]
    public void Checkpoint_signature_roundtrips()
    {
        var (privateKey, publicKey) = AuditChain.GenerateSigningKey();
        var head = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);

        var signature = AuditChain.SignCheckpoint(head, 1000, privateKey);

        Assert.True(AuditChain.VerifyCheckpoint(head, 1000, signature, publicKey));
    }

    /// <summary>
    /// Binding the entry id into the signed payload is what stops a checkpoint signature
    /// being replayed against a truncated chain that happens to end on the same hash.
    /// </summary>
    [Fact]
    public void Checkpoint_signature_is_bound_to_its_entry_id()
    {
        var (privateKey, publicKey) = AuditChain.GenerateSigningKey();
        var head = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        var signature = AuditChain.SignCheckpoint(head, 1000, privateKey);

        Assert.False(AuditChain.VerifyCheckpoint(head, 999, signature, publicKey));
    }

    [Fact]
    public void Checkpoint_signature_fails_against_a_different_head()
    {
        var (privateKey, publicKey) = AuditChain.GenerateSigningKey();
        var signature = AuditChain.SignCheckpoint(
            System.Security.Cryptography.RandomNumberGenerator.GetBytes(32), 1, privateKey);

        Assert.False(AuditChain.VerifyCheckpoint(
            System.Security.Cryptography.RandomNumberGenerator.GetBytes(32), 1, signature, publicKey));
    }

    [Fact]
    public void Checkpoint_signature_fails_under_a_foreign_key()
    {
        var (privateKey, _) = AuditChain.GenerateSigningKey();
        var (_, otherPublic) = AuditChain.GenerateSigningKey();
        var head = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);

        var signature = AuditChain.SignCheckpoint(head, 1, privateKey);

        Assert.False(AuditChain.VerifyCheckpoint(head, 1, signature, otherPublic));
    }

    [Fact]
    public void Canonical_hash_is_stable_across_calls()
    {
        var entry = new AuditEntryData(
            1, new DateTimeOffset(2026, 8, 4, 12, 0, 0, TimeSpan.Zero), Guid.Empty, "admin",
            "10.0.0.1", "user.create", "user", Guid.Empty, "success", "{\"k\":\"v\"}");

        Assert.Equal(
            AuditChain.ComputeEntryHash(entry, AuditChain.GenesisHash),
            AuditChain.ComputeEntryHash(entry, AuditChain.GenesisHash));
    }
}

public class PresenceTests
{
    [Fact]
    public async Task Records_and_reads_back_a_status()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");

        await h.Presence.SetStatusAsync(alice.Id, PresenceStatus.Busy, "In a meeting", false);
        var presence = await h.Presence.GetAsync(alice.Id);

        Assert.Equal(PresenceStatus.Busy, presence.Status);
        Assert.Equal("In a meeting", presence.StatusMessage);
    }

    [Fact]
    public async Task Unknown_user_reads_as_offline()
        => Assert.Equal(PresenceStatus.Offline,
            (await new TestHarness().Presence.GetAsync(Guid.NewGuid())).Status);

    [Fact]
    public async Task Auto_away_is_distinguishable_from_a_chosen_status()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");

        await h.Presence.SetStatusAsync(alice.Id, PresenceStatus.Away, null, isAutoAway: true);

        Assert.True((await h.Presence.GetAsync(alice.Id)).IsAutoAway);
    }

    /// <summary>
    /// Presence is scoped to shared conversations rather than broadcast directory-wide —
    /// it is sensitive metadata, and unbounded fan-out is also a scaling problem.
    /// </summary>
    [Fact]
    public async Task Visibility_is_limited_to_conversation_peers()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var stranger = h.AddUser("stranger");
        await h.Messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);

        var visibleTo = await h.Presence.GetVisibleToAsync(alice.Id);

        Assert.Contains(bob.Id, visibleTo);
        Assert.DoesNotContain(stranger.Id, visibleTo);
        Assert.DoesNotContain(alice.Id, visibleTo);
    }
}
