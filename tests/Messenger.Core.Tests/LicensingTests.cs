using Messenger.Contracts;
using Messenger.Core;
using Messenger.Data;
using Messenger.Licensing;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace Messenger.Core.Tests;

public class LicenseValidationTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 4, 12, 0, 0, TimeSpan.Zero);

    private static LicensePayload Payload(
        DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null,
        int seats = 500, int graceDays = 14)
        => new()
        {
            LicenseId = "LIC-0001",
            Customer = "Contoso Ltd",
            IssuedAt = Now.AddDays(-1),
            NotBefore = notBefore ?? Now.AddDays(-1),
            NotAfter = notAfter ?? Now.AddDays(365),
            MaxSeats = seats,
            MaxFileBytes = 100 * 1024 * 1024,
            MaxSessionsPerUser = 3,
            MaxSessionsTotal = 750,
            IdleTimeoutSeconds = 900,
            GracePeriodDays = graceDays,
            Features = [LicenseFeature.AdSync, LicenseFeature.FileTransfer],
        };

    private static (LicenseValidator Validator, byte[] PrivateKey) Setup(DateTimeOffset? now = null)
    {
        var (priv, pub) = LicenseDocument.GenerateVendorKeyPair();
        return (new LicenseValidator(pub, new FakeTimeProvider(now ?? Now)), priv);
    }

    [Fact]
    public void Accepts_a_correctly_signed_current_licence()
    {
        var (validator, priv) = Setup();
        var status = validator.Validate(LicenseDocument.Issue(Payload(), priv));

        Assert.Equal(LicenseState.Valid, status.State);
        Assert.True(status.AllowsNewSessions);
        Assert.Equal("Contoso Ltd", status.Payload!.Customer);
    }

    [Fact]
    public void Reports_a_missing_licence()
    {
        var (validator, _) = Setup();
        var status = validator.Validate(null);

        Assert.Equal(LicenseState.Missing, status.State);
        Assert.Equal(ErrorCode.NoLicenseInstalled, status.ErrorCode);
    }

    /// <summary>Any edit to the file, including reformatting, must invalidate it.</summary>
    [Fact]
    public void Rejects_a_tampered_payload()
    {
        var (validator, priv) = Setup();
        var document = LicenseDocument.Issue(Payload(seats: 500), priv);

        var tampered = System.Text.Encoding.UTF8.GetString(document.SignedBytes)
            .Replace("\"max_seats\":500", "\"max_seats\":99999");
        var forged = new LicenseDocument(System.Text.Encoding.UTF8.GetBytes(tampered), document.Signature);

        var status = validator.Validate(forged);

        Assert.Equal(LicenseState.Invalid, status.State);
        Assert.Equal(ErrorCode.LicenseSignatureInvalid, status.ErrorCode);
    }

    [Fact]
    public void Rejects_a_licence_signed_by_a_different_vendor_key()
    {
        var (validator, _) = Setup();
        var (attackerKey, _) = LicenseDocument.GenerateVendorKeyPair();

        var status = validator.Validate(LicenseDocument.Issue(Payload(), attackerKey));

        Assert.Equal(LicenseState.Invalid, status.State);
        Assert.Equal(ErrorCode.LicenseSignatureInvalid, status.ErrorCode);
    }

    [Fact]
    public void Rejects_a_licence_that_is_not_yet_valid()
    {
        var (validator, priv) = Setup();
        var status = validator.Validate(LicenseDocument.Issue(Payload(notBefore: Now.AddDays(5)), priv));

        Assert.Equal(LicenseState.NotYetValid, status.State);
        Assert.Equal(ErrorCode.LicenseNotYetValid, status.ErrorCode);
        Assert.Contains("clock", status.Detail!, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Expiry degrades rather than stopping. Silently halting a company's internal
    /// communications at midnight on the expiry date is worse than a visibly degraded mode.
    /// </summary>
    [Fact]
    public void An_expired_licence_enters_read_only_grace()
    {
        var (validator, priv) = Setup();
        var status = validator.Validate(LicenseDocument.Issue(Payload(notAfter: Now.AddDays(-1)), priv));

        Assert.Equal(LicenseState.Grace, status.State);
        Assert.False(status.AllowsNewSessions);
        Assert.True(status.AllowsReading);
        Assert.Equal(ErrorCode.LicenseExpired, status.ErrorCode);
    }

    [Fact]
    public void Grace_ends_after_the_configured_window()
    {
        var (validator, priv) = Setup();
        var status = validator.Validate(
            LicenseDocument.Issue(Payload(notAfter: Now.AddDays(-15), graceDays: 14), priv));

        Assert.Equal(LicenseState.Expired, status.State);
        Assert.False(status.AllowsReading);
        Assert.Equal(ErrorCode.GracePeriodExpired, status.ErrorCode);
    }

    [Fact]
    public void Grace_boundary_is_inclusive_of_its_final_moment()
    {
        var (validator, priv) = Setup();
        var status = validator.Validate(
            LicenseDocument.Issue(Payload(notAfter: Now.AddDays(-14), graceDays: 14), priv));

        Assert.Equal(LicenseState.Grace, status.State);
    }

    [Theory]
    [InlineData("not-a-licence")]
    [InlineData("only.one.too.many.parts")]
    [InlineData("!!!notbase64!!!.c2ln")]
    public void Rejects_a_malformed_file(string content)
    {
        var ex = Assert.Throws<MessengerException>(() => LicenseDocument.Parse(content));
        Assert.Equal(ErrorCode.LicenseMalformed, ex.Code);
    }

    /// <summary>
    /// The raw signed bytes are retained rather than reserialised: verifying against a
    /// reserialised payload is a well-known source of intermittent failures.
    /// </summary>
    [Fact]
    public void Survives_a_file_format_roundtrip()
    {
        var (validator, priv) = Setup();
        var original = LicenseDocument.Issue(Payload(), priv);

        var restored = LicenseDocument.Parse(original.ToFileFormat());

        Assert.Equal(LicenseState.Valid, validator.Validate(restored).State);
        Assert.Equal(original.SignedBytes, restored.SignedBytes);
    }

    [Fact]
    public void Tolerates_surrounding_whitespace_in_the_file()
    {
        var (validator, priv) = Setup();
        var content = "\n  " + LicenseDocument.Issue(Payload(), priv).ToFileFormat() + "  \n";

        Assert.Equal(LicenseState.Valid, validator.Validate(LicenseDocument.Parse(content)).State);
    }
}

public class LicenseEnforcementTests
{
    private static LicensePayload Payload(
        DateTimeOffset issuedAt, int seats = 500, int perUser = 3, int total = 750,
        int idleSeconds = 900, DateTimeOffset? notAfter = null, List<string>? features = null)
        => new()
        {
            LicenseId = "LIC-0001",
            Customer = "Contoso Ltd",
            IssuedAt = issuedAt,
            NotBefore = issuedAt.AddDays(-1),
            NotAfter = notAfter ?? issuedAt.AddDays(365),
            MaxSeats = seats,
            MaxFileBytes = 100 * 1024 * 1024,
            MaxSessionsPerUser = perUser,
            MaxSessionsTotal = total,
            IdleTimeoutSeconds = idleSeconds,
            GracePeriodDays = 14,
            Features = features ?? [LicenseFeature.AdSync, LicenseFeature.FileTransfer],
        };

    private static async Task<TestHarness> WithLicenseAsync(
        Func<DateTimeOffset, LicensePayload>? build = null)
    {
        var h = new TestHarness();
        var payload = (build ?? (now => Payload(now)))(h.Time.GetUtcNow());
        await h.License.InstallAsync(LicenseDocument.Issue(payload, h.VendorPrivateKey).ToFileFormat(), Guid.Empty);
        return h;
    }

    [Fact]
    public async Task Installing_a_licence_records_and_audits_it()
    {
        using var h = await WithLicenseAsync();

        Assert.Equal(1, await h.Db.Licenses.CountAsync(l => l.IsActive));
        Assert.Contains("license.install", await h.Db.AuditLog.Select(e => e.Action).ToListAsync());
    }

    /// <summary>
    /// An invalid licence must not be stored: doing so would leave the installed licence and
    /// the enforced licence disagreeing.
    /// </summary>
    [Fact]
    public async Task An_invalid_licence_is_never_stored()
    {
        using var h = new TestHarness();
        var (attackerKey, _) = LicenseDocument.GenerateVendorKeyPair();
        var forged = LicenseDocument.Issue(Payload(h.Time.GetUtcNow()), attackerKey).ToFileFormat();

        var ex = await Assert.ThrowsAsync<MessengerException>(() => h.License.InstallAsync(forged, Guid.Empty));

        Assert.Equal(ErrorCode.LicenseSignatureInvalid, ex.Code);
        Assert.Equal(0, await h.Db.Licenses.CountAsync());
    }

    /// <summary>
    /// The install audit entry embeds the licence id in its detail field. Hand-built
    /// interpolation left a hostile licence id — attacker-authorable by anyone who can issue a
    /// validly signed licence, not just the vendor's own tooling — able to produce a detail
    /// field no parser accepts, and because it is hashed into the chain the entry is permanent.
    /// </summary>
    [Fact]
    public async Task A_hostile_licence_id_is_audited_as_valid_json()
    {
        using var h = new TestHarness();
        var payload = Payload(h.Time.GetUtcNow());
        payload.LicenseId = "LIC-\"; DROP--\n0001";

        await h.License.InstallAsync(LicenseDocument.Issue(payload, h.VendorPrivateKey).ToFileFormat(), Guid.Empty);

        var entry = await h.Db.AuditLog.SingleAsync(e => e.Action == "license.install");
        using var parsed = System.Text.Json.JsonDocument.Parse(entry.DetailJson!);
        Assert.Equal(payload.LicenseId, parsed.RootElement.GetProperty("license_id").GetString());
    }

    [Fact]
    public async Task Installing_a_new_licence_supersedes_the_previous_one()
    {
        using var h = await WithLicenseAsync();
        var replacement = Payload(h.Time.GetUtcNow(), seats: 1000);
        replacement.LicenseId = "LIC-0002";

        await h.License.InstallAsync(LicenseDocument.Issue(replacement, h.VendorPrivateKey).ToFileFormat(), Guid.Empty);

        Assert.Equal(1, await h.Db.Licenses.CountAsync(l => l.IsActive));
        Assert.Equal(2, await h.Db.Licenses.CountAsync());
        Assert.Equal(1000, (await h.License.GetStatusAsync()).Payload!.MaxSeats);
    }

    [Fact]
    public async Task Login_is_refused_when_no_licence_is_installed()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");

        var ex = await Assert.ThrowsAsync<MessengerException>(() => h.License.AuthoriseLoginAsync(alice.Id));
        Assert.Equal(ErrorCode.NoLicenseInstalled, ex.Code);
    }

    [Fact]
    public async Task Login_returns_the_session_policy_the_licence_dictates()
    {
        using var h = await WithLicenseAsync(now => Payload(now, perUser: 2, idleSeconds: 600));
        var alice = h.AddUser("alice");

        var policy = await h.License.AuthoriseLoginAsync(alice.Id);

        Assert.Equal(600, policy.IdleTimeoutSeconds);
        Assert.Equal(2, policy.MaxConcurrentSessionsPerUser);
    }

    [Fact]
    public async Task Login_is_refused_during_grace()
    {
        using var h = await WithLicenseAsync(now => Payload(now, notAfter: now.AddDays(-1)));
        var alice = h.AddUser("alice");

        var ex = await Assert.ThrowsAsync<MessengerException>(() => h.License.AuthoriseLoginAsync(alice.Id));
        Assert.Equal(ErrorCode.LicenseExpired, ex.Code);
    }

    [Fact]
    public async Task Login_is_refused_once_grace_has_ended()
    {
        using var h = await WithLicenseAsync(now => Payload(now, notAfter: now.AddDays(-30)));
        var alice = h.AddUser("alice");

        var ex = await Assert.ThrowsAsync<MessengerException>(() => h.License.AuthoriseLoginAsync(alice.Id));
        Assert.Equal(ErrorCode.GracePeriodExpired, ex.Code);
    }

    [Fact]
    public async Task Total_concurrent_session_limit_is_enforced()
    {
        using var h = await WithLicenseAsync(now => Payload(now, total: 2));
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var carol = h.AddUser("carol");

        await h.Sessions.CreateAsync(alice, "d1", null, null, AuthMethod.Password, SessionPolicy.Default);
        await h.Sessions.CreateAsync(bob, "d2", null, null, AuthMethod.Password, SessionPolicy.Default);

        var ex = await Assert.ThrowsAsync<MessengerException>(() => h.License.AuthoriseLoginAsync(carol.Id));
        Assert.Equal(ErrorCode.TotalSessionLimit, ex.Code);
    }

    [Fact]
    public async Task A_revoked_session_frees_a_slot()
    {
        using var h = await WithLicenseAsync(now => Payload(now, total: 1));
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");

        var (_, session) = await h.Sessions.CreateAsync(alice, "d1", null, null, AuthMethod.Password, SessionPolicy.Default);
        await Assert.ThrowsAsync<MessengerException>(() => h.License.AuthoriseLoginAsync(bob.Id));

        await h.Sessions.RevokeAsync(session, "logout");

        await h.License.AuthoriseLoginAsync(bob.Id);
    }

    /// <summary>
    /// Seats are checked at activation, not at login. Failing at login would let an
    /// administrator over-provision and only discover it when users were turned away.
    /// </summary>
    [Fact]
    public async Task Seat_limit_is_enforced_when_activating_a_user()
    {
        using var h = await WithLicenseAsync(now => Payload(now, seats: 2));
        h.AddUser("alice");
        h.AddUser("bob");

        var ex = await Assert.ThrowsAsync<MessengerException>(() => h.License.EnsureSeatAvailableAsync());
        Assert.Equal(ErrorCode.SeatLimitReached, ex.Code);
    }

    [Fact]
    public async Task Deactivated_users_do_not_consume_seats()
    {
        using var h = await WithLicenseAsync(now => Payload(now, seats: 2));
        h.AddUser("alice");
        h.AddUser("bob", status: UserStatus.Disabled);

        await h.License.EnsureSeatAvailableAsync();
    }

    [Fact]
    public async Task Reactivating_an_existing_user_does_not_count_them_twice()
    {
        using var h = await WithLicenseAsync(now => Payload(now, seats: 2));
        var alice = h.AddUser("alice");
        h.AddUser("bob");

        // Alice is already active; re-checking her own activation must not see her as a
        // new seat on top of herself.
        await h.License.EnsureSeatAvailableAsync(activatingUserId: alice.Id);
    }

    [Fact]
    public async Task An_unlicensed_feature_is_refused()
    {
        using var h = await WithLicenseAsync(now => Payload(now, features: [LicenseFeature.FileTransfer]));

        await h.License.EnsureFeatureAsync(LicenseFeature.FileTransfer);

        var ex = await Assert.ThrowsAsync<MessengerException>(
            () => h.License.EnsureFeatureAsync(LicenseFeature.SupportChat));
        Assert.Equal(ErrorCode.FeatureNotLicensed, ex.Code);
    }

    [Fact]
    public async Task Usage_reports_seats_and_sessions_against_their_limits()
    {
        using var h = await WithLicenseAsync(now => Payload(now, seats: 10, total: 20));
        var alice = h.AddUser("alice");
        h.AddUser("bob");
        await h.Sessions.CreateAsync(alice, "d1", null, null, AuthMethod.Password, SessionPolicy.Default);

        var usage = await h.License.GetUsageAsync();

        Assert.Equal(2, usage.SeatsUsed);
        Assert.Equal(10, usage.SeatsAllowed);
        Assert.Equal(1, usage.SessionsActive);
        Assert.Equal(20, usage.SessionsAllowed);
        Assert.False(usage.IsNearSeatLimit);
    }

    [Fact]
    public async Task Usage_flags_an_approaching_seat_limit()
    {
        using var h = await WithLicenseAsync(now => Payload(now, seats: 2));
        h.AddUser("alice");
        h.AddUser("bob");

        Assert.True((await h.License.GetUsageAsync()).IsNearSeatLimit);
    }

    [Fact]
    public async Task A_licence_that_expires_while_running_moves_into_grace()
    {
        using var h = await WithLicenseAsync(now => Payload(now, notAfter: now.AddDays(30)));
        var alice = h.AddUser("alice");

        await h.License.AuthoriseLoginAsync(alice.Id);

        h.Time.Advance(TimeSpan.FromDays(31));

        var status = await h.License.GetStatusAsync();
        Assert.Equal(LicenseState.Grace, status.State);
        Assert.True(status.AllowsReading);
        await Assert.ThrowsAsync<MessengerException>(() => h.License.AuthoriseLoginAsync(alice.Id));
    }
}
