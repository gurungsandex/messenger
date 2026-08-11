using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Messenger.Contracts;
using Messenger.Core;
using Messenger.Crypto;
using Messenger.Data;
using Microsoft.Extensions.Configuration;
using Messenger.Licensing;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Xunit;

namespace Messenger.Server.Tests;

/// <summary>
/// End-to-end tests through the real HTTP pipeline against a real PostgreSQL database.
///
/// These cover what the service-level suite cannot: the login endpoint's collapsing of
/// specific auth codes into a generic message, the admin filter, and licence enforcement at
/// the boundary where a client actually meets it.
/// </summary>
public sealed class AdminApiTests : IAsyncLifetime
{
    private static string? BaseConnection => Environment.GetEnvironmentVariable("MESSENGER_TEST_CONNECTION");

    private WebApplicationFactory<Program> _factory = null!;
    private HttpClient _client = null!;
    private string _database = null!;
    private byte[] _vendorPrivateKey = null!;
    private string _keyStoreDirectory = null!;

    public async Task InitializeAsync()
    {
        if (BaseConnection is null) return;

        _database = "messenger_api_" + Guid.NewGuid().ToString("N")[..12];
        _keyStoreDirectory = Path.Combine(Path.GetTempPath(), "messenger-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_keyStoreDirectory);

        var admin = new NpgsqlConnectionStringBuilder(BaseConnection) { Database = "postgres" };
        await using (var setup = new NpgsqlConnection(admin.ConnectionString))
        {
            await setup.OpenAsync();
            await using var cmd = setup.CreateCommand();
            cmd.CommandText = $"CREATE DATABASE \"{_database}\"";
            await cmd.ExecuteNonQueryAsync();
        }

        var scoped = new NpgsqlConnectionStringBuilder(BaseConnection) { Database = _database }.ConnectionString;

        byte[] vendorPublic;
        (_vendorPrivateKey, vendorPublic) = LicenseDocument.GenerateVendorKeyPair();

        // The schema must exist before the host starts: startup seeds the built-in roles,
        // which fails against an empty database.
        var options = new DbContextOptionsBuilder<MessengerDbContext>().UseNpgsql(scoped).Options;
        await using (var schema = new MessengerDbContext(options))
            await schema.Database.EnsureCreatedAsync();

        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseSetting("ConnectionStrings:Messenger", scoped);
            b.UseSetting("Licensing:VendorPublicKey", Convert.ToBase64String(vendorPublic));
            b.UseSetting("KeyStore:Passphrase", "test-keystore-passphrase");
            b.UseSetting("KeyStore:EscrowPath", Path.Combine(_keyStoreDirectory, "root.escrow"));

            // Scoped to this test's directory like the KEK escrow. Left unset it defaults
            // under the test binary's own directory, where it outlives the run and is shared
            // by every other test class — so a checkpoint written by one run would be
            // verified against a key ring left behind by another.
            b.UseSetting("AuditSigningKey:EscrowPath", Path.Combine(_keyStoreDirectory, "audit-signing.escrow"));
        });

        _client = _factory.CreateClient();
    }

    public async Task DisposeAsync()
    {
        if (BaseConnection is null) return;

        _client.Dispose();
        await _factory.DisposeAsync();
        NpgsqlConnection.ClearAllPools();

        if (Directory.Exists(_keyStoreDirectory)) Directory.Delete(_keyStoreDirectory, recursive: true);

        var admin = new NpgsqlConnectionStringBuilder(BaseConnection) { Database = "postgres" };
        await using var cleanup = new NpgsqlConnection(admin.ConnectionString);
        await cleanup.OpenAsync();
        await using var cmd = cleanup.CreateCommand();
        cmd.CommandText = $"DROP DATABASE IF EXISTS \"{_database}\" WITH (FORCE)";
        await cmd.ExecuteNonQueryAsync();
    }

    private async Task<User> SeedUserAsync(string username, string password, string? role = null)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<MessengerDbContext>();
        var hasher = scope.ServiceProvider.GetRequiredService<PasswordHasher>();

        var user = new User
        {
            Username = username,
            DisplayName = username,
            PasswordHash = hasher.Hash(password),
        };
        db.Users.Add(user);
        await db.SaveChangesAsync();

        var authorization = scope.ServiceProvider.GetRequiredService<AuthorizationService>();
        await authorization.EnsureDefaultRoleAsync(user.Id);

        if (role is not null)
        {
            var roleRow = await db.Roles.SingleAsync(r => r.Name == role);
            await authorization.AssignRoleAsync(user.Id, roleRow.Id, Guid.Empty);
        }

        return user;
    }

    private async Task InstallLicenseAsync(int seats = 100, int totalSessions = 100, int? expiresInDays = 365)
    {
        using var scope = _factory.Services.CreateScope();
        var license = scope.ServiceProvider.GetRequiredService<LicenseEnforcementService>();
        var now = DateTimeOffset.UtcNow;

        var payload = new LicensePayload
        {
            LicenseId = "LIC-TEST",
            Customer = "Test Customer",
            IssuedAt = now.AddDays(-1),
            NotBefore = now.AddDays(-1),
            NotAfter = now.AddDays(expiresInDays!.Value),
            MaxSeats = seats,
            MaxFileBytes = 1024 * 1024,
            MaxSessionsPerUser = 3,
            MaxSessionsTotal = totalSessions,
            IdleTimeoutSeconds = 900,
            GracePeriodDays = 14,
            Features = [LicenseFeature.AdSync, LicenseFeature.FileTransfer],
        };

        await license.InstallAsync(LicenseDocument.Issue(payload, _vendorPrivateKey).ToFileFormat(), Guid.Empty);
    }

    private async Task<string> LoginAsync(string username, string password, string device = "device-1")
    {
        var response = await _client.PostAsJsonAsync("/api/auth/login",
            new LoginRequest(username, password, device, "Test Device"));
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<LoginResponse>())!.SessionToken;
    }

    private HttpRequestMessage Authed(HttpMethod method, string url, string token, string device = "device-1")
    {
        var request = new HttpRequestMessage(method, url);
        request.Headers.Add("X-Session-Token", token);
        request.Headers.Add("X-Device-Fingerprint", device);
        return request;
    }

    [SkippableFact]
    public async Task Login_succeeds_with_valid_credentials()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        await SeedUserAsync("alice", "correct horse battery staple");

        var response = await _client.PostAsJsonAsync("/api/auth/login",
            new LoginRequest("alice", "correct horse battery staple", "device-1", "Laptop"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(body);
        Assert.Equal(900, body!.IdleTimeoutSeconds);
    }

    /// <summary>
    /// The endpoint must not distinguish a missing account from a wrong password. Doing so
    /// hands an unauthenticated caller a free account-enumeration oracle.
    /// </summary>
    [SkippableFact]
    public async Task Login_gives_an_identical_response_for_unknown_user_and_wrong_password()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        await SeedUserAsync("alice", "correct horse battery staple");

        var wrongPassword = await _client.PostAsJsonAsync("/api/auth/login",
            new LoginRequest("alice", "wrong password entirely", "device-1", null));
        var unknownUser = await _client.PostAsJsonAsync("/api/auth/login",
            new LoginRequest("nobody-at-all", "wrong password entirely", "device-1", null));

        Assert.Equal(HttpStatusCode.Unauthorized, wrongPassword.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, unknownUser.StatusCode);

        var a = await wrongPassword.Content.ReadFromJsonAsync<ErrorDto>();
        var b = await unknownUser.Content.ReadFromJsonAsync<ErrorDto>();

        Assert.Equal(ErrorCode.InvalidCredentials, a!.Code);
        Assert.Equal(a.Code, b!.Code);
        Assert.Equal(a.Message, b.Message);
    }

    /// <summary>The precise reason must still reach the audit log, or the console is useless.</summary>
    [SkippableFact]
    public async Task The_specific_failure_reason_is_still_recorded_in_the_audit_log()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();

        await _client.PostAsJsonAsync("/api/auth/login",
            new LoginRequest("ghost", "whatever", "device-1", null));

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<MessengerDbContext>();
        var entry = await db.AuditLog.FirstAsync(e => e.Action == "auth.login");

        Assert.Equal("denied", entry.Outcome);
        Assert.Contains("not_found", entry.DetailJson!);
    }

    [SkippableFact]
    public async Task Login_is_refused_when_no_licence_is_installed()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await SeedUserAsync("alice", "correct horse battery staple");

        var response = await _client.PostAsJsonAsync("/api/auth/login",
            new LoginRequest("alice", "correct horse battery staple", "device-1", null));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var error = await response.Content.ReadFromJsonAsync<ErrorDto>();
        Assert.Equal(ErrorCode.NoLicenseInstalled, error!.Code);
    }

    /// <summary>
    /// Licence limits apply only after the credential check. Checking first would let an
    /// unauthenticated caller probe the deployment's seat and session usage.
    /// </summary>
    [SkippableFact]
    public async Task Bad_credentials_are_rejected_before_licence_state_is_revealed()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await SeedUserAsync("alice", "correct horse battery staple");

        var response = await _client.PostAsJsonAsync("/api/auth/login",
            new LoginRequest("alice", "wrong", "device-1", null));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var error = await response.Content.ReadFromJsonAsync<ErrorDto>();
        Assert.Equal(ErrorCode.InvalidCredentials, error!.Code);
    }

    /// <summary>
    /// Liveness answers "is the process up", readiness "can it serve a request". They are
    /// separate because an orchestrator restarts what fails liveness, and restarting does
    /// not fix an unreachable database — it only adds an outage on top of one.
    /// </summary>
    [SkippableFact]
    public async Task Both_health_probes_answer_without_authentication()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");

        Assert.Equal(HttpStatusCode.OK, (await _client.GetAsync("/health/live")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _client.GetAsync("/health/ready")).StatusCode);
    }

    /// <summary>
    /// Readiness has to actually reach the database. A probe that reports Healthy from a
    /// server whose every request 500s is worse than no probe: it keeps the load balancer
    /// confidently sending traffic to an instance that cannot serve any of it.
    ///
    /// The database is dropped after the host is up, because that is the case the probe
    /// exists for — the server already refuses to *start* without one. Liveness has to keep
    /// passing throughout: restarting the process does not bring the database back.
    /// </summary>
    [SkippableFact]
    public async Task Readiness_fails_when_the_database_goes_away()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");

        Assert.Equal(HttpStatusCode.OK, (await _client.GetAsync("/health/ready")).StatusCode);

        NpgsqlConnection.ClearAllPools();
        var admin = new NpgsqlConnectionStringBuilder(BaseConnection!) { Database = "postgres" };
        await using (var drop = new NpgsqlConnection(admin.ConnectionString))
        {
            await drop.OpenAsync();
            await using var cmd = drop.CreateCommand();
            cmd.CommandText = $"DROP DATABASE \"{_database}\" WITH (FORCE)";
            await cmd.ExecuteNonQueryAsync();
        }

        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await _client.GetAsync("/health/ready")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _client.GetAsync("/health/live")).StatusCode);
    }

    /// <summary>
    /// X-Forwarded-For must be ignored unless an operator has said a proxy is in front.
    /// Honouring it by default would let any caller choose the address that lands in the
    /// audit log and the address the per-IP login limiter counts against.
    /// </summary>
    [SkippableFact]
    public async Task A_spoofed_forwarded_address_does_not_reach_the_audit_log()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        await SeedUserAsync("alice", "correct horse battery staple", BuiltInRoles.ServerAdmin);

        var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/login")
        {
            Content = JsonContent.Create(
                new LoginRequest("alice", "correct horse battery staple", "device-1", null)),
        };
        request.Headers.Add("X-Forwarded-For", "203.0.113.99");
        Assert.Equal(HttpStatusCode.OK, (await _client.SendAsync(request)).StatusCode);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<MessengerDbContext>();
        var entry = await db.AuditLog
            .Where(e => e.Action == "auth.login" && e.Outcome == "success")
            .OrderByDescending(e => e.Id).FirstAsync();

        Assert.NotEqual("203.0.113.99", entry.ActorIp);
    }

    [SkippableFact]
    public async Task Admin_endpoints_reject_an_unauthenticated_caller()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");

        var response = await _client.GetAsync("/api/admin/users");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [SkippableFact]
    public async Task Admin_endpoints_reject_a_forged_token()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");

        var response = await _client.SendAsync(Authed(HttpMethod.Get, "/api/admin/users",
            Convert.ToBase64String(new byte[32])));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [SkippableFact]
    public async Task Admin_endpoints_reject_a_token_from_another_device()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        await SeedUserAsync("alice", "correct horse battery staple", BuiltInRoles.ServerAdmin);
        var token = await LoginAsync("alice", "correct horse battery staple");

        var response = await _client.SendAsync(
            Authed(HttpMethod.Get, "/api/admin/users", token, device: "a-different-device"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [SkippableFact]
    public async Task An_authenticated_admin_can_list_users()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        await SeedUserAsync("alice", "correct horse battery staple", BuiltInRoles.ServerAdmin);
        var token = await LoginAsync("alice", "correct horse battery staple");

        var response = await _client.SendAsync(Authed(HttpMethod.Get, "/api/admin/users", token));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var users = await response.Content.ReadFromJsonAsync<List<UserSummary>>();
        Assert.Contains(users!, u => u.Username == "alice");
    }

    [SkippableFact]
    public async Task Logout_revokes_the_session_immediately()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        await SeedUserAsync("alice", "correct horse battery staple", BuiltInRoles.ServerAdmin);
        var token = await LoginAsync("alice", "correct horse battery staple");

        var logout = await _client.SendAsync(Authed(HttpMethod.Post, "/api/auth/logout", token));
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        var afterLogout = await _client.SendAsync(Authed(HttpMethod.Get, "/api/admin/users", token));
        Assert.Equal(HttpStatusCode.Unauthorized, afterLogout.StatusCode);
    }

    [SkippableFact]
    public async Task Health_reports_database_and_licence_state()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        await SeedUserAsync("alice", "correct horse battery staple", BuiltInRoles.ServerAdmin);
        var token = await LoginAsync("alice", "correct horse battery staple");

        var response = await _client.SendAsync(Authed(HttpMethod.Get, "/api/admin/health", token));
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("\"databaseReachable\":true", body);
        Assert.Contains("\"license\":\"Valid\"", body);
    }

    [SkippableFact]
    public async Task Licence_status_reports_seats_and_sessions()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync(seats: 50);
        await SeedUserAsync("alice", "correct horse battery staple", BuiltInRoles.ServerAdmin);
        var token = await LoginAsync("alice", "correct horse battery staple");

        var response = await _client.SendAsync(Authed(HttpMethod.Get, "/api/admin/license", token));
        var body = await response.Content.ReadAsStringAsync();

        Assert.Contains("\"seatsAllowed\":50", body);
        Assert.Contains("\"state\":\"Valid\"", body);
    }

    [SkippableFact]
    public async Task Seat_limit_blocks_creating_another_user()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync(seats: 1);
        await SeedUserAsync("alice", "correct horse battery staple", BuiltInRoles.ServerAdmin);
        var token = await LoginAsync("alice", "correct horse battery staple");

        var request = Authed(HttpMethod.Post, "/api/admin/users", token);
        request.Content = JsonContent.Create(
            new CreateUserRequest("bob", "Bob", "bob@corp.local", "a strong initial password"));
        var response = await _client.SendAsync(request);

        Assert.NotEqual(HttpStatusCode.Created, response.StatusCode);
    }

    /// <summary>
    /// Two administrators racing to create the same username both pass the upfront
    /// uniqueness check before either has committed; the unique index resolves the race, but
    /// only one caller may see it as an opaque 500 rather than the same conflict the upfront
    /// check reports.
    /// </summary>
    [SkippableFact]
    public async Task Concurrent_creation_of_the_same_username_gives_a_clean_conflict_to_the_loser()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        await SeedUserAsync("alice", "correct horse battery staple", BuiltInRoles.ServerAdmin);
        var token = await LoginAsync("alice", "correct horse battery staple");

        Func<Task<HttpResponseMessage>> attempt = () =>
        {
            var request = Authed(HttpMethod.Post, "/api/admin/users", token);
            request.Content = JsonContent.Create(
                new CreateUserRequest("carol", "Carol", null, "a strong initial password"));
            return _client.SendAsync(request);
        };

        var responses = await Task.WhenAll(attempt(), attempt());

        Assert.Single(responses, r => r.StatusCode == HttpStatusCode.Created);
        var loser = responses.Single(r => r.StatusCode != HttpStatusCode.Created);
        var body = await loser.Content.ReadFromJsonAsync<ErrorDto>();
        Assert.Equal(ErrorCode.UserAlreadyExists, body!.Code);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<MessengerDbContext>();
        Assert.Equal(1, await db.Users.CountAsync(u => u.Username == "carol"));
    }

    [SkippableFact]
    public async Task A_rejected_password_leaves_no_account_behind()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        await SeedUserAsync("alice", "correct horse battery staple", BuiltInRoles.ServerAdmin);
        var token = await LoginAsync("alice", "correct horse battery staple");

        var request = Authed(HttpMethod.Post, "/api/admin/users", token);
        request.Content = JsonContent.Create(new CreateUserRequest("bob", "Bob", null, "short"));
        var response = await _client.SendAsync(request);

        Assert.NotEqual(HttpStatusCode.Created, response.StatusCode);

        // The account must not exist at all. Creating the row first and validating the
        // password afterwards left a real user with no password hash, no role, and a
        // consumed licence seat — none of which any error message mentioned.
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<MessengerDbContext>();
        Assert.False(await db.Users.AnyAsync(u => u.Username == "bob"));
    }

    [SkippableTheory]
    [InlineData("", "Bob")]
    [InlineData("   ", "Bob")]
    [InlineData("bob", "")]
    public async Task Creating_a_user_rejects_a_missing_name(string username, string displayName)
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        await SeedUserAsync("alice", "correct horse battery staple", BuiltInRoles.ServerAdmin);
        var token = await LoginAsync("alice", "correct horse battery staple");

        var request = Authed(HttpMethod.Post, "/api/admin/users", token);
        request.Content = JsonContent.Create(
            new CreateUserRequest(username, displayName, null, "a strong initial password"));
        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [SkippableFact]
    public async Task An_over_long_username_is_a_bad_request_not_a_server_error()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        await SeedUserAsync("alice", "correct horse battery staple", BuiltInRoles.ServerAdmin);
        var token = await LoginAsync("alice", "correct horse battery staple");

        var request = Authed(HttpMethod.Post, "/api/admin/users", token);
        request.Content = JsonContent.Create(new CreateUserRequest(
            new string('u', 257), "Bob", null, "a strong initial password"));
        var response = await _client.SendAsync(request);

        // Left to the database this is a DbUpdateException, which reaches the caller as an
        // opaque 500 with a correlation id and no indication of what to fix.
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var error = await response.Content.ReadFromJsonAsync<ErrorDto>();
        Assert.Equal(ErrorCode.MalformedRequest, error!.Code);
    }

    [SkippableFact]
    public async Task An_unrecognised_status_is_a_bad_request_not_a_server_error()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        await SeedUserAsync("alice", "correct horse battery staple", BuiltInRoles.ServerAdmin);
        var bob = await SeedUserAsync("bob", "another good long password");
        var token = await LoginAsync("alice", "correct horse battery staple");

        var request = Authed(HttpMethod.Post, $"/api/admin/users/{bob.Id}/status", token);
        request.Content = JsonContent.Create(new SetStatusRequest("Bananas"));
        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var error = await response.Content.ReadFromJsonAsync<ErrorDto>();
        Assert.Equal(ErrorCode.MalformedRequest, error!.Code);
    }

    [SkippableFact]
    public async Task An_admin_cannot_disable_their_own_account()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        var alice = await SeedUserAsync("alice", "correct horse battery staple", BuiltInRoles.ServerAdmin);
        var token = await LoginAsync("alice", "correct horse battery staple");

        var request = Authed(HttpMethod.Post, $"/api/admin/users/{alice.Id}/status", token);
        request.Content = JsonContent.Create(new SetStatusRequest("Disabled"));
        var response = await _client.SendAsync(request);

        // Otherwise an administrator locks themselves out with no route back short of
        // database surgery.
        var error = await response.Content.ReadFromJsonAsync<ErrorDto>();
        Assert.Equal(ErrorCode.SelfModificationRefused, error!.Code);
    }

    [SkippableFact]
    public async Task Deactivating_a_user_revokes_their_sessions_at_once()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        await SeedUserAsync("alice", "correct horse battery staple", BuiltInRoles.ServerAdmin);
        var bob = await SeedUserAsync("bob", "another good long password");

        var adminToken = await LoginAsync("alice", "correct horse battery staple");
        var bobToken = await LoginAsync("bob", "another good long password", device: "bob-device");

        var request = Authed(HttpMethod.Post, $"/api/admin/users/{bob.Id}/status", adminToken);
        request.Content = JsonContent.Create(new SetStatusRequest("Disabled"));
        await _client.SendAsync(request);

        var bobAfter = await _client.SendAsync(
            Authed(HttpMethod.Get, "/api/admin/users", bobToken, device: "bob-device"));

        Assert.Equal(HttpStatusCode.Unauthorized, bobAfter.StatusCode);
    }

    [SkippableFact]
    public async Task Audit_verification_reports_a_valid_chain()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        await SeedUserAsync("alice", "correct horse battery staple", BuiltInRoles.ServerAdmin);
        var token = await LoginAsync("alice", "correct horse battery staple");

        var response = await _client.SendAsync(Authed(HttpMethod.Post, "/api/admin/audit/verify", token));
        var body = await response.Content.ReadAsStringAsync();

        Assert.Contains("\"valid\":true", body);
    }

    [SkippableFact]
    public async Task Audit_verification_detects_tampering_through_the_api()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        await SeedUserAsync("alice", "correct horse battery staple", BuiltInRoles.ServerAdmin);
        var token = await LoginAsync("alice", "correct horse battery staple");

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<MessengerDbContext>();
            var entry = await db.AuditLog.OrderBy(e => e.Id).FirstAsync();
            entry.Outcome = "tampered";
            await db.SaveChangesAsync();
        }

        var response = await _client.SendAsync(Authed(HttpMethod.Post, "/api/admin/audit/verify", token));
        var body = await response.Content.ReadAsStringAsync();

        Assert.Contains("\"valid\":false", body);
        Assert.Contains(ErrorCode.AuditChainVerificationFailed, body);
    }

    /// <summary>
    /// The checkpoint half of verification is reported, not just the hash chain.
    ///
    /// Before the signing key was made durable there was nothing worth reporting: the key was
    /// minted per process, so any checkpoint written by an earlier run was signed by a key
    /// this one had never held and could never be checked. Anything unverifiable here is a
    /// regression in that durability.
    /// </summary>
    [SkippableFact]
    public async Task Audit_verification_reports_the_checkpoint_signatures()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        await SeedUserAsync("alice", "correct horse battery staple", BuiltInRoles.ServerAdmin);
        var token = await LoginAsync("alice", "correct horse battery staple");

        // Startup does not write 1000 audit entries, so a checkpoint is forced rather than
        // waited for -- the interval is not what is under test here.
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<MessengerDbContext>();
            var audit = scope.ServiceProvider.GetRequiredService<AuditService>();
            await audit.WriteCheckpointAsync(await db.AuditLog.OrderByDescending(e => e.Id).FirstAsync());
        }

        var response = await _client.SendAsync(Authed(HttpMethod.Post, "/api/admin/audit/verify", token));
        var body = await response.Content.ReadAsStringAsync();

        Assert.Contains("\"valid\":true", body);
        Assert.Contains("\"checkpointsVerified\":1", body);
        Assert.Contains("\"checkpointsUnverifiable\":0", body);
    }

    // ---- Authorization: the defect these tests exist to prevent regressing ----

    /// <summary>
    /// The critical finding from the security review: the admin filter authenticated but
    /// never authorized, so any authenticated end user could manage accounts, revoke
    /// sessions, and read the entire audit log.
    /// </summary>
    [SkippableTheory]
    [InlineData("GET", "/api/admin/users")]
    [InlineData("GET", "/api/admin/groups")]
    [InlineData("GET", "/api/admin/sessions")]
    [InlineData("GET", "/api/admin/audit")]
    [InlineData("GET", "/api/admin/license")]
    [InlineData("GET", "/api/admin/health")]
    public async Task An_ordinary_user_is_refused_every_admin_read(string method, string url)
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        await SeedUserAsync("ordinary", "an ordinary user password");
        var token = await LoginAsync("ordinary", "an ordinary user password");

        var response = await _client.SendAsync(Authed(new HttpMethod(method), url, token));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var error = await response.Content.ReadFromJsonAsync<ErrorDto>();
        Assert.Equal(ErrorCode.PermissionDenied, error!.Code);
    }

    [SkippableFact]
    public async Task An_ordinary_user_cannot_create_a_user()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        await SeedUserAsync("ordinary", "an ordinary user password");
        var token = await LoginAsync("ordinary", "an ordinary user password");

        var request = Authed(HttpMethod.Post, "/api/admin/users", token);
        request.Content = JsonContent.Create(
            new CreateUserRequest("backdoor", "Backdoor", null, "a strong initial password"));
        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [SkippableFact]
    public async Task An_ordinary_user_cannot_revoke_another_users_session()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        await SeedUserAsync("ordinary", "an ordinary user password");
        var victim = await SeedUserAsync("victim", "victim long password here");

        var attackerToken = await LoginAsync("ordinary", "an ordinary user password");
        await LoginAsync("victim", "victim long password here", device: "victim-device");

        Guid victimSessionId;
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<MessengerDbContext>();
            victimSessionId = await db.Sessions.Where(x => x.UserId == victim.Id).Select(x => x.Id).FirstAsync();
        }

        var response = await _client.SendAsync(
            Authed(HttpMethod.Delete, $"/api/admin/sessions/{victimSessionId}", attackerToken));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>Reading the audit log discloses the whole organisation's activity.</summary>
    [SkippableFact]
    public async Task An_ordinary_user_cannot_read_the_audit_log()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        await SeedUserAsync("ordinary", "an ordinary user password");
        var token = await LoginAsync("ordinary", "an ordinary user password");

        var response = await _client.SendAsync(Authed(HttpMethod.Get, "/api/admin/audit", token));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.DoesNotContain("auth.login", await response.Content.ReadAsStringAsync());
    }

    [SkippableFact]
    public async Task An_ordinary_user_cannot_install_a_licence()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        await SeedUserAsync("ordinary", "an ordinary user password");
        var token = await LoginAsync("ordinary", "an ordinary user password");

        var request = Authed(HttpMethod.Post, "/api/admin/license", token);
        request.Content = JsonContent.Create(new InstallLicenseRequest("anything"));

        Assert.Equal(HttpStatusCode.Forbidden, (await _client.SendAsync(request)).StatusCode);
    }

    /// <summary>Separation of duties, verified at the HTTP boundary rather than only in the service.</summary>
    [SkippableFact]
    public async Task An_auditor_reads_the_audit_log_but_cannot_create_users()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        await SeedUserAsync("auditor", "auditor long password here", BuiltInRoles.Auditor);
        var token = await LoginAsync("auditor", "auditor long password here");

        var read = await _client.SendAsync(Authed(HttpMethod.Get, "/api/admin/audit", token));
        Assert.Equal(HttpStatusCode.OK, read.StatusCode);

        var create = Authed(HttpMethod.Post, "/api/admin/users", token);
        create.Content = JsonContent.Create(new CreateUserRequest("x", "X", null, "a strong initial password"));
        Assert.Equal(HttpStatusCode.Forbidden, (await _client.SendAsync(create)).StatusCode);
    }

    [SkippableFact]
    public async Task Help_desk_can_revoke_a_session_but_not_create_users()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        await SeedUserAsync("helpdesk", "helpdesk long password", BuiltInRoles.HelpDesk);
        var token = await LoginAsync("helpdesk", "helpdesk long password");

        Assert.Equal(HttpStatusCode.OK,
            (await _client.SendAsync(Authed(HttpMethod.Get, "/api/admin/sessions", token))).StatusCode);

        var create = Authed(HttpMethod.Post, "/api/admin/users", token);
        create.Content = JsonContent.Create(new CreateUserRequest("x", "X", null, "a strong initial password"));
        Assert.Equal(HttpStatusCode.Forbidden, (await _client.SendAsync(create)).StatusCode);
    }

    /// <summary>A permission denial must reach the audit log, not just the caller.</summary>
    [SkippableFact]
    public async Task A_denied_admin_call_is_audited()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        var ordinary = await SeedUserAsync("ordinary", "an ordinary user password");
        var token = await LoginAsync("ordinary", "an ordinary user password");

        await _client.SendAsync(Authed(HttpMethod.Get, "/api/admin/audit", token));

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<MessengerDbContext>();
        var denial = await db.AuditLog.FirstOrDefaultAsync(e => e.Action == "authz.deny" && e.ActorUserId == ordinary.Id);

        Assert.NotNull(denial);
        Assert.Contains(Permissions.AuditRead, denial!.DetailJson!);
    }

    /// <summary>Security headers are applied to responses.</summary>
    [SkippableFact]
    public async Task Security_headers_are_present()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");

        var response = await _client.GetAsync("/health/live");

        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Contains("frame-ancestors 'none'", response.Headers.GetValues("Content-Security-Policy").Single());
    }
}
