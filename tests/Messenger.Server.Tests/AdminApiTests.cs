using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Messenger.Contracts;
using Messenger.Core;
using Messenger.Crypto;
using Messenger.Data;
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

    public async Task InitializeAsync()
    {
        if (BaseConnection is null) return;

        _database = "messenger_api_" + Guid.NewGuid().ToString("N")[..12];

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

        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseSetting("ConnectionStrings:Messenger", scoped);
            b.UseSetting("Licensing:VendorPublicKey", Convert.ToBase64String(vendorPublic));
        });

        _client = _factory.CreateClient();

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<MessengerDbContext>();
        await db.Database.EnsureCreatedAsync();
    }

    public async Task DisposeAsync()
    {
        if (BaseConnection is null) return;

        _client.Dispose();
        await _factory.DisposeAsync();
        NpgsqlConnection.ClearAllPools();

        var admin = new NpgsqlConnectionStringBuilder(BaseConnection) { Database = "postgres" };
        await using var cleanup = new NpgsqlConnection(admin.ConnectionString);
        await cleanup.OpenAsync();
        await using var cmd = cleanup.CreateCommand();
        cmd.CommandText = $"DROP DATABASE IF EXISTS \"{_database}\" WITH (FORCE)";
        await cmd.ExecuteNonQueryAsync();
    }

    private async Task<User> SeedUserAsync(string username, string password)
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
        await SeedUserAsync("alice", "correct horse battery staple");
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
        await SeedUserAsync("alice", "correct horse battery staple");
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
        await SeedUserAsync("alice", "correct horse battery staple");
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
        await SeedUserAsync("alice", "correct horse battery staple");
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
        await SeedUserAsync("alice", "correct horse battery staple");
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
        await SeedUserAsync("alice", "correct horse battery staple");
        var token = await LoginAsync("alice", "correct horse battery staple");

        var request = Authed(HttpMethod.Post, "/api/admin/users", token);
        request.Content = JsonContent.Create(
            new CreateUserRequest("bob", "Bob", "bob@corp.local", "a strong initial password"));
        var response = await _client.SendAsync(request);

        Assert.NotEqual(HttpStatusCode.Created, response.StatusCode);
    }

    [SkippableFact]
    public async Task An_admin_cannot_disable_their_own_account()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        var alice = await SeedUserAsync("alice", "correct horse battery staple");
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
        await SeedUserAsync("alice", "correct horse battery staple");
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
        await SeedUserAsync("alice", "correct horse battery staple");
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
        await SeedUserAsync("alice", "correct horse battery staple");
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
}
