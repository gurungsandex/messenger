using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Messenger.Contracts;
using Messenger.Core;
using Messenger.Crypto;
using Messenger.Data;
using Messenger.Licensing;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Xunit;

namespace Messenger.Server.Tests;

/// <summary>
/// End-to-end tests for the routes added to give the WPF client and admin console something
/// real to call: conversation listing, self-service password change, the file transfer wire
/// API, and the group lifecycle routes that wrap already-tested <see cref="GroupService"/>
/// methods. Mirrors <see cref="AdminApiTests"/>'s fixture pattern.
/// </summary>
public sealed class ClientApiTests : IAsyncLifetime
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

        _database = "messenger_client_api_" + Guid.NewGuid().ToString("N")[..12];
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

        var options = new DbContextOptionsBuilder<MessengerDbContext>().UseNpgsql(scoped).Options;
        await using (var schema = new MessengerDbContext(options))
            await schema.Database.EnsureCreatedAsync();

        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseSetting("ConnectionStrings:Messenger", scoped);
            b.UseSetting("Licensing:VendorPublicKey", Convert.ToBase64String(vendorPublic));
            b.UseSetting("KeyStore:Passphrase", "test-keystore-passphrase");
            b.UseSetting("KeyStore:EscrowPath", Path.Combine(_keyStoreDirectory, "root.escrow"));
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

        var user = new User { Username = username, DisplayName = username, PasswordHash = hasher.Hash(password) };
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

    private async Task InstallLicenseAsync(int seats = 100, int totalSessions = 100)
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
            NotAfter = now.AddDays(365),
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
    public async Task Conversation_list_includes_a_direct_conversation_opened_over_the_hub()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        var alice = await SeedUserAsync("alice", "correct horse battery staple");
        var bob = await SeedUserAsync("bob", "another good long password");
        var aliceToken = await LoginAsync("alice", "correct horse battery staple");

        using (var scope = _factory.Services.CreateScope())
        {
            var messages = scope.ServiceProvider.GetRequiredService<MessageService>();
            await messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);
        }

        var response = await _client.SendAsync(Authed(HttpMethod.Get, "/api/conversations", aliceToken));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var conversations = await response.Content.ReadFromJsonAsync<List<ConversationDto>>();
        Assert.Contains(conversations!, c => c.Title == "bob" && c.Type == ConversationType.Direct);
    }

    [SkippableFact]
    public async Task Conversation_list_requires_authentication()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");

        var response = await _client.GetAsync("/api/conversations");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [SkippableFact]
    public async Task User_directory_excludes_the_caller_and_matches_by_name()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        var alice = await SeedUserAsync("alice", "correct horse battery staple");
        await SeedUserAsync("bob", "another good long password");
        var aliceToken = await LoginAsync("alice", "correct horse battery staple");

        var response = await _client.SendAsync(Authed(HttpMethod.Get, "/api/users", aliceToken));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var users = await response.Content.ReadFromJsonAsync<List<UserDirectoryEntryDto>>();
        Assert.Contains(users!, u => u.Username == "bob");
        Assert.DoesNotContain(users!, u => u.UserId == alice.Id);

        var filtered = await _client.SendAsync(Authed(HttpMethod.Get, "/api/users?q=bo", aliceToken));
        var filteredUsers = await filtered.Content.ReadFromJsonAsync<List<UserDirectoryEntryDto>>();
        Assert.Single(filteredUsers!);
        Assert.Equal("bob", filteredUsers![0].Username);
    }

    [SkippableFact]
    public async Task User_directory_requires_authentication()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");

        var response = await _client.GetAsync("/api/users");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [SkippableFact]
    public async Task Change_password_rejects_the_wrong_current_password()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        await SeedUserAsync("alice", "correct horse battery staple");
        var token = await LoginAsync("alice", "correct horse battery staple");

        var request = Authed(HttpMethod.Post, "/api/auth/change-password", token);
        request.Content = JsonContent.Create(new ChangePasswordRequest("wrong password", "a brand new long password"));
        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>
    /// A password change must revoke every session -- including the one that made the
    /// change -- exactly as an admin-forced reset does, so a stolen token cannot outlive the
    /// credential the user just rotated away from.
    /// </summary>
    [SkippableFact]
    public async Task Change_password_succeeds_and_revokes_the_calling_session()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        await SeedUserAsync("alice", "correct horse battery staple");
        var token = await LoginAsync("alice", "correct horse battery staple");

        var request = Authed(HttpMethod.Post, "/api/auth/change-password", token);
        request.Content = JsonContent.Create(new ChangePasswordRequest("correct horse battery staple", "a brand new long password"));
        var response = await _client.SendAsync(request);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        var afterChange = await _client.SendAsync(Authed(HttpMethod.Get, "/api/conversations", token));
        Assert.Equal(HttpStatusCode.Unauthorized, afterChange.StatusCode);

        var newToken = await LoginAsync("alice", "a brand new long password");
        Assert.False(string.IsNullOrEmpty(newToken));
    }

    /// <summary>
    /// Regression test for the bug the fifth review fixed: an account flagged
    /// must-change-password could not log in at all, so it could never reach the one route
    /// (change-password) that clears the flag. Login must succeed and issue a session; every
    /// other authenticated route must refuse that session until the password is changed.
    /// </summary>
    [SkippableFact]
    public async Task An_account_flagged_must_change_password_can_log_in_and_is_blocked_everywhere_except_change_password()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        var carol = await SeedUserAsync("carol", "carol's original password");

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<MessengerDbContext>();
            var user = await db.Users.SingleAsync(u => u.Id == carol.Id);
            user.MustChangePassword = true;
            await db.SaveChangesAsync();
        }

        var loginResponse = await _client.PostAsJsonAsync("/api/auth/login",
            new LoginRequest("carol", "carol's original password", "device-1", "Test Device"));
        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);
        var login = (await loginResponse.Content.ReadFromJsonAsync<LoginResponse>())!;
        Assert.True(login.MustChangePassword);

        var blocked = await _client.SendAsync(Authed(HttpMethod.Get, "/api/conversations", login.SessionToken));
        Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);
        var error = await blocked.Content.ReadFromJsonAsync<ErrorDto>();
        Assert.Equal(ErrorCode.PasswordChangeRequired, error!.Code);

        var change = Authed(HttpMethod.Post, "/api/auth/change-password", login.SessionToken);
        change.Content = JsonContent.Create(new ChangePasswordRequest("carol's original password", "carol's replacement password"));
        var changeResponse = await _client.SendAsync(change);
        Assert.Equal(HttpStatusCode.NoContent, changeResponse.StatusCode);

        var newToken = await LoginAsync("carol", "carol's replacement password");
        var afterChange = await _client.SendAsync(Authed(HttpMethod.Get, "/api/conversations", newToken));
        Assert.Equal(HttpStatusCode.OK, afterChange.StatusCode);
    }

    [SkippableFact]
    public async Task A_group_can_be_renamed_disabled_and_deleted_through_the_admin_api()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        await SeedUserAsync("admin", "correct horse battery staple", BuiltInRoles.ServerAdmin);
        var token = await LoginAsync("admin", "correct horse battery staple");

        var create = Authed(HttpMethod.Post, "/api/admin/groups", token);
        create.Content = JsonContent.Create(new CreateGroupRequest("Engineering", "desc"));
        var createResponse = await _client.SendAsync(create);
        Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);
        var created = await createResponse.Content.ReadFromJsonAsync<JsonElement>();
        var groupId = created.GetProperty("id").GetGuid();

        var rename = Authed(HttpMethod.Put, $"/api/admin/groups/{groupId}", token);
        rename.Content = JsonContent.Create(new RenameGroupRequest("Engineering Team"));
        Assert.Equal(HttpStatusCode.NoContent, (await _client.SendAsync(rename)).StatusCode);

        var disable = Authed(HttpMethod.Post, $"/api/admin/groups/{groupId}/status", token);
        disable.Content = JsonContent.Create(new SetStatusRequest("Disabled"));
        Assert.Equal(HttpStatusCode.NoContent, (await _client.SendAsync(disable)).StatusCode);

        var list = await _client.SendAsync(Authed(HttpMethod.Get, "/api/admin/groups", token));
        var groups = await list.Content.ReadFromJsonAsync<List<GroupSummary>>();
        Assert.Contains(groups!, g => g.Id == groupId && g.Name == "Engineering Team" && g.Status == "Disabled");

        var delete = await _client.SendAsync(Authed(HttpMethod.Delete, $"/api/admin/groups/{groupId}", token));
        Assert.Equal(HttpStatusCode.NoContent, delete.StatusCode);

        var listAfterDelete = await _client.SendAsync(Authed(HttpMethod.Get, "/api/admin/groups", token));
        var groupsAfterDelete = await listAfterDelete.Content.ReadFromJsonAsync<List<GroupSummary>>();
        Assert.DoesNotContain(groupsAfterDelete!, g => g.Id == groupId);
    }

    [SkippableFact]
    public async Task An_ordinary_user_cannot_rename_a_group()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        await SeedUserAsync("admin", "correct horse battery staple", BuiltInRoles.ServerAdmin);
        await SeedUserAsync("ordinary", "an ordinary user password");
        var adminToken = await LoginAsync("admin", "correct horse battery staple");
        var ordinaryToken = await LoginAsync("ordinary", "an ordinary user password", device: "ordinary-device");

        var create = Authed(HttpMethod.Post, "/api/admin/groups", adminToken);
        create.Content = JsonContent.Create(new CreateGroupRequest("Engineering", null));
        var createdJson = await (await _client.SendAsync(create)).Content.ReadFromJsonAsync<JsonElement>();
        var groupId = createdJson.GetProperty("id").GetGuid();

        var rename = Authed(HttpMethod.Put, $"/api/admin/groups/{groupId}", ordinaryToken, device: "ordinary-device");
        rename.Content = JsonContent.Create(new RenameGroupRequest("Hijacked"));

        Assert.Equal(HttpStatusCode.Forbidden, (await _client.SendAsync(rename)).StatusCode);
    }

    /// <summary>
    /// Exercises the whole file transfer wire API end to end: begin, upload the one chunk,
    /// confirm it shows up in the resume list, complete, download, and verify the round trip
    /// is byte-identical -- the same path the WPF client's file transfer screen will drive.
    /// </summary>
    [SkippableFact]
    public async Task A_file_can_be_uploaded_completed_and_downloaded_byte_identical()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        var alice = await SeedUserAsync("alice", "correct horse battery staple");
        var bob = await SeedUserAsync("bob", "another good long password");
        var token = await LoginAsync("alice", "correct horse battery staple");

        Guid conversationId;
        using (var scope = _factory.Services.CreateScope())
        {
            var messages = scope.ServiceProvider.GetRequiredService<MessageService>();
            var conversation = await messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);
            conversationId = conversation.Id;
        }

        var content = "hello messenger file transfer test content"u8.ToArray();
        var sha256 = SHA256.HashData(content);

        var begin = Authed(HttpMethod.Post, "/api/files", token);
        begin.Content = JsonContent.Create(new BeginUploadRequest(
            conversationId, "testfile.txt", content.Length, Convert.ToBase64String(sha256), "text/plain"));
        var beginResponse = await _client.SendAsync(begin);
        Assert.Equal(HttpStatusCode.Created, beginResponse.StatusCode);
        var slot = await beginResponse.Content.ReadFromJsonAsync<JsonElement>();
        var fileId = slot.GetProperty("fileId").GetGuid();

        var upload = Authed(HttpMethod.Put, $"/api/files/{fileId}/chunks/0", token);
        upload.Content = new ByteArrayContent(content);
        Assert.Equal(HttpStatusCode.NoContent, (await _client.SendAsync(upload)).StatusCode);

        var received = await _client.SendAsync(Authed(HttpMethod.Get, $"/api/files/{fileId}/chunks", token));
        Assert.Equal("[0]", await received.Content.ReadAsStringAsync());

        var complete = await _client.SendAsync(Authed(HttpMethod.Post, $"/api/files/{fileId}/complete", token));
        Assert.Equal(HttpStatusCode.NoContent, complete.StatusCode);

        var download = await _client.SendAsync(Authed(HttpMethod.Get, $"/api/files/{fileId}", token));
        Assert.Equal(HttpStatusCode.OK, download.StatusCode);
        Assert.Equal(content, await download.Content.ReadAsByteArrayAsync());
    }

    [SkippableFact]
    public async Task Uploading_to_a_conversation_you_are_not_a_participant_of_is_refused()
    {
        Skip.If(BaseConnection is null, "MESSENGER_TEST_CONNECTION is not set.");
        await InstallLicenseAsync();
        var alice = await SeedUserAsync("alice", "correct horse battery staple");
        var bob = await SeedUserAsync("bob", "another good long password");
        var mallory = await SeedUserAsync("mallory", "mallory long password here");
        var malloryToken = await LoginAsync("mallory", "mallory long password here");

        Guid conversationId;
        using (var scope = _factory.Services.CreateScope())
        {
            var messages = scope.ServiceProvider.GetRequiredService<MessageService>();
            var conversation = await messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);
            conversationId = conversation.Id;
        }

        var begin = Authed(HttpMethod.Post, "/api/files", malloryToken);
        begin.Content = JsonContent.Create(new BeginUploadRequest(
            conversationId, "testfile.txt", 4, Convert.ToBase64String(SHA256.HashData("abcd"u8.ToArray())), null));
        var response = await _client.SendAsync(begin);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var error = await response.Content.ReadFromJsonAsync<ErrorDto>();
        Assert.Equal(ErrorCode.NotAConversationParticipant, error!.Code);
    }
}
