using System.Net.Http;
using System.Net.Http.Json;
using Messenger.Contracts;

namespace Messenger.Admin.Wpf.Services;

/// <summary>
/// Covers every route in <c>AdminApi.cs</c> plus the auth endpoints in <c>Program.cs</c>,
/// including the group lifecycle routes added alongside this project. Every method is a thin
/// wrapper -- no policy logic lives here, it all lives server-side and every error the server
/// returns arrives as a catalogue-coded <see cref="ErrorDto"/>, wrapped as
/// <see cref="MessengerApiException"/>.
/// </summary>
public sealed class AdminApiClient : IDisposable
{
    private readonly HttpClient _http;

    public string? SessionToken { get; private set; }
    public Guid UserId { get; private set; }
    public string? DisplayName { get; private set; }
    public string DeviceFingerprint { get; } = DeviceIdentity.GetOrCreate();

    public AdminApiClient(string baseUrl)
    {
        _http = new HttpClient { BaseAddress = new Uri(baseUrl) };
    }

    public async Task<LoginResponse> LoginAsync(string username, string password, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync("/api/auth/login",
            new LoginRequest(username, password, DeviceFingerprint, Environment.MachineName), ct);

        if (!response.IsSuccessStatusCode)
            throw new MessengerApiException(await ReadErrorAsync(response, ct));

        var body = (await response.Content.ReadFromJsonAsync<LoginResponse>(cancellationToken: ct))!;
        SessionToken = body.SessionToken;
        UserId = body.UserId;
        DisplayName = body.DisplayName;
        ApplyAuthHeaders();
        return body;
    }

    public async Task LogoutAsync(CancellationToken ct = default)
    {
        if (SessionToken is null) return;
        await _http.PostAsync("/api/auth/logout", null, ct);
        SessionToken = null;
    }

    // ---- Users ---------------------------------------------------------------------------

    public async Task<List<UserSummary>> GetUsersAsync(int page = 0, int pageSize = 50, CancellationToken ct = default)
        => await GetAsync<List<UserSummary>>($"/api/admin/users?page={page}&pageSize={pageSize}", ct);

    public async Task<Guid> CreateUserAsync(CreateUserRequest request, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync("/api/admin/users", request, ct);
        if (!response.IsSuccessStatusCode)
            throw new MessengerApiException(await ReadErrorAsync(response, ct));
        var body = await response.Content.ReadFromJsonAsync<IdResponse>(cancellationToken: ct);
        return body!.Id;
    }

    public Task SetUserStatusAsync(Guid userId, string status, CancellationToken ct = default)
        => PostAsync($"/api/admin/users/{userId}/status", new SetStatusRequest(status), ct);

    // ---- Groups --------------------------------------------------------------------------

    public Task<List<GroupSummary>> GetGroupsAsync(CancellationToken ct = default)
        => GetAsync<List<GroupSummary>>("/api/admin/groups", ct);

    public async Task<Guid> CreateGroupAsync(string name, string? description, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync("/api/admin/groups", new CreateGroupRequest(name, description), ct);
        if (!response.IsSuccessStatusCode)
            throw new MessengerApiException(await ReadErrorAsync(response, ct));
        var body = await response.Content.ReadFromJsonAsync<IdResponse>(cancellationToken: ct);
        return body!.Id;
    }

    public Task AddGroupMemberAsync(Guid groupId, Guid userId, CancellationToken ct = default)
        => PostAsync($"/api/admin/groups/{groupId}/members/{userId}", null, ct);

    public Task RemoveGroupMemberAsync(Guid groupId, Guid userId, CancellationToken ct = default)
        => DeleteAsync($"/api/admin/groups/{groupId}/members/{userId}", ct);

    public Task MoveGroupMemberAsync(Guid fromGroupId, Guid toGroupId, Guid userId, CancellationToken ct = default)
        => PostAsync($"/api/admin/groups/{fromGroupId}/move/{userId}/to/{toGroupId}", null, ct);

    public Task RenameGroupAsync(Guid groupId, string newName, CancellationToken ct = default)
        => PutAsync($"/api/admin/groups/{groupId}", new RenameGroupRequest(newName), ct);

    public Task SetGroupStatusAsync(Guid groupId, string status, CancellationToken ct = default)
        => PostAsync($"/api/admin/groups/{groupId}/status", new SetStatusRequest(status), ct);

    public Task DeleteGroupAsync(Guid groupId, CancellationToken ct = default)
        => DeleteAsync($"/api/admin/groups/{groupId}", ct);

    // ---- Sessions --------------------------------------------------------------------------

    public Task<List<SessionSummary>> GetSessionsAsync(CancellationToken ct = default)
        => GetAsync<List<SessionSummary>>("/api/admin/sessions", ct);

    public Task RevokeSessionAsync(Guid sessionId, CancellationToken ct = default)
        => DeleteAsync($"/api/admin/sessions/{sessionId}", ct);

    // ---- Licence ---------------------------------------------------------------------------

    public Task<LicenseStatusResponse> GetLicenseAsync(CancellationToken ct = default)
        => GetAsync<LicenseStatusResponse>("/api/admin/license", ct);

    public Task InstallLicenseAsync(string licenseFileContent, CancellationToken ct = default)
        => PostAsync("/api/admin/license", new InstallLicenseRequest(licenseFileContent), ct);

    // ---- Directory sync ----------------------------------------------------------------------

    public Task<SyncReportResponse> TriggerDirectorySyncAsync(CancellationToken ct = default)
        => PostForResultAsync<SyncReportResponse>("/api/admin/directory/sync", null, ct);

    // ---- Audit -----------------------------------------------------------------------------

    public Task<List<AuditEntrySummary>> GetAuditLogAsync(long fromId = 0, int limit = 100, CancellationToken ct = default)
        => GetAsync<List<AuditEntrySummary>>($"/api/admin/audit?fromId={fromId}&limit={limit}", ct);

    public Task<AuditVerifyResponse> VerifyAuditChainAsync(CancellationToken ct = default)
        => PostForResultAsync<AuditVerifyResponse>("/api/admin/audit/verify", null, ct);

    // ---- Health --------------------------------------------------------------------------

    public Task<HealthResponse> GetHealthAsync(CancellationToken ct = default)
        => GetAsync<HealthResponse>("/api/admin/health", ct);

    // ---- Plumbing --------------------------------------------------------------------------

    private async Task<T> GetAsync<T>(string url, CancellationToken ct)
    {
        var response = await _http.GetAsync(url, ct);
        if (!response.IsSuccessStatusCode)
            throw new MessengerApiException(await ReadErrorAsync(response, ct));
        return (await response.Content.ReadFromJsonAsync<T>(cancellationToken: ct))!;
    }

    private async Task PostAsync(string url, object? body, CancellationToken ct)
    {
        var response = body is null ? await _http.PostAsync(url, null, ct) : await _http.PostAsJsonAsync(url, body, ct);
        if (!response.IsSuccessStatusCode)
            throw new MessengerApiException(await ReadErrorAsync(response, ct));
    }

    private async Task<T> PostForResultAsync<T>(string url, object? body, CancellationToken ct)
    {
        var response = body is null ? await _http.PostAsync(url, null, ct) : await _http.PostAsJsonAsync(url, body, ct);
        if (!response.IsSuccessStatusCode)
            throw new MessengerApiException(await ReadErrorAsync(response, ct));
        return (await response.Content.ReadFromJsonAsync<T>(cancellationToken: ct))!;
    }

    private async Task PutAsync(string url, object body, CancellationToken ct)
    {
        var response = await _http.PutAsJsonAsync(url, body, ct);
        if (!response.IsSuccessStatusCode)
            throw new MessengerApiException(await ReadErrorAsync(response, ct));
    }

    private async Task DeleteAsync(string url, CancellationToken ct)
    {
        var response = await _http.DeleteAsync(url, ct);
        if (!response.IsSuccessStatusCode)
            throw new MessengerApiException(await ReadErrorAsync(response, ct));
    }

    private void ApplyAuthHeaders()
    {
        _http.DefaultRequestHeaders.Remove("X-Session-Token");
        _http.DefaultRequestHeaders.Remove("X-Device-Fingerprint");
        _http.DefaultRequestHeaders.Add("X-Session-Token", SessionToken);
        _http.DefaultRequestHeaders.Add("X-Device-Fingerprint", DeviceFingerprint);
    }

    private static async Task<ErrorDto> ReadErrorAsync(HttpResponseMessage response, CancellationToken ct)
    {
        try
        {
            var error = await response.Content.ReadFromJsonAsync<ErrorDto>(cancellationToken: ct);
            if (error is not null) return error;
        }
        catch
        {
            // A non-ErrorDto error body (a proxy's HTML error page, for instance) must not
            // crash the client trying to parse it as JSON.
        }

        return new ErrorDto("NET-000", $"Request failed with status {(int)response.StatusCode}.", null);
    }

    public void Dispose() => _http.Dispose();

    private sealed record IdResponse(Guid Id);
}
