using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography;
using Messenger.Contracts;

namespace Messenger.Client.Wpf.Services;

/// <summary>
/// The REST half of the client: login, self-service password change, conversation
/// discovery, and file transfer. Chat itself is <see cref="ChatHubClient"/> -- SignalR, not
/// REST. Every method here calls a route proven working end to end against the real server
/// in the session that added it (see the Part 1 backend-gap smoke tests), so this is a thin
/// wrapper, not a reimplementation of anything.
/// </summary>
public sealed class ApiClient : IDisposable
{
    private readonly HttpClient _http;

    public string? SessionToken { get; private set; }
    public Guid UserId { get; private set; }
    public string? DisplayName { get; private set; }
    public DateTimeOffset ExpiresAt { get; private set; }
    public int IdleTimeoutSeconds { get; private set; }
    public string DeviceFingerprint { get; } = DeviceIdentity.GetOrCreate();

    public ApiClient(string baseUrl)
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
        ExpiresAt = body.ExpiresAt;
        IdleTimeoutSeconds = body.IdleTimeoutSeconds;
        ApplyAuthHeaders();
        return body;
    }

    public async Task LogoutAsync(CancellationToken ct = default)
    {
        if (SessionToken is null) return;
        await _http.PostAsync("/api/auth/logout", null, ct);
        SessionToken = null;
    }

    public async Task ChangePasswordAsync(string currentPassword, string newPassword, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync("/api/auth/change-password",
            new ChangePasswordRequest(currentPassword, newPassword), ct);

        if (!response.IsSuccessStatusCode)
            throw new MessengerApiException(await ReadErrorAsync(response, ct));

        // The server revokes every session on a password change, including the one that made
        // the call -- so the token this client is holding is already dead. The caller must
        // log in again with the new password.
        SessionToken = null;
    }

    public async Task<IReadOnlyList<ConversationDto>> GetConversationsAsync(CancellationToken ct = default)
    {
        var response = await _http.GetAsync("/api/conversations", ct);
        if (!response.IsSuccessStatusCode)
            throw new MessengerApiException(await ReadErrorAsync(response, ct));
        return (await response.Content.ReadFromJsonAsync<List<ConversationDto>>(cancellationToken: ct))!;
    }

    public async Task<IReadOnlyList<UserDirectoryEntryDto>> SearchUsersAsync(string? query, CancellationToken ct = default)
    {
        var url = string.IsNullOrWhiteSpace(query) ? "/api/users" : $"/api/users?q={Uri.EscapeDataString(query)}";
        var response = await _http.GetAsync(url, ct);
        if (!response.IsSuccessStatusCode)
            throw new MessengerApiException(await ReadErrorAsync(response, ct));
        return (await response.Content.ReadFromJsonAsync<List<UserDirectoryEntryDto>>(cancellationToken: ct))!;
    }

    // ---- File transfer ------------------------------------------------------------------

    private async Task<(Guid FileId, int ChunkSize, long ChunkCount)> BeginUploadAsync(
        Guid conversationId, string fileName, byte[] content, string? contentType, CancellationToken ct = default)
    {
        var sha256 = SHA256.HashData(content);
        var response = await _http.PostAsJsonAsync("/api/files", new
        {
            conversationId,
            fileName,
            sizeBytes = (long)content.Length,
            sha256PlaintextBase64 = Convert.ToBase64String(sha256),
            contentType,
        }, ct);

        if (!response.IsSuccessStatusCode)
            throw new MessengerApiException(await ReadErrorAsync(response, ct));

        var slot = await response.Content.ReadFromJsonAsync<UploadSlotResponse>(cancellationToken: ct);
        return (slot!.FileId, slot.ChunkSize, slot.ChunkCount);
    }

    /// <summary>
    /// Uploads a whole small-to-medium file in one call, chunking internally, and returns the
    /// id of the completed <c>StoredFile</c> -- begin, every chunk, and complete all happen
    /// against the one upload session this call created, so the id returned is guaranteed to
    /// be the id of the file that actually finished uploading.
    /// </summary>
    public async Task<Guid> UploadFileAsync(
        Guid conversationId, string fileName, byte[] content, string? contentType,
        IProgress<double>? progress = null, CancellationToken ct = default)
    {
        var (fileId, chunkSize, chunkCount) = await BeginUploadAsync(conversationId, fileName, content, contentType, ct);

        for (long i = 0; i < chunkCount; i++)
        {
            var offset = i * chunkSize;
            var length = (int)Math.Min(chunkSize, content.Length - offset);
            var chunk = new byte[length];
            Array.Copy(content, offset, chunk, 0, length);

            var response = await _http.PutAsync($"/api/files/{fileId}/chunks/{i}", new ByteArrayContent(chunk), ct);
            if (!response.IsSuccessStatusCode)
                throw new MessengerApiException(await ReadErrorAsync(response, ct));

            progress?.Report((i + 1d) / chunkCount);
        }

        var complete = await _http.PostAsync($"/api/files/{fileId}/complete", null, ct);
        if (!complete.IsSuccessStatusCode)
            throw new MessengerApiException(await ReadErrorAsync(complete, ct));

        return fileId;
    }

    public async Task<byte[]> DownloadFileAsync(Guid fileId, CancellationToken ct = default)
    {
        var response = await _http.GetAsync($"/api/files/{fileId}", ct);
        if (!response.IsSuccessStatusCode)
            throw new MessengerApiException(await ReadErrorAsync(response, ct));
        return await response.Content.ReadAsByteArrayAsync(ct);
    }

    public async Task DeleteFileAsync(Guid fileId, CancellationToken ct = default)
    {
        var response = await _http.DeleteAsync($"/api/files/{fileId}", ct);
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
            // Fall through to the generic error below -- an error response that is not
            // itself valid ErrorDto JSON (a proxy's HTML error page, for instance) must not
            // crash the client trying to parse it.
        }

        return new ErrorDto("NET-000", $"Request failed with status {(int)response.StatusCode}.", null);
    }

    public void Dispose() => _http.Dispose();

    private sealed record UploadSlotResponse(Guid FileId, int ChunkSize, long ChunkCount, DateTimeOffset ExpiresAt);
}
