using Messenger.Contracts;
using Microsoft.AspNetCore.SignalR.Client;

namespace Messenger.Client.Wpf.Services;

/// <summary>
/// Wraps the SignalR connection to <c>/hubs/chat</c>. The connect/header setup and every hub
/// method invoked here were proven working end to end earlier in this project's development
/// against the real, running server (open a direct conversation, send both directions, fetch
/// history) -- this class is that same shape wrapped for MVVM consumption instead of a
/// console script.
/// </summary>
public sealed class ChatHubClient : IAsyncDisposable
{
    private readonly HubConnection _connection;

    public event Action<MessageDto>? MessageReceived;
    public event Action<ReceiptDto>? ReceiptReceived;
    public event Action<PresenceDto>? PresenceChanged;
    public event Action<Exception?>? Closed;

    public ChatHubClient(string baseUrl, string sessionToken, string deviceFingerprint)
    {
        _connection = new HubConnectionBuilder()
            .WithUrl($"{baseUrl.TrimEnd('/')}/hubs/chat", options =>
            {
                options.Headers["X-Session-Token"] = sessionToken;
                options.Headers["X-Device-Fingerprint"] = deviceFingerprint;
            })
            .WithAutomaticReconnect()
            .Build();

        _connection.On<MessageDto>("OnMessage", m => MessageReceived?.Invoke(m));
        _connection.On<ReceiptDto>("OnReceipt", r => ReceiptReceived?.Invoke(r));
        _connection.On<PresenceDto>("OnPresence", p => PresenceChanged?.Invoke(p));
        _connection.Closed += ex => { Closed?.Invoke(ex); return Task.CompletedTask; };
    }

    public Task ConnectAsync(CancellationToken ct = default) => _connection.StartAsync(ct);

    public Task<Guid> OpenDirectConversationAsync(Guid otherUserId, CancellationToken ct = default)
        => _connection.InvokeAsync<Guid>("OpenDirectConversation", otherUserId, ct);

    public Task<SendMessageAck> SendMessageAsync(Guid conversationId, string body, CancellationToken ct = default)
        => _connection.InvokeAsync<SendMessageAck>("SendMessage",
            new SendMessageRequest(conversationId, Guid.NewGuid(), body, DateTimeOffset.UtcNow), ct);

    public Task<IReadOnlyList<MessageDto>> GetHistoryAsync(
        Guid conversationId, long afterSeq = 0, int limit = 50, CancellationToken ct = default)
        => _connection.InvokeAsync<IReadOnlyList<MessageDto>>("GetHistory", conversationId, afterSeq, limit, ct);

    public Task AcknowledgeDeliveryAsync(Guid messageId, CancellationToken ct = default)
        => _connection.InvokeAsync("AcknowledgeDelivery", messageId, ct);

    public Task AcknowledgeReadAsync(Guid messageId, CancellationToken ct = default)
        => _connection.InvokeAsync("AcknowledgeRead", messageId, ct);

    public Task SetPresenceAsync(PresenceStatus status, string? statusMessage, bool isAutoAway, CancellationToken ct = default)
        => _connection.InvokeAsync("SetPresence", status, statusMessage, isAutoAway, ct);

    public async ValueTask DisposeAsync() => await _connection.DisposeAsync();
}
