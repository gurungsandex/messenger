using System.Collections.Concurrent;
using Messenger.Contracts;
using Messenger.Data;
using Microsoft.AspNetCore.SignalR;

namespace Messenger.Server;

/// <summary>
/// Tracks which connections belong to which user. In-process by design for v1 (ADR-0003);
/// the interface is the seam a Redis-backed registry would slot into for HA.
/// </summary>
public interface IConnectionRegistry
{
    void Add(Guid userId, string connectionId);
    void Remove(string connectionId);
    IReadOnlyCollection<string> ConnectionsFor(Guid userId);
    bool IsOnline(Guid userId);
}

public sealed class InMemoryConnectionRegistry : IConnectionRegistry
{
    private readonly ConcurrentDictionary<Guid, HashSet<string>> _byUser = new();
    private readonly ConcurrentDictionary<string, Guid> _byConnection = new();

    public void Add(Guid userId, string connectionId)
    {
        _byConnection[connectionId] = userId;
        var set = _byUser.GetOrAdd(userId, _ => []);
        lock (set) set.Add(connectionId);
    }

    public void Remove(string connectionId)
    {
        if (!_byConnection.TryRemove(connectionId, out var userId)) return;
        if (!_byUser.TryGetValue(userId, out var set)) return;

        lock (set)
        {
            set.Remove(connectionId);
            if (set.Count == 0) _byUser.TryRemove(userId, out _);
        }
    }

    public IReadOnlyCollection<string> ConnectionsFor(Guid userId)
    {
        if (!_byUser.TryGetValue(userId, out var set)) return [];
        lock (set) return set.ToArray();
    }

    public bool IsOnline(Guid userId) => _byUser.ContainsKey(userId);
}

/// <summary>
/// Real-time chat surface. Every method re-authorises against the session registry and
/// re-checks conversation membership server-side; a connection id is not a capability.
/// </summary>
public sealed class ChatHub(
    SessionService sessions,
    MessageService messages,
    PresenceService presence,
    IConnectionRegistry registry,
    ILogger<ChatHub> logger) : Hub<IChatClient>
{
    private const string SessionTokenHeader = "X-Session-Token";
    private const string DeviceHeader = "X-Device-Fingerprint";

    public override async Task OnConnectedAsync()
    {
        var session = await AuthenticateAsync();
        if (session is null)
        {
            Context.Abort();
            return;
        }

        registry.Add(session.UserId, Context.ConnectionId);
        await presence.SetStatusAsync(session.UserId, PresenceStatus.Online, null, false);

        // Deliver anything queued while the user was away. This is the whole of
        // store-and-forward from the client's side: reconnect and the gap arrives.
        var backlog = await messages.GetPendingBacklogAsync(session.UserId);
        foreach (var message in backlog)
            await Clients.Caller.OnMessage(message);

        await base.OnConnectedAsync();
    }

    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        var userId = CurrentUserId;
        registry.Remove(Context.ConnectionId);

        if (userId is { } id && !registry.IsOnline(id))
            await presence.SetStatusAsync(id, PresenceStatus.Offline, null, false);

        await base.OnDisconnectedAsync(exception);
    }

    public async Task<SendMessageAck> SendMessage(SendMessageRequest request)
    {
        var session = await RequireSessionAsync();
        var ack = await messages.SendAsync(session.UserId, request);

        var participants = await messages.GetParticipantIdsAsync(request.ConversationId);
        var history = await messages.GetHistoryAsync(session.UserId, request.ConversationId, ack.Seq - 1, 1);
        if (history.Count == 0) return ack;

        var dto = history[0];
        foreach (var participantId in participants.Where(p => p != session.UserId))
        {
            var connections = registry.ConnectionsFor(participantId);
            if (connections.Count == 0) continue; // stays pending; delivered on next login
            await Clients.Clients(connections).OnMessage(dto);
        }

        return ack;
    }

    public async Task<Guid> OpenDirectConversation(Guid otherUserId)
    {
        var session = await RequireSessionAsync();
        var conversation = await messages.GetOrCreateDirectConversationAsync(session.UserId, otherUserId);
        return conversation.Id;
    }

    public async Task<IReadOnlyList<MessageDto>> GetHistory(Guid conversationId, long afterSeq, int limit)
    {
        var session = await RequireSessionAsync();
        return await messages.GetHistoryAsync(session.UserId, conversationId, afterSeq, limit);
    }

    public async Task AcknowledgeDelivery(Guid messageId)
    {
        var session = await RequireSessionAsync();
        if (!await messages.MarkDeliveredAsync(session.UserId, messageId)) return;

        await NotifySenderAsync(messageId, session.UserId, DeliveryState.Delivered);
    }

    public async Task AcknowledgeRead(Guid messageId)
    {
        var session = await RequireSessionAsync();
        var receiptRecorded = await messages.MarkReadAsync(session.UserId, messageId, presence.ReadReceiptsEnabled);
        if (!receiptRecorded) return;

        await NotifySenderAsync(messageId, session.UserId, DeliveryState.Read);
    }

    public async Task SetPresence(PresenceStatus status, string? statusMessage, bool isAutoAway)
    {
        var session = await RequireSessionAsync();
        var updated = await presence.SetStatusAsync(session.UserId, status, statusMessage, isAutoAway);

        // Presence is broadcast only to users sharing a conversation, not directory-wide —
        // both to bound fan-out and because presence is itself sensitive metadata.
        foreach (var peerId in await presence.GetVisibleToAsync(session.UserId))
        {
            var connections = registry.ConnectionsFor(peerId);
            if (connections.Count > 0) await Clients.Clients(connections).OnPresence(updated);
        }
    }

    private async Task NotifySenderAsync(Guid messageId, Guid actorId, DeliveryState state)
    {
        var senderId = await messages.GetSenderIdAsync(messageId);
        if (senderId is not { } sender) return;

        var connections = registry.ConnectionsFor(sender);
        if (connections.Count == 0) return;

        await Clients.Clients(connections)
            .OnReceipt(new ReceiptDto(messageId, actorId, state, DateTimeOffset.UtcNow));
    }

    private Guid? CurrentUserId
        => Context.Items.TryGetValue("UserId", out var value) && value is Guid id ? id : null;

    private async Task<Core.Session?> AuthenticateAsync()
    {
        var http = Context.GetHttpContext();
        var token = http?.Request.Headers[SessionTokenHeader].FirstOrDefault()
                    ?? http?.Request.Query["access_token"].FirstOrDefault();
        var device = http?.Request.Headers[DeviceHeader].FirstOrDefault();

        if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(device)) return null;

        var validation = await sessions.ValidateAsync(token, device, SessionPolicy.Default);
        if (!validation.IsValid || validation.Session is null)
        {
            logger.LogInformation("Hub authentication refused: {Code}", validation.ErrorCode);
            return null;
        }

        Context.Items["UserId"] = validation.Session.UserId;
        return validation.Session;
    }

    /// <summary>
    /// Re-validates on every call rather than trusting the connection. Revocation must take
    /// effect immediately, and a long-lived socket established before a revocation would
    /// otherwise keep working until it happened to drop.
    /// </summary>
    private async Task<Core.Session> RequireSessionAsync()
    {
        var session = await AuthenticateAsync();
        if (session is null)
        {
            Context.Abort();
            throw new HubException(ErrorCode.SessionTokenInvalid);
        }
        return session;
    }
}
