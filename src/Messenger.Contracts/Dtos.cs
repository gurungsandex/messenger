namespace Messenger.Contracts;

public enum PresenceStatus { Offline = 0, Online = 1, Busy = 2, Away = 3 }

public enum DeliveryState { Pending = 0, Delivered = 1, Read = 2 }

public enum ConversationType { Direct = 0, Group = 1 }

public enum AuthMethod { Password = 0, Kerberos = 1, Ntlm = 2 }

public sealed record LoginRequest(
    string Username,
    string Password,
    string DeviceFingerprint,
    string? DeviceName);

public sealed record ChangePasswordRequest(string CurrentPassword, string NewPassword);

public sealed record LoginResponse(
    string SessionToken,
    Guid UserId,
    string DisplayName,
    DateTimeOffset ExpiresAt,
    int IdleTimeoutSeconds,
    bool MustChangePassword);

/// <summary>
/// Client-to-server send. <see cref="ClientMessageId"/> is the idempotency key: a retry
/// carrying the same value returns the original ack rather than creating a duplicate.
/// </summary>
public sealed record SendMessageRequest(
    Guid ConversationId,
    Guid ClientMessageId,
    string Body,
    DateTimeOffset SentAt);

/// <summary>
/// Server ack. Its arrival means the message is durably persisted, not merely received.
/// </summary>
public sealed record SendMessageAck(
    Guid MessageId,
    Guid ClientMessageId,
    long Seq,
    DateTimeOffset ServerReceivedAt);

public sealed record MessageDto(
    Guid MessageId,
    Guid ConversationId,
    long Seq,
    Guid SenderId,
    string SenderDisplayName,
    string Body,
    DateTimeOffset SentAt,
    DateTimeOffset ServerReceivedAt,
    bool IsDeleted);

public sealed record ConversationDto(
    Guid ConversationId,
    ConversationType Type,
    string Title,
    long LastSeq,
    long LastReadSeq,
    DateTimeOffset? LastMessageAt);

public sealed record ReceiptDto(
    Guid MessageId,
    Guid UserId,
    DeliveryState State,
    DateTimeOffset At);

public sealed record PresenceDto(
    Guid UserId,
    PresenceStatus Status,
    string? StatusMessage,
    bool IsAutoAway,
    DateTimeOffset ChangedAt);

public sealed record ErrorDto(string Code, string Message, string? CorrelationId);

/// <summary>
/// A directory entry visible to any authenticated user for the purpose of starting a direct
/// conversation. Deliberately minimal -- no email, role, or status -- since this is reachable
/// by any signed-in user, not just admins.
/// </summary>
public sealed record UserDirectoryEntryDto(Guid UserId, string Username, string DisplayName);

/// <summary>Server-to-client hub calls. Implemented by the client, invoked by the server.</summary>
public interface IChatClient
{
    Task OnMessage(MessageDto message);
    Task OnReceipt(ReceiptDto receipt);
    Task OnPresence(PresenceDto presence);
    Task OnError(ErrorDto error);
}
