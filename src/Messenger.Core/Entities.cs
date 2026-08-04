using Messenger.Contracts;

namespace Messenger.Core;

public enum UserStatus { Active = 0, Disabled = 1, Locked = 2 }

public enum UserSource { Local = 0, ActiveDirectory = 1 }

public class User
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Username { get; set; } = null!;
    public UserSource Source { get; set; } = UserSource.Local;
    public Guid? AdObjectGuid { get; set; }
    public string? AdDn { get; set; }
    public string DisplayName { get; set; } = null!;
    public string? Email { get; set; }

    /// <summary>PHC-format Argon2id hash. Null for AD-sourced users, who never hold a local password.</summary>
    public string? PasswordHash { get; set; }
    public DateTimeOffset? PasswordUpdatedAt { get; set; }
    public bool MustChangePassword { get; set; }

    public UserStatus Status { get; set; } = UserStatus.Active;
    public int FailedLoginCount { get; set; }

    /// <summary>Soft backoff, not a hard lockout — a hard lockout is a free account-DoS for an attacker.</summary>
    public DateTimeOffset? LockoutUntil { get; set; }
    public DateTimeOffset? LastLoginAt { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? DeletedAt { get; set; }

    public ICollection<Session> Sessions { get; set; } = [];
    public ICollection<ConversationParticipant> Participations { get; set; } = [];
}

public class Conversation
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public ConversationType Type { get; set; }

    /// <summary>
    /// Sorted "smallerGuid:largerGuid" for direct conversations, null for groups. The unique
    /// index on this column is what makes "open a chat with Bob" idempotent under concurrency
    /// — two clients racing cannot produce two rows.
    /// </summary>
    public string? DirectKey { get; set; }

    public string? Title { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public Guid? CreatedBy { get; set; }
    public DateTimeOffset? LastMessageAt { get; set; }

    /// <summary>Sequence allocator, advanced inside the message-insert transaction.</summary>
    public long NextSeq { get; set; } = 1;

    public ICollection<ConversationParticipant> Participants { get; set; } = [];
    public ICollection<Message> Messages { get; set; } = [];
    public ICollection<ConversationKey> Keys { get; set; } = [];

    public static string BuildDirectKey(Guid a, Guid b)
        => a.CompareTo(b) <= 0 ? $"{a:D}:{b:D}" : $"{b:D}:{a:D}";
}

public class ConversationParticipant
{
    public Guid ConversationId { get; set; }
    public Conversation Conversation { get; set; } = null!;
    public Guid UserId { get; set; }
    public User User { get; set; } = null!;

    public DateTimeOffset JoinedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? LeftAt { get; set; }
    public long LastReadSeq { get; set; }
    public bool IsMuted { get; set; }
}

public class Message
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ConversationId { get; set; }
    public Conversation Conversation { get; set; } = null!;
    public long Seq { get; set; }
    public Guid SenderId { get; set; }

    /// <summary>Client-supplied idempotency key; unique per (conversation, sender).</summary>
    public Guid ClientMessageId { get; set; }

    public byte[] Ciphertext { get; set; } = null!;
    public byte[] Nonce { get; set; } = null!;
    public byte[] AuthTag { get; set; } = null!;
    public Guid KeyId { get; set; }
    public short AadVersion { get; set; }

    /// <summary>Client-claimed send time. Display only — never trusted for ordering.</summary>
    public DateTimeOffset SentAt { get; set; }

    /// <summary>Authoritative for ordering and retention.</summary>
    public DateTimeOffset ServerReceivedAt { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? EditedAt { get; set; }
    public DateTimeOffset? DeletedAt { get; set; }

    public ICollection<MessageRecipient> Recipients { get; set; } = [];
}

public class MessageRecipient
{
    public Guid MessageId { get; set; }
    public Message Message { get; set; } = null!;
    public Guid UserId { get; set; }
    public DeliveryState State { get; set; } = DeliveryState.Pending;
    public DateTimeOffset? DeliveredAt { get; set; }
    public DateTimeOffset? ReadAt { get; set; }
}

public class ConversationKey
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ConversationId { get; set; }
    public Conversation Conversation { get; set; } = null!;
    public int Version { get; set; }
    public byte[] WrappedDek { get; set; } = null!;
    public string KekId { get; set; } = null!;
    public string Algorithm { get; set; } = "AES-256-GCM";
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? RetiredAt { get; set; }

    /// <summary>Drives rotation: random 96-bit nonces have a birthday bound, so keys rotate at 2^24.</summary>
    public long MessageCount { get; set; }
}

public class Session
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public User User { get; set; } = null!;

    /// <summary>SHA-256 of the bearer token. The token itself is never stored.</summary>
    public byte[] TokenHash { get; set; } = null!;

    public string DeviceFingerprint { get; set; } = null!;
    public string? DeviceName { get; set; }
    public string? IpAddress { get; set; }
    public AuthMethod AuthMethod { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset LastActivityAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public string? RevokeReason { get; set; }
}

public class Presence
{
    public Guid UserId { get; set; }
    public PresenceStatus Status { get; set; } = PresenceStatus.Offline;
    public string? StatusMessage { get; set; }
    public bool IsAutoAway { get; set; }
    public DateTimeOffset ChangedAt { get; set; } = DateTimeOffset.UtcNow;
}

public class AuditLogEntry
{
    public long Id { get; set; }
    public DateTimeOffset OccurredAt { get; set; } = DateTimeOffset.UtcNow;
    public Guid? ActorUserId { get; set; }
    public string ActorTier { get; set; } = "system";
    public string? ActorIp { get; set; }
    public string Action { get; set; } = null!;
    public string? TargetType { get; set; }
    public Guid? TargetId { get; set; }
    public string Outcome { get; set; } = "success";

    /// <summary>Structured context. Never contains message content.</summary>
    public string? DetailJson { get; set; }

    public byte[] PrevHash { get; set; } = null!;
    public byte[] EntryHash { get; set; } = null!;
}

public class AuditCheckpoint
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public long UpToAuditId { get; set; }
    public byte[] HeadHash { get; set; } = null!;
    public byte[] Signature { get; set; } = null!;
    public string SigningKeyId { get; set; } = null!;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? AnchoredAt { get; set; }
    public string? AnchorReference { get; set; }
}

public class ServerSetting
{
    public string Key { get; set; } = null!;
    public string Value { get; set; } = null!;
    public bool IsSecret { get; set; }
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}
