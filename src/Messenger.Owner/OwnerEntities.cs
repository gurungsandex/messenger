namespace Messenger.Owner;

/// <summary>
/// A vendor staff account. Deliberately separate from <c>Messenger.Core.User</c>: an owner
/// operator manages many customer deployments and must never live in any one customer's
/// database, which is the whole reason this is its own project with its own store.
/// </summary>
public sealed class OwnerOperator
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Username { get; set; } = null!;
    public string DisplayName { get; set; } = null!;
    public string PasswordHash { get; set; } = null!;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class OwnerSession
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid OperatorId { get; set; }
    public byte[] TokenHash { get; set; } = null!;
    public string DeviceFingerprint { get; set; } = null!;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset LastActivityAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
}

/// <summary>
/// A licence this vendor has issued, kept for tracking. This is a record of issuance, not
/// the source of truth for validity -- validation is offline and happens entirely on the
/// customer's server against the signature alone, per <c>Messenger.Licensing</c>'s design.
/// Marking a row revoked here stops it showing as active in this console; it cannot reach
/// out and invalidate a file already handed to a customer.
/// </summary>
public sealed class CustomerLicenseRecord
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string LicenseId { get; set; } = null!;
    public string Customer { get; set; } = null!;
    public string RawDocument { get; set; } = null!;
    public DateTimeOffset IssuedAt { get; set; }
    public DateTimeOffset NotBefore { get; set; }
    public DateTimeOffset NotAfter { get; set; }
    public Guid IssuedBy { get; set; }
    public bool Revoked { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
}

/// <summary>
/// A heartbeat/usage event posted by a customer's server. Ingest is unauthenticated by
/// design -- see <c>docs/architecture.md</c>'s outbound-only telemetry path -- so a customer
/// identifies itself by its licence id rather than a vendor-issued credential.
/// </summary>
public sealed class TelemetryEvent
{
    public long Id { get; set; }
    public string LicenseId { get; set; } = null!;
    public string EventType { get; set; } = null!;
    public string? PayloadJson { get; set; }
    public DateTimeOffset ReceivedAt { get; set; } = DateTimeOffset.UtcNow;
}

/// <summary>One message in a support conversation between a customer's admin console and a vendor operator.</summary>
public sealed class SupportMessage
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string CustomerLicenseId { get; set; } = null!;
    public Guid SenderId { get; set; }
    public bool SenderIsOperator { get; set; }
    public string Body { get; set; } = null!;
    public DateTimeOffset SentAt { get; set; } = DateTimeOffset.UtcNow;
}
