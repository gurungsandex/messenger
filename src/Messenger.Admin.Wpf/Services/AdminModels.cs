namespace Messenger.Admin.Wpf.Services;

// Mirrors of the wire shapes AdminApi.cs returns. Not shared via an assembly reference to
// Messenger.Server -- that project is an ASP.NET Core host, not a library meant to be linked
// into a client -- so these are hand-kept in sync with src/Messenger.Server/AdminApi.cs.
// LoginRequest/LoginResponse/ErrorDto/ChangePasswordRequest come from Messenger.Contracts
// instead, since those are genuinely shared wire types used by more than one tier.

public sealed record UserSummary(Guid Id, string Username, string DisplayName, string? Email,
    string Source, string Status, DateTimeOffset? LastLoginAt);

public sealed record GroupSummary(Guid Id, string Name, string? Description, string Type,
    string Source, string Status, int MemberCount);

public sealed record SessionSummary(Guid Id, Guid UserId, string Username, string? DeviceName,
    string? IpAddress, string AuthMethod, DateTimeOffset CreatedAt, DateTimeOffset LastActivityAt);

public sealed record AuditEntrySummary(long Id, DateTimeOffset OccurredAt, Guid? ActorUserId,
    string ActorTier, string? ActorIp, string Action, string? TargetType, Guid? TargetId,
    string Outcome, string? DetailJson);

public sealed record CreateUserRequest(string Username, string DisplayName, string? Email, string InitialPassword);
public sealed record SetStatusRequest(string Status);
public sealed record CreateGroupRequest(string Name, string? Description);
public sealed record RenameGroupRequest(string Name);
public sealed record InstallLicenseRequest(string LicenseFile);

public sealed record LicenseStatusResponse(
    string State, string? Code, string? Detail, string? Customer, DateTimeOffset? Expires,
    DateTimeOffset? GraceEndsAt, int SeatsUsed, int SeatsAllowed, int SessionsActive,
    int SessionsAllowed, bool NearSeatLimit, List<string> Features);

public sealed record HealthResponse(
    bool DatabaseReachable, int ActiveSessions, int Users, int Groups, int Messages,
    int PendingDeliveries, string License, DateTimeOffset ServerTime);

public sealed record SyncReportResponse(
    bool Succeeded, int UsersAdded, int UsersUpdated, int UsersDeactivated,
    int GroupsAdded, int GroupsUpdated, int MembershipsChanged, long HighestUsn,
    bool WasFullReconcile, List<string> Errors);

public sealed record AuditVerifyResponse(bool Valid, long? FirstInvalidEntryId, string? Code);
