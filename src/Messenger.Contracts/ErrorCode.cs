namespace Messenger.Contracts;

/// <summary>
/// Stable error codes from docs/error-codes.md. Codes are permanent: a code is never
/// reused for a different meaning and never renumbered.
/// </summary>
public static class ErrorCode
{
    // AUTH 1xx — credentials
    public const string InvalidCredentials = "AUTH-101";
    public const string AccountNotFound = "AUTH-102";
    public const string AccountDisabled = "AUTH-103";
    public const string AccountLocked = "AUTH-104";
    public const string PasswordExpired = "AUTH-105";
    public const string PasswordChangeRequired = "AUTH-106";
    public const string PasswordPolicyRejected = "AUTH-107";
    public const string PasswordReuseRejected = "AUTH-108";
    public const string Argon2VerificationError = "AUTH-113";

    // AUTH 2xx — sessions
    public const string SessionExpiredIdle = "AUTH-201";
    public const string SessionExpiredAbsolute = "AUTH-202";
    public const string SessionRevokedByAdmin = "AUTH-203";
    public const string SessionRevokedPasswordChange = "AUTH-204";
    public const string SessionTokenInvalid = "AUTH-205";
    public const string SessionDeviceMismatch = "AUTH-206";
    public const string DeviceBlocked = "AUTH-207";
    public const string ConcurrentSessionLimit = "AUTH-208";

    // AUTH 3xx — authorization
    public const string PermissionDenied = "AUTH-301";
    public const string NotAConversationParticipant = "AUTH-302";
    public const string CrossTierEscalationRefused = "AUTH-303";
    public const string BuiltinRoleImmutable = "AUTH-304";
    public const string LastAdminProtected = "AUTH-305";

    // AUTH 4xx — account state
    public const string UserAlreadyExists = "AUTH-401";
    public const string GroupAlreadyExists = "AUTH-404";
    public const string GroupNotFound = "AUTH-405";
    public const string GroupDisabled = "AUTH-406";
    public const string DirectoryOwnedAttribute = "AUTH-402";
    public const string SelfModificationRefused = "AUTH-403";

    // NET 2xx — protocol
    public const string ProtocolVersionUnsupported = "NET-201";
    public const string MessageTooLarge = "NET-202";
    public const string MalformedRequest = "NET-203";
    public const string RateLimitExceeded = "NET-204";
    public const string SendQueueOverflow = "NET-205";

    // LIC 1xx
    public const string LicenseSignatureInvalid = "LIC-101";
    public const string LicenseExpired = "LIC-102";
    public const string SeatLimitReached = "LIC-103";
    public const string PerUserSessionLimit = "LIC-104";
    public const string TotalSessionLimit = "LIC-105";
    public const string LicenseNotYetValid = "LIC-106";
    public const string FeatureNotLicensed = "LIC-107";
    public const string NoLicenseInstalled = "LIC-108";
    public const string LicenseRevoked = "LIC-109";
    public const string GracePeriodExpired = "LIC-110";
    public const string LicenseMalformed = "LIC-111";

    // AD 1xx — connection and binding
    public const string DirectoryUnreachable = "AD-101";
    public const string LdapsCertificateInvalid = "AD-102";
    public const string DirectoryBindFailed = "AD-103";
    public const string ClockSkewTooLarge = "AD-104";
    public const string ServiceAccountLacksRead = "AD-105";
    public const string ServiceAccountOverPrivileged = "AD-106";
    public const string BaseDnNotFound = "AD-107";
    public const string GmsaRetrievalFailed = "AD-108";
    public const string ReferralChasingRefused = "AD-109";

    // AD 2xx — synchronisation
    public const string SyncFailed = "AD-201";
    public const string SyncPartiallyCompleted = "AD-202";
    public const string DuplicateObjectGuid = "AD-203";
    public const string AttributeMappingError = "AD-204";
    public const string SyncScopeTooLarge = "AD-205";
    public const string InvalidLdapFilter = "AD-206";
    public const string WatermarkLost = "AD-207";
    public const string ObjectRemovedFromDirectory = "AD-208";
    public const string SyncScheduleOverlap = "AD-209";

    // FILE 1xx — upload
    public const string FileTooLarge = "FILE-101";
    public const string FileTypeBlocked = "FILE-102";
    public const string QuotaExceeded = "FILE-103";
    public const string StorageFull = "FILE-104";
    public const string UploadSessionExpired = "FILE-105";
    public const string FileIntegrityCheckFailed = "FILE-106";
    public const string ChunkSequenceError = "FILE-107";
    public const string UploadCancelled = "FILE-108";
    public const string FileNameInvalid = "FILE-109";

    // FILE 2xx — download and scanning
    public const string FileNotFound = "FILE-201";
    public const string FileAccessDenied = "FILE-202";
    public const string ScanInProgress = "FILE-203";
    public const string FileFailedMalwareScan = "FILE-204";
    public const string ScannerUnavailable = "FILE-205";
    public const string FileDecryptionFailed = "FILE-206";
    public const string FileExpired = "FILE-207";
    public const string ChunkManifestMismatch = "FILE-208";

    // SRV 1xx — startup and configuration
    public const string ServiceStartFailed = "SRV-101";
    public const string ConfigurationInvalid = "SRV-102";
    public const string ListenerPortUnavailable = "SRV-103";
    public const string SchemaVersionMismatch = "SRV-104";

    // SRV 2xx — dependencies and runtime
    public const string DatabaseUnreachable = "SRV-201";
    public const string DatabaseAuthFailed = "SRV-202";

    // SRV 3xx — cryptography and data
    public const string KeyStoreUnavailable = "SRV-301";
    public const string KeyUnwrapFailed = "SRV-302";
    public const string KeyRotationFailed = "SRV-303";
    public const string MessageDecryptionFailed = "SRV-304";
    public const string AuditChainVerificationFailed = "SRV-305";
    public const string AuditCheckpointSigningFailed = "SRV-306";
    public const string AuditWriteFailed = "SRV-307";
    public const string ClockAnomalyDetected = "SRV-310";
}

/// <summary>
/// An operation failure carrying a catalogue code. Thrown across service boundaries and
/// mapped to a wire error by the hub/API layer.
/// </summary>
public sealed class MessengerException : Exception
{
    public string Code { get; }

    /// <summary>
    /// Detail intended for operators only. Never sent to an unauthenticated caller —
    /// see the account-enumeration note in docs/error-codes.md.
    /// </summary>
    public string? OperatorDetail { get; }

    public MessengerException(string code, string message, string? operatorDetail = null)
        : base(message)
    {
        Code = code;
        OperatorDetail = operatorDetail;
    }
}
