namespace Messenger.Core;

/// <summary>
/// Permission keys. Strings rather than an enum so a permission can be added without a
/// schema migration, and so a row referencing a removed permission fails closed (an unknown
/// key simply grants nothing) rather than silently shifting to a different value the way a
/// renumbered enum would.
/// </summary>
public static class Permissions
{
    // Users
    public const string UsersRead = "users.read";
    public const string UsersCreate = "users.create";
    public const string UsersUpdate = "users.update";
    public const string UsersSetStatus = "users.set_status";

    // Groups
    public const string GroupsRead = "groups.read";
    public const string GroupsManage = "groups.manage";
    public const string GroupsMembership = "groups.membership";

    // Sessions
    public const string SessionsRead = "sessions.read";
    public const string SessionsRevoke = "sessions.revoke";

    // Audit — deliberately separable from server administration so an organisation can
    // give an auditor read access without also granting user management.
    public const string AuditRead = "audit.read";
    public const string AuditVerify = "audit.verify";

    // Server
    public const string ServerHealth = "server.health";
    public const string ServerSettings = "server.settings";
    public const string DirectorySync = "directory.sync";

    // Licence
    public const string LicenseRead = "license.read";
    public const string LicenseInstall = "license.install";

    // Client
    public const string ChatUse = "chat.use";
    public const string FileTransfer = "file.transfer";

    /// <summary>Owner-tier permissions. Never assignable to a server- or client-scope role.</summary>
    public const string VendorIssueLicense = "vendor.license.issue";
    public const string VendorRevokeLicense = "vendor.license.revoke";
    public const string VendorTelemetry = "vendor.telemetry.read";
    public const string VendorSupportChat = "vendor.support.join";

    public static readonly IReadOnlySet<string> OwnerTierOnly = new HashSet<string>(StringComparer.Ordinal)
    {
        VendorIssueLicense, VendorRevokeLicense, VendorTelemetry, VendorSupportChat,
    };

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
    {
        UsersRead, UsersCreate, UsersUpdate, UsersSetStatus,
        GroupsRead, GroupsManage, GroupsMembership,
        SessionsRead, SessionsRevoke,
        AuditRead, AuditVerify,
        ServerHealth, ServerSettings, DirectorySync,
        LicenseRead, LicenseInstall,
        ChatUse, FileTransfer,
        VendorIssueLicense, VendorRevokeLicense, VendorTelemetry, VendorSupportChat,
    };
}

/// <summary>Names of the seeded roles.</summary>
public static class BuiltInRoles
{
    public const string ServerAdmin = "ServerAdmin";
    public const string UserAdmin = "UserAdmin";
    public const string Auditor = "Auditor";
    public const string HelpDesk = "HelpDesk";
    public const string User = "User";

    /// <summary>
    /// The seed set. `User` deliberately carries no administrative permission at all —
    /// an ordinary account must not be able to read the audit log or manage anyone.
    /// </summary>
    public static readonly IReadOnlyList<(string Name, RoleScope Scope, string Description, string[] Permissions)> Seed =
    [
        (ServerAdmin, RoleScope.Server, "Full server administration.",
        [
            Permissions.UsersRead, Permissions.UsersCreate, Permissions.UsersUpdate, Permissions.UsersSetStatus,
            Permissions.GroupsRead, Permissions.GroupsManage, Permissions.GroupsMembership,
            Permissions.SessionsRead, Permissions.SessionsRevoke,
            Permissions.AuditRead, Permissions.AuditVerify,
            Permissions.ServerHealth, Permissions.ServerSettings, Permissions.DirectorySync,
            Permissions.LicenseRead, Permissions.LicenseInstall,
            Permissions.ChatUse, Permissions.FileTransfer,
        ]),

        (UserAdmin, RoleScope.Server, "Manages users and groups; no server configuration or licence control.",
        [
            Permissions.UsersRead, Permissions.UsersCreate, Permissions.UsersUpdate, Permissions.UsersSetStatus,
            Permissions.GroupsRead, Permissions.GroupsManage, Permissions.GroupsMembership,
            Permissions.SessionsRead,
            Permissions.ChatUse, Permissions.FileTransfer,
        ]),

        // Separation of duties: read the evidence without the ability to change what it
        // records. Deliberately holds no user-management permission.
        (Auditor, RoleScope.Server, "Reads and verifies the audit log. No management rights.",
        [
            Permissions.AuditRead, Permissions.AuditVerify, Permissions.ServerHealth,
            Permissions.UsersRead,
            Permissions.ChatUse, Permissions.FileTransfer,
        ]),

        (HelpDesk, RoleScope.Server, "Views users and sessions and can sign a user out.",
        [
            Permissions.UsersRead, Permissions.GroupsRead,
            Permissions.SessionsRead, Permissions.SessionsRevoke,
            Permissions.ServerHealth,
            Permissions.ChatUse, Permissions.FileTransfer,
        ]),

        (User, RoleScope.Client, "Ordinary end user.",
        [
            Permissions.ChatUse, Permissions.FileTransfer,
        ]),
    ];
}
