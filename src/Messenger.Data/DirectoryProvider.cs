using Messenger.Contracts;

namespace Messenger.Data;

/// <summary>A user object as read from the directory.</summary>
public sealed record DirectoryUser(
    Guid ObjectGuid,
    string DistinguishedName,
    string SamAccountName,
    string? UserPrincipalName,
    string DisplayName,
    string? Email,
    string? Title,
    string? Department,
    bool IsEnabled,
    long UsnChanged);

public sealed record DirectoryGroup(
    Guid ObjectGuid,
    string DistinguishedName,
    string Name,
    string? Description,
    IReadOnlyList<Guid> MemberObjectGuids,
    long UsnChanged);

public sealed record DirectoryOrgUnit(
    Guid ObjectGuid,
    string DistinguishedName,
    string Name,
    Guid? ParentObjectGuid);

public sealed record DirectoryDelta(
    IReadOnlyList<DirectoryUser> Users,
    IReadOnlyList<DirectoryGroup> Groups,
    IReadOnlyList<DirectoryOrgUnit> OrgUnits,
    /// <summary>
    /// The directory's own highest committed USN, read from rootDSE
    /// (<c>highestCommittedUSN</c>) — <b>not</b> the maximum over the returned objects.
    ///
    /// The distinction is what makes watermark loss detectable. Derived from the returned
    /// objects, an empty delta reports back whatever was asked for, so a stored watermark
    /// far ahead of a restored directory looks indistinguishable from "nothing changed".
    /// </summary>
    long HighestUsn);

/// <summary>
/// Directory access, abstracted away from LDAP so synchronisation logic is unit-testable
/// without a domain controller.
///
/// This matters beyond convenience: the reconciliation rules — what happens to a user who
/// vanishes, how a rename is distinguished from a new account, how a watermark reset is
/// handled — are where the real defects live, and they cannot be exercised against a live
/// domain in CI.
/// </summary>
public interface IDirectoryProvider
{
    /// <summary>
    /// Objects changed since <paramref name="sinceUsn"/>. Passing 0 requests a full read.
    ///
    /// AD's <c>uSNChanged</c> is per-domain-controller and is not preserved across a restore
    /// from backup, which is why <see cref="DirectorySyncService"/> falls back to a full
    /// reconcile when the watermark looks impossible.
    /// </summary>
    Task<DirectoryDelta> GetChangesAsync(long sinceUsn, CancellationToken ct = default);

    /// <summary>Validates connectivity and the service account's rights before a sync is scheduled.</summary>
    Task<DirectoryProbeResult> ProbeAsync(CancellationToken ct = default);
}

public sealed record DirectoryProbeResult(
    bool CanConnect,
    bool CanRead,
    bool HasWriteAccess,
    string? FailureCode,
    string? Detail)
{
    /// <summary>
    /// Write access is reported as a warning rather than a failure. The product never writes
    /// to the directory, so an over-privileged service account is a finding to surface
    /// (AD-106), not a reason to refuse to run.
    /// </summary>
    public bool IsUsable => CanConnect && CanRead;
}

/// <summary>
/// Escaping helpers for LDAP. Filter values are escaped per RFC 4515 and DN components per
/// RFC 4514.
///
/// LDAP injection is under-appreciated: a user-controlled attribute concatenated into a
/// filter can widen a query's scope — turning a lookup for one account into a match for
/// every account. Filters are therefore always built through this, never by concatenation.
/// </summary>
public static class LdapEscape
{
    public static string Filter(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var sb = new System.Text.StringBuilder(value.Length + 8);
        foreach (var c in value)
        {
            switch (c)
            {
                case '\\': sb.Append("\\5c"); break;
                case '*': sb.Append("\\2a"); break;
                case '(': sb.Append("\\28"); break;
                case ')': sb.Append("\\29"); break;
                case '\0': sb.Append("\\00"); break;
                case '/': sb.Append("\\2f"); break;
                default:
                    // Non-ASCII and control characters are hex-escaped byte by byte.
                    if (c < 0x20 || c > 0x7E)
                    {
                        foreach (var b in System.Text.Encoding.UTF8.GetBytes(c.ToString()))
                            sb.Append('\\').Append(b.ToString("x2"));
                    }
                    else sb.Append(c);
                    break;
            }
        }
        return sb.ToString();
    }

    public static string DistinguishedName(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var sb = new System.Text.StringBuilder(value.Length + 8);
        for (int i = 0; i < value.Length; i++)
        {
            var c = value[i];
            var atEdge = i == 0 || i == value.Length - 1;

            if (c is ',' or '+' or '"' or '\\' or '<' or '>' or ';' or '=')
                sb.Append('\\').Append(c);
            else if (c == ' ' && atEdge)
                sb.Append("\\ ");
            else if (c == '#' && i == 0)
                sb.Append("\\#");
            else if (c == '\0')
                sb.Append("\\00");
            else
                sb.Append(c);
        }
        return sb.ToString();
    }

    /// <summary>Builds a filter matching a single account by sAMAccountName, safely.</summary>
    public static string UserBySamAccountName(string samAccountName)
        => $"(&(objectClass=user)(objectCategory=person)(sAMAccountName={Filter(samAccountName)}))";
}

/// <summary>
/// The default registration where no LDAPS connection has been configured.
///
/// <b>The LDAPS wire implementation is not yet written.</b> Phase 4 delivered the
/// synchronisation engine, the reconciliation rules, and RFC-compliant escaping — all
/// tested against <see cref="FakeDirectoryProvider"/> — but the actual
/// <c>System.DirectoryServices.Protocols</c> binding still has to be built and verified
/// against a real domain controller.
///
/// This type exists so that gap fails loudly and specifically at the point of use, rather
/// than as a dependency-injection error at startup or, worse, a silent no-op sync that an
/// administrator mistakes for success.
/// </summary>
public sealed class UnconfiguredDirectoryProvider : IDirectoryProvider
{
    private const string NotConfigured =
        "No directory connection is configured. The LDAPS provider is not yet implemented; "
        + "see docs/deployment.md for the current status of Active Directory integration.";

    public Task<DirectoryDelta> GetChangesAsync(long sinceUsn, CancellationToken ct = default)
        => throw new MessengerException(ErrorCode.DirectoryUnreachable, NotConfigured);

    public Task<DirectoryProbeResult> ProbeAsync(CancellationToken ct = default)
        => Task.FromResult(new DirectoryProbeResult(
            CanConnect: false, CanRead: false, HasWriteAccess: false,
            FailureCode: ErrorCode.DirectoryUnreachable, Detail: NotConfigured));
}

/// <summary>
/// Scripted directory provider used by the sync tests. Real LDAPS lives behind the same
/// interface; see the deployment guide for the service-account requirements.
/// </summary>
public sealed class FakeDirectoryProvider : IDirectoryProvider
{
    public List<DirectoryUser> Users { get; } = [];
    public List<DirectoryGroup> Groups { get; } = [];
    public List<DirectoryOrgUnit> OrgUnits { get; } = [];
    public DirectoryProbeResult Probe { get; set; } = new(true, true, false, null, null);
    public Exception? FailWith { get; set; }

    public Task<DirectoryDelta> GetChangesAsync(long sinceUsn, CancellationToken ct = default)
    {
        if (FailWith is not null) throw FailWith;

        var users = Users.Where(u => u.UsnChanged > sinceUsn).ToList();
        var groups = Groups.Where(g => g.UsnChanged > sinceUsn).ToList();

        // Mirrors rootDSE highestCommittedUSN: computed over everything the directory
        // holds, independent of what this query returned.
        var highestCommitted = Math.Max(
            Users.Count == 0 ? 0 : Users.Max(u => u.UsnChanged),
            Groups.Count == 0 ? 0 : Groups.Max(g => g.UsnChanged));

        return Task.FromResult(new DirectoryDelta(users, groups, OrgUnits, highestCommitted));
    }

    public Task<DirectoryProbeResult> ProbeAsync(CancellationToken ct = default) => Task.FromResult(Probe);
}
