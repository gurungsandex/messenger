using Messenger.Contracts;
using Messenger.Core;
using Microsoft.EntityFrameworkCore;

namespace Messenger.Data;

public sealed record SyncReport(
    bool Succeeded,
    int UsersAdded,
    int UsersUpdated,
    int UsersDeactivated,
    int GroupsAdded,
    int GroupsUpdated,
    int MembershipsChanged,
    long HighestUsn,
    bool WasFullReconcile,
    IReadOnlyList<string> Errors);

public sealed record SyncOptions(
    /// <summary>Refuses a run whose result set exceeds this, so an over-broad filter cannot import a forest by accident (AD-205).</summary>
    int MaxObjectsPerRun = 50_000,
    /// <summary>Interval at which a full reconcile runs regardless of watermark, to catch tombstoned objects an incremental pass misses.</summary>
    TimeSpan? FullReconcileInterval = null)
{
    public static readonly SyncOptions Default = new();
    public TimeSpan ReconcileInterval => FullReconcileInterval ?? TimeSpan.FromDays(1);
}

/// <summary>
/// Imports users, groups, and OUs from the directory and keeps them in step.
///
/// Two rules shape everything here:
///
/// 1. <b>objectGUID is the only stable identity.</b> Names, DNs, UPNs, and sAMAccountNames
///    all change. Matching on any of them turns a rename or an OU move into a duplicate
///    account, orphaning the user's message history.
///
/// 2. <b>Disappearance is never destructive.</b> An object that vanishes from the directory
///    deactivates its local user rather than deleting it. A mis-scoped filter, a replication
///    hiccup, or an admin moving an OU must not be able to erase message history and audit
///    trail. Purging is a separate, explicit action.
/// </summary>
public sealed class DirectorySyncService(
    MessengerDbContext db,
    IDirectoryProvider directory,
    AuditService audit,
    TimeProvider? timeProvider = null)
{
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    public async Task<SyncReport> SyncAsync(
        long sinceUsn = 0, SyncOptions? options = null, bool forceFullReconcile = false,
        CancellationToken ct = default)
    {
        options ??= SyncOptions.Default;
        var errors = new List<string>();

        var probe = await directory.ProbeAsync(ct);
        if (!probe.IsUsable)
        {
            var code = probe.FailureCode ?? ErrorCode.DirectoryUnreachable;
            await audit.AppendAsync("directory.sync", "error", null, "system", null, null, null,
                $"{{\"code\":\"{code}\"}}", ct);
            throw new MessengerException(code, probe.Detail ?? "The directory is not usable for synchronisation.");
        }

        if (probe.HasWriteAccess)
        {
            // Not a failure: the product never writes to the directory, so this is a
            // least-privilege finding to surface rather than a reason to refuse to run.
            errors.Add($"{ErrorCode.ServiceAccountOverPrivileged}: the bind account has write access; read-only is sufficient.");
        }

        var fullReconcile = forceFullReconcile || sinceUsn <= 0;
        var effectiveSince = fullReconcile ? 0 : sinceUsn;

        DirectoryDelta delta;
        try
        {
            delta = await directory.GetChangesAsync(effectiveSince, ct);
        }
        catch (MessengerException)
        {
            throw;
        }
        catch (Exception ex)
        {
            await audit.AppendAsync("directory.sync", "error", null, "system", null, null, null,
                $"{{\"code\":\"{ErrorCode.SyncFailed}\"}}", ct);
            throw new MessengerException(ErrorCode.SyncFailed, "Directory synchronisation failed.", ex.Message);
        }

        // A watermark ahead of the directory's own highest USN means the DC was restored
        // from backup or replaced. Continuing incrementally would silently skip everything
        // between; a full reconcile is the only correct response (AD-207).
        if (!fullReconcile && delta.HighestUsn < sinceUsn)
        {
            errors.Add($"{ErrorCode.WatermarkLost}: the directory watermark moved backwards; running a full reconcile.");
            fullReconcile = true;
            delta = await directory.GetChangesAsync(0, ct);
        }

        var total = delta.Users.Count + delta.Groups.Count + delta.OrgUnits.Count;
        if (total > options.MaxObjectsPerRun)
        {
            throw new MessengerException(ErrorCode.SyncScopeTooLarge,
                $"The sync returned {total:N0} objects, above the {options.MaxObjectsPerRun:N0} safety cap. Narrow the base DN or filter.");
        }

        var usersAdded = 0;
        var usersUpdated = 0;
        var usersDeactivated = 0;
        var groupsAdded = 0;
        var groupsUpdated = 0;
        var membershipsChanged = 0;

        var now = _time.GetUtcNow();

        foreach (var ou in delta.OrgUnits)
        {
            var existing = await db.OrgUnits.FirstOrDefaultAsync(o => o.AdObjectGuid == ou.ObjectGuid, ct);
            if (existing is null)
            {
                db.OrgUnits.Add(new OrgUnit
                {
                    Name = ou.Name,
                    DistinguishedName = ou.DistinguishedName,
                    Source = UserSource.ActiveDirectory,
                    AdObjectGuid = ou.ObjectGuid,
                    CreatedAt = now,
                });
            }
            else
            {
                existing.Name = ou.Name;
                existing.DistinguishedName = ou.DistinguishedName;
                existing.DeletedAt = null;
            }
        }
        await db.SaveChangesAsync(ct);

        foreach (var dirUser in delta.Users)
        {
            if (string.IsNullOrWhiteSpace(dirUser.DisplayName) || string.IsNullOrWhiteSpace(dirUser.SamAccountName))
            {
                // Skipping beats importing a blank identity that nobody can recognise.
                errors.Add($"{ErrorCode.AttributeMappingError}: {dirUser.DistinguishedName} is missing a display name or account name; skipped.");
                continue;
            }

            var user = await db.Users.FirstOrDefaultAsync(u => u.AdObjectGuid == dirUser.ObjectGuid, ct);

            if (user is null)
            {
                // A local account may already hold this username. Matching it by name would
                // silently hand directory control of an unrelated account, so it is a
                // conflict to report rather than a merge to perform.
                var nameClash = await db.Users.AnyAsync(
                    u => u.Username == dirUser.SamAccountName && u.DeletedAt == null, ct);
                if (nameClash)
                {
                    errors.Add($"{ErrorCode.UserAlreadyExists}: a local account named '{dirUser.SamAccountName}' already exists; {dirUser.DistinguishedName} was skipped.");
                    continue;
                }

                db.Users.Add(new User
                {
                    Username = dirUser.SamAccountName,
                    Source = UserSource.ActiveDirectory,
                    AdObjectGuid = dirUser.ObjectGuid,
                    AdDn = dirUser.DistinguishedName,
                    DisplayName = dirUser.DisplayName,
                    Email = dirUser.Email,
                    Status = dirUser.IsEnabled ? UserStatus.Active : UserStatus.Disabled,
                    CreatedAt = now,
                });
                usersAdded++;
            }
            else
            {
                // Matched on objectGUID, so a rename or OU move updates in place rather than
                // creating a duplicate and orphaning history.
                user.Username = dirUser.SamAccountName;
                user.AdDn = dirUser.DistinguishedName;
                user.DisplayName = dirUser.DisplayName;
                user.Email = dirUser.Email;
                user.Status = dirUser.IsEnabled ? UserStatus.Active : UserStatus.Disabled;
                user.DeletedAt = null;
                usersUpdated++;
            }
        }
        await db.SaveChangesAsync(ct);

        foreach (var dirGroup in delta.Groups)
        {
            var group = await db.Groups.FirstOrDefaultAsync(g => g.AdObjectGuid == dirGroup.ObjectGuid, ct);
            if (group is null)
            {
                group = new Group
                {
                    Name = dirGroup.Name,
                    Description = dirGroup.Description,
                    Type = GroupType.Security,
                    Source = UserSource.ActiveDirectory,
                    AdObjectGuid = dirGroup.ObjectGuid,
                    AdDn = dirGroup.DistinguishedName,
                    CreatedAt = now,
                };
                db.Groups.Add(group);
                await db.SaveChangesAsync(ct);
                groupsAdded++;
            }
            else
            {
                group.Name = dirGroup.Name;
                group.Description = dirGroup.Description;
                group.AdDn = dirGroup.DistinguishedName;
                group.DeletedAt = null;
                groupsUpdated++;
            }

            membershipsChanged += await ReconcileMembershipAsync(group, dirGroup, now, ct);
        }
        await db.SaveChangesAsync(ct);

        // Only a full reconcile can conclude anything from absence. An incremental pass
        // returns changed objects only, so "not in this delta" means nothing at all.
        if (fullReconcile)
        {
            var seen = delta.Users.Select(u => u.ObjectGuid).ToHashSet();
            var vanished = await db.Users
                .Where(u => u.Source == UserSource.ActiveDirectory
                            && u.AdObjectGuid != null
                            && u.Status != UserStatus.Disabled
                            && u.DeletedAt == null)
                .ToListAsync(ct);

            foreach (var user in vanished.Where(u => !seen.Contains(u.AdObjectGuid!.Value)))
            {
                user.Status = UserStatus.Disabled;
                usersDeactivated++;
            }
            await db.SaveChangesAsync(ct);
        }

        var report = new SyncReport(
            true, usersAdded, usersUpdated, usersDeactivated,
            groupsAdded, groupsUpdated, membershipsChanged,
            delta.HighestUsn, fullReconcile, errors);

        await audit.AppendAsync("directory.sync", "success", null, "system", null, null, null,
            $"{{\"added\":{usersAdded},\"updated\":{usersUpdated},\"deactivated\":{usersDeactivated}," +
            $"\"full\":{fullReconcile.ToString().ToLowerInvariant()},\"errors\":{errors.Count}}}", ct);

        return report;
    }

    private async Task<int> ReconcileMembershipAsync(
        Group group, DirectoryGroup dirGroup, DateTimeOffset now, CancellationToken ct)
    {
        var desired = await db.Users
            .Where(u => u.AdObjectGuid != null && dirGroup.MemberObjectGuids.Contains(u.AdObjectGuid.Value))
            .Select(u => u.Id)
            .ToListAsync(ct);

        var current = await db.GroupMembers
            .Where(m => m.GroupId == group.Id)
            .ToListAsync(ct);

        var currentIds = current.Select(m => m.UserId).ToHashSet();
        var desiredIds = desired.ToHashSet();
        var changed = 0;

        foreach (var userId in desiredIds.Except(currentIds))
        {
            db.GroupMembers.Add(new GroupMember { GroupId = group.Id, UserId = userId, AddedAt = now });
            changed++;
        }

        foreach (var member in current.Where(m => !desiredIds.Contains(m.UserId)))
        {
            db.GroupMembers.Remove(member);
            changed++;
        }

        return changed;
    }
}
