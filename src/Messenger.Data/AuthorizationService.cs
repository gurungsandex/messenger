using Messenger.Contracts;
using Messenger.Core;
using Microsoft.EntityFrameworkCore;

namespace Messenger.Data;

/// <summary>
/// The single place an authorization decision is made.
///
/// Centralised deliberately: permission logic scattered across endpoints is how an endpoint
/// ends up with no check at all, which is exactly the defect this class was written to fix.
/// Every admin route goes through <c>RequirePermissionFilter</c>, which calls this.
/// </summary>
public sealed class AuthorizationService(MessengerDbContext db, AuditService audit)
{
    /// <summary>All permission keys granted to a user through their roles.</summary>
    public async Task<IReadOnlySet<string>> GetPermissionsAsync(Guid userId, CancellationToken ct = default)
    {
        var keys = await db.UserRoles
            .Where(ur => ur.UserId == userId)
            .Join(db.RolePermissions, ur => ur.RoleId, rp => rp.RoleId, (_, rp) => rp.PermissionKey)
            .Distinct()
            .ToListAsync(ct);

        return new HashSet<string>(keys, StringComparer.Ordinal);
    }

    public async Task<bool> HasPermissionAsync(Guid userId, string permission, CancellationToken ct = default)
        => await db.UserRoles
            .Where(ur => ur.UserId == userId)
            .Join(db.RolePermissions, ur => ur.RoleId, rp => rp.RoleId, (_, rp) => rp.PermissionKey)
            .AnyAsync(k => k == permission, ct);

    /// <summary>Throws <see cref="ErrorCode.PermissionDenied"/> and audits the denial.</summary>
    public async Task RequireAsync(
        Guid userId, string permission, string? actorIp = null, CancellationToken ct = default)
    {
        if (await HasPermissionAsync(userId, permission, ct)) return;

        await audit.AppendAsync("authz.deny", "denied", userId, "admin", actorIp, null, null,
            $"{{\"permission\":\"{permission}\"}}", ct);

        throw new MessengerException(ErrorCode.PermissionDenied,
            $"This action requires the '{permission}' permission.");
    }

    /// <summary>
    /// Assigns a role, refusing any cross-tier escalation.
    ///
    /// A server-scope role must never carry owner-tier permissions. Checking at assignment
    /// means a mis-seeded or hand-edited role row cannot be used to climb tiers.
    /// </summary>
    public async Task AssignRoleAsync(Guid userId, Guid roleId, Guid actorId, CancellationToken ct = default)
    {
        var role = await db.Roles.FirstOrDefaultAsync(r => r.Id == roleId, ct)
                   ?? throw new MessengerException(ErrorCode.PermissionDenied, "Role not found.");

        if (role.Scope != RoleScope.Owner)
        {
            var ownerTier = await db.RolePermissions
                .Where(rp => rp.RoleId == roleId)
                .Select(rp => rp.PermissionKey)
                .ToListAsync(ct);

            var offending = ownerTier.FirstOrDefault(Permissions.OwnerTierOnly.Contains);
            if (offending is not null)
            {
                await audit.AppendAsync("authz.escalation_refused", "denied", actorId, "admin", null,
                    "role", roleId, $"{{\"permission\":\"{offending}\"}}", ct);

                throw new MessengerException(ErrorCode.CrossTierEscalationRefused,
                    $"Role '{role.Name}' is {role.Scope}-scoped but carries the owner-tier permission "
                    + $"'{offending}'. This is not assignable.");
            }
        }

        if (await db.UserRoles.AnyAsync(ur => ur.UserId == userId && ur.RoleId == roleId, ct)) return;

        db.UserRoles.Add(new UserRole { UserId = userId, RoleId = roleId, AssignedBy = actorId });
        await db.SaveChangesAsync(ct);

        await audit.AppendAsync("authz.role_assign", "success", actorId, "admin", null,
            "user", userId, $"{{\"role\":\"{role.Name}\"}}", ct);
    }

    /// <summary>
    /// Removes a role, refusing to remove the last account able to administer the server.
    ///
    /// Without this an administrator can strip the final `ServerAdmin` and leave the
    /// deployment unmanageable with no route back short of database surgery.
    /// </summary>
    public async Task RemoveRoleAsync(Guid userId, Guid roleId, Guid actorId, CancellationToken ct = default)
    {
        var assignment = await db.UserRoles
            .Include(ur => ur.Role)
            .FirstOrDefaultAsync(ur => ur.UserId == userId && ur.RoleId == roleId, ct);
        if (assignment is null) return;

        if (assignment.Role.Name == BuiltInRoles.ServerAdmin)
        {
            var remaining = await db.UserRoles
                .Where(ur => ur.RoleId == roleId && ur.UserId != userId)
                .Join(db.Users.Where(u => u.Status == UserStatus.Active && u.DeletedAt == null),
                      ur => ur.UserId, u => u.Id, (ur, _) => ur.UserId)
                .CountAsync(ct);

            if (remaining == 0)
                throw new MessengerException(ErrorCode.LastAdminProtected,
                    "This is the last active server administrator. Assign the role to another "
                    + "account before removing it from this one.");
        }

        db.UserRoles.Remove(assignment);
        await db.SaveChangesAsync(ct);

        await audit.AppendAsync("authz.role_remove", "success", actorId, "admin", null,
            "user", userId, $"{{\"role\":\"{assignment.Role.Name}\"}}", ct);
    }

    /// <summary>
    /// Seeds the built-in roles. Idempotent, so it is safe on every start.
    /// Permissions on built-in roles are reconciled to the current definition, which is how
    /// a new permission reaches existing deployments on upgrade.
    /// </summary>
    public async Task SeedBuiltInRolesAsync(CancellationToken ct = default)
    {
        foreach (var (name, scope, description, permissions) in BuiltInRoles.Seed)
        {
            var role = await db.Roles.FirstOrDefaultAsync(r => r.Name == name, ct);
            if (role is null)
            {
                role = new Role { Name = name, Scope = scope, Description = description, IsBuiltIn = true };
                db.Roles.Add(role);
                await db.SaveChangesAsync(ct);
            }
            else
            {
                role.Scope = scope;
                role.Description = description;
                role.IsBuiltIn = true;
            }

            var existing = await db.RolePermissions.Where(rp => rp.RoleId == role.Id).ToListAsync(ct);
            var desired = permissions.ToHashSet(StringComparer.Ordinal);

            foreach (var add in desired.Except(existing.Select(e => e.PermissionKey)))
                db.RolePermissions.Add(new RolePermission { RoleId = role.Id, PermissionKey = add });

            db.RolePermissions.RemoveRange(existing.Where(e => !desired.Contains(e.PermissionKey)));
        }

        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Grants the default client role to a user who has none.
    ///
    /// A user with no roles can do nothing at all — not even chat — so account creation and
    /// directory sync must both go through this. Failing closed is right for administration
    /// but would be an outage for ordinary users.
    /// </summary>
    public async Task EnsureDefaultRoleAsync(Guid userId, CancellationToken ct = default)
    {
        if (await db.UserRoles.AnyAsync(ur => ur.UserId == userId, ct)) return;

        var role = await db.Roles.FirstOrDefaultAsync(r => r.Name == BuiltInRoles.User, ct);
        if (role is null) return;

        db.UserRoles.Add(new UserRole { UserId = userId, RoleId = role.Id });
        await db.SaveChangesAsync(ct);
    }
}
