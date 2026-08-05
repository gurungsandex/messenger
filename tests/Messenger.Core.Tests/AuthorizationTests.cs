using Messenger.Contracts;
using Messenger.Core;
using Messenger.Crypto;
using Messenger.Data;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace Messenger.Core.Tests;

public class RoleSeedingTests
{
    [Fact]
    public async Task Seeds_the_built_in_roles()
    {
        using var h = new TestHarness();

        var roles = await h.Db.Roles.Select(r => r.Name).ToListAsync();

        Assert.Contains(BuiltInRoles.ServerAdmin, roles);
        Assert.Contains(BuiltInRoles.UserAdmin, roles);
        Assert.Contains(BuiltInRoles.Auditor, roles);
        Assert.Contains(BuiltInRoles.HelpDesk, roles);
        Assert.Contains(BuiltInRoles.User, roles);
    }

    [Fact]
    public async Task Seeding_is_idempotent()
    {
        using var h = new TestHarness();
        var before = await h.Db.Roles.CountAsync();

        await h.Authorization.SeedBuiltInRolesAsync();

        Assert.Equal(before, await h.Db.Roles.CountAsync());
    }

    /// <summary>
    /// Reconciling permissions on every seed is how a permission added in a new release
    /// reaches deployments that already have the role.
    /// </summary>
    [Fact]
    public async Task Seeding_reconciles_permissions_on_a_built_in_role()
    {
        using var h = new TestHarness();
        var adminRole = await h.Db.Roles.SingleAsync(r => r.Name == BuiltInRoles.ServerAdmin);

        h.Db.RolePermissions.Remove(
            await h.Db.RolePermissions.FirstAsync(rp => rp.RoleId == adminRole.Id && rp.PermissionKey == Permissions.AuditRead));
        h.Db.RolePermissions.Add(new RolePermission { RoleId = adminRole.Id, PermissionKey = "stale.permission" });
        await h.Db.SaveChangesAsync();

        await h.Authorization.SeedBuiltInRolesAsync();

        var permissions = await h.Authorization.GetPermissionsAsync(Guid.Empty);
        var rolePermissions = await h.Db.RolePermissions
            .Where(rp => rp.RoleId == adminRole.Id).Select(rp => rp.PermissionKey).ToListAsync();

        Assert.Contains(Permissions.AuditRead, rolePermissions);
        Assert.DoesNotContain("stale.permission", rolePermissions);
    }

    /// <summary>
    /// An ordinary account must hold no administrative permission whatsoever. This is the
    /// exact defect the RBAC work was written to close: previously any authenticated user
    /// could read the audit log and manage accounts.
    /// </summary>
    [Fact]
    public async Task An_ordinary_user_holds_no_administrative_permission()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");

        var permissions = await h.Authorization.GetPermissionsAsync(alice.Id);

        Assert.Contains(Permissions.ChatUse, permissions);
        Assert.DoesNotContain(Permissions.AuditRead, permissions);
        Assert.DoesNotContain(Permissions.UsersCreate, permissions);
        Assert.DoesNotContain(Permissions.UsersSetStatus, permissions);
        Assert.DoesNotContain(Permissions.SessionsRevoke, permissions);
        Assert.DoesNotContain(Permissions.LicenseInstall, permissions);
        Assert.DoesNotContain(Permissions.DirectorySync, permissions);
    }

    /// <summary>Separation of duties: the auditor reads evidence but manages nobody.</summary>
    [Fact]
    public async Task An_auditor_can_read_the_audit_log_but_not_manage_users()
    {
        using var h = new TestHarness();
        var auditor = h.AddUser("auditor");
        h.GrantRole(auditor.Id, BuiltInRoles.Auditor);

        var permissions = await h.Authorization.GetPermissionsAsync(auditor.Id);

        Assert.Contains(Permissions.AuditRead, permissions);
        Assert.Contains(Permissions.AuditVerify, permissions);
        Assert.DoesNotContain(Permissions.UsersCreate, permissions);
        Assert.DoesNotContain(Permissions.UsersSetStatus, permissions);
        Assert.DoesNotContain(Permissions.SessionsRevoke, permissions);
    }

    [Fact]
    public async Task A_user_admin_cannot_install_a_licence_or_change_server_settings()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("useradmin");
        h.GrantRole(admin.Id, BuiltInRoles.UserAdmin);

        var permissions = await h.Authorization.GetPermissionsAsync(admin.Id);

        Assert.Contains(Permissions.UsersCreate, permissions);
        Assert.DoesNotContain(Permissions.LicenseInstall, permissions);
        Assert.DoesNotContain(Permissions.ServerSettings, permissions);
        Assert.DoesNotContain(Permissions.DirectorySync, permissions);
    }

    [Fact]
    public async Task A_server_admin_holds_every_server_scope_permission()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        h.GrantRole(admin.Id, BuiltInRoles.ServerAdmin);

        var permissions = await h.Authorization.GetPermissionsAsync(admin.Id);

        foreach (var permission in new[]
        {
            Permissions.UsersCreate, Permissions.UsersSetStatus, Permissions.GroupsManage,
            Permissions.SessionsRevoke, Permissions.AuditRead, Permissions.DirectorySync,
            Permissions.LicenseInstall, Permissions.ServerSettings,
        })
        {
            Assert.Contains(permission, permissions);
        }
    }

    /// <summary>No built-in role may carry an owner-tier permission.</summary>
    [Fact]
    public async Task No_seeded_role_carries_an_owner_tier_permission()
    {
        using var h = new TestHarness();

        var granted = await h.Db.RolePermissions.Select(rp => rp.PermissionKey).Distinct().ToListAsync();

        Assert.Empty(granted.Where(Permissions.OwnerTierOnly.Contains));
    }
}

public class PermissionEnforcementTests
{
    [Fact]
    public async Task Require_passes_for_a_held_permission()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        h.GrantRole(admin.Id, BuiltInRoles.ServerAdmin);

        await h.Authorization.RequireAsync(admin.Id, Permissions.UsersCreate);
    }

    [Fact]
    public async Task Require_throws_permission_denied_for_a_missing_permission()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");

        var ex = await Assert.ThrowsAsync<MessengerException>(
            () => h.Authorization.RequireAsync(alice.Id, Permissions.AuditRead));

        Assert.Equal(ErrorCode.PermissionDenied, ex.Code);
    }

    [Fact]
    public async Task A_denial_is_audited()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");

        await Assert.ThrowsAsync<MessengerException>(
            () => h.Authorization.RequireAsync(alice.Id, Permissions.UsersCreate));

        var entry = await h.Db.AuditLog.SingleAsync(e => e.Action == "authz.deny");
        Assert.Equal(alice.Id, entry.ActorUserId);
        Assert.Contains(Permissions.UsersCreate, entry.DetailJson!);
        Assert.True((await h.Audit.VerifyAsync()).IsValid);
    }

    [Fact]
    public async Task Removing_a_role_removes_its_permissions_immediately()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        var second = h.AddUser("second");
        h.GrantRole(admin.Id, BuiltInRoles.ServerAdmin);
        h.GrantRole(second.Id, BuiltInRoles.ServerAdmin);

        var role = await h.Db.Roles.SingleAsync(r => r.Name == BuiltInRoles.ServerAdmin);
        await h.Authorization.RemoveRoleAsync(admin.Id, role.Id, second.Id);

        Assert.False(await h.Authorization.HasPermissionAsync(admin.Id, Permissions.UsersCreate));
    }

    /// <summary>
    /// Stripping the final server administrator leaves the deployment unmanageable with no
    /// route back short of database surgery.
    /// </summary>
    [Fact]
    public async Task The_last_server_administrator_cannot_be_demoted()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        h.GrantRole(admin.Id, BuiltInRoles.ServerAdmin);

        var role = await h.Db.Roles.SingleAsync(r => r.Name == BuiltInRoles.ServerAdmin);

        var ex = await Assert.ThrowsAsync<MessengerException>(
            () => h.Authorization.RemoveRoleAsync(admin.Id, role.Id, admin.Id));

        Assert.Equal(ErrorCode.LastAdminProtected, ex.Code);
        Assert.True(await h.Authorization.HasPermissionAsync(admin.Id, Permissions.UsersCreate));
    }

    [Fact]
    public async Task A_disabled_second_administrator_does_not_count_as_a_survivor()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        var disabled = h.AddUser("disabled", status: UserStatus.Disabled);
        h.GrantRole(admin.Id, BuiltInRoles.ServerAdmin);
        h.GrantRole(disabled.Id, BuiltInRoles.ServerAdmin);

        var role = await h.Db.Roles.SingleAsync(r => r.Name == BuiltInRoles.ServerAdmin);

        var ex = await Assert.ThrowsAsync<MessengerException>(
            () => h.Authorization.RemoveRoleAsync(admin.Id, role.Id, admin.Id));
        Assert.Equal(ErrorCode.LastAdminProtected, ex.Code);
    }

    /// <summary>
    /// Checking at assignment means a hand-edited or mis-seeded role row cannot be used to
    /// climb from the customer tier to the vendor tier.
    /// </summary>
    [Fact]
    public async Task A_server_scope_role_carrying_an_owner_permission_cannot_be_assigned()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");

        var rogue = new Role { Name = "RogueRole", Scope = RoleScope.Server };
        h.Db.Roles.Add(rogue);
        await h.Db.SaveChangesAsync();
        h.Db.RolePermissions.Add(new RolePermission
        {
            RoleId = rogue.Id,
            PermissionKey = Permissions.VendorIssueLicense,
        });
        await h.Db.SaveChangesAsync();

        var ex = await Assert.ThrowsAsync<MessengerException>(
            () => h.Authorization.AssignRoleAsync(alice.Id, rogue.Id, Guid.Empty));

        Assert.Equal(ErrorCode.CrossTierEscalationRefused, ex.Code);
        Assert.False(await h.Authorization.HasPermissionAsync(alice.Id, Permissions.VendorIssueLicense));
    }

    [Fact]
    public async Task An_escalation_attempt_is_audited()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");

        var rogue = new Role { Name = "RogueRole", Scope = RoleScope.Server };
        h.Db.Roles.Add(rogue);
        await h.Db.SaveChangesAsync();
        h.Db.RolePermissions.Add(new RolePermission { RoleId = rogue.Id, PermissionKey = Permissions.VendorTelemetry });
        await h.Db.SaveChangesAsync();

        await Assert.ThrowsAsync<MessengerException>(
            () => h.Authorization.AssignRoleAsync(alice.Id, rogue.Id, Guid.Empty));

        Assert.Single(await h.Db.AuditLog.Where(e => e.Action == "authz.escalation_refused").ToListAsync());
    }

    [Fact]
    public async Task Assigning_a_role_twice_is_idempotent()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");
        var role = await h.Db.Roles.SingleAsync(r => r.Name == BuiltInRoles.HelpDesk);

        await h.Authorization.AssignRoleAsync(alice.Id, role.Id, Guid.Empty);
        await h.Authorization.AssignRoleAsync(alice.Id, role.Id, Guid.Empty);

        Assert.Equal(1, await h.Db.UserRoles.CountAsync(ur => ur.UserId == alice.Id && ur.RoleId == role.Id));
    }

    [Fact]
    public async Task An_owner_scope_role_may_hold_owner_permissions()
    {
        using var h = new TestHarness();
        var vendor = h.AddUser("vendor");

        var role = new Role { Name = "VendorAdmin", Scope = RoleScope.Owner };
        h.Db.Roles.Add(role);
        await h.Db.SaveChangesAsync();
        h.Db.RolePermissions.Add(new RolePermission { RoleId = role.Id, PermissionKey = Permissions.VendorIssueLicense });
        await h.Db.SaveChangesAsync();

        await h.Authorization.AssignRoleAsync(vendor.Id, role.Id, Guid.Empty);

        Assert.True(await h.Authorization.HasPermissionAsync(vendor.Id, Permissions.VendorIssueLicense));
    }
}

/// <summary>
/// The root key must outlive the process. A KEK generated per start makes every message and
/// file encrypted before a restart permanently unreadable.
/// </summary>
public class KeyStorePersistenceTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "messenger-keystore-" + Guid.NewGuid().ToString("N")[..8]);

    private string EscrowPath => Path.Combine(_directory, "root.escrow");

    [Fact]
    public void Creates_an_escrow_on_first_run_and_reports_it()
    {
        var (provider, created) = FileBackedKeyStore.OpenOrCreate(EscrowPath, "a strong passphrase");
        using var _ = provider;

        Assert.True(created);
        Assert.True(File.Exists(EscrowPath));
    }

    [Fact]
    public void Reopens_the_same_key_on_restart()
    {
        var (first, createdFirst) = FileBackedKeyStore.OpenOrCreate(EscrowPath, "a strong passphrase");
        var dek = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        var wrapped = first.Wrap(dek);
        var kekId = first.ActiveKekId;
        first.Dispose();

        // Second start of the same server.
        var (second, createdSecond) = FileBackedKeyStore.OpenOrCreate(EscrowPath, "a strong passphrase");
        using var _ = second;

        Assert.True(createdFirst);
        Assert.False(createdSecond);
        Assert.Equal(kekId, second.ActiveKekId);

        // The decisive assertion: content encrypted before the restart is still readable.
        Assert.Equal(dek, second.Unwrap(wrapped, kekId));
    }

    [Fact]
    public void Refuses_to_open_with_the_wrong_passphrase()
    {
        var (first, _) = FileBackedKeyStore.OpenOrCreate(EscrowPath, "right passphrase");
        first.Dispose();

        var ex = Assert.Throws<MessengerException>(
            () => FileBackedKeyStore.OpenOrCreate(EscrowPath, "wrong passphrase"));
        Assert.Equal(ErrorCode.KeyUnwrapFailed, ex.Code);
    }

    [Fact]
    public void Refuses_an_empty_passphrase()
        => Assert.Throws<ArgumentException>(() => FileBackedKeyStore.OpenOrCreate(EscrowPath, "  "));

    public void Dispose()
    {
        if (Directory.Exists(_directory)) Directory.Delete(_directory, recursive: true);
    }
}
