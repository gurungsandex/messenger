using Messenger.Contracts;
using Messenger.Core;
using Messenger.Data;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace Messenger.Core.Tests;

public class LdapEscapeTests
{
    /// <summary>
    /// LDAP injection is the under-appreciated risk here: an unescaped <c>*</c> turns a
    /// lookup for one account into a match for every account.
    /// </summary>
    [Theory]
    [InlineData("*", "\\2a")]
    [InlineData("(", "\\28")]
    [InlineData(")", "\\29")]
    [InlineData("\\", "\\5c")]
    [InlineData("/", "\\2f")]
    public void Escapes_filter_metacharacters(string input, string expected)
        => Assert.Equal(expected, LdapEscape.Filter(input));

    [Fact]
    public void A_wildcard_injection_cannot_widen_a_filter()
    {
        var filter = LdapEscape.UserBySamAccountName("*)(objectClass=*");

        Assert.DoesNotContain("(objectClass=*)", filter[filter.IndexOf("sAMAccountName", StringComparison.Ordinal)..]);
        Assert.Contains("\\2a\\29\\28objectClass=\\2a", filter);
    }

    [Fact]
    public void Leaves_ordinary_values_intact()
        => Assert.Equal("jsmith", LdapEscape.Filter("jsmith"));

    [Fact]
    public void Hex_escapes_non_ascii()
        => Assert.Equal("\\c3\\a9", LdapEscape.Filter("é"));

    [Theory]
    [InlineData("a,b", "a\\,b")]
    [InlineData("a+b", "a\\+b")]
    [InlineData("a=b", "a\\=b")]
    public void Escapes_distinguished_name_metacharacters(string input, string expected)
        => Assert.Equal(expected, LdapEscape.DistinguishedName(input));

    [Fact]
    public void Escapes_leading_and_trailing_spaces_in_a_dn()
    {
        Assert.StartsWith("\\ ", LdapEscape.DistinguishedName(" leading"));
        Assert.EndsWith("\\ ", LdapEscape.DistinguishedName("trailing "));
    }

    [Fact]
    public void Escapes_a_leading_hash_in_a_dn()
        => Assert.StartsWith("\\#", LdapEscape.DistinguishedName("#value"));
}

public class DirectorySyncTests
{
    private static DirectoryUser User(
        Guid guid, string sam, string display = "Display Name",
        bool enabled = true, long usn = 1, string? dn = null)
        => new(guid, dn ?? $"CN={sam},OU=Users,DC=corp,DC=local", sam, $"{sam}@corp.local",
               display, $"{sam}@corp.local", null, null, enabled, usn);

    [Fact]
    public async Task Imports_new_users()
    {
        using var h = new TestHarness();
        h.Directory.Users.Add(User(Guid.NewGuid(), "jsmith", "Jane Smith"));
        h.Directory.Users.Add(User(Guid.NewGuid(), "bjones", "Bob Jones"));

        var report = await h.DirectorySync.SyncAsync();

        Assert.True(report.Succeeded);
        Assert.Equal(2, report.UsersAdded);
        Assert.Equal(2, await h.Db.Users.CountAsync(u => u.Source == UserSource.ActiveDirectory));
    }

    [Fact]
    public async Task Imported_users_hold_no_local_password()
    {
        using var h = new TestHarness();
        h.Directory.Users.Add(User(Guid.NewGuid(), "jsmith"));

        await h.DirectorySync.SyncAsync();

        var user = await h.Db.Users.SingleAsync();
        Assert.Null(user.PasswordHash);

        // A directory-sourced account must not be authenticable by local password.
        var result = await h.Auth.AuthenticateAsync("jsmith", "anything");
        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task A_disabled_directory_account_imports_as_disabled()
    {
        using var h = new TestHarness();
        h.Directory.Users.Add(User(Guid.NewGuid(), "former", enabled: false));

        await h.DirectorySync.SyncAsync();

        Assert.Equal(UserStatus.Disabled, (await h.Db.Users.SingleAsync()).Status);
    }

    /// <summary>
    /// objectGUID is the only stable identity in AD. Matching on name would turn a rename
    /// into a duplicate account and orphan the user's message history.
    /// </summary>
    [Fact]
    public async Task A_renamed_user_updates_in_place_rather_than_duplicating()
    {
        using var h = new TestHarness();
        var guid = Guid.NewGuid();
        h.Directory.Users.Add(User(guid, "jsmith", "Jane Smith"));
        await h.DirectorySync.SyncAsync();

        var originalId = (await h.Db.Users.SingleAsync()).Id;

        // Married, renamed, and moved to another OU — all at once.
        h.Directory.Users.Clear();
        h.Directory.Users.Add(User(guid, "jdoe", "Jane Doe", usn: 2, dn: "CN=jdoe,OU=Sales,DC=corp,DC=local"));

        await h.DirectorySync.SyncAsync();

        var user = await h.Db.Users.SingleAsync();
        Assert.Equal(originalId, user.Id);
        Assert.Equal("jdoe", user.Username);
        Assert.Equal("Jane Doe", user.DisplayName);
        Assert.Equal(1, await h.Db.Users.CountAsync());
    }

    [Fact]
    public async Task An_ou_move_does_not_create_a_duplicate()
    {
        using var h = new TestHarness();
        var guid = Guid.NewGuid();
        h.Directory.Users.Add(User(guid, "jsmith", dn: "CN=jsmith,OU=Sales,DC=corp,DC=local"));
        await h.DirectorySync.SyncAsync();

        h.Directory.Users.Clear();
        h.Directory.Users.Add(User(guid, "jsmith", usn: 2, dn: "CN=jsmith,OU=Engineering,DC=corp,DC=local"));
        await h.DirectorySync.SyncAsync();

        Assert.Equal(1, await h.Db.Users.CountAsync());
        Assert.Contains("Engineering", (await h.Db.Users.SingleAsync()).AdDn);
    }

    /// <summary>
    /// A vanished object must never delete local data. A mis-scoped filter or a replication
    /// hiccup would otherwise erase message history and audit trail.
    /// </summary>
    [Fact]
    public async Task A_vanished_user_is_deactivated_not_deleted()
    {
        using var h = new TestHarness();
        var guid = Guid.NewGuid();
        h.Directory.Users.Add(User(guid, "departing"));
        await h.DirectorySync.SyncAsync();

        h.Directory.Users.Clear();
        var report = await h.DirectorySync.SyncAsync(forceFullReconcile: true);

        Assert.Equal(1, report.UsersDeactivated);
        var user = await h.Db.Users.SingleAsync();
        Assert.Equal(UserStatus.Disabled, user.Status);
        Assert.Null(user.DeletedAt);
    }

    [Fact]
    public async Task Deactivation_preserves_message_history()
    {
        using var h = new TestHarness();
        var guid = Guid.NewGuid();
        h.Directory.Users.Add(User(guid, "departing"));
        await h.DirectorySync.SyncAsync();

        var departing = await h.Db.Users.SingleAsync();
        var peer = h.AddUser("peer");
        var c = await h.Messages.GetOrCreateDirectConversationAsync(departing.Id, peer.Id);
        await h.Messages.SendAsync(departing.Id,
            new SendMessageRequest(c.Id, Guid.NewGuid(), "a decision on record", h.Time.GetUtcNow()));

        h.Directory.Users.Clear();
        await h.DirectorySync.SyncAsync(forceFullReconcile: true);

        var history = await h.Messages.GetHistoryAsync(peer.Id, c.Id);
        Assert.Single(history);
        Assert.Equal("a decision on record", history[0].Body);
    }

    /// <summary>
    /// An incremental delta contains only changed objects, so absence from it means nothing.
    /// Deactivating on that basis would disable the entire directory on the first
    /// uneventful sync.
    /// </summary>
    [Fact]
    public async Task An_incremental_sync_never_deactivates_on_absence()
    {
        using var h = new TestHarness();
        h.Directory.Users.Add(User(Guid.NewGuid(), "stable", usn: 1));
        var first = await h.DirectorySync.SyncAsync();

        h.Directory.Users.Add(User(Guid.NewGuid(), "newcomer", usn: 5));
        var second = await h.DirectorySync.SyncAsync(first.HighestUsn);

        Assert.False(second.WasFullReconcile);
        Assert.Equal(0, second.UsersDeactivated);
        Assert.Equal(UserStatus.Active, (await h.Db.Users.SingleAsync(u => u.Username == "stable")).Status);
    }

    [Fact]
    public async Task An_incremental_sync_only_processes_changed_objects()
    {
        using var h = new TestHarness();
        h.Directory.Users.Add(User(Guid.NewGuid(), "old", usn: 1));
        var first = await h.DirectorySync.SyncAsync();

        h.Directory.Users.Add(User(Guid.NewGuid(), "new", usn: 10));
        var second = await h.DirectorySync.SyncAsync(first.HighestUsn);

        Assert.Equal(1, second.UsersAdded);
        Assert.Equal(0, second.UsersUpdated);
    }

    /// <summary>
    /// A watermark ahead of the directory means the DC was restored from backup or replaced.
    /// Continuing incrementally would silently skip every change in between.
    /// </summary>
    [Fact]
    public async Task A_backwards_watermark_triggers_a_full_reconcile()
    {
        using var h = new TestHarness();
        h.Directory.Users.Add(User(Guid.NewGuid(), "jsmith", usn: 5));

        var report = await h.DirectorySync.SyncAsync(sinceUsn: 9999);

        Assert.True(report.WasFullReconcile);
        Assert.Equal(1, report.UsersAdded);
        Assert.Contains(report.Errors, e => e.StartsWith(ErrorCode.WatermarkLost, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Refuses_a_result_set_above_the_safety_cap()
    {
        using var h = new TestHarness();
        for (int i = 0; i < 20; i++)
            h.Directory.Users.Add(User(Guid.NewGuid(), $"user{i}"));

        var ex = await Assert.ThrowsAsync<MessengerException>(
            () => h.DirectorySync.SyncAsync(options: new SyncOptions(MaxObjectsPerRun: 5)));

        Assert.Equal(ErrorCode.SyncScopeTooLarge, ex.Code);
        Assert.Equal(0, await h.Db.Users.CountAsync());
    }

    [Fact]
    public async Task Skips_an_object_missing_required_attributes()
    {
        using var h = new TestHarness();
        h.Directory.Users.Add(User(Guid.NewGuid(), "good", "Good User"));
        h.Directory.Users.Add(User(Guid.NewGuid(), "blank", display: ""));

        var report = await h.DirectorySync.SyncAsync();

        // Skipping beats importing an identity nobody can recognise.
        Assert.Equal(1, report.UsersAdded);
        Assert.Contains(report.Errors, e => e.StartsWith(ErrorCode.AttributeMappingError, StringComparison.Ordinal));
    }

    /// <summary>
    /// Silently adopting a same-named local account would hand directory control of an
    /// unrelated account, including a break-glass administrator.
    /// </summary>
    [Fact]
    public async Task Refuses_to_absorb_an_existing_local_account_by_name()
    {
        using var h = new TestHarness();
        var local = h.AddUser("admin", "a local password");
        h.Directory.Users.Add(User(Guid.NewGuid(), "admin", "Directory Admin"));

        var report = await h.DirectorySync.SyncAsync();

        Assert.Equal(0, report.UsersAdded);
        Assert.Contains(report.Errors, e => e.StartsWith(ErrorCode.UserAlreadyExists, StringComparison.Ordinal));

        var unchanged = await h.Db.Users.SingleAsync(u => u.Id == local.Id);
        Assert.Equal(UserSource.Local, unchanged.Source);
        Assert.NotNull(unchanged.PasswordHash);
    }

    [Fact]
    public async Task Reports_an_over_privileged_service_account_as_a_warning()
    {
        using var h = new TestHarness();
        h.Directory.Probe = new DirectoryProbeResult(true, true, HasWriteAccess: true, null, null);
        h.Directory.Users.Add(User(Guid.NewGuid(), "jsmith"));

        var report = await h.DirectorySync.SyncAsync();

        // A finding to surface, not a reason to refuse to run.
        Assert.True(report.Succeeded);
        Assert.Equal(1, report.UsersAdded);
        Assert.Contains(report.Errors, e => e.StartsWith(ErrorCode.ServiceAccountOverPrivileged, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Refuses_to_sync_when_the_directory_is_unreachable()
    {
        using var h = new TestHarness();
        h.Directory.Probe = new DirectoryProbeResult(false, false, false, ErrorCode.DirectoryUnreachable, "no route to host");

        var ex = await Assert.ThrowsAsync<MessengerException>(() => h.DirectorySync.SyncAsync());
        Assert.Equal(ErrorCode.DirectoryUnreachable, ex.Code);
    }

    [Fact]
    public async Task Surfaces_a_bind_failure_with_its_own_code()
    {
        using var h = new TestHarness();
        h.Directory.Probe = new DirectoryProbeResult(true, false, false, ErrorCode.DirectoryBindFailed, "invalid credentials");

        var ex = await Assert.ThrowsAsync<MessengerException>(() => h.DirectorySync.SyncAsync());
        Assert.Equal(ErrorCode.DirectoryBindFailed, ex.Code);
    }

    [Fact]
    public async Task Wraps_an_unexpected_provider_failure()
    {
        using var h = new TestHarness();
        h.Directory.FailWith = new InvalidOperationException("connection reset");

        var ex = await Assert.ThrowsAsync<MessengerException>(() => h.DirectorySync.SyncAsync());
        Assert.Equal(ErrorCode.SyncFailed, ex.Code);
    }

    [Fact]
    public async Task Every_run_is_audited_and_the_chain_stays_valid()
    {
        using var h = new TestHarness();
        h.Directory.Users.Add(User(Guid.NewGuid(), "jsmith"));

        await h.DirectorySync.SyncAsync();

        Assert.Contains("directory.sync", await h.Db.AuditLog.Select(e => e.Action).ToListAsync());
        Assert.True((await h.Audit.VerifyAsync()).IsValid);
    }
}

public class DirectoryGroupSyncTests
{
    private static DirectoryUser User(Guid guid, string sam, long usn = 1)
        => new(guid, $"CN={sam},DC=corp,DC=local", sam, null, sam, null, null, null, true, usn);

    [Fact]
    public async Task Imports_groups_with_their_membership()
    {
        using var h = new TestHarness();
        var aliceGuid = Guid.NewGuid();
        var bobGuid = Guid.NewGuid();
        h.Directory.Users.Add(User(aliceGuid, "alice"));
        h.Directory.Users.Add(User(bobGuid, "bob"));
        h.Directory.Groups.Add(new DirectoryGroup(
            Guid.NewGuid(), "CN=Engineering,DC=corp,DC=local", "Engineering", "Eng",
            [aliceGuid, bobGuid], 1));

        var report = await h.DirectorySync.SyncAsync();

        Assert.Equal(1, report.GroupsAdded);
        Assert.Equal(2, report.MembershipsChanged);
        Assert.Equal(2, await h.Db.GroupMembers.CountAsync());
    }

    /// <summary>
    /// AD security groups are identity constructs. Creating a chat room for each one would
    /// produce thousands of empty conversations on the first sync.
    /// </summary>
    [Fact]
    public async Task Directory_groups_get_no_chat_conversation()
    {
        using var h = new TestHarness();
        h.Directory.Groups.Add(new DirectoryGroup(
            Guid.NewGuid(), "CN=Engineering,DC=corp,DC=local", "Engineering", null, [], 1));

        await h.DirectorySync.SyncAsync();

        var group = await h.Db.Groups.SingleAsync();
        Assert.Equal(GroupType.Security, group.Type);
        Assert.Null(group.ConversationId);
        Assert.Equal(0, await h.Db.Conversations.CountAsync());
    }

    [Fact]
    public async Task Membership_removals_in_the_directory_propagate()
    {
        using var h = new TestHarness();
        var aliceGuid = Guid.NewGuid();
        var bobGuid = Guid.NewGuid();
        var groupGuid = Guid.NewGuid();
        h.Directory.Users.Add(User(aliceGuid, "alice"));
        h.Directory.Users.Add(User(bobGuid, "bob"));
        h.Directory.Groups.Add(new DirectoryGroup(
            groupGuid, "CN=Engineering,DC=corp,DC=local", "Engineering", null, [aliceGuid, bobGuid], 1));
        await h.DirectorySync.SyncAsync();

        h.Directory.Groups.Clear();
        h.Directory.Groups.Add(new DirectoryGroup(
            groupGuid, "CN=Engineering,DC=corp,DC=local", "Engineering", null, [aliceGuid], 2));
        await h.DirectorySync.SyncAsync(forceFullReconcile: true);

        var members = await h.Db.GroupMembers.ToListAsync();
        Assert.Single(members);
    }

    [Fact]
    public async Task A_renamed_group_updates_in_place()
    {
        using var h = new TestHarness();
        var groupGuid = Guid.NewGuid();
        h.Directory.Groups.Add(new DirectoryGroup(groupGuid, "CN=Eng,DC=corp,DC=local", "Eng", null, [], 1));
        await h.DirectorySync.SyncAsync();

        h.Directory.Groups.Clear();
        h.Directory.Groups.Add(new DirectoryGroup(groupGuid, "CN=Platform,DC=corp,DC=local", "Platform", null, [], 2));
        await h.DirectorySync.SyncAsync();

        Assert.Equal(1, await h.Db.Groups.CountAsync());
        Assert.Equal("Platform", (await h.Db.Groups.SingleAsync()).Name);
    }

    [Fact]
    public async Task Imports_org_units()
    {
        using var h = new TestHarness();
        h.Directory.OrgUnits.Add(new DirectoryOrgUnit(Guid.NewGuid(), "OU=Sales,DC=corp,DC=local", "Sales", null));

        await h.DirectorySync.SyncAsync();

        Assert.Equal(1, await h.Db.OrgUnits.CountAsync());
    }

    [Fact]
    public async Task Re_syncing_an_org_unit_does_not_duplicate_it()
    {
        using var h = new TestHarness();
        var guid = Guid.NewGuid();
        h.Directory.OrgUnits.Add(new DirectoryOrgUnit(guid, "OU=Sales,DC=corp,DC=local", "Sales", null));
        await h.DirectorySync.SyncAsync();
        await h.DirectorySync.SyncAsync();

        Assert.Equal(1, await h.Db.OrgUnits.CountAsync());
    }
}
