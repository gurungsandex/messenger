using Messenger.Contracts;
using Messenger.Core;
using Messenger.Data;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace Messenger.Core.Tests;

public class GroupLifecycleTests
{
    [Fact]
    public async Task Creates_a_chat_group_with_a_conversation()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");

        var group = await h.Groups.CreateAsync("Engineering", "Eng team", admin.Id);

        Assert.NotNull(group.ConversationId);
        var conversation = await h.Db.Conversations.SingleAsync(c => c.Id == group.ConversationId);
        Assert.Equal(ConversationType.Group, conversation.Type);
        Assert.Equal("Engineering", conversation.Title);
    }

    /// <summary>
    /// AD security and distribution groups are identity constructs. Giving each one a chat
    /// room would create thousands of empty conversations on the first directory sync.
    /// </summary>
    [Theory]
    [InlineData(GroupType.Security)]
    [InlineData(GroupType.Distribution)]
    public async Task Non_chat_groups_get_no_conversation(GroupType type)
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");

        var group = await h.Groups.CreateAsync("Sales", null, admin.Id, type);

        Assert.Null(group.ConversationId);
    }

    [Fact]
    public async Task Rejects_a_duplicate_group_name()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        await h.Groups.CreateAsync("Engineering", null, admin.Id);

        var ex = await Assert.ThrowsAsync<MessengerException>(
            () => h.Groups.CreateAsync("Engineering", null, admin.Id));
        Assert.Equal(ErrorCode.GroupAlreadyExists, ex.Code);
    }

    [Fact]
    public async Task Rejects_an_empty_group_name()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");

        await Assert.ThrowsAsync<MessengerException>(() => h.Groups.CreateAsync("   ", null, admin.Id));
    }

    [Fact]
    public async Task Renaming_updates_the_conversation_title()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        var group = await h.Groups.CreateAsync("Engineering", null, admin.Id);

        await h.Groups.RenameAsync(group.Id, "Platform", admin.Id);

        var conversation = await h.Db.Conversations.SingleAsync(c => c.Id == group.ConversationId);
        Assert.Equal("Platform", conversation.Title);
    }

    [Fact]
    public async Task Refuses_to_rename_a_directory_owned_group()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        var group = await h.Groups.CreateAsync("Engineering", null, admin.Id);
        group.Source = UserSource.ActiveDirectory;
        await h.Db.SaveChangesAsync();

        var ex = await Assert.ThrowsAsync<MessengerException>(
            () => h.Groups.RenameAsync(group.Id, "Platform", admin.Id));
        Assert.Equal(ErrorCode.DirectoryOwnedAttribute, ex.Code);
    }

    [Fact]
    public async Task Deleting_is_soft_and_preserves_history()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        var alice = h.AddUser("alice");
        var group = await h.Groups.CreateAsync("Engineering", null, admin.Id);
        await h.Groups.AddMemberAsync(group.Id, alice.Id, admin.Id);
        await h.Messages.SendAsync(alice.Id,
            new SendMessageRequest(group.ConversationId!.Value, Guid.NewGuid(), "a decision", h.Time.GetUtcNow()));

        await h.Groups.DeleteAsync(group.Id, admin.Id);

        // The record survives the group; a purge is a separate, explicit action.
        Assert.Equal(1, await h.Db.Messages.CountAsync());
        Assert.NotNull((await h.Db.Groups.SingleAsync()).DeletedAt);
    }

    [Fact]
    public async Task Unknown_group_operations_report_group_not_found()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");

        var ex = await Assert.ThrowsAsync<MessengerException>(
            () => h.Groups.AddMemberAsync(Guid.NewGuid(), admin.Id, admin.Id));
        Assert.Equal(ErrorCode.GroupNotFound, ex.Code);
    }
}

public class GroupMembershipTests
{
    [Fact]
    public async Task Adding_a_member_joins_them_to_the_conversation()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        var alice = h.AddUser("alice");
        var group = await h.Groups.CreateAsync("Engineering", null, admin.Id);

        await h.Groups.AddMemberAsync(group.Id, alice.Id, admin.Id);

        Assert.Contains(alice.Id, await h.Messages.GetParticipantIdsAsync(group.ConversationId!.Value));
    }

    [Fact]
    public async Task Adding_an_existing_member_is_idempotent()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        var alice = h.AddUser("alice");
        var group = await h.Groups.CreateAsync("Engineering", null, admin.Id);

        await h.Groups.AddMemberAsync(group.Id, alice.Id, admin.Id);
        await h.Groups.AddMemberAsync(group.Id, alice.Id, admin.Id);

        Assert.Equal(1, await h.Db.GroupMembers.CountAsync());
    }

    [Fact]
    public async Task Refuses_to_add_a_disabled_user()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        var alice = h.AddUser("alice", status: UserStatus.Disabled);
        var group = await h.Groups.CreateAsync("Engineering", null, admin.Id);

        var ex = await Assert.ThrowsAsync<MessengerException>(
            () => h.Groups.AddMemberAsync(group.Id, alice.Id, admin.Id));
        Assert.Equal(ErrorCode.AccountDisabled, ex.Code);
    }

    [Fact]
    public async Task Removing_a_member_closes_participation_without_deleting_it()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        var alice = h.AddUser("alice");
        var group = await h.Groups.CreateAsync("Engineering", null, admin.Id);
        await h.Groups.AddMemberAsync(group.Id, alice.Id, admin.Id);

        await h.Groups.RemoveMemberAsync(group.Id, alice.Id, admin.Id);

        Assert.Empty(await h.Db.GroupMembers.Where(m => m.UserId == alice.Id).ToListAsync());
        var participant = await h.Db.ConversationParticipants.SingleAsync(p => p.UserId == alice.Id);
        Assert.NotNull(participant.LeftAt);
    }

    [Fact]
    public async Task Removing_a_non_member_is_a_no_op()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        var alice = h.AddUser("alice");
        var group = await h.Groups.CreateAsync("Engineering", null, admin.Id);

        await h.Groups.RemoveMemberAsync(group.Id, alice.Id, admin.Id);
    }

    [Fact]
    public async Task Moving_a_member_lands_them_in_exactly_one_group()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        var alice = h.AddUser("alice");
        var from = await h.Groups.CreateAsync("Engineering", null, admin.Id);
        var to = await h.Groups.CreateAsync("Platform", null, admin.Id);
        await h.Groups.AddMemberAsync(from.Id, alice.Id, admin.Id);

        await h.Groups.MoveMemberAsync(from.Id, to.Id, alice.Id, admin.Id);

        var groups = await h.Groups.GetGroupsForUserAsync(alice.Id);
        Assert.Single(groups);
        Assert.Equal(to.Id, groups[0].Id);
    }

    [Fact]
    public async Task Moving_within_the_same_group_is_a_no_op()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        var alice = h.AddUser("alice");
        var group = await h.Groups.CreateAsync("Engineering", null, admin.Id);
        await h.Groups.AddMemberAsync(group.Id, alice.Id, admin.Id);

        await h.Groups.MoveMemberAsync(group.Id, group.Id, alice.Id, admin.Id);

        Assert.Single(await h.Groups.GetGroupsForUserAsync(alice.Id));
    }

    [Fact]
    public async Task Membership_changes_are_audited()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        var alice = h.AddUser("alice");
        var group = await h.Groups.CreateAsync("Engineering", null, admin.Id);

        await h.Groups.AddMemberAsync(group.Id, alice.Id, admin.Id);
        await h.Groups.RemoveMemberAsync(group.Id, alice.Id, admin.Id);

        var actions = await h.Db.AuditLog.OrderBy(e => e.Id).Select(e => e.Action).ToListAsync();
        Assert.Equal(["group.create", "group.member_add", "group.member_remove"], actions);
        Assert.True((await h.Audit.VerifyAsync()).IsValid);
    }
}

/// <summary>
/// The security-relevant part of group membership: what a member can and cannot read.
/// </summary>
public class GroupHistoryVisibilityTests
{
    [Fact]
    public async Task A_new_member_cannot_read_discussion_that_predates_them()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var group = await h.Groups.CreateAsync("Engineering", null, admin.Id);
        var conversation = group.ConversationId!.Value;

        await h.Groups.AddMemberAsync(group.Id, alice.Id, admin.Id);
        await h.Messages.SendAsync(alice.Id,
            new SendMessageRequest(conversation, Guid.NewGuid(), "before bob joined", h.Time.GetUtcNow()));

        await h.Groups.AddMemberAsync(group.Id, bob.Id, admin.Id);
        await h.Messages.SendAsync(alice.Id,
            new SendMessageRequest(conversation, Guid.NewGuid(), "after bob joined", h.Time.GetUtcNow()));

        var bobsView = await h.Messages.GetHistoryAsync(bob.Id, conversation);

        Assert.Single(bobsView);
        Assert.Equal("after bob joined", bobsView[0].Body);
    }

    /// <summary>
    /// The window is applied in the query, so paging back explicitly cannot reach around it.
    /// </summary>
    [Fact]
    public async Task A_new_member_cannot_page_back_past_their_join_point()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var group = await h.Groups.CreateAsync("Engineering", null, admin.Id);
        var conversation = group.ConversationId!.Value;

        await h.Groups.AddMemberAsync(group.Id, alice.Id, admin.Id);
        for (int i = 0; i < 5; i++)
            await h.Messages.SendAsync(alice.Id,
                new SendMessageRequest(conversation, Guid.NewGuid(), $"secret {i}", h.Time.GetUtcNow()));

        await h.Groups.AddMemberAsync(group.Id, bob.Id, admin.Id);

        // Explicitly asking from the very beginning must still yield nothing.
        Assert.Empty(await h.Messages.GetHistoryAsync(bob.Id, conversation, afterSeq: 0));
    }

    [Fact]
    public async Task A_removed_member_keeps_what_they_saw_but_gains_nothing_after()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var group = await h.Groups.CreateAsync("Engineering", null, admin.Id);
        var conversation = group.ConversationId!.Value;

        await h.Groups.AddMemberAsync(group.Id, alice.Id, admin.Id);
        await h.Groups.AddMemberAsync(group.Id, bob.Id, admin.Id);
        await h.Messages.SendAsync(alice.Id,
            new SendMessageRequest(conversation, Guid.NewGuid(), "bob was here", h.Time.GetUtcNow()));

        await h.Groups.RemoveMemberAsync(group.Id, bob.Id, admin.Id);
        await h.Messages.SendAsync(alice.Id,
            new SendMessageRequest(conversation, Guid.NewGuid(), "after bob left", h.Time.GetUtcNow()));

        var bobsView = await h.Messages.GetHistoryAsync(bob.Id, conversation);

        Assert.Single(bobsView);
        Assert.Equal("bob was here", bobsView[0].Body);
    }

    [Fact]
    public async Task A_removed_member_cannot_send()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        var alice = h.AddUser("alice");
        var group = await h.Groups.CreateAsync("Engineering", null, admin.Id);
        await h.Groups.AddMemberAsync(group.Id, alice.Id, admin.Id);
        await h.Groups.RemoveMemberAsync(group.Id, alice.Id, admin.Id);

        var ex = await Assert.ThrowsAsync<MessengerException>(() => h.Messages.SendAsync(
            alice.Id, new SendMessageRequest(group.ConversationId!.Value, Guid.NewGuid(), "still here?", h.Time.GetUtcNow())));
        Assert.Equal(ErrorCode.NotAConversationParticipant, ex.Code);
    }

    [Fact]
    public async Task A_removed_member_stops_receiving_undelivered_backlog()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var group = await h.Groups.CreateAsync("Engineering", null, admin.Id);
        var conversation = group.ConversationId!.Value;
        await h.Groups.AddMemberAsync(group.Id, alice.Id, admin.Id);
        await h.Groups.AddMemberAsync(group.Id, bob.Id, admin.Id);

        // Sent while bob is offline, so it is queued rather than delivered.
        await h.Messages.SendAsync(alice.Id,
            new SendMessageRequest(conversation, Guid.NewGuid(), "queued for bob", h.Time.GetUtcNow()));
        Assert.Single(await h.Messages.GetPendingBacklogAsync(bob.Id));

        await h.Groups.RemoveMemberAsync(group.Id, bob.Id, admin.Id);

        // Removal must not leave a message in flight that lands after he was removed.
        Assert.Empty(await h.Messages.GetPendingBacklogAsync(bob.Id));
    }

    /// <summary>
    /// Rejoining reopens the window from the return point. Restoring the original window
    /// would retroactively expose everything said while they were out of the group.
    /// </summary>
    [Fact]
    public async Task Rejoining_does_not_expose_the_period_of_absence()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var group = await h.Groups.CreateAsync("Engineering", null, admin.Id);
        var conversation = group.ConversationId!.Value;

        await h.Groups.AddMemberAsync(group.Id, alice.Id, admin.Id);
        await h.Groups.AddMemberAsync(group.Id, bob.Id, admin.Id);
        await h.Messages.SendAsync(alice.Id,
            new SendMessageRequest(conversation, Guid.NewGuid(), "bob present", h.Time.GetUtcNow()));

        await h.Groups.RemoveMemberAsync(group.Id, bob.Id, admin.Id);
        await h.Messages.SendAsync(alice.Id,
            new SendMessageRequest(conversation, Guid.NewGuid(), "bob absent", h.Time.GetUtcNow()));

        await h.Groups.AddMemberAsync(group.Id, bob.Id, admin.Id);
        await h.Messages.SendAsync(alice.Id,
            new SendMessageRequest(conversation, Guid.NewGuid(), "bob back", h.Time.GetUtcNow()));

        var bodies = (await h.Messages.GetHistoryAsync(bob.Id, conversation)).Select(m => m.Body).ToList();

        Assert.Equal(["bob back"], bodies);
    }

    [Fact]
    public async Task A_non_member_still_gets_a_participation_error()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        var mallory = h.AddUser("mallory");
        var group = await h.Groups.CreateAsync("Engineering", null, admin.Id);

        var ex = await Assert.ThrowsAsync<MessengerException>(
            () => h.Messages.GetHistoryAsync(mallory.Id, group.ConversationId!.Value));
        Assert.Equal(ErrorCode.NotAConversationParticipant, ex.Code);
    }

    [Fact]
    public async Task Direct_conversations_remain_fully_visible_to_both_parties()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var c = await h.Messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);

        for (int i = 0; i < 3; i++)
            await h.Messages.SendAsync(alice.Id,
                new SendMessageRequest(c.Id, Guid.NewGuid(), $"m{i}", h.Time.GetUtcNow()));

        // The window machinery must not accidentally clip 1:1 history.
        Assert.Equal(3, (await h.Messages.GetHistoryAsync(bob.Id, c.Id)).Count);
    }
}

public class GroupStatusTests
{
    [Fact]
    public async Task A_deactivated_group_refuses_new_messages()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        var alice = h.AddUser("alice");
        var group = await h.Groups.CreateAsync("Engineering", null, admin.Id);
        await h.Groups.AddMemberAsync(group.Id, alice.Id, admin.Id);

        await h.Groups.SetStatusAsync(group.Id, GroupStatus.Disabled, admin.Id);

        var ex = await Assert.ThrowsAsync<MessengerException>(() => h.Messages.SendAsync(
            alice.Id, new SendMessageRequest(group.ConversationId!.Value, Guid.NewGuid(), "hello?", h.Time.GetUtcNow())));
        Assert.Equal(ErrorCode.GroupDisabled, ex.Code);
    }

    [Fact]
    public async Task A_deactivated_group_keeps_its_history_readable()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        var alice = h.AddUser("alice");
        var group = await h.Groups.CreateAsync("Engineering", null, admin.Id);
        await h.Groups.AddMemberAsync(group.Id, alice.Id, admin.Id);
        await h.Messages.SendAsync(alice.Id,
            new SendMessageRequest(group.ConversationId!.Value, Guid.NewGuid(), "recorded", h.Time.GetUtcNow()));

        await h.Groups.SetStatusAsync(group.Id, GroupStatus.Disabled, admin.Id);

        Assert.Single(await h.Messages.GetHistoryAsync(alice.Id, group.ConversationId!.Value));
    }

    [Fact]
    public async Task Reactivation_restores_sending()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        var alice = h.AddUser("alice");
        var group = await h.Groups.CreateAsync("Engineering", null, admin.Id);
        await h.Groups.AddMemberAsync(group.Id, alice.Id, admin.Id);

        await h.Groups.SetStatusAsync(group.Id, GroupStatus.Disabled, admin.Id);
        await h.Groups.SetStatusAsync(group.Id, GroupStatus.Active, admin.Id);

        await h.Messages.SendAsync(alice.Id,
            new SendMessageRequest(group.ConversationId!.Value, Guid.NewGuid(), "back", h.Time.GetUtcNow()));

        Assert.Single(await h.Messages.GetHistoryAsync(alice.Id, group.ConversationId!.Value));
    }
}

public class GroupMessagingTests
{
    [Fact]
    public async Task Every_other_member_gets_a_delivery_row()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var carol = h.AddUser("carol");
        var group = await h.Groups.CreateAsync("Engineering", null, admin.Id);

        foreach (var u in new[] { alice, bob, carol })
            await h.Groups.AddMemberAsync(group.Id, u.Id, admin.Id);

        var ack = await h.Messages.SendAsync(alice.Id,
            new SendMessageRequest(group.ConversationId!.Value, Guid.NewGuid(), "standup at 10", h.Time.GetUtcNow()));

        var recipients = await h.Db.MessageRecipients.Where(r => r.MessageId == ack.MessageId).ToListAsync();
        Assert.Equal(2, recipients.Count);
        Assert.DoesNotContain(alice.Id, recipients.Select(r => r.UserId));
    }

    [Fact]
    public async Task Presence_is_visible_to_group_peers()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var stranger = h.AddUser("stranger");
        var group = await h.Groups.CreateAsync("Engineering", null, admin.Id);
        await h.Groups.AddMemberAsync(group.Id, alice.Id, admin.Id);
        await h.Groups.AddMemberAsync(group.Id, bob.Id, admin.Id);

        var visibleTo = await h.Presence.GetVisibleToAsync(alice.Id);

        Assert.Contains(bob.Id, visibleTo);
        Assert.DoesNotContain(stranger.Id, visibleTo);
    }

    [Fact]
    public async Task Presence_stops_being_shared_after_removal()
    {
        using var h = new TestHarness();
        var admin = h.AddUser("admin");
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var group = await h.Groups.CreateAsync("Engineering", null, admin.Id);
        await h.Groups.AddMemberAsync(group.Id, alice.Id, admin.Id);
        await h.Groups.AddMemberAsync(group.Id, bob.Id, admin.Id);

        await h.Groups.RemoveMemberAsync(group.Id, bob.Id, admin.Id);

        Assert.DoesNotContain(bob.Id, await h.Presence.GetVisibleToAsync(alice.Id));
    }
}
