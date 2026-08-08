using Messenger.Contracts;
using Messenger.Core;
using Microsoft.EntityFrameworkCore;

namespace Messenger.Data;

/// <summary>
/// Group lifecycle and membership, and the conversation participation that follows from it.
///
/// Membership changes are never destructive to history: removing a member closes their
/// visibility window rather than deleting their participation row, so their own record of
/// what they saw survives and the audit trail stays intact.
/// </summary>
public sealed class GroupService(
    MessengerDbContext db,
    AuditService audit,
    TimeProvider? timeProvider = null)
{
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    public async Task<Group> CreateAsync(
        string name, string? description, Guid actorId,
        GroupType type = GroupType.Chat, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new MessengerException(ErrorCode.MalformedRequest, "Group name is required.");

        if (await db.Groups.AnyAsync(g => g.Name == name && g.DeletedAt == null, ct))
            throw new MessengerException(ErrorCode.GroupAlreadyExists, $"A group named '{name}' already exists.");

        var now = _time.GetUtcNow();
        var group = new Group
        {
            Name = name,
            Description = description,
            Type = type,
            CreatedAt = now,
            CreatedBy = actorId,
        };

        // Only chat groups get a conversation. AD security and distribution groups are
        // identity constructs, and giving each one a chat room would create thousands of
        // empty conversations on first sync.
        if (type == GroupType.Chat)
        {
            var conversation = new Conversation
            {
                Type = ConversationType.Group,
                Title = name,
                CreatedAt = now,
                CreatedBy = actorId,
            };
            db.Conversations.Add(conversation);
            group.ConversationId = conversation.Id;
        }

        db.Groups.Add(group);

        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            // Lost the race against a concurrent create of the same name; the unique index
            // on (name, deleted_at IS NULL) did its job. Report it as the same conflict the
            // upfront check reports, rather than an opaque 500.
            throw new MessengerException(ErrorCode.GroupAlreadyExists, $"A group named '{name}' already exists.");
        }

        await audit.AppendAsync("group.create", "success", actorId, "admin", null,
            "group", group.Id, $"{{\"name\":{System.Text.Json.JsonSerializer.Serialize(name)}}}", ct);

        return group;
    }

    public async Task RenameAsync(Guid groupId, string newName, Guid actorId, CancellationToken ct = default)
    {
        var group = await RequireGroupAsync(groupId, ct);

        if (group.Source == UserSource.ActiveDirectory)
            throw new MessengerException(ErrorCode.DirectoryOwnedAttribute,
                "This group is synced from Active Directory; rename it there instead.");

        if (await db.Groups.AnyAsync(g => g.Name == newName && g.Id != groupId && g.DeletedAt == null, ct))
            throw new MessengerException(ErrorCode.GroupAlreadyExists, $"A group named '{newName}' already exists.");

        var previous = group.Name;
        group.Name = newName;
        group.UpdatedAt = _time.GetUtcNow();
        group.UpdatedBy = actorId;

        if (group.ConversationId is { } conversationId)
        {
            var conversation = await db.Conversations.FirstAsync(c => c.Id == conversationId, ct);
            conversation.Title = newName;
        }

        await db.SaveChangesAsync(ct);
        await audit.AppendAsync("group.rename", "success", actorId, "admin", null, "group", groupId,
            $"{{\"from\":{System.Text.Json.JsonSerializer.Serialize(previous)},\"to\":{System.Text.Json.JsonSerializer.Serialize(newName)}}}", ct);
    }

    /// <summary>
    /// Adds a user to a group and, for chat groups, to its conversation.
    ///
    /// The new participant's visibility starts at the conversation's current sequence, so
    /// they do not gain retroactive access to discussion that predates their membership.
    /// </summary>
    public async Task AddMemberAsync(
        Guid groupId, Guid userId, Guid actorId,
        GroupMemberRole role = GroupMemberRole.Member, CancellationToken ct = default)
    {
        var group = await RequireGroupAsync(groupId, ct);
        await RequireActiveUserAsync(userId, ct);

        if (await db.GroupMembers.AnyAsync(m => m.GroupId == groupId && m.UserId == userId, ct))
            return; // Idempotent: adding an existing member is not an error.

        var now = _time.GetUtcNow();
        db.GroupMembers.Add(new GroupMember
        {
            GroupId = groupId,
            UserId = userId,
            Role = role,
            AddedAt = now,
            AddedBy = actorId,
        });

        if (group.ConversationId is { } conversationId)
            await JoinConversationAsync(conversationId, userId, now, ct);

        await db.SaveChangesAsync(ct);
        await audit.AppendAsync("group.member_add", "success", actorId, "admin", null,
            "group", groupId, $"{{\"user\":\"{userId:D}\"}}", ct);
    }

    /// <summary>
    /// Removes a user from a group. Their conversation participation is closed rather than
    /// deleted: history they legitimately saw remains theirs, and they see nothing after.
    /// </summary>
    public async Task RemoveMemberAsync(Guid groupId, Guid userId, Guid actorId, CancellationToken ct = default)
    {
        var group = await RequireGroupAsync(groupId, ct);

        var member = await db.GroupMembers.FirstOrDefaultAsync(m => m.GroupId == groupId && m.UserId == userId, ct);
        if (member is null) return;

        db.GroupMembers.Remove(member);

        if (group.ConversationId is { } conversationId)
            await LeaveConversationAsync(conversationId, userId, _time.GetUtcNow(), ct);

        await db.SaveChangesAsync(ct);
        await audit.AppendAsync("group.member_remove", "success", actorId, "admin", null,
            "group", groupId, $"{{\"user\":\"{userId:D}\"}}", ct);
    }

    /// <summary>
    /// Moves a user between groups as one transaction, so they are never briefly in neither
    /// or in both.
    /// </summary>
    public async Task MoveMemberAsync(Guid fromGroupId, Guid toGroupId, Guid userId, Guid actorId, CancellationToken ct = default)
    {
        if (fromGroupId == toGroupId) return;

        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        try
        {
            await RemoveMemberAsync(fromGroupId, userId, actorId, ct);
            await AddMemberAsync(toGroupId, userId, actorId, ct: ct);
            await transaction.CommitAsync(ct);
        }
        catch
        {
            await transaction.RollbackAsync(ct);
            throw;
        }

        await audit.AppendAsync("group.member_move", "success", actorId, "admin", null,
            "group", toGroupId, $"{{\"user\":\"{userId:D}\",\"from\":\"{fromGroupId:D}\"}}", ct);
    }

    /// <summary>
    /// Deactivating a group stops its conversation accepting messages but leaves membership
    /// and history intact, so it can be reversed without data loss.
    /// </summary>
    public async Task SetStatusAsync(Guid groupId, GroupStatus status, Guid actorId, CancellationToken ct = default)
    {
        var group = await RequireGroupAsync(groupId, ct);
        group.Status = status;
        group.UpdatedAt = _time.GetUtcNow();
        group.UpdatedBy = actorId;
        await db.SaveChangesAsync(ct);

        await audit.AppendAsync("group.set_status", "success", actorId, "admin", null,
            "group", groupId, $"{{\"status\":\"{status}\"}}", ct);
    }

    /// <summary>Soft delete. History and audit trail survive; a purge is a separate action.</summary>
    public async Task DeleteAsync(Guid groupId, Guid actorId, CancellationToken ct = default)
    {
        var group = await RequireGroupAsync(groupId, ct);
        var now = _time.GetUtcNow();

        group.DeletedAt = now;
        group.Status = GroupStatus.Disabled;

        if (group.ConversationId is { } conversationId)
        {
            var participants = await db.ConversationParticipants
                .Where(p => p.ConversationId == conversationId && p.LeftAt == null)
                .ToListAsync(ct);
            var lastSeq = await CurrentSeqAsync(conversationId, ct);

            foreach (var p in participants)
            {
                p.LeftAt = now;
                p.VisibleToSeq = lastSeq;
            }
        }

        await db.SaveChangesAsync(ct);
        await audit.AppendAsync("group.delete", "success", actorId, "admin", null, "group", groupId, null, ct);
    }

    public async Task<IReadOnlyList<Guid>> GetMemberIdsAsync(Guid groupId, CancellationToken ct = default)
        => await db.GroupMembers.Where(m => m.GroupId == groupId).Select(m => m.UserId).ToListAsync(ct);

    public async Task<IReadOnlyList<Group>> GetGroupsForUserAsync(Guid userId, CancellationToken ct = default)
        => await db.GroupMembers
            .Where(m => m.UserId == userId)
            .Join(db.Groups.Where(g => g.DeletedAt == null), m => m.GroupId, g => g.Id, (_, g) => g)
            .ToListAsync(ct);

    private async Task JoinConversationAsync(Guid conversationId, Guid userId, DateTimeOffset now, CancellationToken ct)
    {
        var existing = await db.ConversationParticipants
            .FirstOrDefaultAsync(p => p.ConversationId == conversationId && p.UserId == userId, ct);

        var fromSeq = await CurrentSeqAsync(conversationId, ct) + 1;

        if (existing is not null)
        {
            // Rejoining: reopen the window from here rather than restoring their old one,
            // so time spent outside the group does not become visible on return.
            existing.LeftAt = null;
            existing.JoinedAt = now;
            existing.VisibleFromSeq = fromSeq;
            existing.VisibleToSeq = null;
            return;
        }

        db.ConversationParticipants.Add(new ConversationParticipant
        {
            ConversationId = conversationId,
            UserId = userId,
            JoinedAt = now,
            VisibleFromSeq = fromSeq,
            LastReadSeq = fromSeq - 1,
        });
    }

    private async Task LeaveConversationAsync(Guid conversationId, Guid userId, DateTimeOffset now, CancellationToken ct)
    {
        var participant = await db.ConversationParticipants
            .FirstOrDefaultAsync(p => p.ConversationId == conversationId && p.UserId == userId && p.LeftAt == null, ct);
        if (participant is null) return;

        participant.LeftAt = now;
        participant.VisibleToSeq = await CurrentSeqAsync(conversationId, ct);

        // Undelivered messages are dropped: a removed member should not receive backlog
        // that arrives after their removal.
        var pending = await db.MessageRecipients
            .Where(r => r.UserId == userId && r.State == DeliveryState.Pending)
            .Join(db.Messages.Where(m => m.ConversationId == conversationId),
                  r => r.MessageId, m => m.Id, (r, _) => r)
            .ToListAsync(ct);

        db.MessageRecipients.RemoveRange(pending);
    }

    private async Task<long> CurrentSeqAsync(Guid conversationId, CancellationToken ct)
        => (await db.Conversations.Where(c => c.Id == conversationId).Select(c => c.NextSeq).FirstAsync(ct)) - 1;

    private async Task<Group> RequireGroupAsync(Guid groupId, CancellationToken ct)
        => await db.Groups.FirstOrDefaultAsync(g => g.Id == groupId && g.DeletedAt == null, ct)
           ?? throw new MessengerException(ErrorCode.GroupNotFound, "Group not found.");

    private async Task RequireActiveUserAsync(Guid userId, CancellationToken ct)
    {
        var status = await db.Users
            .Where(u => u.Id == userId && u.DeletedAt == null)
            .Select(u => (UserStatus?)u.Status)
            .FirstOrDefaultAsync(ct);

        if (status is null)
            throw new MessengerException(ErrorCode.AccountNotFound, "User not found.");
        if (status == UserStatus.Disabled)
            throw new MessengerException(ErrorCode.AccountDisabled, "Cannot add a disabled user to a group.");
    }
}
