using Messenger.Contracts;
using Messenger.Core;
using Microsoft.EntityFrameworkCore;

namespace Messenger.Data;

/// <summary>
/// Presence tracking. The authoritative copy is in memory on the server; the database row
/// is the restart-recovery mirror and the last-known state for offline users.
/// </summary>
public sealed class PresenceService(MessengerDbContext db, TimeProvider? timeProvider = null)
{
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    /// <summary>
    /// Org-wide read-receipt policy (OD-2). When false, <c>read_at</c> is never written
    /// rather than merely hidden — some organisations treat receipts as surveillance, and
    /// "recorded but not shown" would not satisfy them.
    /// </summary>
    public bool ReadReceiptsEnabled { get; set; } = true;

    public async Task<PresenceDto> SetStatusAsync(
        Guid userId, PresenceStatus status, string? statusMessage, bool isAutoAway,
        CancellationToken ct = default)
    {
        var now = _time.GetUtcNow();
        var row = await db.Presences.FirstOrDefaultAsync(p => p.UserId == userId, ct);

        if (row is null)
        {
            row = new Presence { UserId = userId };
            db.Presences.Add(row);
        }

        row.Status = status;
        row.StatusMessage = statusMessage;
        row.IsAutoAway = isAutoAway;
        row.ChangedAt = now;

        await db.SaveChangesAsync(ct);
        return new PresenceDto(userId, status, statusMessage, isAutoAway, now);
    }

    public async Task<PresenceDto> GetAsync(Guid userId, CancellationToken ct = default)
    {
        var row = await db.Presences.FirstOrDefaultAsync(p => p.UserId == userId, ct);
        return row is null
            ? new PresenceDto(userId, PresenceStatus.Offline, null, false, DateTimeOffset.MinValue)
            : new PresenceDto(userId, row.Status, row.StatusMessage, row.IsAutoAway, row.ChangedAt);
    }

    /// <summary>
    /// Users who may see this user's presence: those sharing at least one conversation.
    /// Presence is deliberately not a directory-wide broadcast.
    /// </summary>
    public async Task<IReadOnlyList<Guid>> GetVisibleToAsync(Guid userId, CancellationToken ct = default)
    {
        var conversationIds = db.ConversationParticipants
            .Where(p => p.UserId == userId && p.LeftAt == null)
            .Select(p => p.ConversationId);

        return await db.ConversationParticipants
            .Where(p => conversationIds.Contains(p.ConversationId) && p.LeftAt == null && p.UserId != userId)
            .Select(p => p.UserId)
            .Distinct()
            .ToListAsync(ct);
    }
}
