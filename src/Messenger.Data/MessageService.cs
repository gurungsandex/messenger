using System.Security.Cryptography;
using Messenger.Contracts;
using Messenger.Core;
using Messenger.Crypto;
using Microsoft.EntityFrameworkCore;

namespace Messenger.Data;

/// <summary>Whether the licence currently permits new messages, and why not if it does not.</summary>
public sealed record SendGateState(bool AllowsSending, string ErrorCode, string Detail)
{
    public static readonly SendGateState Allowed = new(true, string.Empty, string.Empty);
}

/// <summary>
/// Message send, retrieval, receipts, and store-and-forward backlog.
///
/// Delivery is at-least-once with client-supplied idempotency keys, which yields
/// effectively-once display. Persistence happens before the ack, so an ack always means
/// durable — a crash cannot lose an acknowledged message.
/// </summary>
public sealed class MessageService(
    MessengerDbContext db,
    IKeyStoreProvider keyStore,
    MessageCipher cipher,
    TimeProvider? timeProvider = null)
{
    /// <summary>Rotation trigger. Random 96-bit GCM nonces have a birthday bound well above this.</summary>
    public const long KeyRotationMessageCount = 1 << 24;

    public const int MaxMessageBytes = 64 * 1024;

    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    /// <summary>
    /// Optional licence gate consulted on every send.
    ///
    /// Injected as a delegate rather than a service reference to keep `Messenger.Data` free
    /// of a dependency on licensing internals, and so the messaging tests do not need a
    /// licence installed to send a message.
    /// </summary>
    public Func<CancellationToken, Task<SendGateState>>? LicenseGate { get; set; }

    /// <summary>Finds or creates the 1:1 conversation between two users.</summary>
    public async Task<Conversation> GetOrCreateDirectConversationAsync(
        Guid userA, Guid userB, CancellationToken ct = default)
    {
        if (userA == userB)
            throw new MessengerException(ErrorCode.MalformedRequest,
                "A direct conversation requires two distinct users.");

        var key = Conversation.BuildDirectKey(userA, userB);
        var existing = await db.Conversations
            .Include(c => c.Participants)
            .FirstOrDefaultAsync(c => c.DirectKey == key, ct);
        if (existing is not null) return existing;

        var conversation = new Conversation
        {
            Type = ConversationType.Direct,
            DirectKey = key,
            CreatedAt = _time.GetUtcNow(),
            CreatedBy = userA,
        };
        conversation.Participants.Add(new ConversationParticipant { UserId = userA });
        conversation.Participants.Add(new ConversationParticipant { UserId = userB });

        db.Conversations.Add(conversation);

        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            // Lost the race against a concurrent create; the unique index on direct_key did
            // its job. Re-read rather than surfacing a conflict the caller cannot act on.
            db.ChangeTracker.Clear();
            return await db.Conversations
                .Include(c => c.Participants)
                .FirstAsync(c => c.DirectKey == key, ct);
        }

        return conversation;
    }

    public async Task<SendMessageAck> SendAsync(
        Guid senderId, SendMessageRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (System.Text.Encoding.UTF8.GetByteCount(request.Body) > MaxMessageBytes)
            throw new MessengerException(ErrorCode.MessageTooLarge,
                $"Messages are limited to {MaxMessageBytes} bytes; send larger content as a file.");

        var participants = await db.ConversationParticipants
            .Where(p => p.ConversationId == request.ConversationId && p.LeftAt == null)
            .ToListAsync(ct);

        // Membership is re-checked server-side on every send. A conversation id is never
        // treated as authority on its own.
        if (participants.All(p => p.UserId != senderId))
            throw new MessengerException(ErrorCode.NotAConversationParticipant,
                "You are not a participant in this conversation.");

        // Licence state is re-checked on send, not only at login. Grace mode is defined as
        // "history readable, no new sessions and no new messages" — enforcing it only at
        // login would leave every already-connected client sending indefinitely, so a
        // deployment could run for weeks past expiry without noticing.
        if (LicenseGate is not null)
        {
            var state = await LicenseGate(ct);
            if (!state.AllowsSending)
                throw new MessengerException(state.ErrorCode, state.Detail);
        }

        // A deactivated group stops accepting messages, but its history stays readable and
        // its membership intact, so reactivation loses nothing.
        var owningGroupStatus = await db.Groups
            .Where(g => g.ConversationId == request.ConversationId && g.DeletedAt == null)
            .Select(g => (GroupStatus?)g.Status)
            .FirstOrDefaultAsync(ct);

        if (owningGroupStatus == GroupStatus.Disabled)
            throw new MessengerException(ErrorCode.GroupDisabled,
                "This group is deactivated and is not accepting messages.");

        var recipientIds = participants.Where(p => p.UserId != senderId).Select(p => p.UserId).ToList();

        // Sequence numbers are allocated from the conversation row and made unique by the
        // index on (conversation_id, seq), which two simultaneous senders will contend for:
        // both read the same NextSeq, both insert it, and the loser's insert violates the
        // index. Left unhandled that reaches a legitimate user as a 500 on an ordinary
        // message — and the busier the conversation, the likelier it is.
        //
        // The index is the arbiter rather than an application-level check, so the recovery
        // is to re-read and retry. Each attempt has one winner, so the loop converges; the
        // same pattern guards the direct-conversation create above.
        for (int attempt = 0; ; attempt++)
        {
            var duplicate = await FindByClientIdAsync(senderId, request, ct);
            if (duplicate is not null) return duplicate;

            try
            {
                return await TryAppendAsync(senderId, request, recipientIds, ct);
            }
            catch (Exception ex) when (ex is DbUpdateException or DbUpdateConcurrencyException
                                       && attempt < MaxSequenceAllocationAttempts)
            {
                // Nothing from the failed attempt survives — SaveChanges is transactional, so
                // the message, its delivery rows and the sequence bump all rolled back
                // together. The tracker still holds them, and re-reading with those entries
                // attached would return the stale NextSeq that lost the race.
                db.ChangeTracker.Clear();
            }
        }
    }

    /// <summary>
    /// Bounded so a genuine, non-contention write failure surfaces as itself rather than
    /// spinning. Contention needs far fewer attempts than this: each round has a winner, so
    /// N concurrent senders drain in N rounds even in the worst ordering.
    /// </summary>
    private const int MaxSequenceAllocationAttempts = 8;

    /// <summary>A retry carrying the same client id must return the original ack, not duplicate.</summary>
    private async Task<SendMessageAck?> FindByClientIdAsync(
        Guid senderId, SendMessageRequest request, CancellationToken ct)
    {
        var existing = await db.Messages.FirstOrDefaultAsync(
            m => m.ConversationId == request.ConversationId
                 && m.SenderId == senderId
                 && m.ClientMessageId == request.ClientMessageId, ct);

        return existing is null
            ? null
            : new SendMessageAck(existing.Id, existing.ClientMessageId, existing.Seq, existing.ServerReceivedAt);
    }

    /// <summary>
    /// One attempt at appending: claim the next sequence number, seal the body, and write.
    /// Everything it touches is re-read on entry, so a retry after a lost race works from
    /// the conversation's current state rather than the state that lost.
    /// </summary>
    private async Task<SendMessageAck> TryAppendAsync(
        Guid senderId, SendMessageRequest request, List<Guid> recipientIds, CancellationToken ct)
    {
        var conversation = await db.Conversations.FirstAsync(c => c.Id == request.ConversationId, ct);
        var key = await GetOrCreateActiveKeyAsync(conversation, ct);

        var messageId = Guid.NewGuid();
        var seq = conversation.NextSeq;
        var now = _time.GetUtcNow();

        var dek = keyStore.Unwrap(key.WrappedDek, key.KekId);
        SealedMessage sealedBody;
        try
        {
            sealedBody = cipher.Seal(dek, request.Body, conversation.Id, messageId, senderId, key.Version);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }

        var message = new Message
        {
            Id = messageId,
            ConversationId = conversation.Id,
            Seq = seq,
            SenderId = senderId,
            ClientMessageId = request.ClientMessageId,
            Ciphertext = sealedBody.Ciphertext,
            Nonce = sealedBody.Nonce,
            AuthTag = sealedBody.AuthTag,
            KeyId = key.Id,
            AadVersion = sealedBody.AadVersion,
            SentAt = request.SentAt,
            ServerReceivedAt = now,
        };

        // A delivery row is written for every participant regardless of whether they are
        // online. That is the whole of store-and-forward: the backlog is a query over
        // persisted state, so a server restart loses nothing.
        foreach (var recipientId in recipientIds)
            message.Recipients.Add(new MessageRecipient { UserId = recipientId, State = DeliveryState.Pending });

        conversation.NextSeq = seq + 1;
        conversation.LastMessageAt = now;
        key.MessageCount++;

        db.Messages.Add(message);
        await db.SaveChangesAsync(ct);

        return new SendMessageAck(message.Id, message.ClientMessageId, message.Seq, message.ServerReceivedAt);
    }

    public async Task<IReadOnlyList<MessageDto>> GetHistoryAsync(
        Guid userId, Guid conversationId, long afterSeq = 0, int limit = 50, CancellationToken ct = default)
    {
        var window = await RequireVisibilityWindowAsync(userId, conversationId, ct);

        limit = Math.Clamp(limit, 1, 200);

        // The visibility window is applied in the query, not filtered afterwards. A member
        // added to a group today must not be able to page back into discussion that
        // predates them, and a removed member must not see anything after they left.
        var lowerBound = Math.Max(afterSeq, window.FromSeq - 1);

        var query = db.Messages
            .Where(m => m.ConversationId == conversationId && m.Seq > lowerBound);

        if (window.ToSeq is { } upper)
            query = query.Where(m => m.Seq <= upper);

        var messages = await query
            .OrderBy(m => m.Seq)
            .Take(limit)
            .ToListAsync(ct);

        return await DecryptAsync(messages, ct);
    }

    /// <summary>
    /// The store-and-forward backlog: everything still pending for this user.
    ///
    /// Ordered by (conversation, seq) rather than by wall-clock arrival. The ordering
    /// guarantee this system makes is per-conversation — there is deliberately no global
    /// order across conversations — so sequencing within each conversation is what a client
    /// actually needs to replay correctly. Bounded, so a user returning after a long absence
    /// cannot force an unbounded read.
    /// </summary>
    public async Task<IReadOnlyList<MessageDto>> GetPendingBacklogAsync(
        Guid userId, int limit = 200, CancellationToken ct = default)
    {
        limit = Math.Clamp(limit, 1, 500);

        var messages = await db.MessageRecipients
            .Where(r => r.UserId == userId && r.State == DeliveryState.Pending)
            .Join(db.Messages, r => r.MessageId, m => m.Id, (_, m) => m)
            .OrderBy(m => m.ConversationId).ThenBy(m => m.Seq)
            .Take(limit)
            .ToListAsync(ct);

        return await DecryptAsync(messages, ct);
    }

    public async Task<bool> MarkDeliveredAsync(Guid userId, Guid messageId, CancellationToken ct = default)
    {
        var recipient = await db.MessageRecipients
            .FirstOrDefaultAsync(r => r.MessageId == messageId && r.UserId == userId, ct);
        if (recipient is null || recipient.State != DeliveryState.Pending) return false;

        recipient.State = DeliveryState.Delivered;
        recipient.DeliveredAt = _time.GetUtcNow();
        await db.SaveChangesAsync(ct);
        return true;
    }

    /// <summary>
    /// Marks read. When read receipts are disabled org-wide, <c>read_at</c> is never written
    /// rather than merely hidden — the record simply does not exist.
    /// </summary>
    public async Task<bool> MarkReadAsync(
        Guid userId, Guid messageId, bool receiptsEnabled = true, CancellationToken ct = default)
    {
        var recipient = await db.MessageRecipients
            .FirstOrDefaultAsync(r => r.MessageId == messageId && r.UserId == userId, ct);
        if (recipient is null || recipient.State == DeliveryState.Read) return false;

        var now = _time.GetUtcNow();
        recipient.DeliveredAt ??= now;

        if (receiptsEnabled)
        {
            recipient.State = DeliveryState.Read;
            recipient.ReadAt = now;
        }
        else
        {
            recipient.State = DeliveryState.Delivered;
        }

        var message = await db.Messages.FirstAsync(m => m.Id == messageId, ct);
        var participant = await db.ConversationParticipants
            .FirstOrDefaultAsync(p => p.ConversationId == message.ConversationId && p.UserId == userId, ct);
        if (participant is not null && message.Seq > participant.LastReadSeq)
            participant.LastReadSeq = message.Seq;

        await db.SaveChangesAsync(ct);
        return receiptsEnabled;
    }

    public async Task<IReadOnlyList<Guid>> GetParticipantIdsAsync(Guid conversationId, CancellationToken ct = default)
        => await db.ConversationParticipants
            .Where(p => p.ConversationId == conversationId && p.LeftAt == null)
            .Select(p => p.UserId)
            .ToListAsync(ct);

    public async Task<Guid?> GetSenderIdAsync(Guid messageId, CancellationToken ct = default)
        => await db.Messages.Where(m => m.Id == messageId).Select(m => (Guid?)m.SenderId).FirstOrDefaultAsync(ct);

    private async Task<IReadOnlyList<MessageDto>> DecryptAsync(List<Message> messages, CancellationToken ct)
    {
        if (messages.Count == 0) return [];

        var keyIds = messages.Select(m => m.KeyId).Distinct().ToList();
        var keys = await db.ConversationKeys.Where(k => keyIds.Contains(k.Id)).ToDictionaryAsync(k => k.Id, ct);

        var senderIds = messages.Select(m => m.SenderId).Distinct().ToList();
        var senders = await db.Users.Where(u => senderIds.Contains(u.Id))
            .ToDictionaryAsync(u => u.Id, u => u.DisplayName, ct);

        // Unwrap each distinct DEK once rather than per message.
        var deks = new Dictionary<Guid, byte[]>();
        try
        {
            var result = new List<MessageDto>(messages.Count);
            foreach (var m in messages)
            {
                var key = keys[m.KeyId];
                if (!deks.TryGetValue(m.KeyId, out var dek))
                {
                    dek = keyStore.Unwrap(key.WrappedDek, key.KekId);
                    deks[m.KeyId] = dek;
                }

                var body = m.DeletedAt is not null
                    ? string.Empty
                    : cipher.Open(dek,
                        new SealedMessage(m.Ciphertext, m.Nonce, m.AuthTag, m.AadVersion),
                        m.ConversationId, m.Id, m.SenderId, key.Version);

                result.Add(new MessageDto(
                    m.Id, m.ConversationId, m.Seq, m.SenderId,
                    senders.GetValueOrDefault(m.SenderId, "(unknown)"),
                    body, m.SentAt, m.ServerReceivedAt, m.DeletedAt is not null));
            }
            return result;
        }
        finally
        {
            foreach (var dek in deks.Values) CryptographicOperations.ZeroMemory(dek);
        }
    }

    private async Task<ConversationKey> GetOrCreateActiveKeyAsync(Conversation conversation, CancellationToken ct)
    {
        var active = await db.ConversationKeys
            .Where(k => k.ConversationId == conversation.Id && k.RetiredAt == null)
            .OrderByDescending(k => k.Version)
            .FirstOrDefaultAsync(ct);

        if (active is not null && active.MessageCount < KeyRotationMessageCount)
            return active;

        if (active is not null)
        {
            active.RetiredAt = _time.GetUtcNow();
            // Retired keys are kept, not destroyed — history stays readable because each
            // message records the key version it was sealed under.
        }

        var dek = RandomNumberGenerator.GetBytes(32);
        ConversationKey created;
        try
        {
            created = new ConversationKey
            {
                ConversationId = conversation.Id,
                Version = (active?.Version ?? 0) + 1,
                WrappedDek = keyStore.Wrap(dek),
                KekId = keyStore.ActiveKekId,
                CreatedAt = _time.GetUtcNow(),
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }

        db.ConversationKeys.Add(created);
        await db.SaveChangesAsync(ct);
        return created;
    }

    /// <summary>
    /// The range of sequence numbers a user may read in a conversation. A departed member
    /// still has a window — what they legitimately saw — so this deliberately does not
    /// filter on <c>LeftAt == null</c>.
    /// </summary>
    private async Task<(long FromSeq, long? ToSeq)> RequireVisibilityWindowAsync(
        Guid userId, Guid conversationId, CancellationToken ct)
    {
        var window = await db.ConversationParticipants
            .Where(p => p.ConversationId == conversationId && p.UserId == userId)
            .Select(p => new { p.VisibleFromSeq, p.VisibleToSeq })
            .FirstOrDefaultAsync(ct);

        if (window is null)
            throw new MessengerException(ErrorCode.NotAConversationParticipant,
                "You are not a participant in this conversation.");

        return (window.VisibleFromSeq, window.VisibleToSeq);
    }
}
