using Messenger.Contracts;
using Messenger.Core;
using Messenger.Data;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace Messenger.Core.Tests;

public class DirectConversationTests
{
    [Fact]
    public async Task Creates_a_conversation_with_both_participants()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");

        var conversation = await h.Messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);

        Assert.Equal(ConversationType.Direct, conversation.Type);
        var participants = await h.Messages.GetParticipantIdsAsync(conversation.Id);
        Assert.Equal(2, participants.Count);
        Assert.Contains(alice.Id, participants);
        Assert.Contains(bob.Id, participants);
    }

    [Fact]
    public async Task Is_idempotent_regardless_of_argument_order()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");

        var first = await h.Messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);
        var second = await h.Messages.GetOrCreateDirectConversationAsync(bob.Id, alice.Id);

        Assert.Equal(first.Id, second.Id);
        Assert.Equal(1, await h.Db.Conversations.CountAsync());
    }

    [Fact]
    public async Task Refuses_a_conversation_with_oneself()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");

        var ex = await Assert.ThrowsAsync<MessengerException>(
            () => h.Messages.GetOrCreateDirectConversationAsync(alice.Id, alice.Id));
        Assert.Equal(ErrorCode.MalformedRequest, ex.Code);
    }

    [Fact]
    public void Direct_key_is_order_independent()
    {
        var a = Guid.NewGuid();
        var b = Guid.NewGuid();
        Assert.Equal(Conversation.BuildDirectKey(a, b), Conversation.BuildDirectKey(b, a));
    }
}

public class SendMessageTests
{
    [Fact]
    public async Task Roundtrips_a_message_through_encryption()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var c = await h.Messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);

        await h.Messages.SendAsync(alice.Id,
            new SendMessageRequest(c.Id, Guid.NewGuid(), "Budget approved.", h.Time.GetUtcNow()));

        var history = await h.Messages.GetHistoryAsync(bob.Id, c.Id);
        Assert.Single(history);
        Assert.Equal("Budget approved.", history[0].Body);
        Assert.Equal(alice.Id, history[0].SenderId);
    }

    [Fact]
    public async Task Stores_only_ciphertext_in_the_database()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var c = await h.Messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);

        await h.Messages.SendAsync(alice.Id,
            new SendMessageRequest(c.Id, Guid.NewGuid(), "PLAINTEXT-MARKER", h.Time.GetUtcNow()));

        var stored = await h.Db.Messages.AsNoTracking().SingleAsync();
        Assert.DoesNotContain("PLAINTEXT-MARKER", System.Text.Encoding.UTF8.GetString(stored.Ciphertext));
        Assert.Equal(12, stored.Nonce.Length);
        Assert.Equal(16, stored.AuthTag.Length);
    }

    [Fact]
    public async Task Assigns_monotonic_sequence_numbers()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var c = await h.Messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);

        var acks = new List<SendMessageAck>();
        for (int i = 0; i < 5; i++)
            acks.Add(await h.Messages.SendAsync(alice.Id,
                new SendMessageRequest(c.Id, Guid.NewGuid(), $"message {i}", h.Time.GetUtcNow())));

        Assert.Equal([1L, 2, 3, 4, 5], acks.Select(a => a.Seq));
    }

    /// <summary>
    /// The at-least-once delivery contract depends on this: a client that retries after a
    /// lost ack must not produce a duplicate message.
    /// </summary>
    [Fact]
    public async Task Retrying_with_the_same_client_id_returns_the_original_ack()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var c = await h.Messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);

        var clientId = Guid.NewGuid();
        var request = new SendMessageRequest(c.Id, clientId, "sent once", h.Time.GetUtcNow());

        var first = await h.Messages.SendAsync(alice.Id, request);
        var retry = await h.Messages.SendAsync(alice.Id, request);

        Assert.Equal(first.MessageId, retry.MessageId);
        Assert.Equal(first.Seq, retry.Seq);
        Assert.Equal(1, await h.Db.Messages.CountAsync());
    }

    [Fact]
    public async Task Two_senders_may_reuse_the_same_client_message_id()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var c = await h.Messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);

        var shared = Guid.NewGuid();
        await h.Messages.SendAsync(alice.Id, new SendMessageRequest(c.Id, shared, "from alice", h.Time.GetUtcNow()));
        await h.Messages.SendAsync(bob.Id, new SendMessageRequest(c.Id, shared, "from bob", h.Time.GetUtcNow()));

        // Idempotency is scoped per sender; a collision across senders is not a duplicate.
        Assert.Equal(2, await h.Db.Messages.CountAsync());
    }

    [Fact]
    public async Task Refuses_a_send_from_a_non_participant()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var mallory = h.AddUser("mallory");
        var c = await h.Messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);

        var ex = await Assert.ThrowsAsync<MessengerException>(() => h.Messages.SendAsync(
            mallory.Id, new SendMessageRequest(c.Id, Guid.NewGuid(), "intruding", h.Time.GetUtcNow())));

        Assert.Equal(ErrorCode.NotAConversationParticipant, ex.Code);
    }

    [Fact]
    public async Task Refuses_history_to_a_non_participant()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var mallory = h.AddUser("mallory");
        var c = await h.Messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);
        await h.Messages.SendAsync(alice.Id, new SendMessageRequest(c.Id, Guid.NewGuid(), "private", h.Time.GetUtcNow()));

        // Knowing the conversation id must convey no authority over it.
        var ex = await Assert.ThrowsAsync<MessengerException>(
            () => h.Messages.GetHistoryAsync(mallory.Id, c.Id));
        Assert.Equal(ErrorCode.NotAConversationParticipant, ex.Code);
    }

    [Fact]
    public async Task Rejects_an_oversized_message()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var c = await h.Messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);

        var oversized = new string('x', MessageService.MaxMessageBytes + 1);

        var ex = await Assert.ThrowsAsync<MessengerException>(() => h.Messages.SendAsync(
            alice.Id, new SendMessageRequest(c.Id, Guid.NewGuid(), oversized, h.Time.GetUtcNow())));
        Assert.Equal(ErrorCode.MessageTooLarge, ex.Code);
    }

    [Fact]
    public async Task Server_timestamp_is_authoritative_over_a_skewed_client_clock()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var c = await h.Messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);

        // A hostile or skewed client claims a send time far in the past.
        var skewed = h.Time.GetUtcNow().AddYears(-5);
        await h.Messages.SendAsync(alice.Id, new SendMessageRequest(c.Id, Guid.NewGuid(), "first", skewed));
        await h.Messages.SendAsync(bob.Id, new SendMessageRequest(c.Id, Guid.NewGuid(), "second", h.Time.GetUtcNow()));

        var history = await h.Messages.GetHistoryAsync(alice.Id, c.Id);

        // Ordering follows server-assigned seq, so the claimed timestamp cannot reorder it.
        Assert.Equal("first", history[0].Body);
        Assert.Equal("second", history[1].Body);
        Assert.Equal(skewed, history[0].SentAt);
        Assert.Equal(h.Time.GetUtcNow(), history[0].ServerReceivedAt);
    }
}

public class StoreAndForwardTests
{
    [Fact]
    public async Task Queues_messages_for_an_offline_recipient()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var c = await h.Messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);

        await h.Messages.SendAsync(alice.Id, new SendMessageRequest(c.Id, Guid.NewGuid(), "while you were out", h.Time.GetUtcNow()));

        var backlog = await h.Messages.GetPendingBacklogAsync(bob.Id);
        Assert.Single(backlog);
        Assert.Equal("while you were out", backlog[0].Body);
    }

    [Fact]
    public async Task Sender_has_no_backlog_of_their_own_messages()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var c = await h.Messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);

        await h.Messages.SendAsync(alice.Id, new SendMessageRequest(c.Id, Guid.NewGuid(), "hello", h.Time.GetUtcNow()));

        Assert.Empty(await h.Messages.GetPendingBacklogAsync(alice.Id));
    }

    [Fact]
    public async Task Acknowledging_delivery_clears_the_backlog()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var c = await h.Messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);
        var ack = await h.Messages.SendAsync(alice.Id, new SendMessageRequest(c.Id, Guid.NewGuid(), "delivered", h.Time.GetUtcNow()));

        Assert.True(await h.Messages.MarkDeliveredAsync(bob.Id, ack.MessageId));

        Assert.Empty(await h.Messages.GetPendingBacklogAsync(bob.Id));
    }

    [Fact]
    public async Task Delivery_acknowledgement_is_idempotent()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var c = await h.Messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);
        var ack = await h.Messages.SendAsync(alice.Id, new SendMessageRequest(c.Id, Guid.NewGuid(), "x", h.Time.GetUtcNow()));

        Assert.True(await h.Messages.MarkDeliveredAsync(bob.Id, ack.MessageId));
        Assert.False(await h.Messages.MarkDeliveredAsync(bob.Id, ack.MessageId));
    }

    [Fact]
    public async Task Backlog_survives_a_restart_because_it_is_persisted_state()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var c = await h.Messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);
        await h.Messages.SendAsync(alice.Id, new SendMessageRequest(c.Id, Guid.NewGuid(), "queued", h.Time.GetUtcNow()));

        // Drop all tracked state, as a process restart would.
        h.Db.ChangeTracker.Clear();

        var backlog = await h.Messages.GetPendingBacklogAsync(bob.Id);
        Assert.Single(backlog);
    }
}

public class ReceiptTests
{
    [Fact]
    public async Task Marks_read_and_advances_the_read_watermark()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var c = await h.Messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);
        var ack = await h.Messages.SendAsync(alice.Id, new SendMessageRequest(c.Id, Guid.NewGuid(), "read me", h.Time.GetUtcNow()));

        Assert.True(await h.Messages.MarkReadAsync(bob.Id, ack.MessageId));

        var recipient = await h.Db.MessageRecipients.SingleAsync(r => r.UserId == bob.Id);
        Assert.Equal(DeliveryState.Read, recipient.State);
        Assert.NotNull(recipient.ReadAt);

        var participant = await h.Db.ConversationParticipants.SingleAsync(p => p.UserId == bob.Id);
        Assert.Equal(ack.Seq, participant.LastReadSeq);
    }

    /// <summary>
    /// When receipts are disabled the timestamp must not merely be hidden — it must never be
    /// written. An organisation that treats receipts as surveillance is not satisfied by
    /// "recorded but not displayed".
    /// </summary>
    [Fact]
    public async Task Disabled_receipts_never_write_a_read_timestamp()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var c = await h.Messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);
        var ack = await h.Messages.SendAsync(alice.Id, new SendMessageRequest(c.Id, Guid.NewGuid(), "read me", h.Time.GetUtcNow()));

        Assert.False(await h.Messages.MarkReadAsync(bob.Id, ack.MessageId, receiptsEnabled: false));

        var recipient = await h.Db.MessageRecipients.SingleAsync(r => r.UserId == bob.Id);
        Assert.Null(recipient.ReadAt);
        Assert.Equal(DeliveryState.Delivered, recipient.State);
    }
}

public class KeyRotationTests
{
    [Fact]
    public async Task Reuses_one_conversation_key_across_messages()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var c = await h.Messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);

        for (int i = 0; i < 3; i++)
            await h.Messages.SendAsync(alice.Id, new SendMessageRequest(c.Id, Guid.NewGuid(), $"m{i}", h.Time.GetUtcNow()));

        Assert.Equal(1, await h.Db.ConversationKeys.CountAsync());
        Assert.Equal(3, await h.Db.ConversationKeys.Select(k => k.MessageCount).SingleAsync());
    }

    [Fact]
    public async Task History_stays_readable_across_a_key_rotation()
    {
        using var h = new TestHarness();
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var c = await h.Messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);

        await h.Messages.SendAsync(alice.Id, new SendMessageRequest(c.Id, Guid.NewGuid(), "before rotation", h.Time.GetUtcNow()));

        // Force the rotation trigger rather than sending 16 million messages.
        var key = await h.Db.ConversationKeys.SingleAsync();
        key.MessageCount = MessageService.KeyRotationMessageCount;
        await h.Db.SaveChangesAsync();

        await h.Messages.SendAsync(alice.Id, new SendMessageRequest(c.Id, Guid.NewGuid(), "after rotation", h.Time.GetUtcNow()));

        Assert.Equal(2, await h.Db.ConversationKeys.CountAsync());

        // The retired key must be kept, or all history before rotation becomes unreadable.
        var history = await h.Messages.GetHistoryAsync(bob.Id, c.Id);
        Assert.Equal("before rotation", history[0].Body);
        Assert.Equal("after rotation", history[1].Body);
    }
}
