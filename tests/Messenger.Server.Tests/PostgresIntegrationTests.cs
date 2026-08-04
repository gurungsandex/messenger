using Messenger.Contracts;
using Npgsql;
using Messenger.Core;
using Messenger.Crypto;
using Messenger.Data;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace Messenger.Server.Tests;

/// <summary>
/// Integration tests against a real PostgreSQL instance — the production provider.
///
/// These exist because the unit suite runs on SQLite, which cannot compare or order
/// <see cref="DateTimeOffset"/> in SQL and therefore cannot exercise the session-expiry and
/// backlog queries as Npgsql actually runs them. A green SQLite suite is not evidence that
/// those queries translate on the real database.
///
/// Skipped when <c>MESSENGER_TEST_CONNECTION</c> is unset, so the suite stays runnable
/// without a database; CI is expected to set it.
/// </summary>
public sealed class PostgresIntegrationTests : IAsyncLifetime
{
    private static string? ConnectionString =>
        Environment.GetEnvironmentVariable("MESSENGER_TEST_CONNECTION");

    private MessengerDbContext _db = null!;
    private PassphraseKeyStoreProvider _keyStore = null!;
    private MessageService _messages = null!;
    private SessionService _sessions = null!;
    private AuditService _audit = null!;
    private string _schema = null!;

    public async Task InitializeAsync()
    {
        if (ConnectionString is null) return;

        // Each run gets its own database rather than its own schema. A schema is not enough:
        // EnsureCreated decides whether to build the model by looking for existing tables,
        // and it finds them in `public` from any prior migration run, so it skips creation
        // and every query then hits a schema with nothing in it.
        _schema = "messenger_test_" + Guid.NewGuid().ToString("N")[..12];

        var admin = new NpgsqlConnectionStringBuilder(ConnectionString) { Database = "postgres" };
        await using (var setup = new NpgsqlConnection(admin.ConnectionString))
        {
            await setup.OpenAsync();
            await using var cmd = setup.CreateCommand();
            cmd.CommandText = $"CREATE DATABASE \"{_schema}\"";
            await cmd.ExecuteNonQueryAsync();
        }

        var scoped = new NpgsqlConnectionStringBuilder(ConnectionString) { Database = _schema };

        var options = new DbContextOptionsBuilder<MessengerDbContext>()
            .UseNpgsql(scoped.ConnectionString)
            .Options;

        _db = new MessengerDbContext(options);
        await _db.Database.EnsureCreatedAsync();

        _keyStore = PassphraseKeyStoreProvider.Create();
        _audit = new AuditService(_db, new InMemoryAuditSigningKeyProvider());
        _sessions = new SessionService(_db);
        _messages = new MessageService(_db, _keyStore, new MessageCipher());
    }

    public async Task DisposeAsync()
    {
        if (ConnectionString is null) return;

        await _db.DisposeAsync();
        _keyStore.Dispose();

        // Pooled connections to the test database would block the drop.
        NpgsqlConnection.ClearAllPools();

        var admin = new NpgsqlConnectionStringBuilder(ConnectionString) { Database = "postgres" };
        await using var cleanup = new NpgsqlConnection(admin.ConnectionString);
        await cleanup.OpenAsync();
        await using var cmd = cleanup.CreateCommand();
        cmd.CommandText = $"DROP DATABASE IF EXISTS \"{_schema}\" WITH (FORCE)";
        await cmd.ExecuteNonQueryAsync();
    }

    private User AddUser(string username)
    {
        var user = new User { Username = username, DisplayName = username };
        _db.Users.Add(user);
        _db.SaveChanges();
        return user;
    }

    [SkippableFact]
    public async Task Message_roundtrips_through_postgres()
    {
        Skip.If(ConnectionString is null, "MESSENGER_TEST_CONNECTION is not set.");

        var alice = AddUser("alice_" + Guid.NewGuid().ToString("N")[..8]);
        var bob = AddUser("bob_" + Guid.NewGuid().ToString("N")[..8]);
        var c = await _messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);

        await _messages.SendAsync(alice.Id,
            new SendMessageRequest(c.Id, Guid.NewGuid(), "over the wire", DateTimeOffset.UtcNow));

        var history = await _messages.GetHistoryAsync(bob.Id, c.Id);
        Assert.Single(history);
        Assert.Equal("over the wire", history[0].Body);
    }

    /// <summary>
    /// The backlog query orders by (conversation, seq) and filters on delivery state.
    /// This is the query store-and-forward depends on, run through Npgsql.
    /// </summary>
    [SkippableFact]
    public async Task Store_and_forward_backlog_translates_on_npgsql()
    {
        Skip.If(ConnectionString is null, "MESSENGER_TEST_CONNECTION is not set.");

        var alice = AddUser("alice_" + Guid.NewGuid().ToString("N")[..8]);
        var bob = AddUser("bob_" + Guid.NewGuid().ToString("N")[..8]);
        var c = await _messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);

        for (int i = 0; i < 3; i++)
            await _messages.SendAsync(alice.Id,
                new SendMessageRequest(c.Id, Guid.NewGuid(), $"queued {i}", DateTimeOffset.UtcNow));

        var backlog = await _messages.GetPendingBacklogAsync(bob.Id);

        Assert.Equal(3, backlog.Count);
        Assert.Equal(["queued 0", "queued 1", "queued 2"], backlog.Select(m => m.Body));
    }

    /// <summary>
    /// Session validation compares <c>ExpiresAt</c> and <c>LastActivityAt</c> against the
    /// clock. Those are exactly the comparisons SQLite cannot translate, so this is the
    /// only place they are proven to work.
    /// </summary>
    [SkippableFact]
    public async Task Session_lifecycle_translates_on_npgsql()
    {
        Skip.If(ConnectionString is null, "MESSENGER_TEST_CONNECTION is not set.");

        var alice = AddUser("alice_" + Guid.NewGuid().ToString("N")[..8]);

        var (token, session) = await _sessions.CreateAsync(
            alice, "device-1", "laptop", "10.0.0.1", AuthMethod.Password, SessionPolicy.Default);

        Assert.True((await _sessions.ValidateAsync(token, "device-1", SessionPolicy.Default)).IsValid);

        await _sessions.RevokeAsync(session, "admin");
        var revoked = await _sessions.ValidateAsync(token, "device-1", SessionPolicy.Default);

        Assert.False(revoked.IsValid);
        Assert.Equal(ErrorCode.SessionRevokedByAdmin, revoked.ErrorCode);
    }

    [SkippableFact]
    public async Task Concurrent_session_limit_query_translates_on_npgsql()
    {
        Skip.If(ConnectionString is null, "MESSENGER_TEST_CONNECTION is not set.");

        var alice = AddUser("alice_" + Guid.NewGuid().ToString("N")[..8]);
        var policy = SessionPolicy.Default with { MaxConcurrentSessionsPerUser = 2 };

        var (first, _) = await _sessions.CreateAsync(alice, "d1", null, null, AuthMethod.Password, policy);
        await _sessions.CreateAsync(alice, "d2", null, null, AuthMethod.Password, policy);
        await _sessions.CreateAsync(alice, "d3", null, null, AuthMethod.Password, policy);

        Assert.False((await _sessions.ValidateAsync(first, "d1", policy)).IsValid);
        Assert.Equal(2, await _db.Sessions.CountAsync(s => s.RevokedAt == null));
    }

    /// <summary>
    /// The unique index on direct_key is what makes conversation creation race-safe. SQLite
    /// enforces it too, but confirming it on the production engine is the point here.
    /// </summary>
    [SkippableFact]
    public async Task Direct_conversation_uniqueness_is_enforced_by_postgres()
    {
        Skip.If(ConnectionString is null, "MESSENGER_TEST_CONNECTION is not set.");

        var alice = AddUser("alice_" + Guid.NewGuid().ToString("N")[..8]);
        var bob = AddUser("bob_" + Guid.NewGuid().ToString("N")[..8]);

        var first = await _messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id);
        var second = await _messages.GetOrCreateDirectConversationAsync(bob.Id, alice.Id);

        Assert.Equal(first.Id, second.Id);

        // A hand-rolled duplicate must be refused by the database, not merely by the service.
        _db.Conversations.Add(new Conversation
        {
            Type = ConversationType.Direct,
            DirectKey = Conversation.BuildDirectKey(alice.Id, bob.Id),
        });
        await Assert.ThrowsAsync<DbUpdateException>(() => _db.SaveChangesAsync());
        _db.ChangeTracker.Clear();
    }

    [SkippableFact]
    public async Task Audit_chain_verifies_on_postgres()
    {
        Skip.If(ConnectionString is null, "MESSENGER_TEST_CONNECTION is not set.");

        for (int i = 0; i < 5; i++)
            await _audit.AppendAsync($"action.{i}", "success");

        Assert.True((await _audit.VerifyAsync()).IsValid);

        var entry = await _db.AuditLog.OrderBy(e => e.Id).Skip(2).FirstAsync();
        entry.Outcome = "denied";
        await _db.SaveChangesAsync();

        var result = await _audit.VerifyAsync();
        Assert.False(result.IsValid);
        Assert.Equal(entry.Id, result.FirstInvalidEntryId);
    }

    /// <summary>Confirms the SQLite tick-converter is genuinely not applied on Npgsql.</summary>
    [SkippableFact]
    public async Task Timestamps_are_stored_as_timestamptz_not_ticks()
    {
        Skip.If(ConnectionString is null, "MESSENGER_TEST_CONNECTION is not set.");

        var dataType = await _db.Database
            .SqlQuery<string>($"""
                SELECT data_type AS "Value" FROM information_schema.columns
                WHERE table_name = 'messages' AND column_name = 'server_received_at'
                """)
            .SingleAsync();

        Assert.Equal("timestamp with time zone", dataType);
    }
}
