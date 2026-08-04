using Messenger.Core;
using Messenger.Crypto;
using Messenger.Data;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Messenger.Core.Tests;

/// <summary>
/// Per-test database on SQLite in-memory.
///
/// SQLite rather than the EF InMemory provider on purpose: the InMemory provider ignores
/// unique indexes, and several of the guarantees under test here — send idempotency, the
/// one-row-per-pair direct conversation — are enforced *by* those indexes. Testing them
/// against a provider that cannot fail would prove nothing.
/// </summary>
public sealed class TestHarness : IDisposable
{
    private readonly SqliteConnection _connection;

    public MessengerDbContext Db { get; }
    public PassphraseKeyStoreProvider KeyStore { get; }
    public FakeTimeProvider Time { get; }
    public MessageService Messages { get; }
    public SessionService Sessions { get; }
    public AuthService Auth { get; }
    public AuditService Audit { get; }
    public PresenceService Presence { get; }
    public GroupService Groups { get; }
    public FileTransferService Files { get; }
    public InMemoryFileStore Store { get; }
    public PasswordHasher Hasher { get; }
    public InMemoryAuditSigningKeyProvider SigningKeys { get; }

    public TestHarness(IMalwareScanner? scanner = null)
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        var options = new DbContextOptionsBuilder<MessengerDbContext>()
            .UseSqlite(_connection)
            .Options;

        Db = new MessengerDbContext(options);
        Db.Database.EnsureCreated();

        Time = new FakeTimeProvider(new DateTimeOffset(2026, 8, 4, 12, 0, 0, TimeSpan.Zero));
        KeyStore = PassphraseKeyStoreProvider.Create();
        SigningKeys = new InMemoryAuditSigningKeyProvider();

        // Deliberately weak Argon2 parameters so the suite stays fast.
        Hasher = new PasswordHasher(new Argon2Parameters(1024, 1, 1));

        Audit = new AuditService(Db, SigningKeys);
        Sessions = new SessionService(Db, Time);
        Auth = new AuthService(Db, Hasher, Audit, Time);
        Messages = new MessageService(Db, KeyStore, new MessageCipher(), Time);
        Presence = new PresenceService(Db, Time);
        Groups = new GroupService(Db, Audit, Time);
        Store = new InMemoryFileStore();
        Files = new FileTransferService(Db, Store, KeyStore, new FileCipher(), Audit, scanner, Time);
    }

    public User AddUser(string username, string? password = null, UserStatus status = UserStatus.Active)
    {
        var user = new User
        {
            Username = username,
            DisplayName = username,
            Status = status,
            PasswordHash = password is null ? null : Hasher.Hash(password),
            CreatedAt = Time.GetUtcNow(),
        };
        Db.Users.Add(user);
        Db.SaveChanges();
        return user;
    }

    public void Dispose()
    {
        Db.Dispose();
        _connection.Dispose();
        KeyStore.Dispose();
    }
}

/// <summary>Controllable clock, so timeout behaviour is tested by advancing time rather than sleeping.</summary>
public sealed class FakeTimeProvider(DateTimeOffset start) : TimeProvider
{
    private DateTimeOffset _now = start;

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now = _now.Add(by);
}
