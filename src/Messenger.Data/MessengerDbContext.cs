using Messenger.Core;
using Microsoft.EntityFrameworkCore;

namespace Messenger.Data;

public class MessengerDbContext(DbContextOptions<MessengerDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<Group> Groups => Set<Group>();
    public DbSet<GroupMember> GroupMembers => Set<GroupMember>();
    public DbSet<OrgUnit> OrgUnits => Set<OrgUnit>();
    public DbSet<Conversation> Conversations => Set<Conversation>();
    public DbSet<ConversationParticipant> ConversationParticipants => Set<ConversationParticipant>();
    public DbSet<Message> Messages => Set<Message>();
    public DbSet<MessageRecipient> MessageRecipients => Set<MessageRecipient>();
    public DbSet<ConversationKey> ConversationKeys => Set<ConversationKey>();
    public DbSet<Session> Sessions => Set<Session>();
    public DbSet<Presence> Presences => Set<Presence>();
    public DbSet<AuditLogEntry> AuditLog => Set<AuditLogEntry>();
    public DbSet<AuditCheckpoint> AuditCheckpoints => Set<AuditCheckpoint>();
    public DbSet<ServerSetting> ServerSettings => Set<ServerSetting>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<User>(e =>
        {
            e.ToTable("users");
            e.HasKey(x => x.Id);
            e.Property(x => x.Username).IsRequired().HasMaxLength(256);
            e.Property(x => x.DisplayName).IsRequired().HasMaxLength(256);
            e.HasIndex(x => x.Username).IsUnique();
            e.HasIndex(x => x.AdObjectGuid).IsUnique().HasFilter("ad_object_guid IS NOT NULL");
            e.HasIndex(x => x.Status);
        });

        b.Entity<Group>(e =>
        {
            e.ToTable("groups");
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).IsRequired().HasMaxLength(256);
            e.HasIndex(x => x.Name).IsUnique().HasFilter("deleted_at IS NULL");
            e.HasIndex(x => x.AdObjectGuid).IsUnique().HasFilter("ad_object_guid IS NOT NULL");
            e.HasIndex(x => x.Status);
        });

        b.Entity<GroupMember>(e =>
        {
            e.ToTable("group_members");
            e.HasKey(x => new { x.GroupId, x.UserId });
            e.HasOne(x => x.Group).WithMany(g => g.Members).HasForeignKey(x => x.GroupId);
            e.HasOne(x => x.User).WithMany().HasForeignKey(x => x.UserId);
            e.HasIndex(x => x.UserId);
        });

        b.Entity<OrgUnit>(e =>
        {
            e.ToTable("org_units");
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).IsRequired().HasMaxLength(256);
            e.HasIndex(x => x.AdObjectGuid).IsUnique().HasFilter("ad_object_guid IS NOT NULL");
            e.HasIndex(x => x.ParentId);
        });

        b.Entity<Conversation>(e =>
        {
            e.ToTable("conversations");
            e.HasKey(x => x.Id);
            // Unique direct_key is what prevents a race from creating two 1:1 conversations
            // for the same pair. Checking in application code would be a TOCTOU bug.
            e.HasIndex(x => x.DirectKey).IsUnique().HasFilter("direct_key IS NOT NULL");
            e.HasIndex(x => x.LastMessageAt);
        });

        b.Entity<ConversationParticipant>(e =>
        {
            e.ToTable("conversation_participants");
            e.HasKey(x => new { x.ConversationId, x.UserId });
            e.HasOne(x => x.Conversation).WithMany(c => c.Participants).HasForeignKey(x => x.ConversationId);
            e.HasOne(x => x.User).WithMany(u => u.Participations).HasForeignKey(x => x.UserId);
            e.HasIndex(x => x.UserId);
        });

        b.Entity<Message>(e =>
        {
            e.ToTable("messages");
            e.HasKey(x => x.Id);
            e.HasOne(x => x.Conversation).WithMany(c => c.Messages).HasForeignKey(x => x.ConversationId);
            e.Property(x => x.Ciphertext).IsRequired();
            e.Property(x => x.Nonce).IsRequired().HasMaxLength(12);
            e.Property(x => x.AuthTag).IsRequired().HasMaxLength(16);

            // Primary read path and the ordering guarantee.
            e.HasIndex(x => new { x.ConversationId, x.Seq }).IsUnique();
            // Makes a retry idempotent rather than duplicating.
            e.HasIndex(x => new { x.ConversationId, x.SenderId, x.ClientMessageId }).IsUnique();
            e.HasIndex(x => new { x.ConversationId, x.ServerReceivedAt });
        });

        b.Entity<MessageRecipient>(e =>
        {
            e.ToTable("message_recipients");
            e.HasKey(x => new { x.MessageId, x.UserId });
            e.HasOne(x => x.Message).WithMany(m => m.Recipients).HasForeignKey(x => x.MessageId);
            // Partial index: the store-and-forward backlog query touches only genuinely
            // undelivered rows, so it stays cheap as this table grows past every other one.
            e.HasIndex(x => new { x.UserId, x.State });
        });

        b.Entity<ConversationKey>(e =>
        {
            e.ToTable("conversation_keys");
            e.HasKey(x => x.Id);
            e.HasOne(x => x.Conversation).WithMany(c => c.Keys).HasForeignKey(x => x.ConversationId);
            e.HasIndex(x => new { x.ConversationId, x.Version }).IsUnique();
        });

        b.Entity<Session>(e =>
        {
            e.ToTable("sessions");
            e.HasKey(x => x.Id);
            e.HasOne(x => x.User).WithMany(u => u.Sessions).HasForeignKey(x => x.UserId);
            e.Property(x => x.TokenHash).IsRequired().HasMaxLength(32);
            e.HasIndex(x => x.TokenHash).IsUnique();
            // The exact query the concurrent-session licence check runs on every login.
            e.HasIndex(x => new { x.UserId, x.RevokedAt });
        });

        b.Entity<Presence>(e =>
        {
            e.ToTable("presence");
            e.HasKey(x => x.UserId);
        });

        b.Entity<AuditLogEntry>(e =>
        {
            e.ToTable("audit_log");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).ValueGeneratedOnAdd();
            e.Property(x => x.Action).IsRequired().HasMaxLength(128);
            e.Property(x => x.PrevHash).IsRequired().HasMaxLength(32);
            e.Property(x => x.EntryHash).IsRequired().HasMaxLength(32);
            e.HasIndex(x => x.OccurredAt);
            e.HasIndex(x => x.ActorUserId);
        });

        b.Entity<AuditCheckpoint>(e =>
        {
            e.ToTable("audit_checkpoints");
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.UpToAuditId);
        });

        b.Entity<ServerSetting>(e =>
        {
            e.ToTable("server_settings");
            e.HasKey(x => x.Key);
        });

        foreach (var entity in b.Model.GetEntityTypes())
        {
            foreach (var property in entity.GetProperties())
                property.SetColumnName(ToSnakeCase(property.Name));
        }

        if (Database.ProviderName?.Contains("Sqlite", StringComparison.OrdinalIgnoreCase) == true)
            ApplySqliteTimestampWorkaround(b);
    }

    /// <summary>
    /// SQLite has no native timestamp type, so its EF provider cannot compare or order
    /// <see cref="DateTimeOffset"/> in SQL. PostgreSQL — the production database — maps it
    /// to <c>timestamptz</c> and handles both natively.
    ///
    /// SQLite is used only by the test suite, where it is preferred over the EF InMemory
    /// provider because it actually enforces unique indexes. Rather than degrade the
    /// production schema to accommodate a test dependency, timestamps are stored as UTC
    /// ticks under that provider alone. Everything is written UTC, so this is lossless.
    /// </summary>
    private static void ApplySqliteTimestampWorkaround(ModelBuilder b)
    {
        foreach (var entity in b.Model.GetEntityTypes())
        {
            foreach (var property in entity.GetProperties())
            {
                if (property.ClrType == typeof(DateTimeOffset))
                    property.SetValueConverter(SqliteTimestampConverter);
                else if (property.ClrType == typeof(DateTimeOffset?))
                    property.SetValueConverter(NullableSqliteTimestampConverter);
            }
        }
    }

    private static readonly Microsoft.EntityFrameworkCore.Storage.ValueConversion.ValueConverter<DateTimeOffset, long>
        SqliteTimestampConverter = new(
            v => v.UtcTicks,
            v => new DateTimeOffset(v, TimeSpan.Zero));

    private static readonly Microsoft.EntityFrameworkCore.Storage.ValueConversion.ValueConverter<DateTimeOffset?, long?>
        NullableSqliteTimestampConverter = new(
            v => v.HasValue ? v.Value.UtcTicks : null,
            v => v.HasValue ? new DateTimeOffset(v.Value, TimeSpan.Zero) : null);

    private static string ToSnakeCase(string name)
    {
        var sb = new System.Text.StringBuilder(name.Length + 8);
        for (int i = 0; i < name.Length; i++)
        {
            if (char.IsUpper(name[i]))
            {
                if (i > 0) sb.Append('_');
                sb.Append(char.ToLowerInvariant(name[i]));
            }
            else sb.Append(name[i]);
        }
        return sb.ToString();
    }
}
