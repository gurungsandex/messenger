using Microsoft.EntityFrameworkCore;

namespace Messenger.Owner;

public class OwnerDbContext(DbContextOptions<OwnerDbContext> options) : DbContext(options)
{
    public DbSet<OwnerOperator> Operators => Set<OwnerOperator>();
    public DbSet<OwnerSession> Sessions => Set<OwnerSession>();
    public DbSet<CustomerLicenseRecord> CustomerLicenses => Set<CustomerLicenseRecord>();
    public DbSet<TelemetryEvent> TelemetryEvents => Set<TelemetryEvent>();
    public DbSet<SupportMessage> SupportMessages => Set<SupportMessage>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<OwnerOperator>(e =>
        {
            e.ToTable("owner_operators");
            e.HasKey(x => x.Id);
            e.Property(x => x.Username).IsRequired().HasMaxLength(256);
            e.Property(x => x.DisplayName).IsRequired().HasMaxLength(256);
            e.HasIndex(x => x.Username).IsUnique();
        });

        b.Entity<OwnerSession>(e =>
        {
            e.ToTable("owner_sessions");
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.TokenHash).IsUnique();
        });

        b.Entity<CustomerLicenseRecord>(e =>
        {
            e.ToTable("customer_licenses");
            e.HasKey(x => x.Id);
            e.Property(x => x.LicenseId).IsRequired().HasMaxLength(128);
            e.Property(x => x.Customer).IsRequired().HasMaxLength(256);
            e.Property(x => x.RawDocument).IsRequired();
            e.HasIndex(x => x.LicenseId).IsUnique();
        });

        b.Entity<TelemetryEvent>(e =>
        {
            e.ToTable("telemetry_events");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).ValueGeneratedOnAdd();
            e.Property(x => x.LicenseId).IsRequired().HasMaxLength(128);
            e.Property(x => x.EventType).IsRequired().HasMaxLength(64);
            e.HasIndex(x => x.LicenseId);
        });

        b.Entity<SupportMessage>(e =>
        {
            e.ToTable("support_messages");
            e.HasKey(x => x.Id);
            e.Property(x => x.CustomerLicenseId).IsRequired().HasMaxLength(128);
            e.Property(x => x.Body).IsRequired().HasMaxLength(8192);
            e.HasIndex(x => x.CustomerLicenseId);
        });
    }
}
