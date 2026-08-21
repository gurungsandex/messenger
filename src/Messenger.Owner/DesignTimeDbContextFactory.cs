using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Messenger.Owner;

/// <summary>Used only by `dotnet ef` tooling; mirrors Messenger.Data's factory.</summary>
public sealed class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<OwnerDbContext>
{
    public OwnerDbContext CreateDbContext(string[] args)
    {
        var connectionString =
            Environment.GetEnvironmentVariable("MESSENGER_OWNER_CONNECTION")
            ?? "Host=localhost;Port=5432;Database=messenger_owner;Username=messenger;Password=messenger";

        var options = new DbContextOptionsBuilder<OwnerDbContext>()
            .UseNpgsql(connectionString)
            .Options;

        return new OwnerDbContext(options);
    }
}
