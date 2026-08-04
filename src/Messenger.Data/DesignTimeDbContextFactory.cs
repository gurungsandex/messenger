using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Messenger.Data;

/// <summary>
/// Used only by the EF tooling when generating or applying migrations. The runtime host
/// registers the context from configuration; this exists so `dotnet ef` does not need a
/// running application, and so migration generation never depends on the server's DI graph
/// being constructible.
/// </summary>
public sealed class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<MessengerDbContext>
{
    public MessengerDbContext CreateDbContext(string[] args)
    {
        var connectionString =
            Environment.GetEnvironmentVariable("MESSENGER_CONNECTION")
            ?? "Host=localhost;Port=5432;Database=messenger;Username=messenger;Password=messenger";

        var options = new DbContextOptionsBuilder<MessengerDbContext>()
            .UseNpgsql(connectionString)
            .Options;

        return new MessengerDbContext(options);
    }
}
