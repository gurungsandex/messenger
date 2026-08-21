using Messenger.Core;
using Messenger.Crypto;
using Messenger.Data;
using Messenger.Licensing;
using Microsoft.EntityFrameworkCore;

// Bootstraps a deployment far enough to log in.
//
// A freshly migrated database has five seeded roles and zero users, and the server refuses
// every login until a licence is installed. Both of the routes out of that state are behind
// the authenticated admin API, so a new deployment cannot reach its own first session:
// creating the first administrator needs a session, and installing the licence that would
// permit a session needs one too.
//
// This tool writes both directly, which is the only thing that can break the cycle without a
// session. It is a provisioning step, not a feature — see docs/getting-started.md. The
// evaluation licence it can issue is signed with a key pair generated here, so it is valid
// only against a server configured with the matching public key.

var arguments = ParseArguments(args);

if (arguments.ContainsKey("help") || args.Length == 0)
{
    Console.WriteLine("""
        Bootstraps a Messenger deployment: issues an evaluation licence and creates the
        first administrator. Both write straight to the database, because neither is
        reachable through the API before the first session exists.

        Usage:
          dotnet run --project tools/Messenger.Bootstrap -- [options]

        Required:
          --connection <string>     PostgreSQL connection string for the server's database.
          --admin-password <pw>     Password for the administrator. Minimum 12 characters.

        Optional:
          --admin-username <name>   Default: admin
          --admin-display <name>    Default: the username
          --role <name>             Role to grant. Default: ServerAdmin. Use 'User' to make
                                    an ordinary account for testing chat.
          --customer <name>         Licence holder name. Default: Evaluation
          --seats <n>               Default: 25
          --days <n>                Licence validity in days. Default: 90
          --out <directory>         Where to write the licence and keys. Default: ./bootstrap
          --skip-license            Create only the administrator.
          --skip-admin              Issue only the licence.

        The vendor public key printed at the end must be set as Licensing:VendorPublicKey
        before the server will accept the licence. Restart the server after setting it.
        """);
    return 0;
}

var connection = Required(arguments, "connection");
var outputDirectory = Value(arguments, "out") ?? "bootstrap";
var skipLicense = arguments.ContainsKey("skip-license");
var skipAdmin = arguments.ContainsKey("skip-admin");

var options = new DbContextOptionsBuilder<MessengerDbContext>().UseNpgsql(connection).Options;
await using var db = new MessengerDbContext(options);

if (!await db.Database.CanConnectAsync())
{
    Console.Error.WriteLine("Cannot reach the database. Check --connection.");
    return 1;
}

// Roles are seeded by the server at startup, not by migrations. Without them the
// administrator would be created with no role and no permissions -- an account that exists,
// can sign in, and can do nothing.
if (!await db.Roles.AnyAsync())
{
    Console.Error.WriteLine(
        "No roles are present. Start the server once so it seeds the built-in roles, then re-run this.");
    return 1;
}

Directory.CreateDirectory(outputDirectory);
string? vendorPublicKeyBase64 = null;

if (!skipLicense)
{
    var customer = Value(arguments, "customer") ?? "Evaluation";
    var seats = int.Parse(Value(arguments, "seats") ?? "25");
    var days = int.Parse(Value(arguments, "days") ?? "90");
    var now = DateTimeOffset.UtcNow;

    var (privateKey, publicKey) = LicenseDocument.GenerateVendorKeyPair();
    vendorPublicKeyBase64 = Convert.ToBase64String(publicKey);

    var payload = new LicensePayload
    {
        LicenseId = Guid.NewGuid().ToString("N"),
        Customer = customer,
        IssuedAt = now,

        // Backdated a day so a server whose clock is slightly behind does not reject a
        // licence issued seconds ago as not-yet-valid.
        NotBefore = now.AddDays(-1),
        NotAfter = now.AddDays(days),
        MaxSeats = seats,
        MaxFileBytes = 100L * 1024 * 1024,
        MaxSessionsPerUser = 3,
        MaxSessionsTotal = seats * 3,
        IdleTimeoutSeconds = 900,
        GracePeriodDays = 14,
        Features = [LicenseFeature.AdSync, LicenseFeature.FileTransfer, LicenseFeature.SupportChat],
    };

    var document = LicenseDocument.Issue(payload, privateKey);
    var licenseText = document.ToFileFormat();

    var licensePath = Path.Combine(outputDirectory, "messenger.lic");
    await File.WriteAllTextAsync(licensePath, licenseText);
    await File.WriteAllTextAsync(Path.Combine(outputDirectory, "vendor-public-key.txt"), vendorPublicKeyBase64);
    await File.WriteAllTextAsync(
        Path.Combine(outputDirectory, "vendor-private-key.txt"), Convert.ToBase64String(privateKey));

    // Superseded rather than deleted, matching what LicenseEnforcementService.InstallAsync
    // does: exactly one licence is active, and the history of what was installed survives.
    foreach (var existing in await db.Licenses.Where(l => l.IsActive).ToListAsync())
        existing.IsActive = false;

    db.Licenses.Add(new LicenseRecord
    {
        RawDocument = licenseText,
        LicenseId = payload.LicenseId,
        Customer = payload.Customer,
        NotBefore = payload.NotBefore,
        NotAfter = payload.NotAfter,
        IsActive = true,
        InstalledAt = now,
    });

    await db.SaveChangesAsync();
    Console.WriteLine($"Licence issued for '{customer}': {seats} seats, valid {days} days.");
    Console.WriteLine($"  {licensePath}");
}

if (!skipAdmin)
{
    var username = Value(arguments, "admin-username") ?? "admin";
    var password = Required(arguments, "admin-password");

    // The same policy the server enforces. Checked here so the failure is a clear message
    // rather than an account that exists but can never sign in.
    if (password.Length < 12)
    {
        Console.Error.WriteLine("--admin-password must be at least 12 characters.");
        return 1;
    }

    if (await db.Users.AnyAsync(u => u.Username == username && u.DeletedAt == null))
    {
        Console.Error.WriteLine($"A user named '{username}' already exists. Use --admin-username for a different name.");
        return 1;
    }

    var hasher = new PasswordHasher();
    var user = new User
    {
        Username = username,
        DisplayName = Value(arguments, "admin-display") ?? username,
        Source = UserSource.Local,
        Status = UserStatus.Active,
        PasswordHash = hasher.Hash(password),
        PasswordUpdatedAt = DateTimeOffset.UtcNow,

        // Deliberately false so the first login does not require a password change before
        // the administrator has done anything -- they can change it via
        // POST /api/auth/change-password whenever they choose.
        MustChangePassword = false,
        CreatedAt = DateTimeOffset.UtcNow,
    };

    db.Users.Add(user);
    await db.SaveChangesAsync();

    var roleName = Value(arguments, "role") ?? BuiltInRoles.ServerAdmin;
    var role = await db.Roles.FirstOrDefaultAsync(r => r.Name == roleName);
    if (role is null)
    {
        var available = string.Join(", ", await db.Roles.Select(r => r.Name).OrderBy(n => n).ToListAsync());
        Console.Error.WriteLine($"No role named '{roleName}'. Available roles: {available}");
        return 1;
    }

    db.UserRoles.Add(new UserRole { UserId = user.Id, RoleId = role.Id });
    await db.SaveChangesAsync();

    Console.WriteLine($"User '{username}' created with the {roleName} role.");
}

if (vendorPublicKeyBase64 is not null)
{
    Console.WriteLine();
    Console.WriteLine("Set this on the server, then restart it:");
    Console.WriteLine($"  Licensing__VendorPublicKey={vendorPublicKeyBase64}");
    Console.WriteLine();
    Console.WriteLine("The server validates the installed licence against this key. Until it matches,");
    Console.WriteLine("every login is refused with LIC-101.");
}

return 0;

static Dictionary<string, string?> ParseArguments(string[] args)
{
    var parsed = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

    for (var i = 0; i < args.Length; i++)
    {
        if (!args[i].StartsWith("--", StringComparison.Ordinal)) continue;

        var key = args[i][2..];
        var hasValue = i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal);
        parsed[key] = hasValue ? args[++i] : null;
    }

    return parsed;
}

static string? Value(Dictionary<string, string?> arguments, string key)
    => arguments.TryGetValue(key, out var value) ? value : null;

static string Required(Dictionary<string, string?> arguments, string key)
    => Value(arguments, key)
       ?? throw new ArgumentException($"--{key} is required. Run with --help for usage.");
