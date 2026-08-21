using Messenger.Crypto;
using Messenger.Owner;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSignalR();
builder.Services.AddSingleton<PasswordHasher>();
builder.Services.AddSingleton(TimeProvider.System);

var connectionString = builder.Configuration.GetConnectionString("Owner");
if (string.IsNullOrWhiteSpace(connectionString))
    throw new InvalidOperationException("'ConnectionStrings:Owner' is not configured.");

builder.Services.AddDbContext<OwnerDbContext>(o => o.UseNpgsql(connectionString));
builder.Services.AddScoped<OwnerAuthService>();
builder.Services.AddScoped<OwnerAuthFilter>();

var keyStorePassphrase = builder.Configuration["KeyStore:Passphrase"];
if (string.IsNullOrWhiteSpace(keyStorePassphrase))
    throw new InvalidOperationException(
        "'KeyStore:Passphrase' is not configured. This escrows the vendor signing key that "
        + "every customer licence is verified against -- losing it makes every issued "
        + "licence unreplaceable without re-keying every deployment.");

var keyStorePath = builder.Configuration["KeyStore:EscrowPath"]
    ?? Path.Combine(AppContext.BaseDirectory, "keystore", "root.escrow");
var vendorKeyPath = builder.Configuration["KeyStore:VendorKeyPath"]
    ?? Path.Combine(AppContext.BaseDirectory, "keystore", "vendor-key.json");

var (vendorKeys, vendorKeyCreated) = VendorKeyProvider.OpenOrCreate(keyStorePath, vendorKeyPath, keyStorePassphrase);
builder.Services.AddSingleton(vendorKeys);

builder.Services.AddHealthChecks().AddCheck<OwnerDatabaseHealthCheck>("database", tags: ["ready"]);

var app = builder.Build();

if (vendorKeyCreated)
{
    app.Logger.LogWarning(
        "A new vendor signing keypair was created. Its public key (base64) is: {PublicKey} -- "
        + "every customer deployment's Licensing:VendorPublicKey must be set to this exact "
        + "value, and this key must never be regenerated once a customer holds a licence "
        + "signed by it. Back up {VendorKeyPath} and the key store passphrase now.",
        Convert.ToBase64String(vendorKeys.PublicKey), vendorKeyPath);
}

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<OwnerDbContext>();
    await db.Database.MigrateAsync();

    // Same chicken-and-egg gap as the customer server's first ServerAdmin: there is no REST
    // path to create the first account on an empty database, by design elsewhere in this
    // codebase (Permissions.cs / AdminApi.cs never gained one either). Unlike the customer
    // server, an operator here is a deliberately rare, ops-managed account, so an
    // environment-variable bootstrap on first start is reasonable rather than a gap to leave
    // silently unfixable -- it only ever fires once, when the operator table is empty.
    if (!await db.Operators.AnyAsync())
    {
        var bootstrapUser = Environment.GetEnvironmentVariable("OWNER_BOOTSTRAP_USERNAME");
        var bootstrapPassword = Environment.GetEnvironmentVariable("OWNER_BOOTSTRAP_PASSWORD");
        if (!string.IsNullOrWhiteSpace(bootstrapUser) && !string.IsNullOrWhiteSpace(bootstrapPassword))
        {
            var hasher = scope.ServiceProvider.GetRequiredService<PasswordHasher>();
            db.Operators.Add(new OwnerOperator
            {
                Username = bootstrapUser,
                DisplayName = bootstrapUser,
                PasswordHash = hasher.Hash(bootstrapPassword),
            });
            await db.SaveChangesAsync();
            app.Logger.LogWarning("Bootstrapped the first owner operator account '{Username}' from environment variables.", bootstrapUser);
        }
    }
}

app.Use(async (context, next) =>
{
    var headers = context.Response.Headers;
    headers["X-Content-Type-Options"] = "nosniff";
    headers["X-Frame-Options"] = "DENY";
    headers["Referrer-Policy"] = "no-referrer";
    headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'";
    headers["Cache-Control"] = "no-store";
    await next();
});

app.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false });
app.MapHealthChecks("/health/ready", new HealthCheckOptions { Predicate = check => check.Tags.Contains("ready") });

app.MapOwnerAuth();
app.MapOwnerApi();
app.MapTelemetryIngest();
app.MapHub<SupportHub>("/hubs/support");

app.Run();

public sealed class OwnerDatabaseHealthCheck(OwnerDbContext db) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken ct = default)
    {
        try
        {
            return await db.Database.CanConnectAsync(ct)
                ? HealthCheckResult.Healthy("Database reachable.")
                : HealthCheckResult.Unhealthy("Database is not reachable.");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy(ex.Message);
        }
    }
}

/// <summary>Exposed so an integration-test host can reference this assembly.</summary>
public partial class Program;
