using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Messenger.Contracts;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace Messenger.Licensing;

/// <summary>The signed payload. Field names are part of the signed bytes and must not change.</summary>
public sealed class LicensePayload
{
    [JsonPropertyName("license_id")] public string LicenseId { get; set; } = null!;
    [JsonPropertyName("customer")] public string Customer { get; set; } = null!;
    [JsonPropertyName("issued_at")] public DateTimeOffset IssuedAt { get; set; }
    [JsonPropertyName("not_before")] public DateTimeOffset NotBefore { get; set; }
    [JsonPropertyName("not_after")] public DateTimeOffset NotAfter { get; set; }
    [JsonPropertyName("max_seats")] public int MaxSeats { get; set; }
    [JsonPropertyName("max_file_bytes")] public long MaxFileBytes { get; set; }
    [JsonPropertyName("max_concurrent_sessions_per_user")] public int MaxSessionsPerUser { get; set; }
    [JsonPropertyName("max_concurrent_sessions_total")] public int MaxSessionsTotal { get; set; }
    [JsonPropertyName("idle_timeout_seconds")] public int IdleTimeoutSeconds { get; set; }
    [JsonPropertyName("grace_period_days")] public int GracePeriodDays { get; set; } = 14;
    [JsonPropertyName("features")] public List<string> Features { get; set; } = [];
}

/// <summary>Feature flags a licence may grant.</summary>
public static class LicenseFeature
{
    public const string AdSync = "ad_sync";
    public const string FileTransfer = "file_transfer";
    public const string SupportChat = "support_chat";
}

public enum LicenseState
{
    Valid,
    /// <summary>Expired but inside the grace window: history readable, no new sessions or messages.</summary>
    Grace,
    Expired,
    NotYetValid,
    Invalid,
    Missing,
}

public sealed record LicenseStatus(
    LicenseState State,
    LicensePayload? Payload,
    string? ErrorCode,
    string? Detail,
    DateTimeOffset? GraceEndsAt)
{
    public bool AllowsNewSessions => State == LicenseState.Valid;
    public bool AllowsReading => State is LicenseState.Valid or LicenseState.Grace;
}

/// <summary>
/// A licence document: the exact signed bytes plus their Ed25519 signature.
///
/// The raw bytes are retained verbatim rather than reserialised. Verifying a signature
/// against a re-serialised object is a well-known source of intermittent failures — any
/// change in property order, whitespace, or number formatting silently invalidates a
/// perfectly good licence, typically months later during an upgrade.
/// </summary>
public sealed record LicenseDocument(byte[] SignedBytes, byte[] Signature)
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = null,
        WriteIndented = false,
    };

    public string ToFileFormat()
        => $"{Convert.ToBase64String(SignedBytes)}.{Convert.ToBase64String(Signature)}";

    public static LicenseDocument Parse(string fileContent)
    {
        ArgumentNullException.ThrowIfNull(fileContent);

        var parts = fileContent.Trim().Split('.');
        if (parts.Length != 2)
            throw new MessengerException(ErrorCode.LicenseMalformed,
                "The licence file is not in the expected format.");

        try
        {
            return new LicenseDocument(Convert.FromBase64String(parts[0]), Convert.FromBase64String(parts[1]));
        }
        catch (FormatException)
        {
            throw new MessengerException(ErrorCode.LicenseMalformed, "The licence file is corrupted.");
        }
    }

    public LicensePayload DeserializePayload()
    {
        try
        {
            return JsonSerializer.Deserialize<LicensePayload>(SignedBytes, SerializerOptions)
                   ?? throw new MessengerException(ErrorCode.LicenseMalformed, "The licence payload is empty.");
        }
        catch (JsonException ex)
        {
            throw new MessengerException(ErrorCode.LicenseMalformed, "The licence payload is not valid JSON.", ex.Message);
        }
    }

    /// <summary>Vendor-side issuance. Not reachable from customer deployments.</summary>
    public static LicenseDocument Issue(LicensePayload payload, byte[] vendorPrivateKey)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(payload, SerializerOptions);

        var signer = new Ed25519Signer();
        signer.Init(true, new Ed25519PrivateKeyParameters(vendorPrivateKey, 0));
        signer.BlockUpdate(bytes, 0, bytes.Length);

        return new LicenseDocument(bytes, signer.GenerateSignature());
    }

    public static (byte[] PrivateKey, byte[] PublicKey) GenerateVendorKeyPair()
    {
        var random = new SecureRandom();
        var privateKey = new byte[Ed25519PrivateKeyParameters.KeySize];
        random.NextBytes(privateKey);
        return (privateKey, new Ed25519PrivateKeyParameters(privateKey, 0).GeneratePublicKey().GetEncoded());
    }
}

/// <summary>
/// Validates licences offline against the vendor public key compiled into the server.
///
/// Offline validation is deliberate: a customer's internal messaging must not stop because
/// the vendor's licensing endpoint is unreachable, and air-gapped deployments must work
/// indefinitely. Online activation exists only to enable revocation and seat telemetry.
/// </summary>
public sealed class LicenseValidator(byte[] vendorPublicKey, TimeProvider? timeProvider = null)
{
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    public LicenseStatus Validate(LicenseDocument? document)
    {
        if (document is null)
            return new LicenseStatus(LicenseState.Missing, null, ErrorCode.NoLicenseInstalled,
                "No licence is installed.", null);

        if (!VerifySignature(document))
        {
            return new LicenseStatus(LicenseState.Invalid, null, ErrorCode.LicenseSignatureInvalid,
                "The licence signature is invalid. Reinstall the file exactly as supplied — any edit, "
                + "including reformatting, invalidates it.", null);
        }

        LicensePayload payload;
        try
        {
            payload = document.DeserializePayload();
        }
        catch (MessengerException ex)
        {
            return new LicenseStatus(LicenseState.Invalid, null, ex.Code, ex.Message, null);
        }

        var now = _time.GetUtcNow();

        if (now < payload.NotBefore)
            return new LicenseStatus(LicenseState.NotYetValid, payload, ErrorCode.LicenseNotYetValid,
                $"This licence is not valid until {payload.NotBefore:u}. Check the server clock.", null);

        if (now <= payload.NotAfter)
            return new LicenseStatus(LicenseState.Valid, payload, null, null, null);

        // Expiry degrades rather than stopping. Silently halting a company's internal
        // communications at midnight on the expiry date is a worse outcome than a loud,
        // visibly degraded mode that an administrator can act on.
        var graceEnds = payload.NotAfter.AddDays(payload.GracePeriodDays);
        if (now <= graceEnds)
        {
            return new LicenseStatus(LicenseState.Grace, payload, ErrorCode.LicenseExpired,
                $"The licence expired on {payload.NotAfter:u}. History remains readable; new sessions and "
                + $"messages are refused until it is renewed. Grace ends {graceEnds:u}.", graceEnds);
        }

        return new LicenseStatus(LicenseState.Expired, payload, ErrorCode.GracePeriodExpired,
            $"The licence expired on {payload.NotAfter:u} and the grace period ended {graceEnds:u}.", graceEnds);
    }

    private bool VerifySignature(LicenseDocument document)
    {
        try
        {
            var signer = new Ed25519Signer();
            signer.Init(false, new Ed25519PublicKeyParameters(vendorPublicKey, 0));
            signer.BlockUpdate(document.SignedBytes, 0, document.SignedBytes.Length);
            return signer.VerifySignature(document.Signature);
        }
        catch (Exception)
        {
            return false;
        }
    }
}
