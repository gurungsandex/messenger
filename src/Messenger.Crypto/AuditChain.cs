using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Messenger.Contracts;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace Messenger.Crypto;

/// <summary>Fields covered by an audit entry's hash. Order is fixed by the canonical serialiser.</summary>
public sealed record AuditEntryData(
    long Id,
    DateTimeOffset OccurredAt,
    Guid? ActorUserId,
    string ActorTier,
    string? ActorIp,
    string Action,
    string? TargetType,
    Guid? TargetId,
    string Outcome,
    string? DetailJson);

/// <summary>
/// Hash-chains audit entries and signs periodic checkpoints with Ed25519.
///
/// This gives tamper *evidence*, not tamper *proofing*: an attacker holding both database
/// write access and the signing key can rewrite history and re-sign it. See AR-6 in the
/// threat model — the controls that close that gap are a TPM/HSM-held signing key and
/// external anchoring of checkpoints.
/// </summary>
public static class AuditChain
{
    /// <summary>The chain's starting value, used as prev_hash for the very first entry.</summary>
    public static readonly byte[] GenesisHash = new byte[32];

    /// <summary>entry_hash = SHA-256( canonical_json(entry) ‖ prev_hash )</summary>
    public static byte[] ComputeEntryHash(AuditEntryData entry, byte[] previousHash)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(previousHash);
        if (previousHash.Length != 32)
            throw new ArgumentException("Previous hash must be 32 bytes.", nameof(previousHash));

        var canonical = Canonicalize(entry);
        var buffer = new byte[canonical.Length + 32];
        canonical.CopyTo(buffer, 0);
        previousHash.CopyTo(buffer, canonical.Length);
        return SHA256.HashData(buffer);
    }

    /// <summary>
    /// Canonical serialisation, version-pinned. Verification years from now must reproduce
    /// byte-identical input, so this deliberately does not use a general-purpose serialiser
    /// whose property ordering or escaping could change under it.
    /// </summary>
    private static byte[] Canonicalize(AuditEntryData e)
    {
        var sb = new StringBuilder();
        sb.Append("{\"v\":1");
        sb.Append(",\"id\":").Append(e.Id);
        sb.Append(",\"ts\":\"").Append(e.OccurredAt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ")).Append('"');
        sb.Append(",\"actor\":").Append(e.ActorUserId is null ? "null" : $"\"{e.ActorUserId:D}\"");
        sb.Append(",\"tier\":").Append(JsonSerializer.Serialize(e.ActorTier));
        sb.Append(",\"ip\":").Append(e.ActorIp is null ? "null" : JsonSerializer.Serialize(e.ActorIp));
        sb.Append(",\"action\":").Append(JsonSerializer.Serialize(e.Action));
        sb.Append(",\"ttype\":").Append(e.TargetType is null ? "null" : JsonSerializer.Serialize(e.TargetType));
        sb.Append(",\"tid\":").Append(e.TargetId is null ? "null" : $"\"{e.TargetId:D}\"");
        sb.Append(",\"outcome\":").Append(JsonSerializer.Serialize(e.Outcome));
        sb.Append(",\"detail\":").Append(e.DetailJson is null ? "null" : JsonSerializer.Serialize(e.DetailJson));
        sb.Append('}');
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    /// <summary>Verifies an ordered run of entries against the hash preceding the first of them.</summary>
    public static AuditVerificationResult VerifyChain(IReadOnlyList<(AuditEntryData Entry, byte[] StoredHash)> entries, byte[] startingPreviousHash)
    {
        ArgumentNullException.ThrowIfNull(entries);

        var previous = startingPreviousHash;
        foreach (var (entry, stored) in entries)
        {
            var computed = ComputeEntryHash(entry, previous);
            if (!CryptographicOperations.FixedTimeEquals(computed, stored))
                return new AuditVerificationResult(false, entry.Id);
            previous = stored;
        }
        return new AuditVerificationResult(true, null);
    }

    public static (byte[] PrivateKey, byte[] PublicKey) GenerateSigningKey()
    {
        var random = new SecureRandom();
        var privateKey = new byte[Ed25519PrivateKeyParameters.KeySize];
        random.NextBytes(privateKey);
        var parameters = new Ed25519PrivateKeyParameters(privateKey, 0);
        return (privateKey, parameters.GeneratePublicKey().GetEncoded());
    }

    public static byte[] SignCheckpoint(byte[] headHash, long upToAuditId, byte[] privateKey)
    {
        var signer = new Ed25519Signer();
        signer.Init(true, new Ed25519PrivateKeyParameters(privateKey, 0));
        var payload = CheckpointPayload(headHash, upToAuditId);
        signer.BlockUpdate(payload, 0, payload.Length);
        return signer.GenerateSignature();
    }

    public static bool VerifyCheckpoint(byte[] headHash, long upToAuditId, byte[] signature, byte[] publicKey)
    {
        var signer = new Ed25519Signer();
        signer.Init(false, new Ed25519PublicKeyParameters(publicKey, 0));
        var payload = CheckpointPayload(headHash, upToAuditId);
        signer.BlockUpdate(payload, 0, payload.Length);
        return signer.VerifySignature(signature);
    }

    /// <summary>
    /// The signature covers the head hash *and* the entry id it stands for. Without the id,
    /// a checkpoint signature could be replayed against a truncated chain that happens to
    /// end on the same hash.
    /// </summary>
    private static byte[] CheckpointPayload(byte[] headHash, long upToAuditId)
    {
        var payload = new byte[32 + 8];
        headHash.CopyTo(payload, 0);
        BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(upToAuditId)).CopyTo(payload, 32);
        return payload;
    }
}

public sealed record AuditVerificationResult(bool IsValid, long? FirstInvalidEntryId)
{
    public void EnsureValid()
    {
        if (!IsValid)
            throw new MessengerException(ErrorCode.AuditChainVerificationFailed,
                $"Audit chain broken at entry {FirstInvalidEntryId}.");
    }
}
