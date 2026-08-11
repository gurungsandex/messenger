using System.Text.Json;
using System.Text.Json.Serialization;
using Messenger.Contracts;
using Messenger.Crypto;

namespace Messenger.Data;

/// <summary>
/// Audit checkpoint signing keys held in a passphrase-sealed file on disk.
///
/// This exists for the same reason <see cref="FileBackedKeyStore"/> does: a key that is
/// regenerated per process is not a key, it is a coincidence. <see
/// cref="InMemoryAuditSigningKeyProvider"/> mints a fresh Ed25519 pair at every start, so
/// every checkpoint signed before a restart references a key id the running process has
/// never heard of, and its public half is gone. The signatures stay in the database and can
/// never be checked again — the audit chain silently loses its tamper evidence at the first
/// service restart, which for a compliance feature is worse than not having shipped it.
///
/// Superseded keys are retained rather than replaced, so checkpoints signed under an earlier
/// key keep verifying after a rotation. A signing key is only ever added to the ring.
/// </summary>
public sealed class FileBackedAuditSigningKeyProvider : IAuditSigningKeyProvider
{
    private readonly string _activeKeyId;
    private readonly IReadOnlyDictionary<string, AuditSigningKeyEntry> _keys;

    private FileBackedAuditSigningKeyProvider(string activeKeyId, IReadOnlyDictionary<string, AuditSigningKeyEntry> keys)
    {
        _activeKeyId = activeKeyId;
        _keys = keys;
    }

    /// <summary>
    /// Opens the key ring at <paramref name="path"/>, creating one if absent. Returns whether
    /// it was newly created, so the caller can tell the operator to back it up — the same
    /// contract <see cref="FileBackedKeyStore.OpenOrCreate"/> has, and for the same reason.
    /// </summary>
    public static (FileBackedAuditSigningKeyProvider Provider, bool Created) OpenOrCreate(string path, string passphrase)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentException.ThrowIfNullOrWhiteSpace(passphrase);

        if (File.Exists(path))
            return (FromRing(Read(path, passphrase)), false);

        var (privateKey, publicKey) = AuditChain.GenerateSigningKey();
        var ring = new AuditSigningKeyRing
        {
            ActiveKeyId = Guid.NewGuid().ToString("N"),
            Keys = [],
        };
        ring.Keys.Add(new AuditSigningKeyEntry
        {
            KeyId = ring.ActiveKeyId,
            PrivateKey = Convert.ToBase64String(privateKey),
            PublicKey = Convert.ToBase64String(publicKey),
        });

        PassphraseSealedFile.WriteAtomic(path, PassphraseSealedFile.Seal(Serialize(ring), passphrase));

        // Re-open from what was actually written rather than trusting the in-memory copy. If
        // the ring cannot be read back, that must fail now — not at the first verification,
        // years later, when the signatures it protects are the only evidence available.
        return (FromRing(Read(path, passphrase)), true);
    }

    public (string KeyId, byte[] PrivateKey) GetSigningKey()
        => _keys.TryGetValue(_activeKeyId, out var entry)
            ? (entry.KeyId, Convert.FromBase64String(entry.PrivateKey))
            : throw new MessengerException(ErrorCode.AuditCheckpointSigningFailed,
                $"The active signing key '{_activeKeyId}' is missing from the key ring.");

    public byte[] GetPublicKey(string keyId)
        => _keys.TryGetValue(keyId, out var entry)
            ? Convert.FromBase64String(entry.PublicKey)
            : throw new MessengerException(ErrorCode.AuditCheckpointSigningFailed,
                $"Unknown signing key '{keyId}'. It is not present in the key ring at this server.");

    private static AuditSigningKeyRing Read(string path, string passphrase)
    {
        var plaintext = PassphraseSealedFile.Open(File.ReadAllBytes(path), passphrase);
        try
        {
            return JsonSerializer.Deserialize<AuditSigningKeyRing>(plaintext)
                   ?? throw new MessengerException(ErrorCode.AuditCheckpointSigningFailed,
                       "The audit signing key ring is empty.");
        }
        catch (JsonException ex)
        {
            throw new MessengerException(ErrorCode.AuditCheckpointSigningFailed,
                "The audit signing key ring is corrupt.", ex.Message);
        }
    }

    private static FileBackedAuditSigningKeyProvider FromRing(AuditSigningKeyRing ring)
    {
        if (string.IsNullOrWhiteSpace(ring.ActiveKeyId) || ring.Keys.Count == 0)
            throw new MessengerException(ErrorCode.AuditCheckpointSigningFailed,
                "The audit signing key ring names no active key.");

        var keys = ring.Keys.ToDictionary(k => k.KeyId, StringComparer.Ordinal);
        if (!keys.ContainsKey(ring.ActiveKeyId))
            throw new MessengerException(ErrorCode.AuditCheckpointSigningFailed,
                $"The audit signing key ring's active key '{ring.ActiveKeyId}' is not among its keys.");

        return new FileBackedAuditSigningKeyProvider(ring.ActiveKeyId, keys);
    }

    private static byte[] Serialize(AuditSigningKeyRing ring) => JsonSerializer.SerializeToUtf8Bytes(ring);
}

internal sealed class AuditSigningKeyRing
{
    [JsonPropertyName("v")]
    public int Version { get; set; } = 1;

    [JsonPropertyName("activeKeyId")]
    public string ActiveKeyId { get; set; } = string.Empty;

    [JsonPropertyName("keys")]
    public List<AuditSigningKeyEntry> Keys { get; set; } = [];
}

internal sealed class AuditSigningKeyEntry
{
    [JsonPropertyName("keyId")]
    public string KeyId { get; set; } = string.Empty;

    [JsonPropertyName("privateKey")]
    public string PrivateKey { get; set; } = string.Empty;

    [JsonPropertyName("publicKey")]
    public string PublicKey { get; set; } = string.Empty;
}
