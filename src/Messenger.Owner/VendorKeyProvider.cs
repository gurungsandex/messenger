using System.Text.Json;
using Messenger.Crypto;
using Messenger.Licensing;

namespace Messenger.Owner;

/// <summary>
/// Holds the vendor's Ed25519 signing keypair used to issue customer licences. The private
/// key must outlive the process for the same reason the customer server's KEK must: every
/// licence a customer holds becomes unverifiable garbage the moment the key that signed it
/// is regenerated, since <c>Licensing:VendorPublicKey</c> on every deployment is compiled in
/// from a specific keypair. Escrowed the same way as the server's KEK -- reusing
/// <see cref="FileBackedKeyStore"/>'s AES-KW wrap/unwrap rather than inventing a second
/// mechanism, since a 32-byte Ed25519 private key is exactly the shape that primitive wraps.
/// </summary>
public sealed class VendorKeyProvider
{
    private sealed record StoredKey(string WrappedPrivateKeyBase64, string KekId, string PublicKeyBase64);

    public byte[] PrivateKey { get; }
    public byte[] PublicKey { get; }

    private VendorKeyProvider(byte[] privateKey, byte[] publicKey)
    {
        PrivateKey = privateKey;
        PublicKey = publicKey;
    }

    public static (VendorKeyProvider Provider, bool Created) OpenOrCreate(
        string keyStorePath, string vendorKeyPath, string passphrase)
    {
        var (keyStore, _) = FileBackedKeyStore.OpenOrCreate(keyStorePath, passphrase);

        if (File.Exists(vendorKeyPath))
        {
            var stored = JsonSerializer.Deserialize<StoredKey>(File.ReadAllText(vendorKeyPath))
                         ?? throw new InvalidOperationException("Vendor key file is corrupt.");
            var privateKey = keyStore.Unwrap(Convert.FromBase64String(stored.WrappedPrivateKeyBase64), stored.KekId);
            return (new VendorKeyProvider(privateKey, Convert.FromBase64String(stored.PublicKeyBase64)), false);
        }

        var (newPrivate, newPublic) = LicenseDocument.GenerateVendorKeyPair();
        var wrapped = keyStore.Wrap(newPrivate);

        var directory = Path.GetDirectoryName(Path.GetFullPath(vendorKeyPath));
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);

        File.WriteAllText(vendorKeyPath, JsonSerializer.Serialize(new StoredKey(
            Convert.ToBase64String(wrapped), keyStore.ActiveKekId, Convert.ToBase64String(newPublic))));

        return (new VendorKeyProvider(newPrivate, newPublic), true);
    }
}
