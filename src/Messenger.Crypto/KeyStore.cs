using System.Security.Cryptography;
using Messenger.Contracts;

namespace Messenger.Crypto;

/// <summary>
/// Wraps and unwraps data-encryption keys under a root KEK that never leaves the provider.
/// See docs/adr/0002-encryption-model.md.
/// </summary>
public interface IKeyStoreProvider
{
    /// <summary>Identifier of the active KEK, stored alongside every wrapped key.</summary>
    string ActiveKekId { get; }

    /// <summary>Wraps a 256-bit DEK using AES-KW (RFC 3394).</summary>
    byte[] Wrap(ReadOnlySpan<byte> dek);

    /// <summary>Unwraps a DEK previously wrapped under <paramref name="kekId"/>.</summary>
    byte[] Unwrap(byte[] wrapped, string kekId);

    /// <summary>
    /// Exports the KEK wrapped under a passphrase, for disaster-recovery escrow.
    /// A machine-bound KEK with no escrow means a dead server is unrecoverable history
    /// even with perfect database backups — the installer must call this before first use.
    /// </summary>
    byte[] ExportEscrow(string passphrase);
}

/// <summary>
/// Portable key store holding the KEK in memory, unwrapped from an escrow blob at startup.
/// This is the implementation used for development, tests, and non-Windows hosts. Windows
/// production deployments use the DPAPI-NG or TPM provider, which keep the KEK outside the
/// process; this one does not, and is not a substitute for them.
/// </summary>
public sealed class PassphraseKeyStoreProvider : IKeyStoreProvider, IDisposable
{
    private const int EscrowIterations = 600_000; // OWASP 2023 floor for PBKDF2-HMAC-SHA256
    private const int SaltLength = 16;
    private const int KeyLength = 32;

    private readonly byte[] _kek;
    private bool _disposed;

    public string ActiveKekId { get; }

    private PassphraseKeyStoreProvider(byte[] kek, string kekId)
    {
        _kek = kek;
        ActiveKekId = kekId;
    }

    /// <summary>Generates a fresh random KEK.</summary>
    public static PassphraseKeyStoreProvider Create(string? kekId = null)
        => new(RandomNumberGenerator.GetBytes(KeyLength), kekId ?? Guid.NewGuid().ToString("N"));

    /// <summary>Restores a KEK from an escrow blob produced by <see cref="ExportEscrow"/>.</summary>
    public static PassphraseKeyStoreProvider FromEscrow(byte[] escrow, string passphrase)
    {
        ArgumentNullException.ThrowIfNull(escrow);

        // layout: [1 version][16 salt][12 nonce][32 ciphertext][16 tag][16 kekId]
        const int expected = 1 + SaltLength + 12 + KeyLength + 16 + 16;
        if (escrow.Length != expected)
            throw new MessengerException(ErrorCode.KeyUnwrapFailed, "Escrow blob is malformed.");
        if (escrow[0] != 1)
            throw new MessengerException(ErrorCode.KeyUnwrapFailed, "Unsupported escrow version.");

        var salt = escrow.AsSpan(1, SaltLength);
        var nonce = escrow.AsSpan(1 + SaltLength, 12);
        var ciphertext = escrow.AsSpan(1 + SaltLength + 12, KeyLength);
        var tag = escrow.AsSpan(1 + SaltLength + 12 + KeyLength, 16);
        var kekIdBytes = escrow.AsSpan(1 + SaltLength + 12 + KeyLength + 16, 16);

        var wrappingKey = Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, EscrowIterations, HashAlgorithmName.SHA256, KeyLength);
        var kek = new byte[KeyLength];
        try
        {
            using var aes = new AesGcm(wrappingKey, 16);
            aes.Decrypt(nonce, ciphertext, tag, kek);
        }
        catch (CryptographicException)
        {
            throw new MessengerException(ErrorCode.KeyUnwrapFailed,
                "Escrow could not be decrypted — wrong passphrase or corrupted blob.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrappingKey);
        }

        return new PassphraseKeyStoreProvider(kek, new Guid(kekIdBytes).ToString("N"));
    }

    public byte[] ExportEscrow(string passphrase)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (string.IsNullOrWhiteSpace(passphrase))
            throw new ArgumentException("Escrow passphrase must not be empty.", nameof(passphrase));

        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var wrappingKey = Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, EscrowIterations, HashAlgorithmName.SHA256, KeyLength);

        var ciphertext = new byte[KeyLength];
        var tag = new byte[16];
        try
        {
            using var aes = new AesGcm(wrappingKey, 16);
            aes.Encrypt(nonce, _kek, ciphertext, tag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrappingKey);
        }

        var result = new byte[1 + SaltLength + 12 + KeyLength + 16 + 16];
        result[0] = 1;
        salt.CopyTo(result.AsSpan(1));
        nonce.CopyTo(result.AsSpan(1 + SaltLength));
        ciphertext.CopyTo(result.AsSpan(1 + SaltLength + 12));
        tag.CopyTo(result.AsSpan(1 + SaltLength + 12 + KeyLength));
        Guid.Parse(ActiveKekId).ToByteArray().CopyTo(result.AsSpan(1 + SaltLength + 12 + KeyLength + 16));
        return result;
    }

    public byte[] Wrap(ReadOnlySpan<byte> dek)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (dek.Length != KeyLength)
            throw new ArgumentException("DEK must be 256 bits.", nameof(dek));

        return AesKeyWrap.Wrap(_kek, dek.ToArray());
    }

    public byte[] Unwrap(byte[] wrapped, string kekId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(wrapped);

        if (!string.Equals(kekId, ActiveKekId, StringComparison.Ordinal))
            throw new MessengerException(ErrorCode.KeyUnwrapFailed,
                $"Key was wrapped under KEK '{kekId}', which this key store does not hold.");

        try
        {
            return AesKeyWrap.Unwrap(_kek, wrapped);
        }
        catch (CryptographicException)
        {
            throw new MessengerException(ErrorCode.KeyUnwrapFailed,
                "Wrapped key failed its integrity check.");
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        CryptographicOperations.ZeroMemory(_kek);
        _disposed = true;
    }
}

/// <summary>
/// AES Key Wrap (RFC 3394). .NET exposes no managed AES-KW, so the algorithm is implemented
/// here directly on top of the raw AES block cipher. Unwrap validates the RFC's fixed
/// integrity check value, which is what makes a corrupted or foreign wrapped key detectable.
///
/// Verified against the RFC 3394 §4.6 test vector — a self-consistent wrap/unwrap pair
/// proves nothing, since a wrong cipher mode roundtrips happily against itself.
/// </summary>
public static class AesKeyWrap
{
    private static readonly byte[] DefaultIv = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];

    /// <summary>
    /// Key wrap uses AES as a bare block function, so the mode must be ECB with no padding.
    /// Creating this centrally keeps a caller from handing in a default (CBC) instance,
    /// which silently produces something that is not AES-KW.
    /// </summary>
    private static Aes CreateBlockCipher(byte[] kek)
    {
        var aes = Aes.Create();
        aes.Key = kek;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        return aes;
    }

    public static byte[] Wrap(byte[] kek, byte[] plaintextKey)
    {
        ArgumentNullException.ThrowIfNull(kek);
        ArgumentNullException.ThrowIfNull(plaintextKey);
        if (plaintextKey.Length % 8 != 0 || plaintextKey.Length < 16)
            throw new ArgumentException("Key to wrap must be a multiple of 64 bits and at least 128 bits.");

        using var aes = CreateBlockCipher(kek);
        int n = plaintextKey.Length / 8;
        var a = (byte[])DefaultIv.Clone();
        var r = new byte[n][];
        for (int i = 0; i < n; i++)
        {
            r[i] = new byte[8];
            Array.Copy(plaintextKey, i * 8, r[i], 0, 8);
        }

        using var encryptor = aes.CreateEncryptor();
        var block = new byte[16];
        var outBlock = new byte[16];

        for (int j = 0; j < 6; j++)
        {
            for (int i = 0; i < n; i++)
            {
                a.CopyTo(block, 0);
                r[i].CopyTo(block, 8);
                encryptor.TransformBlock(block, 0, 16, outBlock, 0);

                Array.Copy(outBlock, 0, a, 0, 8);
                // t = (n * j) + i + 1, XORed into the low-order bytes of A
                long t = (long)n * j + i + 1;
                for (int k = 0; k < 8; k++)
                    a[7 - k] ^= (byte)(t >> (8 * k));

                Array.Copy(outBlock, 8, r[i], 0, 8);
            }
        }

        var result = new byte[(n + 1) * 8];
        a.CopyTo(result, 0);
        for (int i = 0; i < n; i++) r[i].CopyTo(result, (i + 1) * 8);
        return result;
    }

    public static byte[] Unwrap(byte[] kek, byte[] wrapped)
    {
        ArgumentNullException.ThrowIfNull(kek);
        ArgumentNullException.ThrowIfNull(wrapped);
        if (wrapped.Length % 8 != 0 || wrapped.Length < 24)
            throw new CryptographicException("Wrapped key has an invalid length.");

        using var aes = CreateBlockCipher(kek);
        int n = wrapped.Length / 8 - 1;
        var a = new byte[8];
        Array.Copy(wrapped, 0, a, 0, 8);
        var r = new byte[n][];
        for (int i = 0; i < n; i++)
        {
            r[i] = new byte[8];
            Array.Copy(wrapped, (i + 1) * 8, r[i], 0, 8);
        }

        using var decryptor = aes.CreateDecryptor();
        var block = new byte[16];
        var outBlock = new byte[16];

        for (int j = 5; j >= 0; j--)
        {
            for (int i = n - 1; i >= 0; i--)
            {
                long t = (long)n * j + i + 1;
                for (int k = 0; k < 8; k++)
                    a[7 - k] ^= (byte)(t >> (8 * k));

                a.CopyTo(block, 0);
                r[i].CopyTo(block, 8);
                decryptor.TransformBlock(block, 0, 16, outBlock, 0);

                Array.Copy(outBlock, 0, a, 0, 8);
                Array.Copy(outBlock, 8, r[i], 0, 8);
            }
        }

        if (!CryptographicOperations.FixedTimeEquals(a, DefaultIv))
            throw new CryptographicException("Key wrap integrity check failed.");

        var result = new byte[n * 8];
        for (int i = 0; i < n; i++) r[i].CopyTo(result, i * 8);
        return result;
    }
}
