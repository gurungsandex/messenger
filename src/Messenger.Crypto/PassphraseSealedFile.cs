using System.Security.Cryptography;
using Messenger.Contracts;

namespace Messenger.Crypto;

/// <summary>
/// Seals an arbitrary secret under a passphrase and writes it to disk durably.
///
/// This is the general form of what <see cref="FileBackedKeyStore"/> does for the root KEK.
/// It exists because the KEK is not the only key that has to outlive the process: the audit
/// checkpoint signing key does too, and re-deriving the same PBKDF2/AES-GCM handling at each
/// such site is how one of them ends up subtly weaker than the others.
///
/// Deliberately *not* used to re-implement the KEK escrow. That blob's layout is already on
/// disk in existing deployments, and changing how it is read would strand them.
/// </summary>
public static class PassphraseSealedFile
{
    private const int Iterations = 600_000; // OWASP 2023 floor for PBKDF2-HMAC-SHA256
    private const int SaltLength = 16;
    private const int NonceLength = 12;
    private const int TagLength = 16;
    private const int KeyLength = 32;
    private const byte Version = 1;

    private const int HeaderLength = 1 + SaltLength + NonceLength + TagLength;

    /// <summary>Seals <paramref name="plaintext"/>. Layout: [1 version][16 salt][12 nonce][16 tag][ciphertext].</summary>
    public static byte[] Seal(ReadOnlySpan<byte> plaintext, string passphrase)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(passphrase);

        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        var nonce = RandomNumberGenerator.GetBytes(NonceLength);
        var wrappingKey = Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, Iterations, HashAlgorithmName.SHA256, KeyLength);

        var result = new byte[HeaderLength + plaintext.Length];
        result[0] = Version;
        salt.CopyTo(result.AsSpan(1));
        nonce.CopyTo(result.AsSpan(1 + SaltLength));

        try
        {
            using var aes = new AesGcm(wrappingKey, TagLength);
            aes.Encrypt(
                nonce,
                plaintext,
                result.AsSpan(HeaderLength),
                result.AsSpan(1 + SaltLength + NonceLength, TagLength));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrappingKey);
        }

        return result;
    }

    /// <summary>Opens a blob produced by <see cref="Seal"/>.</summary>
    public static byte[] Open(byte[] blob, string passphrase)
    {
        ArgumentNullException.ThrowIfNull(blob);
        ArgumentException.ThrowIfNullOrWhiteSpace(passphrase);

        if (blob.Length < HeaderLength)
            throw new MessengerException(ErrorCode.KeyUnwrapFailed, "Sealed file is malformed.");
        if (blob[0] != Version)
            throw new MessengerException(ErrorCode.KeyUnwrapFailed, $"Unsupported sealed-file version {blob[0]}.");

        var salt = blob.AsSpan(1, SaltLength);
        var nonce = blob.AsSpan(1 + SaltLength, NonceLength);
        var tag = blob.AsSpan(1 + SaltLength + NonceLength, TagLength);
        var ciphertext = blob.AsSpan(HeaderLength);

        var wrappingKey = Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, Iterations, HashAlgorithmName.SHA256, KeyLength);
        var plaintext = new byte[ciphertext.Length];
        try
        {
            using var aes = new AesGcm(wrappingKey, TagLength);
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
        }
        catch (CryptographicException)
        {
            throw new MessengerException(ErrorCode.KeyUnwrapFailed,
                "Sealed file could not be decrypted — wrong passphrase or corrupted blob.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrappingKey);
        }

        return plaintext;
    }

    /// <summary>
    /// Writes through a temporary file and moves into place, so an interrupted first run
    /// cannot leave a truncated blob behind — which for key material is indistinguishable
    /// from having lost the key. Restricted to the owner before the move, so it is never
    /// briefly world-readable at its final name.
    /// </summary>
    public static void WriteAtomic(string path, byte[] contents)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(contents);

        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);

        var temporary = path + ".tmp";
        File.WriteAllBytes(temporary, contents);
        RestrictToOwner(temporary);
        File.Move(temporary, path, overwrite: false);
    }

    /// <summary>
    /// Narrows a file to owner read/write.
    ///
    /// Unix only — Windows has no equivalent mode bits, and a new file there inherits the
    /// directory's ACL, so the protection is the ACL on the key store directory. Best-effort:
    /// a file system that cannot express permissions is a reason to warn, not a reason to
    /// refuse to start and leave the server with no signing key at all.
    /// </summary>
    private static void RestrictToOwner(string path)
    {
        if (OperatingSystem.IsWindows()) return;

        try
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            // Left at the default mode. The caller surfaces the path on creation, which is
            // where an operator is already being told to secure and back it up.
        }
    }
}
