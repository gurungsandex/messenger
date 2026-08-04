using System.Buffers.Binary;
using System.Security.Cryptography;
using Messenger.Contracts;

namespace Messenger.Crypto;

/// <summary>
/// Chunked AES-256-GCM file encryption under a per-file DEK.
///
/// Files get their own key rather than sharing the conversation key because their
/// lifecycles are independent — individually shared, scanned, retained, exported, and
/// deleted. A per-file key makes crypto-shredding one file possible: destroy the key and
/// the content is unrecoverable even from a restored backup of the file store.
///
/// Nonces are a 32-bit random per-file prefix followed by a 64-bit chunk counter. Unlike
/// random nonces, a counter has no birthday bound, so collision risk within a file is
/// eliminated rather than merely bounded.
/// </summary>
public sealed class FileCipher
{
    public const int DefaultChunkSize = 4 * 1024 * 1024;
    private const int NonceLength = 12;
    private const int TagLength = 16;
    private const int NoncePrefixLength = 4;

    public static byte[] GenerateNoncePrefix() => RandomNumberGenerator.GetBytes(NoncePrefixLength);

    /// <summary>
    /// Encrypts one chunk. The chunk index, total count, and file id are bound into the AAD,
    /// so a chunk cannot be reordered, duplicated into another position, or moved to a
    /// different file without failing its tag check.
    ///
    /// Binding <paramref name="chunkCount"/> is what makes truncation detectable: dropping
    /// trailing chunks would otherwise leave every remaining chunk individually valid.
    /// </summary>
    public (byte[] Ciphertext, byte[] Tag) SealChunk(
        ReadOnlySpan<byte> dek,
        ReadOnlySpan<byte> plaintext,
        Guid fileId,
        byte[] noncePrefix,
        long chunkIndex,
        long chunkCount,
        int keyVersion)
    {
        var nonce = BuildNonce(noncePrefix, chunkIndex);
        var aad = BuildAad(fileId, chunkIndex, chunkCount, keyVersion);

        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagLength];

        using var aes = new AesGcm(dek, TagLength);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        return (ciphertext, tag);
    }

    public byte[] OpenChunk(
        ReadOnlySpan<byte> dek,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Guid fileId,
        byte[] noncePrefix,
        long chunkIndex,
        long chunkCount,
        int keyVersion)
    {
        var nonce = BuildNonce(noncePrefix, chunkIndex);
        var aad = BuildAad(fileId, chunkIndex, chunkCount, keyVersion);

        var plaintext = new byte[ciphertext.Length];
        try
        {
            using var aes = new AesGcm(dek, TagLength);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);
        }
        catch (CryptographicException)
        {
            throw new MessengerException(ErrorCode.FileDecryptionFailed,
                $"Chunk {chunkIndex} failed its authentication check; the file may have been altered.");
        }

        return plaintext;
    }

    /// <summary>
    /// Builds the manifest: SHA-256 over every chunk's authentication tag, in order.
    ///
    /// Per-chunk tags alone catch a modified chunk but not a *rearranged set of valid
    /// chunks* at the storage layer. The manifest covers the sequence as a whole.
    /// </summary>
    public static byte[] BuildManifest(IReadOnlyList<byte[]> chunkTags)
    {
        ArgumentNullException.ThrowIfNull(chunkTags);

        using var sha = SHA256.Create();
        var countBytes = new byte[8];
        BinaryPrimitives.WriteInt64BigEndian(countBytes, chunkTags.Count);
        sha.TransformBlock(countBytes, 0, countBytes.Length, null, 0);

        for (int i = 0; i < chunkTags.Count; i++)
        {
            var indexBytes = new byte[8];
            BinaryPrimitives.WriteInt64BigEndian(indexBytes, i);
            sha.TransformBlock(indexBytes, 0, indexBytes.Length, null, 0);
            sha.TransformBlock(chunkTags[i], 0, chunkTags[i].Length, null, 0);
        }

        sha.TransformFinalBlock([], 0, 0);
        return sha.Hash!;
    }

    private static byte[] BuildNonce(byte[] noncePrefix, long chunkIndex)
    {
        if (noncePrefix.Length != NoncePrefixLength)
            throw new ArgumentException("Nonce prefix must be 4 bytes.", nameof(noncePrefix));
        if (chunkIndex < 0)
            throw new ArgumentOutOfRangeException(nameof(chunkIndex));

        var nonce = new byte[NonceLength];
        noncePrefix.CopyTo(nonce, 0);
        BinaryPrimitives.WriteInt64BigEndian(nonce.AsSpan(NoncePrefixLength), chunkIndex);
        return nonce;
    }

    private static byte[] BuildAad(Guid fileId, long chunkIndex, long chunkCount, int keyVersion)
    {
        var aad = new byte[16 + 8 + 8 + 4];
        fileId.TryWriteBytes(aad.AsSpan(0, 16));
        BinaryPrimitives.WriteInt64BigEndian(aad.AsSpan(16, 8), chunkIndex);
        BinaryPrimitives.WriteInt64BigEndian(aad.AsSpan(24, 8), chunkCount);
        BinaryPrimitives.WriteInt32BigEndian(aad.AsSpan(32, 4), keyVersion);
        return aad;
    }
}
