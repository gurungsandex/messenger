using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Messenger.Contracts;

namespace Messenger.Crypto;

/// <summary>A sealed message body: ciphertext plus the AEAD parameters needed to open it.</summary>
public sealed record SealedMessage(byte[] Ciphertext, byte[] Nonce, byte[] AuthTag, short AadVersion);

/// <summary>
/// AES-256-GCM message body encryption under a per-conversation DEK.
///
/// Identifiers are bound into the AAD, so a ciphertext cannot be silently relocated to
/// another message, conversation, or sender by someone with database write access — the
/// tag check fails. That is what makes this tamper-resistant and not merely confidential.
/// </summary>
public sealed class MessageCipher
{
    public const short CurrentAadVersion = 1;
    private const int NonceLength = 12;
    private const int TagLength = 16;

    public SealedMessage Seal(
        ReadOnlySpan<byte> dek,
        string plaintext,
        Guid conversationId,
        Guid messageId,
        Guid senderId,
        int keyVersion)
    {
        ArgumentNullException.ThrowIfNull(plaintext);

        var body = Encoding.UTF8.GetBytes(plaintext);
        var nonce = RandomNumberGenerator.GetBytes(NonceLength);
        var aad = BuildAad(conversationId, messageId, senderId, keyVersion, CurrentAadVersion);

        var ciphertext = new byte[body.Length];
        var tag = new byte[TagLength];

        using var aes = new AesGcm(dek, TagLength);
        aes.Encrypt(nonce, body, ciphertext, tag, aad);

        CryptographicOperations.ZeroMemory(body);
        return new SealedMessage(ciphertext, nonce, tag, CurrentAadVersion);
    }

    public string Open(
        ReadOnlySpan<byte> dek,
        SealedMessage sealedMessage,
        Guid conversationId,
        Guid messageId,
        Guid senderId,
        int keyVersion)
    {
        ArgumentNullException.ThrowIfNull(sealedMessage);

        if (sealedMessage.AadVersion != CurrentAadVersion)
            throw new MessengerException(ErrorCode.MessageDecryptionFailed,
                $"Unsupported AAD version {sealedMessage.AadVersion}.");

        var aad = BuildAad(conversationId, messageId, senderId, keyVersion, sealedMessage.AadVersion);
        var body = new byte[sealedMessage.Ciphertext.Length];

        try
        {
            using var aes = new AesGcm(dek, TagLength);
            aes.Decrypt(sealedMessage.Nonce, sealedMessage.Ciphertext, sealedMessage.AuthTag, body, aad);
        }
        catch (CryptographicException)
        {
            // Either the ciphertext was altered, or it was moved from another row. Both are
            // integrity incidents rather than ordinary failures — see SRV-304.
            throw new MessengerException(ErrorCode.MessageDecryptionFailed,
                "Message failed its authentication check; it may have been altered or relocated.");
        }

        return Encoding.UTF8.GetString(body);
    }

    /// <summary>
    /// AAD = conversation_id ‖ message_id ‖ sender_id ‖ key_version ‖ aad_version.
    /// Fixed-width fields only, so the encoding is unambiguous and cannot be confused by
    /// shifting bytes between adjacent fields.
    /// </summary>
    private static byte[] BuildAad(Guid conversationId, Guid messageId, Guid senderId, int keyVersion, short aadVersion)
    {
        var aad = new byte[16 * 3 + 4 + 2];
        conversationId.TryWriteBytes(aad.AsSpan(0, 16));
        messageId.TryWriteBytes(aad.AsSpan(16, 16));
        senderId.TryWriteBytes(aad.AsSpan(32, 16));
        BinaryPrimitives.WriteInt32BigEndian(aad.AsSpan(48, 4), keyVersion);
        BinaryPrimitives.WriteInt16BigEndian(aad.AsSpan(52, 2), aadVersion);
        return aad;
    }
}
