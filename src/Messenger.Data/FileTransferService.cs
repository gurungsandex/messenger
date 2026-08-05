using System.Security.Cryptography;
using Messenger.Contracts;
using Messenger.Core;
using Messenger.Crypto;
using Microsoft.EntityFrameworkCore;

namespace Messenger.Data;

public sealed record FilePolicy(
    long MaxFileBytes,
    long PerUserQuotaBytes,
    long StorageCapacityBytes,
    IReadOnlySet<string> BlockedExtensions,
    bool ScanningEnabled,
    bool FailClosedOnScannerError,
    TimeSpan UploadWindow)
{
    /// <summary>
    /// Defaults until a licence supplies the real file-size cap (LIC-107 / FILE-101).
    ///
    /// The blocked-extension list is a policy convenience, not a security boundary — an
    /// attacker renames the file. AV scanning and the client's own handling are what
    /// actually matter.
    /// </summary>
    public static readonly FilePolicy Default = new(
        MaxFileBytes: 100L * 1024 * 1024,
        PerUserQuotaBytes: 5L * 1024 * 1024 * 1024,
        StorageCapacityBytes: long.MaxValue,
        BlockedExtensions: new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js", ".jar", ".msi", ".ps1" },
        ScanningEnabled: false,
        FailClosedOnScannerError: true,
        UploadWindow: TimeSpan.FromHours(6));
}

public sealed record UploadSlot(Guid FileId, string StorageKey, int ChunkSize, long ChunkCount, DateTimeOffset ExpiresAt);

/// <summary>
/// Relayed file transfer: chunked, encrypted at rest under a per-file DEK, resumable.
///
/// Files are relayed through the server rather than sent peer-to-peer. P2P would defeat
/// audit logging and AV scanning, break across segmented networks, and contradict the
/// product's "no third-party relay" guarantee by requiring NAT traversal infrastructure.
/// </summary>
public sealed class FileTransferService(
    MessengerDbContext db,
    IFileStore store,
    IKeyStoreProvider keyStore,
    FileCipher cipher,
    AuditService audit,
    IMalwareScanner? scanner = null,
    TimeProvider? timeProvider = null)
{
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;
    private readonly IMalwareScanner _scanner = scanner ?? new NoOpMalwareScanner();

    /// <summary>
    /// Reserves an upload. Every policy check happens here, before a single byte moves —
    /// rejecting a 90 MB upload after transferring it wastes the user's time and the
    /// server's bandwidth for a decision that was knowable up front.
    /// </summary>
    public async Task<UploadSlot> BeginUploadAsync(
        Guid uploaderId, Guid conversationId, string fileName, long sizeBytes,
        byte[] sha256Plaintext, string? contentType = null,
        FilePolicy? policy = null, int chunkSize = FileCipher.DefaultChunkSize,
        CancellationToken ct = default)
    {
        policy ??= FilePolicy.Default;

        await EnsureParticipantAsync(uploaderId, conversationId, ct);

        if (string.IsNullOrWhiteSpace(fileName) || fileName.Length > 255)
            throw new MessengerException(ErrorCode.FileNameInvalid, "File name is missing or too long.");

        if (sizeBytes <= 0)
            throw new MessengerException(ErrorCode.MalformedRequest, "File size must be positive.");

        if (sizeBytes > policy.MaxFileBytes)
            throw new MessengerException(ErrorCode.FileTooLarge,
                $"File exceeds the {policy.MaxFileBytes:N0}-byte limit set by the licence.");

        var extension = Path.GetExtension(fileName);
        if (!string.IsNullOrEmpty(extension) && policy.BlockedExtensions.Contains(extension))
            throw new MessengerException(ErrorCode.FileTypeBlocked, $"Files of type '{extension}' are blocked by policy.");

        if (sha256Plaintext is not { Length: 32 })
            throw new MessengerException(ErrorCode.MalformedRequest, "A SHA-256 of the file contents is required.");

        var used = await db.StoredFiles
            .Where(f => f.UploaderId == uploaderId && f.DeletedAt == null)
            .SumAsync(f => f.SizeBytes, ct);
        if (used + sizeBytes > policy.PerUserQuotaBytes)
            throw new MessengerException(ErrorCode.QuotaExceeded, "Your storage quota is full.");

        if (await store.GetUsedBytesAsync(ct) + sizeBytes > policy.StorageCapacityBytes)
            throw new MessengerException(ErrorCode.StorageFull, "The server file store has insufficient space.");

        var now = _time.GetUtcNow();
        var dek = RandomNumberGenerator.GetBytes(32);
        StoredFile file;
        try
        {
            file = new StoredFile
            {
                ConversationId = conversationId,
                UploaderId = uploaderId,
                FileName = fileName,
                ContentType = contentType,
                SizeBytes = sizeBytes,
                Sha256Plaintext = sha256Plaintext,
                StorageKey = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant(),
                WrappedDek = keyStore.Wrap(dek),
                KekId = keyStore.ActiveKekId,
                NoncePrefix = FileCipher.GenerateNoncePrefix(),
                ChunkSize = chunkSize,
                ChunkCount = (sizeBytes + chunkSize - 1) / chunkSize,
                CreatedAt = now,
                ExpiresAt = now + policy.UploadWindow,
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }

        db.StoredFiles.Add(file);
        await db.SaveChangesAsync(ct);

        await audit.AppendAsync("file.upload_begin", "success", uploaderId, "client", null,
            "file", file.Id, $"{{\"size\":{sizeBytes},\"chunks\":{file.ChunkCount}}}", ct);

        return new UploadSlot(file.Id, file.StorageKey, file.ChunkSize, file.ChunkCount, file.ExpiresAt!.Value);
    }

    /// <summary>
    /// Accepts one chunk. Re-uploading a chunk already received is allowed and idempotent,
    /// which is what makes an interrupted upload resumable rather than restartable.
    /// </summary>
    public async Task UploadChunkAsync(
        Guid uploaderId, Guid fileId, long chunkIndex, byte[] plaintext, CancellationToken ct = default)
    {
        var file = await RequireUploadableAsync(uploaderId, fileId, ct);

        if (chunkIndex < 0 || chunkIndex >= file.ChunkCount)
            throw new MessengerException(ErrorCode.ChunkSequenceError,
                $"Chunk index {chunkIndex} is outside the expected range 0..{file.ChunkCount - 1}.");

        var expectedLength = chunkIndex == file.ChunkCount - 1
            ? (int)(file.SizeBytes - chunkIndex * file.ChunkSize)
            : file.ChunkSize;

        if (plaintext.Length != expectedLength)
            throw new MessengerException(ErrorCode.ChunkSequenceError,
                $"Chunk {chunkIndex} is {plaintext.Length} bytes; {expectedLength} were expected.");

        var dek = keyStore.Unwrap(file.WrappedDek, file.KekId);
        byte[] ciphertext, tag;
        try
        {
            (ciphertext, tag) = cipher.SealChunk(
                dek, plaintext, file.Id, file.NoncePrefix, chunkIndex, file.ChunkCount, file.KeyVersion);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }

        await store.WriteChunkAsync(file.StorageKey, chunkIndex, ciphertext, ct);

        var existing = await db.FileChunks.FirstOrDefaultAsync(c => c.FileId == fileId && c.ChunkIndex == chunkIndex, ct);
        if (existing is null)
        {
            db.FileChunks.Add(new FileChunk
            {
                FileId = fileId,
                ChunkIndex = chunkIndex,
                ByteLength = plaintext.Length,
                AuthTag = tag,
                ReceivedAt = _time.GetUtcNow(),
            });
        }
        else
        {
            existing.ByteLength = plaintext.Length;
            existing.AuthTag = tag;
            existing.ReceivedAt = _time.GetUtcNow();
        }

        await db.SaveChangesAsync(ct);
    }

    /// <summary>Chunk indices already accepted, so an interrupted client can resume.</summary>
    public async Task<IReadOnlyList<long>> GetReceivedChunksAsync(
        Guid uploaderId, Guid fileId, CancellationToken ct = default)
    {
        await RequireUploadableAsync(uploaderId, fileId, ct);
        return await db.FileChunks.Where(c => c.FileId == fileId)
            .OrderBy(c => c.ChunkIndex).Select(c => c.ChunkIndex).ToListAsync(ct);
    }

    /// <summary>
    /// Finalises an upload: verifies every chunk arrived, verifies the plaintext digest
    /// matches what the client declared, builds the tamper-evident manifest, and runs AV.
    /// </summary>
    public async Task CompleteUploadAsync(Guid uploaderId, Guid fileId, CancellationToken ct = default)
    {
        var file = await RequireUploadableAsync(uploaderId, fileId, ct);

        var chunks = await db.FileChunks.Where(c => c.FileId == fileId).OrderBy(c => c.ChunkIndex).ToListAsync(ct);

        if (chunks.Count != file.ChunkCount)
            throw new MessengerException(ErrorCode.ChunkSequenceError,
                $"{chunks.Count} of {file.ChunkCount} chunks were received.");

        for (int i = 0; i < chunks.Count; i++)
        {
            if (chunks[i].ChunkIndex != i)
                throw new MessengerException(ErrorCode.ChunkSequenceError, $"Chunk {i} is missing.");
        }

        // Reassemble and verify against the digest the client declared up front. This is
        // what catches corruption in transit and a client that lied about its content.
        var plaintext = await ReadPlaintextAsync(file, chunks, ct);
        try
        {
            var actual = SHA256.HashData(plaintext);
            if (!CryptographicOperations.FixedTimeEquals(actual, file.Sha256Plaintext))
            {
                file.UploadState = Core.UploadState.Failed;
                await db.SaveChangesAsync(ct);
                await audit.AppendAsync("file.upload_complete", "error", uploaderId, "client", null,
                    "file", fileId, "{\"reason\":\"digest_mismatch\"}", ct);
                throw new MessengerException(ErrorCode.FileIntegrityCheckFailed,
                    "The uploaded content does not match the declared SHA-256.");
            }

            file.ChunkManifest = FileCipher.BuildManifest(chunks.Select(c => c.AuthTag).ToList());
            file.UploadState = Core.UploadState.Complete;
            file.CompletedAt = _time.GetUtcNow();

            await RunScanAsync(file, plaintext, ct);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }

        await db.SaveChangesAsync(ct);
        await audit.AppendAsync("file.upload_complete", "success", uploaderId, "client", null,
            "file", fileId, $"{{\"av\":\"{file.AvState}\"}}", ct);
    }

    /// <summary>
    /// Downloads a completed file. Membership is re-checked here: a file id alone conveys
    /// no authority, and the uploader's permission is not the downloader's.
    /// </summary>
    public async Task<byte[]> DownloadAsync(Guid userId, Guid fileId, CancellationToken ct = default)
    {
        var file = await db.StoredFiles.FirstOrDefaultAsync(f => f.Id == fileId && f.DeletedAt == null, ct)
                   ?? throw new MessengerException(ErrorCode.FileNotFound, "File not found.");

        // Membership alone is not sufficient. Group history visibility windows apply to
        // files exactly as they do to messages: a member added today must not be able to
        // download files shared before they joined, and a removed member must not reach
        // files shared after they left. Checking only membership would leave the
        // confidentiality boundary enforced for messages and open for their attachments.
        if (!await CanAccessFileAsync(userId, file, ct))
            throw new MessengerException(ErrorCode.FileAccessDenied, "You do not have access to this file.");

        if (file.UploadState != Core.UploadState.Complete)
            throw new MessengerException(ErrorCode.FileNotFound, "This file was never completed.");

        if (file.ExpiresAt is { } expiry && expiry <= _time.GetUtcNow() && file.CompletedAt is null)
            throw new MessengerException(ErrorCode.FileExpired, "This file has expired.");

        switch (file.AvState)
        {
            case AvScanState.Infected:
                throw new MessengerException(ErrorCode.FileFailedMalwareScan, "This file was flagged by malware scanning.");
            case AvScanState.Scanning:
                throw new MessengerException(ErrorCode.ScanInProgress, "This file is still being scanned.");
            case AvScanState.Error:
                throw new MessengerException(ErrorCode.ScannerUnavailable, "This file could not be scanned and is withheld.");
        }

        var chunks = await db.FileChunks.Where(c => c.FileId == fileId).OrderBy(c => c.ChunkIndex).ToListAsync(ct);

        // Verify the manifest before serving. Per-chunk tags catch a modified chunk, but
        // only the manifest catches a set of individually valid chunks that were reordered
        // or truncated at the storage layer.
        var manifest = FileCipher.BuildManifest(chunks.Select(c => c.AuthTag).ToList());
        if (file.ChunkManifest is null || !CryptographicOperations.FixedTimeEquals(manifest, file.ChunkManifest))
            throw new MessengerException(ErrorCode.ChunkManifestMismatch,
                "The stored chunk set does not match this file's manifest; it will not be served.");

        var plaintext = await ReadPlaintextAsync(file, chunks, ct);

        await audit.AppendAsync("file.download", "success", userId, "client", null, "file", fileId, null, ct);
        return plaintext;
    }

    /// <summary>
    /// Deletes a file by destroying its key as well as its bytes — crypto-shredding.
    ///
    /// This is why files hold a per-file DEK: without it, a restored backup of the file
    /// store would resurrect content that was deliberately deleted.
    /// </summary>
    public async Task DeleteAsync(Guid actorId, Guid fileId, CancellationToken ct = default)
    {
        var file = await db.StoredFiles.FirstOrDefaultAsync(f => f.Id == fileId && f.DeletedAt == null, ct)
                   ?? throw new MessengerException(ErrorCode.FileNotFound, "File not found.");

        await store.DeleteAsync(file.StorageKey, ct);

        file.WrappedDek = [];
        file.DeletedAt = _time.GetUtcNow();

        db.FileChunks.RemoveRange(await db.FileChunks.Where(c => c.FileId == fileId).ToListAsync(ct));
        await db.SaveChangesAsync(ct);

        await audit.AppendAsync("file.delete", "success", actorId, "client", null,
            "file", fileId, "{\"crypto_shredded\":true}", ct);
    }

    private async Task RunScanAsync(StoredFile file, byte[] plaintext, CancellationToken ct)
    {
        if (_scanner is NoOpMalwareScanner)
        {
            file.AvState = AvScanState.NotScanned;
            return;
        }

        try
        {
            using var stream = new MemoryStream(plaintext, writable: false);
            var (isClean, detail) = await _scanner.ScanAsync(stream, file.FileName, ct);
            file.AvState = isClean ? AvScanState.Clean : AvScanState.Infected;
            file.AvDetail = detail;
        }
        catch (Exception ex)
        {
            // Fail-closed is the default: a file that could not be scanned is withheld
            // rather than served on the assumption it is probably fine.
            file.AvState = AvScanState.Error;
            file.AvDetail = ex.Message;
        }
    }

    private async Task<byte[]> ReadPlaintextAsync(StoredFile file, List<FileChunk> chunks, CancellationToken ct)
    {
        var dek = keyStore.Unwrap(file.WrappedDek, file.KekId);
        try
        {
            using var assembled = new MemoryStream();
            foreach (var chunk in chunks)
            {
                var ciphertext = await store.ReadChunkAsync(file.StorageKey, chunk.ChunkIndex, ct)
                                 ?? throw new MessengerException(ErrorCode.FileNotFound,
                                     $"Chunk {chunk.ChunkIndex} is missing from the file store.");

                var plain = cipher.OpenChunk(
                    dek, ciphertext, chunk.AuthTag, file.Id, file.NoncePrefix,
                    chunk.ChunkIndex, file.ChunkCount, file.KeyVersion);

                assembled.Write(plain, 0, plain.Length);
                CryptographicOperations.ZeroMemory(plain);
            }
            return assembled.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    private async Task<StoredFile> RequireUploadableAsync(Guid uploaderId, Guid fileId, CancellationToken ct)
    {
        var file = await db.StoredFiles.FirstOrDefaultAsync(f => f.Id == fileId && f.DeletedAt == null, ct)
                   ?? throw new MessengerException(ErrorCode.FileNotFound, "Upload not found.");

        if (file.UploaderId != uploaderId)
            throw new MessengerException(ErrorCode.FileAccessDenied, "This upload belongs to another user.");

        if (file.UploadState == Core.UploadState.Complete)
            throw new MessengerException(ErrorCode.UploadCancelled, "This upload is already complete.");

        if (file.UploadState is Core.UploadState.Failed or Core.UploadState.Expired)
            throw new MessengerException(ErrorCode.UploadSessionExpired, "This upload is no longer active.");

        if (file.ExpiresAt is { } expiry && expiry <= _time.GetUtcNow())
        {
            file.UploadState = Core.UploadState.Expired;
            await db.SaveChangesAsync(ct);
            throw new MessengerException(ErrorCode.UploadSessionExpired,
                "The upload window has closed; start the upload again.");
        }

        return file;
    }

    private async Task<bool> IsParticipantAsync(Guid userId, Guid conversationId, CancellationToken ct)
        => await db.ConversationParticipants
            .AnyAsync(p => p.ConversationId == conversationId && p.UserId == userId && p.LeftAt == null, ct);

    /// <summary>
    /// Whether a user may read a stored file, honouring the same visibility window that
    /// governs messages.
    ///
    /// A file is anchored to the message that carried it. Where a file has no message —
    /// an upload completed but never sent — only a current participant may reach it, and
    /// only if they were present when it was created.
    /// </summary>
    private async Task<bool> CanAccessFileAsync(Guid userId, StoredFile file, CancellationToken ct)
    {
        var window = await db.ConversationParticipants
            .Where(p => p.ConversationId == file.ConversationId && p.UserId == userId)
            .Select(p => new { p.VisibleFromSeq, p.VisibleToSeq, p.LeftAt })
            .FirstOrDefaultAsync(ct);

        if (window is null) return false;

        // The uploader always retains access to their own upload.
        if (file.UploaderId == userId) return true;

        var messageSeq = file.MessageId is null
            ? (long?)null
            : await db.Messages.Where(m => m.Id == file.MessageId)
                .Select(m => (long?)m.Seq).FirstOrDefaultAsync(ct);

        if (messageSeq is { } seq)
            return seq >= window.VisibleFromSeq && (window.VisibleToSeq is null || seq <= window.VisibleToSeq);

        // Unattached upload: require current membership, and require that the participant's
        // window was already open when the file was created.
        if (window.LeftAt is not null) return false;

        var seqAtUpload = await db.Messages
            .Where(m => m.ConversationId == file.ConversationId && m.ServerReceivedAt <= file.CreatedAt)
            .CountAsync(ct);

        return window.VisibleFromSeq <= seqAtUpload + 1;
    }

    private async Task EnsureParticipantAsync(Guid userId, Guid conversationId, CancellationToken ct)
    {
        if (!await IsParticipantAsync(userId, conversationId, ct))
            throw new MessengerException(ErrorCode.NotAConversationParticipant,
                "You are not a participant in this conversation.");
    }
}
