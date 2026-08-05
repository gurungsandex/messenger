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

        // Only measured when a capacity is actually configured. The local store measures by
        // walking every file it holds, so an unbounded capacity — the default — was paying
        // for a full directory enumeration on every single upload and discarding the answer.
        if (policy.StorageCapacityBytes != long.MaxValue
            && await store.GetUsedBytesAsync(ct) + sizeBytes > policy.StorageCapacityBytes)
        {
            throw new MessengerException(ErrorCode.StorageFull, "The server file store has insufficient space.");
        }

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

        // Verify against the digest the client declared up front. This is what catches
        // corruption in transit and a client that lied about its content.
        //
        // Hashed a chunk at a time rather than over a reassembled copy: the whole point of
        // chunking is that a 100 MB transfer never needs 100 MB of server memory, and
        // reassembling to hash gave that back — with the growth churn of a MemoryStream on
        // top. Only a configured scanner needs the file whole.
        using (var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
        {
            await WritePlaintextAsync(file, chunks, new IncrementalHashStream(digest), ct);

            if (!CryptographicOperations.FixedTimeEquals(digest.GetCurrentHash(), file.Sha256Plaintext))
            {
                file.UploadState = Core.UploadState.Failed;
                await db.SaveChangesAsync(ct);
                await audit.AppendAsync("file.upload_complete", "error", uploaderId, "client", null,
                    "file", fileId, "{\"reason\":\"digest_mismatch\"}", ct);
                throw new MessengerException(ErrorCode.FileIntegrityCheckFailed,
                    "The uploaded content does not match the declared SHA-256.");
            }
        }

        file.ChunkManifest = FileCipher.BuildManifest(chunks.Select(c => c.AuthTag).ToList());
        file.UploadState = Core.UploadState.Complete;
        file.CompletedAt = _time.GetUtcNow();

        await RunScanAsync(file, chunks, ct);

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
        var (file, chunks) = await AuthoriseDownloadAsync(userId, fileId, ct);

        // One exactly-sized allocation. Assembling into a growable MemoryStream and then
        // calling ToArray held two copies of the file at once and, because the stream
        // doubles as it grows, reserved up to twice the file size for the first of them —
        // roughly 3x the file in flight, per concurrent download.
        var plaintext = new byte[TotalBytes(file, chunks)];
        await WritePlaintextAsync(file, chunks, new MemoryStream(plaintext, writable: true), ct);

        await audit.AppendAsync("file.download", "success", userId, "client", null, "file", fileId, null, ct);
        return plaintext;
    }

    /// <summary>
    /// Streams a completed file to <paramref name="destination"/>, decrypting a chunk at a
    /// time. Preferred over <see cref="DownloadAsync"/> wherever the caller has somewhere to
    /// write to — an HTTP response body, a pipe — because peak memory stays at one chunk
    /// however large the file is.
    /// </summary>
    public async Task DownloadToAsync(Guid userId, Guid fileId, Stream destination, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(destination);

        var (file, chunks) = await AuthoriseDownloadAsync(userId, fileId, ct);
        await WritePlaintextAsync(file, chunks, destination, ct);

        await audit.AppendAsync("file.download", "success", userId, "client", null, "file", fileId, null, ct);
    }

    /// <summary>
    /// Every check a download must pass, in order, returning the chunk set to read. Shared
    /// so the buffered and streaming paths cannot drift apart on what they enforce.
    /// </summary>
    private async Task<(StoredFile File, List<FileChunk> Chunks)> AuthoriseDownloadAsync(
        Guid userId, Guid fileId, CancellationToken ct)
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

        return (file, chunks);
    }

    /// <summary>
    /// Deletes a file by destroying its key as well as its bytes — crypto-shredding.
    ///
    /// This is why files hold a per-file DEK: without it, a restored backup of the file
    /// store would resurrect content that was deliberately deleted.
    /// </summary>
    /// <param name="asAdministrator">
    /// Set only by a caller that has already made its own authorization decision — a future
    /// retention or moderation route, which would check a permission first. Deletion here
    /// is irreversible — the key is destroyed, so no backup restores the content — and every
    /// other entry point in this service checks the caller against the file. Defaulting this
    /// to false means a new call site has to opt into skipping the ownership check rather
    /// than silently inheriting no check at all.
    /// </param>
    public async Task DeleteAsync(
        Guid actorId, Guid fileId, bool asAdministrator = false, CancellationToken ct = default)
    {
        var file = await db.StoredFiles.FirstOrDefaultAsync(f => f.Id == fileId && f.DeletedAt == null, ct)
                   ?? throw new MessengerException(ErrorCode.FileNotFound, "File not found.");

        if (!asAdministrator && file.UploaderId != actorId)
        {
            await audit.AppendAsync("file.delete", "denied", actorId, "client", null,
                "file", fileId, "{\"reason\":\"not_uploader\"}", ct);
            throw new MessengerException(ErrorCode.FileAccessDenied,
                "Only the uploader can delete this file.");
        }

        await store.DeleteAsync(file.StorageKey, ct);

        file.WrappedDek = [];
        file.DeletedAt = _time.GetUtcNow();

        db.FileChunks.RemoveRange(await db.FileChunks.Where(c => c.FileId == fileId).ToListAsync(ct));
        await db.SaveChangesAsync(ct);

        await audit.AppendAsync("file.delete", "success", actorId, "client", null,
            "file", fileId,
            $"{{\"crypto_shredded\":true,\"as_administrator\":{(asAdministrator ? "true" : "false")}}}", ct);
    }

    /// <summary>
    /// Runs the configured scanner over a completed upload.
    ///
    /// The file is reassembled only when a scanner is actually configured — the shipped
    /// default is the no-op, and materialising the whole payload to hand to something that
    /// ignores it was the single largest allocation in the upload path.
    /// </summary>
    private async Task RunScanAsync(StoredFile file, List<FileChunk> chunks, CancellationToken ct)
    {
        if (_scanner is NoOpMalwareScanner)
        {
            file.AvState = AvScanState.NotScanned;
            return;
        }

        byte[]? plaintext = null;
        try
        {
            plaintext = new byte[TotalBytes(file, chunks)];
            await WritePlaintextAsync(file, chunks, new MemoryStream(plaintext, writable: true), ct);

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
        finally
        {
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    /// <summary>
    /// Decrypts every chunk in order and writes the plaintext straight to
    /// <paramref name="destination"/>, holding one chunk in memory at a time.
    /// </summary>
    private async Task WritePlaintextAsync(
        StoredFile file, List<FileChunk> chunks, Stream destination, CancellationToken ct)
    {
        var dek = keyStore.Unwrap(file.WrappedDek, file.KekId);
        try
        {
            foreach (var chunk in chunks)
            {
                var ciphertext = await store.ReadChunkAsync(file.StorageKey, chunk.ChunkIndex, ct)
                                 ?? throw new MessengerException(ErrorCode.FileNotFound,
                                     $"Chunk {chunk.ChunkIndex} is missing from the file store.");

                var plain = cipher.OpenChunk(
                    dek, ciphertext, chunk.AuthTag, file.Id, file.NoncePrefix,
                    chunk.ChunkIndex, file.ChunkCount, file.KeyVersion);

                try
                {
                    await destination.WriteAsync(plain, ct);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(plain);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    /// <summary>
    /// Size of the reassembled plaintext, taken from the chunk rows rather than the size the
    /// uploader declared. The two agree — every chunk's length is checked on arrival — but a
    /// fixed-size buffer must be sized by what will actually be written into it, so that a
    /// disagreement is a caught error here rather than an overflow later.
    /// </summary>
    private static int TotalBytes(StoredFile file, List<FileChunk> chunks)
    {
        var total = chunks.Sum(c => (long)c.ByteLength);

        if (total != file.SizeBytes)
            throw new MessengerException(ErrorCode.ChunkManifestMismatch,
                $"The stored chunks total {total} bytes; this file is recorded as {file.SizeBytes}.");

        if (total > Array.MaxLength)
            throw new MessengerException(ErrorCode.FileTooLarge,
                "This file is too large to be served as a single buffer; stream it instead.");

        return (int)total;
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

    /// <summary>
    /// A write-only sink that feeds everything written to it into a running hash. Lets the
    /// completion digest reuse the same chunk-at-a-time decryption path as a download,
    /// without either of them needing the file whole.
    /// </summary>
    private sealed class IncrementalHashStream(IncrementalHash hash) : Stream
    {
        private long _length;

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => _length;

        public override long Position
        {
            get => _length;
            set => throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
            => Write(new ReadOnlySpan<byte>(buffer, offset, count));

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            hash.AppendData(buffer);
            _length += buffer.Length;
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
        {
            Write(buffer.Span);
            return ValueTask.CompletedTask;
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            Write(new ReadOnlySpan<byte>(buffer, offset, count));
            return Task.CompletedTask;
        }

        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
