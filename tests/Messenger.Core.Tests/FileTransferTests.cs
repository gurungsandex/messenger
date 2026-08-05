using System.Security.Cryptography;
using Messenger.Contracts;
using Messenger.Core;
using Messenger.Crypto;
using Messenger.Data;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace Messenger.Core.Tests;

/// <summary>Shared setup: two users in a direct conversation, ready to transfer a file.</summary>
public abstract class FileTestBase : IDisposable
{
    protected readonly TestHarness H = new();
    protected User Alice = null!;
    protected User Bob = null!;
    protected Guid ConversationId;

    protected FileTestBase()
    {
        Alice = H.AddUser("alice");
        Bob = H.AddUser("bob");
        ConversationId = H.Messages.GetOrCreateDirectConversationAsync(Alice.Id, Bob.Id).Result.Id;
    }

    /// <summary>Small chunk size so multi-chunk paths are exercised without large payloads.</summary>
    protected const int ChunkSize = 1024;

    protected static byte[] RandomContent(int size) => RandomNumberGenerator.GetBytes(size);

    protected async Task<Guid> UploadAsync(byte[] content, string fileName = "report.pdf", FilePolicy? policy = null)
    {
        var slot = await H.Files.BeginUploadAsync(
            Alice.Id, ConversationId, fileName, content.Length,
            SHA256.HashData(content), "application/pdf", policy, ChunkSize);

        for (long i = 0; i < slot.ChunkCount; i++)
        {
            var offset = (int)(i * ChunkSize);
            var length = Math.Min(ChunkSize, content.Length - offset);
            await H.Files.UploadChunkAsync(Alice.Id, slot.FileId, i, content[offset..(offset + length)]);
        }

        await H.Files.CompleteUploadAsync(Alice.Id, slot.FileId);
        return slot.FileId;
    }

    public void Dispose() => H.Dispose();
}

public class FileUploadTests : FileTestBase
{
    [Fact]
    public async Task Roundtrips_a_single_chunk_file()
    {
        var content = RandomContent(500);
        var fileId = await UploadAsync(content);

        Assert.Equal(content, await H.Files.DownloadAsync(Bob.Id, fileId));
    }

    [Fact]
    public async Task Roundtrips_a_multi_chunk_file_with_a_partial_final_chunk()
    {
        // 3.5 chunks, so the final-chunk length calculation is actually exercised.
        var content = RandomContent(ChunkSize * 3 + 512);
        var fileId = await UploadAsync(content);

        Assert.Equal(content, await H.Files.DownloadAsync(Bob.Id, fileId));
        Assert.Equal(4, await H.Db.FileChunks.CountAsync(c => c.FileId == fileId));
    }

    [Fact]
    public async Task Roundtrips_a_file_that_is_an_exact_chunk_multiple()
    {
        var content = RandomContent(ChunkSize * 2);
        var fileId = await UploadAsync(content);

        Assert.Equal(content, await H.Files.DownloadAsync(Bob.Id, fileId));
        Assert.Equal(2, await H.Db.FileChunks.CountAsync(c => c.FileId == fileId));
    }

    [Fact]
    public async Task Stores_only_ciphertext()
    {
        var marker = System.Text.Encoding.UTF8.GetBytes("PLAINTEXT-MARKER-IN-FILE");
        var fileId = await UploadAsync(marker);

        var file = await H.Db.StoredFiles.SingleAsync(f => f.Id == fileId);
        var stored = await H.Store.ReadChunkAsync(file.StorageKey, 0);

        Assert.NotNull(stored);
        Assert.DoesNotContain("PLAINTEXT-MARKER", System.Text.Encoding.UTF8.GetString(stored!));
    }

    [Fact]
    public async Task Rejects_a_file_over_the_licence_size_cap()
    {
        var policy = FilePolicy.Default with { MaxFileBytes = 100 };

        var ex = await Assert.ThrowsAsync<MessengerException>(() => H.Files.BeginUploadAsync(
            Alice.Id, ConversationId, "big.bin", 101, SHA256.HashData([1]), policy: policy));

        // Rejected before any bytes move.
        Assert.Equal(ErrorCode.FileTooLarge, ex.Code);
        Assert.Equal(0, await H.Db.StoredFiles.CountAsync());
    }

    [Fact]
    public async Task Rejects_a_blocked_extension()
    {
        var ex = await Assert.ThrowsAsync<MessengerException>(() => H.Files.BeginUploadAsync(
            Alice.Id, ConversationId, "payload.exe", 100, SHA256.HashData([1])));
        Assert.Equal(ErrorCode.FileTypeBlocked, ex.Code);
    }

    [Fact]
    public async Task Rejects_an_upload_over_quota()
    {
        var policy = FilePolicy.Default with { PerUserQuotaBytes = 1000 };
        await UploadAsync(RandomContent(800), policy: policy);

        var ex = await Assert.ThrowsAsync<MessengerException>(() => H.Files.BeginUploadAsync(
            Alice.Id, ConversationId, "more.pdf", 500, SHA256.HashData([1]), policy: policy));
        Assert.Equal(ErrorCode.QuotaExceeded, ex.Code);
    }

    [Fact]
    public async Task Rejects_an_upload_from_a_non_participant()
    {
        var mallory = H.AddUser("mallory");

        var ex = await Assert.ThrowsAsync<MessengerException>(() => H.Files.BeginUploadAsync(
            mallory.Id, ConversationId, "intrusion.pdf", 100, SHA256.HashData([1])));
        Assert.Equal(ErrorCode.NotAConversationParticipant, ex.Code);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task Rejects_an_invalid_file_name(string fileName)
    {
        var ex = await Assert.ThrowsAsync<MessengerException>(() => H.Files.BeginUploadAsync(
            Alice.Id, ConversationId, fileName, 100, SHA256.HashData([1])));
        Assert.Equal(ErrorCode.FileNameInvalid, ex.Code);
    }

    /// <summary>
    /// The storage key is server-generated and the on-disk path derives only from it, so a
    /// traversal attempt in the filename is structurally inert rather than filtered.
    /// </summary>
    [Fact]
    public async Task A_traversal_style_filename_never_reaches_the_storage_path()
    {
        var content = RandomContent(100);
        var fileId = await UploadAsync(content, fileName: "../../../etc/passwd.pdf");

        var file = await H.Db.StoredFiles.SingleAsync(f => f.Id == fileId);
        Assert.DoesNotContain("..", file.StorageKey);
        Assert.DoesNotContain("/", file.StorageKey);
        Assert.Equal("../../../etc/passwd.pdf", file.FileName);
        Assert.Equal(content, await H.Files.DownloadAsync(Bob.Id, fileId));
    }

    [Fact]
    public async Task Rejects_a_chunk_outside_the_expected_range()
    {
        var content = RandomContent(500);
        var slot = await H.Files.BeginUploadAsync(
            Alice.Id, ConversationId, "f.pdf", content.Length, SHA256.HashData(content), chunkSize: ChunkSize);

        var ex = await Assert.ThrowsAsync<MessengerException>(
            () => H.Files.UploadChunkAsync(Alice.Id, slot.FileId, 5, content));
        Assert.Equal(ErrorCode.ChunkSequenceError, ex.Code);
    }

    [Fact]
    public async Task Rejects_a_chunk_of_the_wrong_length()
    {
        var content = RandomContent(ChunkSize * 2);
        var slot = await H.Files.BeginUploadAsync(
            Alice.Id, ConversationId, "f.pdf", content.Length, SHA256.HashData(content), chunkSize: ChunkSize);

        var ex = await Assert.ThrowsAsync<MessengerException>(
            () => H.Files.UploadChunkAsync(Alice.Id, slot.FileId, 0, RandomContent(50)));
        Assert.Equal(ErrorCode.ChunkSequenceError, ex.Code);
    }

    [Fact]
    public async Task Completion_fails_when_chunks_are_missing()
    {
        var content = RandomContent(ChunkSize * 3);
        var slot = await H.Files.BeginUploadAsync(
            Alice.Id, ConversationId, "f.pdf", content.Length, SHA256.HashData(content), chunkSize: ChunkSize);

        await H.Files.UploadChunkAsync(Alice.Id, slot.FileId, 0, content[..ChunkSize]);

        var ex = await Assert.ThrowsAsync<MessengerException>(
            () => H.Files.CompleteUploadAsync(Alice.Id, slot.FileId));
        Assert.Equal(ErrorCode.ChunkSequenceError, ex.Code);
    }

    /// <summary>
    /// The declared digest is what catches corruption in transit and a client that lied
    /// about what it was sending.
    /// </summary>
    [Fact]
    public async Task Completion_fails_when_content_does_not_match_the_declared_digest()
    {
        var declared = RandomContent(500);
        var actual = RandomContent(500);

        var slot = await H.Files.BeginUploadAsync(
            Alice.Id, ConversationId, "f.pdf", actual.Length, SHA256.HashData(declared), chunkSize: ChunkSize);
        await H.Files.UploadChunkAsync(Alice.Id, slot.FileId, 0, actual);

        var ex = await Assert.ThrowsAsync<MessengerException>(
            () => H.Files.CompleteUploadAsync(Alice.Id, slot.FileId));
        Assert.Equal(ErrorCode.FileIntegrityCheckFailed, ex.Code);
    }

    [Fact]
    public async Task Another_user_cannot_push_chunks_into_someone_elses_upload()
    {
        var content = RandomContent(500);
        var slot = await H.Files.BeginUploadAsync(
            Alice.Id, ConversationId, "f.pdf", content.Length, SHA256.HashData(content), chunkSize: ChunkSize);

        var ex = await Assert.ThrowsAsync<MessengerException>(
            () => H.Files.UploadChunkAsync(Bob.Id, slot.FileId, 0, content));
        Assert.Equal(ErrorCode.FileAccessDenied, ex.Code);
    }
}

public class FileResumeTests : FileTestBase
{
    [Fact]
    public async Task Reports_which_chunks_have_been_received()
    {
        var content = RandomContent(ChunkSize * 3);
        var slot = await H.Files.BeginUploadAsync(
            Alice.Id, ConversationId, "f.pdf", content.Length, SHA256.HashData(content), chunkSize: ChunkSize);

        await H.Files.UploadChunkAsync(Alice.Id, slot.FileId, 0, content[..ChunkSize]);
        await H.Files.UploadChunkAsync(Alice.Id, slot.FileId, 2, content[(ChunkSize * 2)..]);

        Assert.Equal([0L, 2L], await H.Files.GetReceivedChunksAsync(Alice.Id, slot.FileId));
    }

    /// <summary>An interrupted upload resumes rather than restarting.</summary>
    [Fact]
    public async Task Resuming_completes_a_partially_uploaded_file()
    {
        var content = RandomContent(ChunkSize * 3);
        var slot = await H.Files.BeginUploadAsync(
            Alice.Id, ConversationId, "f.pdf", content.Length, SHA256.HashData(content), chunkSize: ChunkSize);

        await H.Files.UploadChunkAsync(Alice.Id, slot.FileId, 0, content[..ChunkSize]);
        // ... connection drops here ...

        var received = await H.Files.GetReceivedChunksAsync(Alice.Id, slot.FileId);
        for (long i = 0; i < slot.ChunkCount; i++)
        {
            if (received.Contains(i)) continue;
            var offset = (int)(i * ChunkSize);
            await H.Files.UploadChunkAsync(Alice.Id, slot.FileId, i,
                content[offset..(offset + Math.Min(ChunkSize, content.Length - offset))]);
        }

        await H.Files.CompleteUploadAsync(Alice.Id, slot.FileId);
        Assert.Equal(content, await H.Files.DownloadAsync(Bob.Id, slot.FileId));
    }

    [Fact]
    public async Task Re_uploading_a_chunk_is_idempotent()
    {
        var content = RandomContent(ChunkSize * 2);
        var slot = await H.Files.BeginUploadAsync(
            Alice.Id, ConversationId, "f.pdf", content.Length, SHA256.HashData(content), chunkSize: ChunkSize);

        await H.Files.UploadChunkAsync(Alice.Id, slot.FileId, 0, content[..ChunkSize]);
        await H.Files.UploadChunkAsync(Alice.Id, slot.FileId, 0, content[..ChunkSize]);
        await H.Files.UploadChunkAsync(Alice.Id, slot.FileId, 1, content[ChunkSize..]);

        Assert.Equal(2, await H.Db.FileChunks.CountAsync(c => c.FileId == slot.FileId));
        await H.Files.CompleteUploadAsync(Alice.Id, slot.FileId);
    }

    [Fact]
    public async Task An_expired_upload_window_is_refused()
    {
        var content = RandomContent(500);
        var policy = FilePolicy.Default with { UploadWindow = TimeSpan.FromMinutes(5) };
        var slot = await H.Files.BeginUploadAsync(
            Alice.Id, ConversationId, "f.pdf", content.Length, SHA256.HashData(content),
            policy: policy, chunkSize: ChunkSize);

        H.Time.Advance(TimeSpan.FromMinutes(6));

        var ex = await Assert.ThrowsAsync<MessengerException>(
            () => H.Files.UploadChunkAsync(Alice.Id, slot.FileId, 0, content));
        Assert.Equal(ErrorCode.UploadSessionExpired, ex.Code);
    }
}

public class FileIntegrityTests : FileTestBase
{
    /// <summary>
    /// Per-chunk AEAD detects a modified chunk at the storage layer, even though the
    /// database row is untouched.
    /// </summary>
    [Fact]
    public async Task Detects_a_corrupted_chunk_in_storage()
    {
        var content = RandomContent(ChunkSize * 2);
        var fileId = await UploadAsync(content);
        var file = await H.Db.StoredFiles.SingleAsync(f => f.Id == fileId);

        H.Store.Corrupt(file.StorageKey, 1);

        var ex = await Assert.ThrowsAsync<MessengerException>(() => H.Files.DownloadAsync(Bob.Id, fileId));
        Assert.Equal(ErrorCode.FileDecryptionFailed, ex.Code);
    }

    /// <summary>
    /// Reordering is the case per-chunk tags alone would miss: both chunks are individually
    /// valid, but the chunk index is bound into each one's AAD.
    /// </summary>
    [Fact]
    public async Task Detects_reordered_chunks()
    {
        var content = RandomContent(ChunkSize * 2);
        var fileId = await UploadAsync(content);
        var file = await H.Db.StoredFiles.SingleAsync(f => f.Id == fileId);

        H.Store.SwapChunks(file.StorageKey, 0, 1);

        await Assert.ThrowsAsync<MessengerException>(() => H.Files.DownloadAsync(Bob.Id, fileId));
    }

    /// <summary>
    /// Truncation would otherwise leave every remaining chunk individually valid. The
    /// manifest covers the sequence as a whole, and chunk_count is in each chunk's AAD.
    /// </summary>
    [Fact]
    public async Task Detects_a_truncated_chunk_set()
    {
        var content = RandomContent(ChunkSize * 3);
        var fileId = await UploadAsync(content);

        var lastChunk = await H.Db.FileChunks.SingleAsync(c => c.FileId == fileId && c.ChunkIndex == 2);
        H.Db.FileChunks.Remove(lastChunk);
        await H.Db.SaveChangesAsync();

        var ex = await Assert.ThrowsAsync<MessengerException>(() => H.Files.DownloadAsync(Bob.Id, fileId));
        Assert.Equal(ErrorCode.ChunkManifestMismatch, ex.Code);
    }

    /// <summary>
    /// The streaming download decrypts a chunk at a time instead of assembling the file in
    /// memory. It has to produce byte-identical output to the buffered path, and go through
    /// the same authorization and integrity checks — the two sharing one gate is what keeps
    /// them from drifting apart.
    /// </summary>
    [Fact]
    public async Task Streaming_a_download_yields_the_same_bytes()
    {
        var content = RandomContent(ChunkSize * 3 + 17);
        var fileId = await UploadAsync(content);

        using var destination = new MemoryStream();
        await H.Files.DownloadToAsync(Bob.Id, fileId, destination);

        Assert.Equal(content, destination.ToArray());
        Assert.Equal(content, await H.Files.DownloadAsync(Bob.Id, fileId));
    }

    [Fact]
    public async Task Streaming_a_download_enforces_access()
    {
        var carol = H.AddUser("carol");
        var fileId = await UploadAsync(RandomContent(500));

        using var destination = new MemoryStream();
        var ex = await Assert.ThrowsAsync<MessengerException>(
            () => H.Files.DownloadToAsync(carol.Id, fileId, destination));

        Assert.Equal(ErrorCode.FileAccessDenied, ex.Code);
        Assert.Equal(0, destination.Length);
    }

    /// <summary>
    /// The buffered path sizes its output from the chunk rows. If those disagree with the
    /// recorded file size the mismatch has to be an error, not a buffer sized from one
    /// number and filled from another.
    /// </summary>
    [Fact]
    public async Task Detects_chunk_lengths_that_disagree_with_the_recorded_size()
    {
        var fileId = await UploadAsync(RandomContent(ChunkSize * 2));

        var file = await H.Db.StoredFiles.SingleAsync(f => f.Id == fileId);
        file.SizeBytes -= 1;
        await H.Db.SaveChangesAsync();

        var ex = await Assert.ThrowsAsync<MessengerException>(() => H.Files.DownloadAsync(Bob.Id, fileId));
        Assert.Equal(ErrorCode.ChunkManifestMismatch, ex.Code);
    }

    [Fact]
    public void Manifest_changes_when_a_tag_changes()
    {
        var tags = new List<byte[]> { new byte[16], new byte[16] };
        var original = FileCipher.BuildManifest(tags);

        tags[1] = Enumerable.Repeat((byte)1, 16).ToArray();

        Assert.NotEqual(original, FileCipher.BuildManifest(tags));
    }

    [Fact]
    public void Manifest_is_order_sensitive()
    {
        var a = Enumerable.Repeat((byte)1, 16).ToArray();
        var b = Enumerable.Repeat((byte)2, 16).ToArray();

        Assert.NotEqual(FileCipher.BuildManifest([a, b]), FileCipher.BuildManifest([b, a]));
    }
}

public class FileAccessTests : FileTestBase
{
    [Fact]
    public async Task A_non_participant_cannot_download()
    {
        var mallory = H.AddUser("mallory");
        var fileId = await UploadAsync(RandomContent(500));

        // Holding the file id conveys no authority.
        var ex = await Assert.ThrowsAsync<MessengerException>(() => H.Files.DownloadAsync(mallory.Id, fileId));
        Assert.Equal(ErrorCode.FileAccessDenied, ex.Code);
    }

    [Fact]
    public async Task An_incomplete_upload_cannot_be_downloaded()
    {
        var content = RandomContent(500);
        var slot = await H.Files.BeginUploadAsync(
            Alice.Id, ConversationId, "f.pdf", content.Length, SHA256.HashData(content), chunkSize: ChunkSize);
        await H.Files.UploadChunkAsync(Alice.Id, slot.FileId, 0, content);

        var ex = await Assert.ThrowsAsync<MessengerException>(() => H.Files.DownloadAsync(Bob.Id, slot.FileId));
        Assert.Equal(ErrorCode.FileNotFound, ex.Code);
    }

    /// <summary>
    /// Group history visibility must apply to files exactly as it does to messages.
    /// Checking membership alone left the confidentiality boundary enforced for messages and
    /// wide open for their attachments — a member added today could download every file ever
    /// shared in the group.
    /// </summary>
    [Fact]
    public async Task A_member_added_later_cannot_download_files_shared_before_they_joined()
    {
        var admin = H.AddUser("admin");
        var latecomer = H.AddUser("latecomer");
        var group = await H.Groups.CreateAsync("Engineering", null, admin.Id);
        var conversation = group.ConversationId!.Value;
        await H.Groups.AddMemberAsync(group.Id, Alice.Id, admin.Id);

        // Alice shares a file, attached to a message, before the latecomer arrives.
        var content = RandomContent(500);
        var slot = await H.Files.BeginUploadAsync(
            Alice.Id, conversation, "confidential.pdf", content.Length, System.Security.Cryptography.SHA256.HashData(content));
        await H.Files.UploadChunkAsync(Alice.Id, slot.FileId, 0, content);
        await H.Files.CompleteUploadAsync(Alice.Id, slot.FileId);

        var ack = await H.Messages.SendAsync(Alice.Id,
            new SendMessageRequest(conversation, Guid.NewGuid(), "see attached", H.Time.GetUtcNow()));
        var file = await H.Db.StoredFiles.SingleAsync(f => f.Id == slot.FileId);
        file.MessageId = ack.MessageId;
        await H.Db.SaveChangesAsync();

        await H.Groups.AddMemberAsync(group.Id, latecomer.Id, admin.Id);

        // They cannot read the message, and must not be able to read its attachment either.
        Assert.Empty(await H.Messages.GetHistoryAsync(latecomer.Id, conversation));

        var ex = await Assert.ThrowsAsync<MessengerException>(
            () => H.Files.DownloadAsync(latecomer.Id, slot.FileId));
        Assert.Equal(ErrorCode.FileAccessDenied, ex.Code);
    }

    [Fact]
    public async Task A_member_present_at_the_time_can_still_download()
    {
        var admin = H.AddUser("admin");
        var present = H.AddUser("present");
        var group = await H.Groups.CreateAsync("Engineering", null, admin.Id);
        var conversation = group.ConversationId!.Value;
        await H.Groups.AddMemberAsync(group.Id, Alice.Id, admin.Id);
        await H.Groups.AddMemberAsync(group.Id, present.Id, admin.Id);

        var content = RandomContent(500);
        var slot = await H.Files.BeginUploadAsync(
            Alice.Id, conversation, "shared.pdf", content.Length, System.Security.Cryptography.SHA256.HashData(content));
        await H.Files.UploadChunkAsync(Alice.Id, slot.FileId, 0, content);
        await H.Files.CompleteUploadAsync(Alice.Id, slot.FileId);

        var ack = await H.Messages.SendAsync(Alice.Id,
            new SendMessageRequest(conversation, Guid.NewGuid(), "see attached", H.Time.GetUtcNow()));
        var file = await H.Db.StoredFiles.SingleAsync(f => f.Id == slot.FileId);
        file.MessageId = ack.MessageId;
        await H.Db.SaveChangesAsync();

        Assert.Equal(content, await H.Files.DownloadAsync(present.Id, slot.FileId));
    }

    [Fact]
    public async Task The_uploader_retains_access_to_their_own_file()
    {
        var content = RandomContent(500);
        var fileId = await UploadAsync(content);

        Assert.Equal(content, await H.Files.DownloadAsync(Alice.Id, fileId));
    }

    [Fact]
    public async Task Downloads_are_audited()
    {
        var fileId = await UploadAsync(RandomContent(500));
        await H.Files.DownloadAsync(Bob.Id, fileId);

        Assert.Contains("file.download", await H.Db.AuditLog.Select(e => e.Action).ToListAsync());
        Assert.True((await H.Audit.VerifyAsync()).IsValid);
    }
}

public class FileDeletionTests : FileTestBase
{
    /// <summary>
    /// Crypto-shredding is why files hold their own DEK: destroying the key means a restored
    /// backup of the file store cannot resurrect deleted content.
    /// </summary>
    [Fact]
    public async Task Deleting_destroys_the_key_as_well_as_the_bytes()
    {
        var fileId = await UploadAsync(RandomContent(500));

        await H.Files.DeleteAsync(Alice.Id, fileId);

        var file = await H.Db.StoredFiles.SingleAsync(f => f.Id == fileId);
        Assert.Empty(file.WrappedDek);
        Assert.NotNull(file.DeletedAt);
    }

    [Fact]
    public async Task A_deleted_file_cannot_be_downloaded()
    {
        var fileId = await UploadAsync(RandomContent(500));
        await H.Files.DeleteAsync(Alice.Id, fileId);

        var ex = await Assert.ThrowsAsync<MessengerException>(() => H.Files.DownloadAsync(Bob.Id, fileId));
        Assert.Equal(ErrorCode.FileNotFound, ex.Code);
    }

    [Fact]
    public async Task Deletion_is_audited_as_a_crypto_shred()
    {
        var fileId = await UploadAsync(RandomContent(500));
        await H.Files.DeleteAsync(Alice.Id, fileId);

        var entry = await H.Db.AuditLog.SingleAsync(e => e.Action == "file.delete");
        Assert.Contains("crypto_shredded", entry.DetailJson!);
    }

    /// <summary>
    /// Deletion is irreversible — the key is destroyed, so no backup brings the content
    /// back. Every other entry point checks the caller against the file; this one taking a
    /// file id and destroying whatever it named let any conversation peer shred another
    /// user's upload.
    /// </summary>
    [Fact]
    public async Task A_peer_cannot_delete_someone_elses_upload()
    {
        var fileId = await UploadAsync(RandomContent(500));

        var ex = await Assert.ThrowsAsync<MessengerException>(() => H.Files.DeleteAsync(Bob.Id, fileId));
        Assert.Equal(ErrorCode.FileAccessDenied, ex.Code);

        var file = await H.Db.StoredFiles.SingleAsync(f => f.Id == fileId);
        Assert.Null(file.DeletedAt);
        Assert.NotEmpty(file.WrappedDek);

        // Still readable: the refusal has to leave the file intact, not half-shredded.
        Assert.Equal(500, (await H.Files.DownloadAsync(Bob.Id, fileId)).Length);
    }

    [Fact]
    public async Task A_refused_deletion_is_audited()
    {
        var fileId = await UploadAsync(RandomContent(500));
        await Assert.ThrowsAsync<MessengerException>(() => H.Files.DeleteAsync(Bob.Id, fileId));

        var entry = await H.Db.AuditLog.SingleAsync(e => e.Action == "file.delete");
        Assert.Equal("denied", entry.Outcome);
    }

    /// <summary>
    /// The escape hatch a retention or moderation route would use, after making its own
    /// authorization decision. It has to be opted into explicitly.
    /// </summary>
    [Fact]
    public async Task An_administrative_caller_may_delete_another_users_upload()
    {
        var fileId = await UploadAsync(RandomContent(500));

        await H.Files.DeleteAsync(Bob.Id, fileId, asAdministrator: true);

        var file = await H.Db.StoredFiles.SingleAsync(f => f.Id == fileId);
        Assert.NotNull(file.DeletedAt);
        Assert.Empty(file.WrappedDek);
    }
}

public class MalwareScanTests
{
    private sealed class RejectingScanner : IMalwareScanner
    {
        public Task<(bool IsClean, string? Detail)> ScanAsync(Stream c, string n, CancellationToken ct = default)
            => Task.FromResult<(bool, string?)>((false, "EICAR-Test-Signature"));
    }

    private sealed class FailingScanner : IMalwareScanner
    {
        public Task<(bool IsClean, string? Detail)> ScanAsync(Stream c, string n, CancellationToken ct = default)
            => throw new IOException("scanner unreachable");
    }

    private static async Task<(TestHarness H, Guid FileId, User Bob)> UploadWith(IMalwareScanner scanner)
    {
        var h = new TestHarness(scanner);
        var alice = h.AddUser("alice");
        var bob = h.AddUser("bob");
        var conversation = (await h.Messages.GetOrCreateDirectConversationAsync(alice.Id, bob.Id)).Id;

        var content = RandomNumberGenerator.GetBytes(500);
        var slot = await h.Files.BeginUploadAsync(
            alice.Id, conversation, "f.pdf", content.Length, SHA256.HashData(content));
        await h.Files.UploadChunkAsync(alice.Id, slot.FileId, 0, content);
        await h.Files.CompleteUploadAsync(alice.Id, slot.FileId);

        return (h, slot.FileId, bob);
    }

    [Fact]
    public async Task An_infected_file_is_not_served()
    {
        var (h, fileId, bob) = await UploadWith(new RejectingScanner());
        using var _ = h;

        var ex = await Assert.ThrowsAsync<MessengerException>(() => h.Files.DownloadAsync(bob.Id, fileId));
        Assert.Equal(ErrorCode.FileFailedMalwareScan, ex.Code);
    }

    /// <summary>
    /// Fail-closed: a file that could not be scanned is withheld rather than served on the
    /// assumption it is probably fine.
    /// </summary>
    [Fact]
    public async Task A_file_that_could_not_be_scanned_is_withheld()
    {
        var (h, fileId, bob) = await UploadWith(new FailingScanner());
        using var _ = h;

        var ex = await Assert.ThrowsAsync<MessengerException>(() => h.Files.DownloadAsync(bob.Id, fileId));
        Assert.Equal(ErrorCode.ScannerUnavailable, ex.Code);
    }
}
