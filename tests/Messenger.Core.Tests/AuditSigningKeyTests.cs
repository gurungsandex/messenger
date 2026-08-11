using Messenger.Contracts;
using Messenger.Crypto;
using Messenger.Data;

namespace Messenger.Core.Tests;

/// <summary>
/// Covers the durability of the audit checkpoint signing key, and the verification that
/// makes it worth having.
///
/// The defect these were written against: the signing key was minted in the provider's
/// constructor and registered as a singleton, so it lived exactly as long as the process.
/// Every checkpoint signed before a restart named a key id the new process had never held,
/// and the public half was never persisted anywhere — so the signatures stayed in the
/// database and could never be checked again. Nothing failed loudly; the audit chain simply
/// stopped being able to prove its own origin from the first routine restart onward.
/// </summary>
public class AuditSigningKeyTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "messenger-audit-keys-" + Guid.NewGuid().ToString("N"));

    private string Path_(string name) => System.IO.Path.Combine(_directory, name);

    public void Dispose()
    {
        if (Directory.Exists(_directory)) Directory.Delete(_directory, recursive: true);
        GC.SuppressFinalize(this);
    }

    /// <summary>The defect itself, pinned so it cannot quietly come back.</summary>
    [Fact]
    public void The_in_memory_provider_loses_its_key_across_a_restart()
    {
        var before = new InMemoryAuditSigningKeyProvider();
        var (keyId, _) = before.GetSigningKey();

        var afterRestart = new InMemoryAuditSigningKeyProvider();

        Assert.Throws<MessengerException>(() => afterRestart.GetPublicKey(keyId));
    }

    [Fact]
    public void A_file_backed_key_survives_a_restart()
    {
        var path = Path_("audit.escrow");

        var (first, created) = FileBackedAuditSigningKeyProvider.OpenOrCreate(path, "correct horse battery staple");
        Assert.True(created);
        var (keyId, _) = first.GetSigningKey();

        var (second, createdAgain) = FileBackedAuditSigningKeyProvider.OpenOrCreate(path, "correct horse battery staple");
        Assert.False(createdAgain);

        Assert.Equal(keyId, second.GetSigningKey().KeyId);
        Assert.Equal(first.GetPublicKey(keyId), second.GetPublicKey(keyId));
    }

    [Fact]
    public void A_wrong_passphrase_is_refused_rather_than_silently_reseeding()
    {
        var path = Path_("audit.escrow");
        FileBackedAuditSigningKeyProvider.OpenOrCreate(path, "the real passphrase");

        // Reseeding on a bad passphrase would be the worst possible behaviour: the server
        // would start clean and orphan every existing checkpoint without saying anything.
        Assert.Throws<MessengerException>(
            () => FileBackedAuditSigningKeyProvider.OpenOrCreate(path, "not the real passphrase"));
    }

    [Fact]
    public void A_truncated_key_ring_is_refused()
    {
        var path = Path_("audit.escrow");
        FileBackedAuditSigningKeyProvider.OpenOrCreate(path, "passphrase");

        var blob = File.ReadAllBytes(path);
        File.WriteAllBytes(path, blob[..(blob.Length - 4)]);

        Assert.Throws<MessengerException>(() => FileBackedAuditSigningKeyProvider.OpenOrCreate(path, "passphrase"));
    }

    /// <summary>
    /// The end-to-end version of the bug: sign a checkpoint, restart, and verify it. Against
    /// the in-memory provider this is exactly what could not be done.
    /// </summary>
    [Fact]
    public async Task A_checkpoint_signed_before_a_restart_still_verifies_after_it()
    {
        var path = Path_("audit.escrow");
        using var h = new TestHarness();

        var (beforeRestart, _) = FileBackedAuditSigningKeyProvider.OpenOrCreate(path, "passphrase");
        var writer = new AuditService(h.Db, beforeRestart);

        var head = await writer.AppendAsync("test.action", "success");
        await writer.WriteCheckpointAsync(head);

        // A new provider reading the same file is what a restarted server has.
        var (afterRestart, _) = FileBackedAuditSigningKeyProvider.OpenOrCreate(path, "passphrase");
        var verifier = new AuditService(h.Db, afterRestart);

        var result = await verifier.VerifyCheckpointsAsync();

        Assert.True(result.IsValid);
        Assert.Equal(1, result.Verified);
        Assert.Equal(0, result.Unverifiable);
    }

    [Fact]
    public async Task A_checkpoint_from_an_unknown_key_is_reported_unverifiable_not_invalid()
    {
        using var h = new TestHarness();

        var head = await h.Audit.AppendAsync("test.action", "success");
        await h.Audit.WriteCheckpointAsync(head);

        // A different signing key is what restoring a database without its key ring gives you.
        var (foreign, _) = FileBackedAuditSigningKeyProvider.OpenOrCreate(Path_("other.escrow"), "passphrase");
        var result = await new AuditService(h.Db, foreign).VerifyCheckpointsAsync();

        // Missing evidence and contradicted evidence are different facts to an auditor.
        Assert.True(result.IsValid);
        Assert.Equal(0, result.Verified);
        Assert.Equal(1, result.Unverifiable);
    }

    /// <summary>
    /// The attack the signatures exist to catch, and which the hash chain alone cannot: an
    /// attacker with database write access rewrites an entry and recomputes every hash after
    /// it, so the chain is internally consistent again. Only the signature — which they
    /// cannot forge without the key — still disagrees.
    /// </summary>
    [Fact]
    public async Task A_rewritten_chain_passes_the_hash_check_and_fails_the_signature()
    {
        var path = Path_("audit.escrow");
        using var h = new TestHarness();

        var (keys, _) = FileBackedAuditSigningKeyProvider.OpenOrCreate(path, "passphrase");
        var audit = new AuditService(h.Db, keys);

        await audit.AppendAsync("user.create", "success");
        var head = await audit.AppendAsync("license.install", "success");
        await audit.WriteCheckpointAsync(head);

        Assert.True((await audit.VerifyAsync()).IsValid);
        Assert.True((await audit.VerifyCheckpointsAsync()).IsValid);

        // Rewrite the first entry and re-chain everything after it, exactly as an attacker
        // holding write access would.
        var entries = h.Db.AuditLog.OrderBy(e => e.Id).ToList();
        entries[0].Action = "user.delete";

        var previous = entries[0].PrevHash;
        foreach (var entry in entries)
        {
            var data = new AuditEntryData(
                entry.Id, entry.OccurredAt, entry.ActorUserId, entry.ActorTier, entry.ActorIp,
                entry.Action, entry.TargetType, entry.TargetId, entry.Outcome, entry.DetailJson);

            entry.PrevHash = previous;
            entry.EntryHash = AuditChain.ComputeEntryHash(data, previous);
            previous = entry.EntryHash;
        }
        await h.Db.SaveChangesAsync();

        // The forgery is self-consistent, so the hash chain reports clean...
        Assert.True((await audit.VerifyAsync()).IsValid);

        // ...and the signature is what catches it.
        var checkpoints = await audit.VerifyCheckpointsAsync();
        Assert.False(checkpoints.IsValid);
        Assert.Equal(head.Id, checkpoints.FirstInvalidCheckpointId);
    }

    [Fact]
    public async Task A_chain_with_no_checkpoints_verifies_vacuously()
    {
        using var h = new TestHarness();
        await h.Audit.AppendAsync("test.action", "success");

        var result = await h.Audit.VerifyCheckpointsAsync();

        Assert.True(result.IsValid);
        Assert.Equal(0, result.Verified);
    }
}
