using System.Security.Cryptography;
using Messenger.Contracts;
using Messenger.Core;
using Messenger.Crypto;
using Microsoft.EntityFrameworkCore;

namespace Messenger.Data;

/// <summary>
/// Appends hash-chained audit entries and signs periodic checkpoints.
///
/// Audit writes are fail-closed: if an entry cannot be written, the audited operation is
/// refused (SRV-307). An unauditable privileged action is not permitted to proceed.
/// </summary>
public sealed class AuditService(MessengerDbContext db, IAuditSigningKeyProvider signingKeys)
{
    public const int CheckpointInterval = 1000;

    /// <summary>Serialises chain appends within the process. See AppendAsync.</summary>
    private static readonly SemaphoreSlim AppendLock = new(1, 1);

    /// <summary>
    /// Appends an entry. The caller is responsible for the surrounding transaction; the
    /// chain is only consistent if appends within a transaction are serialised, which is
    /// why this takes the chain head under the caller's lock rather than racing for it.
    /// </summary>
    public async Task<AuditLogEntry> AppendAsync(
        string action,
        string outcome,
        Guid? actorUserId = null,
        string actorTier = "system",
        string? actorIp = null,
        string? targetType = null,
        Guid? targetId = null,
        string? detailJson = null,
        CancellationToken ct = default)
    {
        // Appends are serialised across all server threads. The chain is a linked list: two
        // concurrent appends would read the same head, compute the same predecessor hash and
        // the same id, and one would lose — turning an ordinary concurrent request into a
        // refused operation, because audit writes are fail-closed.
        //
        // A process-wide lock is correct for the single-server topology (ADR-0003). Adding a
        // second server requires a database-level advisory lock here; that is called out in
        // the HA seams rather than left to be discovered.
        await AppendLock.WaitAsync(ct);
        try
        {
            var head = await db.AuditLog
                .OrderByDescending(x => x.Id)
                .Select(x => new { x.Id, x.EntryHash })
                .FirstOrDefaultAsync(ct);

            var prevHash = head?.EntryHash ?? AuditChain.GenesisHash;
            var nextId = (head?.Id ?? 0) + 1;

            // Truncated to the storage resolution before hashing, so the value that is
            // hashed is bit-identical to the value that comes back on verification. See
            // AuditChain.TruncateToStorageResolution.
            var occurredAt = AuditChain.TruncateToStorageResolution(DateTimeOffset.UtcNow);

            var data = new AuditEntryData(
                nextId, occurredAt, actorUserId, actorTier, actorIp,
                action, targetType, targetId, outcome, detailJson);

            var entry = new AuditLogEntry
            {
                Id = nextId,
                OccurredAt = data.OccurredAt,
                ActorUserId = actorUserId,
                ActorTier = actorTier,
                ActorIp = actorIp,
                Action = action,
                TargetType = targetType,
                TargetId = targetId,
                Outcome = outcome,
                DetailJson = detailJson,
                PrevHash = prevHash,
                EntryHash = AuditChain.ComputeEntryHash(data, prevHash),
            };

            db.AuditLog.Add(entry);
            await db.SaveChangesAsync(ct);

            if (nextId % CheckpointInterval == 0)
                await WriteCheckpointAsync(entry, ct);

            return entry;
        }
        catch (Exception ex) when (ex is not MessengerException)
        {
            throw new MessengerException(ErrorCode.AuditWriteFailed,
                "The action was refused because it could not be audited.", ex.Message);
        }
        finally
        {
            AppendLock.Release();
        }
    }

    public async Task WriteCheckpointAsync(AuditLogEntry head, CancellationToken ct = default)
    {
        try
        {
            var (keyId, privateKey) = signingKeys.GetSigningKey();
            var signature = AuditChain.SignCheckpoint(head.EntryHash, head.Id, privateKey);

            db.AuditCheckpoints.Add(new AuditCheckpoint
            {
                UpToAuditId = head.Id,
                HeadHash = head.EntryHash,
                Signature = signature,
                SigningKeyId = keyId,
            });
            await db.SaveChangesAsync(ct);
        }
        catch (Exception ex)
        {
            // Entries still append and chain without a checkpoint, so this degrades rather
            // than blocking. It is loud because an unsigned chain is materially weaker.
            throw new MessengerException(ErrorCode.AuditCheckpointSigningFailed,
                "Audit entries are appending but cannot be signed.", ex.Message);
        }
    }

    /// <summary>
    /// Verifies every stored checkpoint signature against the chain head it claims to cover.
    ///
    /// Without this the checkpoints were write-only: they were signed on append and nothing
    /// ever checked one, so a rewritten chain that recomputed its own hashes — the exact
    /// attack the signatures exist to catch — verified clean. The hash chain alone proves
    /// only internal consistency; the signature is what a party holding the public key can
    /// use to prove the chain is the one the server actually wrote.
    ///
    /// A checkpoint whose signing key this server does not hold is reported as unverifiable
    /// rather than invalid. Those are different facts to an auditor: one means the evidence
    /// is missing, the other means it is contradicted.
    /// </summary>
    public async Task<AuditCheckpointVerification> VerifyCheckpointsAsync(CancellationToken ct = default)
    {
        var checkpoints = await db.AuditCheckpoints.OrderBy(c => c.UpToAuditId).ToListAsync(ct);
        if (checkpoints.Count == 0) return new AuditCheckpointVerification(0, 0, null, null);

        var verified = 0;
        var unverifiable = 0;

        foreach (var checkpoint in checkpoints)
        {
            byte[] publicKey;
            try
            {
                publicKey = signingKeys.GetPublicKey(checkpoint.SigningKeyId);
            }
            catch (MessengerException)
            {
                unverifiable++;
                continue;
            }

            // The stored head hash is checked against the entry it names before the signature
            // is checked. A signature that is valid over a head hash which no longer matches
            // the entry at that id is the interesting case: the chain was rewritten under a
            // genuine old signature.
            var storedHead = await db.AuditLog
                .Where(e => e.Id == checkpoint.UpToAuditId)
                .Select(e => e.EntryHash)
                .FirstOrDefaultAsync(ct);

            if (storedHead is null
                || !CryptographicOperations.FixedTimeEquals(storedHead, checkpoint.HeadHash)
                || !AuditChain.VerifyCheckpoint(
                        checkpoint.HeadHash, checkpoint.UpToAuditId, checkpoint.Signature, publicKey))
            {
                return new AuditCheckpointVerification(
                    verified, unverifiable, checkpoint.UpToAuditId,
                    $"Checkpoint at entry {checkpoint.UpToAuditId} does not match the chain.");
            }

            verified++;
        }

        return new AuditCheckpointVerification(verified, unverifiable, null, null);
    }

    /// <summary>Recomputes the chain over a range and reports the first entry that fails.</summary>
    public async Task<AuditVerificationResult> VerifyAsync(long fromId = 1, long? toId = null, CancellationToken ct = default)
    {
        var query = db.AuditLog.Where(x => x.Id >= fromId);
        if (toId is not null) query = query.Where(x => x.Id <= toId);

        var entries = await query.OrderBy(x => x.Id).ToListAsync(ct);
        if (entries.Count == 0) return new AuditVerificationResult(true, null);

        var startingPrev = entries[0].PrevHash;
        var pairs = entries
            .Select(x => (new AuditEntryData(
                x.Id, x.OccurredAt, x.ActorUserId, x.ActorTier, x.ActorIp,
                x.Action, x.TargetType, x.TargetId, x.Outcome, x.DetailJson), x.EntryHash))
            .ToList();

        return AuditChain.VerifyChain(pairs, startingPrev);
    }
}

/// <summary>
/// Outcome of checking the stored checkpoint signatures.
///
/// <paramref name="Unverifiable"/> counts checkpoints signed by a key this server does not
/// hold. That is not a failure — it is the expected state after restoring a database without
/// its signing key ring — but it is reported rather than ignored, because a chain whose
/// checkpoints cannot be checked offers no more assurance than one with none.
/// </summary>
public sealed record AuditCheckpointVerification(
    int Verified,
    int Unverifiable,
    long? FirstInvalidCheckpointId,
    string? Detail)
{
    public bool IsValid => FirstInvalidCheckpointId is null;
}

public interface IAuditSigningKeyProvider
{
    (string KeyId, byte[] PrivateKey) GetSigningKey();
    byte[] GetPublicKey(string keyId);
}

/// <summary>
/// In-memory signing key for development and tests only.
///
/// <b>Not usable in production:</b> the pair is generated in the constructor, so every
/// process start produces a new key id and discards the previous public key. Checkpoints
/// signed before a restart become permanently unverifiable. Production uses
/// <see cref="FileBackedAuditSigningKeyProvider"/>, or a TPM/HSM-backed provider that keeps
/// the key usable but not extractable — see AR-6 in the threat model.
/// </summary>
public sealed class InMemoryAuditSigningKeyProvider : IAuditSigningKeyProvider
{
    private readonly string _keyId = Guid.NewGuid().ToString("N");
    private readonly byte[] _privateKey;
    private readonly byte[] _publicKey;

    public InMemoryAuditSigningKeyProvider()
        => (_privateKey, _publicKey) = AuditChain.GenerateSigningKey();

    public (string KeyId, byte[] PrivateKey) GetSigningKey() => (_keyId, _privateKey);

    public byte[] GetPublicKey(string keyId) => keyId == _keyId
        ? _publicKey
        : throw new MessengerException(ErrorCode.AuditCheckpointSigningFailed, $"Unknown signing key '{keyId}'.");
}
