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
        try
        {
            var head = await db.AuditLog
                .OrderByDescending(x => x.Id)
                .Select(x => new { x.Id, x.EntryHash })
                .FirstOrDefaultAsync(ct);

            var prevHash = head?.EntryHash ?? AuditChain.GenesisHash;
            var nextId = (head?.Id ?? 0) + 1;

            var data = new AuditEntryData(
                nextId, DateTimeOffset.UtcNow, actorUserId, actorTier, actorIp,
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

public interface IAuditSigningKeyProvider
{
    (string KeyId, byte[] PrivateKey) GetSigningKey();
    byte[] GetPublicKey(string keyId);
}

/// <summary>
/// In-memory signing key for development and tests. Production keeps this in a TPM or HSM
/// so the key can be used but not extracted — see AR-6 in the threat model.
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
