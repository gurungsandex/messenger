using System.Collections.Concurrent;

namespace Messenger.Data;

/// <summary>
/// Chunk storage. Abstracted so the single-node local implementation can be swapped for a
/// shared SMB or object store when HA arrives (ADR-0003), without reshaping call sites.
/// </summary>
public interface IFileStore
{
    Task WriteChunkAsync(string storageKey, long chunkIndex, byte[] data, CancellationToken ct = default);
    Task<byte[]?> ReadChunkAsync(string storageKey, long chunkIndex, CancellationToken ct = default);
    Task DeleteAsync(string storageKey, CancellationToken ct = default);
    Task<long> GetUsedBytesAsync(CancellationToken ct = default);
}

/// <summary>
/// Local-filesystem chunk store.
///
/// Paths are built only from the server-generated storage key and the chunk index. The
/// user-supplied filename never reaches the filesystem, so a crafted name cannot escape the
/// root. The key is validated anyway — defence in depth costs nothing here.
/// </summary>
public sealed class LocalFileStore(string rootPath) : IFileStore
{
    public async Task WriteChunkAsync(string storageKey, long chunkIndex, byte[] data, CancellationToken ct = default)
    {
        var path = ChunkPath(storageKey, chunkIndex);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await File.WriteAllBytesAsync(path, data, ct);
    }

    public async Task<byte[]?> ReadChunkAsync(string storageKey, long chunkIndex, CancellationToken ct = default)
    {
        var path = ChunkPath(storageKey, chunkIndex);
        return File.Exists(path) ? await File.ReadAllBytesAsync(path, ct) : null;
    }

    public Task DeleteAsync(string storageKey, CancellationToken ct = default)
    {
        var dir = Path.Combine(rootPath, ValidateKey(storageKey));
        if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        return Task.CompletedTask;
    }

    public Task<long> GetUsedBytesAsync(CancellationToken ct = default)
    {
        if (!Directory.Exists(rootPath)) return Task.FromResult(0L);

        var total = new DirectoryInfo(rootPath)
            .EnumerateFiles("*", SearchOption.AllDirectories)
            .Sum(f => f.Length);

        return Task.FromResult(total);
    }

    private string ChunkPath(string storageKey, long chunkIndex)
    {
        if (chunkIndex < 0) throw new ArgumentOutOfRangeException(nameof(chunkIndex));
        return Path.Combine(rootPath, ValidateKey(storageKey), $"{chunkIndex:D9}.chunk");
    }

    /// <summary>
    /// Storage keys are server-generated hex, so anything else means a bug or an attempt to
    /// reach outside the root. Rejecting rather than sanitising keeps the failure loud.
    /// </summary>
    private static string ValidateKey(string storageKey)
    {
        if (string.IsNullOrEmpty(storageKey) || storageKey.Length is < 16 or > 64
            || !storageKey.All(c => char.IsAsciiLetterOrDigit(c)))
        {
            throw new ArgumentException("Storage key is not a valid server-generated key.", nameof(storageKey));
        }
        return storageKey;
    }
}

/// <summary>In-memory chunk store for tests.</summary>
public sealed class InMemoryFileStore : IFileStore
{
    private readonly ConcurrentDictionary<string, byte[]> _chunks = new();

    private static string Key(string storageKey, long index) => $"{storageKey}/{index}";

    public Task WriteChunkAsync(string storageKey, long chunkIndex, byte[] data, CancellationToken ct = default)
    {
        _chunks[Key(storageKey, chunkIndex)] = data;
        return Task.CompletedTask;
    }

    public Task<byte[]?> ReadChunkAsync(string storageKey, long chunkIndex, CancellationToken ct = default)
        => Task.FromResult(_chunks.TryGetValue(Key(storageKey, chunkIndex), out var data) ? data : null);

    public Task DeleteAsync(string storageKey, CancellationToken ct = default)
    {
        foreach (var key in _chunks.Keys.Where(k => k.StartsWith($"{storageKey}/", StringComparison.Ordinal)))
            _chunks.TryRemove(key, out _);
        return Task.CompletedTask;
    }

    public Task<long> GetUsedBytesAsync(CancellationToken ct = default)
        => Task.FromResult(_chunks.Values.Sum(v => (long)v.Length));

    /// <summary>Test hook: corrupt stored bytes to prove tamper detection actually fires.</summary>
    public void Corrupt(string storageKey, long chunkIndex)
    {
        var key = Key(storageKey, chunkIndex);
        if (_chunks.TryGetValue(key, out var data) && data.Length > 0)
        {
            var copy = (byte[])data.Clone();
            copy[0] ^= 0xFF;
            _chunks[key] = copy;
        }
    }

    /// <summary>Test hook: swap two chunks to prove the manifest catches reordering.</summary>
    public void SwapChunks(string storageKey, long a, long b)
    {
        var keyA = Key(storageKey, a);
        var keyB = Key(storageKey, b);
        if (_chunks.TryGetValue(keyA, out var dataA) && _chunks.TryGetValue(keyB, out var dataB))
        {
            _chunks[keyA] = dataB;
            _chunks[keyB] = dataA;
        }
    }
}

/// <summary>Malware scanning hook. Fail-closed by policy — see FILE-205.</summary>
public interface IMalwareScanner
{
    Task<(bool IsClean, string? Detail)> ScanAsync(Stream content, string fileName, CancellationToken ct = default);
}

/// <summary>No-op scanner used where scanning is not configured.</summary>
public sealed class NoOpMalwareScanner : IMalwareScanner
{
    public Task<(bool IsClean, string? Detail)> ScanAsync(Stream content, string fileName, CancellationToken ct = default)
        => Task.FromResult<(bool, string?)>((true, null));
}
