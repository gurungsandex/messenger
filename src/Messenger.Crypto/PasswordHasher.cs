using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Messenger.Contracts;

namespace Messenger.Crypto;

public sealed record Argon2Parameters(int MemoryKib, int Iterations, int Parallelism)
{
    /// <summary>
    /// Current policy: 64 MiB / t=3 / p=4. See docs/architecture.md §3.2.
    /// Raising these does not invalidate existing hashes — parameters travel with each
    /// hash in PHC format, and a below-policy hash is upgraded on next successful login.
    /// </summary>
    public static readonly Argon2Parameters Current = new(65536, 3, 4);

    public bool IsWeakerThan(Argon2Parameters other)
        => MemoryKib < other.MemoryKib || Iterations < other.Iterations || Parallelism < other.Parallelism;
}

public sealed record PasswordVerificationResult(bool Succeeded, bool NeedsUpgrade);

/// <summary>
/// Argon2id password hashing in PHC string format:
/// <c>$argon2id$v=19$m=65536,t=3,p=4$&lt;b64 salt&gt;$&lt;b64 hash&gt;</c>
/// </summary>
public sealed class PasswordHasher
{
    private const int SaltLength = 16;
    private const int HashLength = 32;

    private readonly Argon2Parameters _parameters;

    public PasswordHasher(Argon2Parameters? parameters = null)
        => _parameters = parameters ?? Argon2Parameters.Current;

    public string Hash(string password)
    {
        ArgumentNullException.ThrowIfNull(password);

        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        var hash = Derive(password, salt, _parameters);

        return string.Create(CultureInfo.InvariantCulture,
            $"$argon2id$v=19$m={_parameters.MemoryKib},t={_parameters.Iterations},p={_parameters.Parallelism}$" +
            $"{Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}");
    }

    /// <summary>
    /// Verifies in constant time. Returns whether the stored hash is below current policy so
    /// the caller can transparently re-hash while it holds the plaintext.
    /// </summary>
    public PasswordVerificationResult Verify(string password, string encoded)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(encoded);

        var (parameters, salt, expected) = Parse(encoded);
        var actual = Derive(password, salt, parameters);

        var ok = CryptographicOperations.FixedTimeEquals(actual, expected);
        return new PasswordVerificationResult(ok, ok && parameters.IsWeakerThan(_parameters));
    }

    private static byte[] Derive(string password, byte[] salt, Argon2Parameters p)
    {
        using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            MemorySize = p.MemoryKib,
            Iterations = p.Iterations,
            DegreeOfParallelism = p.Parallelism,
        };
        return argon2.GetBytes(HashLength);
    }

    private static (Argon2Parameters, byte[] Salt, byte[] Hash) Parse(string encoded)
    {
        var parts = encoded.Split('$');
        // ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash]
        if (parts.Length != 6 || parts[1] != "argon2id")
            throw new MessengerException(ErrorCode.Argon2VerificationError, "Stored password hash is malformed.");

        int memory = 0, iterations = 0, parallelism = 0;
        foreach (var field in parts[3].Split(','))
        {
            var kv = field.Split('=');
            if (kv.Length != 2 || !int.TryParse(kv[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
                throw new MessengerException(ErrorCode.Argon2VerificationError, "Stored password hash is malformed.");

            switch (kv[0])
            {
                case "m": memory = value; break;
                case "t": iterations = value; break;
                case "p": parallelism = value; break;
            }
        }

        if (memory <= 0 || iterations <= 0 || parallelism <= 0)
            throw new MessengerException(ErrorCode.Argon2VerificationError, "Stored password hash is malformed.");

        try
        {
            return (new Argon2Parameters(memory, iterations, parallelism),
                    Convert.FromBase64String(parts[4]),
                    Convert.FromBase64String(parts[5]));
        }
        catch (FormatException)
        {
            throw new MessengerException(ErrorCode.Argon2VerificationError, "Stored password hash is malformed.");
        }
    }
}
