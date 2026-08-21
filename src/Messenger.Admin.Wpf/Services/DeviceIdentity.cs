using System.IO;

namespace Messenger.Admin.Wpf.Services;

/// <summary>Stable per-installation device fingerprint, matching the pattern Messenger.Client.Wpf uses.</summary>
public static class DeviceIdentity
{
    private static readonly string FilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Messenger.Admin", "device.id");

    private static string? _cached;

    public static string GetOrCreate()
    {
        if (_cached is not null) return _cached;

        if (File.Exists(FilePath))
        {
            var existing = File.ReadAllText(FilePath).Trim();
            if (!string.IsNullOrEmpty(existing))
                return _cached = existing;
        }

        var generated = Guid.NewGuid().ToString("N");
        var directory = Path.GetDirectoryName(FilePath);
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
        File.WriteAllText(FilePath, generated);
        return _cached = generated;
    }
}
