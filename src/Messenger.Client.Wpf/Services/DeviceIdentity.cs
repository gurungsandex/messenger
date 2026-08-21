using System.IO;

namespace Messenger.Client.Wpf.Services;

/// <summary>
/// A stable per-installation device fingerprint. The server binds every session to the
/// fingerprint it was created with (see <c>AUTH-206 SessionDeviceMismatch</c> in the server's
/// error catalogue) and requires it on every authenticated call, so this has to be generated
/// once and persisted, not regenerated per launch.
/// </summary>
public static class DeviceIdentity
{
    private static readonly string FilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Messenger", "device.id");

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
