using System.Windows;
using Messenger.Client.Wpf.ViewModels;

namespace Messenger.Client.Wpf;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var baseUrl = Environment.GetEnvironmentVariable("MESSENGER_SERVER_URL") ?? "https://localhost:8443";

        var window = new MainWindow { DataContext = new ShellViewModel(baseUrl) };
        window.Show();
    }
}
