using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Messenger.Admin.Wpf.Services;

namespace Messenger.Admin.Wpf.ViewModels;

/// <summary>
/// Triggers a directory sync and shows the report. This will return <c>AD-101</c>
/// (<c>DirectoryUnreachable</c>) on every real deployment today -- the LDAPS wire binding is
/// not implemented, only the sync engine behind <c>IDirectoryProvider</c> is -- so the view
/// says that plainly rather than implying this screen does something it cannot yet do.
/// </summary>
public sealed class DirectorySyncViewModel : ObservableObject
{
    private readonly AdminApiClient _api;
    private SyncReportResponse? _lastReport;
    private string _errorMessage = string.Empty;

    public DirectorySyncViewModel(AdminApiClient api)
    {
        _api = api;
        SyncCommand = new AsyncRelayCommand(SyncAsync);
    }

    public SyncReportResponse? LastReport
    {
        get => _lastReport;
        private set => SetProperty(ref _lastReport, value);
    }

    public string ErrorMessage
    {
        get => _errorMessage;
        private set => SetProperty(ref _errorMessage, value);
    }

    public IAsyncRelayCommand SyncCommand { get; }

    private async Task SyncAsync()
    {
        try
        {
            LastReport = await _api.TriggerDirectorySyncAsync();
            ErrorMessage = string.Empty;
        }
        catch (MessengerApiException ex)
        {
            ErrorMessage = ex.Message;
        }
    }
}
