using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Messenger.Admin.Wpf.Services;

namespace Messenger.Admin.Wpf.ViewModels;

public sealed class SessionsViewModel : ObservableObject
{
    private readonly AdminApiClient _api;
    private SessionSummary? _selectedSession;
    private string _errorMessage = string.Empty;

    public SessionsViewModel(AdminApiClient api)
    {
        _api = api;
        RefreshCommand = new AsyncRelayCommand(RefreshAsync);
        RevokeCommand = new AsyncRelayCommand(RevokeAsync, () => SelectedSession is not null);
    }

    public ObservableCollection<SessionSummary> Sessions { get; } = [];

    public SessionSummary? SelectedSession
    {
        get => _selectedSession;
        set
        {
            if (SetProperty(ref _selectedSession, value))
                ((AsyncRelayCommand)RevokeCommand).NotifyCanExecuteChanged();
        }
    }

    public string ErrorMessage
    {
        get => _errorMessage;
        private set => SetProperty(ref _errorMessage, value);
    }

    public IAsyncRelayCommand RefreshCommand { get; }
    public IAsyncRelayCommand RevokeCommand { get; }

    public async Task RefreshAsync()
    {
        try
        {
            var sessions = await _api.GetSessionsAsync();
            Sessions.Clear();
            foreach (var s in sessions) Sessions.Add(s);
            ErrorMessage = string.Empty;
        }
        catch (MessengerApiException ex)
        {
            ErrorMessage = ex.Message;
        }
    }

    private async Task RevokeAsync()
    {
        if (SelectedSession is null) return;
        try
        {
            await _api.RevokeSessionAsync(SelectedSession.Id);
            await RefreshAsync();
        }
        catch (MessengerApiException ex)
        {
            ErrorMessage = ex.Message;
        }
    }
}
