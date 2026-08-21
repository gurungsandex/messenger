using CommunityToolkit.Mvvm.ComponentModel;
using Messenger.Admin.Wpf.Services;

namespace Messenger.Admin.Wpf.ViewModels;

public sealed class ShellViewModel : ObservableObject
{
    private readonly AdminApiClient _api;
    private object _currentView;

    public ShellViewModel(string baseUrl)
    {
        _api = new AdminApiClient(baseUrl);
        _currentView = CreateLoginView();
    }

    public object CurrentView
    {
        get => _currentView;
        private set => SetProperty(ref _currentView, value);
    }

    private LoginViewModel CreateLoginView()
    {
        var vm = new LoginViewModel(_api);
        vm.LoggedIn += response => { _ = EnterMainAsync(); };
        return vm;
    }

    private async Task EnterMainAsync()
    {
        var main = new MainViewModel(_api);
        CurrentView = main;
        await main.LoadAllAsync();
    }
}
