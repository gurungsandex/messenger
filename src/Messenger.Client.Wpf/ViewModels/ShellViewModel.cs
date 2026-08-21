using CommunityToolkit.Mvvm.ComponentModel;
using Messenger.Client.Wpf.Services;
using Messenger.Contracts;

namespace Messenger.Client.Wpf.ViewModels;

/// <summary>
/// Top-level navigation: which of the three screens (login, forced password change, main
/// chat shell) is on screen right now. Swapping <see cref="CurrentView"/> is what the
/// DataTemplates in App.xaml render.
/// </summary>
public sealed class ShellViewModel : ObservableObject
{
    private readonly ApiClient _api;
    private readonly string _baseUrl;
    private object _currentView;
    private MainViewModel? _mainViewModel;

    public ShellViewModel(string baseUrl)
    {
        _baseUrl = baseUrl;
        _api = new ApiClient(baseUrl);
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
        vm.LoggedIn += OnLoggedIn;
        return vm;
    }

    private void OnLoggedIn(LoginResponse response)
    {
        if (response.MustChangePassword)
        {
            var vm = new ChangePasswordViewModel(_api);
            vm.Completed += ReturnToLogin;
            CurrentView = vm;
            return;
        }

        _ = EnterMainAsync();
    }

    private async Task EnterMainAsync()
    {
        _mainViewModel = new MainViewModel(_api, _baseUrl);
        CurrentView = _mainViewModel;
        await _mainViewModel.ConnectAsync();
    }

    private void ReturnToLogin() => CurrentView = CreateLoginView();
}
