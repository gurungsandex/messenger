using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Messenger.Client.Wpf.Services;
using Messenger.Contracts;

namespace Messenger.Client.Wpf.ViewModels;

public sealed class LoginViewModel : ObservableObject
{
    private readonly ApiClient _api;
    private string _username = string.Empty;
    private string _errorMessage = string.Empty;
    private bool _isBusy;

    public event Action<LoginResponse>? LoggedIn;

    public LoginViewModel(ApiClient api)
    {
        _api = api;
        LoginCommand = new AsyncRelayCommand<PasswordContainer>(LoginAsync, _ => !IsBusy);
    }

    public string Username
    {
        get => _username;
        set => SetProperty(ref _username, value);
    }

    public string ErrorMessage
    {
        get => _errorMessage;
        set => SetProperty(ref _errorMessage, value);
    }

    public bool IsBusy
    {
        get => _isBusy;
        set
        {
            if (SetProperty(ref _isBusy, value))
                ((AsyncRelayCommand<PasswordContainer>)LoginCommand).NotifyCanExecuteChanged();
        }
    }

    public ICommand LoginCommand { get; }

    private async Task LoginAsync(PasswordContainer? passwordBox)
    {
        if (passwordBox is null || string.IsNullOrWhiteSpace(Username)) return;

        IsBusy = true;
        ErrorMessage = string.Empty;
        try
        {
            var response = await _api.LoginAsync(Username, passwordBox.Password);
            LoggedIn?.Invoke(response);
        }
        catch (MessengerApiException ex)
        {
            ErrorMessage = ex.Message;
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Could not reach the server: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }
}

/// <summary>
/// WPF's <c>PasswordBox.Password</c> is deliberately not bindable (it does not want a
/// plaintext password sitting in a view model property for the lifetime of the window), so
/// the code-behind passes it through as a command parameter at the moment of submission
/// instead.
/// </summary>
public sealed class PasswordContainer(string password)
{
    public string Password { get; } = password;
}
