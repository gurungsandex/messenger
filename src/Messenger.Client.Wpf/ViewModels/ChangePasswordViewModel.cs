using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Messenger.Client.Wpf.Services;

namespace Messenger.Client.Wpf.ViewModels;

public sealed class ChangePasswordViewModel : ObservableObject
{
    private readonly ApiClient _api;
    private string _errorMessage = string.Empty;
    private string _statusMessage = string.Empty;
    private bool _isBusy;

    /// <summary>
    /// Fires once the change succeeds. The server revokes every session on a password
    /// change, including the one that made the call, so the shell must return the user to
    /// the login screen rather than pretend the current session still works.
    /// </summary>
    public event Action? Completed;

    public ChangePasswordViewModel(ApiClient api)
    {
        _api = api;
        SubmitCommand = new AsyncRelayCommand<ChangePasswordFields>(SubmitAsync, _ => !IsBusy);
    }

    public string ErrorMessage
    {
        get => _errorMessage;
        set => SetProperty(ref _errorMessage, value);
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set => SetProperty(ref _statusMessage, value);
    }

    public bool IsBusy
    {
        get => _isBusy;
        set
        {
            if (SetProperty(ref _isBusy, value))
                ((AsyncRelayCommand<ChangePasswordFields>)SubmitCommand).NotifyCanExecuteChanged();
        }
    }

    public ICommand SubmitCommand { get; }

    private async Task SubmitAsync(ChangePasswordFields? fields)
    {
        if (fields is null) return;

        if (fields.NewPassword != fields.ConfirmNewPassword)
        {
            ErrorMessage = "The new password and its confirmation do not match.";
            return;
        }

        IsBusy = true;
        ErrorMessage = string.Empty;
        try
        {
            await _api.ChangePasswordAsync(fields.CurrentPassword, fields.NewPassword);
            StatusMessage = "Password changed. Please sign in again.";
            Completed?.Invoke();
        }
        catch (MessengerApiException ex)
        {
            ErrorMessage = ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }
}

public sealed class ChangePasswordFields(string currentPassword, string newPassword, string confirmNewPassword)
{
    public string CurrentPassword { get; } = currentPassword;
    public string NewPassword { get; } = newPassword;
    public string ConfirmNewPassword { get; } = confirmNewPassword;
}
