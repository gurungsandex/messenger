using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Messenger.Admin.Wpf.Services;

namespace Messenger.Admin.Wpf.ViewModels;

public sealed class UsersViewModel : ObservableObject
{
    private readonly AdminApiClient _api;
    private UserSummary? _selectedUser;
    private string _errorMessage = string.Empty;

    public UsersViewModel(AdminApiClient api)
    {
        _api = api;
        RefreshCommand = new AsyncRelayCommand(RefreshAsync);
        CreateUserCommand = new AsyncRelayCommand<NewUserFields>(CreateUserAsync, f => f is not null);
        ToggleStatusCommand = new AsyncRelayCommand(ToggleStatusAsync, () => SelectedUser is not null);
    }

    public ObservableCollection<UserSummary> Users { get; } = [];

    public UserSummary? SelectedUser
    {
        get => _selectedUser;
        set
        {
            if (SetProperty(ref _selectedUser, value))
                ((AsyncRelayCommand)ToggleStatusCommand).NotifyCanExecuteChanged();
        }
    }

    public string ErrorMessage
    {
        get => _errorMessage;
        private set => SetProperty(ref _errorMessage, value);
    }

    public IAsyncRelayCommand RefreshCommand { get; }
    public IAsyncRelayCommand<NewUserFields> CreateUserCommand { get; }
    public IAsyncRelayCommand ToggleStatusCommand { get; }

    public async Task RefreshAsync()
    {
        try
        {
            var users = await _api.GetUsersAsync();
            Users.Clear();
            foreach (var u in users) Users.Add(u);
            ErrorMessage = string.Empty;
        }
        catch (MessengerApiException ex)
        {
            ErrorMessage = ex.Message;
        }
    }

    private async Task CreateUserAsync(NewUserFields? fields)
    {
        if (fields is null) return;

        try
        {
            await _api.CreateUserAsync(new CreateUserRequest(
                fields.Username, fields.DisplayName, string.IsNullOrWhiteSpace(fields.Email) ? null : fields.Email,
                fields.InitialPassword));
            await RefreshAsync();
        }
        catch (MessengerApiException ex)
        {
            ErrorMessage = ex.Message;
        }
    }

    /// <summary>Toggles between Active and Disabled -- the only two statuses an operator sets by hand; the rest are system-managed.</summary>
    private async Task ToggleStatusAsync()
    {
        if (SelectedUser is null) return;

        var target = SelectedUser.Status == "Active" ? "Disabled" : "Active";
        try
        {
            await _api.SetUserStatusAsync(SelectedUser.Id, target);
            await RefreshAsync();
        }
        catch (MessengerApiException ex)
        {
            ErrorMessage = ex.Message;
        }
    }
}

public sealed class NewUserFields(string username, string displayName, string? email, string initialPassword)
{
    public string Username { get; } = username;
    public string DisplayName { get; } = displayName;
    public string? Email { get; } = email;
    public string InitialPassword { get; } = initialPassword;
}
