using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Messenger.Admin.Wpf.Services;

namespace Messenger.Admin.Wpf.ViewModels;

public sealed class GroupsViewModel : ObservableObject
{
    private readonly AdminApiClient _api;
    private GroupSummary? _selectedGroup;
    private string _newGroupName = string.Empty;
    private string _memberUserId = string.Empty;
    private string _errorMessage = string.Empty;

    public GroupsViewModel(AdminApiClient api)
    {
        _api = api;
        RefreshCommand = new AsyncRelayCommand(RefreshAsync);
        CreateGroupCommand = new AsyncRelayCommand(CreateGroupAsync, () => !string.IsNullOrWhiteSpace(NewGroupName));
        AddMemberCommand = new AsyncRelayCommand(AddMemberAsync, () => SelectedGroup is not null && Guid.TryParse(MemberUserId, out _));
        RemoveMemberCommand = new AsyncRelayCommand(RemoveMemberAsync, () => SelectedGroup is not null && Guid.TryParse(MemberUserId, out _));
        ToggleStatusCommand = new AsyncRelayCommand(ToggleStatusAsync, () => SelectedGroup is not null);
        DeleteGroupCommand = new AsyncRelayCommand(DeleteGroupAsync, () => SelectedGroup is not null);
    }

    public ObservableCollection<GroupSummary> Groups { get; } = [];

    public GroupSummary? SelectedGroup
    {
        get => _selectedGroup;
        set
        {
            if (SetProperty(ref _selectedGroup, value))
                NotifyGroupDependentCommands();
        }
    }

    public string NewGroupName
    {
        get => _newGroupName;
        set
        {
            if (SetProperty(ref _newGroupName, value))
                ((AsyncRelayCommand)CreateGroupCommand).NotifyCanExecuteChanged();
        }
    }

    public string MemberUserId
    {
        get => _memberUserId;
        set
        {
            if (SetProperty(ref _memberUserId, value))
                NotifyGroupDependentCommands();
        }
    }

    public string ErrorMessage
    {
        get => _errorMessage;
        private set => SetProperty(ref _errorMessage, value);
    }

    public IAsyncRelayCommand RefreshCommand { get; }
    public IAsyncRelayCommand CreateGroupCommand { get; }
    public IAsyncRelayCommand AddMemberCommand { get; }
    public IAsyncRelayCommand RemoveMemberCommand { get; }
    public IAsyncRelayCommand ToggleStatusCommand { get; }
    public IAsyncRelayCommand DeleteGroupCommand { get; }

    private void NotifyGroupDependentCommands()
    {
        ((AsyncRelayCommand)AddMemberCommand).NotifyCanExecuteChanged();
        ((AsyncRelayCommand)RemoveMemberCommand).NotifyCanExecuteChanged();
        ((AsyncRelayCommand)ToggleStatusCommand).NotifyCanExecuteChanged();
        ((AsyncRelayCommand)DeleteGroupCommand).NotifyCanExecuteChanged();
    }

    public async Task RefreshAsync()
    {
        try
        {
            var groups = await _api.GetGroupsAsync();
            Groups.Clear();
            foreach (var g in groups) Groups.Add(g);
            ErrorMessage = string.Empty;
        }
        catch (MessengerApiException ex)
        {
            ErrorMessage = ex.Message;
        }
    }

    private async Task CreateGroupAsync()
    {
        try
        {
            await _api.CreateGroupAsync(NewGroupName, null);
            NewGroupName = string.Empty;
            await RefreshAsync();
        }
        catch (MessengerApiException ex)
        {
            ErrorMessage = ex.Message;
        }
    }

    private async Task AddMemberAsync()
    {
        if (SelectedGroup is null || !Guid.TryParse(MemberUserId, out var userId)) return;
        try
        {
            await _api.AddGroupMemberAsync(SelectedGroup.Id, userId);
            await RefreshAsync();
        }
        catch (MessengerApiException ex)
        {
            ErrorMessage = ex.Message;
        }
    }

    private async Task RemoveMemberAsync()
    {
        if (SelectedGroup is null || !Guid.TryParse(MemberUserId, out var userId)) return;
        try
        {
            await _api.RemoveGroupMemberAsync(SelectedGroup.Id, userId);
            await RefreshAsync();
        }
        catch (MessengerApiException ex)
        {
            ErrorMessage = ex.Message;
        }
    }

    private async Task ToggleStatusAsync()
    {
        if (SelectedGroup is null) return;
        var target = SelectedGroup.Status == "Active" ? "Disabled" : "Active";
        try
        {
            await _api.SetGroupStatusAsync(SelectedGroup.Id, target);
            await RefreshAsync();
        }
        catch (MessengerApiException ex)
        {
            ErrorMessage = ex.Message;
        }
    }

    private async Task DeleteGroupAsync()
    {
        if (SelectedGroup is null) return;
        try
        {
            await _api.DeleteGroupAsync(SelectedGroup.Id);
            await RefreshAsync();
        }
        catch (MessengerApiException ex)
        {
            ErrorMessage = ex.Message;
        }
    }
}
