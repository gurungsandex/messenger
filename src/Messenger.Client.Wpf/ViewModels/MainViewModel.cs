using System.Collections.ObjectModel;
using System.IO;
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Messenger.Client.Wpf.Services;
using Messenger.Contracts;

namespace Messenger.Client.Wpf.ViewModels;

/// <summary>
/// Shell view model: conversation list, the active chat thread, and file transfer. There is
/// deliberately no group-creation or membership UI here -- Part 1's research into the
/// server's API confirmed that is admin-console-only by the <c>groups.manage</c> permission
/// design, and an ordinary client only ever joins conversations an admin already created.
///
/// Starting a *direct* conversation searches <c>GET /api/users</c> (a non-admin directory
/// scoped to any signed-in user) rather than requiring the other user's id to be known or
/// pasted in -- that gap is what the search box below closes.
/// </summary>
public sealed class MainViewModel : ObservableObject, IAsyncDisposable
{
    private readonly ApiClient _api;
    private readonly string _baseUrl;
    private ChatHubClient? _hub;

    private ConversationItemViewModel? _selectedConversation;
    private string _messageText = string.Empty;
    private string _userSearchText = string.Empty;
    private UserDirectoryEntryDto? _selectedDirectoryUser;
    private string _statusMessage = string.Empty;
    private bool _peerOnline;

    public MainViewModel(ApiClient api, string baseUrl)
    {
        _api = api;
        _baseUrl = baseUrl;

        LoadConversationsCommand = new AsyncRelayCommand(LoadConversationsAsync);
        SendMessageCommand = new AsyncRelayCommand(SendMessageAsync, () => SelectedConversation is not null && !string.IsNullOrWhiteSpace(MessageText));
        SearchUsersCommand = new AsyncRelayCommand(SearchUsersAsync);
        StartDirectConversationCommand = new AsyncRelayCommand(StartDirectConversationAsync, () => SelectedDirectoryUser is not null);
        AttachFileCommand = new AsyncRelayCommand<string>(AttachFileAsync, path => SelectedConversation is not null && !string.IsNullOrEmpty(path));
    }

    public ObservableCollection<ConversationItemViewModel> Conversations { get; } = [];
    public ObservableCollection<ChatMessageViewModel> Messages { get; } = [];
    public ObservableCollection<UserDirectoryEntryDto> UserSearchResults { get; } = [];

    public ConversationItemViewModel? SelectedConversation
    {
        get => _selectedConversation;
        set
        {
            if (SetProperty(ref _selectedConversation, value))
            {
                OnPropertyChanged(nameof(HeaderTitle));
                ((AsyncRelayCommand)SendMessageCommand).NotifyCanExecuteChanged();
                _ = LoadHistoryAsync();
            }
        }
    }

    public string MessageText
    {
        get => _messageText;
        set
        {
            if (SetProperty(ref _messageText, value))
                ((AsyncRelayCommand)SendMessageCommand).NotifyCanExecuteChanged();
        }
    }

    public string UserSearchText
    {
        get => _userSearchText;
        set => SetProperty(ref _userSearchText, value);
    }

    public UserDirectoryEntryDto? SelectedDirectoryUser
    {
        get => _selectedDirectoryUser;
        set
        {
            if (SetProperty(ref _selectedDirectoryUser, value))
                ((AsyncRelayCommand)StartDirectConversationCommand).NotifyCanExecuteChanged();
        }
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set => SetProperty(ref _statusMessage, value);
    }

    public bool PeerOnline
    {
        get => _peerOnline;
        private set => SetProperty(ref _peerOnline, value);
    }

    public string HeaderTitle => SelectedConversation?.Title ?? "Select a conversation";

    public ICommand LoadConversationsCommand { get; }
    public ICommand SendMessageCommand { get; }
    public ICommand SearchUsersCommand { get; }
    public ICommand StartDirectConversationCommand { get; }
    public ICommand AttachFileCommand { get; }

    public async Task ConnectAsync()
    {
        _hub = new ChatHubClient(_baseUrl, _api.SessionToken!, _api.DeviceFingerprint);
        _hub.MessageReceived += OnMessageReceived;
        _hub.PresenceChanged += OnPresenceChanged;
        _hub.Closed += ex => StatusMessage = ex is null
            ? "Disconnected."
            : $"Connection lost: {ex.Message}";

        await _hub.ConnectAsync();
        await LoadConversationsAsync();
    }

    private async Task LoadConversationsAsync()
    {
        try
        {
            var conversations = await _api.GetConversationsAsync();
            Conversations.Clear();
            foreach (var c in conversations)
                Conversations.Add(new ConversationItemViewModel(c));
        }
        catch (MessengerApiException ex)
        {
            StatusMessage = ex.Message;
        }
    }

    private async Task LoadHistoryAsync()
    {
        Messages.Clear();
        if (SelectedConversation is null || _hub is null) return;

        try
        {
            var history = await _hub.GetHistoryAsync(SelectedConversation.ConversationId);
            foreach (var m in history)
                Messages.Add(new ChatMessageViewModel(m, m.SenderId == _api.UserId));
        }
        catch (Exception ex)
        {
            StatusMessage = $"Could not load history: {ex.Message}";
        }
    }

    private async Task SendMessageAsync()
    {
        if (_hub is null || SelectedConversation is null || string.IsNullOrWhiteSpace(MessageText)) return;

        var body = MessageText;
        MessageText = string.Empty;
        try
        {
            await _hub.SendMessageAsync(SelectedConversation.ConversationId, body);
        }
        catch (Exception ex)
        {
            StatusMessage = $"Send failed: {ex.Message}";
        }
    }

    private async Task SearchUsersAsync()
    {
        try
        {
            var results = await _api.SearchUsersAsync(UserSearchText);
            UserSearchResults.Clear();
            foreach (var u in results)
                UserSearchResults.Add(u);
        }
        catch (MessengerApiException ex)
        {
            StatusMessage = ex.Message;
        }
    }

    private async Task StartDirectConversationAsync()
    {
        if (_hub is null || SelectedDirectoryUser is null) return;

        try
        {
            var conversationId = await _hub.OpenDirectConversationAsync(SelectedDirectoryUser.UserId);
            await LoadConversationsAsync();
            SelectedConversation = Conversations.FirstOrDefault(c => c.ConversationId == conversationId);
            UserSearchText = string.Empty;
            UserSearchResults.Clear();
            SelectedDirectoryUser = null;
        }
        catch (Exception ex)
        {
            StatusMessage = $"Could not start conversation: {ex.Message}";
        }
    }

    /// <summary>
    /// There is no dedicated file-attachment message type on the wire -- the server has a
    /// complete file transfer API (Part 1) but nothing linking a stored file back to a chat
    /// message. Encoding it into the message body as a simple "FILE:id:name" marker is a
    /// client-side convention, not a server contract, and every other Messenger client would
    /// need to agree on the same convention to render it as anything other than plain text.
    /// </summary>
    private async Task AttachFileAsync(string? filePath)
    {
        if (_hub is null || SelectedConversation is null || string.IsNullOrEmpty(filePath)) return;

        try
        {
            var content = await File.ReadAllBytesAsync(filePath);
            var fileName = Path.GetFileName(filePath);
            var fileId = await _api.UploadFileAsync(SelectedConversation.ConversationId, fileName, content, null);
            await _hub.SendMessageAsync(SelectedConversation.ConversationId, $"FILE:{fileId}:{fileName}");
        }
        catch (Exception ex)
        {
            StatusMessage = $"Attachment failed: {ex.Message}";
        }
    }

    public async Task DownloadAttachmentAsync(Guid fileId, string suggestedFileName, string destinationPath)
    {
        var content = await _api.DownloadFileAsync(fileId);
        await File.WriteAllBytesAsync(destinationPath, content);
    }

    private void OnMessageReceived(MessageDto message)
    {
        var conversation = Conversations.FirstOrDefault(c => c.ConversationId == message.ConversationId);
        conversation?.MarkNewActivity(message.Seq, message.ServerReceivedAt);

        if (SelectedConversation?.ConversationId == message.ConversationId)
            Messages.Add(new ChatMessageViewModel(message, message.SenderId == _api.UserId));
    }

    private void OnPresenceChanged(PresenceDto presence)
    {
        if (SelectedConversation is { Type: ConversationType.Direct })
            PeerOnline = presence.Status == PresenceStatus.Online;
    }

    public async ValueTask DisposeAsync()
    {
        if (_hub is not null) await _hub.DisposeAsync();
    }
}
