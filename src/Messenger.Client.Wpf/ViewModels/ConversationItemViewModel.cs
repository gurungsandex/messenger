using CommunityToolkit.Mvvm.ComponentModel;
using Messenger.Contracts;

namespace Messenger.Client.Wpf.ViewModels;

public sealed class ConversationItemViewModel(ConversationDto dto) : ObservableObject
{
    private ConversationDto _dto = dto;

    public Guid ConversationId => _dto.ConversationId;
    public ConversationType Type => _dto.Type;
    public string Title => _dto.Title;
    public bool HasUnread => _dto.LastSeq > _dto.LastReadSeq;
    public DateTimeOffset? LastMessageAt => _dto.LastMessageAt;

    public void Update(ConversationDto dto)
    {
        _dto = dto;
        OnPropertyChanged(nameof(HasUnread));
        OnPropertyChanged(nameof(LastMessageAt));
    }

    /// <summary>Bumps last-activity when a new message arrives, without touching what the user has actually read.</summary>
    public void MarkNewActivity(long seq, DateTimeOffset at)
        => Update(_dto with { LastSeq = seq, LastMessageAt = at });
}
