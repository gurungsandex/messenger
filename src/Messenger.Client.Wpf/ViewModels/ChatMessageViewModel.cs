using Messenger.Contracts;

namespace Messenger.Client.Wpf.ViewModels;

public sealed class ChatMessageViewModel(MessageDto message, bool isMine)
{
    public Guid MessageId { get; } = message.MessageId;
    public long Seq { get; } = message.Seq;
    public string SenderDisplayName { get; } = message.SenderDisplayName;
    public string Body { get; } = message.IsDeleted ? "(message deleted)" : message.Body;
    public DateTimeOffset SentAt { get; } = message.SentAt;
    public bool IsMine { get; } = isMine;
}
