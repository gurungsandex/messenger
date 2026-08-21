using Messenger.Contracts;

namespace Messenger.Admin.Wpf.Services;

public sealed class MessengerApiException(ErrorDto error) : Exception(error.Message)
{
    public string Code { get; } = error.Code;
}
