using Messenger.Contracts;

namespace Messenger.Client.Wpf.Services;

/// <summary>Wraps the server's catalogue-coded <see cref="ErrorDto"/> so a view model can show it directly.</summary>
public sealed class MessengerApiException(ErrorDto error) : Exception(error.Message)
{
    public string Code { get; } = error.Code;
}
