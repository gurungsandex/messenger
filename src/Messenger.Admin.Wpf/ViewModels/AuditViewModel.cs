using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Messenger.Admin.Wpf.Services;

namespace Messenger.Admin.Wpf.ViewModels;

public sealed class AuditViewModel : ObservableObject
{
    private readonly AdminApiClient _api;
    private string _errorMessage = string.Empty;
    private string _verificationResult = string.Empty;

    public AuditViewModel(AdminApiClient api)
    {
        _api = api;
        RefreshCommand = new AsyncRelayCommand(RefreshAsync);
        VerifyCommand = new AsyncRelayCommand(VerifyAsync);
    }

    public ObservableCollection<AuditEntrySummary> Entries { get; } = [];

    public string ErrorMessage
    {
        get => _errorMessage;
        private set => SetProperty(ref _errorMessage, value);
    }

    public string VerificationResult
    {
        get => _verificationResult;
        private set => SetProperty(ref _verificationResult, value);
    }

    public IAsyncRelayCommand RefreshCommand { get; }
    public IAsyncRelayCommand VerifyCommand { get; }

    public async Task RefreshAsync()
    {
        try
        {
            var entries = await _api.GetAuditLogAsync();
            Entries.Clear();
            foreach (var e in entries) Entries.Add(e);
            ErrorMessage = string.Empty;
        }
        catch (MessengerApiException ex)
        {
            ErrorMessage = ex.Message;
        }
    }

    private async Task VerifyAsync()
    {
        try
        {
            var result = await _api.VerifyAuditChainAsync();
            VerificationResult = result.Valid
                ? "The audit chain is intact."
                // A verification failure is a security incident (SRV-305 in the server's
                // error catalogue), not a routine error -- worth the operator's attention,
                // not a message that scrolls by.
                : $"AUDIT CHAIN VERIFICATION FAILED at entry {result.FirstInvalidEntryId}. Treat this as a security incident.";
        }
        catch (MessengerApiException ex)
        {
            ErrorMessage = ex.Message;
        }
    }
}
