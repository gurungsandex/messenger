using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Messenger.Admin.Wpf.Services;

namespace Messenger.Admin.Wpf.ViewModels;

public sealed class LicenseViewModel : ObservableObject
{
    private readonly AdminApiClient _api;
    private LicenseStatusResponse? _status;
    private string _errorMessage = string.Empty;
    private string _statusMessage = string.Empty;

    public LicenseViewModel(AdminApiClient api)
    {
        _api = api;
        RefreshCommand = new AsyncRelayCommand(RefreshAsync);
        InstallCommand = new AsyncRelayCommand<string>(InstallAsync, content => !string.IsNullOrWhiteSpace(content));
    }

    public LicenseStatusResponse? Status
    {
        get => _status;
        private set => SetProperty(ref _status, value);
    }

    public string ErrorMessage
    {
        get => _errorMessage;
        private set => SetProperty(ref _errorMessage, value);
    }

    public string StatusMessage
    {
        get => _statusMessage;
        private set => SetProperty(ref _statusMessage, value);
    }

    public IAsyncRelayCommand RefreshCommand { get; }
    public IAsyncRelayCommand<string> InstallCommand { get; }

    public async Task RefreshAsync()
    {
        try
        {
            Status = await _api.GetLicenseAsync();
            ErrorMessage = string.Empty;
        }
        catch (MessengerApiException ex)
        {
            ErrorMessage = ex.Message;
        }
    }

    /// <summary>
    /// The licence file must be installed byte-for-byte as supplied -- any edit, including
    /// reformatting, invalidates its signature (LIC-101) -- so the caller reads it as raw
    /// text and this posts it unmodified.
    /// </summary>
    private async Task InstallAsync(string? licenseFileContent)
    {
        if (string.IsNullOrWhiteSpace(licenseFileContent)) return;
        try
        {
            await _api.InstallLicenseAsync(licenseFileContent);
            StatusMessage = "Licence installed.";
            await RefreshAsync();
        }
        catch (MessengerApiException ex)
        {
            ErrorMessage = ex.Message;
        }
    }
}
