using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Messenger.Admin.Wpf.Services;

namespace Messenger.Admin.Wpf.ViewModels;

public sealed class DashboardViewModel : ObservableObject
{
    private readonly AdminApiClient _api;
    private HealthResponse? _health;
    private LicenseStatusResponse? _license;
    private string _errorMessage = string.Empty;

    public DashboardViewModel(AdminApiClient api)
    {
        _api = api;
        RefreshCommand = new AsyncRelayCommand(RefreshAsync);
    }

    public HealthResponse? Health
    {
        get => _health;
        private set => SetProperty(ref _health, value);
    }

    public LicenseStatusResponse? License
    {
        get => _license;
        private set => SetProperty(ref _license, value);
    }

    public string ErrorMessage
    {
        get => _errorMessage;
        private set => SetProperty(ref _errorMessage, value);
    }

    public IAsyncRelayCommand RefreshCommand { get; }

    public async Task RefreshAsync()
    {
        try
        {
            Health = await _api.GetHealthAsync();
            License = await _api.GetLicenseAsync();
            ErrorMessage = string.Empty;
        }
        catch (MessengerApiException ex)
        {
            ErrorMessage = ex.Message;
        }
    }
}
