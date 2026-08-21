using Messenger.Admin.Wpf.Services;

namespace Messenger.Admin.Wpf.ViewModels;

/// <summary>Hosts the seven admin console screens as tabs, each independently refreshable.</summary>
public sealed class MainViewModel
{
    public MainViewModel(AdminApiClient api)
    {
        Dashboard = new DashboardViewModel(api);
        Users = new UsersViewModel(api);
        Groups = new GroupsViewModel(api);
        Sessions = new SessionsViewModel(api);
        Audit = new AuditViewModel(api);
        License = new LicenseViewModel(api);
        DirectorySync = new DirectorySyncViewModel(api);
    }

    public DashboardViewModel Dashboard { get; }
    public UsersViewModel Users { get; }
    public GroupsViewModel Groups { get; }
    public SessionsViewModel Sessions { get; }
    public AuditViewModel Audit { get; }
    public LicenseViewModel License { get; }
    public DirectorySyncViewModel DirectorySync { get; }

    public async Task LoadAllAsync()
    {
        await Dashboard.RefreshAsync();
        await Users.RefreshAsync();
        await Groups.RefreshAsync();
        await Sessions.RefreshAsync();
        await Audit.RefreshAsync();
        await License.RefreshAsync();
    }
}
