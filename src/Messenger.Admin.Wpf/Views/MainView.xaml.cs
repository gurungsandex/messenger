using System.Windows;
using System.Windows.Controls;
using Messenger.Admin.Wpf.ViewModels;

namespace Messenger.Admin.Wpf.Views;

public partial class MainView : UserControl
{
    public MainView()
    {
        InitializeComponent();
    }

    /// <summary>
    /// The clicked button's DataContext is the TabItem's DataContext (the tab's own sub view
    /// model, e.g. UsersViewModel) via WPF's normal inheritance -- not this UserControl's,
    /// which is the top-level MainViewModel.
    /// </summary>
    private void CreateUser_Click(object sender, RoutedEventArgs e)
    {
        if (((FrameworkElement)sender).DataContext is not UsersViewModel vm) return;

        var fields = new NewUserFields(
            NewUsername.Text, NewDisplayName.Text, NewEmail.Text, NewPassword.Password);

        if (vm.CreateUserCommand.CanExecute(fields))
            vm.CreateUserCommand.Execute(fields);

        NewUsername.Clear();
        NewDisplayName.Clear();
        NewEmail.Clear();
        NewPassword.Clear();
    }

    private void InstallLicense_Click(object sender, RoutedEventArgs e)
    {
        if (((FrameworkElement)sender).DataContext is not LicenseViewModel vm) return;

        if (vm.InstallCommand.CanExecute(LicenseFileBox.Text))
            vm.InstallCommand.Execute(LicenseFileBox.Text);
    }
}
