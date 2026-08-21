using System.Windows.Controls;
using System.Windows.Input;
using Messenger.Client.Wpf.ViewModels;

namespace Messenger.Client.Wpf.Views;

/// <summary>
/// <c>PasswordBox.Password</c> is deliberately not a dependency property WPF lets you bind
/// to (a plaintext password should not linger in a view model property for the window's
/// whole lifetime), so this code-behind reads it only at the moment of submission and hands
/// it to the command as a one-shot parameter.
/// </summary>
public partial class LoginView : UserControl
{
    public LoginView()
    {
        InitializeComponent();
    }

    private void SignIn_Click(object sender, System.Windows.RoutedEventArgs e) => Submit();

    private void PasswordBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) Submit();
    }

    private void Submit()
    {
        if (DataContext is not LoginViewModel vm) return;
        var parameter = new PasswordContainer(PasswordBox.Password);
        if (vm.LoginCommand.CanExecute(parameter))
            vm.LoginCommand.Execute(parameter);
    }
}
