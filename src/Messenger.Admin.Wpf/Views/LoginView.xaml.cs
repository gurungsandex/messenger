using System.Windows.Controls;
using System.Windows.Input;
using Messenger.Admin.Wpf.ViewModels;

namespace Messenger.Admin.Wpf.Views;

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
