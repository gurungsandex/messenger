using System.Windows.Controls;
using Messenger.Client.Wpf.ViewModels;

namespace Messenger.Client.Wpf.Views;

public partial class ChangePasswordView : UserControl
{
    public ChangePasswordView()
    {
        InitializeComponent();
    }

    private void Submit_Click(object sender, System.Windows.RoutedEventArgs e)
    {
        if (DataContext is not ChangePasswordViewModel vm) return;

        var fields = new ChangePasswordFields(
            CurrentPasswordBox.Password, NewPasswordBox.Password, ConfirmPasswordBox.Password);

        if (vm.SubmitCommand.CanExecute(fields))
            vm.SubmitCommand.Execute(fields);
    }
}
