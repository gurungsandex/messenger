using System.Windows.Controls;
using System.Windows.Input;
using Messenger.Client.Wpf.ViewModels;
using Microsoft.Win32;

namespace Messenger.Client.Wpf.Views;

public partial class MainView : UserControl
{
    public MainView()
    {
        InitializeComponent();
    }

    private void MessageBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter || DataContext is not MainViewModel vm) return;
        if (vm.SendMessageCommand.CanExecute(null))
            vm.SendMessageCommand.Execute(null);
    }

    private void UserSearchBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter || DataContext is not MainViewModel vm) return;
        if (vm.SearchUsersCommand.CanExecute(null))
            vm.SearchUsersCommand.Execute(null);
    }

    private void AttachFile_Click(object sender, System.Windows.RoutedEventArgs e)
    {
        if (DataContext is not MainViewModel vm) return;

        var dialog = new OpenFileDialog { Title = "Attach a file" };
        if (dialog.ShowDialog() != true) return;

        if (vm.AttachFileCommand.CanExecute(dialog.FileName))
            vm.AttachFileCommand.Execute(dialog.FileName);
    }
}
