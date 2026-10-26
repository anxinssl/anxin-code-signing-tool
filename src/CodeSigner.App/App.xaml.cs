namespace CodeSigner.App;

public partial class App : System.Windows.Application
{
    protected override void OnStartup(System.Windows.StartupEventArgs e)
    {
        base.OnStartup(e);
        ThemeManager.Start(this);

        if (e.Args.Contains("--primitive-showcase", StringComparer.Ordinal))
        {
            MainWindow = new PrimitiveShowcaseWindow();
        }
        else
        {
            MainWindow = new MainWindow();
        }

        MainWindow.Show();
    }

    protected override void OnExit(System.Windows.ExitEventArgs e)
    {
        ThemeManager.Stop();
        base.OnExit(e);
    }
}
