using System.ComponentModel;
using System.Windows;
using System.Windows.Media;

namespace CodeSigner.App;

internal static class ThemeManager
{
    private static Application? application;

    public static void Start(Application currentApplication)
    {
        application = currentApplication ?? throw new ArgumentNullException(nameof(currentApplication));
        SystemParameters.StaticPropertyChanged += OnSystemParametersChanged;
        ApplyContrastResources();
    }

    public static void Stop()
    {
        SystemParameters.StaticPropertyChanged -= OnSystemParametersChanged;
        application = null;
    }

    private static void OnSystemParametersChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (string.Equals(e.PropertyName, nameof(SystemParameters.HighContrast), StringComparison.Ordinal))
        {
            ApplyContrastResources();
        }
    }

    private static void ApplyContrastResources()
    {
        if (application is null)
        {
            return;
        }

        ResourceDictionary resources = application.Resources;
        if (SystemParameters.HighContrast)
        {
            resources["Color.Surface.Primary"] = SystemColors.WindowBrush;
            resources["Color.Surface.Secondary"] = SystemColors.ControlBrush;
            resources["Color.Surface.Elevated"] = SystemColors.WindowBrush;
            resources["Color.Surface.Inset"] = SystemColors.WindowBrush;
            resources["Color.Surface.Header"] = SystemColors.ControlBrush;
            resources["Color.Surface.Summary"] = SystemColors.ControlBrush;
            resources["Color.Text.Primary"] = SystemColors.WindowTextBrush;
            resources["Color.Text.Secondary"] = SystemColors.ControlTextBrush;
            resources["Color.Text.Tertiary"] = SystemColors.GrayTextBrush;
            resources["Color.Text.OnAccent"] = SystemColors.HighlightTextBrush;
            resources["Color.Border.Default"] = SystemColors.ControlDarkBrush;
            resources["Color.Border.Subtle"] = SystemColors.ControlDarkBrush;
            resources["Color.Separator"] = SystemColors.ControlDarkBrush;
            resources["Brush.PageBackground"] = SystemColors.WindowBrush;
            resources["Brush.CardBackground"] = SystemColors.WindowBrush;
            resources["Brush.ReadinessBackground"] = SystemColors.ControlBrush;
            resources["Color.Accent.Primary"] = SystemColors.HighlightBrush;
            resources["Color.Accent.Hover"] = SystemColors.HighlightBrush;
            resources["Color.Accent.Pressed"] = SystemColors.HighlightBrush;
            resources["Color.Accent.Subtle"] = SystemColors.ControlBrush;
            resources["Color.Accent.PressedBackground"] = SystemColors.HighlightBrush;
            resources["Color.Status.Success"] = SystemColors.WindowTextBrush;
            resources["Color.Status.SuccessBackground"] = SystemColors.WindowBrush;
            resources["Color.Status.SuccessBorder"] = SystemColors.ControlDarkBrush;
            resources["Color.Status.Warning"] = SystemColors.WindowTextBrush;
            resources["Color.Status.WarningBackground"] = SystemColors.WindowBrush;
            resources["Color.Status.WarningBorder"] = SystemColors.ControlDarkBrush;
            resources["Color.Status.Error"] = SystemColors.WindowTextBrush;
            resources["Color.Status.ErrorBackground"] = SystemColors.WindowBrush;
            resources["Color.Status.ErrorBorder"] = SystemColors.ControlDarkBrush;
            resources["Color.Status.Info"] = SystemColors.WindowTextBrush;
            resources["Color.Status.InfoBackground"] = SystemColors.WindowBrush;
            resources["Color.Status.InfoBorder"] = SystemColors.ControlDarkBrush;
            resources["Color.Selection.Background"] = SystemColors.HighlightBrush;
            resources["Color.Focus.Ring"] = SystemColors.HighlightBrush;
            resources["Color.Focus.Ring.OnAccent"] = SystemColors.HighlightTextBrush;
            return;
        }

        string[] keys =
        [
            "Color.Surface.Primary",
            "Color.Surface.Secondary",
            "Color.Surface.Elevated",
            "Color.Surface.Inset",
            "Color.Surface.Header",
            "Color.Surface.Summary",
            "Color.Text.Primary",
            "Color.Text.Secondary",
            "Color.Text.Tertiary",
            "Color.Text.OnAccent",
            "Color.Border.Default",
            "Color.Border.Subtle",
            "Color.Separator",
            "Brush.PageBackground",
            "Brush.CardBackground",
            "Brush.ReadinessBackground",
            "Color.Accent.Primary",
            "Color.Accent.Hover",
            "Color.Accent.Pressed",
            "Color.Accent.Subtle",
            "Color.Accent.PressedBackground",
            "Color.Status.Success",
            "Color.Status.SuccessBackground",
            "Color.Status.SuccessBorder",
            "Color.Status.Warning",
            "Color.Status.WarningBackground",
            "Color.Status.WarningBorder",
            "Color.Status.Error",
            "Color.Status.ErrorBackground",
            "Color.Status.ErrorBorder",
            "Color.Status.Info",
            "Color.Status.InfoBackground",
            "Color.Status.InfoBorder",
            "Color.Selection.Background",
            "Color.Focus.Ring",
            "Color.Focus.Ring.OnAccent"
        ];
        foreach (string key in keys)
        {
            resources.Remove(key);
        }
    }
}
