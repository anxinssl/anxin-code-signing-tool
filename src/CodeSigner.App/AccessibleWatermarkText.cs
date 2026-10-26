using System.Windows.Automation.Peers;
using System.Windows.Controls;

namespace CodeSigner.App;

public sealed class AccessibleWatermarkText : TextBlock
{
    protected override AutomationPeer? OnCreateAutomationPeer() => null;
}
