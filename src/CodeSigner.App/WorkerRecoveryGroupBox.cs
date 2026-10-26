using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Controls;

namespace CodeSigner.App;

internal sealed class WorkerRecoveryGroupBox : GroupBox
{
    protected override AutomationPeer OnCreateAutomationPeer() =>
        new WorkerRecoveryGroupBoxAutomationPeer(this);
}

internal sealed class WorkerRecoveryGroupBoxAutomationPeer(WorkerRecoveryGroupBox owner)
    : FrameworkElementAutomationPeer(owner)
{
    protected override AutomationControlType GetAutomationControlTypeCore() =>
        AutomationControlType.Group;

    protected override string GetClassNameCore() => nameof(WorkerRecoveryGroupBox);

    protected override AutomationLiveSetting GetLiveSettingCore() =>
        AutomationProperties.GetLiveSetting(Owner);
}
