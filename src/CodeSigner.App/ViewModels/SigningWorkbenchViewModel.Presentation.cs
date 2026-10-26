using CodeSigner.Windows.Readiness;

namespace CodeSigner.App.ViewModels;

public sealed partial class SigningWorkbenchViewModel
{
    private bool environmentCheckAttempted;
    private bool readinessRefreshing;

    public string RefreshButtonText => readinessRefreshing ? "正在刷新…" : "刷新证书";

    private string? PendingEnvironmentText(string pending, string checking) =>
        readinessRefreshing ? checking :
        readiness is not null ? null :
        environmentCheckAttempted ? "环境检查失败，请重试" : pending;

    private string WorkstationPresentation =>
        PendingEnvironmentText("系统环境待检查", "正在检查环境") ??
        (readiness!.Workstation.Status == WorkstationSupportStatus.Supported
            ? "系统环境符合要求"
            : readiness.Workstation.DiagnosticCode switch
            {
                "RequiresWindows10Or11Nt10" => "需要 Windows 10 或 11",
                "RequiresX64" => "需要 x64 系统",
                "RequiresWorkstation" => "系统类型不符合运行要求",
                _ => "系统环境不符合运行要求"
            });

    private void SetReadinessRefreshing(bool refreshing)
    {
        readinessRefreshing = refreshing;
        OnPropertyChanged(nameof(RefreshButtonText));
        OnPropertyChanged(nameof(WorkstationStatus));
        OnPropertyChanged(nameof(NativeApiStatus));
        OnPropertyChanged(nameof(PowerShellBridgeStatus));
        OnPropertyChanged(nameof(CertificateStatus));
        OnPropertyChanged(nameof(TimestampStatus));
    }
}
