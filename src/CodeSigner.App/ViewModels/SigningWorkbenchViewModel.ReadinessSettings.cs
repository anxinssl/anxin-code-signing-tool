using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Reflection;
using CodeSigner.App.Services;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Readiness;
using CodeSigner.Windows.Signing;

namespace CodeSigner.App.ViewModels;

public sealed partial class SigningWorkbenchViewModel
{
    private WorkerSdkFallback sdkSignToolFallback = WorkerSdkFallback.Disabled;

    public bool SdkSignToolFallbackEnabledForSession => sdkSignToolFallback.Enabled;

    private async Task RefreshSdkSignToolReadinessAsync(CancellationToken cancellationToken)
    {
        SdkSignToolDiscoveryResult result;
        if (sdkSignToolReadinessState is null)
        {
            result = SdkSignToolDiscoveryResult.Unavailable();
        }
        else
        {
            try
            {
                result = await Task.Run(sdkSignToolReadinessState.Refresh, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception) when (exception is
                InvalidOperationException or
                IOException or
                UnauthorizedAccessException or
                System.Security.SecurityException)
            {
                result = SdkSignToolDiscoveryResult.Rejected(SdkSignToolRejectionReason.ProbeFailed);
            }
        }

        sdkSignToolDiscovery = result;
        sdkSignToolFallback = CreateSdkSignToolFallback(result);
        OnPropertyChanged(nameof(SdkSignToolAvailable));
        OnPropertyChanged(nameof(SdkSignToolCandidate));
        OnPropertyChanged(nameof(SdkSignToolStatusText));
        OnPropertyChanged(nameof(SdkSignToolFallbackEnabledForSession));
    }

    private async Task RefreshSdkSignToolReadinessActionAsync(CancellationToken cancellationToken)
    {
        ActionAudit? audit = BeginActionAudit(QueueAuditActions.ReadinessRefresh, CurrentItem);
        if (audit is null)
        {
            return;
        }

        try
        {
            await RefreshSdkSignToolReadinessAsync(cancellationToken);
            EndActionAudit(audit, QueueAuditOutcomes.Completed);
        }
        catch (OperationCanceledException)
        {
            EndActionAudit(audit, QueueAuditOutcomes.Cancelled, QueueAuditReasons.Cancelled);
            throw;
        }
    }

    private WorkerSdkFallback CaptureSdkSignToolFallback() => sdkSignToolFallback;

    private static WorkerSdkFallback CreateSdkSignToolFallback(SdkSignToolDiscoveryResult result)
    {
        TrustedSdkSignToolCandidate? candidate = result.IsAvailable ? result.Candidate : null;
        return candidate is null
            ? WorkerSdkFallback.Disabled
            : new WorkerSdkFallback(
                true,
                new WorkerSdkCandidateIdentity(
                    candidate.Path,
                    candidate.SdkVersion.ToString(4),
                    candidate.ProductVersion.ToString(4),
                    candidate.Publisher,
                    candidate.CompanyName,
                    candidate.ProductName,
                    candidate.Sha256.ToLowerInvariant()));
    }

    private void RefreshEnvironmentReadiness()
    {
        environmentCheckAttempted = true;
        using AuditSuppression auditScope = SuppressActionAudit();
        CancelActivePreflight(PreflightCancellationKind.Superseded);
        try
        {
            readiness = readinessAdapter.Probe(timestampUri);
            ReplaceCertificates(readiness.CertificateCatalog.Certificates);
            ReadinessAnnouncement = $"就绪检查完成。{FirstBlocking().Reason ?? "就绪，可开始签名"}";
        }
        catch (Exception exception) when (exception is InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            readiness = null;
            Certificates.Clear();
            PrimaryCertificate = null;
            SecondaryCertificate = null;
            ReadinessAnnouncement = "就绪状态无法检查";
        }

        OnPropertyChanged(nameof(WorkstationStatus));
        OnPropertyChanged(nameof(NativeApiStatus));
        OnPropertyChanged(nameof(PowerShellBridgeStatus));
        OnPropertyChanged(nameof(SimplySignStatus));
        OnPropertyChanged(nameof(CertificateStatus));
        OnPropertyChanged(nameof(CertificatePreparationHint));
        OnPropertyChanged(nameof(TimestampStatus));
        Interlocked.Increment(ref preflightReadinessGeneration);
        RefreshValidation(moveFocus: true);
        _ = InvalidateCurrentPreflightAsync();
    }

    public bool ApplySettings(string timestampUriText, int retentionDays)
    {
        ActionAudit? audit = BeginActionAudit(QueueAuditActions.TimestampSettingsApply, CurrentItem);
        if (audit is null)
        {
            return false;
        }

        PolicyResult<TimestampPolicy> timestamp = TimestampPolicy.TryCreate(timestampUriText);
        if (!timestamp.IsSuccess)
        {
            SettingsValidationError = "请输入不带凭据的绝对 HTTP 或 HTTPS 时间戳 URI";
            FocusTargetAutomationId = "SettingsTimestampUri";
            EndActionAudit(audit, QueueAuditOutcomes.Rejected, QueueAuditReasons.TimestampUnavailable);
            return false;
        }

        if (!AllowedRetentionDays.Contains(retentionDays))
        {
            SettingsValidationError = "请选择诊断保留期限：7、30 或 90 天";
            FocusTargetAutomationId = "SettingsRetention";
            EndActionAudit(audit, QueueAuditOutcomes.Rejected, QueueAuditReasons.InvalidState);
            return false;
        }

        timestampUri = timestamp.Value!.Uri;
        diagnosticRetentionDays = retentionDays;
        SettingsValidationError = string.Empty;
        OnPropertyChanged(nameof(TimestampUri));
        OnPropertyChanged(nameof(DiagnosticRetentionDays));
        RefreshEnvironmentReadiness();
        EndActionAudit(audit, QueueAuditOutcomes.Completed);
        return true;
    }

    private void ReplaceCertificates(IReadOnlyList<EligibleCertificate> eligible)
    {
        string? primaryIdentity = PrimaryCertificate is null ? null : Identity(PrimaryCertificate.Certificate);
        string? secondaryIdentity = SecondaryCertificate is null ? null : Identity(SecondaryCertificate.Certificate);
        Certificates.Clear();
        foreach (EligibleCertificate certificate in eligible)
        {
            Certificates.Add(new CertificateOptionViewModel(certificate));
        }

        PrimaryCertificate = Certificates.FirstOrDefault(item => Identity(item.Certificate) == primaryIdentity)
            ?? Certificates.FirstOrDefault();
        SecondaryCertificate = Certificates.FirstOrDefault(item => Identity(item.Certificate) == secondaryIdentity);
    }

    private static string FormatSdkSignToolRejection(SdkSignToolRejectionReason reason) => reason switch
    {
        SdkSignToolRejectionReason.OutsideCanonicalHierarchy => "候选不在 Windows Kits 标准 x64 目录",
        SdkSignToolRejectionReason.MalformedSdkVersion => "SDK 版本目录格式无效",
        SdkSignToolRejectionReason.ReparsePoint => "候选路径包含重解析点",
        SdkSignToolRejectionReason.NotX64PortableExecutable => "候选不是 x64 PE 可执行文件",
        SdkSignToolRejectionReason.WindowsTrustFailed => "Windows 无法验证候选签名信任",
        SdkSignToolRejectionReason.PublisherMismatch => "Microsoft 发布者元数据不匹配",
        SdkSignToolRejectionReason.CompanyMismatch => "Microsoft 公司元数据不匹配",
        SdkSignToolRejectionReason.ProductMismatch => "Microsoft 产品元数据不匹配",
        SdkSignToolRejectionReason.IdentityMismatch => "SignTool 文件身份元数据不匹配",
        SdkSignToolRejectionReason.InvalidVersionMetadata => "SignTool 版本元数据无效",
        SdkSignToolRejectionReason.CandidateChanged => "候选在检测后发生变化，请重新检测",
        _ => "候选验证失败"
    };
}
