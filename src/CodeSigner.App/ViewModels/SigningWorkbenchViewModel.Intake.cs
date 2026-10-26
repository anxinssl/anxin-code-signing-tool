using System.Globalization;
using System.IO;
using CodeSigner.App.Services;
using CodeSigner.Windows.Batch;
using CodeSigner.Windows.Files;

namespace CodeSigner.App.ViewModels;

public sealed partial class SigningWorkbenchViewModel
{
    private long outputGeneration;
    private long outputPlanRevision;
    private string? committedOutputRoot;
    private readonly HashSet<string> removedItemIds = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> destinationReservations =
        new(StringComparer.OrdinalIgnoreCase);

    internal bool IsRemovedItemTombstoned(string itemId) => removedItemIds.Contains(itemId);

    public async Task QueueFilesAsync(IReadOnlyCollection<string> paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        if (auditIncomplete || IsBusy)
        {
            return;
        }

        if (paths.Count == 0)
        {
            SetInputError("请至少选择一个支持的签名文件");
            return;
        }

        await QueueInputsAsync(paths, recurseDirectories: false);
    }

    public Task QueueFolderAsync(string path)
    {
        if (auditIncomplete || IsBusy)
        {
            return Task.CompletedTask;
        }

        if (string.IsNullOrWhiteSpace(path))
        {
            SetInputError("请选择包含支持签名文件的文件夹");
            return Task.CompletedTask;
        }

        return QueueInputsAsync([path], recurseDirectories: true);
    }

    public async Task QueueDroppedInputsAsync(IReadOnlyCollection<string> paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        if (auditIncomplete || IsBusy)
        {
            return;
        }

        await QueueInputsAsync(paths, recurseDirectories: true);
    }

    public async Task ReplanOutputRootAsync(string candidate)
    {
        ActionAudit? audit = BeginActionAudit(QueueAuditActions.OutputReplan, CurrentItem);
        if (audit is null)
        {
            return;
        }

        if (IsBusy)
        {
            EndActionAudit(audit, QueueAuditOutcomes.Rejected, QueueAuditReasons.Busy);
            return;
        }

        try
        {
            await ReplanOutputRootCoreAsync(candidate);
            EndActionAudit(
                audit,
                HasValidOutputRoot() ? QueueAuditOutcomes.Completed : QueueAuditOutcomes.Rejected,
                HasValidOutputRoot() ? null : QueueAuditReasons.OutputRequired);
        }
        catch
        {
            EndActionAudit(audit, QueueAuditOutcomes.Rejected, QueueAuditReasons.UnexpectedFailure);
            throw;
        }
    }

    private async Task ReplanOutputRootCoreAsync(string candidate)
    {
        if (IsBusy)
        {
            return;
        }

        using (SuppressActionAudit())
        {
            OutputRoot = candidate;
        }
        if (!HasValidOutputRoot())
        {
            FocusTargetAutomationId = "OutputRootTextBox";
            return;
        }

        if (!CommitOutputRoot(OutputRoot))
        {
            OutputError = string.Empty;
            if (CurrentItem is { State: BatchItemState.Pending } current &&
                (!current.HasOutputPlan(outputGeneration) ||
                 current.PreflightState != QueueItemPreflightState.Ready))
            {
                await InvalidateCurrentPreflightAsync();
            }

            RefreshValidation();
            return;
        }

        long revision = ++outputPlanRevision;
        foreach (QueueItemViewModel row in Rows.Where(row => row.State == BatchItemState.Pending))
        {
            row.InvalidateOutputPlan();
        }

        RebuildDestinationReservations();

        await InvalidateCurrentPreflightAsync();

        RefreshValidation();
    }

    private bool CommitOutputRoot(string candidate)
    {
        string canonical = Path.TrimEndingDirectorySeparator(Path.GetFullPath(candidate));
        if (committedOutputRoot is not null &&
            string.Equals(canonical, committedOutputRoot, StringComparison.OrdinalIgnoreCase))
        {
            outputRoot = canonical;
            OnPropertyChanged(nameof(OutputRoot));
            return false;
        }

        committedOutputRoot = canonical;
        outputRoot = canonical;
        outputGeneration++;
        OnPropertyChanged(nameof(OutputRoot));
        return true;
    }

    private bool IsCommittedOutputRootCurrent()
    {
        if (committedOutputRoot is null || !HasValidOutputRoot())
        {
            return false;
        }

        string canonical = Path.TrimEndingDirectorySeparator(Path.GetFullPath(OutputRoot));
        return string.Equals(canonical, committedOutputRoot, StringComparison.OrdinalIgnoreCase);
    }

    public void RemoveSelected()
    {
        RemoveRows(Rows.Where(row => row.IsSelected));
    }

    private void RemoveQueueItem(object? parameter)
    {
        if (parameter is QueueItemViewModel row)
        {
            RemoveRows([row]);
        }
    }

    private void RemoveRows(IEnumerable<QueueItemViewModel> candidates)
    {
        if (IsBusy)
        {
            RefreshValidation();
            return;
        }

        QueueItemViewModel[] removable = candidates
            .Where(row => IsRemovable(row) && Rows.Contains(row))
            .Distinct()
            .ToArray();
        var audits = new List<ActionAudit>(removable.Length);
        foreach (QueueItemViewModel row in removable)
        {
            ActionAudit? audit = BeginActionAudit(QueueAuditActions.Remove, row);
            if (audit is null)
            {
                foreach (ActionAudit started in audits)
                {
                    EndActionAudit(started, QueueAuditOutcomes.Rejected, QueueAuditReasons.AuditLogUnavailable);
                }

                return;
            }

            audits.Add(audit);
        }

        var removing = removable.ToHashSet();
        QueueItemViewModel? nextCurrent = CurrentItem;
        if (CurrentItem is not null && removing.Contains(CurrentItem))
        {
            int currentIndex = Rows.IndexOf(CurrentItem);
            nextCurrent = Rows
                .Skip(currentIndex + 1)
                .FirstOrDefault(row => !removing.Contains(row)) ??
                Rows
                    .Take(currentIndex)
                    .Reverse()
                    .FirstOrDefault(row => !removing.Contains(row));
        }
        string[] retainedBatchItemIds = removable
            .Where(row => row.RetainedRequest is not null)
            .Select(row => row.ItemId)
            .ToArray();
        if (retainedBatchItemIds.Length > 0)
        {
            try
            {
                batchAdapter.PruneItems(retainedBatchItemIds);
            }
            catch (Exception exception) when (exception is
                ArgumentException or InvalidOperationException or NotSupportedException)
            {
                StatusMessage = "无法移除签名文件项目，保留的重试批次未能同步";
                FocusTargetAutomationId = removable[0].AutomationId;
                RefreshValidation();
                foreach (ActionAudit audit in audits)
                {
                    EndActionAudit(audit, QueueAuditOutcomes.Rejected, QueueAuditReasons.UnexpectedFailure);
                }
                return;
            }
        }

        foreach (QueueItemViewModel row in removable)
        {
            CancelDetection(row.ItemId);
            removedPaths.Add(row.FullPath);
            removedItemIds.Add(row.ItemId);
            TombstoneExecutionItem(row.ItemId);
            RemoveAdmissionIndex(row.Source);
            Rows.Remove(row);
        }

        RebuildDestinationReservations();

        if (!ReferenceEquals(CurrentItem, nextCurrent))
        {
            SetCurrentItem(nextCurrent);
        }
        else if (CurrentItem is { State: BatchItemState.Pending } current &&
                 current.PreflightIssue?.DetailCode == QueueAuditReasons.DestinationUnsafe)
        {
            current.InvalidateOutputPlan();
            _ = InvalidateCurrentPreflightAsync();
        }

        UpdateAggregateProgress();
        if (Rows.Count == 0)
        {
            StatusMessage = "请添加支持的签名文件或文件夹开始";
        }
        else
        {
            UpdateSummaryAndFocus();
        }

        RefreshValidation();
        foreach (ActionAudit audit in audits)
        {
            EndActionAudit(audit, QueueAuditOutcomes.Completed);
        }
    }

    private async Task QueueInputsAsync(IReadOnlyCollection<string> paths, bool recurseDirectories)
    {
        var source = new IntakeSource(paths.ToArray(), recurseDirectories);
        await admissionGate.WaitAsync();
        try
        {
            if (disposeRequested != 0 || auditIncomplete)
            {
                return;
            }

            AdmissionAudit? admissionAudit = BeginAdmissionAudit();
            if (admissionAudit is null)
            {
                return;
            }

            QueuedSourceAdmissionResult admission;
            try
            {
                admission = await intakeAdapter.AdmitAsync(
                paths,
                recurseDirectories,
                    detectionLifetimeCancellation.Token);
            }
            catch (OperationCanceledException) when (detectionLifetimeCancellation.IsCancellationRequested)
            {
                EndAdmissionAudit(admissionAudit, QueueAuditOutcomes.Rejected, QueueAuditReasons.Cancelled);
                return;
            }
            catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException)
            {
                EndAdmissionAudit(admissionAudit, QueueAuditOutcomes.Rejected, QueueAuditReasons.UnexpectedFailure);
                ReportAdmissionFailure("签名文件输入无法检查", source, IntakeError.InaccessibleInput);
                return;
            }

            List<QueueItemViewModel> added = AddAdmittedSources(admission.Sources);
            string outcome = admission.Failures.Count == 0
                ? QueueAuditOutcomes.Accepted
                : added.Count > 0
                    ? QueueAuditOutcomes.Partial
                    : QueueAuditOutcomes.Rejected;
            EndAdmissionAudit(
                admissionAudit,
                outcome,
                outcome == QueueAuditOutcomes.Rejected ? QueueAuditReasons.IntakeFailed : null);

            if (admission.Failures.Count > 0)
            {
                QueuedSourceAdmissionFailure failure = admission.Failures[0];
                ReportAdmissionFailure(
                    FormatAdmissionFailure(failure),
                    source,
                    MapAdmissionError(failure.Error));
            }
            else if (added.Count > 0)
            {
                ClearInputError();
            }

            if (added.Count > 0)
            {
                StatusMessage = $"{Rows.Count} 个签名文件项目等待格式检测";
                EnqueueDetections(added);
            }

            RefreshValidation();
        }
        finally
        {
            admissionGate.Release();
        }
    }

    private List<QueueItemViewModel> AddAdmittedSources(IReadOnlyList<QueuedSource> sources)
    {
        bool selectFirstAdded = CurrentItem is null;
        var added = new List<QueueItemViewModel>(sources.Count);
        foreach (QueuedSource admitted in sources)
        {
            if (!TryAddAdmissionIndex(admitted))
            {
                continue;
            }

            string itemId = nextItemId.ToString(CultureInfo.InvariantCulture);
            bool isReAdd = removedPaths.Contains(admitted.CanonicalPath);
            ActionAudit? reAddAudit = isReAdd
                ? BeginActionAudit(QueueAuditActions.ReAdd, itemId)
                : ActionAudit.Disabled;
            if (reAddAudit is null)
            {
                RemoveAdmissionIndex(admitted);
                continue;
            }

            nextItemId++;
            removedPaths.Remove(admitted.CanonicalPath);
            var row = new QueueItemViewModel(itemId, admitted);
            row.UpdateSigningMode(SelectedMode);
            RegisterExecutionItem(itemId);
            Rows.Add(row);
            added.Add(row);
            EndActionAudit(reAddAudit, QueueAuditOutcomes.Completed);
        }

        if (selectFirstAdded && added.Count > 0)
        {
            SetCurrentItem(added[0]);
        }

        UpdateAggregateProgress();
        return added;
    }

    private void RebuildDestinationReservations()
    {
        destinationReservations.Clear();
        if (!HasValidOutputRoot())
        {
            return;
        }

        foreach (QueueItemViewModel row in Rows
                     .Where(row => row.State == BatchItemState.Pending &&
                         row.DetectionState == QueueItemDetectionState.Supported &&
                         row.SourceIntegrityState == QueueItemSourceIntegrityState.Current)
                     .OrderBy(row => long.Parse(row.ItemId, NumberStyles.None, CultureInfo.InvariantCulture)))
        {
            string destination = NormalizeDestination(Path.Combine(OutputRoot, row.Source.RelativePath));
            destinationReservations.TryAdd(destination, row.ItemId);
        }
    }

    private bool OwnsDestinationReservation(QueueItemViewModel row, string destinationPath)
    {
        RebuildDestinationReservations();
        string destination = NormalizeDestination(destinationPath);
        return destinationReservations.TryGetValue(destination, out string? ownerItemId) &&
            string.Equals(ownerItemId, row.ItemId, StringComparison.Ordinal);
    }

    private static string NormalizeDestination(string path) =>
        Path.GetFullPath(path);

    private void ReportAdmissionFailure(string message, IntakeSource source, IntakeError error)
    {
        if (CurrentItem is null)
        {
            SetInputError(message, source, error);
            return;
        }

        inputErrorSource = source;
        inputErrorKind = error;
        InputError = message;
        StatusMessage = message;
        RefreshValidation();
    }

    private static string FormatAdmissionFailure(QueuedSourceAdmissionFailure failure) =>
        FormatIntakeError(new IntakeValidationException(
            MapAdmissionError(failure.Error),
            "签名文件输入无法检查",
            failure.Path));

    private static IntakeError MapAdmissionError(QueuedSourceAdmissionError error) => error switch
    {
        QueuedSourceAdmissionError.InvalidInput => IntakeError.InvalidInput,
        QueuedSourceAdmissionError.InputNotFound => IntakeError.InputNotFound,
        QueuedSourceAdmissionError.ReparsePoint => IntakeError.ReparsePoint,
        QueuedSourceAdmissionError.InaccessibleInput => IntakeError.InaccessibleInput,
        _ => throw new ArgumentOutOfRangeException(nameof(error), error, "未知入队错误")
    };

    private static bool IsSameIntakeSource(IntakeSource left, IntakeSource right)
    {
        if (left.RecurseDirectories != right.RecurseDirectories)
        {
            return false;
        }

        var leftPaths = new HashSet<string>(left.Paths, StringComparer.OrdinalIgnoreCase);
        return leftPaths.SetEquals(right.Paths);
    }

    private sealed record IntakeSource(IReadOnlyCollection<string> Paths, bool RecurseDirectories);
}
