namespace CodeSigner.InstallerVerifier;

internal sealed record Subscription(string Event, string Attribute);

internal sealed record Publication(
    string? Event,
    string? Property,
    string Value,
    string? Condition,
    int Order);

internal sealed record AuthoringControlAttributes(
    bool Disabled,
    bool Hidden,
    bool Indirect,
    bool Integer,
    bool RightToLeft,
    bool RightAligned,
    bool LeftScroll,
    bool Sunken,
    bool TabSkip,
    bool Transparent,
    bool Default,
    bool Cancel,
    bool ProgressBlocks);

internal sealed record AuthoringControl(
    string Id,
    string Type,
    int X,
    int Y,
    int Width,
    int Height,
    string? Property,
    string? Text,
    AuthoringControlAttributes Attributes,
    IReadOnlyList<Subscription> Subscriptions,
    IReadOnlyList<Publication> Publications);

internal sealed record AuthoringDialogAttributes(
    bool Modeless,
    bool NoMinimize,
    bool KeepModeless,
    bool TrackDiskSpace,
    bool RightToLeft,
    bool RightAligned,
    bool LeftScroll,
    bool ErrorDialog);

internal sealed record AuthoringDialog(
    string Id,
    int HCentering,
    int VCentering,
    int Width,
    int Height,
    string? Title,
    AuthoringDialogAttributes Attributes,
    IReadOnlyList<AuthoringControl> Controls);

internal sealed record AuthoringSequenceRow(string Dialog, string? Condition, int Sequence);

internal sealed record AuthoringExitRoute(string Dialog, string OnExit, string? Condition);

internal sealed record AuthoringShortcut(
    string Id,
    string? Target,
    string? Arguments,
    string? WorkingDirectory);

internal sealed record AuthoringFile(string ComponentId, string SourceFile);

internal sealed record AuthoringBinary(string Id, string SourceFile);

internal sealed record AuthoringTextStyle(
    string Id,
    string? FaceName,
    string? Size,
    string? StyleBits);

internal sealed record AuthoringSnapshot(
    string SourcePath,
    string SourceSha256,
    IReadOnlyList<AuthoringDialog> Dialogs,
    IReadOnlyList<AuthoringSequenceRow> InstallUiSequence,
    IReadOnlyList<AuthoringExitRoute> InstallUiExitRoutes,
    IReadOnlyList<string> InstallExecuteSequenceActions,
    IReadOnlyDictionary<string, string> Properties,
    IReadOnlyList<AuthoringTextStyle> TextStyles,
    IReadOnlyList<AuthoringShortcut> Shortcuts,
    IReadOnlyList<AuthoringFile> Files,
    IReadOnlyList<AuthoringBinary> Binaries,
    string? MajorUpgradeSchedule,
    bool RollbackActionPreserved,
    bool RollbackSequencePreserved,
    string SettingsSourcePath,
    bool SettingsInteractiveUninstallPreserved);

internal sealed record MsiTableRow(IReadOnlyDictionary<string, string> Fields);

internal sealed record MsiSnapshot(
    string Path,
    string Sha256,
    IReadOnlyDictionary<string, IReadOnlyList<MsiTableRow>> Tables);

internal sealed record MsiTableFixture(
    string Schema,
    string SourceMsiPath,
    string SourceMsiSha256,
    IReadOnlyDictionary<string, IReadOnlyList<MsiTableRow>> Tables);

internal sealed record StagedPayloadFile(string RelativePath, long Size, string Sha256);

internal sealed record StagingSnapshot(
    string Path,
    IReadOnlyList<StagedPayloadFile> Files);

internal sealed record ExtractedMsiPayloadFile(
    string FileId,
    string FileName,
    long Size,
    string Sha256);

internal sealed record MsiPayloadSnapshot(
    string ExtractionMethod,
    string ExtractorPath,
    string ExtractorSha256,
    bool TemporaryDirectoryRemoved,
    IReadOnlyList<ExtractedMsiPayloadFile> Files);

internal sealed record ExpectedPackageIdentity(
    string ProductVersion,
    string ProductCode,
    string UpgradeCode);

internal sealed record PackageClosureSummary(
    IReadOnlyList<string> RequiredPayloads,
    IReadOnlyList<string> ForbiddenPayloads,
    int AuthoringFileCount,
    int StagedFileCount,
    int MsiFileCount,
    int ExtractedMsiPayloadCount,
    bool? StagedPayloadHashesMatch,
    string SipBridgeDeployment,
    bool ExternalSipBridgePayloadRequired);

internal sealed record ScenarioResult(
    string Scenario,
    bool UiSequenceRuns,
    IReadOnlyList<string> SelectedPairs,
    IReadOnlyList<string> DialogRoute);

internal sealed record VerificationReceipt(
    string Schema,
    string CapturedAtUtc,
    bool Success,
    IReadOnlyList<string> Violations,
    AuthoringSnapshot Authoring,
    StagingSnapshot? Staging,
    MsiSnapshot? Msi,
    MsiPayloadSnapshot? ExtractedMsiPayloads,
    ExpectedPackageIdentity? ExpectedIdentity,
    PackageClosureSummary PackageClosure,
    IReadOnlyList<ScenarioResult> AuthoringScenarios,
    IReadOnlyList<ScenarioResult>? MsiScenarios,
    bool ProductIconBindingRequired);
