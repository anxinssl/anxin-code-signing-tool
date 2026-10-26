namespace CodeSigner.InstallerVerifier;

internal static class ContractVerifier
{
    internal const string WizardCondition = "NOT Installed";
    internal const string InstallCondition = "NOT (REMOVE=\"ALL\" AND Installed)";
    internal const string UninstallCondition = "REMOVE=\"ALL\" AND Installed";

    private const int ShellHCentering = 50;
    private const int ShellVCentering = 50;
    private const int ShellWidth = 370;
    private const int ShellHeight = 270;
    private const int FormerShellWidth = 623;
    private const int FormerShellHeight = 450;
    private const int TransparentTextControlAttribute = 65536;
    private const string BlueSidePanelFamily = "blue-side-panel";
    private const string HeaderBodyFooterFamily = "white-header-body-footer";
    private const string DirectoryBrowserFamily = "directory-browser";
    private const string SidePanelBinaryId = "InstallerSidePanel";
    private const string PanelFillBinaryId = "InstallerPanelFill";
    private const string SidePanelSource = "Assets/InstallerSidePanel.bmp";
    private const string PanelFillSource = "Assets/InstallerPanelFill.bmp";
    private const string DefaultFontStyleId = "CodeSigner_Font_Normal";
    private const string DefaultFontFaceName = "Microsoft YaHei UI";
    private const string SipBridgeDeployment = "compiled-worker-command";

    private static readonly Dictionary<string, string> RequiredPayloadByComponent =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["AppComponent"] = "CodeSigner.App.exe",
            ["WorkerComponent"] = "CodeSigner.Worker.exe",
            ["NoticesComponent"] = "THIRD-PARTY-NOTICES.txt",
        };

    private static readonly string[] RequiredPayloads =
        ["CodeSigner.App.exe", "CodeSigner.Worker.exe", "THIRD-PARTY-NOTICES.txt"];

    private static readonly PairContract[] PairContracts =
    [
        new(
            "InstallOrMaintenance",
            "InstallProgressDlg",
            "ExitDialog",
            InstallCondition,
            1298,
            "[ProductName] - 安装、升级或维护",
            "正在安装、升级或维护 [ProductName]",
            "Windows Installer 正在应用安装、升级或维护操作，请稍候...",
            "[ProductName] - 操作完成",
            "操作完成",
            "[ProductName] 的操作已完成。"),
        new(
            "Uninstall",
            "UninstallProgressDlg",
            "ExitDialog",
            UninstallCondition,
            1299,
            "[ProductName] - 卸载",
            "正在卸载 [ProductName]",
            "Windows Installer 正在移除程序文件，请稍候...",
            "[ProductName] - 操作完成",
            "操作完成",
            "[ProductName] 的操作已完成。"),
    ];

    private static readonly OperationScenario[] InteractiveScenarios =
    [
        new("FreshInstall", Installed: false, UpgradeDetected: false, Remove: string.Empty, UiSequenceRuns: true),
        new("MajorUpgrade", Installed: false, UpgradeDetected: true, Remove: string.Empty, UiSequenceRuns: true),
        new("Maintenance", Installed: true, UpgradeDetected: false, Remove: string.Empty, UiSequenceRuns: true),
        new("Uninstall", Installed: true, UpgradeDetected: false, Remove: "ALL", UiSequenceRuns: true),
        new("SilentQn", Installed: false, UpgradeDetected: false, Remove: string.Empty, UiSequenceRuns: false),
    ];

    private static readonly AuthoringControlAttributes DisabledAttributes = new(
        Disabled: true,
        Hidden: false,
        Indirect: false,
        Integer: false,
        RightToLeft: false,
        RightAligned: false,
        LeftScroll: false,
        Sunken: false,
        TabSkip: false,
        Transparent: false,
        Default: false,
        Cancel: false,
        ProgressBlocks: false);

    private static readonly AuthoringControlAttributes EnabledAttributes =
        DisabledAttributes with { Disabled = false };

    private static readonly DialogContract[] DialogContracts = CreateDialogContracts();

    public static IReadOnlyList<string> VerifyAuthoring(AuthoringSnapshot source)
    {
        List<string> failures = [];
        VerifyAuthoringDialogs(source, failures);
        VerifyAuthoringVisualAssets(source, failures);
        VerifyAuthoringProperties(source, failures);
        VerifyAuthoringFontContract(source, failures);
        VerifyAuthoringEvents(source, failures);
        VerifyAuthoringSequence(source, failures);
        VerifyUninstallRoutes(source, failures);
        VerifyAuthoringPackageClosure(source, failures);
        if (source.MajorUpgradeSchedule != "afterInstallInitialize")
        {
            failures.Add($"MajorUpgrade schedule changed: '{source.MajorUpgradeSchedule ?? "<missing>"}'.");
        }
        if (!source.RollbackActionPreserved || !source.RollbackSequencePreserved)
        {
            failures.Add("Controlled rollback authoring was not preserved after InstallFiles.");
        }
        return failures;
    }

    public static IReadOnlyList<string> VerifyStaging(StagingSnapshot staging)
    {
        List<string> failures = [];
        foreach (string required in RequiredPayloads)
        {
            StagedPayloadFile[] matches = staging.Files
                .Where(file => file.RelativePath == required)
                .ToArray();
            if (matches.Length != 1)
            {
                failures.Add(
                    $"Staged package closure requires exactly one root payload '{required}'; observed {matches.Length}.");
            }
            else if (matches[0].Size <= 0)
            {
                failures.Add($"Staged package closure requires non-empty payload '{required}'.");
            }
        }
        foreach (StagedPayloadFile file in staging.Files.Where(file =>
                     !RequiredPayloads.Contains(file.RelativePath, StringComparer.Ordinal)))
        {
            failures.Add($"Staged package closure contains unexpected payload '{file.RelativePath}'.");
        }
        return failures;
    }

    public static IReadOnlyList<string> VerifyPayloadHashes(
        StagingSnapshot staging,
        MsiPayloadSnapshot extractedMsiPayloads)
    {
        List<string> failures = [];
        foreach (string required in RequiredPayloads)
        {
            StagedPayloadFile[] stagedMatches = staging.Files
                .Where(file => file.RelativePath == required)
                .ToArray();
            ExtractedMsiPayloadFile[] extractedMatches = extractedMsiPayloads.Files
                .Where(file => file.FileName == required)
                .ToArray();
            if (stagedMatches.Length != 1 || extractedMatches.Length != 1)
            {
                failures.Add(
                    $"Payload hash closure requires exactly one staged and one extracted MSI '{required}' payload; " +
                    $"observed staged={stagedMatches.Length}, extracted={extractedMatches.Length}.");
                continue;
            }
            StagedPayloadFile staged = stagedMatches[0];
            ExtractedMsiPayloadFile extracted = extractedMatches[0];
            if (staged.Size != extracted.Size ||
                !staged.Sha256.Equals(extracted.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                failures.Add(
                    $"Extracted MSI payload '{required}' must match staged bytes; " +
                    $"staged size/hash={staged.Size}/{staged.Sha256}, " +
                    $"extracted size/hash={extracted.Size}/{extracted.Sha256}.");
            }
        }
        if (!extractedMsiPayloads.TemporaryDirectoryRemoved)
        {
            failures.Add("Static MSI extraction temporary directory cleanup was not verified.");
        }
        return failures;
    }

    public static IReadOnlyList<string> VerifyMsi(
        MsiSnapshot msi,
        ExpectedPackageIdentity? expectedIdentity = null)
    {
        List<string> failures = [];
        VerifyMsiDialogs(msi, failures);
        VerifyMsiVisualAssets(msi, failures);
        VerifyMsiProperties(msi, failures);
        VerifyMsiFontContract(msi, failures);
        VerifyMsiEvents(msi, failures);
        VerifyMsiSequence(msi, failures);
        VerifyMsiShortcut(msi, failures);
        VerifyMsiPackageClosure(msi, expectedIdentity, failures);
        return failures;
    }

    public static PackageClosureSummary SummarizePackageClosure(
        AuthoringSnapshot authoring,
        StagingSnapshot? staging,
        MsiSnapshot? msi,
        MsiPayloadSnapshot? extractedMsiPayloads)
    {
        IEnumerable<string> authoringUnexpected = authoring.Files
            .Where(file => !IsExpectedAuthoringFile(file))
            .Select(file => PayloadName(file.SourceFile));
        IEnumerable<string> stagingUnexpected = staging?.Files
            .Where(file => !RequiredPayloads.Contains(file.RelativePath, StringComparer.Ordinal))
            .Select(file => file.RelativePath) ?? [];
        IReadOnlyList<MsiTableRow> msiFiles = msi is not null &&
            msi.Tables.TryGetValue("File", out IReadOnlyList<MsiTableRow>? rows)
                ? rows
                : [];
        IEnumerable<string> msiUnexpected = msiFiles
            .Where(row => !IsExpectedMsiFile(row))
            .Select(row => LongMsiFileName(row.Fields["FileName"]));
        string[] forbiddenPayloads = authoringUnexpected
            .Concat(stagingUnexpected)
            .Concat(msiUnexpected)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new PackageClosureSummary(
            RequiredPayloads,
            forbiddenPayloads,
            authoring.Files.Count,
            staging?.Files.Count ?? 0,
            msiFiles.Count,
            extractedMsiPayloads?.Files.Count ?? 0,
            staging is null || extractedMsiPayloads is null
                ? null
                : VerifyPayloadHashes(staging, extractedMsiPayloads).Count == 0,
            SipBridgeDeployment,
            ExternalSipBridgePayloadRequired: false);
    }

    public static IReadOnlyList<ScenarioResult> EvaluateAuthoringScenarios(AuthoringSnapshot source) =>
        EvaluateScenarios(
            source.InstallUiSequence
                .Select(row => new SequenceCondition(row.Dialog, row.Condition))
                .ToArray(),
            (dialog, control, eventName, value) => source.Dialogs
                .Where(candidate => candidate.Id == dialog)
                .SelectMany(candidate => candidate.Controls)
                .Where(candidate => candidate.Id == control)
                .SelectMany(candidate => candidate.Publications)
                .Any(publication =>
                    publication.Event == eventName &&
                    publication.Value == value &&
                    EffectiveCondition(publication.Condition) == "1"),
            HasAuthoringExitRoute(source, "ExitDialog", "success"));

    public static IReadOnlyList<ScenarioResult> EvaluateMsiScenarios(MsiSnapshot msi) =>
        EvaluateScenarios(
            msi.Tables["InstallUISequence"]
                .Select(row => new SequenceCondition(
                    row.Fields["Action"],
                    EmptyToNull(row.Fields["Condition"])))
                .ToArray(),
            (dialog, control, eventName, value) => msi.Tables["ControlEvent"].Any(row =>
                row.Fields["Dialog_"] == dialog &&
                row.Fields["Control_"] == control &&
                row.Fields["Event"] == eventName &&
                row.Fields["Argument"] == value &&
                EffectiveCondition(EmptyToNull(row.Fields["Condition"])) == "1"),
            HasMsiExitRoute(msi, "ExitDialog", -1));

    private static DialogContract[] CreateDialogContracts()
    {
        ControlContract[] sidePanelShell =
        [
            BitmapControl("SidePanel", 0, 0, 121, 243, SidePanelBinaryId),
            BitmapControl("BodyPanel", 121, 0, 249, 243, PanelFillBinaryId),
            TextControl("BrandTitle", 14, 16, 61, 22, "[ProductName]", hidden: true, transparent: false),
            LineControl("HeaderSeparator", 121, 44, 249, 1, hidden: true),
            LineControl("FooterSeparator", 0, 243, 370, 1),
        ];
        ControlContract[] headerShell =
        [
            BitmapControl("HeaderPanel", 0, 0, 370, 44, PanelFillBinaryId),
            TextControl("BrandTitle", 14, 16, 61, 22, "[ProductName]", hidden: true, transparent: false),
            LineControl("HeaderSeparator", 0, 44, 370, 1),
            LineControl("FooterSeparator", 0, 243, 370, 1),
        ];

        List<DialogContract> contracts =
        [
            new(
                "WelcomeDlg",
                BlueSidePanelFamily,
                "[ProductName] - 安装",
                Modeless: false,
                DefaultControl: "NextButton",
                CancelControl: "CancelButton",
                [
                    .. sidePanelShell,
                    TextControl("Title", 135, 14, 220, 18, "欢迎使用 [ProductName] 安装向导"),
                    TextControl("IntroText", 135, 56, 220, 12, "此向导将引导您完成 [ProductName] 的安装。"),
                    TextControl("CloseAppsText", 135, 72, 220, 12, "在安装之前，请先关闭其他所有应用程序。"),
                    TextControl("UpdateFilesText", 135, 84, 220, 12, "这将确保安装程序能够更新所需的系统文件，"),
                    TextControl("RestartText", 135, 96, 220, 12, "从而避免在安装后重新启动计算机。"),
                    TextControl("NextHint", 135, 116, 220, 12, "单击“下一步”继续。"),
                    ButtonControl("NextButton", 236, 250, 56, 17, "下一步(&N) >", isDefault: true),
                    ButtonControl("CancelButton", 304, 250, 56, 17, "取消(&C)", isCancel: true),
                ]),
            new(
                "InstallDirectoryDlg",
                HeaderBodyFooterFamily,
                "[ProductName] - 安装位置",
                Modeless: false,
                DefaultControl: "InstallButton",
                CancelControl: "CancelButton",
                [
                    .. headerShell,
                    TextControl("Title", 12, 7, 250, 14, "选择安装位置"),
                    TextControl("Description", 18, 25, 330, 14, "选择 [ProductName] 的安装目录。"),
                    TextControl("PathLabel", 28, 132, 334, 12, "安装目录："),
                    InputControl("InstallPath", "PathEdit", 28, 154, 246, 18, "WIXUI_INSTALLDIR", indirect: true),
                    ButtonControl("BrowseButton", 282, 154, 70, 18, "浏览..."),
                    ButtonControl("BackButton", 180, 250, 56, 17, "上一步"),
                    ButtonControl("InstallButton", 236, 250, 56, 17, "安装", isDefault: true),
                    ButtonControl("CancelButton", 304, 250, 56, 17, "取消", isCancel: true),
                ]),
            new(
                "BrowseDlg",
                DirectoryBrowserFamily,
                "[ProductName] - 浏览安装目录",
                Modeless: false,
                DefaultControl: "OkButton",
                CancelControl: "CancelButton",
                [
                    .. headerShell,
                    TextControl("Title", 12, 7, 250, 14, "浏览安装目录"),
                    TextControl("Description", 18, 25, 330, 14, "选择 [ProductName] 的安装目录。"),
                    InputControl("DirectoryCombo", "DirectoryCombo", 18, 54, 334, 12, "_BrowseProperty", indirect: true),
                    InputControl("DirectoryList", "DirectoryList", 18, 72, 334, 130, "_BrowseProperty", indirect: true),
                    InputControl("PathEdit", "PathEdit", 18, 210, 334, 18, "_BrowseProperty", indirect: true),
                    ButtonControl("OkButton", 236, 250, 56, 17, "确定", isDefault: true),
                    ButtonControl("CancelButton", 304, 250, 56, 17, "取消", isCancel: true),
                ]),
        ];

        foreach (PairContract pair in PairContracts)
        {
            List<ControlContract> progressControls =
            [
                .. headerShell,
                TextControl("Title", 12, 7, 340, 14, pair.ProgressTitle),
                TextControl("Status", 18, 25, 334, 14, pair.ProgressStatus),
            ];
            if (pair.Name == "InstallOrMaintenance")
            {
                progressControls.Add(TextControl("TargetLabel", 18, 72, 334, 12, "安装目录："));
                progressControls.Add(TextControl("TargetPath", 18, 86, 334, 14, "[INSTALLFOLDER]"));
            }
            int progressY = pair.Name == "InstallOrMaintenance" ? 110 : 72;
            progressControls.Add(ProgressControl("ProgressBar", 18, progressY, 334, 13));
            progressControls.Add(ButtonControl("BackButton", 180, 250, 56, 17, "上一步", disabled: true));
            progressControls.Add(ButtonControl("NextButton", 236, 250, 56, 17, "下一步", disabled: true));
            progressControls.Add(ButtonControl("CancelButton", 304, 250, 56, 17, "取消", disabled: true));
            contracts.Add(new DialogContract(
                pair.ProgressDialog,
                HeaderBodyFooterFamily,
                pair.ProgressWindowTitle,
                Modeless: true,
                DefaultControl: null,
                CancelControl: null,
                progressControls));
            if (contracts.All(contract => contract.Id != pair.CompletedDialog))
            {
                contracts.Add(new DialogContract(
                    pair.CompletedDialog,
                    BlueSidePanelFamily,
                    pair.CompletedWindowTitle,
                    Modeless: false,
                    DefaultControl: "CloseButton",
                    CancelControl: "CloseButton",
                    [
                        .. sidePanelShell,
                        TextControl("Title", 135, 14, 220, 18, pair.CompletedTitle),
                        TextControl("Description", 135, 64, 220, 28, pair.CompletedText),
                        ButtonControl("CloseButton", 304, 250, 56, 17, "关闭", isDefault: true, isCancel: true),
                    ]));
            }
        }
        return [.. contracts];
    }

    private static ControlContract BitmapControl(
        string id,
        int x,
        int y,
        int width,
        int height,
        string binaryId) =>
        new(id, "Bitmap", new Rect(x, y, width, height), null, binaryId, EnabledAttributes, 1);

    private static ControlContract TextControl(
        string id,
        int x,
        int y,
        int width,
        int height,
        string text,
        bool hidden = false,
        bool transparent = true) =>
        new(
            id,
            "Text",
            new Rect(x, y, width, height),
            null,
            text,
            hidden
                ? DisabledAttributes with { Hidden = true, Transparent = transparent }
                : EnabledAttributes with { Transparent = transparent },
            (hidden ? 0 : 3) + (transparent ? TransparentTextControlAttribute : 0));

    private static ControlContract LineControl(
        string id,
        int x,
        int y,
        int width,
        int height,
        bool hidden = false) =>
        new(
            id,
            "Line",
            new Rect(x, y, width, height),
            null,
            null,
            hidden ? DisabledAttributes with { Hidden = true } : EnabledAttributes,
            hidden ? 0 : 1);

    private static ControlContract ButtonControl(
        string id,
        int x,
        int y,
        int width,
        int height,
        string text,
        bool disabled = false,
        bool isDefault = false,
        bool isCancel = false) =>
        new(
            id,
            "PushButton",
            new Rect(x, y, width, height),
            null,
            text,
            new AuthoringControlAttributes(
                disabled,
                Hidden: false,
                Indirect: false,
                Integer: false,
                RightToLeft: false,
                RightAligned: false,
                LeftScroll: false,
                Sunken: false,
                TabSkip: false,
                Transparent: false,
                Default: isDefault,
                Cancel: isCancel,
                ProgressBlocks: false),
            disabled ? 1 : 3);

    private static ControlContract InputControl(
        string id,
        string type,
        int x,
        int y,
        int width,
        int height,
        string property,
        bool indirect) =>
        new(
            id,
            type,
            new Rect(x, y, width, height),
            property,
            null,
            new AuthoringControlAttributes(
                Disabled: false,
                Hidden: false,
                Indirect: indirect,
                Integer: false,
                RightToLeft: false,
                RightAligned: false,
                LeftScroll: false,
                Sunken: false,
                TabSkip: false,
                Transparent: false,
                Default: false,
                Cancel: false,
                ProgressBlocks: false),
            indirect ? 11 : 3);

    private static ControlContract ProgressControl(
        string id,
        int x,
        int y,
        int width,
        int height) =>
        new(
            id,
            "ProgressBar",
            new Rect(x, y, width, height),
            null,
            null,
            new AuthoringControlAttributes(
                Disabled: false,
                Hidden: false,
                Indirect: false,
                Integer: false,
                RightToLeft: false,
                RightAligned: false,
                LeftScroll: false,
                Sunken: false,
                TabSkip: false,
                Transparent: false,
                Default: false,
                Cancel: false,
                ProgressBlocks: true),
            65537);

    private static void VerifyAuthoringDialogs(AuthoringSnapshot source, List<string> failures)
    {
        foreach (DialogContract contract in DialogContracts)
        {
            AuthoringDialog? dialog = SingleDialog(source.Dialogs, contract.Id, failures);
            if (dialog is null)
            {
                continue;
            }
            VerifyAuthoringDialog(dialog, contract, failures);
        }

        foreach (AuthoringDialog dialog in source.Dialogs.Where(dialog =>
                     dialog.Id.StartsWith("Uninstall", StringComparison.Ordinal)))
        {
            IEnumerable<string> visibleText = dialog.Controls
                .Select(control => control.Text)
                .OfType<string>()
                .Append(dialog.Title ?? string.Empty);
            if (visibleText.Any(text => text.Contains("安装", StringComparison.Ordinal)))
            {
                failures.Add($"{dialog.Id} contains installation wording in uninstall UI.");
            }
        }
    }

    private static void VerifyAuthoringDialog(
        AuthoringDialog dialog,
        DialogContract contract,
        List<string> failures)
    {
        if (dialog.HCentering != ShellHCentering ||
            dialog.VCentering != ShellVCentering ||
            dialog.Width != ShellWidth ||
            dialog.Height != ShellHeight)
        {
            if (dialog.Width == FormerShellWidth && dialog.Height == FormerShellHeight)
            {
                failures.Add(
                    $"{dialog.Id} uses the former {FormerShellWidth}x{FormerShellHeight} DLU shell; " +
                    $"reference family '{contract.Family}' requires " +
                    $"HCentering={ShellHCentering},VCentering={ShellVCentering}," +
                    $"Width={ShellWidth},Height={ShellHeight}.");
            }
            else
            {
                failures.Add(
                    $"{dialog.Id} reference family '{contract.Family}' geometry mismatch; " +
                    $"expected HCentering={ShellHCentering},VCentering={ShellVCentering}," +
                    $"Width={ShellWidth},Height={ShellHeight}; " +
                    $"observed HCentering={dialog.HCentering},VCentering={dialog.VCentering}," +
                    $"Width={dialog.Width},Height={dialog.Height}.");
            }
        }
        RequireEqual(dialog.Title, contract.Title, $"{dialog.Id} window title", failures);
        AuthoringDialogAttributes expectedAttributes = new(
            contract.Modeless,
            NoMinimize: true,
            KeepModeless: false,
            TrackDiskSpace: false,
            RightToLeft: false,
            RightAligned: false,
            LeftScroll: false,
            ErrorDialog: false);
        if (dialog.Attributes != expectedAttributes)
        {
            failures.Add($"{dialog.Id} dialog attributes mismatch.");
        }

        string[] expectedIds = contract.Controls.Select(control => control.Id).Order().ToArray();
        string[] observedIds = dialog.Controls.Select(control => control.Id).Order().ToArray();
        if (!expectedIds.SequenceEqual(observedIds, StringComparer.Ordinal))
        {
            failures.Add(
                $"{dialog.Id} control set mismatch; expected '{string.Join(",", expectedIds)}'; " +
                $"observed '{string.Join(",", observedIds)}'.");
        }
        foreach (ControlContract controlContract in contract.Controls)
        {
            VerifyAuthoringControl(dialog, contract.Family, controlContract, failures);
        }
    }

    private static void VerifyAuthoringControl(
        AuthoringDialog dialog,
        string family,
        ControlContract contract,
        List<string> failures)
    {
        AuthoringControl[] matches = dialog.Controls.Where(control => control.Id == contract.Id).ToArray();
        if (matches.Length != 1)
        {
            failures.Add($"{dialog.Id} must contain exactly one {contract.Id} control.");
            return;
        }
        AuthoringControl control = matches[0];
        RequireEqual(control.Type, contract.Type, $"{dialog.Id}.{contract.Id} type", failures);
        RequireEqual(control.Property, contract.Property, $"{dialog.Id}.{contract.Id} property", failures);
        RequireEqual(control.Text, contract.Text, $"{dialog.Id}.{contract.Id} text", failures);
        if (control.X != contract.Geometry.X ||
            control.Y != contract.Geometry.Y ||
            control.Width != contract.Geometry.Width ||
            control.Height != contract.Geometry.Height)
        {
            failures.Add(
                $"{dialog.Id}.{contract.Id} reference family '{family}' geometry mismatch; " +
                $"expected X={contract.Geometry.X}," +
                $"Y={contract.Geometry.Y},Width={contract.Geometry.Width},Height={contract.Geometry.Height}; " +
                $"observed X={control.X},Y={control.Y},Width={control.Width},Height={control.Height}.");
        }
        if (control.Attributes != contract.Attributes)
        {
            failures.Add($"{dialog.Id}.{contract.Id} control attributes mismatch.");
        }
    }

    private static void VerifyAuthoringProperties(AuthoringSnapshot source, List<string> failures)
    {
        if (!source.Properties.TryGetValue("WIXUI_INSTALLDIR", out string? value) || value != "INSTALLFOLDER")
        {
            failures.Add("Property WIXUI_INSTALLDIR must be 'INSTALLFOLDER'.");
        }
    }

    private static void VerifyAuthoringFontContract(AuthoringSnapshot source, List<string> failures)
    {
        AuthoringTextStyle[] styles = source.TextStyles
            .Where(style => style.Id == DefaultFontStyleId)
            .ToArray();
        if (styles.Length != 1)
        {
            failures.Add(
                $"Authoring font contract requires exactly one TextStyle {DefaultFontStyleId} row; " +
                $"observed {styles.Length}.");
        }
        else
        {
            AuthoringTextStyle style = styles[0];
            RequireEqual(
                style.FaceName,
                DefaultFontFaceName,
                $"Authoring TextStyle {DefaultFontStyleId} exact-case FaceName",
                failures);
            RequireEqual(style.Size, "9", $"Authoring TextStyle {DefaultFontStyleId} Size", failures);
            RequireEqual(style.StyleBits, "0", $"Authoring TextStyle {DefaultFontStyleId} StyleBits", failures);
        }

        VerifyDefaultUiFontProperty(
            source.Properties.TryGetValue("DefaultUIFont", out string? value) ? value : null,
            source.TextStyles.Select(style => style.Id),
            "Authoring",
            failures);
    }

    private static void VerifyAuthoringVisualAssets(
        AuthoringSnapshot source,
        List<string> failures)
    {
        RequireBinary(SidePanelBinaryId, SidePanelSource);
        RequireBinary(PanelFillBinaryId, PanelFillSource);

        void RequireBinary(string id, string sourceFile)
        {
            AuthoringBinary[] matches = source.Binaries
                .Where(binary => binary.Id == id && binary.SourceFile == sourceFile)
                .ToArray();
            if (matches.Length != 1)
            {
                failures.Add(
                    $"Authoring visual asset {id} must bind '{sourceFile}' exactly once; " +
                    $"observed {matches.Length} matching Binary rows.");
            }
        }
    }

    private static void VerifyAuthoringEvents(AuthoringSnapshot source, List<string> failures)
    {
        RequireAuthoringPublication(source, "WelcomeDlg", "NextButton", "NewDialog", null,
            "InstallDirectoryDlg", "1", 1,
            "WelcomeDlg.NextButton navigation mismatch");
        RequireAuthoringPublication(source, "WelcomeDlg", "CancelButton", "EndDialog", null,
            "Exit", "1", 1,
            "WelcomeDlg.CancelButton cancel navigation mismatch");
        RequireAuthoringPublication(source, "InstallDirectoryDlg", "BackButton", "NewDialog", null,
            "WelcomeDlg", "1", 1,
            "InstallDirectoryDlg.BackButton navigation mismatch");
        RequireAuthoringPublication(source, "InstallDirectoryDlg", "BrowseButton", null, "_BrowseProperty",
            "[WIXUI_INSTALLDIR]", "1", 1,
            "InstallDirectoryDlg.BrowseButton browse navigation mismatch");
        RequireAuthoringPublication(source, "InstallDirectoryDlg", "BrowseButton", "SpawnDialog", null,
            "BrowseDlg", "1", 2,
            "InstallDirectoryDlg.BrowseButton browse navigation mismatch");
        RequireAuthoringPublication(source, "InstallDirectoryDlg", "InstallButton", "SetTargetPath", null,
            "[WIXUI_INSTALLDIR]", "1", 1,
            "InstallDirectoryDlg.InstallButton must publish SetTargetPath/[WIXUI_INSTALLDIR] exactly once");
        RequireAuthoringPublication(source, "InstallDirectoryDlg", "InstallButton", "EndDialog", null,
            "Return", "1", 2,
            "InstallDirectoryDlg.InstallButton install navigation mismatch");
        RequireAuthoringPublication(source, "InstallDirectoryDlg", "CancelButton", "EndDialog", null,
            "Exit", "1", 1,
            "InstallDirectoryDlg.CancelButton cancel navigation mismatch");
        RequireAuthoringPublication(source, "BrowseDlg", "OkButton", "SetTargetPath", null,
            "[_BrowseProperty]", "1", 1,
            "BrowseDlg.OkButton must publish SetTargetPath/[_BrowseProperty] exactly once");
        RequireAuthoringPublication(source, "BrowseDlg", "OkButton", "EndDialog", null,
            "Return", "1", 2,
            "BrowseDlg.OkButton navigation mismatch");
        RequireAuthoringPublication(source, "BrowseDlg", "CancelButton", "EndDialog", null,
            "Return", "1", 1,
            "BrowseDlg.CancelButton navigation mismatch");

        HashSet<string> completedDialogs = new(StringComparer.Ordinal);
        foreach (PairContract pair in PairContracts)
        {
            RequireAuthoringSubscription(source, pair.ProgressDialog, "ProgressBar", failures);
            if (completedDialogs.Add(pair.CompletedDialog))
            {
                RequireAuthoringPublication(source, pair.CompletedDialog, "CloseButton", "EndDialog", null,
                    "Return", "1", 1,
                    $"{pair.CompletedDialog}.CloseButton must publish EndDialog/Return exactly once");
            }
        }

        void RequireAuthoringPublication(
            AuthoringSnapshot snapshot,
            string dialog,
            string control,
            string? eventName,
            string? property,
            string value,
            string condition,
            int order,
            string violation)
        {
            Publication[] matches = snapshot.Dialogs
                .Where(candidate => candidate.Id == dialog)
                .SelectMany(candidate => candidate.Controls)
                .Where(candidate => candidate.Id == control)
                .SelectMany(candidate => candidate.Publications)
                .Where(publication =>
                    publication.Event == eventName &&
                    publication.Property == property &&
                    publication.Value == value &&
                    EffectiveCondition(publication.Condition) == condition &&
                    publication.Order == order)
                .ToArray();
            if (matches.Length != 1)
            {
                failures.Add($"{violation}; observed {matches.Length} matching publications.");
            }
        }
    }

    private static void RequireAuthoringSubscription(
        AuthoringSnapshot source,
        string dialog,
        string control,
        List<string> failures)
    {
        Subscription[] subscriptions = source.Dialogs
            .Where(candidate => candidate.Id == dialog)
            .SelectMany(candidate => candidate.Controls)
            .Where(candidate => candidate.Id == control)
            .SelectMany(candidate => candidate.Subscriptions)
            .Where(subscription => subscription.Event == "SetProgress" && subscription.Attribute == "Progress")
            .ToArray();
        if (subscriptions.Length != 1)
        {
            failures.Add($"{dialog}.{control} must subscribe exactly once to SetProgress/Progress.");
        }
    }

    private static void VerifyAuthoringSequence(AuthoringSnapshot source, List<string> failures)
    {
        VerifySequenceRows(
            source.InstallUiSequence
                .Select(row => new SequenceRow(row.Dialog, row.Condition, row.Sequence))
                .ToArray(),
            failures,
            "authoring");
        VerifyAuthoringExitRoutes(source, failures);
        VerifyScenarioSelections(EvaluateAuthoringScenarios(source), failures, "Authoring");
        HashSet<string> dialogActions = DialogContracts
            .Select(dialog => dialog.Id)
            .ToHashSet(StringComparer.Ordinal);
        if (source.InstallExecuteSequenceActions.Any(dialogActions.Contains))
        {
            failures.Add(
                "Authoring SilentQn route violation: custom dialog actions must not appear in InstallExecuteSequence.");
        }
    }

    private static void VerifyUninstallRoutes(AuthoringSnapshot source, List<string> failures)
    {
        AuthoringShortcut[] shortcuts = source.Shortcuts
            .Where(shortcut => shortcut.Id == "AppShortcutUninstall")
            .ToArray();
        string? arguments = shortcuts.SingleOrDefault()?.Arguments;
        if (shortcuts.Length != 1 ||
            shortcuts[0].Target != "[System64Folder]msiexec.exe" ||
            arguments != "/x [ProductCode]" ||
            arguments.Contains("/qn", StringComparison.OrdinalIgnoreCase))
        {
            failures.Add("Start-menu uninstall shortcut must remain interactive msiexec /x [ProductCode].");
        }
        if (!source.SettingsInteractiveUninstallPreserved)
        {
            failures.Add("Settings uninstall route must remain interactive msiexec /x InstalledProductCode.");
        }
        foreach (string id in new[] { "AppShortcut", "DesktopAppShortcut" })
        {
            AuthoringShortcut[] launchShortcuts = source.Shortcuts
                .Where(shortcut => shortcut.Id == id)
                .ToArray();
            if (launchShortcuts.Length != 1 ||
                launchShortcuts[0].Target != "[INSTALLFOLDER]CodeSigner.App.exe" ||
                launchShortcuts[0].WorkingDirectory != "INSTALLFOLDER")
            {
                failures.Add($"{id} must launch [INSTALLFOLDER]CodeSigner.App.exe from INSTALLFOLDER.");
            }
        }
    }

    private static void VerifyAuthoringPackageClosure(
        AuthoringSnapshot source,
        List<string> failures)
    {
        foreach ((string componentId, string fileName) in RequiredPayloadByComponent)
        {
            string expectedSource = $"../../artifacts/staging/{fileName}";
            AuthoringFile[] matches = source.Files
                .Where(file =>
                    file.ComponentId == componentId &&
                    NormalizeAuthoringSource(file.SourceFile) == expectedSource)
                .ToArray();
            if (matches.Length != 1)
            {
                failures.Add(
                    $"Authoring package closure requires exactly one {componentId} payload '{expectedSource}'; " +
                    $"observed {matches.Length}.");
            }
        }
        foreach (AuthoringFile file in source.Files.Where(file => !IsExpectedAuthoringFile(file)))
        {
            failures.Add(
                $"Authoring package closure contains unexpected payload '{PayloadName(file.SourceFile)}'.");
        }
    }

    private static void VerifyMsiDialogs(MsiSnapshot msi, List<string> failures)
    {
        IReadOnlyList<MsiTableRow> dialogs = msi.Tables["Dialog"];
        IReadOnlyList<MsiTableRow> controls = msi.Tables["Control"];
        foreach (DialogContract contract in DialogContracts)
        {
            MsiTableRow[] dialogMatches = dialogs
                .Where(row => row.Fields["Dialog"] == contract.Id)
                .ToArray();
            if (dialogMatches.Length != 1)
            {
                failures.Add($"Expected exactly one MSI Dialog {contract.Id}; observed {dialogMatches.Length}.");
                continue;
            }
            MsiTableRow dialog = dialogMatches[0];
            if (dialog.Fields["HCentering"] != ShellHCentering.ToString(System.Globalization.CultureInfo.InvariantCulture) ||
                dialog.Fields["VCentering"] != ShellVCentering.ToString(System.Globalization.CultureInfo.InvariantCulture) ||
                dialog.Fields["Width"] != ShellWidth.ToString(System.Globalization.CultureInfo.InvariantCulture) ||
                dialog.Fields["Height"] != ShellHeight.ToString(System.Globalization.CultureInfo.InvariantCulture))
            {
                if (dialog.Fields["Width"] == FormerShellWidth.ToString(System.Globalization.CultureInfo.InvariantCulture) &&
                    dialog.Fields["Height"] == FormerShellHeight.ToString(System.Globalization.CultureInfo.InvariantCulture))
                {
                    failures.Add(
                        $"MSI {contract.Id} uses the former {FormerShellWidth}x{FormerShellHeight} DLU shell; " +
                        $"reference family '{contract.Family}' requires Width={ShellWidth},Height={ShellHeight}.");
                }
                else
                {
                    failures.Add($"MSI {contract.Id} reference family '{contract.Family}' geometry mismatch.");
                }
            }
            RequireEqual(dialog.Fields["Title"], contract.Title, $"MSI {contract.Id} window title", failures);
            RequireEqual(
                dialog.Fields["Attributes"],
                contract.Modeless ? "1" : "3",
                $"MSI {contract.Id} dialog attributes",
                failures);
            RequireEqual(
                EmptyToNull(dialog.Fields["Control_Default"]),
                contract.DefaultControl,
                $"MSI {contract.Id} default control",
                failures);
            RequireEqual(
                EmptyToNull(dialog.Fields["Control_Cancel"]),
                contract.CancelControl,
                $"MSI {contract.Id} cancel control",
                failures);

            MsiTableRow[] dialogControls = controls
                .Where(row => row.Fields["Dialog_"] == contract.Id)
                .ToArray();
            string[] expectedIds = contract.Controls.Select(control => control.Id).Order().ToArray();
            string[] observedIds = dialogControls.Select(row => row.Fields["Control"]).Order().ToArray();
            if (!expectedIds.SequenceEqual(observedIds, StringComparer.Ordinal))
            {
                failures.Add($"MSI {contract.Id} control set mismatch.");
            }
            foreach (ControlContract controlContract in contract.Controls)
            {
                VerifyMsiControl(dialogControls, contract.Id, contract.Family, controlContract, failures);
            }
        }

        foreach (MsiTableRow control in controls.Where(row =>
                     row.Fields["Dialog_"].StartsWith("Uninstall", StringComparison.Ordinal)))
        {
            if (control.Fields["Text"].Contains("安装", StringComparison.Ordinal))
            {
                failures.Add($"MSI {control.Fields["Dialog_"]}.{control.Fields["Control"]} contains installation wording.");
            }
        }
    }

    private static void VerifyMsiControl(
        IReadOnlyList<MsiTableRow> controls,
        string dialog,
        string family,
        ControlContract contract,
        List<string> failures)
    {
        MsiTableRow[] matches = controls.Where(row => row.Fields["Control"] == contract.Id).ToArray();
        if (matches.Length != 1)
        {
            failures.Add($"MSI {dialog} must contain exactly one {contract.Id} control.");
            return;
        }
        MsiTableRow control = matches[0];
        RequireEqual(control.Fields["Type"], contract.Type, $"MSI {dialog}.{contract.Id} type", failures);
        RequireEqual(
            EmptyToNull(control.Fields["Property"]),
            contract.Property,
            $"MSI {dialog}.{contract.Id} property",
            failures);
        RequireEqual(
            EmptyToNull(control.Fields["Text"]),
            contract.Text,
            $"MSI {dialog}.{contract.Id} text",
            failures);
        if (control.Fields["X"] != contract.Geometry.X.ToString(System.Globalization.CultureInfo.InvariantCulture) ||
            control.Fields["Y"] != contract.Geometry.Y.ToString(System.Globalization.CultureInfo.InvariantCulture) ||
            control.Fields["Width"] != contract.Geometry.Width.ToString(System.Globalization.CultureInfo.InvariantCulture) ||
            control.Fields["Height"] != contract.Geometry.Height.ToString(System.Globalization.CultureInfo.InvariantCulture))
        {
            failures.Add(
                $"MSI {dialog}.{contract.Id} reference family '{family}' geometry mismatch.");
        }
        RequireEqual(
            control.Fields["Attributes"],
            contract.MsiAttributes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            $"MSI {dialog}.{contract.Id} control attributes",
            failures);
    }

    private static void VerifyMsiProperties(MsiSnapshot msi, List<string> failures)
    {
        MsiTableRow[] rows = msi.Tables["Property"]
            .Where(row => row.Fields["Property"] == "WIXUI_INSTALLDIR")
            .ToArray();
        if (rows.Length != 1 || rows[0].Fields["Value"] != "INSTALLFOLDER")
        {
            failures.Add("MSI Property WIXUI_INSTALLDIR must be 'INSTALLFOLDER'.");
        }
    }

    private static void VerifyMsiFontContract(MsiSnapshot msi, List<string> failures)
    {
        IReadOnlyList<MsiTableRow> textStyleRows;
        if (!msi.Tables.TryGetValue("TextStyle", out textStyleRows!))
        {
            failures.Add("MSI TextStyle table is absent.");
            textStyleRows = [];
        }

        MsiTableRow[] styles = textStyleRows
            .Where(row => row.Fields["TextStyle"] == DefaultFontStyleId)
            .ToArray();
        if (styles.Length != 1)
        {
            failures.Add(
                $"MSI font contract requires exactly one TextStyle {DefaultFontStyleId} row; " +
                $"observed {styles.Length}.");
        }
        else
        {
            MsiTableRow style = styles[0];
            RequireEqual(
                style.Fields["FaceName"],
                DefaultFontFaceName,
                $"MSI TextStyle {DefaultFontStyleId} exact-case FaceName",
                failures);
            RequireEqual(style.Fields["Size"], "9", $"MSI TextStyle {DefaultFontStyleId} Size", failures);
            RequireEqual(
                style.Fields["StyleBits"],
                "0",
                $"MSI TextStyle {DefaultFontStyleId} StyleBits",
                failures);
        }

        MsiTableRow[] properties = msi.Tables["Property"]
            .Where(row => row.Fields["Property"] == "DefaultUIFont")
            .ToArray();
        if (properties.Length == 0)
        {
            VerifyDefaultUiFontProperty(null, textStyleRows.Select(row => row.Fields["TextStyle"]), "MSI", failures);
        }
        else if (properties.Length != 1)
        {
            failures.Add($"MSI Property DefaultUIFont must appear exactly once; observed {properties.Length} rows.");
        }
        else
        {
            VerifyDefaultUiFontProperty(
                properties[0].Fields["Value"],
                textStyleRows.Select(row => row.Fields["TextStyle"]),
                "MSI",
                failures);
        }
    }

    private static void VerifyDefaultUiFontProperty(
        string? value,
        IEnumerable<string> styleIds,
        string source,
        List<string> failures)
    {
        if (value is null)
        {
            failures.Add($"{source} Property DefaultUIFont is missing.");
            return;
        }
        if (!styleIds.Contains(value, StringComparer.Ordinal))
        {
            failures.Add($"{source} Property DefaultUIFont references missing TextStyle '{value}'.");
            return;
        }
        if (value != DefaultFontStyleId)
        {
            failures.Add(
                $"{source} Property DefaultUIFont must be '{DefaultFontStyleId}'; observed '{value}'.");
        }
    }

    private static void VerifyMsiVisualAssets(MsiSnapshot msi, List<string> failures)
    {
        IReadOnlyList<MsiTableRow> binaries = msi.Tables["Binary"];
        foreach (string id in new[] { SidePanelBinaryId, PanelFillBinaryId })
        {
            int count = binaries.Count(row => row.Fields["Name"] == id);
            if (count != 1)
            {
                failures.Add($"MSI Binary table must contain {id} exactly once; observed {count} rows.");
            }
        }
    }

    private static void VerifyMsiEvents(MsiSnapshot msi, List<string> failures)
    {
        IReadOnlyList<MsiTableRow> events = msi.Tables["ControlEvent"];
        RequireMsiEvent(events, "WelcomeDlg", "NextButton", "NewDialog", "InstallDirectoryDlg", "1", 1,
            "MSI WelcomeDlg.NextButton navigation mismatch", failures);
        RequireMsiEvent(events, "WelcomeDlg", "CancelButton", "EndDialog", "Exit", "1", 1,
            "MSI WelcomeDlg.CancelButton cancel navigation mismatch", failures);
        RequireMsiEvent(events, "InstallDirectoryDlg", "BackButton", "NewDialog", "WelcomeDlg", "1", 1,
            "MSI InstallDirectoryDlg.BackButton navigation mismatch", failures);
        RequireMsiEvent(events, "InstallDirectoryDlg", "BrowseButton", "[_BrowseProperty]", "[WIXUI_INSTALLDIR]", "1", 1,
            "MSI InstallDirectoryDlg.BrowseButton browse navigation mismatch", failures);
        RequireMsiEvent(events, "InstallDirectoryDlg", "BrowseButton", "SpawnDialog", "BrowseDlg", "1", 2,
            "MSI InstallDirectoryDlg.BrowseButton browse navigation mismatch", failures);
        RequireMsiEvent(events, "InstallDirectoryDlg", "InstallButton", "SetTargetPath", "[WIXUI_INSTALLDIR]", "1", 1,
            "MSI InstallDirectoryDlg.InstallButton must publish SetTargetPath/[WIXUI_INSTALLDIR] exactly once", failures);
        RequireMsiEvent(events, "InstallDirectoryDlg", "InstallButton", "EndDialog", "Return", "1", 2,
            "MSI InstallDirectoryDlg.InstallButton install navigation mismatch", failures);
        RequireMsiEvent(events, "InstallDirectoryDlg", "CancelButton", "EndDialog", "Exit", "1", 1,
            "MSI InstallDirectoryDlg.CancelButton cancel navigation mismatch", failures);
        RequireMsiEvent(events, "BrowseDlg", "OkButton", "SetTargetPath", "[_BrowseProperty]", "1", 1,
            "MSI BrowseDlg.OkButton must publish SetTargetPath/[_BrowseProperty] exactly once", failures);
        RequireMsiEvent(events, "BrowseDlg", "OkButton", "EndDialog", "Return", "1", 2,
            "MSI BrowseDlg.OkButton navigation mismatch", failures);
        RequireMsiEvent(events, "BrowseDlg", "CancelButton", "EndDialog", "Return", "1", 1,
            "MSI BrowseDlg.CancelButton navigation mismatch", failures);

        IReadOnlyList<MsiTableRow> mappings = msi.Tables["EventMapping"];
        HashSet<string> completedDialogs = new(StringComparer.Ordinal);
        foreach (PairContract pair in PairContracts)
        {
            if (mappings.Count(row =>
                    row.Fields["Dialog_"] == pair.ProgressDialog &&
                    row.Fields["Control_"] == "ProgressBar" &&
                    row.Fields["Event"] == "SetProgress" &&
                    row.Fields["Attribute"] == "Progress") != 1)
            {
                failures.Add($"MSI {pair.ProgressDialog}.ProgressBar lacks one SetProgress/Progress EventMapping row.");
            }
            if (completedDialogs.Add(pair.CompletedDialog))
            {
                RequireMsiEvent(events, pair.CompletedDialog, "CloseButton", "EndDialog", "Return", "1", 1,
                    $"MSI {pair.CompletedDialog}.CloseButton lacks one EndDialog/Return ControlEvent row", failures);
            }
        }
    }

    private static void RequireMsiEvent(
        IReadOnlyList<MsiTableRow> rows,
        string dialog,
        string control,
        string eventName,
        string argument,
        string condition,
        int ordering,
        string violation,
        List<string> failures)
    {
        int count = rows.Count(row =>
            row.Fields["Dialog_"] == dialog &&
            row.Fields["Control_"] == control &&
            row.Fields["Event"] == eventName &&
            row.Fields["Argument"] == argument &&
            EffectiveCondition(EmptyToNull(row.Fields["Condition"])) == condition &&
            row.Fields["Ordering"] == ordering.ToString(System.Globalization.CultureInfo.InvariantCulture));
        if (count != 1)
        {
            failures.Add($"{violation}; observed {count} matching ControlEvent rows.");
        }
    }

    private static void VerifyMsiSequence(MsiSnapshot msi, List<string> failures)
    {
        SequenceRow[] uiRows = msi.Tables["InstallUISequence"]
            .Select(row => new SequenceRow(
                row.Fields["Action"],
                EmptyToNull(row.Fields["Condition"]),
                int.Parse(row.Fields["Sequence"], System.Globalization.CultureInfo.InvariantCulture)))
            .ToArray();
        VerifySequenceRows(uiRows, failures, "MSI");
        VerifyMsiExitRoutes(uiRows, failures);
        VerifyScenarioSelections(EvaluateMsiScenarios(msi), failures, "MSI");

        SequenceRow[] executeActions = uiRows.Where(row => row.Action == "ExecuteAction").ToArray();
        if (executeActions.Length != 1)
        {
            failures.Add($"MSI InstallUISequence must contain exactly one ExecuteAction; observed {executeActions.Length}.");
        }
        else
        {
            SequenceRow executeAction = executeActions[0];
            foreach (PairContract pair in PairContracts)
            {
                SequenceRow[] progressRows = uiRows.Where(row => row.Action == pair.ProgressDialog).ToArray();
                if (progressRows.Length == 1 && progressRows[0].Sequence >= executeAction.Sequence)
                {
                    failures.Add($"MSI {pair.Name} progress dialog must precede ExecuteAction.");
                }
            }
        }

        IReadOnlyList<MsiTableRow> executeRows = msi.Tables["InstallExecuteSequence"];
        MsiTableRow[] removeExisting = executeRows
            .Where(row => row.Fields["Action"] == "RemoveExistingProducts")
            .ToArray();
        if (removeExisting.Length != 1 || removeExisting[0].Fields["Sequence"] != "1501")
        {
            failures.Add("RemoveExistingProducts must remain at InstallExecuteSequence 1501.");
        }
        HashSet<string> dialogActions = DialogContracts
            .Select(dialog => dialog.Id)
            .ToHashSet(StringComparer.Ordinal);
        if (executeRows.Any(row => dialogActions.Contains(row.Fields["Action"])))
        {
            failures.Add("Custom dialog actions must not appear in InstallExecuteSequence; /qn must skip them.");
        }
    }

    private static void VerifyMsiShortcut(MsiSnapshot msi, List<string> failures)
    {
        MsiTableRow[] rows = msi.Tables["Shortcut"]
            .Where(row => row.Fields["Shortcut"] == "AppShortcutUninstall")
            .ToArray();
        if (rows.Length != 1 ||
            rows[0].Fields["Target"] != "[System64Folder]msiexec.exe" ||
            rows[0].Fields["Arguments"] != "/x [ProductCode]" ||
            rows[0].Fields["Arguments"].Contains("/qn", StringComparison.OrdinalIgnoreCase))
        {
            failures.Add("MSI Shortcut table must retain interactive msiexec /x uninstall semantics.");
        }
        foreach (string id in new[] { "AppShortcut", "DesktopAppShortcut" })
        {
            MsiTableRow[] launchRows = msi.Tables["Shortcut"]
                .Where(row => row.Fields["Shortcut"] == id)
                .ToArray();
            if (launchRows.Length != 1 ||
                launchRows[0].Fields["Target"] != "[INSTALLFOLDER]CodeSigner.App.exe" ||
                launchRows[0].Fields["WkDir"] != "INSTALLFOLDER")
            {
                failures.Add($"MSI {id} must launch [INSTALLFOLDER]CodeSigner.App.exe from INSTALLFOLDER.");
            }
        }
    }

    private static void VerifyMsiPackageClosure(
        MsiSnapshot msi,
        ExpectedPackageIdentity? expectedIdentity,
        List<string> failures)
    {
        IReadOnlyList<MsiTableRow> files = msi.Tables["File"];
        foreach ((string componentId, string fileName) in RequiredPayloadByComponent)
        {
            MsiTableRow[] matches = files
                .Where(row =>
                    row.Fields["Component_"] == componentId &&
                    LongMsiFileName(row.Fields["FileName"]) == fileName)
                .ToArray();
            if (matches.Length != 1)
            {
                failures.Add(
                    $"MSI package closure requires exactly one {componentId} File row '{fileName}'; " +
                    $"observed {matches.Length}.");
                continue;
            }
            if (expectedIdentity is not null &&
                fileName != "THIRD-PARTY-NOTICES.txt" &&
                matches[0].Fields["Version"] != $"{expectedIdentity.ProductVersion}.0")
            {
                failures.Add(
                    $"MSI package closure payload '{fileName}' version must be " +
                    $"'{expectedIdentity.ProductVersion}.0'; observed '{matches[0].Fields["Version"]}'.");
            }
            if (fileName == "THIRD-PARTY-NOTICES.txt" &&
                !string.IsNullOrEmpty(matches[0].Fields["Version"]))
            {
                failures.Add("Third-party notices must be an unversioned text payload.");
            }
        }
        foreach (MsiTableRow file in files.Where(row => !IsExpectedMsiFile(row)))
        {
            failures.Add(
                $"MSI package closure contains unexpected payload " +
                $"'{LongMsiFileName(file.Fields["FileName"])}'.");
        }

        if (expectedIdentity is null)
        {
            return;
        }
        VerifyMsiProperty(msi, "ProductVersion", expectedIdentity.ProductVersion, matchCase: true, failures);
        VerifyMsiProperty(msi, "ProductCode", expectedIdentity.ProductCode, matchCase: false, failures);
        VerifyMsiProperty(msi, "UpgradeCode", expectedIdentity.UpgradeCode, matchCase: false, failures);
    }

    private static void VerifyMsiProperty(
        MsiSnapshot msi,
        string property,
        string expected,
        bool matchCase,
        List<string> failures)
    {
        MsiTableRow[] matches = msi.Tables["Property"]
            .Where(row => row.Fields["Property"] == property)
            .ToArray();
        StringComparison comparison = matchCase
            ? StringComparison.Ordinal
            : StringComparison.OrdinalIgnoreCase;
        if (matches.Length != 1 ||
            !matches[0].Fields["Value"].Equals(expected, comparison))
        {
            string observed = matches.Length == 1 ? matches[0].Fields["Value"] : "<missing-or-duplicate>";
            failures.Add(
                $"MSI package identity {property} must be '{expected}'; observed '{observed}'.");
        }
    }

    private static bool IsExpectedAuthoringFile(AuthoringFile file) =>
        RequiredPayloadByComponent.TryGetValue(file.ComponentId, out string? expectedFileName) &&
        NormalizeAuthoringSource(file.SourceFile) == $"../../artifacts/staging/{expectedFileName}";

    private static bool IsExpectedMsiFile(MsiTableRow row) =>
        RequiredPayloadByComponent.TryGetValue(row.Fields["Component_"], out string? expectedFileName) &&
        LongMsiFileName(row.Fields["FileName"]) == expectedFileName;

    private static string NormalizeAuthoringSource(string source) => source.Replace('\\', '/');

    private static string PayloadName(string source)
    {
        string normalized = NormalizeAuthoringSource(source);
        int separator = normalized.LastIndexOf('/');
        return separator < 0 ? normalized : normalized[(separator + 1)..];
    }

    private static string LongMsiFileName(string fileName)
    {
        int separator = fileName.IndexOf('|');
        return separator < 0 ? fileName : fileName[(separator + 1)..];
    }

    private static void VerifySequenceRows(
        IReadOnlyList<SequenceRow> sequence,
        List<string> failures,
        string source)
    {
        RequireSequence(sequence, "WelcomeDlg", WizardCondition, 1297, source, failures);
        foreach (PairContract pair in PairContracts)
        {
            RequireSequence(sequence, pair.ProgressDialog, pair.Condition, pair.ProgressSequence, source, failures);
        }
        HashSet<string> expected = PairContracts
            .Select(pair => pair.ProgressDialog)
            .Append("WelcomeDlg")
            .ToHashSet(StringComparer.Ordinal);
        if (sequence.Count(row => expected.Contains(row.Action)) != 3)
        {
            failures.Add($"{source} must contain exactly three wizard/operation dialog sequence rows.");
        }
        if (sequence.Any(row => row.Action is "InstallDirectoryDlg" or "BrowseDlg"))
        {
            failures.Add($"{source} must navigate to InstallDirectoryDlg/BrowseDlg only through ControlEvent rows.");
        }
        if (sequence.Any(row => row.Action is "ProgressDlg" or "CompletedDlg"))
        {
            failures.Add($"{source} still sequences legacy unconditional ProgressDlg/CompletedDlg.");
        }
    }

    private static void VerifyAuthoringExitRoutes(AuthoringSnapshot source, List<string> failures)
    {
        RequireAuthoringExitRoute(source, "ExitDialog", "success", failures);
        RequireAuthoringExitRoute(source, "UserExit", "cancel", failures);
        RequireAuthoringExitRoute(source, "FatalError", "error", failures);
    }

    private static void RequireAuthoringExitRoute(
        AuthoringSnapshot source,
        string dialog,
        string onExit,
        List<string> failures)
    {
        int count = source.InstallUiExitRoutes.Count(route =>
            route.Dialog == dialog && route.OnExit == onExit && route.Condition is null);
        if (count != 1)
        {
            failures.Add($"Authoring must route {dialog} through OnExit={onExit} exactly once; observed {count}.");
        }
    }

    private static void VerifyMsiExitRoutes(IReadOnlyList<SequenceRow> sequence, List<string> failures)
    {
        RequireMsiExitRoute(sequence, "ExitDialog", -1, failures);
        RequireMsiExitRoute(sequence, "UserExit", -2, failures);
        RequireMsiExitRoute(sequence, "FatalError", -3, failures);
    }

    private static void RequireMsiExitRoute(
        IReadOnlyList<SequenceRow> sequence,
        string dialog,
        int expectedSequence,
        List<string> failures)
    {
        int count = sequence.Count(row =>
            row.Action == dialog && row.Sequence == expectedSequence && row.Condition is null);
        if (count != 1)
        {
            failures.Add($"MSI must route {dialog} at sequence {expectedSequence} exactly once; observed {count}.");
        }
    }

    private static bool HasAuthoringExitRoute(AuthoringSnapshot source, string dialog, string onExit) =>
        source.InstallUiExitRoutes.Any(route =>
            route.Dialog == dialog && route.OnExit == onExit && route.Condition is null);

    private static bool HasMsiExitRoute(MsiSnapshot msi, string dialog, int sequence) =>
        msi.Tables["InstallUISequence"].Any(row =>
            row.Fields["Action"] == dialog &&
            EmptyToNull(row.Fields["Condition"]) is null &&
            int.Parse(row.Fields["Sequence"], System.Globalization.CultureInfo.InvariantCulture) == sequence);

    private static List<ScenarioResult> EvaluateScenarios(
        IReadOnlyList<SequenceCondition> sequence,
        Func<string, string, string, string, bool> hasNavigation,
        bool hasSuccessfulExit)
    {
        List<ScenarioResult> results = [];
        foreach (OperationScenario scenario in InteractiveScenarios)
        {
            List<string> selected = [];
            List<string> route = [];
            if (scenario.UiSequenceRuns)
            {
                SequenceCondition[] welcomeRows = sequence.Where(row => row.Action == "WelcomeDlg").ToArray();
                if (welcomeRows.Length == 1 && EvaluateCondition(welcomeRows[0].Condition, scenario))
                {
                    route.Add("WelcomeDlg");
                    if (hasNavigation("WelcomeDlg", "NextButton", "NewDialog", "InstallDirectoryDlg"))
                    {
                        route.Add("InstallDirectoryDlg");
                    }
                }

                foreach (PairContract pair in PairContracts)
                {
                    SequenceCondition[] progressRows = sequence
                        .Where(row => row.Action == pair.ProgressDialog)
                        .ToArray();
                    if (progressRows.Length == 1 && EvaluateCondition(progressRows[0].Condition, scenario))
                    {
                        selected.Add(pair.Name);
                        route.Add(pair.ProgressDialog);
                    }
                }
                if (selected.Count > 0 && hasSuccessfulExit)
                {
                    route.Add("ExitDialog");
                }
            }
            results.Add(new ScenarioResult(scenario.Name, scenario.UiSequenceRuns, selected, route));
        }
        return results;
    }

    private static void VerifyScenarioSelections(
        IReadOnlyList<ScenarioResult> scenarios,
        List<string> failures,
        string source)
    {
        foreach (ScenarioResult scenario in scenarios)
        {
            int expectedPairs = scenario.UiSequenceRuns ? 1 : 0;
            if (scenario.SelectedPairs.Count != expectedPairs)
            {
                failures.Add(
                    $"{source} scenario {scenario.Scenario} selected {scenario.SelectedPairs.Count} dialog pairs; " +
                    $"expected {expectedPairs}.");
            }
            string[] expectedRoute = ExpectedRoute(scenario.Scenario);
            if (!scenario.DialogRoute.SequenceEqual(expectedRoute, StringComparer.Ordinal))
            {
                failures.Add(
                    $"{source} scenario {scenario.Scenario} route mismatch; " +
                    $"expected '{string.Join(" -> ", expectedRoute)}'; " +
                    $"observed '{string.Join(" -> ", scenario.DialogRoute)}'.");
            }
        }
    }

    private static string[] ExpectedRoute(string scenario) => scenario switch
    {
        "FreshInstall" or "MajorUpgrade" =>
            ["WelcomeDlg", "InstallDirectoryDlg", "InstallProgressDlg", "ExitDialog"],
        "Maintenance" => ["InstallProgressDlg", "ExitDialog"],
        "Uninstall" => ["UninstallProgressDlg", "ExitDialog"],
        "SilentQn" => [],
        _ => throw new InvalidOperationException($"Unknown installer scenario: {scenario}"),
    };

    private static bool EvaluateCondition(string? condition, OperationScenario scenario) => condition switch
    {
        WizardCondition => !scenario.Installed,
        InstallCondition => !(scenario.Remove == "ALL" && scenario.Installed),
        UninstallCondition => scenario.Remove == "ALL" && scenario.Installed,
        "WIX_UPGRADE_DETECTED" => scenario.UpgradeDetected,
        "1" or null => true,
        _ => false,
    };

    private static AuthoringDialog? SingleDialog(
        IReadOnlyList<AuthoringDialog> dialogs,
        string id,
        List<string> failures)
    {
        AuthoringDialog[] matches = dialogs.Where(dialog => dialog.Id == id).ToArray();
        if (matches.Length != 1)
        {
            failures.Add($"Expected exactly one authoring Dialog {id}; observed {matches.Length}.");
            return null;
        }
        return matches[0];
    }

    private static void RequireSequence(
        IReadOnlyList<SequenceRow> rows,
        string action,
        string condition,
        int sequence,
        string source,
        List<string> failures)
    {
        SequenceRow[] matches = rows.Where(row => row.Action == action).ToArray();
        if (matches.Length != 1 || matches[0].Condition != condition || matches[0].Sequence != sequence)
        {
            failures.Add($"{source} {action} must appear once at {sequence} with condition '{condition}'.");
        }
    }

    private static void RequireEqual(
        string? actual,
        string? expected,
        string field,
        List<string> failures)
    {
        if (actual != expected)
        {
            failures.Add($"{field} must be '{expected ?? "<missing>"}'; observed '{actual ?? "<missing>"}'.");
        }
    }

    private static string EffectiveCondition(string? condition) =>
        string.IsNullOrEmpty(condition) ? "1" : condition;

    private static string? EmptyToNull(string value) => value.Length == 0 ? null : value;

    private sealed record Rect(int X, int Y, int Width, int Height);

    private sealed record ControlContract(
        string Id,
        string Type,
        Rect Geometry,
        string? Property,
        string? Text,
        AuthoringControlAttributes Attributes,
        int MsiAttributes);

    private sealed record DialogContract(
        string Id,
        string Family,
        string Title,
        bool Modeless,
        string? DefaultControl,
        string? CancelControl,
        IReadOnlyList<ControlContract> Controls);

    private sealed record PairContract(
        string Name,
        string ProgressDialog,
        string CompletedDialog,
        string Condition,
        int ProgressSequence,
        string ProgressWindowTitle,
        string ProgressTitle,
        string ProgressStatus,
        string CompletedWindowTitle,
        string CompletedTitle,
        string CompletedText);

    private sealed record OperationScenario(
        string Name,
        bool Installed,
        bool UpgradeDetected,
        string Remove,
        bool UiSequenceRuns);

    private sealed record SequenceCondition(string Action, string? Condition);

    private sealed record SequenceRow(string Action, string? Condition, int Sequence);
}
