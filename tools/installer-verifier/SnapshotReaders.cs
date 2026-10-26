using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;

namespace CodeSigner.InstallerVerifier;

internal static class AuthoringReader
{
    public static AuthoringSnapshot Read(string sourcePath, string settingsSourcePath)
    {
        string resolvedSource = Path.GetFullPath(sourcePath);
        string resolvedSettings = Path.GetFullPath(settingsSourcePath);
        XDocument document = XDocument.Load(resolvedSource, LoadOptions.SetLineInfo);
        XNamespace ns = document.Root?.Name.Namespace
            ?? throw new InvalidDataException("WiX authoring has no root element.");
        XElement package = document.Root?.Element(ns + "Package")
            ?? throw new InvalidDataException("WiX authoring has no Package element.");
        XElement ui = package.Element(ns + "UI")
            ?? throw new InvalidDataException("WiX authoring has no UI element.");

        AuthoringDialog[] dialogs = ui.Elements(ns + "Dialog")
            .Select(dialog => new AuthoringDialog(
                RequiredAttribute(dialog, "Id"),
                OptionalIntAttribute(dialog, "HCentering", 50),
                OptionalIntAttribute(dialog, "VCentering", 50),
                RequiredIntAttribute(dialog, "Width"),
                RequiredIntAttribute(dialog, "Height"),
                OptionalAttribute(dialog, "Title"),
                new AuthoringDialogAttributes(
                    YesAttribute(dialog, "Modeless"),
                    YesAttribute(dialog, "NoMinimize"),
                    YesAttribute(dialog, "KeepModeless"),
                    YesAttribute(dialog, "TrackDiskSpace"),
                    YesAttribute(dialog, "RightToLeft"),
                    YesAttribute(dialog, "RightAligned"),
                    YesAttribute(dialog, "LeftScroll"),
                    YesAttribute(dialog, "ErrorDialog")),
                dialog.Elements(ns + "Control")
                    .Select(control => new AuthoringControl(
                        RequiredAttribute(control, "Id"),
                        RequiredAttribute(control, "Type"),
                        RequiredIntAttribute(control, "X"),
                        RequiredIntAttribute(control, "Y"),
                        RequiredIntAttribute(control, "Width"),
                        RequiredIntAttribute(control, "Height"),
                        OptionalAttribute(control, "Property"),
                        OptionalAttribute(control, "Text"),
                        new AuthoringControlAttributes(
                            YesAttribute(control, "Disabled"),
                            YesAttribute(control, "Hidden"),
                            YesAttribute(control, "Indirect"),
                            YesAttribute(control, "Integer"),
                            YesAttribute(control, "RightToLeft"),
                            YesAttribute(control, "RightAligned"),
                            YesAttribute(control, "LeftScroll"),
                            YesAttribute(control, "Sunken"),
                            YesAttribute(control, "TabSkip"),
                            YesAttribute(control, "Transparent"),
                            YesAttribute(control, "Default"),
                            YesAttribute(control, "Cancel"),
                            YesAttribute(control, "ProgressBlocks")),
                        control.Elements(ns + "Subscribe")
                            .Select(subscription => new Subscription(
                                RequiredAttribute(subscription, "Event"),
                                RequiredAttribute(subscription, "Attribute")))
                            .ToArray(),
                        control.Elements(ns + "Publish")
                            .Select(ReadPublication)
                            .ToArray()))
                    .ToArray()))
            .ToArray();

        XElement[] uiShows = ui.Element(ns + "InstallUISequence")?
            .Elements(ns + "Show")
            .ToArray() ?? [];
        AuthoringSequenceRow[] sequence = uiShows
            .Where(show => OptionalAttribute(show, "Sequence") is not null)
            .Select(show => new AuthoringSequenceRow(
                RequiredAttribute(show, "Dialog"),
                OptionalAttribute(show, "Condition"),
                int.Parse(RequiredAttribute(show, "Sequence"), System.Globalization.CultureInfo.InvariantCulture)))
            .ToArray();
        AuthoringExitRoute[] exitRoutes = uiShows
            .Where(show => OptionalAttribute(show, "OnExit") is not null)
            .Select(show => new AuthoringExitRoute(
                RequiredAttribute(show, "Dialog"),
                RequiredAttribute(show, "OnExit"),
                OptionalAttribute(show, "Condition")))
            .ToArray();

        string[] executeSequenceActions = package.Element(ns + "InstallExecuteSequence")?
            .Elements(ns + "Custom")
            .Select(custom => RequiredAttribute(custom, "Action"))
            .ToArray() ?? [];

        AuthoringShortcut[] shortcuts = package.Descendants(ns + "Shortcut")
            .Select(shortcut => new AuthoringShortcut(
                RequiredAttribute(shortcut, "Id"),
                OptionalAttribute(shortcut, "Target"),
                OptionalAttribute(shortcut, "Arguments"),
                OptionalAttribute(shortcut, "WorkingDirectory")))
            .ToArray();

        AuthoringFile[] files = package.Descendants(ns + "File")
            .Select(file =>
            {
                XElement component = file.Ancestors(ns + "Component").FirstOrDefault()
                    ?? throw new InvalidDataException("WiX File has no containing Component.");
                return new AuthoringFile(
                    RequiredAttribute(component, "Id"),
                    RequiredAttribute(file, "Source"));
            })
            .ToArray();

        AuthoringBinary[] binaries = package.Elements(ns + "Binary")
            .Select(binary => new AuthoringBinary(
                RequiredAttribute(binary, "Id"),
                RequiredAttribute(binary, "SourceFile")))
            .ToArray();

        IReadOnlyDictionary<string, string> properties = package.Elements(ns + "Property")
            .ToDictionary(
                property => RequiredAttribute(property, "Id"),
                property => OptionalAttribute(property, "Value") ?? string.Empty,
                StringComparer.Ordinal);

        AuthoringTextStyle[] textStyles = ui.Elements(ns + "TextStyle")
            .Select(style => new AuthoringTextStyle(
                RequiredAttribute(style, "Id"),
                OptionalAttribute(style, "FaceName"),
                OptionalAttribute(style, "Size"),
                TextStyleBits(style)))
            .ToArray();

        XElement? rollbackAction = package.Elements(ns + "CustomAction")
            .SingleOrDefault(action => OptionalAttribute(action, "Id") == "ForceLifecycleRollback");
        XElement? rollbackSequence = package.Elements(ns + "InstallExecuteSequence")
            .Elements(ns + "Custom")
            .SingleOrDefault(action => OptionalAttribute(action, "Action") == "ForceLifecycleRollback");
        string settingsSource = File.ReadAllText(resolvedSettings)
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n');

        return new AuthoringSnapshot(
            resolvedSource,
            Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(resolvedSource))),
            dialogs,
            sequence,
            exitRoutes,
            executeSequenceActions,
            properties,
            textStyles,
            shortcuts,
            files,
            binaries,
            OptionalAttribute(package.Element(ns + "MajorUpgrade"), "Schedule"),
            rollbackAction is not null &&
                OptionalAttribute(rollbackAction, "Error") ==
                    "CodeSigner lifecycle rollback test: controlled failure after InstallFiles.",
            rollbackSequence is not null &&
                OptionalAttribute(rollbackSequence, "After") == "InstallFiles" &&
                OptionalAttribute(rollbackSequence, "Condition") ==
                    "NOT Installed AND WIX_UPGRADE_DETECTED AND CODESIGNER_TEST_FORCE_ROLLBACK = \"1\"",
            resolvedSettings,
            settingsSource.Contains(
                "Process.Start(CreateUninstallStartInfo());",
                StringComparison.Ordinal) &&
            settingsSource.Contains(
                "Path.Combine(Environment.SystemDirectory, \"msiexec.exe\")",
                StringComparison.Ordinal) &&
            settingsSource.Contains("startInfo.ArgumentList.Add(\"/x\");", StringComparison.Ordinal) &&
            settingsSource.Contains("startInfo.ArgumentList.Add(InstalledProductCode);", StringComparison.Ordinal) &&
            !settingsSource.Contains(
                "/qn",
                StringComparison.Ordinal));
    }

    private static Publication ReadPublication(XElement publication)
    {
        string? eventName = OptionalAttribute(publication, "Event");
        string? property = OptionalAttribute(publication, "Property");
        if ((eventName is null) == (property is null))
        {
            throw new InvalidDataException(
                "Publish must contain exactly one Event or Property attribute.");
        }
        return new Publication(
            eventName,
            property,
            RequiredAttribute(publication, "Value"),
            OptionalAttribute(publication, "Condition"),
            OptionalIntAttribute(publication, "Order", 1));
    }

    private static int RequiredIntAttribute(XElement element, string name) =>
        int.Parse(
            RequiredAttribute(element, name),
            System.Globalization.CultureInfo.InvariantCulture);

    private static int OptionalIntAttribute(XElement element, string name, int defaultValue) =>
        OptionalAttribute(element, name) is { } value
            ? int.Parse(value, System.Globalization.CultureInfo.InvariantCulture)
            : defaultValue;

    private static bool YesAttribute(XElement element, string name) =>
        OptionalAttribute(element, name) == "yes";

    private static string TextStyleBits(XElement element) =>
        ((YesAttribute(element, "Bold") ? 1 : 0) |
         (YesAttribute(element, "Italic") ? 2 : 0) |
         (YesAttribute(element, "Underline") ? 4 : 0) |
         (YesAttribute(element, "Strike") ? 8 : 0))
        .ToString(System.Globalization.CultureInfo.InvariantCulture);

    private static string RequiredAttribute(XElement element, string name) =>
        OptionalAttribute(element, name)
        ?? throw new InvalidDataException($"{element.Name.LocalName} is missing required {name}.");

    private static string? OptionalAttribute(XElement? element, string name) =>
        element?.Attribute(name)?.Value;
}

internal static class StagingReader
{
    public static StagingSnapshot Read(string stagingPath)
    {
        string resolvedPath = Path.GetFullPath(stagingPath);
        if (!Directory.Exists(resolvedPath))
        {
            throw new DirectoryNotFoundException($"Installer staging directory is missing: {resolvedPath}");
        }
        if ((File.GetAttributes(resolvedPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("Installer staging directory must not be a reparse point.");
        }

        string rootPrefix = Path.TrimEndingDirectorySeparator(resolvedPath) + Path.DirectorySeparatorChar;
        var pending = new Queue<string>();
        var files = new List<StagedPayloadFile>();
        pending.Enqueue(resolvedPath);
        while (pending.TryDequeue(out string? directory))
        {
            foreach (string entry in Directory.EnumerateFileSystemEntries(directory)
                         .Order(StringComparer.OrdinalIgnoreCase))
            {
                string resolvedEntry = Path.GetFullPath(entry);
                if (!resolvedEntry.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException("Installer staging entry escaped the staging directory.");
                }
                FileAttributes attributes = File.GetAttributes(resolvedEntry);
                string relativePath = NormalizeRelativePath(Path.GetRelativePath(resolvedPath, resolvedEntry));
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    throw new InvalidDataException(
                        $"Installer staging entry must not be a reparse point: {relativePath}");
                }
                if ((attributes & FileAttributes.Directory) != 0)
                {
                    pending.Enqueue(resolvedEntry);
                    continue;
                }

                using FileStream stream = File.OpenRead(resolvedEntry);
                files.Add(new StagedPayloadFile(
                    relativePath,
                    stream.Length,
                    Convert.ToHexString(SHA256.HashData(stream))));
            }
        }

        return new StagingSnapshot(
            resolvedPath,
            files.OrderBy(file => file.RelativePath, StringComparer.Ordinal).ToArray());
    }

    private static string NormalizeRelativePath(string path) =>
        path.Replace(Path.DirectorySeparatorChar, '/').Replace(Path.AltDirectorySeparatorChar, '/');
}

internal static class MsiPayloadExtractor
{
    private const int ExtractionTimeoutMilliseconds = 120_000;

    public static MsiPayloadSnapshot Read(MsiSnapshot msi, string wixToolsetDllPath)
    {
        string resolvedExtractorPath = Path.GetFullPath(wixToolsetDllPath);
        if (!File.Exists(resolvedExtractorPath))
        {
            throw new FileNotFoundException("WiX Toolset command assembly is missing.", resolvedExtractorPath);
        }
        if ((File.GetAttributes(resolvedExtractorPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("WiX Toolset command assembly must not be a reparse point.");
        }

        string temporaryDirectory = Path.Combine(
            Path.GetTempPath(),
            $"codesigner-msi-extraction-{Guid.NewGuid():N}");
        string extractedDirectory = Path.Combine(temporaryDirectory, "extracted");
        string decompiledSourcePath = Path.Combine(temporaryDirectory, "decompiled.wxs");
        ExtractedMsiPayloadFile[] payloads;
        Directory.CreateDirectory(temporaryDirectory);
        try
        {
            RunStaticExtraction(
                resolvedExtractorPath,
                msi.Path,
                extractedDirectory,
                decompiledSourcePath,
                temporaryDirectory);
            payloads = ReadExtractedPayloads(msi, extractedDirectory);
        }
        finally
        {
            if (Directory.Exists(temporaryDirectory))
            {
                Directory.Delete(temporaryDirectory, recursive: true);
            }
        }

        using FileStream extractorStream = File.OpenRead(resolvedExtractorPath);
        return new MsiPayloadSnapshot(
            "wix-msi-decompile-x",
            resolvedExtractorPath,
            Convert.ToHexString(SHA256.HashData(extractorStream)),
            TemporaryDirectoryRemoved: !Directory.Exists(temporaryDirectory),
            payloads);
    }

    private static void RunStaticExtraction(
        string extractorPath,
        string msiPath,
        string extractedDirectory,
        string decompiledSourcePath,
        string workingDirectory)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "dotnet",
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add(extractorPath);
        startInfo.ArgumentList.Add("msi");
        startInfo.ArgumentList.Add("decompile");
        startInfo.ArgumentList.Add("-x");
        startInfo.ArgumentList.Add(extractedDirectory);
        startInfo.ArgumentList.Add("-o");
        startInfo.ArgumentList.Add(decompiledSourcePath);
        startInfo.ArgumentList.Add(msiPath);

        using Process process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("WiX Toolset static extraction process did not start.");
        Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
        Task<string> stderrTask = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(ExtractionTimeoutMilliseconds))
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit();
            throw new TimeoutException("WiX Toolset static MSI extraction timed out.");
        }
        string stdout = stdoutTask.GetAwaiter().GetResult();
        string stderr = stderrTask.GetAwaiter().GetResult();
        if (process.ExitCode != 0)
        {
            string detail = string.Join(
                " ",
                new[] { stdout.Trim(), stderr.Trim() }.Where(value => value.Length > 0));
            throw new InvalidDataException(
                $"WiX Toolset static MSI extraction failed with exit code {process.ExitCode}: {detail}");
        }
    }

    private static ExtractedMsiPayloadFile[] ReadExtractedPayloads(
        MsiSnapshot msi,
        string extractedDirectory)
    {
        string fileDirectory = Path.Combine(extractedDirectory, "File");
        if (!Directory.Exists(fileDirectory))
        {
            throw new InvalidDataException("WiX Toolset static extraction produced no File payload directory.");
        }
        IReadOnlyList<MsiTableRow> fileRows = msi.Tables["File"];
        string[] extractedFiles = Directory
            .EnumerateFiles(fileDirectory, "*", SearchOption.AllDirectories)
            .ToArray();
        if (extractedFiles.Length != fileRows.Count)
        {
            throw new InvalidDataException(
                $"Static MSI extraction produced {extractedFiles.Length} File payloads; " +
                $"the compiled File table contains {fileRows.Count} rows.");
        }

        var payloads = new List<ExtractedMsiPayloadFile>(fileRows.Count);
        foreach (MsiTableRow row in fileRows)
        {
            string fileId = row.Fields["File"];
            if (fileId.Length == 0 ||
                Path.GetFileName(fileId) != fileId ||
                fileId.IndexOfAny([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar]) >= 0)
            {
                throw new InvalidDataException($"MSI File identifier is not a safe extracted name: '{fileId}'.");
            }
            string extractedPath = Path.Combine(fileDirectory, fileId);
            if (!File.Exists(extractedPath))
            {
                throw new InvalidDataException(
                    $"Static MSI extraction is missing File payload identifier '{fileId}'.");
            }
            if ((File.GetAttributes(extractedPath) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    $"Static MSI extraction payload must not be a reparse point: '{fileId}'.");
            }

            using FileStream stream = File.OpenRead(extractedPath);
            payloads.Add(new ExtractedMsiPayloadFile(
                fileId,
                LongMsiFileName(row.Fields["FileName"]),
                stream.Length,
                Convert.ToHexString(SHA256.HashData(stream))));
        }
        return payloads
            .OrderBy(payload => payload.FileName, StringComparer.Ordinal)
            .ToArray();
    }

    private static string LongMsiFileName(string fileName)
    {
        int separator = fileName.IndexOf('|');
        return separator < 0 ? fileName : fileName[(separator + 1)..];
    }
}

internal static class MsiDatabaseReader
{
    private const string TableFixtureSchema = "codesigner-compiled-msi-table-fixture-v1";

    private static readonly JsonSerializerOptions FixtureJsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    private static readonly HashSet<string> OptionalTableNames =
        new(StringComparer.Ordinal) { "TextStyle" };

    private static readonly IReadOnlyDictionary<string, string[]> TableSchemas =
        new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            ["Dialog"] = ["Dialog", "HCentering", "VCentering", "Width", "Height", "Attributes", "Title", "Control_First", "Control_Default", "Control_Cancel"],
            ["Control"] = ["Dialog_", "Control", "Type", "X", "Y", "Width", "Height", "Attributes", "Property", "Text", "Control_Next", "Help"],
            ["ControlEvent"] = ["Dialog_", "Control_", "Event", "Argument", "Condition", "Ordering"],
            ["EventMapping"] = ["Dialog_", "Control_", "Event", "Attribute"],
            ["InstallUISequence"] = ["Action", "Condition", "Sequence"],
            ["InstallExecuteSequence"] = ["Action", "Condition", "Sequence"],
            ["Shortcut"] = ["Shortcut", "Directory_", "Name", "Component_", "Target", "Arguments", "Description", "Hotkey", "Icon_", "IconIndex", "ShowCmd", "WkDir"],
            ["File"] = ["File", "Component_", "FileName", "FileSize", "Version", "Language", "Attributes", "Sequence"],
            ["Property"] = ["Property", "Value"],
            ["Binary"] = ["Name"],
            ["TextStyle"] = ["TextStyle", "FaceName", "Size", "Color", "StyleBits"],
        };

    public static MsiSnapshot Read(string msiPath)
    {
        string resolvedPath = Path.GetFullPath(msiPath);
        if (!File.Exists(resolvedPath))
        {
            throw new FileNotFoundException("Candidate MSI is missing.", resolvedPath);
        }
        if (Path.GetExtension(resolvedPath).Equals(".json", StringComparison.OrdinalIgnoreCase))
        {
            return ReadTableFixture(resolvedPath);
        }

        Type installerType = Type.GetTypeFromProgID("WindowsInstaller.Installer")
            ?? throw new PlatformNotSupportedException("WindowsInstaller.Installer COM is unavailable.");
        object installer = Activator.CreateInstance(installerType)
            ?? throw new InvalidOperationException("WindowsInstaller.Installer could not be created.");
        object? database = null;
        try
        {
            database = Invoke(installer, "OpenDatabase", resolvedPath, 0);
            HashSet<string> presentTables = ReadTable(database, "_Tables", ["Name"])
                .Select(row => row.Fields["Name"])
                .ToHashSet(StringComparer.Ordinal);
            Dictionary<string, IReadOnlyList<MsiTableRow>> tables = new(StringComparer.Ordinal);
            foreach ((string table, string[] columns) in TableSchemas)
            {
                if (!presentTables.Contains(table))
                {
                    if (OptionalTableNames.Contains(table))
                    {
                        continue;
                    }
                    throw new InvalidDataException($"Candidate MSI is missing required table '{table}'.");
                }
                tables.Add(table, ReadTable(database, table, columns));
            }

            return new MsiSnapshot(
                resolvedPath,
                Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(resolvedPath))),
                tables);
        }
        finally
        {
            Release(database);
            Release(installer);
        }
    }

    private static MsiSnapshot ReadTableFixture(string fixturePath)
    {
        MsiTableFixture fixture = JsonSerializer.Deserialize<MsiTableFixture>(
            File.ReadAllText(fixturePath),
            FixtureJsonOptions)
            ?? throw new InvalidDataException("Compiled MSI table fixture is empty.");
        if (fixture.Schema != TableFixtureSchema)
        {
            throw new InvalidDataException(
                $"Compiled MSI table fixture schema must be '{TableFixtureSchema}'.");
        }

        string sourceMsiPath = Path.IsPathRooted(fixture.SourceMsiPath)
            ? Path.GetFullPath(fixture.SourceMsiPath)
            : Path.GetFullPath(Path.Combine(
                Path.GetDirectoryName(fixturePath)
                    ?? throw new InvalidDataException("Compiled MSI table fixture has no parent directory."),
                fixture.SourceMsiPath));
        if (!File.Exists(sourceMsiPath))
        {
            throw new FileNotFoundException(
                "Compiled MSI table fixture source MSI is missing.",
                sourceMsiPath);
        }
        string actualSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(sourceMsiPath)));
        if (!actualSha256.Equals(fixture.SourceMsiSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Compiled MSI table fixture source hash mismatch; the captured tables are stale.");
        }

        foreach ((string table, string[] columns) in TableSchemas)
        {
            if (!fixture.Tables.TryGetValue(table, out IReadOnlyList<MsiTableRow>? rows))
            {
                if (OptionalTableNames.Contains(table))
                {
                    continue;
                }
                throw new InvalidDataException(
                    $"Compiled MSI table fixture is missing required table '{table}'.");
            }
            foreach (MsiTableRow row in rows)
            {
                string? missingColumn = columns.FirstOrDefault(column => !row.Fields.ContainsKey(column));
                if (missingColumn is not null)
                {
                    throw new InvalidDataException(
                        $"Compiled MSI table fixture {table} row is missing column '{missingColumn}'.");
                }
            }
        }

        return new MsiSnapshot(sourceMsiPath, actualSha256, fixture.Tables);
    }

    private static List<MsiTableRow> ReadTable(
        object database,
        string table,
        string[] columns)
    {
        object view = Invoke(database, "OpenView", $"SELECT * FROM `{table}`");
        try
        {
            InvokeOptional(view, "Execute");
            List<MsiTableRow> rows = [];
            while (InvokeOptional(view, "Fetch") is { } record)
            {
                try
                {
                    Dictionary<string, string> fields = new(StringComparer.Ordinal);
                    for (int index = 0; index < columns.Length; index++)
                    {
                        string value = ReadStringData(record, index + 1);
                        if (table == "TextStyle" && columns[index] == "StyleBits" && value.Length == 0)
                        {
                            value = "0";
                        }
                        fields.Add(columns[index], value);
                    }
                    rows.Add(new MsiTableRow(fields));
                }
                finally
                {
                    Release(record);
                }
            }
            return rows;
        }
        finally
        {
            Release(view);
        }
    }

    private static object Invoke(object target, string member, params object[] arguments) =>
        target.GetType().InvokeMember(
            member,
            BindingFlags.InvokeMethod,
            binder: null,
            target,
            arguments,
            System.Globalization.CultureInfo.InvariantCulture)
        ?? throw new InvalidOperationException($"COM member {member} returned null.");

    private static object? InvokeOptional(object target, string member) =>
        target.GetType().InvokeMember(
            member,
            BindingFlags.InvokeMethod,
            binder: null,
            target,
            args: null,
            System.Globalization.CultureInfo.InvariantCulture);

    private static string ReadStringData(object record, int field) =>
        (string?)record.GetType().InvokeMember(
            "StringData",
            BindingFlags.GetProperty,
            binder: null,
            record,
            [field],
            System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;

    private static void Release(object? value)
    {
        if (value is not null && Marshal.IsComObject(value))
        {
            Marshal.FinalReleaseComObject(value);
        }
    }
}
