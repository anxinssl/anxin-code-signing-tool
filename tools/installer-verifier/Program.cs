using System.Text;
using System.Text.Json;

namespace CodeSigner.InstallerVerifier;

internal static class Program
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static int Main(string[] args)
    {
        try
        {
            VerifyOptions options = VerifyOptions.Parse(args);
            AuthoringSnapshot authoring = AuthoringReader.Read(options.SourcePath, options.SettingsSourcePath);
            StagingSnapshot? staging = options.StagingPath is null
                ? null
                : StagingReader.Read(options.StagingPath);
            MsiSnapshot? msi = options.MsiPath is null ? null : MsiDatabaseReader.Read(options.MsiPath);
            MsiSnapshot? extractionSource = msi is not null && options.MsiPath is not null &&
                Path.GetExtension(options.MsiPath).Equals(".json", StringComparison.OrdinalIgnoreCase)
                    ? MsiDatabaseReader.Read(msi.Path)
                    : msi;
            MsiPayloadSnapshot? extractedMsiPayloads = staging is null || msi is null
                ? null
                : MsiPayloadExtractor.Read(extractionSource!, options.WixToolsetDllPath!);
            List<string> violations = [.. ContractVerifier.VerifyAuthoring(authoring)];
            if (staging is not null)
            {
                violations.AddRange(ContractVerifier.VerifyStaging(staging));
            }
            if (staging is not null && extractedMsiPayloads is not null)
            {
                violations.AddRange(ContractVerifier.VerifyPayloadHashes(staging, extractedMsiPayloads));
            }
            IReadOnlyList<ScenarioResult> authoringScenarios =
                ContractVerifier.EvaluateAuthoringScenarios(authoring);
            IReadOnlyList<ScenarioResult>? msiScenarios = null;
            if (msi is not null)
            {
                violations.AddRange(ContractVerifier.VerifyMsi(msi, options.ExpectedIdentity));
                msiScenarios = ContractVerifier.EvaluateMsiScenarios(msi);
            }
            PackageClosureSummary packageClosure = ContractVerifier.SummarizePackageClosure(
                authoring,
                staging,
                msi,
                extractedMsiPayloads);

            VerificationReceipt receipt = new(
                "codesigner-installer-ui-contract-v1",
                DateTimeOffset.UtcNow.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
                violations.Count == 0,
                violations,
                authoring,
                staging,
                msi,
                extractedMsiPayloads,
                options.ExpectedIdentity,
                packageClosure,
                authoringScenarios,
                msiScenarios,
                ProductIconBindingRequired: false);
            string json = JsonSerializer.Serialize(receipt, JsonOptions);
            Console.WriteLine(json);
            if (options.ReceiptPath is not null)
            {
                string receiptPath = Path.GetFullPath(options.ReceiptPath);
                Directory.CreateDirectory(Path.GetDirectoryName(receiptPath)
                    ?? throw new InvalidOperationException("Receipt path has no directory."));
                File.WriteAllText(receiptPath, json + Environment.NewLine, new UTF8Encoding(false));
            }
            return receipt.Success ? 0 : 1;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"Installer UI verifier error: {exception.Message}");
            return 2;
        }
    }
}

internal sealed record VerifyOptions(
    string SourcePath,
    string SettingsSourcePath,
    string? StagingPath,
    string? MsiPath,
    string? WixToolsetDllPath,
    ExpectedPackageIdentity? ExpectedIdentity,
    string? ReceiptPath)
{
    public static VerifyOptions Parse(IReadOnlyList<string> args)
    {
        Dictionary<string, string> values = new(StringComparer.Ordinal);
        for (int index = 0; index < args.Count; index += 2)
        {
            if (index + 1 >= args.Count || !args[index].StartsWith("--", StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    "Arguments must be exact --source/--settings-source/--staging/--msi/" +
                    "--wix-toolset-dll/--expected-version/--expected-product-code/" +
                    "--expected-upgrade-code/--receipt name-value pairs.");
            }
            if (!values.TryAdd(args[index], args[index + 1]))
            {
                throw new ArgumentException($"Duplicate argument: {args[index]}");
            }
        }

        HashSet<string> allowed =
        [
            "--source",
            "--settings-source",
            "--staging",
            "--msi",
            "--wix-toolset-dll",
            "--expected-version",
            "--expected-product-code",
            "--expected-upgrade-code",
            "--receipt",
        ];
        string? unsupported = values.Keys.FirstOrDefault(key => !allowed.Contains(key));
        if (unsupported is not null)
        {
            throw new ArgumentException($"Unsupported argument: {unsupported}");
        }
        if (!values.TryGetValue("--source", out string? source) ||
            !values.TryGetValue("--settings-source", out string? settings))
        {
            throw new ArgumentException("--source and --settings-source are required.");
        }
        string? staging = values.GetValueOrDefault("--staging");
        string? msi = values.GetValueOrDefault("--msi");
        string? wixToolsetDll = values.GetValueOrDefault("--wix-toolset-dll");
        string? expectedVersion = values.GetValueOrDefault("--expected-version");
        string? expectedProductCode = values.GetValueOrDefault("--expected-product-code");
        string? expectedUpgradeCode = values.GetValueOrDefault("--expected-upgrade-code");
        bool anyPackageOption = staging is not null ||
            wixToolsetDll is not null ||
            expectedVersion is not null ||
            expectedProductCode is not null ||
            expectedUpgradeCode is not null;
        ExpectedPackageIdentity? expectedIdentity = null;
        if (anyPackageOption)
        {
            if (staging is null ||
                msi is null ||
                wixToolsetDll is null ||
                expectedVersion is null ||
                expectedProductCode is null ||
                expectedUpgradeCode is null)
            {
                throw new ArgumentException(
                    "--staging, --msi, --wix-toolset-dll, --expected-version, " +
                    "--expected-product-code, and --expected-upgrade-code must be provided together.");
            }
            if (!Version.TryParse(expectedVersion, out Version? parsedVersion) ||
                parsedVersion.ToString(3) != expectedVersion ||
                !Guid.TryParseExact(expectedProductCode, "B", out _) ||
                !Guid.TryParseExact(expectedUpgradeCode, "B", out _))
            {
                throw new ArgumentException("Expected package identity is malformed.");
            }
            expectedIdentity = new ExpectedPackageIdentity(
                expectedVersion,
                expectedProductCode,
                expectedUpgradeCode);
        }
        return new VerifyOptions(
            source,
            settings,
            staging,
            msi,
            wixToolsetDll,
            expectedIdentity,
            values.GetValueOrDefault("--receipt"));
    }
}
