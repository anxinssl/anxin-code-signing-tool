using CodeSigner.CompatibilityProbe.Oracle;
using CodeSigner.CompatibilityProbe.Fixtures;
using CodeSigner.Core.Evidence;
using CodeSigner.CompatibilityProbe.Signing;

return await CompatibilityProbeCli.RunAsync(args, Console.OpenStandardOutput(), CancellationToken.None);

internal static class CompatibilityProbeCli
{
    internal static async Task<int> RunAsync(string[] arguments, Stream output, CancellationToken cancellationToken)
    {
        if (arguments.Length == 0 || arguments[0] is "--help" or "-h")
        {
            await WriteTextAsync(
                output,
                "Usage: CodeSigner.CompatibilityProbe native-availability | cert-ready <CurrentUser|LocalMachine> <store-name> <thumbprint> | single <input> <output> <CurrentUser|LocalMachine> <store-name> <thumbprint> <timestamp-uri> | dual <input> <output> <primary-location> <primary-store> <primary-thumbprint> <secondary-location> <secondary-store> <secondary-thumbprint> <timestamp-uri> | product-pe-single <input> <output> <CurrentUser|LocalMachine> <store-name> <thumbprint> <timestamp-uri> | product-pe-dual <input> <output> <CurrentUser|LocalMachine> <store-name> <thumbprint> <timestamp-uri> | product-pe-inspect <input> <CurrentUser|LocalMachine> <store-name> <thumbprint> <single|dual> | diagnose-sha1-store-retained <input> <output> <CurrentUser|LocalMachine> <store-name> <thumbprint> <timestamp-uri> | self-test <input> <work-dir> <timestamp-uri> <signtool-path> | evidence-demo <output.json> | oracle-check [path] | generate-fixtures <output-dir> <unsigned-exe> <unsigned-dll> <unsigned-msi>",
                cancellationToken);
            return 0;
        }

        return arguments[0] switch
        {
            "evidence-demo" => await WriteEvidenceDemoAsync(arguments, output, cancellationToken),
            "oracle-check" => await CheckOracleAsync(arguments, output, cancellationToken),
            "generate-fixtures" => await GenerateFixturesAsync(arguments, output, cancellationToken),
            "native-availability" => await CompatibilitySigningCommands.CheckAvailabilityAsync(output, cancellationToken),
            "cert-ready" => await CertificateReadinessCommand.RunAsync(arguments, output, cancellationToken),
            "single" => await CompatibilitySigningCommands.RunSingleAsync(arguments, output, cancellationToken),
            "dual" => await CompatibilitySigningCommands.RunDualAsync(arguments, output, cancellationToken),
            "product-pe-single" => await ProductPeSigningCommands.RunSingleAsync(arguments, output, cancellationToken),
            "product-pe-dual" => await ProductPeSigningCommands.RunDualAsync(arguments, output, cancellationToken),
            "product-pe-inspect" => await ProductPeSigningCommands.RunInspectAsync(arguments, output, cancellationToken),
            "diagnose-sha1-store-retained" => await StoreRetainedSha1DiagnosticCommand.RunAsync(arguments, output, cancellationToken),
            "self-test" => await SelfSignedCompatibilityGate.RunAsync(arguments, output, cancellationToken),
            _ => await WriteUnknownCommandAsync(output, cancellationToken)
        };
    }

    private static async Task<int> WriteEvidenceDemoAsync(
        string[] arguments,
        Stream output,
        CancellationToken cancellationToken)
    {
        if (arguments.Length != 2)
        {
            await WriteReceiptAsync(output, "evidence-demo", "failed", OracleReasonCode.FileMissing.ToString(), null, null, cancellationToken);
            return 2;
        }

        Dictionary<string, object?> candidate = new()
        {
            ["schemaVersion"] = 1,
            ["event"] = "allow-list-demo",
            ["status"] = "passed",
            ["count"] = 3,
            ["password"] = "secret-canary-password",
            ["token"] = "secret-canary-token",
            ["unknown"] = "secret-canary-unknown"
        };
        await using (FileStream file = new(arguments[1], FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            await AllowListEvidenceWriter.WriteAsync(file, candidate, cancellationToken);
        }

        await AllowListEvidenceWriter.WriteAsync(output, candidate, cancellationToken);
        return 0;
    }

    private static async Task<int> CheckOracleAsync(
        string[] arguments,
        Stream output,
        CancellationToken cancellationToken)
    {
        string? configuredPath = arguments.Length > 1
            ? arguments[1]
            : Environment.GetEnvironmentVariable("SIGNTOOL_EXE");
        ExternalSignToolResolver resolver = new(new WindowsExternalExecutableProbe());
        OracleResolution result = resolver.Resolve(configuredPath);
        await WriteReceiptAsync(
            output,
            "oracle-check",
            result.IsApproved ? "passed" : "rejected",
            result.ReasonCode.ToString(),
            result.FileName,
            result.Sha256,
            cancellationToken);
        return result.IsApproved ? 0 : ExitCode(result.ReasonCode);
    }

    private static async Task<int> GenerateFixturesAsync(
        string[] arguments,
        Stream output,
        CancellationToken cancellationToken)
    {
        if (arguments.Length != 5)
        {
            await WriteReceiptAsync(output, "fixture-manifest", "failed", "InvalidArguments", null, null, cancellationToken);
            return 64;
        }

        try
        {
            FixtureManifest manifest = await FixtureGenerator.GenerateAsync(
                arguments[1],
                arguments[2],
                arguments[3],
                arguments[4],
                cancellationToken);
            Dictionary<string, object?> receipt = new()
            {
                ["schemaVersion"] = manifest.SchemaVersion,
                ["event"] = "fixture-manifest",
                ["status"] = "passed",
                ["fileName"] = "manifest.json",
                ["count"] = manifest.Entries.Count
            };
            await AllowListEvidenceWriter.WriteAsync(output, receipt, cancellationToken);
            return 0;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            await WriteReceiptAsync(output, "fixture-manifest", "failed", "FixtureGenerationFailed", null, null, cancellationToken);
            return 9;
        }
    }

    private static async Task<int> WriteUnknownCommandAsync(Stream output, CancellationToken cancellationToken)
    {
        await WriteReceiptAsync(output, "command", "failed", "UnknownCommand", null, null, cancellationToken);
        return 64;
    }

    private static Task WriteReceiptAsync(
        Stream output,
        string eventName,
        string status,
        string reasonCode,
        string? fileName,
        string? sha256,
        CancellationToken cancellationToken)
    {
        Dictionary<string, object?> receipt = new()
        {
            ["schemaVersion"] = 1,
            ["event"] = eventName,
            ["status"] = status,
            ["reasonCode"] = reasonCode,
            ["fileName"] = fileName,
            ["sha256"] = sha256
        };
        return AllowListEvidenceWriter.WriteAsync(output, receipt, cancellationToken);
    }

    private static async Task WriteTextAsync(Stream output, string text, CancellationToken cancellationToken)
    {
        await output.WriteAsync(System.Text.Encoding.UTF8.GetBytes(text + Environment.NewLine), cancellationToken);
    }

    private static int ExitCode(OracleReasonCode reasonCode) => reasonCode switch
    {
        OracleReasonCode.FileMissing => 2,
        OracleReasonCode.NotPortableExecutable => 3,
        OracleReasonCode.AuthenticodeInvalid => 4,
        OracleReasonCode.PublisherMismatch => 5,
        OracleReasonCode.IdentityMismatch => 6,
        OracleReasonCode.VersionNotApproved => 7,
        OracleReasonCode.ProbeFailed => 8,
        OracleReasonCode.Approved => 0,
        _ => 70
    };
}
