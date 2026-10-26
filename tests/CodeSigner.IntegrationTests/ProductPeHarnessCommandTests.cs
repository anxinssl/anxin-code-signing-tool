using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CodeSigner.CompatibilityProbe.Signing;
using CodeSigner.Windows.Signing;

namespace CodeSigner.IntegrationTests;

public sealed class ProductPeHarnessCommandTests
{
    private const string Thumbprint = "00112233445566778899AABBCCDDEEFF00112233";
    private const string TimestampUri = "https://timestamp.example.test";

    [Theory]
    [InlineData("product-pe-single")]
    [InlineData("product-pe-dual")]
    [InlineData("product-pe-inspect")]
    public async Task ProductPeCommandsAreRoutedInsteadOfReportedUnknown(string command)
    {
        await using MemoryStream output = new();

        int exitCode = await CompatibilityProbeCli.RunAsync(
            [command],
            output,
            CancellationToken.None);

        using JsonDocument receipt = ParseReceipt(output);
        Assert.Equal(64, exitCode);
        Assert.Equal("InvalidArguments", receipt.RootElement.GetProperty("reasonCode").GetString());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SigningCommandsPreserveSourcePublishNewOutputAndEmitTypedInspection(bool dual)
    {
        using TestWorkspace workspace = TestWorkspace.Create();
        string sourceHash = Hash(workspace.SourcePath);
        var fixture = new InMemoryProductPeFixture();
        await using MemoryStream output = new();

        int exitCode = dual
            ? await ProductPeSigningCommands.RunDualAsync(
                Arguments("product-pe-dual", workspace), output, fixture.SignAsync, fixture.InspectAsync, CancellationToken.None)
            : await ProductPeSigningCommands.RunSingleAsync(
                Arguments("product-pe-single", workspace), output, fixture.SignAsync, fixture.InspectAsync, CancellationToken.None);

        using JsonDocument receipt = ParseReceipt(output);
        JsonElement root = receipt.RootElement;
        Assert.Equal(0, exitCode);
        Assert.Equal("passed", root.GetProperty("status").GetString());
        Assert.Equal(sourceHash, Hash(workspace.SourcePath));
        Assert.True(File.Exists(workspace.OutputPath));
        Assert.Equal(root.GetProperty("stagedSha256").GetString(), root.GetProperty("outputSha256").GetString());
        Assert.Equal(Hash(workspace.OutputPath), root.GetProperty("outputSha256").GetString());
        Assert.Equal(dual ? 2 : 1, fixture.SigningPlan?.Legs.Count);
        Assert.Equal(dual ? 2 : 1, root.GetProperty("signatures").GetArrayLength());
        Assert.Empty(workspace.StagingDirectories());
        Assert.Equal(0, fixture.Mssign32Calls);
        Assert.Equal(0, fixture.SipCalls);
        Assert.Equal(0, fixture.SdkSignToolCalls);

        IReadOnlyList<SignatureLeg> legs = Assert.IsAssignableFrom<IReadOnlyList<SignatureLeg>>(fixture.SigningPlan?.Legs);
        Assert.Equal(NativeDigestAlgorithm.Sha256, legs[^1].FileDigest);
        Assert.Equal(dual, legs[^1].Append);
        if (dual)
        {
            Assert.Equal(NativeDigestAlgorithm.Sha1, legs[0].FileDigest);
            Assert.False(legs[0].Append);
            Assert.Equal(legs[0].Certificate, legs[1].Certificate);
        }
    }

    [Fact]
    public async Task ExistingOutputIsRefusedBeforeSigningAndIsNotModified()
    {
        using TestWorkspace workspace = TestWorkspace.Create();
        await File.WriteAllTextAsync(workspace.OutputPath, "existing-output");
        string outputHash = Hash(workspace.OutputPath);
        var fixture = new InMemoryProductPeFixture();
        await using MemoryStream output = new();

        int exitCode = await ProductPeSigningCommands.RunSingleAsync(
            Arguments("product-pe-single", workspace), output, fixture.SignAsync, fixture.InspectAsync, CancellationToken.None);

        using JsonDocument receipt = ParseReceipt(output);
        Assert.Equal(1, exitCode);
        Assert.Equal(NativeSigningReasonCode.DestinationExists.ToString(), receipt.RootElement.GetProperty("reasonCode").GetString());
        Assert.Equal(outputHash, Hash(workspace.OutputPath));
        Assert.Equal(0, fixture.SigningCalls);
        Assert.Empty(workspace.StagingDirectories());
    }

    [Fact]
    public async Task SignedInputIsRejectedWithoutProviderOrFallbackCalls()
    {
        using TestWorkspace workspace = TestWorkspace.Create();
        PeImageCertificateTable.Append(workspace.SourcePath, [1, 2, 3, 4]);
        string sourceHash = Hash(workspace.SourcePath);
        var fixture = new InMemoryProductPeFixture();
        await using MemoryStream output = new();

        int exitCode = await ProductPeSigningCommands.RunSingleAsync(
            Arguments("product-pe-single", workspace), output, fixture.SignAsync, fixture.InspectAsync, CancellationToken.None);

        using JsonDocument receipt = ParseReceipt(output);
        Assert.Equal(1, exitCode);
        Assert.Equal(NativeSigningReasonCode.InvalidInput.ToString(), receipt.RootElement.GetProperty("reasonCode").GetString());
        Assert.Equal(sourceHash, Hash(workspace.SourcePath));
        Assert.False(File.Exists(workspace.OutputPath));
        Assert.Equal(0, fixture.SigningCalls);
        Assert.Equal(0, fixture.Mssign32Calls);
        Assert.Equal(0, fixture.SipCalls);
        Assert.Equal(0, fixture.SdkSignToolCalls);
        Assert.Empty(workspace.StagingDirectories());
    }

    [Theory]
    [InlineData("BAD", TimestampUri)]
    [InlineData(Thumbprint, "file:///timestamp")]
    public async Task MalformedCertificateOrTimestampIsRejectedBeforeFilesystemMutation(
        string thumbprint,
        string timestampUri)
    {
        using TestWorkspace workspace = TestWorkspace.Create();
        var fixture = new InMemoryProductPeFixture();
        await using MemoryStream output = new();
        string[] arguments =
        [
            "product-pe-single", workspace.SourcePath, workspace.OutputPath,
            "CurrentUser", "My", thumbprint, timestampUri
        ];

        int exitCode = await ProductPeSigningCommands.RunSingleAsync(
            arguments, output, fixture.SignAsync, fixture.InspectAsync, CancellationToken.None);

        using JsonDocument receipt = ParseReceipt(output);
        Assert.Equal(64, exitCode);
        Assert.Equal("InvalidArguments", receipt.RootElement.GetProperty("reasonCode").GetString());
        Assert.False(File.Exists(workspace.OutputPath));
        Assert.Equal(0, fixture.SigningCalls);
        Assert.Empty(workspace.StagingDirectories());
    }

    [Theory]
    [InlineData(NativeSigningReasonCode.CertificateHasNoPrivateKey, -2146893802)]
    [InlineData(NativeSigningReasonCode.TimestampUnavailable, -2147012721)]
    public async Task InjectedProviderOrTimestampFailureIsTypedAndCleansStaging(
        NativeSigningReasonCode reason,
        int hResult)
    {
        using TestWorkspace workspace = TestWorkspace.Create();
        string sourceHash = Hash(workspace.SourcePath);
        var fixture = new InMemoryProductPeFixture
        {
            SigningResult = NativeSigningResult.Failure(reason, hResult)
        };
        await using MemoryStream output = new();

        int exitCode = await ProductPeSigningCommands.RunSingleAsync(
            Arguments("product-pe-single", workspace), output, fixture.SignAsync, fixture.InspectAsync, CancellationToken.None);

        using JsonDocument receipt = ParseReceipt(output);
        JsonElement root = receipt.RootElement;
        Assert.Equal(1, exitCode);
        Assert.Equal(reason.ToString(), root.GetProperty("reasonCode").GetString());
        Assert.Equal(hResult, root.GetProperty("hResult").GetInt32());
        Assert.Equal($"0x{unchecked((uint)hResult):X8}", root.GetProperty("hResultHex").GetString());
        Assert.Equal(sourceHash, Hash(workspace.SourcePath));
        Assert.False(File.Exists(workspace.OutputPath));
        Assert.Empty(workspace.StagingDirectories());
        Assert.Equal(0, fixture.Mssign32Calls);
        Assert.Equal(0, fixture.SipCalls);
        Assert.Equal(0, fixture.SdkSignToolCalls);
    }

    [Fact]
    public async Task InspectIsReadOnlyAndEmitsSignerTimestampBindingAndTrustStatus()
    {
        using TestWorkspace workspace = TestWorkspace.Create();
        string sourceHash = Hash(workspace.SourcePath);
        var fixture = new InMemoryProductPeFixture();
        await using MemoryStream output = new();

        int exitCode = await ProductPeSigningCommands.RunInspectAsync(
            ["product-pe-inspect", workspace.SourcePath, "CurrentUser", "My", Thumbprint, "dual"],
            output,
            fixture.InspectAsync,
            CancellationToken.None);

        using JsonDocument receipt = ParseReceipt(output);
        JsonElement root = receipt.RootElement;
        Assert.Equal(0, exitCode);
        Assert.Equal(sourceHash, Hash(workspace.SourcePath));
        Assert.Equal(sourceHash, root.GetProperty("sourceSha256").GetString());
        Assert.Equal(sourceHash, root.GetProperty("stagedSha256").GetString());
        Assert.Equal(sourceHash, root.GetProperty("outputSha256").GetString());
        Assert.Equal(2, root.GetProperty("signatures").GetArrayLength());
        Assert.Equal(0, root.GetProperty("winVerifyTrustStatus").GetInt32());
        Assert.True(root.GetProperty("signatures")[1].GetProperty("rfc3161SignatureBinding").GetBoolean());
        Assert.Equal(0, fixture.SigningCalls);
    }

    [Fact]
    public async Task MalformedPeInputFailsTypedAndLeavesNoOutputOrStaging()
    {
        using TestWorkspace workspace = TestWorkspace.Create();
        await File.WriteAllTextAsync(workspace.SourcePath, "not-a-pe");
        string sourceHash = Hash(workspace.SourcePath);
        var fixture = new InMemoryProductPeFixture();
        await using MemoryStream output = new();

        int exitCode = await ProductPeSigningCommands.RunSingleAsync(
            Arguments("product-pe-single", workspace), output, fixture.SignAsync, fixture.InspectAsync, CancellationToken.None);

        using JsonDocument receipt = ParseReceipt(output);
        Assert.Equal(1, exitCode);
        Assert.Equal(NativeSigningReasonCode.InvalidInput.ToString(), receipt.RootElement.GetProperty("reasonCode").GetString());
        Assert.Equal(sourceHash, Hash(workspace.SourcePath));
        Assert.False(File.Exists(workspace.OutputPath));
        Assert.Equal(0, fixture.SigningCalls);
        Assert.Empty(workspace.StagingDirectories());
    }

    [Fact]
    public async Task MisleadingSuccessResultIsNormalizedAndCannotPublish()
    {
        using TestWorkspace workspace = TestWorkspace.Create();
        var fixture = new InMemoryProductPeFixture
        {
            SigningResult = new NativeSigningResult(true, NativeSigningReasonCode.TimestampUnavailable, 0)
        };
        await using MemoryStream output = new();

        int exitCode = await ProductPeSigningCommands.RunSingleAsync(
            Arguments("product-pe-single", workspace), output, fixture.SignAsync, fixture.InspectAsync, CancellationToken.None);

        using JsonDocument receipt = ParseReceipt(output);
        Assert.Equal(1, exitCode);
        Assert.Equal(NativeSigningReasonCode.NativeSigningFailed.ToString(), receipt.RootElement.GetProperty("reasonCode").GetString());
        Assert.False(File.Exists(workspace.OutputPath));
        Assert.Empty(workspace.StagingDirectories());
    }

    [Fact]
    public async Task UnownedStaleStagingDirectoryIsNeitherUsedNorDeleted()
    {
        using TestWorkspace workspace = TestWorkspace.Create();
        string staleDirectory = Path.Combine(workspace.Root, ".codesigner-staging-stale-state");
        Directory.CreateDirectory(staleDirectory);
        await File.WriteAllTextAsync(Path.Combine(staleDirectory, "foreign.txt"), "foreign");
        var fixture = new InMemoryProductPeFixture();
        await using MemoryStream output = new();

        int exitCode = await ProductPeSigningCommands.RunSingleAsync(
            Arguments("product-pe-single", workspace), output, fixture.SignAsync, fixture.InspectAsync, CancellationToken.None);

        Assert.Equal(0, exitCode);
        Assert.True(File.Exists(Path.Combine(staleDirectory, "foreign.txt")));
        Assert.Equal([staleDirectory], workspace.StagingDirectories());
    }

    [Fact]
    public async Task RepeatedCancellationLeavesNoOutputsOrOwnedStaging()
    {
        using TestWorkspace workspace = TestWorkspace.Create();
        var fixture = new InMemoryProductPeFixture();
        for (int attempt = 0; attempt < 2; attempt++)
        {
            using CancellationTokenSource cancellation = new();
            cancellation.Cancel();
            await using MemoryStream output = new();
            int exitCode = await ProductPeSigningCommands.RunSingleAsync(
                Arguments("product-pe-single", workspace), output, fixture.SignAsync, fixture.InspectAsync, cancellation.Token);

            using JsonDocument receipt = ParseReceipt(output);
            Assert.Equal(1, exitCode);
            Assert.Equal(NativeSigningReasonCode.Cancelled.ToString(), receipt.RootElement.GetProperty("reasonCode").GetString());
            Assert.False(File.Exists(workspace.OutputPath));
            Assert.Empty(workspace.StagingDirectories());
        }
        Assert.Equal(0, fixture.SigningCalls);
    }

    [Fact]
    public async Task FixtureCommandsWriteManualSingleDualAndInspectArtifactsWhenRequested()
    {
        string? evidenceDirectory = Environment.GetEnvironmentVariable("CODESIGNER_TASK2_EVIDENCE_DIR");
        if (string.IsNullOrWhiteSpace(evidenceDirectory))
        {
            return;
        }

        Directory.CreateDirectory(evidenceDirectory);
        using TestWorkspace workspace = TestWorkspace.Create();
        var fixture = new InMemoryProductPeFixture();
        await using MemoryStream singleReceipt = new();
        int singleExit = await ProductPeSigningCommands.RunSingleAsync(
            Arguments("product-pe-single", workspace), singleReceipt, fixture.SignAsync, fixture.InspectAsync, CancellationToken.None);
        Assert.Equal(0, singleExit);
        await File.WriteAllBytesAsync(Path.Combine(evidenceDirectory, "manual-single.json"), singleReceipt.ToArray());
        File.Copy(workspace.OutputPath, Path.Combine(evidenceDirectory, "manual-single-artifact.dll"), overwrite: true);

        File.Delete(workspace.OutputPath);
        await using MemoryStream dualReceipt = new();
        int dualExit = await ProductPeSigningCommands.RunDualAsync(
            Arguments("product-pe-dual", workspace), dualReceipt, fixture.SignAsync, fixture.InspectAsync, CancellationToken.None);
        Assert.Equal(0, dualExit);
        await File.WriteAllBytesAsync(Path.Combine(evidenceDirectory, "manual-dual.json"), dualReceipt.ToArray());
        File.Copy(workspace.OutputPath, Path.Combine(evidenceDirectory, "manual-dual-artifact.dll"), overwrite: true);

        await using MemoryStream inspectReceipt = new();
        int inspectExit = await ProductPeSigningCommands.RunInspectAsync(
            ["product-pe-inspect", workspace.OutputPath, "CurrentUser", "My", Thumbprint, "dual"],
            inspectReceipt,
            fixture.InspectAsync,
            CancellationToken.None);
        Assert.Equal(0, inspectExit);
        await File.WriteAllBytesAsync(Path.Combine(evidenceDirectory, "manual-inspect.json"), inspectReceipt.ToArray());

        Assert.Equal(0, fixture.Mssign32Calls);
        Assert.Equal(0, fixture.SipCalls);
        Assert.Equal(0, fixture.SdkSignToolCalls);
        byte[] counters = JsonSerializer.SerializeToUtf8Bytes(new
        {
            productPeSigningCalls = fixture.SigningCalls,
            productPeInspectionCalls = fixture.InspectionCalls,
            mssign32Calls = fixture.Mssign32Calls,
            sipCalls = fixture.SipCalls,
            sdkSignToolCalls = fixture.SdkSignToolCalls
        });
        await File.WriteAllBytesAsync(Path.Combine(evidenceDirectory, "manual-call-counters.json"), counters);
    }

    private static string[] Arguments(string command, TestWorkspace workspace) =>
    [
        command,
        workspace.SourcePath,
        workspace.OutputPath,
        "CurrentUser",
        "My",
        Thumbprint,
        TimestampUri
    ];

    private static JsonDocument ParseReceipt(MemoryStream output) =>
        JsonDocument.Parse(Encoding.UTF8.GetString(output.ToArray()));

    private static string Hash(string path) =>
        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

    private sealed class InMemoryProductPeFixture
    {
        public NativeSigningResult SigningResult { get; init; } = NativeSigningResult.Success();

        public int SigningCalls { get; private set; }

        public int InspectionCalls { get; private set; }

        public int Mssign32Calls { get; private set; }

        public int SipCalls { get; private set; }

        public int SdkSignToolCalls { get; private set; }

        public ProductionNativeSigningPlan? SigningPlan { get; private set; }

        public async Task<NativeSigningResult> SignAsync(
            string stagedPath,
            ProductionNativeSigningPlan plan,
            CancellationToken cancellationToken)
        {
            SigningCalls++;
            SigningPlan = plan;
            if (SigningResult.Succeeded)
            {
                await File.AppendAllTextAsync(stagedPath, $"fixture-signatures:{plan.Legs.Count}", cancellationToken);
            }
            return SigningResult;
        }

        public Task<ProductPeInspection> InspectAsync(
            string path,
            ProductionNativeSigningPlan plan,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            InspectionCalls++;
            ProductPeSignatureInspection[] signatures = plan.Legs
                .Select(static (leg, index) => new ProductPeSignatureInspection(
                    index,
                    leg.FileDigest.ToString(),
                    leg.Certificate.Thumbprint,
                    1,
                    NativeDigestAlgorithm.Sha256.ToString(),
                    true))
                .ToArray();
            return Task.FromResult(new ProductPeInspection(NativeSigningResult.Success(), signatures, 0));
        }
    }

    private sealed class TestWorkspace : IDisposable
    {
        private TestWorkspace(string root, string sourcePath, string outputPath)
        {
            Root = root;
            SourcePath = sourcePath;
            OutputPath = outputPath;
        }

        public string Root { get; }

        public string SourcePath { get; }

        public string OutputPath { get; }

        public static TestWorkspace Create()
        {
            string root = Path.Combine(Path.GetTempPath(), $"codesigner-product-pe-{Guid.NewGuid():N}");
            Directory.CreateDirectory(root);
            string source = Path.Combine(root, "source.dll");
            File.Copy(typeof(ProductPeSigningCommands).Assembly.Location, source, overwrite: false);
            return new TestWorkspace(root, source, Path.Combine(root, "output.dll"));
        }

        public string[] StagingDirectories() =>
            Directory.GetDirectories(Root, ".codesigner-staging-*", SearchOption.TopDirectoryOnly);

        public void Dispose()
        {
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }
    }
}
