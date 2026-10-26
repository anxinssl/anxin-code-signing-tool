using System.Text;
using System.Text.Json;
using CodeSigner.Core.Diagnostics;

namespace CodeSigner.Core.Tests;

public sealed class SigningDiagnosticRedactorTests
{
    public static TheoryData<string, string> SensitiveTextCases => new()
    {
        { "sign failed --pin 749201", "749201" },
        { "password=credential-canary", "credential-canary" },
        { "passphrase: phrase-canary", "phrase-canary" },
        { "token=bearer-canary", "bearer-canary" },
        { "api_key=api-canary", "api-canary" },
        { "private-key=private-canary", "private-canary" },
        { "keyContainer=container-canary", "container-canary" },
        { "certificate=base64-certificate-canary", "base64-certificate-canary" },
        { "provider output: provider-transcript-canary", "provider-transcript-canary" },
        { "provider arguments: /p provider-arguments-canary /f code.pfx", "provider-arguments-canary" },
        { "commandLine: signtool.exe sign /p command-canary", "command-canary" },
        { "temporary JSON: {\"token\":\"temporary-json-canary\", \"note\":\"safe\"}", "temporary-json-canary" },
        { "sessionData=session-data-canary trailing-text", "session-data-canary" },
        { "private key material: private-material-canary trailing-text", "private-material-canary" },
        { "https://timestamp.example.invalid/rfc3161?token=query-canary#fragment-canary", "query-canary" }
    };

    [Theory]
    [MemberData(nameof(SensitiveTextCases))]
    public void SensitiveTextNeverEscapes(string input, string sensitiveLiteral)
    {
        string? redacted = SigningDiagnosticRedactor.RedactText(input);

        Assert.NotNull(redacted);
        Assert.DoesNotContain(sensitiveLiteral, redacted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("?", redacted, StringComparison.Ordinal);
        Assert.DoesNotContain("#", redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void RecursiveJsonMembersAreRedactedWithoutChangingSafeDiagnostics()
    {
        const string json = """
            {
              "diagnostic": {
                "hresult": "0x80004002",
                "hresultSymbol": "E_NOINTERFACE",
                "password": "nested-password-canary",
                "children": [
                  { "apiKey": "nested-api-canary" },
                  { "privateKey": "nested-key-canary" },
                  { "providerTranscript": "nested-provider-canary" }
                ]
              }
            }
            """;

        string? first = SigningDiagnosticRedactor.RedactJson(json);
        string? second = SigningDiagnosticRedactor.RedactJson(first);

        Assert.NotNull(first);
        Assert.Equal(first, second);
        Assert.DoesNotContain("nested-", first, StringComparison.Ordinal);
        Assert.Contains("0x80004002", first, StringComparison.Ordinal);
        Assert.Contains("E_NOINTERFACE", first, StringComparison.Ordinal);
        using JsonDocument document = JsonDocument.Parse(first);
        JsonElement diagnostic = document.RootElement.GetProperty("diagnostic");
        Assert.Equal(SigningDiagnosticRedactor.RedactedValue, diagnostic.GetProperty("password").GetString());
        Assert.All(
            diagnostic.GetProperty("children").EnumerateArray(),
            child => Assert.Equal(
                SigningDiagnosticRedactor.RedactedValue,
                child.EnumerateObject().Single().Value.GetString()));
    }

    [Fact]
    public void CommandTemporaryJsonSessionAndPrivateKeyMembersAreAlwaysRedacted()
    {
        const string json = """
            {
              "providerCommand": "signtool.exe sign /p command-pin-canary",
              "temporaryJson": "{\"token\":\"temporary-token-canary\"}",
              "sessionData": "session-data-canary",
              "certificatePrivateKey": "private-key-canary",
              "rawProviderTranscript": "provider-transcript-canary"
            }
            """;

        string? redacted = SigningDiagnosticRedactor.RedactJson(json);

        Assert.NotNull(redacted);
        Assert.DoesNotContain("command-pin-canary", redacted, StringComparison.Ordinal);
        Assert.DoesNotContain("temporary-token-canary", redacted, StringComparison.Ordinal);
        Assert.DoesNotContain("session-data-canary", redacted, StringComparison.Ordinal);
        Assert.DoesNotContain("private-key-canary", redacted, StringComparison.Ordinal);
        Assert.DoesNotContain("provider-transcript-canary", redacted, StringComparison.Ordinal);
        using JsonDocument document = JsonDocument.Parse(redacted);
        Assert.All(
            document.RootElement.EnumerateObject(),
            property => Assert.Equal(SigningDiagnosticRedactor.RedactedValue, property.Value.GetString()));
    }

    [Fact]
    public void SafeHresultDiagnosticTextRemainsUnchangedAndRedactionIsIdempotent()
    {
        const string safe = "SignerSignEx3 failed with 0x80004002 (E_NOINTERFACE).";

        string? first = SigningDiagnosticRedactor.RedactText(safe);

        Assert.Equal(safe, first);
        Assert.Equal(first, SigningDiagnosticRedactor.RedactText(first));
    }

    [Fact]
    public void AbsolutePathsRenderAsBasenameOnly()
    {
        const string path = "C:\\Users\\operator\\private\\fixture.exe";

        string? fileName = SigningDiagnosticRedactor.RedactFileName(path);
        string? text = SigningDiagnosticRedactor.RedactText("failed path=" + path);

        Assert.Equal("fixture.exe", fileName);
        Assert.NotNull(text);
        Assert.Contains("fixture.exe", text, StringComparison.Ordinal);
        Assert.DoesNotContain("operator", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("C:\\", text, StringComparison.Ordinal);
    }

    [Fact]
    public void UnsafeFileNameAndUnknownCommandUseTheFixedSafeOutput()
    {
        Assert.Equal(
            SigningDiagnosticRedactor.RedactedValue,
            SigningDiagnosticRedactor.RedactFileName("C:\\safe\\token=filename-canary.exe"));
        Assert.Equal(
            SigningDiagnosticRedactor.RedactedValue,
            SigningDiagnosticRedactor.RedactText(
                "signtool.exe sign /f C:\\keys\\code.pfx /p command-password-canary"));
    }

    [Fact]
    public void WorkerStderrTailIsExactlyBoundedAndReportsTruncationSeparately()
    {
        byte[] exact = Encoding.UTF8.GetBytes(new string('x', SigningDiagnosticRedactor.WorkerStderrTailCapacityBytes));
        RedactedDiagnosticText exactResult = SigningDiagnosticRedactor.RedactWorkerStderrTail(exact);

        Assert.False(exactResult.Truncated);
        Assert.Equal(SigningDiagnosticRedactor.WorkerStderrTailCapacityBytes, Encoding.UTF8.GetByteCount(exactResult.Value!));

        byte[] oversized = Encoding.UTF8.GetBytes(
            "discarded-prefix" + new string('y', SigningDiagnosticRedactor.WorkerStderrTailCapacityBytes));
        RedactedDiagnosticText oversizedResult = SigningDiagnosticRedactor.RedactWorkerStderrTail(oversized);

        Assert.True(oversizedResult.Truncated);
        Assert.Equal(new string('y', SigningDiagnosticRedactor.WorkerStderrTailCapacityBytes), oversizedResult.Value);
        Assert.Equal(
            SigningDiagnosticRedactor.WorkerStderrTailCapacityBytes,
            Encoding.UTF8.GetByteCount(oversizedResult.Value!));
    }

    [Fact]
    public void WorkerStderrTailNeverSplitsUtf8AndIsDeterministic()
    {
        byte[] input = Encoding.UTF8.GetBytes(new string('\u20ac', 3000));

        RedactedDiagnosticText first = SigningDiagnosticRedactor.RedactWorkerStderrTail(input);
        RedactedDiagnosticText second = SigningDiagnosticRedactor.RedactWorkerStderrTail(input);

        Assert.Equal(first, second);
        Assert.True(first.Truncated);
        Assert.InRange(
            Encoding.UTF8.GetByteCount(first.Value!),
            1,
            SigningDiagnosticRedactor.WorkerStderrTailCapacityBytes);
        Assert.All(first.Value!, character => Assert.Equal('\u20ac', character));
    }

    [Fact]
    public void WorkerStderrRedactionHappensBeforeTheTailLeavesCore()
    {
        byte[] input = Encoding.UTF8.GetBytes(
            "noise --pin stderr-pin-canary https://host.invalid/path?token=stderr-query-canary#fragment");

        RedactedDiagnosticText result = SigningDiagnosticRedactor.RedactWorkerStderrTail(input);

        Assert.False(result.Truncated);
        Assert.DoesNotContain("stderr-pin-canary", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("stderr-query-canary", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("?", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("#", result.Value, StringComparison.Ordinal);
    }
}
