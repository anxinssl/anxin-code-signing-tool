using System.IO;
using System.Text.Json;
using CodeSigner.App.Services;

namespace CodeSigner.App.Tests;

public sealed partial class QueueInteractionAuditLogTests
{
    private static readonly string[] ExpectedEventNames =
    [
        "item-selected",
        "item-deselected",
        "preflight-started",
        "preflight-check-completed",
        "preflight-completed",
        "user-action-started",
        "user-action-completed",
        "user-action-rejected",
        "admission-started",
        "admission-completed",
        "detection-started",
        "detection-completed",
        "planning-started",
        "planning-completed"
    ];

    [Fact]
    public void QueueEventNamesAreIncludedInTheRuntimeAllowList()
    {
        Assert.All(ExpectedEventNames, eventName => Assert.Contains(eventName, SigningRuntimeEventNames.All));
    }

    [Fact]
    public void SchemaV5QueueEventsRoundTripWithOnlyAllowListedFields()
    {
        using var fixture = new QueueLogFixture();
        var log = new SigningRuntimeEventLog(fixture.Root);
        const string operationId = "0123456789abcdef0123456789abcdef";

        Assert.True(log.WriteQueueEvent(
            SigningRuntimeEventNames.PreflightStarted,
            "42",
            operationId,
            QueueAuditPhases.Preflight));
        Assert.True(log.WriteQueueEvent(
            SigningRuntimeEventNames.PreflightCheckCompleted,
            "42",
            operationId,
            QueueAuditPhases.Preflight,
            check: QueueAuditChecks.SourceIdentity,
            outcome: QueueAuditOutcomes.Passed));
        Assert.True(log.WriteQueueEvent(
            SigningRuntimeEventNames.PreflightCompleted,
            "42",
            operationId,
            QueueAuditPhases.Preflight,
            outcome: QueueAuditOutcomes.Ready));

        SigningRuntimeEvent[] entries = SigningRuntimeEventLog.ReadAll(log.Path).ToArray();
        Assert.Equal(3, entries.Length);
        Assert.All(entries, static entry => Assert.Equal(5, entry.SchemaVersion));
        Assert.All(entries, static entry => Assert.Equal(TimeSpan.Zero, entry.TimestampUtc.Offset));
        Assert.Equal(operationId, entries[1].OperationId);
        Assert.Equal(QueueAuditChecks.SourceIdentity, entries[1].Check);
        Assert.Equal(QueueAuditOutcomes.Passed, entries[1].Outcome);

        string[][] expectedProperties =
        [
            ["schemaVersion", "timestampUtc", "event", "itemId", "operationId", "phase"],
            ["schemaVersion", "timestampUtc", "event", "itemId", "operationId", "phase", "check", "outcome"],
            ["schemaVersion", "timestampUtc", "event", "itemId", "operationId", "phase", "outcome"]
        ];
        string[] lines = File.ReadAllLines(log.Path);
        for (int index = 0; index < lines.Length; index++)
        {
            using JsonDocument document = JsonDocument.Parse(lines[index]);
            Assert.Equal(
                expectedProperties[index],
                document.RootElement.EnumerateObject().Select(static property => property.Name));
        }

        QueueLogFixture.CopyEvidence(log.Path, "queue-schema-v5.jsonl");
    }

    [Fact]
    public void PreflightOperationAcceptsOneTerminalOutcomeOnly()
    {
        using var fixture = new QueueLogFixture();
        var log = new SigningRuntimeEventLog(fixture.Root);
        const string operationId = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        Assert.False(log.WriteQueueEvent(
            SigningRuntimeEventNames.PreflightCompleted,
            "7",
            operationId,
            QueueAuditPhases.Preflight,
            outcome: QueueAuditOutcomes.Blocked,
            reason: QueueAuditReasons.SourceUnavailable));
        Assert.True(log.WriteQueueEvent(
            SigningRuntimeEventNames.PreflightStarted,
            "7",
            operationId,
            QueueAuditPhases.Preflight));
        Assert.True(log.WriteQueueEvent(
            SigningRuntimeEventNames.PreflightCompleted,
            "7",
            operationId,
            QueueAuditPhases.Preflight,
            outcome: QueueAuditOutcomes.Blocked,
            reason: QueueAuditReasons.SourceUnavailable));
        Assert.False(log.WriteQueueEvent(
            SigningRuntimeEventNames.PreflightCompleted,
            "7",
            operationId,
            QueueAuditPhases.Preflight,
            outcome: QueueAuditOutcomes.Faulted,
            reason: QueueAuditReasons.UnexpectedFailure));

        Assert.Equal(2, log.Read().Count);
    }

    [Theory]
    [InlineData("item-7", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "preflight")]
    [InlineData("7", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "preflight")]
    [InlineData("7", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "preflight")]
    [InlineData("7", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "unknown-phase")]
    public void QueueWriteRejectsMalformedIdentifiersAndVocabulary(
        string itemId,
        string operationId,
        string phase)
    {
        using var fixture = new QueueLogFixture();
        var log = new SigningRuntimeEventLog(fixture.Root);

        Assert.False(log.WriteQueueEvent(
            SigningRuntimeEventNames.PreflightStarted,
            itemId,
            operationId,
            phase));
        Assert.Empty(log.Read());
    }

    [Fact]
    public void QueueWriteRejectsUnknownCheckActionAndOutcomeVocabulary()
    {
        using var fixture = new QueueLogFixture();
        var log = new SigningRuntimeEventLog(fixture.Root);
        const string preflightId = "dddddddddddddddddddddddddddddddd";
        const string actionId = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

        Assert.True(log.WriteQueueEvent(
            SigningRuntimeEventNames.PreflightStarted,
            "8",
            preflightId,
            QueueAuditPhases.Preflight));
        Assert.False(log.WriteQueueEvent(
            SigningRuntimeEventNames.PreflightCheckCompleted,
            "8",
            preflightId,
            QueueAuditPhases.Preflight,
            check: "source-path",
            outcome: QueueAuditOutcomes.Passed));
        Assert.False(log.WriteQueueEvent(
            SigningRuntimeEventNames.PreflightCompleted,
            "8",
            preflightId,
            QueueAuditPhases.Preflight,
            outcome: "mostly-ready"));
        Assert.False(log.WriteQueueEvent(
            SigningRuntimeEventNames.UserActionStarted,
            "8",
            actionId,
            QueueAuditPhases.UserAction,
            action: "open-provider-uri"));
        Assert.True(log.WriteQueueEvent(
            SigningRuntimeEventNames.UserActionStarted,
            "8",
            actionId,
            QueueAuditPhases.UserAction,
            action: QueueAuditActions.Sign));
        Assert.False(log.WriteQueueEvent(
            SigningRuntimeEventNames.UserActionCompleted,
            "8",
            actionId,
            QueueAuditPhases.UserAction,
            action: QueueAuditActions.Retry,
            outcome: QueueAuditOutcomes.Completed));

        Assert.Equal(2, log.Read().Count);
    }

    [Fact]
    public void UntrustedPathCertificatePinTokenUriAndProviderTextAreRejectedNotSerialized()
    {
        using var fixture = new QueueLogFixture();
        var log = new SigningRuntimeEventLog(fixture.Root);
        const string operationId = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        const string secret = "C:/secret/provider/cert.pfx?pin=1234&token=abcd&tsa=https://tsa.invalid";

        Assert.False(log.WriteQueueEvent(
            SigningRuntimeEventNames.UserActionRejected,
            "9",
            operationId,
            QueueAuditPhases.UserAction,
            action: QueueAuditActions.Sign,
            outcome: QueueAuditOutcomes.Rejected,
            reason: secret));
        Assert.True(log.WriteQueueEvent(
            SigningRuntimeEventNames.UserActionStarted,
            "9",
            operationId,
            QueueAuditPhases.UserAction,
            action: QueueAuditActions.Sign));
        Assert.True(log.WriteQueueEvent(
            SigningRuntimeEventNames.UserActionRejected,
            "9",
            operationId,
            QueueAuditPhases.UserAction,
            action: QueueAuditActions.Sign,
            outcome: QueueAuditOutcomes.Rejected,
            reason: QueueAuditReasons.InvalidState));

        string json = File.ReadAllText(log.Path);
        Assert.DoesNotContain(secret, json, StringComparison.Ordinal);
        Assert.DoesNotContain("cert.pfx", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("1234", json, StringComparison.Ordinal);
        Assert.DoesNotContain("abcd", json, StringComparison.Ordinal);
        Assert.DoesNotContain("tsa.invalid", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("provider/", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void UnwritableQueueLogReturnsFalseWithoutAdvancingTheContractState()
    {
        using var fixture = new QueueLogFixture();
        var log = new SigningRuntimeEventLog(fixture.Root);
        Directory.CreateDirectory(log.Path);

        Assert.False(log.WriteQueueEvent(
            SigningRuntimeEventNames.PreflightStarted,
            "11",
            "cccccccccccccccccccccccccccccccc",
            QueueAuditPhases.Preflight));
        Assert.Null(log.LastEvent);
        Assert.Empty(log.Read());
    }

    [Fact]
    public void QueueWritesDoNotChangeTheRuntimeStallObservation()
    {
        using var fixture = new QueueLogFixture();
        var log = new SigningRuntimeEventLog(fixture.Root);
        Assert.True(log.Write(SigningRuntimeEventNames.WorkerStarting, "12"));
        SigningRuntimeEvent? runtimeEvent = log.LastEvent;

        Assert.True(log.WriteQueueEvent(
            SigningRuntimeEventNames.ItemSelected,
            "12",
            "ffffffffffffffffffffffffffffffff",
            QueueAuditPhases.Selection));

        Assert.Same(runtimeEvent, log.LastEvent);
        Assert.Equal(2, log.Read().Count);
    }

    [Fact]
    public void LifecycleTerminalAppendFailureDoesNotAdvanceTheOperationState()
    {
        using var fixture = new QueueLogFixture();
        var log = new SigningRuntimeEventLog(fixture.Root);
        const string operationId = "44444444444444444444444444444444";

        Assert.True(log.WriteQueueEvent(
            SigningRuntimeEventNames.DetectionStarted,
            "13",
            operationId,
            QueueAuditPhases.Detection));

        using (new FileStream(log.Path, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            Assert.False(log.WriteQueueEvent(
                SigningRuntimeEventNames.DetectionCompleted,
                "13",
                operationId,
                QueueAuditPhases.Detection,
                outcome: QueueAuditOutcomes.Supported));
        }

        Assert.True(log.WriteQueueEvent(
            SigningRuntimeEventNames.DetectionCompleted,
            "13",
            operationId,
            QueueAuditPhases.Detection,
            outcome: QueueAuditOutcomes.Supported));
        Assert.False(log.WriteQueueEvent(
            SigningRuntimeEventNames.DetectionCompleted,
            "13",
            operationId,
            QueueAuditPhases.Detection,
            outcome: QueueAuditOutcomes.Supported));
        Assert.Equal(2, log.Read().Count);
    }

    private sealed class QueueLogFixture : IDisposable
    {
        public QueueLogFixture()
        {
            Root = Path.Combine(Path.GetTempPath(), "CodeSigner-QueueAudit-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
        }

        public string Root { get; }

        public static void CopyEvidence(string source, string fileName)
        {
            string? evidenceDirectory = Environment.GetEnvironmentVariable("CODESIGNER_EVIDENCE_DIR");
            if (string.IsNullOrWhiteSpace(evidenceDirectory))
            {
                return;
            }

            Directory.CreateDirectory(evidenceDirectory);
            File.Copy(source, Path.Combine(evidenceDirectory, fileName), overwrite: true);
        }

        public void Dispose() => Directory.Delete(Root, recursive: true);
    }
}
