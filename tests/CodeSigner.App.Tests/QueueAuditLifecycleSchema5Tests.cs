using System.IO;
using System.Text.Json;
using CodeSigner.App.Services;

namespace CodeSigner.App.Tests;

public sealed partial class QueueInteractionAuditLogTests
{
    [Fact]
    public void ActionVocabularyRemainsTheExactThirteenUserActions()
    {
        string[] actions = typeof(QueueAuditActions)
            .GetFields(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)
            .Where(static field => field.FieldType == typeof(string))
            .Select(static field => (string)field.GetRawConstantValue()!)
            .OrderBy(static action => action, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(
            [
                "cancel", "current-deselection", "current-selection", "mode-change", "output-replan",
                "primary-certificate-role-change", "re-add", "readiness-refresh", "remove", "retry",
                "secondary-certificate-role-change", "sign", "timestamp-settings-apply"
            ],
            actions);
    }

    [Fact]
    public void SchemaReadersAcceptVersionsOneThroughFive()
    {
        using var fixture = new QueueAuditLifecycleFixture();
        string path = Path.Combine(fixture.Root, "legacy-and-current.jsonl");
        File.WriteAllLines(
            path,
            [
                "{\"schemaVersion\":1,\"timestampUtc\":\"2026-08-07T00:00:00Z\",\"event\":\"batch-start\",\"itemId\":null,\"processId\":null,\"detail\":null}",
                "{\"schemaVersion\":2,\"timestampUtc\":\"2026-08-07T00:00:01Z\",\"event\":\"batch-failed\",\"itemId\":null,\"processId\":null,\"detail\":null}",
                "{\"schemaVersion\":3,\"timestampUtc\":\"2026-08-07T00:00:02Z\",\"event\":\"batch-completed\",\"itemId\":null,\"processId\":null,\"detail\":null}",
                "{\"schemaVersion\":4,\"timestampUtc\":\"2026-08-07T00:00:03Z\",\"event\":\"preflight-started\",\"itemId\":\"7\",\"operationId\":\"0123456789abcdef0123456789abcdef\",\"phase\":\"preflight\"}",
                "{\"schemaVersion\":5,\"timestampUtc\":\"2026-08-07T00:00:04Z\",\"event\":\"admission-started\",\"itemId\":null,\"operationId\":\"fedcba9876543210fedcba9876543210\",\"phase\":\"admission\"}"
            ]);

        SigningRuntimeEvent[] entries = SigningRuntimeEventLog.ReadAll(path).ToArray();

        Assert.Equal([1, 2, 3, 4, 5], entries.Select(static entry => entry.SchemaVersion));
        Assert.Null(entries[4].ItemId);
        Assert.Equal(QueueAuditPhases.Admission, entries[4].Phase);
    }

    [Fact]
    public void AdmissionDetectionAndPlanningRequireMatchedStartAndAllowOnlyOneTerminal()
    {
        using var fixture = new QueueAuditLifecycleFixture();
        var log = new SigningRuntimeEventLog(fixture.Root);
        const string admissionOperation = "0123456789abcdef0123456789abcdef";
        const string detectionOperation = "11111111111111111111111111111111";
        const string planningOperation = "22222222222222222222222222222222";

        Assert.False(log.WriteQueueEvent(
            SigningRuntimeEventNames.AdmissionCompleted,
            null,
            admissionOperation,
            QueueAuditPhases.Admission,
            outcome: QueueAuditOutcomes.Accepted));
        Assert.False(log.WriteQueueEvent(
            SigningRuntimeEventNames.AdmissionStarted,
            "7",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            QueueAuditPhases.Admission));
        Assert.True(log.WriteQueueEvent(
            SigningRuntimeEventNames.AdmissionStarted,
            null,
            admissionOperation,
            QueueAuditPhases.Admission));
        Assert.True(log.WriteQueueEvent(
            SigningRuntimeEventNames.AdmissionCompleted,
            null,
            admissionOperation,
            QueueAuditPhases.Admission,
            outcome: QueueAuditOutcomes.Partial));
        Assert.False(log.WriteQueueEvent(
            SigningRuntimeEventNames.AdmissionCompleted,
            null,
            admissionOperation,
            QueueAuditPhases.Admission,
            outcome: QueueAuditOutcomes.Rejected));

        Assert.True(log.WriteQueueEvent(
            SigningRuntimeEventNames.DetectionStarted,
            "7",
            detectionOperation,
            QueueAuditPhases.Detection));
        Assert.False(log.WriteQueueEvent(
            SigningRuntimeEventNames.DetectionStarted,
            null,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            QueueAuditPhases.Detection));
        Assert.False(log.WriteQueueEvent(
            SigningRuntimeEventNames.DetectionCompleted,
            "8",
            detectionOperation,
            QueueAuditPhases.Detection,
            outcome: QueueAuditOutcomes.Supported));
        Assert.True(log.WriteQueueEvent(
            SigningRuntimeEventNames.DetectionCompleted,
            "7",
            detectionOperation,
            QueueAuditPhases.Detection,
            outcome: QueueAuditOutcomes.Supported));

        Assert.True(log.WriteQueueEvent(
            SigningRuntimeEventNames.PlanningStarted,
            "7",
            planningOperation,
            QueueAuditPhases.Planning));
        Assert.True(log.WriteQueueEvent(
            SigningRuntimeEventNames.PlanningCompleted,
            "7",
            planningOperation,
            QueueAuditPhases.Planning,
            outcome: QueueAuditOutcomes.Ready));

        Assert.Equal(6, log.Read().Count);
        QueueLogFixture.CopyEvidence(log.Path, "queue-schema-v5-lifecycle.jsonl");
    }

    [Fact]
    public void LifecyclePayloadRejectsSecretsAndContainsOnlyAllowListedFields()
    {
        using var fixture = new QueueAuditLifecycleFixture();
        var log = new SigningRuntimeEventLog(fixture.Root);
        const string operationId = "33333333333333333333333333333333";
        const string forbidden = "C:/secret/source.exe rel/path fingerprint=abc hash=deadbeef message=pin=9231 exception=token";

        Assert.False(log.WriteQueueEvent(
            SigningRuntimeEventNames.DetectionStarted,
            forbidden,
            operationId,
            QueueAuditPhases.Detection));
        Assert.True(log.WriteQueueEvent(
            SigningRuntimeEventNames.DetectionStarted,
            "9",
            operationId,
            QueueAuditPhases.Detection));
        Assert.False(log.WriteQueueEvent(
            SigningRuntimeEventNames.DetectionCompleted,
            "9",
            operationId,
            QueueAuditPhases.Detection,
            outcome: QueueAuditOutcomes.Blocked,
            reason: forbidden));
        Assert.True(log.WriteQueueEvent(
            SigningRuntimeEventNames.DetectionCompleted,
            "9",
            operationId,
            QueueAuditPhases.Detection,
            outcome: QueueAuditOutcomes.Blocked,
            reason: QueueAuditReasons.UnsupportedFormat));

        string[] lines = File.ReadAllLines(log.Path);
        Assert.All(lines, line =>
        {
            using JsonDocument document = JsonDocument.Parse(line);
            string[] allowedProperties =
            [
                "schemaVersion", "timestampUtc", "event", "itemId", "operationId", "phase", "check", "action",
                "outcome", "reason"
            ];
            Assert.All(
                document.RootElement.EnumerateObject(),
                property => Assert.Contains(property.Name, allowedProperties));
        });
        string json = File.ReadAllText(log.Path);
        Assert.DoesNotContain(forbidden, json, StringComparison.Ordinal);
        Assert.DoesNotContain("fingerprint", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("deadbeef", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("pin=9231", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("exception=", json, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class QueueAuditLifecycleFixture : IDisposable
    {
        public QueueAuditLifecycleFixture()
        {
            Root = Path.Combine(Path.GetTempPath(), "CodeSigner-QueueAuditSchema5-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
        }

        public string Root { get; }

        public void Dispose() => Directory.Delete(Root, recursive: true);
    }
}
