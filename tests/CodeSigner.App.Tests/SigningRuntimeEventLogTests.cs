using System.IO;
using System.Reflection;
using System.Text.Json;
using CodeSigner.App.Services;
using CodeSigner.Core.Worker;

namespace CodeSigner.App.Tests;

public sealed class SigningRuntimeEventLogTests
{
    [Fact]
    public void DiagnosticSchemaCharacterizationReadsV1V2AndV3Entries()
    {
        string root = Path.Combine(
            Path.GetTempPath(),
            "CodeSigner-DiagnosticSchemaCharacterization-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            string path = Path.Combine(root, "schemas.jsonl");
            File.WriteAllLines(
                path,
                [
                    "{\"schemaVersion\":1,\"timestampUtc\":\"2026-07-29T00:00:00Z\",\"event\":\"batch-start\",\"itemId\":null,\"processId\":null,\"detail\":null}",
                    "{\"schemaVersion\":2,\"timestampUtc\":\"2026-07-29T00:00:01Z\",\"event\":\"worker-start-failed\",\"itemId\":null,\"processId\":null,\"detail\":null,\"reason\":\"missing\"}",
                    "{\"schemaVersion\":3,\"timestampUtc\":\"2026-07-29T00:00:02Z\",\"event\":\"batch-failed\",\"itemId\":\"7\",\"processId\":321,\"detail\":null,\"diagnosticPhase\":\"verifying\"}"
                ]);

            SigningRuntimeEvent[] entries = SigningRuntimeEventLog.ReadAll(path).ToArray();

            Assert.Equal([1, 2, 3], entries.Select(static entry => entry.SchemaVersion));
            Assert.Equal(WorkerDiagnosticPhases.Verifying, entries[2].DiagnosticPhase);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task JsonLinesPreserveOrderAndStallReferencesLastProcessStep()
    {
        string root = Path.Combine(
            Path.GetTempPath(),
            "CodeSigner-RuntimeEvents-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var log = new SigningRuntimeEventLog(root);

            log.Write(SigningRuntimeEventNames.BatchStart);
            log.Write(SigningRuntimeEventNames.WorkerStarting, "item-1");
            await log.MonitorForStallAsync(TimeSpan.FromMilliseconds(25), CancellationToken.None);

            string[] lines = await File.ReadAllLinesAsync(log.Path);
            Assert.Equal(3, lines.Length);
            using JsonDocument first = JsonDocument.Parse(lines[0]);
            using JsonDocument second = JsonDocument.Parse(lines[1]);
            using JsonDocument third = JsonDocument.Parse(lines[2]);
            Assert.Equal(3, first.RootElement.GetProperty("schemaVersion").GetInt32());
            Assert.Equal("batch-start", first.RootElement.GetProperty("event").GetString());
            Assert.Equal("worker-starting", second.RootElement.GetProperty("event").GetString());
            Assert.Equal(JsonValueKind.Null, second.RootElement.GetProperty("itemId").ValueKind);
            Assert.Equal("stall-detected", third.RootElement.GetProperty("event").GetString());
            Assert.Equal("worker-starting", third.RootElement.GetProperty("detail").GetString());
            Assert.Equal(SigningRuntimeEventNames.StallDetected, log.LastEvent?.Event);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Schema3WorkerLaunchFieldsAreAllowListedAndSchema1ReaderRemainsCompatible()
    {
        string root = Path.Combine(
            Path.GetTempPath(),
            "CodeSigner-RuntimeSchema-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            string legacyPath = Path.Combine(root, "legacy.jsonl");
            File.WriteAllText(
                legacyPath,
                "{\"schemaVersion\":1,\"timestampUtc\":\"2026-07-22T00:00:00Z\",\"event\":\"worker-start-failed\",\"itemId\":\"legacy\",\"processId\":null,\"detail\":null}\n");
            SigningRuntimeEvent legacyLog = Assert.Single(SigningRuntimeEventLog.ReadAll(legacyPath));
            Assert.Equal(1, legacyLog.SchemaVersion);
            Assert.Equal(SigningRuntimeEventNames.WorkerStartFailed, legacyLog.Event);
            Assert.Null(legacyLog.Reason);
            Assert.Null(legacyLog.RepairEligible);

            var log = new SigningRuntimeEventLog(root);
            WorkerLaunchDiagnostic diagnostic =
                WorkerLaunchDiagnosticMapper.ForReason(WorkerLaunchReason.Missing);
            Assert.True(log.Write(
                SigningRuntimeEventNames.WorkerStartFailed,
                "current",
                diagnostic: diagnostic));

            string line = Assert.Single(File.ReadAllLines(log.Path));
            using JsonDocument document = JsonDocument.Parse(line);
            JsonElement rootElement = document.RootElement;
            Assert.Equal(3, rootElement.GetProperty("schemaVersion").GetInt32());
            Assert.Equal("missing", rootElement.GetProperty("reason").GetString());
            Assert.True(rootElement.GetProperty("repairEligible").GetBoolean());
            string[] names = rootElement.EnumerateObject().Select(static property => property.Name).ToArray();
            Assert.DoesNotContain("exception", names);
            Assert.DoesNotContain("message", names);
            Assert.DoesNotContain("stackTrace", names);
            Assert.All(
                names,
                static name => Assert.True(
                    name is "schemaVersion" or "timestampUtc" or "event" or "itemId" or "processId" or
                        "detail" or "reason" or "repairEligible" or "hresult" or "nativeErrorCode" or "exitCode" or
                        "operationId" or "diagnosticId" or "diagnosticPhase" or "diagnosticLeg" or
                        "digestAlgorithm" or "appendSignature" or "nativeCall" or "signerSignEx3Flags" or
                        "nativeReasonCode" or "hresultHex" or "hresultSymbol" or "hresultOrigin" or
                        "legElapsedMilliseconds" or "workerProtocolVersion" or "workerExitCode" or
                        "workerStderrTail" or "workerStderrTruncated" or "failureSummary" or "responseCode" or
                        "subject" or "capability" or "engine" or "verification" or "detectedFormat" or
                        "contentProbeResult" or "requestedPolicy" or "effectivePolicy" or "selectedEngine" or
                        "legacyFallbackAttempt" or "sdkSignToolAvailable" or "sdkSignToolVersion" or
                        "sdkSignToolPathStatus" or "powerShellBridgeAvailability" or "providerFamily" or
                        "structuredStage" or "hresultClass" or "exitClass" or "finalVerification"));
            SigningRuntimeEvent current = Assert.Single(log.Read());
            Assert.Equal(3, current.SchemaVersion);
            Assert.Equal("missing", current.Reason);
            Assert.True(current.RepairEligible);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void HistoricalElevationReasonsRemainReadableAsRawStringsOnly()
    {
        string root = Path.Combine(
            Path.GetTempPath(),
            "CodeSigner-HistoricalRuntimeSchema-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            string historicalPath = Path.Combine(root, "historical.jsonl");
            File.WriteAllLines(
                historicalPath,
                [
                    "{\"schemaVersion\":2,\"timestampUtc\":\"2026-07-22T00:00:00Z\",\"event\":\"worker-start-failed\",\"itemId\":\"launcher\",\"processId\":null,\"detail\":null,\"reason\":\"launcher_elevated\",\"repairEligible\":false,\"hresult\":null,\"nativeErrorCode\":null,\"exitCode\":null}",
                    "{\"schemaVersion\":2,\"timestampUtc\":\"2026-07-22T00:00:01Z\",\"event\":\"worker-start-failed\",\"itemId\":\"worker\",\"processId\":null,\"detail\":null,\"reason\":\"worker_elevated\",\"repairEligible\":false,\"hresult\":null,\"nativeErrorCode\":null,\"exitCode\":null}"
                ]);

            SigningRuntimeEvent[] deserialized = SigningRuntimeEventLog.ReadAll(historicalPath).ToArray();
            string[] currentReasonCodes = Enum.GetValues<WorkerLaunchReason>()
                .Select(WorkerLaunchDiagnosticMapper.GetReasonCode)
                .ToArray();

            Assert.Equal(
                ["launcher_elevated", "worker_elevated"],
                deserialized.Select(static entry => entry.Reason));
            Assert.All(
                deserialized,
                entry => Assert.DoesNotContain(entry.Reason, currentReasonCodes));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ProductionProbeWritesExactSuccessAndTypedFailureEventsToOneJsonLinesFile()
    {
        string root = Path.Combine(
            Path.GetTempPath(),
            "CodeSigner-StartupProbeEvents-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            string applicationPath = Path.Combine(AppContext.BaseDirectory, "CodeSigner.App.exe");
            string workerPath = Path.Combine(
                ResolveRepositoryRoot(),
                "src",
                "CodeSigner.Worker",
                "bin",
#if DEBUG
                "Debug",
#else
                "Release",
#endif
                "net10.0-windows",
                "win-x64",
                "CodeSigner.Worker.exe");
            Assert.True(File.Exists(applicationPath));
            Assert.True(File.Exists(workerPath));
            var log = new SigningRuntimeEventLog(root);
            IWorkerHealthService healthyService = CreateProductionHealthService(
                applicationPath,
                workerPath,
                log);

            WorkerLaunchDiagnostic healthy = await healthyService.ProbeAsync(CancellationToken.None);

            Assert.Equal(WorkerLaunchReason.Healthy, healthy.Reason);
            string missingWorker = Path.Combine(root, "missing", "CodeSigner.Worker.exe");
            IWorkerHealthService missingService = CreateProductionHealthService(
                applicationPath,
                missingWorker,
                log);
            WorkerLaunchDiagnostic missing = await missingService.ProbeAsync(CancellationToken.None);
            SigningRuntimeEvent[] events = log.Read().ToArray();

            Assert.Equal(WorkerLaunchReason.Missing, missing.Reason);
            Assert.Equal(
                [
                    "worker-probe-start",
                    "worker-probe-succeeded",
                    "worker-probe-start",
                    "worker-probe-failed"
                ],
                events.Select(static entry => entry.Event));
            SigningRuntimeEvent failure = events[^1];
            Assert.Equal(missing.ReasonCode, failure.Reason);
            Assert.Equal(missing.RepairEligible, failure.RepairEligible);
            Assert.Equal(missing.HResult, failure.HResult);
            Assert.Equal(missing.NativeErrorCode, failure.NativeErrorCode);
            Assert.Equal(missing.ExitCode, failure.ExitCode);

            string json = await File.ReadAllTextAsync(log.Path);
            Assert.DoesNotContain("exception", json, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("stackTrace", json, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("providerTranscript", json, StringComparison.OrdinalIgnoreCase);
            Assert.All(events, static entry => Assert.Null(entry.WorkerStderrTail));

            string? evidenceDirectory = Environment.GetEnvironmentVariable("CODESIGNER_EVIDENCE_DIR");
            if (!string.IsNullOrWhiteSpace(evidenceDirectory))
            {
                evidenceDirectory = Path.GetFullPath(evidenceDirectory);
                Directory.CreateDirectory(evidenceDirectory);
                File.Copy(
                    log.Path,
                    Path.Combine(evidenceDirectory, "production-probe-success-failure.jsonl"),
                    overwrite: true);
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task NullOrUnwritableRuntimeLogNeverChangesTheProbeResult()
    {
        string root = Path.Combine(
            Path.GetTempPath(),
            "CodeSigner-UnwritableStartupProbe-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            string applicationPath = Path.Combine(AppContext.BaseDirectory, "CodeSigner.App.exe");
            string missingWorker = Path.Combine(root, "missing", "CodeSigner.Worker.exe");
            var unwritable = new SigningRuntimeEventLog(root);
            Directory.CreateDirectory(unwritable.Path);

            WorkerLaunchDiagnostic withoutLog = await CreateProductionHealthService(
                applicationPath,
                missingWorker,
                runtimeEventLog: null).ProbeAsync(CancellationToken.None);
            WorkerLaunchDiagnostic writeRejected = await CreateProductionHealthService(
                applicationPath,
                missingWorker,
                unwritable).ProbeAsync(CancellationToken.None);

            Assert.Equal(WorkerLaunchReason.Missing, withoutLog.Reason);
            Assert.Equal(WorkerLaunchReason.Missing, writeRejected.Reason);
            Assert.Empty(unwritable.Read());
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static IWorkerHealthService CreateProductionHealthService(
        string applicationPath,
        string workerPath,
        SigningRuntimeEventLog? runtimeEventLog)
    {
        object? service = Activator.CreateInstance(
            typeof(ProductionWorkerHealthService),
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            binder: null,
            args: [applicationPath, workerPath, runtimeEventLog],
            culture: null);
        return Assert.IsAssignableFrom<IWorkerHealthService>(service);
    }

    private static string ResolveRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "CodeSigner.sln")))
        {
            directory = directory.Parent;
        }

        return Assert.IsType<DirectoryInfo>(directory).FullName;
    }
}
