using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Reflection;
using System.Text;
using System.Text.Json;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;

namespace CodeSigner.IntegrationTests;

public sealed class WorkerLaunchDiagnosticTests
{
    private const string Task5CandidateSha256 =
        "1111111111111111111111111111111111111111111111111111111111111111";

    [Fact]
    public void EveryReasonHasTheExactStableCodeAndRepairEligibility()
    {
        (WorkerLaunchReason Reason, string Code, WorkerRepairEligibility Repair)[] cases =
        [
            (WorkerLaunchReason.Healthy, "healthy", WorkerRepairEligibility.NotEligible),
            (WorkerLaunchReason.Missing, "missing", WorkerRepairEligibility.Eligible),
            (WorkerLaunchReason.InvalidImage, "invalid_image", WorkerRepairEligibility.Eligible),
            (WorkerLaunchReason.VersionMismatch, "version_mismatch", WorkerRepairEligibility.Eligible),
            (WorkerLaunchReason.AccessDenied, "access_denied", WorkerRepairEligibility.NotEligible),
            (WorkerLaunchReason.StartFailed, "start_failed", WorkerRepairEligibility.NotEligible),
            (WorkerLaunchReason.UserMismatch, "user_mismatch", WorkerRepairEligibility.NotEligible),
            (WorkerLaunchReason.SessionMismatch, "session_mismatch", WorkerRepairEligibility.NotEligible),
            (WorkerLaunchReason.MissingUserSid, "missing_user_sid", WorkerRepairEligibility.NotEligible),
            (WorkerLaunchReason.Timeout, "timeout", WorkerRepairEligibility.NotEligible),
            (WorkerLaunchReason.Crashed, "crashed", WorkerRepairEligibility.NotEligible),
            (WorkerLaunchReason.ProtocolMismatch, "protocol_mismatch", WorkerRepairEligibility.NotEligible),
            (WorkerLaunchReason.InvalidFrame, "invalid_frame", WorkerRepairEligibility.NotEligible)
        ];

        Assert.Equal(cases.Select(testCase => testCase.Reason), Enum.GetValues<WorkerLaunchReason>());
        foreach ((WorkerLaunchReason reason, string code, WorkerRepairEligibility repair) in cases)
        {
            WorkerLaunchDiagnostic diagnostic = WorkerLaunchDiagnosticMapper.ForReason(reason);

            Assert.Equal(code, diagnostic.ReasonCode);
            Assert.Equal(repair, diagnostic.RepairEligibility);
            Assert.Equal(repair == WorkerRepairEligibility.Eligible, diagnostic.RepairEligible);
            Assert.Null(diagnostic.HResult);
            Assert.Null(diagnostic.NativeErrorCode);
            Assert.Null(diagnostic.ExitCode);
        }
    }

    [Fact]
    public void LaunchExceptionsMapWithoutCarryingArbitraryTextOrSecrets()
    {
        const string secret = "pin=do-not-copy-this";
        (Exception Error, WorkerLaunchReason Reason, int? NativeError, int? ExitCode)[] cases =
        [
            (new FileNotFoundException(secret), WorkerLaunchReason.Missing, 2, null),
            (new Win32Exception(2, secret), WorkerLaunchReason.Missing, 2, null),
            (new Win32Exception(3, secret), WorkerLaunchReason.Missing, 3, null),
            (new Win32Exception(5, secret), WorkerLaunchReason.AccessDenied, 5, null),
            (new Win32Exception(193, secret), WorkerLaunchReason.InvalidImage, 193, null),
            (new Win32Exception(216, secret), WorkerLaunchReason.InvalidImage, 216, null),
            (new Win32Exception(87, secret), WorkerLaunchReason.StartFailed, 87, null),
            (new WorkerProcessSecurityException("user_mismatch"), WorkerLaunchReason.UserMismatch, null, null),
            (new WorkerProcessSecurityException("session_mismatch"), WorkerLaunchReason.SessionMismatch, null, null),
            (new WorkerProcessSecurityException("missing_user_sid"), WorkerLaunchReason.MissingUserSid, null, null),
            (new WorkerProcessTimeoutException(), WorkerLaunchReason.Timeout, null, null),
            (new WorkerProcessCrashedException(23), WorkerLaunchReason.Crashed, null, 23),
            (new WorkerProtocolException(WorkerResponseCodes.ProtocolVersionMismatch, secret), WorkerLaunchReason.ProtocolMismatch, null, null),
            (new WorkerProtocolException(WorkerResponseCodes.InvalidFrame, secret), WorkerLaunchReason.InvalidFrame, null, null),
            (new WorkerProtocolException(WorkerResponseCodes.FrameTooLarge, secret), WorkerLaunchReason.InvalidFrame, null, null),
            (new InvalidOperationException(secret), WorkerLaunchReason.StartFailed, null, null)
        ];

        foreach ((Exception error, WorkerLaunchReason reason, int? nativeError, int? exitCode) in cases)
        {
            WorkerLaunchDiagnostic diagnostic = WorkerLaunchDiagnosticMapper.FromException(error);
            string json = JsonSerializer.Serialize(diagnostic);

            Assert.Equal(reason, diagnostic.Reason);
            Assert.Equal(nativeError, diagnostic.NativeErrorCode);
            Assert.Equal(exitCode, diagnostic.ExitCode);
            Assert.DoesNotContain(secret, json, StringComparison.Ordinal);
            Assert.DoesNotContain("Message", json, StringComparison.Ordinal);
            Assert.DoesNotContain("StackTrace", json, StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("LauncherElevated", "launcher_elevated")]
    [InlineData("WorkerElevated", "worker_elevated")]
    public void HistoricalElevationReasonsAreNotCurrentTypedStates(
        string typedName,
        string historicalCode)
    {
        Assert.False(Enum.TryParse(typedName, ignoreCase: false, out WorkerLaunchReason _));

        WorkerLaunchDiagnostic diagnostic = WorkerLaunchDiagnosticMapper.FromException(
            new WorkerProcessSecurityException(historicalCode));

        Assert.Equal(WorkerLaunchReason.StartFailed, diagnostic.Reason);
        Assert.Equal("start_failed", diagnostic.ReasonCode);
    }

    [Fact]
    public void ProbeResultRequiresReadySuccessAndExitZero()
    {
        (WorkerResponse Response, int ExitCode, WorkerLaunchReason Reason)[] cases =
        [
            (new WorkerResponse(WorkerProtocol.Version, true, WorkerResponseCodes.Ready), 0, WorkerLaunchReason.Healthy),
            (new WorkerResponse(WorkerProtocol.Version, true, WorkerResponseCodes.SigningCompleted), 0, WorkerLaunchReason.InvalidFrame),
            (new WorkerResponse(WorkerProtocol.Version, true, WorkerResponseCodes.Ready), 2, WorkerLaunchReason.InvalidFrame),
            (new WorkerResponse(WorkerProtocol.Version, false, WorkerResponseCodes.Ready), 0, WorkerLaunchReason.InvalidFrame),
            (new WorkerResponse(WorkerProtocol.Version, false, WorkerResponseCodes.ProtocolVersionMismatch), 2, WorkerLaunchReason.ProtocolMismatch),
            (new WorkerResponse(WorkerProtocol.Version, false, WorkerResponseCodes.InvalidFrame), 2, WorkerLaunchReason.InvalidFrame)
        ];

        foreach ((WorkerResponse response, int exitCode, WorkerLaunchReason reason) in cases)
        {
            WorkerProcessResult result = new(response, 1234, exitCode);
            WorkerLaunchDiagnostic diagnostic = WorkerLaunchDiagnosticMapper.FromProbeResult(result);

            Assert.Equal(reason, diagnostic.Reason);
            Assert.Equal(exitCode, diagnostic.ExitCode);
        }
    }

    [Fact]
    public async Task VersionMismatchStopsBeforeAnyWorkerLaunch()
    {
        using TemporaryFiles fixture = TemporaryFiles.Create();
        int launches = 0;
        var probe = new WorkerHealthProbe(
            fixture.ApplicationPath,
            fixture.WorkerPath,
            path => path == fixture.ApplicationPath ? "2.0.0.0" : "1.0.0.0",
            (_, _) =>
            {
                launches++;
                throw new InvalidOperationException("The stale Worker must not launch.");
            });

        WorkerLaunchDiagnostic diagnostic = await probe.ProbeAsync(CancellationToken.None);

        Assert.Equal(WorkerLaunchReason.VersionMismatch, diagnostic.Reason);
        Assert.True(diagnostic.RepairEligible);
        Assert.Equal(0, launches);
    }

    [Fact]
    public async Task HealthProbeUsesTheExactFiveSecondDeadline()
    {
        using TemporaryFiles fixture = TemporaryFiles.Create();
        TimeSpan observedTimeout = default;
        var probe = new WorkerHealthProbe(
            fixture.ApplicationPath,
            fixture.WorkerPath,
            _ => "1.0.0.0",
            (timeout, _) =>
            {
                observedTimeout = timeout;
                return Task.FromResult(new WorkerProcessResult(
                    new WorkerResponse(WorkerProtocol.Version, true, WorkerResponseCodes.Ready),
                    4321,
                    0));
            });

        WorkerLaunchDiagnostic diagnostic = await probe.ProbeAsync(CancellationToken.None);

        Assert.Equal(TimeSpan.FromSeconds(5), observedTimeout);
        Assert.Equal(WorkerLaunchReason.Healthy, diagnostic.Reason);
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task RealPublishedWorkerProbeIsHealthyAndLeavesNoProcess()
    {
        WorkerProcessClient client = new(WorkerPath());

        WorkerProcessResult result = await client.ProbeAsync(CancellationToken.None);

        Assert.True(result.Response.Success);
        Assert.Equal(WorkerResponseCodes.Ready, result.Response.Code);
        Assert.Equal(0, result.ExitCode);
        Assert.False(IsProcessRunning(result.ProcessId));
    }

    [Fact]
    public async Task HungChildTreeMapsToTimeoutAndLeavesNoProcesses()
    {
        using TemporaryFiles fixture = TemporaryFiles.Create();
        string pidReceipt = Path.Combine(fixture.Root, "hung-pids.txt");
        string escapedReceipt = pidReceipt.Replace("'", "''", StringComparison.Ordinal);
        string script =
            "$child=Start-Process $env:SystemRoot\\System32\\ping.exe " +
            "-ArgumentList @('127.0.0.1','-n','30') -PassThru -WindowStyle Hidden; " +
            $"[IO.File]::WriteAllLines('{escapedReceipt}',[string[]]@([string]$PID,[string]$child.Id)); " +
            "[Threading.Thread]::Sleep(30000)";
        WorkerProcessClient client = CreatePowerShellClient(script);
        var probe = new WorkerHealthProbe(
            fixture.ApplicationPath,
            fixture.WorkerPath,
            _ => "1.0.0.0",
            client.ProbeAsync);

        WorkerLaunchDiagnostic diagnostic = await probe.ProbeAsync(CancellationToken.None);
        string[] processIds = await ReadFileReceiptAsync(pidReceipt);

        Assert.Equal(WorkerLaunchReason.Timeout, diagnostic.Reason);
        Assert.All(processIds, value => Assert.False(IsProcessRunning(int.Parse(value, System.Globalization.CultureInfo.InvariantCulture))));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public async Task RepeatedCancellationTerminatesExactWorkerProcessTree(int attempt)
    {
        using TemporaryFiles fixture = TemporaryFiles.Create();
        string pipeName = $"CodeSigner-cancelled-pids-{attempt}-{Guid.NewGuid():N}";
        using var receiptPipe = new NamedPipeServerStream(
            pipeName,
            PipeDirection.In,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        string escapedPipeName = pipeName.Replace("'", "''", StringComparison.Ordinal);
        string script =
            "$child=Start-Process $env:SystemRoot\\System32\\ping.exe " +
            "-ArgumentList @('127.0.0.1','-n','30') -PassThru -WindowStyle Hidden; " +
            $"$pipe=[IO.Pipes.NamedPipeClientStream]::new('.','{escapedPipeName}',[IO.Pipes.PipeDirection]::Out); " +
            "$pipe.Connect(5000); $writer=[IO.StreamWriter]::new($pipe); " +
            "$writer.WriteLine(([string]$PID)+','+([string]$child.Id)); " +
            "$writer.Dispose(); $pipe.Dispose(); " +
            "[Threading.Thread]::Sleep(30000)";
        WorkerProcessClient client = CreatePowerShellClient(script);
        var probe = new WorkerHealthProbe(
            fixture.ApplicationPath,
            fixture.WorkerPath,
            _ => "1.0.0.0",
            client.ProbeAsync);
        using CancellationTokenSource cancellation = new();

        Task<WorkerLaunchDiagnostic> probeTask = probe.ProbeAsync(cancellation.Token);
        string[] processIds = [];
        try
        {
            processIds = await ReceiveProcessIdsAsync(receiptPipe, probeTask);
            cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await probeTask);
        }
        finally
        {
            cancellation.Cancel();
            try
            {
                await probeTask;
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
            {
            }

            Assert.All(
                processIds,
                value => Assert.False(IsProcessRunning(
                    int.Parse(value, System.Globalization.CultureInfo.InvariantCulture))));
        }
    }

    [Fact]
    public async Task MalformedTruncatedOversizedAndEofHostsMapExactlyAndExit()
    {
        (byte[]? Frame, int ExitCode, WorkerLaunchReason Reason)[] cases =
        [
            (CreateHeader(-1), 2, WorkerLaunchReason.InvalidFrame),
            (CreateTruncatedFrame(), 2, WorkerLaunchReason.InvalidFrame),
            (CreateHeader(WorkerProtocol.MaxPayloadBytes + 1), 2, WorkerLaunchReason.InvalidFrame),
            (CreateResponseFrame(WorkerProtocol.Version + 1, false, WorkerResponseCodes.ProtocolVersionMismatch), 2, WorkerLaunchReason.ProtocolMismatch),
            (CreateIncompleteResponseFrame(WorkerProtocol.Version + 1, false, WorkerResponseCodes.ProtocolVersionMismatch), 2, WorkerLaunchReason.InvalidFrame),
            (CreateResponseFrame(WorkerProtocol.Version, true, WorkerResponseCodes.SigningCompleted), 0, WorkerLaunchReason.InvalidFrame),
            (null, 7, WorkerLaunchReason.Crashed)
        ];

        foreach ((byte[]? frame, int exitCode, WorkerLaunchReason reason) in cases)
        {
            using TemporaryFiles fixture = TemporaryFiles.Create();
            WorkerProcessClient client = frame is null
                ? CreatePowerShellClient("exit 7")
                : CreatePowerShellClient(CreateFrameWriterScript(frame, exitCode));
            var probe = new WorkerHealthProbe(
                fixture.ApplicationPath,
                fixture.WorkerPath,
                _ => "1.0.0.0",
                client.ProbeAsync);

            WorkerLaunchDiagnostic diagnostic = await probe.ProbeAsync(CancellationToken.None);

            Assert.Equal(reason, diagnostic.Reason);
        }
    }

    [Theory]
    [InlineData(WorkerSigningOutcome.Signed)]
    [InlineData(WorkerSigningOutcome.SkippedExistingSignature)]
    [InlineData(WorkerSigningOutcome.Failure)]
    public async Task WorkerProcessSessionRejectsMismatchedOperationIdWithoutPublishingOrAttributingResponse(
        WorkerSigningOutcome outcome)
    {
        WorkerRequest request = CreateSigningRequest();
        WorkerResponse response = CreateSigningResponse(outcome, request, "fedcba9876543210fedcba9876543210");
        byte[] frame = await CreateResponseFrameAsync(response);
        await using WorkerProcessSession session = CreatePowerShellSession(CreateSessionFrameWriterScript(frame));
        int processId = session.ProcessId;
        WorkerSessionResult? trustedResult = null;

        WorkerProtocolException error = await Assert.ThrowsAsync<WorkerProtocolException>(async () =>
        {
            trustedResult = await session.SendAsync(
                request,
                TimeSpan.FromSeconds(5),
                onProgress: null,
                CancellationToken.None);
        });

        Assert.Equal(WorkerResponseCodes.InvalidFrame, error.Code);
        Assert.Null(trustedResult);
        Assert.False(session.IsRunning);
        Assert.False(IsProcessRunning(processId));
        await Assert.ThrowsAsync<WorkerProcessCrashedException>(() => session.SendAsync(
            request,
            TimeSpan.FromSeconds(5),
            onProgress: null,
            CancellationToken.None));
    }

    [Fact]
    public async Task WorkerProcessSessionUsesUniqueTransportIdForRetryAndRestoresLogicalOperationId()
    {
        using TemporaryFiles fixture = TemporaryFiles.Create();
        string receiptPath = Path.Combine(fixture.Root, "retry-operation-ids.txt");
        WorkerRequest request = CreateSigningRequest();
        WorkerResponse response = CreateSigningResponse(
            WorkerSigningOutcome.Signed,
            request,
            new string('0', 32));
        byte[] templateFrame = await CreateResponseFrameAsync(response);
        await using WorkerProcessSession session = CreatePowerShellSession(
            CreateTwoRequestResponseScript(templateFrame, receiptPath, replayFirstResponse: false));

        WorkerSessionResult first = await session.SendAsync(
            request,
            TimeSpan.FromSeconds(5),
            onProgress: null,
            CancellationToken.None);
        WorkerSessionResult retry = await session.SendAsync(
            request,
            TimeSpan.FromSeconds(5),
            onProgress: null,
            CancellationToken.None);
        string[] transportIds = await File.ReadAllLinesAsync(receiptPath);

        Assert.Equal(2, transportIds.Length);
        Assert.All(transportIds, value => Assert.Matches("^[0-9a-f]{32}$", value));
        Assert.NotEqual(transportIds[0], transportIds[1]);
        Assert.Equal(request.OperationId, first.Response.OperationId);
        Assert.Equal(request.OperationId, retry.Response.OperationId);
        Assert.Equal(0, await session.CompleteAsync());
        Assert.False(IsProcessRunning(session.ProcessId));
    }

    [Fact]
    public async Task WorkerProcessSessionRejectsSameLogicalIdReplayOnSecondRequest()
    {
        using TemporaryFiles fixture = TemporaryFiles.Create();
        string receiptPath = Path.Combine(fixture.Root, "replay-operation-ids.txt");
        WorkerRequest request = CreateSigningRequest();
        WorkerResponse response = CreateSigningResponse(
            WorkerSigningOutcome.Signed,
            request,
            new string('0', 32));
        byte[] templateFrame = await CreateResponseFrameAsync(response);
        await using WorkerProcessSession session = CreatePowerShellSession(
            CreateTwoRequestResponseScript(templateFrame, receiptPath, replayFirstResponse: true));
        int processId = session.ProcessId;

        WorkerSessionResult first = await session.SendAsync(
            request,
            TimeSpan.FromSeconds(5),
            onProgress: null,
            CancellationToken.None);
        WorkerSessionResult? replayedResult = null;
        WorkerProtocolException error = await Assert.ThrowsAsync<WorkerProtocolException>(async () =>
        {
            replayedResult = await session.SendAsync(
                request,
                TimeSpan.FromSeconds(5),
                onProgress: null,
                CancellationToken.None);
        });
        string[] transportIds = await File.ReadAllLinesAsync(receiptPath);

        Assert.Equal(request.OperationId, first.Response.OperationId);
        Assert.Equal(2, transportIds.Length);
        Assert.NotEqual(transportIds[0], transportIds[1]);
        Assert.Equal(WorkerResponseCodes.InvalidFrame, error.Code);
        Assert.Null(replayedResult);
        Assert.False(session.IsRunning);
        Assert.False(IsProcessRunning(processId));
    }

    [Fact]
    public async Task WorkerProcessSessionSerializesConcurrentSendsWithUniqueTransportIds()
    {
        using TemporaryFiles fixture = TemporaryFiles.Create();
        string receiptPath = Path.Combine(fixture.Root, "concurrent-operation-ids.txt");
        WorkerRequest request = CreateSigningRequest();
        WorkerResponse response = CreateSigningResponse(
            WorkerSigningOutcome.Signed,
            request,
            new string('0', 32));
        byte[] templateFrame = await CreateResponseFrameAsync(response);
        await using WorkerProcessSession session = CreatePowerShellSession(
            CreateTwoRequestResponseScript(templateFrame, receiptPath, replayFirstResponse: false));

        Task<WorkerSessionResult> firstTask = session.SendAsync(
            request,
            TimeSpan.FromSeconds(5),
            onProgress: null,
            CancellationToken.None);
        Task<WorkerSessionResult> secondTask = session.SendAsync(
            request,
            TimeSpan.FromSeconds(5),
            onProgress: null,
            CancellationToken.None);
        WorkerSessionResult[] results = await Task.WhenAll(firstTask, secondTask);
        string[] transportIds = await File.ReadAllLinesAsync(receiptPath);

        Assert.Equal(2, transportIds.Length);
        Assert.NotEqual(transportIds[0], transportIds[1]);
        Assert.All(results, result => Assert.Equal(request.OperationId, result.Response.OperationId));
        Assert.Equal(0, await session.CompleteAsync());
    }

    [Fact]
    public async Task WorkerProcessSessionRejectsMalformedLogicalOperationIdBeforeTransportReplacement()
    {
        WorkerRequest request = CreateSigningRequest() with
        {
            OperationId = "ABCDEF0123456789ABCDEF0123456789"
        };
        await using WorkerProcessSession session = CreatePowerShellSession(
            "[Threading.Thread]::Sleep(30000)");
        int processId = session.ProcessId;

        WorkerProtocolException error = await Assert.ThrowsAsync<WorkerProtocolException>(() => session.SendAsync(
            request,
            TimeSpan.FromSeconds(5),
            onProgress: null,
            CancellationToken.None));

        Assert.Equal(WorkerResponseCodes.InvalidRequest, error.Code);
        Assert.False(session.IsRunning);
        Assert.False(IsProcessRunning(processId));
    }

    [Fact]
    public async Task OneShotSignAsyncWritesRepositoryConventionOperationId()
    {
        using TemporaryFiles fixture = TemporaryFiles.Create();
        string receiptPath = Path.Combine(fixture.Root, "operation-id.txt");
        WorkerProcessClient client = CreatePowerShellClient(CreateOperationIdReceiptScript(receiptPath));

        await Assert.ThrowsAnyAsync<EndOfStreamException>(() => client.SignAsync(
            fixture.ApplicationPath,
            fixture.WorkerPath,
            CreateSigningPlanJson(),
            TimeSpan.FromSeconds(5),
            CancellationToken.None));

        Assert.True(File.Exists(receiptPath), "The helper did not receive a protocol-valid request frame.");
        string operationId = await File.ReadAllTextAsync(receiptPath);
        Assert.Matches("^[0-9a-f]{32}$", operationId);
        Assert.True(Guid.TryParseExact(operationId, "N", out _));
    }

    private static WorkerProcessClient CreatePowerShellClient(string script)
    {
        string powershellPath = PowerShellPath();
        return new WorkerProcessClient(
            powershellPath,
            static (_, _) => { },
            _ => CreatePowerShellStartInfo(script));
    }

    private static WorkerProcessSession CreatePowerShellSession(string script)
    {
        Process process = Process.Start(CreatePowerShellStartInfo(script))
            ?? throw new InvalidOperationException("The protocol helper process did not start.");
        WorkerJob job = WorkerJob.CreateKillOnClose();
        try
        {
            job.Assign(process);
            ConstructorInfo constructor = typeof(WorkerProcessSession).GetConstructor(
                BindingFlags.Instance | BindingFlags.NonPublic,
                binder: null,
                [typeof(Process), typeof(WorkerJob)],
                modifiers: null)
                ?? throw new MissingMethodException(typeof(WorkerProcessSession).FullName, ".ctor");
            return (WorkerProcessSession)constructor.Invoke([process, job]);
        }
        catch
        {
            try
            {
                job.Terminate(WorkerJob.TimeoutExitCode);
            }
            catch (Exception)
            {
            }

            process.Dispose();
            job.Dispose();
            throw;
        }
    }

    private static ProcessStartInfo CreatePowerShellStartInfo(string script)
    {
        ProcessStartInfo startInfo = WorkerProcessClient.CreateStartInfo(PowerShellPath());
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-Command");
        startInfo.ArgumentList.Add(script);
        return startInfo;
    }

    private static string CreateFrameWriterScript(byte[] frame, int exitCode)
    {
        string encodedFrame = Convert.ToBase64String(frame);
        return
            "[Threading.Thread]::Sleep(100); " +
            $"$bytes=[Convert]::FromBase64String('{encodedFrame}'); " +
            "$output=[Console]::OpenStandardOutput(); $output.Write($bytes,0,$bytes.Length); $output.Flush(); " +
            $"exit {exitCode}";
    }

    private static string CreateSessionFrameWriterScript(byte[] frame)
    {
        string encodedFrame = Convert.ToBase64String(frame);
        return
            "[Threading.Thread]::Sleep(100); " +
            $"$bytes=[Convert]::FromBase64String('{encodedFrame}'); " +
            "$output=[Console]::OpenStandardOutput(); $output.Write($bytes,0,$bytes.Length); $output.Flush(); " +
            "[Threading.Thread]::Sleep(30000)";
    }

    private static string CreateOperationIdReceiptScript(string receiptPath)
    {
        string escapedReceipt = receiptPath.Replace("'", "''", StringComparison.Ordinal);
        return
            "$inputStream=[Console]::OpenStandardInput(); $header=[byte[]]::new(4); $offset=0; " +
            "while($offset -lt 4){$count=$inputStream.Read($header,$offset,4-$offset); if($count -eq 0){exit 2}; $offset+=$count}; " +
            "$length=[BitConverter]::ToInt32($header,0); $payload=[byte[]]::new($length); $offset=0; " +
            "while($offset -lt $length){$count=$inputStream.Read($payload,$offset,$length-$offset); if($count -eq 0){exit 3}; $offset+=$count}; " +
            "$request=([Text.Encoding]::UTF8.GetString($payload) | ConvertFrom-Json); " +
            $"[IO.File]::WriteAllText('{escapedReceipt}',[string]$request.operationId,[Text.UTF8Encoding]::new($false)); exit 7";
    }

    private static string CreateTwoRequestResponseScript(
        byte[] templateFrame,
        string receiptPath,
        bool replayFirstResponse)
    {
        const string placeholder = "00000000000000000000000000000000";
        string encodedTemplate = Convert.ToBase64String(templateFrame);
        string escapedReceipt = receiptPath.Replace("'", "''", StringComparison.Ordinal);
        string secondResponseId = replayFirstResponse ? "$firstId" : "$secondId";
        string ending = replayFirstResponse
            ? "[Threading.Thread]::Sleep(30000)"
            : "exit 0";
        return
            "$inputStream=[Console]::OpenStandardInput(); $outputStream=[Console]::OpenStandardOutput(); " +
            $"$template=[Convert]::FromBase64String('{encodedTemplate}'); " +
            "function Read-Request { $header=[byte[]]::new(4); $offset=0; " +
            "while($offset -lt 4){$count=$inputStream.Read($header,$offset,4-$offset); if($count -eq 0){exit 2}; $offset+=$count}; " +
            "$length=[BitConverter]::ToInt32($header,0); $payload=[byte[]]::new($length); $offset=0; " +
            "while($offset -lt $length){$count=$inputStream.Read($payload,$offset,$length-$offset); if($count -eq 0){exit 3}; $offset+=$count}; " +
            "return ([Text.Encoding]::UTF8.GetString($payload) | ConvertFrom-Json) }; " +
            "function Write-Response([string]$operationId) { " +
            $"$json=[Text.Encoding]::UTF8.GetString($template,4,$template.Length-4).Replace('{placeholder}',$operationId); " +
            "$payload=[Text.Encoding]::UTF8.GetBytes($json); $header=[BitConverter]::GetBytes([int]$payload.Length); " +
            "$outputStream.Write($header,0,$header.Length); $outputStream.Write($payload,0,$payload.Length); $outputStream.Flush() }; " +
            "$first=Read-Request; $firstId=[string]$first.operationId; Write-Response $firstId; " +
            "$second=Read-Request; $secondId=[string]$second.operationId; " +
            $"[IO.File]::WriteAllLines('{escapedReceipt}',[string[]]@($firstId,$secondId),[Text.UTF8Encoding]::new($false)); " +
            $"Write-Response {secondResponseId}; {ending}";
    }

    private static byte[] CreateHeader(int length)
    {
        byte[] header = new byte[WorkerProtocol.HeaderBytes];
        BinaryPrimitives.WriteInt32LittleEndian(header, length);
        return header;
    }

    private static byte[] CreateTruncatedFrame()
    {
        byte[] header = CreateHeader(100);
        return [.. header, (byte)'{', (byte)'}'];
    }

    private static byte[] CreateResponseFrame(int protocolVersion, bool success, string code)
    {
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(new WorkerResponse(protocolVersion, success, code));
        byte[] header = CreateHeader(payload.Length);
        return [.. header, .. payload];
    }

    private static byte[] CreateIncompleteResponseFrame(int protocolVersion, bool success, string code)
    {
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            protocolVersion,
            success,
            code,
            hresult = (int?)null,
            failedLegIndex = (int?)null,
            originalSha256 = (string?)null,
            stagedSha256 = (string?)null
        });
        byte[] header = CreateHeader(payload.Length);
        return [.. header, .. payload];
    }

    private static async Task<byte[]> CreateResponseFrameAsync(WorkerResponse response)
    {
        using MemoryStream frame = new();
        await WorkerProtocol.WriteResponseAsync(frame, response, CancellationToken.None);
        return frame.ToArray();
    }

    private static WorkerRequest CreateSigningRequest()
    {
        using Process owner = Process.GetCurrentProcess();
        return new WorkerRequest(
            WorkerProtocol.Version,
            WorkerCommands.Sign,
            Path.Combine(Path.GetTempPath(), "CodeSigner-operation-correlation", "original.exe"),
            Path.Combine(Path.GetTempPath(), "CodeSigner-operation-correlation", "staged.exe"),
            CreateSigningPlanJson(),
            owner.Id,
            new DateTimeOffset(owner.StartTime.ToUniversalTime(), TimeSpan.Zero),
            "0123456789abcdef0123456789abcdef");
    }

    private static WorkerResponse CreateSigningResponse(
        WorkerSigningOutcome outcome,
        WorkerRequest request,
        string operationId) => outcome switch
        {
            WorkerSigningOutcome.Signed => new WorkerResponse(
                WorkerProtocol.Version,
                true,
                WorkerResponseCodes.SigningCompleted,
                OriginalSha256: Task5CandidateSha256,
                StagedSha256: Task5CandidateSha256,
                OperationId: operationId,
                Subject: request.Subject,
                Capability: request.Capability,
                Engine: request.Engine,
                Verification: request.Verification,
                LegacyFallbackAttempted: false,
                Outcome: WorkerSigningOutcome.Signed,
                Route: WorkerExecutionRoute.ProductPe),
            WorkerSigningOutcome.SkippedExistingSignature => new WorkerResponse(
                WorkerProtocol.Version,
                true,
                WorkerResponseCodes.SkippedExistingSignature,
                OperationId: operationId,
                Subject: request.Subject,
                Capability: request.Capability,
                Engine: request.Engine,
                Verification: request.Verification,
                LegacyFallbackAttempted: false,
                Outcome: WorkerSigningOutcome.SkippedExistingSignature,
                Route: WorkerExecutionRoute.Skip),
            WorkerSigningOutcome.Failure => new WorkerResponse(
                WorkerProtocol.Version,
                false,
                WorkerResponseCodes.HandlerFailure,
                OperationId: operationId,
                Subject: request.Subject,
                Capability: request.Capability,
                Engine: request.Engine,
                Verification: request.Verification,
                LegacyFallbackAttempted: false,
                Outcome: WorkerSigningOutcome.Failure,
                Route: WorkerExecutionRoute.ProductPe,
                Failure: WorkerFailureCode.HandlerFailure),
            _ => throw new ArgumentOutOfRangeException(nameof(outcome), outcome, "Unknown signing outcome.")
        };

    private static string CreateSigningPlanJson()
    {
        CertificateRef certificate = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(
                CertificateStoreLocation.CurrentUser,
                "My",
                "00112233445566778899AABBCCDDEEFF00112233").Value);
        SigningPlan plan = Assert.IsType<SigningPlan>(SigningPlan.TryCreateSingle(certificate, ".exe").Value);
        return SigningPlanJson.Serialize(plan);
    }

    private static string PowerShellPath() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.Windows),
        "System32",
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe");

    private static Task<string[]> ReadFileReceiptAsync(string path)
    {
        Assert.True(File.Exists(path), "The hung process host did not write its PID receipt.");
        return File.ReadAllLinesAsync(path);
    }

    private static async Task<string[]> ReceiveProcessIdsAsync(
        NamedPipeServerStream receiptPipe,
        Task<WorkerLaunchDiagnostic> probeTask)
    {
        using CancellationTokenSource receiptDeadline = new(WorkerProcessClient.ProbeTimeout);
        Task connectionTask = receiptPipe.WaitForConnectionAsync(receiptDeadline.Token);
        Task completedTask = await Task.WhenAny(connectionTask, probeTask);
        Assert.Same(connectionTask, completedTask);
        await connectionTask;

        using var reader = new StreamReader(
            receiptPipe,
            Encoding.UTF8,
            detectEncodingFromByteOrderMarks: false,
            bufferSize: 1024,
            leaveOpen: true);
        string? receipt = await reader.ReadLineAsync(receiptDeadline.Token);
        Assert.False(string.IsNullOrWhiteSpace(receipt), "The hung process host wrote an empty PID receipt.");
        string[] processIds = receipt.Split(
            ',',
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        Assert.Equal(2, processIds.Length);
        return processIds;
    }

    private static string WorkerPath() => Path.Combine(
        FindRepositoryRoot(),
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

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "CodeSigner.sln")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate CodeSigner.sln.");
    }

    private static bool IsProcessRunning(int processId)
    {
        try
        {
            using Process process = Process.GetProcessById(processId);
            return !process.HasExited;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private sealed class TemporaryFiles : IDisposable
    {
        private TemporaryFiles(string root, string applicationPath, string workerPath)
        {
            Root = root;
            ApplicationPath = applicationPath;
            WorkerPath = workerPath;
        }

        public string Root { get; }
        public string ApplicationPath { get; }
        public string WorkerPath { get; }

        public static TemporaryFiles Create()
        {
            string root = Path.Combine(Path.GetTempPath(), "CodeSigner-worker-health-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            string applicationPath = Path.Combine(root, "CodeSigner.App.exe");
            string workerPath = Path.Combine(root, "CodeSigner.Worker.exe");
            File.WriteAllText(applicationPath, string.Empty, Encoding.UTF8);
            File.WriteAllText(workerPath, string.Empty, Encoding.UTF8);
            return new TemporaryFiles(root, applicationPath, workerPath);
        }

        public void Dispose()
        {
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }
    }
}
