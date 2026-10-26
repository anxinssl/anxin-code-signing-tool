using System.Diagnostics;
using System.Text;
using CodeSigner.Core.Diagnostics;
using CodeSigner.Core.Worker;

namespace CodeSigner.IntegrationTests;

public sealed class WorkerStderrTailTests
{
    [Fact]
    public async Task EmptyAndShortStderrRemainUntruncated()
    {
        WorkerProcessResult empty = await RunHostAsync([]);
        byte[] shortStderr = Encoding.UTF8.GetBytes("bridge_reason=handler_failure");
        WorkerProcessResult shortResult = await RunHostAsync(shortStderr);
        byte[] exactStderr = Encoding.UTF8.GetBytes(
            new string('e', SigningDiagnosticRedactor.WorkerStderrTailCapacityBytes));
        WorkerProcessResult exactResult = await RunHostAsync(exactStderr);

        Assert.Null(empty.WorkerStderrTail);
        Assert.False(empty.WorkerStderrTruncated);
        Assert.Equal("bridge_reason=handler_failure", shortResult.WorkerStderrTail);
        Assert.False(shortResult.WorkerStderrTruncated);
        Assert.Equal(
            SigningDiagnosticRedactor.WorkerStderrTailCapacityBytes,
            Encoding.UTF8.GetByteCount(exactResult.WorkerStderrTail!));
        Assert.False(exactResult.WorkerStderrTruncated);
    }

    [Fact]
    public async Task OversizedStderrKeepsOnlyTheTerminal8192Utf8Bytes()
    {
        const string terminalMarker = "terminal-stderr-marker";
        string stderr = "discarded-prefix-" +
            new string('x', SigningDiagnosticRedactor.WorkerStderrTailCapacityBytes) +
            terminalMarker;

        WorkerProcessResult result = await RunHostAsync(Encoding.UTF8.GetBytes(stderr));

        Assert.True(result.WorkerStderrTruncated);
        Assert.NotNull(result.WorkerStderrTail);
        Assert.Equal(
            SigningDiagnosticRedactor.WorkerStderrTailCapacityBytes,
            Encoding.UTF8.GetByteCount(result.WorkerStderrTail));
        Assert.EndsWith(terminalMarker, result.WorkerStderrTail, StringComparison.Ordinal);
        Assert.DoesNotContain("discarded-prefix", result.WorkerStderrTail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CancellationTerminatesTheTailReaderTask()
    {
        using CancellationTokenSource cancellation = new();
        await using var stream = new NeverCompletingStream();
        WorkerStderrTailCapture capture = WorkerStderrTailCapture.Start(stream, cancellation.Token);

        cancellation.Cancel();
        await capture.Completion.WaitAsync(TimeSpan.FromSeconds(2));

        WorkerStderrDiagnostic diagnostic = capture.Snapshot();
        Assert.Null(diagnostic.Tail);
        Assert.False(diagnostic.Truncated);
    }

    [Fact]
    public async Task TimeoutCarriesOnlyRedactedPartialStderr()
    {
        byte[] stderr = Encoding.UTF8.GetBytes(
            "--pin timeout-pin-canary " +
            "https://provider.invalid/sign?token=timeout-query-canary#fragment " +
            "C:\\Users\\operator-name-canary\\profile\\provider.json");
        WorkerProcessClient client = CreatePowerShellClient(stderr, responseFrame: null, sleepMilliseconds: 30000);
        WorkerRequest request = new(WorkerProtocol.Version, WorkerCommands.Probe, "C:\\stage\\fixture.exe");

        WorkerProcessTimeoutException error = await Assert.ThrowsAsync<WorkerProcessTimeoutException>(() =>
            client.SendAsync(request, TimeSpan.FromMilliseconds(500), CancellationToken.None));

        Assert.NotNull(error.WorkerStderrTail);
        Assert.False(error.WorkerStderrTruncated);
        Assert.DoesNotContain("timeout-pin-canary", error.WorkerStderrTail, StringComparison.Ordinal);
        Assert.DoesNotContain("timeout-query-canary", error.WorkerStderrTail, StringComparison.Ordinal);
        Assert.DoesNotContain("operator-name-canary", error.WorkerStderrTail, StringComparison.Ordinal);
        Assert.DoesNotContain("?", error.WorkerStderrTail, StringComparison.Ordinal);
        Assert.DoesNotContain("#", error.WorkerStderrTail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OversizedSecretLikeStderrCannotCorruptTheV2StdoutFrame()
    {
        byte[] frame = await CreateReadyResponseFrameAsync();
        byte[] stderr = Encoding.UTF8.GetBytes(
            new string('n', SigningDiagnosticRedactor.WorkerStderrTailCapacityBytes + 512) +
            " --pin stderr-pin-canary " +
            "https://provider.invalid/sign?token=stderr-query-canary#fragment " +
            "C:\\Users\\profile-owner-canary\\AppData\\provider.json");

        WorkerProcessResult baseline = await RunHostAsync([]);
        WorkerProcessResult result = await RunHostAsync(stderr, frame);

        Assert.Equal(baseline.Response, result.Response);
        Assert.Equal(0, result.ExitCode);
        Assert.True(result.WorkerStderrTruncated);
        Assert.NotNull(result.WorkerStderrTail);
        Assert.InRange(
            Encoding.UTF8.GetByteCount(result.WorkerStderrTail),
            1,
            SigningDiagnosticRedactor.WorkerStderrTailCapacityBytes);
        Assert.DoesNotContain("stderr-pin-canary", result.WorkerStderrTail, StringComparison.Ordinal);
        Assert.DoesNotContain("stderr-query-canary", result.WorkerStderrTail, StringComparison.Ordinal);
        Assert.DoesNotContain("profile-owner-canary", result.WorkerStderrTail, StringComparison.Ordinal);
        Assert.DoesNotContain("?", result.WorkerStderrTail, StringComparison.Ordinal);
        Assert.DoesNotContain("#", result.WorkerStderrTail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SafeTailPropagatesThroughResultsExceptionsAndLaunchMapping()
    {
        byte[] stderr = Encoding.UTF8.GetBytes("worker bridge --pin mapping-pin-canary code=invalid_frame");
        WorkerStderrTailCapture capture = WorkerStderrTailCapture.Start(
            new MemoryStream(stderr),
            CancellationToken.None);
        await capture.Completion;
        WorkerStderrDiagnostic captured = capture.Snapshot();
        var response = new WorkerResponse(WorkerProtocol.Version, true, WorkerResponseCodes.Ready);
        var processResult = new WorkerProcessResult(response, 1201, 0, captured);
        var sessionResult = new WorkerSessionResult(response, 1202, captured);
        var timeout = new WorkerProcessTimeoutException(captured);
        var crashed = new WorkerProcessCrashedException(23, captured);

        WorkerLaunchDiagnostic healthy = WorkerLaunchDiagnosticMapper.FromProbeResult(processResult);
        WorkerLaunchDiagnostic timedOut = WorkerLaunchDiagnosticMapper.FromException(timeout);
        WorkerLaunchDiagnostic crash = WorkerLaunchDiagnosticMapper.FromException(crashed);

        Assert.Equal(captured.Tail, processResult.WorkerStderrTail);
        Assert.Equal(captured.Tail, sessionResult.WorkerStderrTail);
        Assert.Equal(captured.Tail, timeout.WorkerStderrTail);
        Assert.Equal(captured.Tail, crashed.WorkerStderrTail);
        Assert.Equal(captured.Tail, healthy.WorkerStderrTail);
        Assert.Equal(captured.Tail, timedOut.WorkerStderrTail);
        Assert.Equal(captured.Tail, crash.WorkerStderrTail);
        Assert.False(healthy.WorkerStderrTruncated);
        Assert.False(timedOut.WorkerStderrTruncated);
        Assert.False(crash.WorkerStderrTruncated);
        Assert.DoesNotContain("mapping-pin-canary", captured.Tail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task InvalidFrameStillMapsExactlyAndRetainsOnlySafeTerminalStderr()
    {
        byte[] stderr = Encoding.UTF8.GetBytes(
            new string('z', SigningDiagnosticRedactor.WorkerStderrTailCapacityBytes + 128) +
            " --pin invalid-frame-pin-canary");
        WorkerProcessClient client = CreatePowerShellClient(
            stderr,
            responseFrame: [0xff, 0xff, 0xff, 0xff],
            sleepMilliseconds: 0);
        WorkerRequest request = new(WorkerProtocol.Version, WorkerCommands.Probe, "C:\\stage\\fixture.exe");

        WorkerProtocolException error = await Assert.ThrowsAsync<WorkerProtocolException>(() =>
            client.SendAsync(request, TimeSpan.FromSeconds(5), CancellationToken.None));
        WorkerLaunchDiagnostic diagnostic = WorkerLaunchDiagnosticMapper.FromException(error);

        Assert.Equal(WorkerLaunchReason.InvalidFrame, diagnostic.Reason);
        Assert.True(diagnostic.WorkerStderrTruncated);
        Assert.NotNull(diagnostic.WorkerStderrTail);
        Assert.DoesNotContain("invalid-frame-pin-canary", diagnostic.WorkerStderrTail, StringComparison.Ordinal);
    }

    private static Task<WorkerProcessResult> RunHostAsync(byte[] stderr, byte[]? responseFrame = null)
    {
        WorkerProcessClient client = CreatePowerShellClient(
            stderr,
            responseFrame ?? CreateReadyResponseFrameAsync().GetAwaiter().GetResult(),
            sleepMilliseconds: 0);
        WorkerRequest request = new(WorkerProtocol.Version, WorkerCommands.Probe, "C:\\stage\\fixture.exe");
        return client.SendAsync(request, TimeSpan.FromSeconds(5), CancellationToken.None);
    }

    private static WorkerProcessClient CreatePowerShellClient(
        byte[] stderr,
        byte[]? responseFrame,
        int sleepMilliseconds)
    {
        string powershellPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32",
            "WindowsPowerShell",
            "v1.0",
            "powershell.exe");
        string stderrBase64 = Convert.ToBase64String(stderr);
        string responseBase64 = responseFrame is null ? string.Empty : Convert.ToBase64String(responseFrame);
        string script =
            "[Console]::OpenStandardInput().CopyTo([IO.Stream]::Null); " +
            $"$stderrBytes=[Convert]::FromBase64String('{stderrBase64}'); " +
            "$stderr=[Console]::OpenStandardError(); " +
            "$stderr.Write($stderrBytes,0,$stderrBytes.Length); $stderr.Flush(); " +
            (responseFrame is null
                ? string.Empty
                : $"$responseBytes=[Convert]::FromBase64String('{responseBase64}'); " +
                  "$stdout=[Console]::OpenStandardOutput(); " +
                  "$stdout.Write($responseBytes,0,$responseBytes.Length); $stdout.Flush(); ") +
            (sleepMilliseconds > 0
                ? $"[Threading.Thread]::Sleep({sleepMilliseconds}); "
                : string.Empty) +
            "exit 0";
        return new WorkerProcessClient(
            powershellPath,
            static (_, _) => { },
            path =>
            {
                ProcessStartInfo startInfo = WorkerProcessClient.CreateStartInfo(path);
                startInfo.ArgumentList.Add("-NoProfile");
                startInfo.ArgumentList.Add("-NonInteractive");
                startInfo.ArgumentList.Add("-Command");
                startInfo.ArgumentList.Add(script);
                return startInfo;
            });
    }

    private static async Task<byte[]> CreateReadyResponseFrameAsync()
    {
        using MemoryStream stream = new();
        await WorkerProtocol.WriteResponseAsync(
            stream,
            new WorkerResponse(WorkerProtocol.Version, true, WorkerResponseCodes.Ready),
            CancellationToken.None);
        return stream.ToArray();
    }

    private sealed class NeverCompletingStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return 0;
        }
    }
}
