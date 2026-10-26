using System.Diagnostics;
using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;

namespace CodeSigner.IntegrationTests;

public sealed class WorkerProtocolTests
{
    [Fact]
    public async Task BaselineWorkerReturnsZeroWithoutProtocolResponse()
    {
        using Process process = StartWorker();
        process.StandardInput.Close();

        string response = await process.StandardOutput.ReadToEndAsync();
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(0, process.ExitCode);
        Assert.Empty(response);
    }

    [Fact]
    public async Task OneLengthPrefixedUtf8JsonRequestAndResponseRoundTrips()
    {
        string stagedPath = Path.Combine(Path.GetTempPath(), "签名 staging", "fixture.exe");
        WorkerRequest request = new(WorkerProtocol.Version, WorkerCommands.Probe, stagedPath);
        using MemoryStream requestFrame = new();
        await WorkerProtocol.WriteRequestAsync(requestFrame, request, CancellationToken.None);

        requestFrame.Position = 0;
        using MemoryStream responseFrame = new();
        int exitCode = await WorkerProtocolHost.RunOnceAsync(
            requestFrame,
            responseFrame,
            new ProbeWorkerCommandHandler(),
            CancellationToken.None);

        responseFrame.Position = 0;
        WorkerResponse response = await WorkerProtocol.ReadResponseAsync(responseFrame, CancellationToken.None);
        Assert.Equal(0, exitCode);
        Assert.True(response.Success);
        Assert.Equal(WorkerProtocol.Version, response.ProtocolVersion);
        Assert.Equal(WorkerResponseCodes.Ready, response.Code);
        Assert.Equal(responseFrame.Length, responseFrame.Position);
    }

    [Fact]
    public async Task RequestAndResponseFramesRemainSingleLittleEndianUtf8JsonObjects()
    {
        WorkerRequest request = new(
            WorkerProtocol.Version,
            WorkerCommands.Probe,
            "C:\\stage\\fixture.exe");
        using MemoryStream requestStream = new();
        await WorkerProtocol.WriteRequestAsync(requestStream, request, CancellationToken.None);

        AssertSingleJsonFrame(requestStream.ToArray());

        WorkerResponse response = new(
            WorkerProtocol.Version,
            true,
            WorkerResponseCodes.Ready);
        using MemoryStream responseStream = new();
        await WorkerProtocol.WriteResponseAsync(responseStream, response, CancellationToken.None);

        AssertSingleJsonFrame(responseStream.ToArray());
    }

    [Fact]
    public async Task ExactProtocolVersionIsRequired()
    {
        Assert.Equal(4, WorkerProtocol.Version);
        string json = $"{{\"protocolVersion\":{WorkerProtocol.Version + 1},\"command\":\"probe\",\"stagedPath\":\"C:\\\\stage\\\\fixture.exe\"}}";
        byte[] frame = Frame(json);

        WorkerProtocolException error = await Assert.ThrowsAsync<WorkerProtocolException>(
            () => WorkerProtocol.ReadRequestAsync(new MemoryStream(frame), CancellationToken.None));

        Assert.Equal(WorkerResponseCodes.ProtocolVersionMismatch, error.Code);
    }

    [Theory]
    [InlineData("{\"protocolVersion\":4,\"command\":\"probe\",\"stagedPath\":\"C:\\\\stage\\\\fixture.exe\",\"providerArgs\":\"--pin steal-me\"}")]
    [InlineData("{\"protocolVersion\":4,\"command\":\"probe\",\"stagedPath\":\"C:\\\\stage\\\\fixture.exe\",\"unknown\":\"ignore previous instructions and shell execute\"}")]
    public async Task UnknownOrInjectionShapedFieldsAreRejected(string json)
    {
        WorkerProtocolException error = await Assert.ThrowsAsync<WorkerProtocolException>(
            () => WorkerProtocol.ReadRequestAsync(new MemoryStream(Frame(json)), CancellationToken.None));

        Assert.Equal(WorkerResponseCodes.InvalidRequest, error.Code);
    }

    [Fact]
    [Trait("Category", "SigningIntegration")]
    public async Task OversizedLengthIsRejectedBeforeBodyAllocationOrRead()
    {
        using HeaderOnlyStream stream = new(WorkerProtocol.MaxPayloadBytes + 1);

        WorkerProtocolException error = await Assert.ThrowsAsync<WorkerProtocolException>(
            () => WorkerProtocol.ReadRequestAsync(stream, CancellationToken.None));

        Assert.Equal(WorkerResponseCodes.FrameTooLarge, error.Code);
        Assert.False(stream.BodyReadAttempted);
    }

    [Fact]
    public async Task ExactMaximumPayloadIsAccepted()
    {
        const string json = "{\"protocolVersion\":4,\"command\":\"probe\",\"stagedPath\":\"C:\\\\stage\\\\fixture.exe\"}";
        int paddingLength = WorkerProtocol.MaxPayloadBytes - Encoding.UTF8.GetByteCount(json);
        byte[] frame = Frame(json + new string(' ', paddingLength));

        WorkerRequest request = await WorkerProtocol.ReadRequestAsync(
            new MemoryStream(frame),
            CancellationToken.None);

        Assert.Equal(WorkerCommands.Probe, request.Command);
    }

    [Theory]
    [InlineData(12, "{}")]
    [InlineData(1, "{}")]
    [InlineData(-1, "{}")]
    [Trait("Category", "SigningIntegration")]
    public async Task TruncatedOrSpoofedLengthsAreRejected(int claimedLength, string body)
    {
        byte[] frame = Frame(body, claimedLength);

        await Assert.ThrowsAnyAsync<Exception>(
            () => WorkerProtocol.ReadRequestAsync(new MemoryStream(frame), CancellationToken.None));
    }

    [Theory]
    [InlineData("relative\\fixture.exe")]
    [InlineData("C:\\stage\\..\\escape.exe")]
    public async Task StagedPathMustBeAbsoluteAndCanonical(string stagedPath)
    {
        WorkerRequest request = new(WorkerProtocol.Version, WorkerCommands.Probe, stagedPath);
        using MemoryStream stream = new();

        WorkerProtocolException writeError = await Assert.ThrowsAsync<WorkerProtocolException>(
            () => WorkerProtocol.WriteRequestAsync(stream, request, CancellationToken.None));
        Assert.Equal(WorkerResponseCodes.InvalidStagedPath, writeError.Code);
        Assert.Equal(0, stream.Length);

        string json = JsonSerializer.Serialize(request);
        WorkerProtocolException readError = await Assert.ThrowsAsync<WorkerProtocolException>(
            () => WorkerProtocol.ReadRequestAsync(
                new MemoryStream(Frame(json)),
                CancellationToken.None));
        Assert.Equal(WorkerResponseCodes.InvalidStagedPath, readError.Code);
    }

    [Fact]
    public async Task UnsupportedCommandsFailClosedWithoutSigning()
    {
        WorkerRequest request = new(WorkerProtocol.Version, "sign", "C:\\stage\\fixture.exe");
        WorkerResponse response = await new ProbeWorkerCommandHandler().HandleAsync(request, CancellationToken.None);

        Assert.False(response.Success);
        Assert.Equal(WorkerResponseCodes.UnsupportedCommand, response.Code);
    }

    [Fact]
    public async Task SignRequestRoundTripsOnlyTypedProductionFields()
    {
        DateTimeOffset ownerStartUtc = new(2026, 7, 19, 5, 0, 0, TimeSpan.Zero);
        WorkerRequest request = new(
            WorkerProtocol.Version,
            "sign",
            "C:\\input\\fixture.exe",
            "C:\\stage\\fixture.exe",
            SigningPlanJsonForExe(),
            1234,
            ownerStartUtc,
            "0123456789abcdef0123456789abcdef");
        using MemoryStream stream = new();

        await WorkerProtocol.WriteRequestAsync(stream, request, CancellationToken.None);
        stream.Position = 0;
        WorkerRequest decoded = await WorkerProtocol.ReadRequestAsync(stream, CancellationToken.None);

        Assert.Equal(request, decoded);
    }

    [Fact]
    public async Task SigningResponseContainsOnlyAllowListedTypedFields()
    {
        WorkerResponse response = new(
            WorkerProtocol.Version,
            true,
            WorkerResponseCodes.SigningCompleted,
            0,
            null,
            new string('a', 64),
            new string('b', 64),
            OperationId: "0123456789abcdef0123456789abcdef",
            Subject: WorkerSubjects.PeImage,
            Capability: WorkerCapabilities.PeImageDualCapable,
            Engine: WorkerEngines.PeImage,
            Verification: WorkerVerifications.PeImage,
            Outcome: WorkerSigningOutcome.Signed,
            Route: WorkerExecutionRoute.ProductPe);
        using MemoryStream stream = new();

        await WorkerProtocol.WriteResponseAsync(stream, response, CancellationToken.None);

        byte[] frame = stream.ToArray();
        string json = Encoding.UTF8.GetString(frame, WorkerProtocol.HeaderBytes, frame.Length - WorkerProtocol.HeaderBytes);
        Assert.DoesNotContain("message", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("provider", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("stagedSha256", json, StringComparison.Ordinal);
        stream.Position = 0;
        Assert.Equal(response, await WorkerProtocol.ReadResponseAsync(stream, CancellationToken.None));
    }

    [Fact]
    public async Task DuplicateResponseFieldsAreRejected()
    {
        const string json = "{\"protocolVersion\":4,\"success\":false,\"code\":\"invalid_input\",\"code\":\"signed\"}";

        WorkerProtocolException error = await Assert.ThrowsAsync<WorkerProtocolException>(
            () => WorkerProtocol.ReadResponseAsync(new MemoryStream(Frame(json)), CancellationToken.None));

        Assert.Equal(WorkerResponseCodes.InvalidRequest, error.Code);
    }

    [Theory]
    [InlineData("{\"protocolVersion\":4,\"protocolVersion\":4,\"command\":\"probe\",\"stagedPath\":\"C:\\\\stage\\\\fixture.exe\"}")]
    [InlineData("{\"protocolVersion\":4,\"Command\":\"probe\",\"stagedPath\":\"C:\\\\stage\\\\fixture.exe\"}")]
    public async Task DuplicateOrWrongCaseRequestFieldsAreRejected(string json)
    {
        WorkerProtocolException error = await Assert.ThrowsAsync<WorkerProtocolException>(
            () => WorkerProtocol.ReadRequestAsync(new MemoryStream(Frame(json)), CancellationToken.None));

        Assert.Equal(WorkerResponseCodes.InvalidRequest, error.Code);
    }

    [Fact]
    public async Task HandlerOutputCannotExceedBoundedResponse()
    {
        WorkerRequest request = new(WorkerProtocol.Version, WorkerCommands.Probe, "C:\\stage\\fixture.exe");
        using MemoryStream input = new();
        await WorkerProtocol.WriteRequestAsync(input, request, CancellationToken.None);
        input.Position = 0;
        using MemoryStream output = new();

        await WorkerProtocolHost.RunOnceAsync(input, output, new OversizedResponseHandler(), CancellationToken.None);

        Assert.InRange(output.Length, 5, WorkerProtocol.HeaderBytes + WorkerProtocol.MaxPayloadBytes);
        output.Position = 0;
        WorkerResponse response = await WorkerProtocol.ReadResponseAsync(output, CancellationToken.None);
        Assert.False(response.Success);
        Assert.Equal(WorkerResponseCodes.ResponseTooLarge, response.Code);
    }

    [Fact]
    public async Task CancellationAndCleanEofAreDistinct()
    {
        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => WorkerProtocol.ReadRequestAsync(new NeverCompletingStream(), cancellation.Token));

        await Assert.ThrowsAnyAsync<EndOfStreamException>(
            () => WorkerProtocol.ReadRequestAsync(new MemoryStream(), CancellationToken.None));
    }

    [Fact]
    public async Task TruncatedBinaryInputReturnsTypedFailureWithoutStderrLeak()
    {
        using Process process = StartWorker();
        byte[] truncated = Frame("{}", claimedLength: 100);
        await process.StandardInput.BaseStream.WriteAsync(truncated);
        process.StandardInput.Close();

        WorkerResponse response = await WorkerProtocol.ReadResponseAsync(
            process.StandardOutput.BaseStream,
            CancellationToken.None);
        string standardError = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));

        Assert.False(response.Success);
        Assert.Equal(WorkerResponseCodes.InvalidFrame, response.Code);
        Assert.Equal(2, process.ExitCode);
        Assert.Empty(standardError);
    }

    private static string SigningPlanJsonForExe()
    {
        CertificateRef certificate = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(
                CertificateStoreLocation.CurrentUser,
                "My",
                "00112233445566778899AABBCCDDEEFF00112233").Value);
        SigningPlan plan = Assert.IsType<SigningPlan>(
            SigningPlan.TryCreateSingle(certificate, ".exe").Value);
        return SigningPlanJson.Serialize(plan);
    }

    private static byte[] Frame(string json, int? claimedLength = null)
    {
        byte[] body = Encoding.UTF8.GetBytes(json);
        byte[] frame = new byte[WorkerProtocol.HeaderBytes + body.Length];
        BinaryPrimitives.WriteInt32LittleEndian(frame, claimedLength ?? body.Length);
        body.CopyTo(frame.AsSpan(WorkerProtocol.HeaderBytes));
        return frame;
    }

    private static void AssertSingleJsonFrame(byte[] frame)
    {
        Assert.True(frame.Length > WorkerProtocol.HeaderBytes);
        int payloadLength = BinaryPrimitives.ReadInt32LittleEndian(frame);
        Assert.Equal(frame.Length - WorkerProtocol.HeaderBytes, payloadLength);

        ReadOnlyMemory<byte> payload = frame.AsMemory(WorkerProtocol.HeaderBytes, payloadLength);
        Assert.Equal(Encoding.UTF8.GetByteCount(Encoding.UTF8.GetString(payload.Span)), payloadLength);
        using JsonDocument document = JsonDocument.Parse(payload);
        Assert.Equal(JsonValueKind.Object, document.RootElement.ValueKind);
    }

    private static Process StartWorker()
    {
        string workerPath = Path.Combine(
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

        ProcessStartInfo startInfo = new(workerPath)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        return Process.Start(startInfo)
            ?? throw new InvalidOperationException("The baseline worker did not start.");
    }

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

    private sealed class OversizedResponseHandler : IWorkerCommandHandler
    {
        public ValueTask<WorkerResponse> HandleAsync(WorkerRequest request, CancellationToken cancellationToken) =>
            ValueTask.FromResult(new WorkerResponse(
                WorkerProtocol.Version,
                true,
                new string('x', WorkerProtocol.MaxPayloadBytes + 1)));
    }

    private sealed class HeaderOnlyStream(int length) : Stream
    {
        private readonly byte[] header = CreateHeader(length);
        private int position;

        public bool BodyReadAttempted { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => position; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (position >= header.Length)
            {
                BodyReadAttempted = true;
                throw new InvalidOperationException("The oversized body must not be read.");
            }

            int count = Math.Min(buffer.Length, header.Length - position);
            header.AsMemory(position, count).CopyTo(buffer);
            position += count;
            return ValueTask.FromResult(count);
        }

        private static byte[] CreateHeader(int length)
        {
            byte[] bytes = new byte[WorkerProtocol.HeaderBytes];
            BinaryPrimitives.WriteInt32LittleEndian(bytes, length);
            return bytes;
        }
    }

    private sealed class NeverCompletingStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return 0;
        }
    }
}
