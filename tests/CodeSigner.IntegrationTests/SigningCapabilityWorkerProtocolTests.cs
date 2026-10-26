using System.Buffers.Binary;
using System.Text;
using CodeSigner.Core.Signing;
using CodeSigner.Core.Worker;

namespace CodeSigner.IntegrationTests;

public sealed class SigningCapabilityWorkerProtocolTests
{
    private const string Thumbprint = "00112233445566778899AABBCCDDEEFF00112233";

    [Fact]
    public async Task WorkerProtocolV4SignRequestCarriesExactPlanMetadata()
    {
        Assert.Equal(4, WorkerProtocol.Version);
        SigningPlan plan = Plan(SigningMode.Dual, ".msi");
        WorkerRequest request = new(
            WorkerProtocol.Version,
            WorkerCommands.Sign,
            "C:\\input\\fixture.msi",
            "C:\\stage\\fixture.msi",
            SigningPlanJson.Serialize(plan),
            1234,
            new DateTimeOffset(2026, 7, 28, 0, 0, 0, TimeSpan.Zero),
            "0123456789abcdef0123456789abcdef");
        using MemoryStream frame = new();

        await WorkerProtocol.WriteRequestAsync(frame, request, CancellationToken.None);
        frame.Position = 0;
        WorkerRequest decoded = await WorkerProtocol.ReadRequestAsync(frame, CancellationToken.None);

        Assert.Equal(WorkerSubjects.WindowsInstaller, decoded.Subject);
        Assert.Equal(WorkerCapabilities.WindowsSipSingleOnly, decoded.Capability);
        Assert.Equal(WorkerEngines.WindowsSip, decoded.Engine);
        Assert.Equal(WorkerVerifications.WindowsSip, decoded.Verification);
    }

    [Fact]
    public async Task WorkerProtocolV1AndForgedOrUnknownCapabilityFieldsAreRejected()
    {
        SigningPlan plan = Plan(SigningMode.Dual, ".msi");
        WorkerRequest request = new(
            WorkerProtocol.Version,
            WorkerCommands.Sign,
            "C:\\input\\fixture.msi",
            "C:\\stage\\fixture.msi",
            SigningPlanJson.Serialize(plan),
            1234,
            new DateTimeOffset(2026, 7, 28, 0, 0, 0, TimeSpan.Zero),
            "0123456789abcdef0123456789abcdef");
        using MemoryStream validFrame = new();
        await WorkerProtocol.WriteRequestAsync(validFrame, request, CancellationToken.None);
        string json = Payload(validFrame.ToArray());

        string[] rejected =
        [
            json.Replace("\"protocolVersion\":4", "\"protocolVersion\":1", StringComparison.Ordinal),
            json.Replace(
                "\"capability\":\"windowsSipSingleOnly\"",
                "\"capability\":\"peImageDualCapable\"",
                StringComparison.Ordinal),
            json.Replace("\"capability\":", "\"forgedCapability\":true,\"capability\":", StringComparison.Ordinal)
        ];

        foreach (string candidate in rejected)
        {
            await Assert.ThrowsAsync<WorkerProtocolException>(
                () => WorkerProtocol.ReadRequestAsync(
                    new MemoryStream(Frame(candidate)),
                    CancellationToken.None));
        }
    }

    [Fact]
    public async Task WorkerProtocolProgressAndResponseCarrySubjectEngineAndVerification()
    {
        WorkerProgress progress = new(
            WorkerProtocol.Version,
            WorkerProgressPhases.Verifying,
            WorkerSubjects.PeImage,
            WorkerCapabilities.PeImageDualCapable,
            WorkerEngines.PeImage,
            WorkerVerifications.PeImage);
        using MemoryStream progressFrame = new();

        await WorkerProtocol.WriteProgressAsync(progressFrame, progress, CancellationToken.None);
        progressFrame.Position = 0;
        WorkerSessionMessage progressMessage = await WorkerProtocol.ReadSessionMessageAsync(
            progressFrame,
            CancellationToken.None);
        Assert.Equal(progress, progressMessage.Progress);

        WorkerResponse response = new(
            WorkerProtocol.Version,
            true,
            WorkerResponseCodes.SigningCompleted,
            0,
            OriginalSha256: new string('a', 64),
            StagedSha256: new string('b', 64),
            OperationId: "0123456789abcdef0123456789abcdef",
            Subject: WorkerSubjects.PeImage,
            Capability: WorkerCapabilities.PeImageDualCapable,
            Engine: WorkerEngines.PeImage,
            Verification: WorkerVerifications.PeImage,
            Outcome: WorkerSigningOutcome.Signed,
            Route: WorkerExecutionRoute.ProductPe);
        using MemoryStream responseFrame = new();

        await WorkerProtocol.WriteResponseAsync(responseFrame, response, CancellationToken.None);
        responseFrame.Position = 0;
        Assert.Equal(
            response,
            await WorkerProtocol.ReadResponseAsync(responseFrame, CancellationToken.None));
    }

    private static SigningPlan Plan(SigningMode mode, string extension)
    {
        CertificateRef certificate = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(CertificateStoreLocation.CurrentUser, "My", Thumbprint).Value);
        return mode == SigningMode.Single
            ? Assert.IsType<SigningPlan>(SigningPlan.TryCreateSingle(certificate, extension).Value)
            : Assert.IsType<SigningPlan>(SigningPlan.TryCreateDual(certificate, null, extension).Value);
    }

    private static string Payload(byte[] frame) => Encoding.UTF8.GetString(
        frame,
        WorkerProtocol.HeaderBytes,
        frame.Length - WorkerProtocol.HeaderBytes);

    private static byte[] Frame(string json)
    {
        byte[] payload = Encoding.UTF8.GetBytes(json);
        byte[] frame = new byte[WorkerProtocol.HeaderBytes + payload.Length];
        BinaryPrimitives.WriteInt32LittleEndian(frame, payload.Length);
        payload.CopyTo(frame.AsSpan(WorkerProtocol.HeaderBytes));
        return frame;
    }
}
