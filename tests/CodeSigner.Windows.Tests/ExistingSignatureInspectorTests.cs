using CodeSigner.Core.Signing;
using CodeSigner.Windows.Files;
using CodeSigner.Windows.Signing;

namespace CodeSigner.Windows.Tests;

public sealed class ExistingSignatureInspectorTests : IDisposable
{
    private const string Thumbprint = "00112233445566778899AABBCCDDEEFF00112233";
    private const int TrustENoSignature = unchecked((int)0x800B0100);
    private const int TrustESubjectFormUnknown = unchecked((int)0x800B0003);
    private const int InvalidArgumentHResult = unchecked((int)0x80070057);
    private readonly string root = Path.Combine(
        Path.GetTempPath(),
        "CodeSigner-ExistingSignatureInspector-" + Guid.NewGuid().ToString("N"));

    [Fact]
    [Trait("Category", "ExistingSignature")]
    public void TrustNoSignatureWithoutStructuralSignatureReturnsUnsigned()
    {
        FilePair files = CreateFilePair(".msi");
        var signatures = new StubSignatureInspector(
            new AuthenticodeSignatureCountInspection(TrustENoSignature, 0));
        var inspector = new WindowsExistingSignatureInspector(signatures, SubjectProbeFor(".msi"));

        ExistingSignatureInspectionResult result = inspector.Inspect(
            files.Original,
            files.Staged,
            PlanFor(".msi"),
            CancellationToken.None);

        Assert.Equal(ExistingSignatureInspectionStatus.Unsigned, result.Status);
        Assert.Equal(TrustENoSignature, result.HResult);
        Assert.Equal(1, signatures.CountCalls);
        Assert.Equal(0, signatures.InspectCalls);
    }

    [Fact]
    [Trait("Category", "ExistingSignature")]
    public void StructurallyUnsignedPeReturnsUnsignedWithPlatformNoSignature()
    {
        FilePair files = CreateFixturePair("valid-unsigned.dll");
        ClassifiedSignableContent classified = SignableSubjectContentClassifier.Classify(files.Staged);
        PeImageCertificateTable certificateTable = PeImageCertificateTable.Read(files.Staged);
        var signatures = new AuthenticodeSignatureInspector();
        AuthenticodeSignatureCountInspection count = signatures.GetSignatureCount(files.Staged);
        var inspector = new WindowsExistingSignatureInspector(signatures, SubjectProbeFor(".dll"));

        ExistingSignatureInspectionResult result = inspector.Inspect(
            files.Original,
            files.Staged,
            PlanFor(".dll"),
            CancellationToken.None);

        Assert.Equal(SigningFormatFamily.PeImage, classified.PolicySubject.FormatFamily);
        Assert.Empty(certificateTable.Records);
        Assert.Equal(TrustENoSignature, count.TrustStatus);
        Assert.Equal(ExistingSignatureInspectionStatus.Unsigned, result.Status);
        Assert.Equal(TrustENoSignature, result.HResult);
    }

    [Fact]
    [Trait("Category", "ExistingSignature")]
    public void TrustedSignatureWithRequiredDigestAndTimestampReturnsValid()
    {
        FilePair files = CreateFilePair(".msi");
        var signatures = new StubSignatureInspector(
            new AuthenticodeSignatureCountInspection(0, 0),
            ValidSignature());
        var inspector = new WindowsExistingSignatureInspector(signatures, SubjectProbeFor(".msi"));

        ExistingSignatureInspectionResult result = inspector.Inspect(
            files.Original,
            files.Staged,
            PlanFor(".msi"),
            CancellationToken.None);

        Assert.Equal(ExistingSignatureInspectionStatus.Valid, result.Status);
        Assert.Equal(0, result.HResult);
        Assert.Equal(1, signatures.CountCalls);
        Assert.Equal(1, signatures.InspectCalls);
    }

    [Theory]
    [InlineData(unchecked((int)0x80096010), ExistingSignatureInspectionStatus.Invalid)]
    [InlineData(unchecked((int)0x800B0109), ExistingSignatureInspectionStatus.Untrusted)]
    [InlineData(unchecked((int)0x800B0101), ExistingSignatureInspectionStatus.Expired)]
    [InlineData(TrustESubjectFormUnknown, ExistingSignatureInspectionStatus.Malformed)]
    [Trait("Category", "ExistingSignature")]
    public void TrustFailureReturnsNormalizedDisposition(
        int trustStatus,
        ExistingSignatureInspectionStatus expectedStatus)
    {
        FilePair files = CreateFilePair(".msi");
        var signatures = new StubSignatureInspector(
            new AuthenticodeSignatureCountInspection(trustStatus, 0));
        var inspector = new WindowsExistingSignatureInspector(signatures, SubjectProbeFor(".msi"));

        ExistingSignatureInspectionResult result = inspector.Inspect(
            files.Original,
            files.Staged,
            PlanFor(".msi"),
            CancellationToken.None);

        Assert.Equal(expectedStatus, result.Status);
        Assert.Equal(trustStatus, result.HResult);
        Assert.Equal(0, signatures.InspectCalls);
    }

    [Fact]
    [Trait("Category", "ExistingSignature")]
    public void SignatureCountThatDoesNotMatchPlanReturnsPartial()
    {
        FilePair files = CreateFilePair(".msi");
        var signatures = new StubSignatureInspector(
            new AuthenticodeSignatureCountInspection(0, 1));
        var inspector = new WindowsExistingSignatureInspector(signatures, SubjectProbeFor(".msi"));

        ExistingSignatureInspectionResult result = inspector.Inspect(
            files.Original,
            files.Staged,
            PlanFor(".msi"),
            CancellationToken.None);

        Assert.Equal(ExistingSignatureInspectionStatus.Partial, result.Status);
        Assert.Equal(TrustENoSignature, result.HResult);
        Assert.Equal(0, signatures.InspectCalls);
    }

    [Fact]
    [Trait("Category", "ExistingSignature")]
    public void NonCanonicalSignerMetadataReturnsMalformed()
    {
        FilePair files = CreateFilePair(".msi");
        AuthenticodeSignatureInspection malformed = ValidSignature() with { SignerThumbprint = "not-canonical" };
        var signatures = new StubSignatureInspector(
            new AuthenticodeSignatureCountInspection(0, 0),
            malformed);
        var inspector = new WindowsExistingSignatureInspector(signatures, SubjectProbeFor(".msi"));

        ExistingSignatureInspectionResult result = inspector.Inspect(
            files.Original,
            files.Staged,
            PlanFor(".msi"),
            CancellationToken.None);

        Assert.Equal(ExistingSignatureInspectionStatus.Malformed, result.Status);
        Assert.Equal(TrustESubjectFormUnknown, result.HResult);
    }

    [Fact]
    [Trait("Category", "ExistingSignature")]
    public void SubjectThatDoesNotMatchPlanReturnsFamilyIncompatibleBeforeTrustInspection()
    {
        FilePair files = CreateFilePair(".msi");
        var signatures = new StubSignatureInspector(
            new AuthenticodeSignatureCountInspection(0, 0),
            ValidSignature());
        var inspector = new WindowsExistingSignatureInspector(
            signatures,
            new StubSubjectProbe(path => SubjectFor(path == files.Original ? ".msi" : ".cab")));

        ExistingSignatureInspectionResult result = inspector.Inspect(
            files.Original,
            files.Staged,
            PlanFor(".msi"),
            CancellationToken.None);

        Assert.Equal(ExistingSignatureInspectionStatus.FamilyIncompatible, result.Status);
        Assert.Equal(InvalidArgumentHResult, result.HResult);
        Assert.Equal(0, signatures.CountCalls);
        Assert.Equal(0, signatures.InspectCalls);
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
        {
            Directory.Delete(root, recursive: true);
        }

        GC.SuppressFinalize(this);
    }

    private FilePair CreateFilePair(string extension)
    {
        Directory.CreateDirectory(root);
        string original = Path.Combine(root, "original" + extension);
        string staged = Path.Combine(root, "staged" + extension);
        File.WriteAllBytes(original, "existing-signature-inspection"u8.ToArray());
        File.Copy(original, staged);
        return new FilePair(original, staged);
    }

    private FilePair CreateFixturePair(string fixtureName)
    {
        Directory.CreateDirectory(root);
        string source = Path.Combine(RepositoryRoot(), "tests", "fixtures", "generated", fixtureName);
        string original = Path.Combine(root, "original" + Path.GetExtension(fixtureName));
        string staged = Path.Combine(root, "staged" + Path.GetExtension(fixtureName));
        File.Copy(source, original);
        File.Copy(source, staged);
        return new FilePair(original, staged);
    }

    private static string RepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "CodeSigner.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName
            ?? throw new DirectoryNotFoundException("Could not locate CodeSigner.sln.");
    }

    private static SigningPlan PlanFor(string extension)
    {
        CertificateRef certificate = Assert.IsType<CertificateRef>(
            CertificateRef.TryCreate(CertificateStoreLocation.CurrentUser, "My", Thumbprint).Value);
        return Assert.IsType<SigningPlan>(SigningPlan.TryCreateSingle(certificate, extension).Value);
    }

    private static StubSubjectProbe SubjectProbeFor(string extension) =>
        new StubSubjectProbe(_ => SubjectFor(extension));

    private static SignableSubject SubjectFor(string extension)
    {
        SigningSubject subject = Assert.IsType<SigningSubject>(
            SigningSubject.TryCreateForExtension(extension).Value);
        return new SignableSubject(subject, Guid.Parse("01234567-89ab-cdef-0123-456789abcdef"), null);
    }

    private static AuthenticodeSignatureInspection ValidSignature() => new(
        0,
        0,
        AuthenticodeOids.Sha256,
        Thumbprint,
        [1],
        new AuthenticodeTimestampInspection(
            AuthenticodeTimestampKind.Rfc3161,
            AuthenticodeOids.Sha256,
            CryptographicallyValid: true,
            ChainValid: true,
            TimeValid: true,
            TimestampingEkuValid: true));

    private sealed record FilePair(string Original, string Staged);

    private sealed class StubSubjectProbe(Func<string, SignableSubject> probe) : ISignableSubjectProbe
    {
        public SignableSubject Probe(string path) => probe(path);
    }

    private sealed class StubSignatureInspector(
        AuthenticodeSignatureCountInspection count,
        params AuthenticodeSignatureInspection[] signatures) : IAuthenticodeSignatureInspector
    {
        public int CountCalls { get; private set; }

        public int InspectCalls { get; private set; }

        public AuthenticodeSignatureCountInspection GetSignatureCount(string path)
        {
            CountCalls++;
            return count;
        }

        public AuthenticodeSignatureInspection InspectSignature(string path, uint index)
        {
            InspectCalls++;
            return signatures[checked((int)index)];
        }
    }
}
