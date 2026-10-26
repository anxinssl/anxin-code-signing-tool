using System.Reflection;
using CodeSigner.Core.Signing;

namespace CodeSigner.Core.Tests.Signing;

public sealed class SigningPlanPolicyTests
{
    private const string PrimaryThumbprint = "00112233445566778899AABBCCDDEEFF00112233";
    private const string SecondaryThumbprint = "FFEEDDCCBBAA99887766554433221100FFEEDDCC";

    [Fact]
    public void ExistingSignatureDispositionRemainsSkipValidAndFailEveryOtherStatus()
    {
        SigningPlan plan = AssertSuccess(SigningPlan.TryCreateSingle(CreateCertificate(), ".exe"));

        Assert.Equal(ExistingSignatureDisposition.Skip, plan.ExistingSignatures.For(ExistingSignatureStatus.Valid));
        Assert.Equal(ExistingSignatureDisposition.Fail, plan.ExistingSignatures.For(ExistingSignatureStatus.Invalid));
        Assert.Equal(ExistingSignatureDisposition.Fail, plan.ExistingSignatures.For(ExistingSignatureStatus.Untrusted));
        Assert.Equal(ExistingSignatureDisposition.Fail, plan.ExistingSignatures.For(ExistingSignatureStatus.Expired));
        Assert.Equal(ExistingSignatureDisposition.Fail, plan.ExistingSignatures.For(ExistingSignatureStatus.Partial));
        Assert.Equal(ExistingSignatureDisposition.Fail, plan.ExistingSignatures.For(ExistingSignatureStatus.Malformed));
    }

    [Fact]
    public void SinglePlanSnapshotIsExactAndImmutable()
    {
        CertificateRef certificate = CreateCertificate(CertificateStoreLocation.CurrentUser, PrimaryThumbprint);

        PolicyResult<SigningPlan> result = SigningPlan.TryCreateSingle(certificate, ".exe");

        SigningPlan plan = AssertSuccess(result);
        Assert.Equal(SigningPlan.CurrentVersion, plan.Version);
        Assert.Equal(SigningMode.Single, plan.Mode);
        SignatureLeg leg = Assert.Single(plan.Legs);
        Assert.Equal(FileDigestAlgorithm.Sha256, leg.FileDigest);
        Assert.False(leg.Append);
        Assert.Same(certificate, leg.Certificate);
        AssertTimestampPolicy(leg.Timestamp);
        Assert.Equal(SigningFormatFamily.PeImage, plan.Subject.FormatFamily);
        Assert.Equal(SigningCapability.PeImageDualCapable, plan.Subject.Capability);
        AssertFailClosedExistingSignaturePolicy(plan.ExistingSignatures);
        Assert.IsAssignableFrom<IReadOnlyList<SignatureLeg>>(plan.Legs);
        Assert.Throws<NotSupportedException>(() => ((IList<SignatureLeg>)plan.Legs).Clear());
    }

    [Fact]
    public void DualPlanSnapshotIsSha1PrimaryThenSha256AppendWithIndependentCertificates()
    {
        CertificateRef primary = CreateCertificate(CertificateStoreLocation.CurrentUser, PrimaryThumbprint);
        CertificateRef secondary = CreateCertificate(CertificateStoreLocation.LocalMachine, SecondaryThumbprint);

        SigningPlan plan = AssertSuccess(SigningPlan.TryCreateDual(primary, secondary, ".exe"));

        Assert.Equal(SigningMode.Dual, plan.Mode);
        Assert.Collection(
            plan.Legs,
            leg =>
            {
                Assert.Same(primary, leg.Certificate);
                Assert.Equal(FileDigestAlgorithm.Sha1, leg.FileDigest);
                Assert.False(leg.Append);
                AssertTimestampPolicy(leg.Timestamp);
            },
            leg =>
            {
                Assert.Same(secondary, leg.Certificate);
                Assert.Equal(FileDigestAlgorithm.Sha256, leg.FileDigest);
                Assert.True(leg.Append);
                AssertTimestampPolicy(leg.Timestamp);
            });
    }

    [Fact]
    public void PromisedExecutableConstructsExactPeCapability()
    {
        SigningPlan plan = AssertSuccess(SigningPlan.TryCreateSingle(CreateCertificate(), ".exe"));

        Assert.Equal(SigningFormatFamily.PeImage, plan.Subject.FormatFamily);
        Assert.Equal(".exe", plan.Subject.Extension);
        Assert.Equal(SigningCapability.PeImageDualCapable, plan.Subject.Capability);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("0011")]
    [InlineData("00112233445566778899AABBCCDDEEFF0011223Z")]
    public void CertificateRefRejectsMissingOrNonFullThumbprint(string? thumbprint)
    {
        PolicyResult<CertificateRef> result = CertificateRef.TryCreate(
            CertificateStoreLocation.CurrentUser,
            "My",
            thumbprint);

        AssertFailure(result, PolicyErrorCode.InvalidCertificate, "certificate.thumbprint");
    }

    [Theory]
    [InlineData("ftp://time.example.test")]
    [InlineData("/relative")]
    [InlineData("not a uri")]
    public void AdvancedTimestampRejectsNonAbsoluteHttpUris(string timestampUri)
    {
        PolicyResult<SigningPlan> result = SigningPlan.TryCreateSingle(
            CreateCertificate(),
            ".exe",
            timestampUri);

        AssertFailure(result, PolicyErrorCode.InvalidUri, "timestamp.uri");
    }

    [Fact]
    public void AdvancedTimestampOverrideIsExactAndHasNoFallbackState()
    {
        const string overrideUri = "https://tsa.example.test/rfc3161?tenant=exact";

        SigningPlan plan = AssertSuccess(SigningPlan.TryCreateDual(
            CreateCertificate(),
            CreateCertificate(CertificateStoreLocation.LocalMachine, SecondaryThumbprint),
            ".exe",
            overrideUri));

        Assert.All(plan.Legs, leg => Assert.Equal(overrideUri, leg.Timestamp.Uri.OriginalString));
        Assert.DoesNotContain(
            typeof(TimestampPolicy).GetProperties(BindingFlags.Instance | BindingFlags.Public),
            property => property.Name.Contains("fallback", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void MissingFactoryCertificateReturnsTypedFailure()
    {
        PolicyResult<SigningPlan> single = SigningPlan.TryCreateSingle(null, ".exe");
        PolicyResult<SigningPlan> dual = SigningPlan.TryCreateDual(CreateCertificate(), null, ".exe");

        AssertFailure(single, PolicyErrorCode.InvalidCertificate, "certificate");
        AssertFailure(dual, PolicyErrorCode.InvalidCertificate, "certificate");
    }

    [Theory]
    [InlineData(".obj")]
    [InlineData(".txt")]
    [InlineData("exe")]
    [InlineData("")]
    public void UnsupportedExtensionCannotConstructPlan(string extension)
    {
        PolicyResult<SigningPlan> result = SigningPlan.TryCreateSingle(CreateCertificate(), extension);

        AssertFailure(result, PolicyErrorCode.UnsupportedFileType, "subject.extension");
    }

    [Fact]
    public void SingleAndDualJsonRoundTripWithoutUnknownOrSecretFields()
    {
        SigningPlan single = AssertSuccess(SigningPlan.TryCreateSingle(CreateCertificate(), ".exe"));
        SigningPlan dual = AssertSuccess(SigningPlan.TryCreateDual(
            CreateCertificate(CertificateStoreLocation.CurrentUser, PrimaryThumbprint),
            CreateCertificate(CertificateStoreLocation.LocalMachine, SecondaryThumbprint),
            ".exe",
            "https://tsa.example.test/rfc3161"));

        AssertStableRoundTrip(single);
        AssertStableRoundTrip(dual);

        string json = SigningPlanJson.Serialize(dual);
        Assert.DoesNotContain("pin", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("password", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("token", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("privateKey", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("args", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("flags", json, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [MemberData(nameof(UnsafeJsonMutations))]
    public void MutatedJsonCannotEmitExecutablePlan(
        string mutationName,
        Func<string, string> mutate,
        PolicyErrorCode expectedCode,
        string expectedPath)
    {
        _ = mutationName;
        SigningPlan valid = AssertSuccess(SigningPlan.TryCreateDual(
            CreateCertificate(CertificateStoreLocation.CurrentUser, PrimaryThumbprint),
            CreateCertificate(CertificateStoreLocation.LocalMachine, SecondaryThumbprint),
            ".exe"));
        string mutated = mutate(SigningPlanJson.Serialize(valid));

        PolicyResult<SigningPlan> result = SigningPlanJson.Parse(mutated);

        Assert.Null(result.Value);
        Assert.Contains(result.Errors, error => error.Code == expectedCode && error.Path == expectedPath);
    }

    [Fact]
    public void DeterministicUnknownFieldFuzzNeverEmitsPlan()
    {
        string validJson = SigningPlanJson.Serialize(
            AssertSuccess(SigningPlan.TryCreateSingle(CreateCertificate(), ".exe")));
        var random = new Random(4102026);

        for (int index = 0; index < 128; index++)
        {
            string field = $"unknown_{random.NextInt64():x}";
            string mutated = validJson.Replace("{", $"{{\"{field}\":true,", StringComparison.Ordinal);

            PolicyResult<SigningPlan> result = SigningPlanJson.Parse(mutated);

            Assert.Null(result.Value);
            Assert.Contains(result.Errors, error => error.Code == PolicyErrorCode.UnknownField);
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("[]")]
    [InlineData("{\"version\":1,")]
    [InlineData("{\"version\":1,/*comment*/\"mode\":\"single\"}")]
    public void MalformedOrWrongRootJsonNeverEmitsPlan(string? json)
    {
        PolicyResult<SigningPlan> result = SigningPlanJson.Parse(json);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Value);
        Assert.Contains(
            result.Errors,
            error => error.Code is PolicyErrorCode.MalformedJson or PolicyErrorCode.InvalidFieldType);
    }

    [Fact]
    public void DuplicateKnownFieldIsRejectedAndDoesNotPolluteNextParse()
    {
        string validJson = SigningPlanJson.Serialize(
            AssertSuccess(SigningPlan.TryCreateSingle(CreateCertificate(), ".exe")));
        string duplicateVersion = validJson.Replace(
            "\"version\":2",
            "\"version\":2,\"version\":2",
            StringComparison.Ordinal);

        PolicyResult<SigningPlan> rejected = SigningPlanJson.Parse(duplicateVersion);
        PolicyResult<SigningPlan> next = SigningPlanJson.Parse(validJson);

        AssertFailure(rejected, PolicyErrorCode.UnknownField, "$.version");
        Assert.True(next.IsSuccess, string.Join(Environment.NewLine, next.Errors));
        Assert.Equal(validJson, SigningPlanJson.Serialize(Assert.IsType<SigningPlan>(next.Value)));
    }

    [Fact]
    public async Task ConcurrentParsersDoNotShareFailureOrPlanState()
    {
        string validJson = SigningPlanJson.Serialize(
            AssertSuccess(SigningPlan.TryCreateDual(
                CreateCertificate(),
                CreateCertificate(CertificateStoreLocation.LocalMachine, SecondaryThumbprint),
                ".exe")));
        Task<PolicyResult<SigningPlan>>[] operations = Enumerable.Range(0, 64)
            .Select(index => Task.Run(() => SigningPlanJson.Parse(index % 2 == 0 ? validJson : "{}")))
            .ToArray();

        PolicyResult<SigningPlan>[] results = await Task.WhenAll(operations);

        for (int index = 0; index < results.Length; index++)
        {
            Assert.Equal(index % 2 == 0, results[index].IsSuccess);
            Assert.Equal(index % 2 == 0, results[index].Value is not null);
        }
    }

    [Fact]
    public void ExcessiveJsonDepthIsRejectedWithoutAPlan()
    {
        string json = new string('[', 40) + new string(']', 40);

        PolicyResult<SigningPlan> result = SigningPlanJson.Parse(json);

        AssertFailure(result, PolicyErrorCode.MalformedJson, "$");
    }

    [Fact]
    public void ExecutableModelsExposeNoRawArgumentsOrCertificateInferenceFields()
    {
        Type[] modelTypes =
        [
            typeof(CertificateRef),
            typeof(SignatureLeg),
            typeof(TimestampPolicy),
            typeof(ExistingSignaturePolicy),
            typeof(SigningSubject),
            typeof(SigningPlan)
        ];
        string[] forbiddenFragments = ["arg", "flag", "oid", "fallback", "password", "pin", "token"];

        foreach (Type type in modelTypes)
        {
            Assert.Empty(type.GetConstructors(BindingFlags.Instance | BindingFlags.Public));
            foreach (PropertyInfo property in type.GetProperties(BindingFlags.Instance | BindingFlags.Public))
            {
                Assert.DoesNotContain(
                    forbiddenFragments,
                    fragment => property.Name.Contains(fragment, StringComparison.OrdinalIgnoreCase));
                Assert.Null(property.SetMethod);
            }
        }
    }

    public static TheoryData<string, Func<string, string>, PolicyErrorCode, string> UnsafeJsonMutations => new()
    {
        { "unknown root", json => json.Replace("{", "{\"rawArguments\":\"/fd sha1\",", StringComparison.Ordinal), PolicyErrorCode.UnknownField, "$.rawArguments" },
        { "missing certificate", json => json.Replace("\"certificate\":{\"storeLocation\":\"currentUser\",\"storeName\":\"My\",\"thumbprint\":\"00112233445566778899AABBCCDDEEFF00112233\"},", string.Empty, StringComparison.Ordinal), PolicyErrorCode.MissingField, "$.legs[0].certificate" },
        { "sha256 before sha1", json => ReplaceFirst(json, "\"fileDigest\":\"sha1\"", "\"fileDigest\":\"sha256\""), PolicyErrorCode.InvalidSignatureOrder, "$.legs" },
        { "primary append", json => ReplaceFirst(json, "\"append\":false", "\"append\":true"), PolicyErrorCode.InvalidAppendSequence, "$.legs" },
        { "repeated non-append", json => json.Replace("\"append\":true", "\"append\":false", StringComparison.Ordinal), PolicyErrorCode.InvalidAppendSequence, "$.legs" },
        { "sha1 timestamp digest", json => ReplaceFirst(json, "\"timestampDigest\":\"sha256\"", "\"timestampDigest\":\"sha1\""), PolicyErrorCode.InvalidTimestampDigest, "$.legs[0].timestamp.timestampDigest" },
        { "timestamp fallback list", json => ReplaceFirst(json, "\"uri\":\"http://time.certum.pl\"", "\"uri\":[\"http://time.certum.pl\",\"https://fallback.test\"]"), PolicyErrorCode.InvalidFieldType, "$.legs[0].timestamp.uri" },
        { "unknown format family", json => json.Replace("\"formatFamily\":\"peImage\"", "\"formatFamily\":\"rawCoff\"", StringComparison.Ordinal), PolicyErrorCode.UnsupportedFileType, "$.subject.formatFamily" },
        { "forged capability", json => json.Replace("\"capability\":\"peImageDualCapable\"", "\"capability\":\"windowsSipSingleOnly\"", StringComparison.Ordinal), PolicyErrorCode.UnsafePolicy, "$.subject.capability" },
        { "mutate valid signature", json => json.Replace("\"valid\":\"skip\"", "\"valid\":\"sign\"", StringComparison.Ordinal), PolicyErrorCode.UnsafePolicy, "$.existingSignatures.valid" },
        { "trust untrusted signature", json => json.Replace("\"untrusted\":\"fail\"", "\"untrusted\":\"skip\"", StringComparison.Ordinal), PolicyErrorCode.UnsafePolicy, "$.existingSignatures.untrusted" },
        { "unsupported version", json => json.Replace("\"version\":2", "\"version\":1", StringComparison.Ordinal), PolicyErrorCode.UnsupportedVersion, "$.version" }
    };

    private static string ReplaceFirst(string value, string oldValue, string newValue)
    {
        int index = value.IndexOf(oldValue, StringComparison.Ordinal);
        Assert.True(index >= 0, $"Expected token was not found: {oldValue}");
        return string.Concat(value.AsSpan(0, index), newValue, value.AsSpan(index + oldValue.Length));
    }

    private static CertificateRef CreateCertificate(
        CertificateStoreLocation location = CertificateStoreLocation.CurrentUser,
        string thumbprint = PrimaryThumbprint) =>
        AssertSuccess(CertificateRef.TryCreate(location, "My", thumbprint));

    private static T AssertSuccess<T>(PolicyResult<T> result) where T : class
    {
        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Errors));
        return Assert.IsType<T>(result.Value);
    }

    private static void AssertFailure<T>(PolicyResult<T> result, PolicyErrorCode code, string path) where T : class
    {
        Assert.False(result.IsSuccess);
        Assert.Null(result.Value);
        Assert.Contains(result.Errors, error => error.Code == code && error.Path == path);
    }

    private static void AssertTimestampPolicy(TimestampPolicy timestamp)
    {
        Assert.Equal(TimestampProtocol.Rfc3161, timestamp.Protocol);
        Assert.Equal(TimestampDigestAlgorithm.Sha256, timestamp.TimestampDigest);
        Assert.Equal("http://time.certum.pl", timestamp.Uri.OriginalString);
    }

    private static void AssertFailClosedExistingSignaturePolicy(ExistingSignaturePolicy policy)
    {
        Assert.Equal(ExistingSignatureDisposition.Skip, policy.For(ExistingSignatureStatus.Valid));
        Assert.Equal(ExistingSignatureDisposition.Fail, policy.For(ExistingSignatureStatus.Invalid));
        Assert.Equal(ExistingSignatureDisposition.Fail, policy.For(ExistingSignatureStatus.Untrusted));
        Assert.Equal(ExistingSignatureDisposition.Fail, policy.For(ExistingSignatureStatus.Expired));
        Assert.Equal(ExistingSignatureDisposition.Fail, policy.For(ExistingSignatureStatus.Partial));
        Assert.Equal(ExistingSignatureDisposition.Fail, policy.For(ExistingSignatureStatus.Malformed));
    }

    private static void AssertStableRoundTrip(SigningPlan plan)
    {
        string json = SigningPlanJson.Serialize(plan);
        SigningPlan parsed = AssertSuccess(SigningPlanJson.Parse(json));
        Assert.Equal(json, SigningPlanJson.Serialize(parsed));
    }
}
