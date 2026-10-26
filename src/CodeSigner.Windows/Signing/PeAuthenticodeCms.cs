using System.Formats.Asn1;
using System.Net.Http.Headers;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CodeSigner.Windows.Signing;

internal sealed record PeAuthenticodeCmsInspection(
    string DigestAlgorithmOid,
    byte[] ImageDigest,
    byte[] SignatureValue,
    int Rfc3161TimestampCount,
    string? TimestampDigestAlgorithmOid,
    bool TimestampMessageImprintMatchesSignature,
    string SignerCertificateThumbprint)
{
    internal IReadOnlyList<string> CertificateThumbprints { get; init; } = Array.Empty<string>();

    internal byte[] SignatureInput { get; init; } = [];

    internal IReadOnlyList<PeAuthenticodeCmsInspection> NestedSignatures { get; init; } =
        Array.Empty<PeAuthenticodeCmsInspection>();
}

internal sealed record PeUnsignedAuthenticodeCms(byte[] EncodedCms, byte[] SignatureValue);

internal sealed record PeCmsCreationResult(NativeSigningResult Result, byte[]? EncodedCms)
{
    internal static PeCmsCreationResult Success(byte[] cms) =>
        new(NativeSigningResult.Success(), cms);

    internal static PeCmsCreationResult Failure(NativeSigningReasonCode reason, int hResult) =>
        new(NativeSigningResult.Failure(reason, hResult), null);
}

internal sealed record PeTimestampResult(NativeSigningResult Result, byte[]? Token)
{
    internal static PeTimestampResult Success(byte[] token) =>
        new(NativeSigningResult.Success(), token);

    internal static PeTimestampResult Failure(int hResult) =>
        new(NativeSigningResult.Failure(NativeSigningReasonCode.TimestampUnavailable, hResult), null);
}

internal interface IPeAuthenticodeCmsSigner
{
    Task<PeCmsCreationResult> CreateAsync(
        SignatureLeg leg,
        ReadOnlyMemory<byte> imageDigest,
        nint providerWindowHandle,
        CancellationToken cancellationToken);
}

internal interface IAuthenticodeCmsEncoder
{
    PeUnsignedAuthenticodeCms CreateUnsignedCms(
        PeCertificatePrivateKeyLease privateKey,
        NativeDigestAlgorithm digestAlgorithm,
        ReadOnlySpan<byte> indirectData);

    byte[] AddRfc3161Timestamp(ReadOnlySpan<byte> unsignedCms, ReadOnlySpan<byte> timestampToken);
}

internal interface IPeRfc3161TimestampClient
{
    Task<PeTimestampResult> GetTimestampAsync(
        Uri timestampUri,
        ReadOnlyMemory<byte> signatureValue,
        CancellationToken cancellationToken);
}

internal interface IAuthenticodeCmsRecordInspector
{
    PeAuthenticodeCmsInspection Inspect(ReadOnlyMemory<byte> encodedCms);
}

internal sealed class WindowsPeAuthenticodeCmsSigner(
    IPeCertificatePrivateKeyAcquirer privateKeyAcquirer,
    IAuthenticodeCmsEncoder cmsEncoder,
    IPeRfc3161TimestampClient timestampClient,
    IAuthenticodeCmsRecordInspector inspector) : IPeAuthenticodeCmsSigner
{
    private const int FailureHResult = unchecked((int)0x80004005);
    private const int InvalidArgumentHResult = unchecked((int)0x80070057);

    public async Task<PeCmsCreationResult> CreateAsync(
        SignatureLeg leg,
        ReadOnlyMemory<byte> imageDigest,
        nint providerWindowHandle,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(leg);
        cancellationToken.ThrowIfCancellationRequested();
        if (leg.TimestampDigest != NativeDigestAlgorithm.Sha256 ||
            imageDigest.Length != DigestLength(leg.FileDigest))
        {
            return PeCmsCreationResult.Failure(
                NativeSigningReasonCode.InvalidInput,
                InvalidArgumentHResult);
        }

        PePrivateKeyAcquisition acquisition = privateKeyAcquirer.Acquire(
            leg.Certificate,
            providerWindowHandle);
        if (!acquisition.Result.Succeeded || acquisition.Lease is null)
        {
            return new PeCmsCreationResult(acquisition.Result, null);
        }

        try
        {
            using PeCertificatePrivateKeyLease privateKey = acquisition.Lease;
            byte[] indirectData = AuthenticodeAsn1.EncodeIndirectData(leg.FileDigest, imageDigest.Span);
            PeUnsignedAuthenticodeCms unsigned = cmsEncoder.CreateUnsignedCms(
                privateKey,
                leg.FileDigest,
                indirectData);
            cancellationToken.ThrowIfCancellationRequested();
            PeTimestampResult timestamp = await timestampClient.GetTimestampAsync(
                leg.TimestampUri,
                unsigned.SignatureValue,
                cancellationToken).ConfigureAwait(false);
            if (!timestamp.Result.Succeeded || timestamp.Token is null)
            {
                return new PeCmsCreationResult(timestamp.Result, null);
            }

            byte[] encoded = cmsEncoder.AddRfc3161Timestamp(unsigned.EncodedCms, timestamp.Token);
            PeAuthenticodeCmsInspection inspection = inspector.Inspect(encoded);
            string expectedOid = AuthenticodeAsn1.DigestOid(leg.FileDigest);
            if (!string.Equals(inspection.DigestAlgorithmOid, expectedOid, StringComparison.Ordinal) ||
                !inspection.ImageDigest.AsSpan().SequenceEqual(imageDigest.Span) ||
                inspection.Rfc3161TimestampCount != 1 ||
                !string.Equals(
                    inspection.TimestampDigestAlgorithmOid,
                    AuthenticodeOids.Sha256,
                    StringComparison.Ordinal) ||
                !inspection.TimestampMessageImprintMatchesSignature)
            {
                return PeCmsCreationResult.Failure(
                    NativeSigningReasonCode.NativeSigningFailed,
                    FailureHResult);
            }

            return PeCmsCreationResult.Success(encoded);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (exception is InvalidDataException or
            AsnContentException or
            CryptographicException or
            System.ComponentModel.Win32Exception or
            OverflowException or
            ArgumentException)
        {
            return PeCmsCreationResult.Failure(
                NativeSigningReasonCode.NativeSigningFailed,
                exception.HResult < 0 ? exception.HResult : FailureHResult);
        }
    }

    private static int DigestLength(NativeDigestAlgorithm algorithm) => algorithm switch
    {
        NativeDigestAlgorithm.Sha1 => 20,
        NativeDigestAlgorithm.Sha256 => 32,
        _ => 0
    };
}

internal sealed class CryptMsgAuthenticodeCmsEncoder(
    IAuthenticodeCmsRecordInspector inspector) : IAuthenticodeCmsEncoder
{
    private const uint BareContentParameter = 3;
    private const int MaximumCmsSize = 64 * 1024 * 1024;
    private static readonly Asn1Tag ExplicitContent =
        new(TagClass.ContextSpecific, 0, isConstructed: true);

    public PeUnsignedAuthenticodeCms CreateUnsignedCms(
        PeCertificatePrivateKeyLease privateKey,
        NativeDigestAlgorithm digestAlgorithm,
        ReadOnlySpan<byte> indirectData)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        if (privateKey.Padding != PeRsaPadding.Pkcs1)
        {
            throw new InvalidDataException("Only RSA PKCS#1 v1.5 Authenticode signatures are supported.");
        }

        byte[] content = indirectData.ToArray();
        byte[] certificateDer = privateKey.Certificate.RawDataMemory.ToArray();
        nint hashOid = nint.Zero;
        nint rsaOid = nint.Zero;
        nint certificateBytes = nint.Zero;
        nint signerPointer = nint.Zero;
        nint certificateBlobPointer = nint.Zero;
        try
        {
            hashOid = Marshal.StringToCoTaskMemUTF8(AuthenticodeAsn1.DigestOid(digestAlgorithm));
            rsaOid = Marshal.StringToCoTaskMemUTF8(AuthenticodeAsn1.RsaEncryptionOid);
            certificateBytes = Marshal.AllocCoTaskMem(certificateDer.Length);
            Marshal.Copy(certificateDer, 0, certificateBytes, certificateDer.Length);
            NativeCertificateContext certificateContext = Marshal.PtrToStructure<NativeCertificateContext>(
                privateKey.Certificate.Handle);
            if (certificateContext.CertificateInfo == nint.Zero)
            {
                throw new InvalidDataException("The selected certificate context has no CERT_INFO.");
            }

            NativeCmsgSignerEncodeInfo signer = new()
            {
                Size = checked((uint)Marshal.SizeOf<NativeCmsgSignerEncodeInfo>()),
                CertificateInfo = certificateContext.CertificateInfo,
                KeyHandle = privateKey.KeyHandle,
                KeySpec = privateKey.Family == PePrivateKeyFamily.Cng ? 0 : privateKey.KeySpec,
                HashAlgorithm = new NativeAlgorithmIdentifier { ObjectId = hashOid },
                HashEncryptionAlgorithm = new NativeAlgorithmIdentifier { ObjectId = rsaOid }
            };
            signerPointer = Allocate(signer);
            NativeBlob certificateBlob = new()
            {
                Size = checked((uint)certificateDer.Length),
                Data = certificateBytes
            };
            certificateBlobPointer = Allocate(certificateBlob);
            NativeCmsgSignedEncodeInfo signed = new()
            {
                Size = checked((uint)Marshal.SizeOf<NativeCmsgSignedEncodeInfo>()),
                SignerCount = 1,
                Signers = signerPointer,
                CertificateCount = 1,
                Certificates = certificateBlobPointer
            };

            using SafeCryptographicMessageHandle message =
                PeAuthenticodeCryptographicInterop.CryptMsgOpenToEncode(
                    PeAuthenticodeCryptographicInterop.X509AndPkcs7Encoding,
                    flags: 0,
                    PeAuthenticodeCryptographicInterop.SignedMessage,
                    ref signed,
                    AuthenticodeAsn1.SpcIndirectDataOid,
                    nint.Zero);
            EnsureValid(message, "CryptMsgOpenToEncode");
            if (!PeAuthenticodeCryptographicInterop.CryptMsgUpdate(
                message,
                content,
                checked((uint)content.Length),
                final: true))
            {
                ThrowNativeFailure("CryptMsgUpdate");
            }

            byte[] signedData = GetMessageParameter(
                message,
                BareContentParameter);
            byte[] cms = EncodeSignedDataContentInfo(signedData);
            PeAuthenticodeCmsInspection inspection = inspector.Inspect(cms);
            return new PeUnsignedAuthenticodeCms(cms, inspection.SignatureValue);
        }
        finally
        {
            Marshal.FreeCoTaskMem(certificateBlobPointer);
            Marshal.FreeCoTaskMem(signerPointer);
            Marshal.FreeCoTaskMem(certificateBytes);
            Marshal.FreeCoTaskMem(rsaOid);
            Marshal.FreeCoTaskMem(hashOid);
        }
    }

    public byte[] AddRfc3161Timestamp(
        ReadOnlySpan<byte> unsignedCms,
        ReadOnlySpan<byte> timestampToken)
    {
        byte[] cms = unsignedCms.ToArray();
        byte[] attribute = AuthenticodeAsn1.EncodeRfc3161Attribute(timestampToken);
        nint attributeBytes = nint.Zero;
        try
        {
            using SafeCryptographicMessageHandle message =
                PeAuthenticodeCryptographicInterop.CryptMsgOpenToDecode(
                    PeAuthenticodeCryptographicInterop.X509AndPkcs7Encoding,
                    flags: 0,
                    messageType: 0,
                    legacyProvider: nint.Zero,
                    recipientInfo: nint.Zero,
                    streamInfo: nint.Zero);
            EnsureValid(message, "CryptMsgOpenToDecode");
            if (!PeAuthenticodeCryptographicInterop.CryptMsgUpdate(
                message,
                cms,
                checked((uint)cms.Length),
                final: true))
            {
                ThrowNativeFailure("CryptMsgUpdate");
            }

            attributeBytes = Marshal.AllocCoTaskMem(attribute.Length);
            Marshal.Copy(attribute, 0, attributeBytes, attribute.Length);
            NativeCmsgAddSignerUnauthenticatedAttribute control = new()
            {
                Size = checked((uint)Marshal.SizeOf<NativeCmsgAddSignerUnauthenticatedAttribute>()),
                SignerIndex = 0,
                EncodedAttribute = new NativeBlob
                {
                    Size = checked((uint)attribute.Length),
                    Data = attributeBytes
                }
            };
            if (!PeAuthenticodeCryptographicInterop.CryptMsgControl(
                message,
                flags: 0,
                PeAuthenticodeCryptographicInterop.AddSignerUnauthenticatedAttribute,
                ref control))
            {
                ThrowNativeFailure("CryptMsgControl");
            }

            return GetMessageParameter(
                message,
                PeAuthenticodeCryptographicInterop.EncodedMessageParameter);
        }
        finally
        {
            Marshal.FreeCoTaskMem(attributeBytes);
        }
    }

    private static nint Allocate<T>(T value)
        where T : struct
    {
        nint pointer = Marshal.AllocCoTaskMem(Marshal.SizeOf<T>());
        Marshal.StructureToPtr(value, pointer, fDeleteOld: false);
        return pointer;
    }

    private static byte[] EncodeSignedDataContentInfo(ReadOnlySpan<byte> signedData)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.WriteObjectIdentifier(AuthenticodeAsn1.SignedDataOid);
        writer.PushSequence(ExplicitContent);
        writer.WriteEncodedValue(signedData);
        writer.PopSequence(ExplicitContent);
        writer.PopSequence();
        return writer.Encode();
    }

    private static byte[] GetMessageParameter(SafeCryptographicMessageHandle message, uint parameter)
    {
        uint length = 0;
        if (!PeAuthenticodeCryptographicInterop.CryptMsgGetParameterSize(
            message,
            parameter,
            index: 0,
            nint.Zero,
            ref length))
        {
            ThrowNativeFailure("CryptMsgGetParam");
        }

        if (length == 0 || length > MaximumCmsSize)
        {
            throw new InvalidDataException("CryptMsg returned an invalid CMS size.");
        }

        byte[] bytes = new byte[checked((int)length)];
        if (!PeAuthenticodeCryptographicInterop.CryptMsgGetParameter(
            message,
            parameter,
            index: 0,
            bytes,
            ref length) || length != bytes.Length)
        {
            ThrowNativeFailure("CryptMsgGetParam");
        }

        return bytes;
    }

    private static void EnsureValid(SafeCryptographicMessageHandle message, string operation)
    {
        if (message.IsInvalid)
        {
            ThrowNativeFailure(operation);
        }
    }

    private static void ThrowNativeFailure(string operation) =>
        throw new System.ComponentModel.Win32Exception(
            Marshal.GetLastWin32Error(),
            $"{operation} failed.");
}

internal sealed class Rfc3161TimestampClient : IPeRfc3161TimestampClient
{
    private const int MaximumResponseSize = 4 * 1024 * 1024;
    private const int FailureHResult = unchecked((int)0x80072F8F);
    private static readonly HttpClient SharedClient = new();

    private readonly HttpClient client;
    private readonly IWindowsRfc3161TokenVerifier tokenVerifier;

    internal Rfc3161TimestampClient()
        : this(SharedClient, new WindowsRfc3161TokenVerifier())
    {
    }

    internal Rfc3161TimestampClient(
        HttpClient client,
        IWindowsRfc3161TokenVerifier tokenVerifier)
    {
        this.client = client;
        this.tokenVerifier = tokenVerifier;
    }

    public async Task<PeTimestampResult> GetTimestampAsync(
        Uri timestampUri,
        ReadOnlyMemory<byte> signatureValue,
        CancellationToken cancellationToken)
    {
        try
        {
            byte[] requestBytes = AuthenticodeAsn1.EncodeRfc3161Request(signatureValue.Span);
            using HttpRequestMessage request = new(HttpMethod.Post, timestampUri);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/timestamp-reply"));
            request.Content = new ByteArrayContent(requestBytes);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");
            using HttpResponseMessage response = await client.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode ||
                response.Content.Headers.ContentLength is > MaximumResponseSize)
            {
                return PeTimestampResult.Failure(FailureHResult);
            }

            byte[] responseBytes = await ReadLimitedAsync(
                response.Content,
                cancellationToken).ConfigureAwait(false);
            byte[] token = AuthenticodeAsn1.ExtractRfc3161Token(responseBytes);
            AuthenticodeAsn1.ValidateTimestampToken(token, signatureValue.Span);
            return tokenVerifier.Verify(token, signatureValue.Span)
                ? PeTimestampResult.Success(token)
                : PeTimestampResult.Failure(FailureHResult);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is HttpRequestException or
            TaskCanceledException or
            IOException or
            AsnContentException or
            InvalidDataException or
            CryptographicException or
            OverflowException)
        {
            return PeTimestampResult.Failure(
                exception.HResult < 0 ? exception.HResult : FailureHResult);
        }
    }

    private static async Task<byte[]> ReadLimitedAsync(
        HttpContent content,
        CancellationToken cancellationToken)
    {
        await using Stream source = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using MemoryStream destination = new();
        byte[] buffer = new byte[8192];
        while (true)
        {
            int read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return destination.ToArray();
            }

            if (destination.Length + read > MaximumResponseSize)
            {
                throw new InvalidDataException("The RFC 3161 response exceeds the size limit.");
            }

            destination.Write(buffer, 0, read);
        }
    }
}

internal interface IWindowsRfc3161TokenVerifier
{
    bool Verify(ReadOnlySpan<byte> timestampToken, ReadOnlySpan<byte> signatureValue);
}

internal sealed class WindowsRfc3161TokenVerifier : IWindowsRfc3161TokenVerifier
{
    public bool Verify(ReadOnlySpan<byte> timestampToken, ReadOnlySpan<byte> signatureValue)
    {
        byte[] token = timestampToken.ToArray();
        byte[] signature = signatureValue.ToArray();
        bool verified = AuthenticodeSignatureInspectorInterop.CryptVerifyTimeStampSignature(
            token,
            checked((uint)token.Length),
            signature,
            checked((uint)signature.Length),
            nint.Zero,
            out SafeTimestampContextHandle timestampContext,
            out SafeCertificateContextHandle timestampSigner,
            out SafeCertificateStoreHandle timestampStore);
        using (timestampContext)
        using (timestampSigner)
        using (timestampStore)
        {
            return verified && !timestampContext.IsInvalid && !timestampSigner.IsInvalid;
        }
    }
}

internal sealed class AuthenticodeCmsRecordInspector : IAuthenticodeCmsRecordInspector
{
    public PeAuthenticodeCmsInspection Inspect(ReadOnlyMemory<byte> encodedCms) =>
        AuthenticodeAsn1.InspectAuthenticodeCms(encodedCms);
}

internal static class PeAuthenticodeCmsEnvelope
{
    internal static byte[] ValidateSingle(
        ReadOnlyMemory<byte> encodedCms,
        NativeDigestAlgorithm expectedAlgorithm,
        ReadOnlySpan<byte> expectedImageDigest,
        string expectedCertificateThumbprint)
    {
        PeAuthenticodeCmsInspection inspection = AuthenticodeAsn1.InspectAuthenticodeCms(encodedCms);
        ValidateLogicalSignature(inspection, expectedAlgorithm, expectedImageDigest);
        if (inspection.CertificateThumbprints.Count != 1 ||
            !string.Equals(
                inspection.SignerCertificateThumbprint,
                expectedCertificateThumbprint,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException("The Authenticode leg certificate does not match its immutable plan.");
        }

        if (inspection.NestedSignatures.Count != 0)
        {
            throw new InvalidDataException("A logical Authenticode leg must not already contain a nested signature.");
        }

        return encodedCms.ToArray();
    }

    internal static byte[] CreateDual(
        ReadOnlyMemory<byte> primaryCms,
        ReadOnlySpan<byte> expectedPrimaryImageDigest,
        string expectedPrimaryCertificateThumbprint,
        ReadOnlyMemory<byte> secondaryCms,
        ReadOnlySpan<byte> expectedSecondaryImageDigest,
        string expectedSecondaryCertificateThumbprint)
    {
        byte[] validatedPrimary = ValidateSingle(
            primaryCms,
            NativeDigestAlgorithm.Sha1,
            expectedPrimaryImageDigest,
            expectedPrimaryCertificateThumbprint);
        byte[] validatedSecondary = ValidateSingle(
            secondaryCms,
            NativeDigestAlgorithm.Sha256,
            expectedSecondaryImageDigest,
            expectedSecondaryCertificateThumbprint);
        byte[] envelope = AuthenticodeAsn1.AddNestedSignature(
            validatedPrimary,
            validatedSecondary);
        PeAuthenticodeCmsInspection inspection = AuthenticodeAsn1.InspectAuthenticodeCms(envelope);
        PeAuthenticodeCmsInspection nested = AssertSingleNested(inspection);
        ValidateLogicalSignature(
            inspection,
            NativeDigestAlgorithm.Sha1,
            expectedPrimaryImageDigest);
        ValidateLogicalSignature(
            nested,
            NativeDigestAlgorithm.Sha256,
            expectedSecondaryImageDigest);
        return envelope;
    }

    private static PeAuthenticodeCmsInspection AssertSingleNested(
        PeAuthenticodeCmsInspection inspection)
    {
        if (inspection.NestedSignatures.Count != 1)
        {
            throw new InvalidDataException("A dual Authenticode envelope must contain one nested signature.");
        }

        return inspection.NestedSignatures[0];
    }

    private static void ValidateLogicalSignature(
        PeAuthenticodeCmsInspection inspection,
        NativeDigestAlgorithm expectedAlgorithm,
        ReadOnlySpan<byte> expectedImageDigest)
    {
        if (!string.Equals(
                inspection.DigestAlgorithmOid,
                AuthenticodeAsn1.DigestOid(expectedAlgorithm),
                StringComparison.Ordinal) ||
            !CryptographicOperations.FixedTimeEquals(
                inspection.ImageDigest,
                expectedImageDigest) ||
            inspection.Rfc3161TimestampCount != 1 ||
            !string.Equals(
                inspection.TimestampDigestAlgorithmOid,
                AuthenticodeOids.Sha256,
                StringComparison.Ordinal) ||
            !inspection.TimestampMessageImprintMatchesSignature)
        {
            throw new InvalidDataException("The completed Authenticode leg does not match its immutable plan.");
        }
    }
}

internal static class AuthenticodeAsn1
{
    internal const string SignedDataOid = "1.2.840.113549.1.7.2";
    internal const string SpcIndirectDataOid = "1.3.6.1.4.1.311.2.1.4";
    internal const string SpcPeImageDataOid = "1.3.6.1.4.1.311.2.1.15";
    internal const string RsaEncryptionOid = "1.2.840.113549.1.1.1";
    internal const string RsaWithSha1Oid = "1.2.840.113549.1.1.5";
    internal const string RsaWithSha256Oid = "1.2.840.113549.1.1.11";
    internal const string TimestampInfoOid = "1.2.840.113549.1.9.16.1.4";
    internal const string NestedSignatureOid = "1.3.6.1.4.1.311.2.4.1";
    private const string SubjectKeyIdentifierOid = "2.5.29.14";

    private static readonly Asn1Tag ExplicitContentTag = new(TagClass.ContextSpecific, 0, isConstructed: true);
    private static readonly Asn1Tag CertificatesTag = new(TagClass.ContextSpecific, 0, isConstructed: true);
    private static readonly Asn1Tag SubjectKeyIdentifierTag = new(TagClass.ContextSpecific, 0);
    private static readonly Asn1Tag SignedAttributesTag = new(TagClass.ContextSpecific, 0, isConstructed: true);
    private static readonly Asn1Tag UnsignedAttributesTag = new(TagClass.ContextSpecific, 1, isConstructed: true);

    internal static string DigestOid(NativeDigestAlgorithm algorithm) => algorithm switch
    {
        NativeDigestAlgorithm.Sha1 => AuthenticodeOids.Sha1,
        NativeDigestAlgorithm.Sha256 => AuthenticodeOids.Sha256,
        _ => throw new InvalidDataException("The Authenticode digest algorithm is unsupported.")
    };

    internal static byte[] EncodeIndirectData(
        NativeDigestAlgorithm algorithm,
        ReadOnlySpan<byte> imageDigest)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.PushSequence();
        writer.WriteObjectIdentifier(SpcPeImageDataOid);
        writer.PushSequence();
        writer.WriteBitString(ReadOnlySpan<byte>.Empty);
        Asn1Tag fileTag = new(TagClass.ContextSpecific, 0, isConstructed: true);
        Asn1Tag unicodeTag = new(TagClass.ContextSpecific, 2, isConstructed: true);
        Asn1Tag unicodeValueTag = new(TagClass.ContextSpecific, 0);
        writer.PushSequence(fileTag);
        writer.PushSequence(unicodeTag);
        writer.WriteOctetString(ReadOnlySpan<byte>.Empty, unicodeValueTag);
        writer.PopSequence(unicodeTag);
        writer.PopSequence(fileTag);
        writer.PopSequence();
        writer.PopSequence();
        writer.PushSequence();
        WriteAlgorithmIdentifier(writer, DigestOid(algorithm));
        writer.WriteOctetString(imageDigest);
        writer.PopSequence();
        writer.PopSequence();
        return writer.Encode();
    }

    internal static byte[] EncodeRfc3161Request(ReadOnlySpan<byte> signatureValue)
    {
        byte[] imprint = SHA256.HashData(signatureValue);
        AsnWriter writer = new(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.WriteInteger(1);
        writer.PushSequence();
        WriteAlgorithmIdentifier(writer, AuthenticodeOids.Sha256);
        writer.WriteOctetString(imprint);
        writer.PopSequence();
        writer.WriteBoolean(true);
        writer.PopSequence();
        return writer.Encode();
    }

    internal static byte[] ExtractRfc3161Token(ReadOnlyMemory<byte> response)
    {
        AsnReader reader = new(response, AsnEncodingRules.BER);
        AsnReader sequence = reader.ReadSequence();
        AsnReader statusInfo = sequence.ReadSequence();
        BigInteger status = statusInfo.ReadInteger();
        while (statusInfo.HasData)
        {
            _ = statusInfo.ReadEncodedValue();
        }

        if (status != BigInteger.Zero && status != BigInteger.One)
        {
            throw new InvalidDataException("The RFC 3161 authority rejected the request.");
        }

        if (!sequence.HasData)
        {
            throw new InvalidDataException("The RFC 3161 response contains no timestamp token.");
        }

        byte[] token = sequence.ReadEncodedValue().ToArray();
        sequence.ThrowIfNotEmpty();
        reader.ThrowIfNotEmpty();
        return token;
    }

    internal static byte[] EncodeRfc3161Attribute(ReadOnlySpan<byte> timestampToken)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.WriteObjectIdentifier(AuthenticodeOids.Rfc3161CounterSignature);
        writer.PushSetOf();
        writer.WriteEncodedValue(timestampToken);
        writer.PopSetOf();
        writer.PopSequence();
        return writer.Encode();
    }

    internal static byte[] AddNestedSignature(
        ReadOnlyMemory<byte> primaryCms,
        ReadOnlyMemory<byte> secondaryCms)
    {
        AsnReader reader = new(primaryCms, AsnEncodingRules.BER);
        AsnReader contentInfo = reader.ReadSequence();
        RequireOid(contentInfo.ReadObjectIdentifier(), SignedDataOid, "CMS content type");
        AsnReader explicitContent = contentInfo.ReadSequence(ExplicitContentTag);
        AsnReader signedData = explicitContent.ReadSequence();
        byte[] version = signedData.ReadEncodedValue().ToArray();
        byte[] digestAlgorithms = signedData.ReadEncodedValue().ToArray();
        byte[] encapsulatedContent = signedData.ReadEncodedValue().ToArray();
        var optionalSignedDataFields = new List<byte[]>();
        while (signedData.HasData && signedData.PeekTag().TagClass == TagClass.ContextSpecific)
        {
            optionalSignedDataFields.Add(signedData.ReadEncodedValue().ToArray());
        }

        AsnReader signerSet = signedData.ReadSetOf(skipSortOrderValidation: true);
        byte[] signer = signerSet.ReadEncodedValue().ToArray();
        signerSet.ThrowIfNotEmpty();
        signedData.ThrowIfNotEmpty();
        explicitContent.ThrowIfNotEmpty();
        contentInfo.ThrowIfNotEmpty();
        reader.ThrowIfNotEmpty();

        byte[] nestedSigner = AddNestedAttributeToSigner(signer, secondaryCms);
        AsnWriter writer = new(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.WriteObjectIdentifier(SignedDataOid);
        writer.PushSequence(ExplicitContentTag);
        writer.PushSequence();
        writer.WriteEncodedValue(version);
        writer.WriteEncodedValue(digestAlgorithms);
        writer.WriteEncodedValue(encapsulatedContent);
        foreach (byte[] optionalField in optionalSignedDataFields)
        {
            writer.WriteEncodedValue(optionalField);
        }

        writer.PushSetOf();
        writer.WriteEncodedValue(nestedSigner);
        writer.PopSetOf();
        writer.PopSequence();
        writer.PopSequence(ExplicitContentTag);
        writer.PopSequence();
        return writer.Encode();
    }

    internal static PeAuthenticodeCmsInspection InspectAuthenticodeCms(
        ReadOnlyMemory<byte> encodedCms)
    {
        try
        {
            return InspectAuthenticodeCms(encodedCms, nestingDepth: 0);
        }
        catch (AsnContentException exception)
        {
            throw new InvalidDataException("The Authenticode CMS is malformed.", exception);
        }
    }

    private static PeAuthenticodeCmsInspection InspectAuthenticodeCms(
        ReadOnlyMemory<byte> encodedCms,
        int nestingDepth)
    {
        encodedCms = TrimWinCertificatePadding(encodedCms);
        AsnReader reader = new(encodedCms, AsnEncodingRules.BER);
        AsnReader contentInfo = reader.ReadSequence();
        RequireOid(contentInfo.ReadObjectIdentifier(), SignedDataOid, "CMS content type");
        AsnReader explicitContent = contentInfo.ReadSequence(ExplicitContentTag);
        AsnReader signedData = explicitContent.ReadSequence();
        _ = signedData.ReadInteger();
        string outerDigestOid = ReadSingleDigestSet(signedData.ReadSetOf(skipSortOrderValidation: true));
        AsnReader encapsulated = signedData.ReadSequence();
        RequireOid(encapsulated.ReadObjectIdentifier(), SpcIndirectDataOid, "Authenticode content type");
        AsnReader encapsulatedValue = encapsulated.ReadSequence(ExplicitContentTag);
        byte[] indirectData = encapsulatedValue.PeekTag().HasSameClassAndValue(
            new Asn1Tag(UniversalTagNumber.OctetString))
            ? encapsulatedValue.ReadOctetString()
            : encapsulatedValue.ReadEncodedValue().ToArray();
        encapsulatedValue.ThrowIfNotEmpty();
        encapsulated.ThrowIfNotEmpty();

        var certificateThumbprints = new List<string>();
        var certificateIdentities = new List<CmsCertificateIdentity>();
        while (signedData.HasData && signedData.PeekTag().TagClass == TagClass.ContextSpecific)
        {
            if (signedData.PeekTag().HasSameClassAndValue(CertificatesTag))
            {
                AsnReader certificates = signedData.ReadSetOf(
                    skipSortOrderValidation: true,
                    expectedTag: CertificatesTag);
                while (certificates.HasData)
                {
                    byte[] certificate = certificates.ReadEncodedValue().ToArray();
#pragma warning disable CA5350 // Windows certificate references are SHA-1 thumbprint identities.
                    string thumbprint = Convert.ToHexString(SHA1.HashData(certificate));
#pragma warning restore CA5350
                    certificateThumbprints.Add(thumbprint);
                    certificateIdentities.Add(ReadCertificateIdentity(certificate, thumbprint));
                }
            }
            else
            {
                _ = signedData.ReadEncodedValue();
            }
        }

        AsnReader signers = signedData.ReadSetOf(skipSortOrderValidation: true);
        AsnReader signer = signers.ReadSequence();
        signers.ThrowIfNotEmpty();
        signedData.ThrowIfNotEmpty();
        explicitContent.ThrowIfNotEmpty();
        contentInfo.ThrowIfNotEmpty();
        reader.ThrowIfNotEmpty();

        _ = signer.ReadInteger();
        string signerCertificateThumbprint = ReadSignerCertificateThumbprint(
            signer,
            certificateIdentities);
        string signerDigestOid = ReadAlgorithmIdentifier(signer.ReadSequence());
        byte[] signatureInput = indirectData;
        if (signer.HasData && signer.PeekTag().HasSameClassAndValue(SignedAttributesTag))
        {
            signatureInput = signer.ReadEncodedValue().ToArray();
            signatureInput[0] = 0x31;
        }

        string signatureAlgorithm = ReadAlgorithmIdentifier(signer.ReadSequence());
        if (signatureAlgorithm is not (RsaEncryptionOid or RsaWithSha1Oid or RsaWithSha256Oid))
        {
            throw new InvalidDataException("The Authenticode signer does not use a supported RSA signature algorithm.");
        }

        byte[] signatureValue = signer.ReadOctetString();
        if (signatureValue.Length == 0)
        {
            throw new InvalidDataException("The Authenticode signer has no signature value.");
        }

        int timestampCount = 0;
        byte[]? timestampToken = null;
        PeAuthenticodeCmsInspection? nestedSignature = null;
        if (signer.HasData && signer.PeekTag().HasSameClassAndValue(UnsignedAttributesTag))
        {
            AsnReader attributes = signer.ReadSetOf(
                skipSortOrderValidation: true,
                expectedTag: UnsignedAttributesTag);
            while (attributes.HasData)
            {
                AsnReader attribute = attributes.ReadSequence();
                string oid = attribute.ReadObjectIdentifier();
                AsnReader values = attribute.ReadSetOf(skipSortOrderValidation: true);
                if (string.Equals(oid, AuthenticodeOids.LegacyCounterSignature, StringComparison.Ordinal))
                {
                    throw new InvalidDataException("A legacy Authenticode countersignature is not permitted.");
                }

                if (string.Equals(oid, AuthenticodeOids.Rfc3161CounterSignature, StringComparison.Ordinal))
                {
                    timestampCount++;
                    if (timestampCount != 1 || !values.HasData)
                    {
                        throw new InvalidDataException("The RFC 3161 timestamp attribute count is invalid.");
                    }

                    timestampToken = values.ReadEncodedValue().ToArray();
                    values.ThrowIfNotEmpty();
                }
                else if (string.Equals(oid, NestedSignatureOid, StringComparison.Ordinal))
                {
                    if (nestingDepth != 0 || nestedSignature is not null || !values.HasData)
                    {
                        throw new InvalidDataException("The nested Authenticode signature count is invalid.");
                    }

                    byte[] nestedCms = values.ReadEncodedValue().ToArray();
                    values.ThrowIfNotEmpty();
                    try
                    {
                        nestedSignature = InspectAuthenticodeCms(nestedCms, nestingDepth + 1);
                    }
                    catch (AsnContentException exception)
                    {
                        throw new InvalidDataException(
                            "The nested Authenticode signature is malformed.",
                            exception);
                    }
                }
                else
                {
                    while (values.HasData)
                    {
                        _ = values.ReadEncodedValue();
                    }
                }

                attribute.ThrowIfNotEmpty();
            }
        }

        signer.ThrowIfNotEmpty();
        (string indirectDigestOid, byte[] imageDigest) = ReadIndirectData(indirectData);
        if (!string.Equals(outerDigestOid, signerDigestOid, StringComparison.Ordinal) ||
            !string.Equals(signerDigestOid, indirectDigestOid, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The Authenticode digest identifiers disagree.");
        }

        string? timestampDigestOid = null;
        bool timestampMatches = false;
        if (timestampToken is not null)
        {
            (timestampDigestOid, byte[] messageImprint) = ReadTimestampToken(timestampToken);
            timestampMatches = CryptographicOperations.FixedTimeEquals(
                messageImprint,
                SHA256.HashData(signatureValue));
        }

        return new PeAuthenticodeCmsInspection(
            signerDigestOid,
            imageDigest,
            signatureValue,
            timestampCount,
            timestampDigestOid,
            timestampMatches,
            signerCertificateThumbprint)
        {
            CertificateThumbprints = certificateThumbprints.AsReadOnly(),
            SignatureInput = signatureInput,
            NestedSignatures = nestedSignature is null
                ? Array.Empty<PeAuthenticodeCmsInspection>()
                : [nestedSignature]
        };
    }

    private static CmsCertificateIdentity ReadCertificateIdentity(
        byte[] encodedCertificate,
        string thumbprint)
    {
        using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(encodedCertificate);
        byte[] serialNumber = certificate.GetSerialNumber();
        return new CmsCertificateIdentity(
            thumbprint,
            certificate.IssuerName.RawData,
            new BigInteger(serialNumber, isUnsigned: true, isBigEndian: false),
            ReadSubjectKeyIdentifier(certificate));
    }

    private static byte[]? ReadSubjectKeyIdentifier(X509Certificate2 certificate)
    {
        X509Extension? subjectKeyIdentifier = null;
        foreach (X509Extension extension in certificate.Extensions)
        {
            if (!string.Equals(extension.Oid?.Value, SubjectKeyIdentifierOid, StringComparison.Ordinal))
            {
                continue;
            }

            if (subjectKeyIdentifier is not null)
            {
                throw new InvalidDataException("The Authenticode certificate has duplicate subject key identifiers.");
            }

            subjectKeyIdentifier = extension;
        }

        if (subjectKeyIdentifier is null)
        {
            return null;
        }

        AsnReader reader = new(subjectKeyIdentifier.RawData, AsnEncodingRules.BER);
        byte[] value = reader.ReadOctetString();
        reader.ThrowIfNotEmpty();
        return value;
    }

    private static string ReadSignerCertificateThumbprint(
        AsnReader signer,
        IReadOnlyList<CmsCertificateIdentity> certificates)
    {
        List<CmsCertificateIdentity> matches;
        Asn1Tag tag = signer.PeekTag();
        if (tag.HasSameClassAndValue(Asn1Tag.Sequence))
        {
            AsnReader issuerAndSerial = signer.ReadSequence();
            byte[] issuer = issuerAndSerial.ReadEncodedValue().ToArray();
            BigInteger serialNumber = issuerAndSerial.ReadInteger();
            issuerAndSerial.ThrowIfNotEmpty();
            if (serialNumber.Sign < 0)
            {
                throw new InvalidDataException("The Authenticode signer serial number is invalid.");
            }

            matches = certificates
                .Where(certificate =>
                    certificate.SerialNumber == serialNumber &&
                    certificate.Issuer.AsSpan().SequenceEqual(issuer))
                .ToList();
        }
        else if (tag.HasSameClassAndValue(SubjectKeyIdentifierTag))
        {
            byte[] subjectKeyIdentifier = signer.ReadOctetString(SubjectKeyIdentifierTag);
            if (subjectKeyIdentifier.Length == 0)
            {
                throw new InvalidDataException("The Authenticode signer subject key identifier is empty.");
            }

            matches = certificates
                .Where(certificate =>
                    certificate.SubjectKeyIdentifier is not null &&
                    CryptographicOperations.FixedTimeEquals(
                        certificate.SubjectKeyIdentifier,
                        subjectKeyIdentifier))
                .ToList();
        }
        else
        {
            throw new InvalidDataException("The Authenticode signer identifier is unsupported.");
        }

        if (matches.Count != 1)
        {
            throw new InvalidDataException("The Authenticode signer identifier does not resolve uniquely.");
        }

        return matches[0].Thumbprint;
    }

    private sealed record CmsCertificateIdentity(
        string Thumbprint,
        byte[] Issuer,
        BigInteger SerialNumber,
        byte[]? SubjectKeyIdentifier);

    private static ReadOnlyMemory<byte> TrimWinCertificatePadding(ReadOnlyMemory<byte> encodedCms)
    {
        AsnDecoder.ReadEncodedValue(
            encodedCms.Span,
            AsnEncodingRules.BER,
            out _,
            out _,
            out int bytesConsumed);
        ReadOnlySpan<byte> padding = encodedCms.Span[bytesConsumed..];
        if (padding.IsEmpty)
        {
            return encodedCms;
        }
        if (padding.Length > 7 ||
            (encodedCms.Length & 7) != 0 ||
            padding.IndexOfAnyExcept((byte)0) >= 0)
        {
            throw new InvalidDataException("The Authenticode CMS has invalid trailing data.");
        }

        return encodedCms[..bytesConsumed];
    }

    private static byte[] AddNestedAttributeToSigner(
        ReadOnlyMemory<byte> encodedSigner,
        ReadOnlyMemory<byte> secondaryCms)
    {
        AsnReader reader = new(encodedSigner, AsnEncodingRules.BER);
        AsnReader signer = reader.ReadSequence();
        var fields = new List<byte[]>
        {
            signer.ReadEncodedValue().ToArray(),
            signer.ReadEncodedValue().ToArray(),
            signer.ReadEncodedValue().ToArray()
        };
        if (signer.HasData && signer.PeekTag().HasSameClassAndValue(SignedAttributesTag))
        {
            fields.Add(signer.ReadEncodedValue().ToArray());
        }

        fields.Add(signer.ReadEncodedValue().ToArray());
        fields.Add(signer.ReadEncodedValue().ToArray());
        var unsignedAttributes = new List<byte[]>();
        if (signer.HasData && signer.PeekTag().HasSameClassAndValue(UnsignedAttributesTag))
        {
            AsnReader attributes = signer.ReadSetOf(
                skipSortOrderValidation: true,
                expectedTag: UnsignedAttributesTag);
            while (attributes.HasData)
            {
                byte[] encodedAttribute = attributes.ReadEncodedValue().ToArray();
                AsnReader attributeReader = new(encodedAttribute, AsnEncodingRules.BER);
                AsnReader attribute = attributeReader.ReadSequence();
                if (string.Equals(
                    attribute.ReadObjectIdentifier(),
                    NestedSignatureOid,
                    StringComparison.Ordinal))
                {
                    throw new InvalidDataException("The primary signer already contains a nested signature.");
                }

                unsignedAttributes.Add(encodedAttribute);
            }
        }

        signer.ThrowIfNotEmpty();
        reader.ThrowIfNotEmpty();

        AsnWriter nestedAttributeWriter = new(AsnEncodingRules.DER);
        nestedAttributeWriter.PushSequence();
        nestedAttributeWriter.WriteObjectIdentifier(NestedSignatureOid);
        nestedAttributeWriter.PushSetOf();
        nestedAttributeWriter.WriteEncodedValue(secondaryCms.Span);
        nestedAttributeWriter.PopSetOf();
        nestedAttributeWriter.PopSequence();
        unsignedAttributes.Add(nestedAttributeWriter.Encode());

        AsnWriter writer = new(AsnEncodingRules.DER);
        writer.PushSequence();
        foreach (byte[] field in fields)
        {
            writer.WriteEncodedValue(field);
        }

        writer.PushSetOf(UnsignedAttributesTag);
        foreach (byte[] attribute in unsignedAttributes)
        {
            writer.WriteEncodedValue(attribute);
        }

        writer.PopSetOf(UnsignedAttributesTag);
        writer.PopSequence();
        return writer.Encode();
    }

    internal static void ValidateTimestampToken(
        ReadOnlyMemory<byte> timestampToken,
        ReadOnlySpan<byte> signatureValue)
    {
        (string digestOid, byte[] messageImprint) = ReadTimestampToken(timestampToken);
        if (!string.Equals(digestOid, AuthenticodeOids.Sha256, StringComparison.Ordinal) ||
            !CryptographicOperations.FixedTimeEquals(
                messageImprint,
                SHA256.HashData(signatureValue)))
        {
            throw new InvalidDataException("The RFC 3161 message imprint is not SHA-256 bound to the signature.");
        }
    }

    private static (string DigestOid, byte[] ImageDigest) ReadIndirectData(ReadOnlyMemory<byte> encoded)
    {
        AsnReader reader = new(encoded, AsnEncodingRules.BER);
        AsnReader indirect = reader.ReadSequence();
        AsnReader data = indirect.ReadSequence();
        RequireOid(data.ReadObjectIdentifier(), SpcPeImageDataOid, "PE image data type");
        AsnReader peImageData;
        if (data.PeekTag().HasSameClassAndValue(ExplicitContentTag))
        {
            AsnReader explicitValue = data.ReadSequence(ExplicitContentTag);
            peImageData = explicitValue.ReadSequence();
            explicitValue.ThrowIfNotEmpty();
        }
        else
        {
            peImageData = data.ReadSequence();
        }
        _ = peImageData.ReadBitString(out _);
        while (peImageData.HasData)
        {
            _ = peImageData.ReadEncodedValue();
        }

        data.ThrowIfNotEmpty();
        AsnReader digestInfo = indirect.ReadSequence();
        string digestOid = ReadAlgorithmIdentifier(digestInfo.ReadSequence());
        byte[] digest = digestInfo.ReadOctetString();
        if (digest.Length == 0)
        {
            throw new InvalidDataException("The PE image digest is empty.");
        }

        digestInfo.ThrowIfNotEmpty();
        indirect.ThrowIfNotEmpty();
        reader.ThrowIfNotEmpty();
        return (digestOid, digest);
    }

    private static (string DigestOid, byte[] MessageImprint) ReadTimestampToken(
        ReadOnlyMemory<byte> encodedToken)
    {
        AsnReader reader = new(encodedToken, AsnEncodingRules.BER);
        AsnReader contentInfo = reader.ReadSequence();
        RequireOid(contentInfo.ReadObjectIdentifier(), SignedDataOid, "timestamp CMS content type");
        AsnReader explicitContent = contentInfo.ReadSequence(ExplicitContentTag);
        AsnReader signedData = explicitContent.ReadSequence();
        _ = signedData.ReadInteger();
        _ = signedData.ReadSetOf(skipSortOrderValidation: true);
        AsnReader encapsulated = signedData.ReadSequence();
        RequireOid(encapsulated.ReadObjectIdentifier(), TimestampInfoOid, "timestamp content type");
        AsnReader explicitTimestampInfo = encapsulated.ReadSequence(ExplicitContentTag);
        byte[] encodedTimestampInfo = explicitTimestampInfo.ReadOctetString();
        explicitTimestampInfo.ThrowIfNotEmpty();
        encapsulated.ThrowIfNotEmpty();

        AsnReader timestampReader = new(encodedTimestampInfo, AsnEncodingRules.BER);
        AsnReader timestampInfo = timestampReader.ReadSequence();
        _ = timestampInfo.ReadInteger();
        _ = timestampInfo.ReadObjectIdentifier();
        AsnReader imprint = timestampInfo.ReadSequence();
        string digestOid = ReadAlgorithmIdentifier(imprint.ReadSequence());
        byte[] messageImprint = imprint.ReadOctetString();
        imprint.ThrowIfNotEmpty();
        _ = timestampInfo.ReadInteger();
        _ = timestampInfo.ReadGeneralizedTime();
        while (timestampInfo.HasData)
        {
            _ = timestampInfo.ReadEncodedValue();
        }

        timestampReader.ThrowIfNotEmpty();
        return (digestOid, messageImprint);
    }

    private static string ReadSingleDigestSet(AsnReader digestAlgorithms)
    {
        string oid = ReadAlgorithmIdentifier(digestAlgorithms.ReadSequence());
        digestAlgorithms.ThrowIfNotEmpty();
        return oid;
    }

    private static string ReadAlgorithmIdentifier(AsnReader algorithm)
    {
        string oid = algorithm.ReadObjectIdentifier();
        while (algorithm.HasData)
        {
            _ = algorithm.ReadEncodedValue();
        }

        return oid;
    }

    private static void WriteAlgorithmIdentifier(AsnWriter writer, string oid)
    {
        writer.PushSequence();
        writer.WriteObjectIdentifier(oid);
        writer.WriteNull();
        writer.PopSequence();
    }

    private static void RequireOid(string actual, string expected, string field)
    {
        if (!string.Equals(actual, expected, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"The {field} is unsupported.");
        }
    }
}
