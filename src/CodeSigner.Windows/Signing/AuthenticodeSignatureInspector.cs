using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CodeSigner.Windows.Signing;

internal sealed class AuthenticodeSignatureInspector : IAuthenticodeSignatureInspector
{
    private const uint MaximumAttributes = 64;
    private const uint MaximumBlobSize = 16 * 1024 * 1024;

    public AuthenticodeSignatureCountInspection GetSignatureCount(string path) => Execute(
        path,
        index: 0,
        AuthenticodeSignatureInspectorInterop.WssGetSecondarySignatureCount,
        static (status, settings, _) => new AuthenticodeSignatureCountInspection(status, settings.SecondarySignatures));

    public AuthenticodeSignatureInspection InspectSignature(string path, uint index) => Execute(
        path,
        index,
        AuthenticodeSignatureInspectorInterop.WssVerifySpecific,
        (status, settings, data) => InspectVerifiedState(status, settings, data));

    private static AuthenticodeSignatureInspection InspectVerifiedState(
        int status,
        WinTrustSignatureSettings settings,
        WinTrustData data)
    {
        if (status != 0)
        {
            return EmptyInspection(status, settings.VerifiedSignatureIndex);
        }

        nint providerData = AuthenticodeSignatureInspectorInterop.WTHelperProvDataFromStateData(data.StateData);
        nint signerPointer = providerData == nint.Zero
            ? nint.Zero
            : AuthenticodeSignatureInspectorInterop.WTHelperGetProvSignerFromChain(
                providerData,
                signerIndex: 0,
                counterSigner: false,
                counterSignerIndex: 0);
        nint providerCertificatePointer = signerPointer == nint.Zero
            ? nint.Zero
            : AuthenticodeSignatureInspectorInterop.WTHelperGetProvCertFromChain(signerPointer, certificateIndex: 0);
        if (signerPointer == nint.Zero || providerCertificatePointer == nint.Zero)
        {
            throw new InvalidDataException("WinVerifyTrust did not expose the verified signer chain.");
        }

        NativeProviderSigner providerSigner = Marshal.PtrToStructure<NativeProviderSigner>(signerPointer);
        NativeProviderCertificate providerCertificate = Marshal.PtrToStructure<NativeProviderCertificate>(providerCertificatePointer);
        if (providerSigner.SignerInfo == nint.Zero || providerCertificate.CertificateContext == nint.Zero)
        {
            throw new InvalidDataException("WinVerifyTrust returned an incomplete signer chain.");
        }

        NativeSignerInfo signerInfo = Marshal.PtrToStructure<NativeSignerInfo>(providerSigner.SignerInfo);
        byte[] certificateDer = CopyCertificate(providerCertificate.CertificateContext);
        using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(certificateDer);
        string thumbprint = certificate.Thumbprint.ToUpperInvariant();
        string? digestOid = Marshal.PtrToStringAnsi(signerInfo.HashAlgorithm.ObjectId);
        AuthenticodeTimestampInspection timestamp = InspectTimestamp(signerInfo);
        return new AuthenticodeSignatureInspection(
            status,
            settings.VerifiedSignatureIndex,
            digestOid,
            thumbprint,
            certificateDer,
            timestamp);
    }

    private static AuthenticodeTimestampInspection InspectTimestamp(NativeSignerInfo signerInfo)
    {
        byte[]? rfc3161Value = null;
        bool hasLegacyCounterSignature = false;
        NativeCryptAttributes attributes = signerInfo.UnauthenticatedAttributes;
        if (attributes.Count > MaximumAttributes || (attributes.Count != 0 && attributes.Attributes == nint.Zero))
        {
            throw new InvalidDataException("The signer contains malformed unauthenticated attributes.");
        }

        int attributeSize = Marshal.SizeOf<NativeCryptAttribute>();
        for (uint attributeIndex = 0; attributeIndex < attributes.Count; attributeIndex++)
        {
            nint pointer = nint.Add(attributes.Attributes, checked((int)(attributeIndex * attributeSize)));
            NativeCryptAttribute attribute = Marshal.PtrToStructure<NativeCryptAttribute>(pointer);
            string? objectId = Marshal.PtrToStringAnsi(attribute.ObjectId);
            if (string.Equals(objectId, AuthenticodeOids.LegacyCounterSignature, StringComparison.Ordinal))
            {
                hasLegacyCounterSignature = true;
                continue;
            }

            if (!string.Equals(objectId, AuthenticodeOids.Rfc3161CounterSignature, StringComparison.Ordinal))
            {
                continue;
            }

            if (rfc3161Value is not null || attribute.ValueCount != 1 || attribute.Values == nint.Zero)
            {
                return InvalidRfc3161Timestamp();
            }

            NativeBlob value = Marshal.PtrToStructure<NativeBlob>(attribute.Values);
            rfc3161Value = CopyBlob(value);
        }

        if (rfc3161Value is null)
        {
            return new AuthenticodeTimestampInspection(
                hasLegacyCounterSignature
                    ? AuthenticodeTimestampKind.LegacyCounterSignature
                    : AuthenticodeTimestampKind.Missing,
                MessageImprintAlgorithmOid: null,
                CryptographicallyValid: false,
                ChainValid: false,
                TimeValid: false,
                TimestampingEkuValid: false);
        }

        byte[] encryptedHash = CopyBlob(signerInfo.EncryptedHash);
        if (encryptedHash.Length == 0)
        {
            return InvalidRfc3161Timestamp();
        }

        bool verified = AuthenticodeSignatureInspectorInterop.CryptVerifyTimeStampSignature(
            rfc3161Value,
            checked((uint)rfc3161Value.Length),
            encryptedHash,
            checked((uint)encryptedHash.Length),
            nint.Zero,
            out SafeTimestampContextHandle timestampContext,
            out SafeCertificateContextHandle timestampSigner,
            out SafeCertificateStoreHandle timestampStore);
        using (timestampContext)
        using (timestampSigner)
        using (timestampStore)
        {
            if (!verified || timestampContext.IsInvalid || timestampSigner.IsInvalid)
            {
                return InvalidRfc3161Timestamp();
            }

            NativeTimestampContext context = Marshal.PtrToStructure<NativeTimestampContext>(
                timestampContext.DangerousGetHandle());
            if (context.TimestampInfo == nint.Zero)
            {
                return InvalidRfc3161Timestamp();
            }

            NativeTimestampInfo info = Marshal.PtrToStructure<NativeTimestampInfo>(context.TimestampInfo);
            string? imprintOid = Marshal.PtrToStringAnsi(info.HashAlgorithm.ObjectId);
            DateTimeOffset timestampTime = DateTimeOffset.FromFileTime(info.Time.ToInt64());
            byte[] signerDer = CopyCertificate(timestampSigner.DangerousGetHandle());
            using X509Certificate2 signerCertificate = X509CertificateLoader.LoadCertificate(signerDer);
            bool ekuValid = HasTimestampingEku(signerCertificate);
            bool timeValid = timestampTime <= DateTimeOffset.UtcNow.AddMinutes(5) &&
                timestampTime >= signerCertificate.NotBefore.ToUniversalTime() &&
                timestampTime <= signerCertificate.NotAfter.ToUniversalTime();
            bool chainValid = BuildTimestampChain(signerCertificate, timestampStore, timestampTime);
            return new AuthenticodeTimestampInspection(
                AuthenticodeTimestampKind.Rfc3161,
                imprintOid,
                CryptographicallyValid: true,
                chainValid,
                timeValid,
                ekuValid);
        }
    }

    private static bool BuildTimestampChain(
        X509Certificate2 signer,
        SafeCertificateStoreHandle timestampStore,
        DateTimeOffset timestampTime)
    {
        using X509Chain chain = new();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.VerificationTime = timestampTime.UtcDateTime;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(AuthenticodeOids.TimestampingEku));

        List<X509Certificate2> additionalCertificates = [];
        try
        {
            if (!timestampStore.IsInvalid)
            {
                nint certificateContext = nint.Zero;
                while ((certificateContext = AuthenticodeSignatureInspectorInterop.CertEnumCertificatesInStore(
                    timestampStore,
                    certificateContext)) != nint.Zero)
                {
                    X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(
                        CopyCertificate(certificateContext));
                    additionalCertificates.Add(certificate);
                    chain.ChainPolicy.ExtraStore.Add(certificate);
                }
            }

            return chain.Build(signer);
        }
        finally
        {
            foreach (X509Certificate2 certificate in additionalCertificates)
            {
                certificate.Dispose();
            }
        }
    }

    private static bool HasTimestampingEku(X509Certificate2 certificate)
    {
        foreach (X509Extension extension in certificate.Extensions)
        {
            if (extension is X509EnhancedKeyUsageExtension enhancedKeyUsage)
            {
                return enhancedKeyUsage.EnhancedKeyUsages
                    .OfType<Oid>()
                    .Any(oid => string.Equals(oid.Value, AuthenticodeOids.TimestampingEku, StringComparison.Ordinal));
            }
        }

        return false;
    }

    private static T Execute<T>(
        string path,
        uint index,
        uint signatureFlags,
        Func<int, WinTrustSignatureSettings, WinTrustData, T> readState)
    {
        string fullPath = Path.GetFullPath(path);
        nint filePath = Marshal.StringToCoTaskMemUni(fullPath);
        nint fileInfoPointer = nint.Zero;
        nint settingsPointer = nint.Zero;
        nint dataPointer = nint.Zero;
        bool verifyCalled = false;
        try
        {
            fileInfoPointer = Allocate(new WinTrustFileInfo
            {
                Size = checked((uint)Marshal.SizeOf<WinTrustFileInfo>()),
                FilePath = filePath
            });
            settingsPointer = Allocate(new WinTrustSignatureSettings
            {
                Size = checked((uint)Marshal.SizeOf<WinTrustSignatureSettings>()),
                Index = index,
                Flags = signatureFlags
            });
            dataPointer = Allocate(new WinTrustData
            {
                Size = checked((uint)Marshal.SizeOf<WinTrustData>()),
                UiChoice = AuthenticodeSignatureInspectorInterop.WtdUiNone,
                UnionChoice = AuthenticodeSignatureInspectorInterop.WtdChoiceFile,
                FileInfo = fileInfoPointer,
                StateAction = AuthenticodeSignatureInspectorInterop.WtdStateActionVerify,
                SignatureSettings = settingsPointer
            });

            Guid action = AuthenticodeSignatureInspectorInterop.GenericVerifyV2;
            int status = AuthenticodeSignatureInspectorInterop.WinVerifyTrust(nint.Zero, ref action, dataPointer);
            verifyCalled = true;
            WinTrustSignatureSettings settings = Marshal.PtrToStructure<WinTrustSignatureSettings>(settingsPointer);
            WinTrustData data = Marshal.PtrToStructure<WinTrustData>(dataPointer);
            return readState(status, settings, data);
        }
        finally
        {
            if (verifyCalled && dataPointer != nint.Zero)
            {
                WinTrustData data = Marshal.PtrToStructure<WinTrustData>(dataPointer);
                data.StateAction = AuthenticodeSignatureInspectorInterop.WtdStateActionClose;
                Marshal.StructureToPtr(data, dataPointer, fDeleteOld: false);
                Guid action = AuthenticodeSignatureInspectorInterop.GenericVerifyV2;
                _ = AuthenticodeSignatureInspectorInterop.WinVerifyTrust(nint.Zero, ref action, dataPointer);
            }

            Marshal.FreeCoTaskMem(dataPointer);
            Marshal.FreeCoTaskMem(settingsPointer);
            Marshal.FreeCoTaskMem(fileInfoPointer);
            Marshal.FreeCoTaskMem(filePath);
        }
    }

    private static nint Allocate<T>(T value)
        where T : struct
    {
        nint pointer = Marshal.AllocCoTaskMem(Marshal.SizeOf<T>());
        Marshal.StructureToPtr(value, pointer, fDeleteOld: false);
        return pointer;
    }

    private static byte[] CopyCertificate(nint certificateContextPointer)
    {
        if (certificateContextPointer == nint.Zero)
        {
            throw new InvalidDataException("A certificate context was missing.");
        }

        NativeCertificateContext context = Marshal.PtrToStructure<NativeCertificateContext>(certificateContextPointer);
        return CopyBytes(context.EncodedCertificate, context.EncodedCertificateSize);
    }

    private static byte[] CopyBlob(NativeBlob blob) => CopyBytes(blob.Data, blob.Size);

    private static byte[] CopyBytes(nint pointer, uint size)
    {
        if (size > MaximumBlobSize || (size != 0 && pointer == nint.Zero))
        {
            throw new InvalidDataException("A native cryptographic blob was malformed or too large.");
        }

        byte[] bytes = new byte[checked((int)size)];
        if (bytes.Length != 0)
        {
            Marshal.Copy(pointer, bytes, 0, bytes.Length);
        }

        return bytes;
    }

    private static AuthenticodeTimestampInspection InvalidRfc3161Timestamp() => new(
        AuthenticodeTimestampKind.Rfc3161,
        MessageImprintAlgorithmOid: null,
        CryptographicallyValid: false,
        ChainValid: false,
        TimeValid: false,
        TimestampingEkuValid: false);

    private static AuthenticodeSignatureInspection EmptyInspection(int status, uint verifiedIndex) => new(
        status,
        verifiedIndex,
        FileDigestAlgorithmOid: null,
        SignerThumbprint: null,
        SignerCertificateDer: [],
        new AuthenticodeTimestampInspection(
            AuthenticodeTimestampKind.Missing,
            MessageImprintAlgorithmOid: null,
            CryptographicallyValid: false,
            ChainValid: false,
            TimeValid: false,
            TimestampingEkuValid: false));
}
