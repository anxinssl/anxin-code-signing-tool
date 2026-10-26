using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace CodeSigner.Windows.Signing;

internal interface IPeImageDigestProvider
{
    byte[] ComputeDigest(string path, NativeDigestAlgorithm algorithm);
}

internal sealed class AuthenticodePeImageDigestProvider : IPeImageDigestProvider
{
    private const int DosPeOffsetField = 0x3c;
    private const int PeSignatureSize = 4;
    private const int CoffHeaderSize = 20;
    private const int OptionalHeaderChecksumOffset = 64;
    private const int OptionalHeaderSizeOfHeadersOffset = 60;
    private const int SectionHeaderSize = 40;
    private const int SectionRawSizeOffset = 16;
    private const int SectionRawPointerOffset = 20;
    private const int DigestBufferSize = 80 * 1024;
    private const ushort Pe32Magic = 0x10b;
    private const ushort Pe32PlusMagic = 0x20b;

    public byte[] ComputeDigest(string path, NativeDigestAlgorithm algorithm)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        HashAlgorithmName hashAlgorithm = algorithm switch
        {
            NativeDigestAlgorithm.Sha1 => HashAlgorithmName.SHA1,
            NativeDigestAlgorithm.Sha256 => HashAlgorithmName.SHA256,
            _ => throw new InvalidDataException("The PE digest algorithm is unsupported.")
        };

        PeImageCertificateTable table = PeImageCertificateTable.Read(path);
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length != table.FileLength)
        {
            throw new InvalidDataException("The PE image changed while its Authenticode digest was prepared.");
        }

        AuthenticodeDigestLayout layout = ReadLayout(stream, table);
        using IncrementalHash hash = IncrementalHash.CreateHash(hashAlgorithm);
        byte[] buffer = new byte[DigestBufferSize];
        AppendRange(stream, hash, buffer, 0, layout.ChecksumOffset);
        AppendRange(
            stream,
            hash,
            buffer,
            checked(layout.ChecksumOffset + sizeof(uint)),
            checked(layout.CertificateDirectoryOffset - layout.ChecksumOffset - sizeof(uint)));
        AppendRange(
            stream,
            hash,
            buffer,
            checked(layout.CertificateDirectoryOffset + (sizeof(uint) * 2)),
            checked(layout.SizeOfHeaders - layout.CertificateDirectoryOffset - (sizeof(uint) * 2)));

        long hashedByteCount = layout.SizeOfHeaders;
        foreach (AuthenticodeDigestSection section in layout.Sections)
        {
            AppendRange(stream, hash, buffer, section.RawOffset, section.RawSize);
            hashedByteCount = checked(hashedByteCount + section.RawSize);
        }

        long extraByteCount = checked(layout.ContentLength - hashedByteCount);
        AppendRange(stream, hash, buffer, hashedByteCount, extraByteCount);
        return hash.GetHashAndReset();
    }

    private static AuthenticodeDigestLayout ReadLayout(
        FileStream stream,
        PeImageCertificateTable table)
    {
        Span<byte> dosHeader = stackalloc byte[DosPeOffsetField + sizeof(int)];
        ReadExactlyAt(stream, 0, dosHeader);
        int peOffset = BinaryPrimitives.ReadInt32LittleEndian(dosHeader[DosPeOffsetField..]);
        long coffOffset = checked((long)peOffset + PeSignatureSize);
        Span<byte> coff = stackalloc byte[CoffHeaderSize];
        ReadExactlyAt(stream, coffOffset, coff);
        ushort sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(coff[2..]);
        ushort optionalHeaderSize = BinaryPrimitives.ReadUInt16LittleEndian(coff[16..]);
        long optionalHeaderOffset = checked(coffOffset + CoffHeaderSize);
        byte[] optionalHeader = new byte[optionalHeaderSize];
        ReadExactlyAt(stream, optionalHeaderOffset, optionalHeader);
        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(optionalHeader);
        if (magic is not (Pe32Magic or Pe32PlusMagic) ||
            optionalHeader.Length < OptionalHeaderChecksumOffset + sizeof(uint) ||
            optionalHeader.Length < OptionalHeaderSizeOfHeadersOffset + sizeof(uint))
        {
            throw new InvalidDataException("The PE optional header cannot be hashed by Authenticode.");
        }

        long checksumOffset = checked(optionalHeaderOffset + OptionalHeaderChecksumOffset);
        long sizeOfHeaders = BinaryPrimitives.ReadUInt32LittleEndian(
            optionalHeader.AsSpan(OptionalHeaderSizeOfHeadersOffset));
        long sectionTableOffset = checked(optionalHeaderOffset + optionalHeaderSize);
        long sectionTableEnd = checked(sectionTableOffset + ((long)sectionCount * SectionHeaderSize));
        long contentLength = table.TableSize == 0 ? table.FileLength : table.TableOffset;
        if (checksumOffset + sizeof(uint) > table.DirectoryFieldOffset ||
            table.DirectoryFieldOffset + (sizeof(uint) * 2) > sizeOfHeaders ||
            sectionTableEnd > sizeOfHeaders ||
            sizeOfHeaders > contentLength)
        {
            throw new InvalidDataException("The PE Authenticode header ranges are invalid.");
        }

        var sections = new List<AuthenticodeDigestSection>(sectionCount);
        Span<byte> sectionHeader = stackalloc byte[SectionHeaderSize];
        for (int index = 0; index < sectionCount; index++)
        {
            ReadExactlyAt(stream, checked(sectionTableOffset + ((long)index * SectionHeaderSize)), sectionHeader);
            long rawSize = BinaryPrimitives.ReadUInt32LittleEndian(
                sectionHeader[SectionRawSizeOffset..]);
            if (rawSize == 0)
            {
                continue;
            }

            long rawOffset = BinaryPrimitives.ReadUInt32LittleEndian(
                sectionHeader[SectionRawPointerOffset..]);
            sections.Add(new AuthenticodeDigestSection(rawOffset, rawSize));
        }

        sections.Sort(static (left, right) => left.RawOffset.CompareTo(right.RawOffset));
        long previousEnd = sizeOfHeaders;
        long hashedByteCount = sizeOfHeaders;
        foreach (AuthenticodeDigestSection section in sections)
        {
            long sectionEnd = checked(section.RawOffset + section.RawSize);
            if (section.RawOffset < sizeOfHeaders ||
                section.RawOffset < previousEnd ||
                sectionEnd > contentLength)
            {
                throw new InvalidDataException("The PE section ranges overlap or extend outside the Authenticode image.");
            }

            previousEnd = sectionEnd;
            hashedByteCount = checked(hashedByteCount + section.RawSize);
        }

        if (hashedByteCount > contentLength)
        {
            throw new InvalidDataException("The PE section sizes exceed the Authenticode image length.");
        }

        return new AuthenticodeDigestLayout(
            checksumOffset,
            table.DirectoryFieldOffset,
            sizeOfHeaders,
            contentLength,
            sections.AsReadOnly());
    }

    private static void AppendRange(
        FileStream stream,
        IncrementalHash hash,
        byte[] buffer,
        long offset,
        long length)
    {
        if (offset < 0 || length < 0 || offset > stream.Length - length)
        {
            throw new InvalidDataException("A PE Authenticode digest range is outside the image.");
        }

        stream.Position = offset;
        long remaining = length;
        while (remaining > 0)
        {
            int count = checked((int)Math.Min(buffer.Length, remaining));
            stream.ReadExactly(buffer.AsSpan(0, count));
            hash.AppendData(buffer.AsSpan(0, count));
            remaining -= count;
        }
    }

    private static void ReadExactlyAt(FileStream stream, long offset, Span<byte> destination)
    {
        if (offset < 0 || offset > stream.Length - destination.Length)
        {
            throw new InvalidDataException("The PE digest structure extends past the end of the file.");
        }

        stream.Position = offset;
        stream.ReadExactly(destination);
    }

    private sealed record AuthenticodeDigestSection(long RawOffset, long RawSize);

    private sealed record AuthenticodeDigestLayout(
        long ChecksumOffset,
        long CertificateDirectoryOffset,
        long SizeOfHeaders,
        long ContentLength,
        IReadOnlyList<AuthenticodeDigestSection> Sections);
}

[StructLayout(LayoutKind.Sequential)]
internal struct NativeCertificateIssuerSerial
{
    internal NativeBlob Issuer;
    internal NativeBlob SerialNumber;
}

[StructLayout(LayoutKind.Explicit, Size = 40)]
internal struct NativeCertificateId
{
    [FieldOffset(0)]
    internal uint Choice;

    [FieldOffset(8)]
    internal NativeCertificateIssuerSerial IssuerSerial;
}

[StructLayout(LayoutKind.Sequential)]
internal struct NativeCmsgSignerEncodeInfo
{
    internal uint Size;
    internal nint CertificateInfo;
    internal nint KeyHandle;
    internal uint KeySpec;
    internal NativeAlgorithmIdentifier HashAlgorithm;
    internal nint HashAuxInfo;
    internal uint AuthenticatedAttributeCount;
    internal nint AuthenticatedAttributes;
    internal uint UnauthenticatedAttributeCount;
    internal nint UnauthenticatedAttributes;
    internal NativeCertificateId SignerId;
    internal NativeAlgorithmIdentifier HashEncryptionAlgorithm;
    internal nint HashEncryptionAuxInfo;
}

[StructLayout(LayoutKind.Sequential)]
internal struct NativeCmsgSignedEncodeInfo
{
    internal uint Size;
    internal uint SignerCount;
    internal nint Signers;
    internal uint CertificateCount;
    internal nint Certificates;
    internal uint CertificateRevocationListCount;
    internal nint CertificateRevocationLists;
    internal uint AttributeCertificateCount;
    internal nint AttributeCertificates;
}

[StructLayout(LayoutKind.Sequential)]
internal struct NativeCmsgAddSignerUnauthenticatedAttribute
{
    internal uint Size;
    internal uint SignerIndex;
    internal NativeBlob EncodedAttribute;
}

internal static class PeAuthenticodeCryptographicInterop
{
    internal const uint X509AndPkcs7Encoding = 0x00010001;
    internal const uint SignedMessage = 2;
    internal const uint ContentParameter = 2;
    internal const uint EncodedMessageParameter = 29;
    internal const uint AddSignerUnauthenticatedAttribute = 8;

    [DllImport(
        "crypt32.dll",
        ExactSpelling = true,
        SetLastError = true,
        CharSet = CharSet.Ansi,
        BestFitMapping = false,
        ThrowOnUnmappableChar = true)]
    internal static extern SafeCryptographicMessageHandle CryptMsgOpenToEncode(
        uint encodingType,
        uint flags,
        uint messageType,
        ref NativeCmsgSignedEncodeInfo encodeInfo,
        [MarshalAs(UnmanagedType.LPStr)] string innerContentObjectId,
        nint streamInfo);

    [DllImport("crypt32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern SafeCryptographicMessageHandle CryptMsgOpenToDecode(
        uint encodingType,
        uint flags,
        uint messageType,
        nint legacyProvider,
        nint recipientInfo,
        nint streamInfo);

    [DllImport("crypt32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptMsgUpdate(
        SafeCryptographicMessageHandle message,
        byte[] data,
        uint dataLength,
        [MarshalAs(UnmanagedType.Bool)] bool final);

    [DllImport("crypt32.dll", EntryPoint = "CryptMsgGetParam", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptMsgGetParameterSize(
        SafeCryptographicMessageHandle message,
        uint parameterType,
        uint index,
        nint data,
        ref uint dataLength);

    [DllImport("crypt32.dll", EntryPoint = "CryptMsgGetParam", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptMsgGetParameter(
        SafeCryptographicMessageHandle message,
        uint parameterType,
        uint index,
        byte[] data,
        ref uint dataLength);

    [DllImport("crypt32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptMsgControl(
        SafeCryptographicMessageHandle message,
        uint flags,
        uint controlType,
        ref NativeCmsgAddSignerUnauthenticatedAttribute controlParameters);

    [DllImport("crypt32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptMsgClose(nint message);
}

internal sealed class SafeCryptographicMessageHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeCryptographicMessageHandle()
        : base(ownsHandle: true)
    {
    }

    protected override bool ReleaseHandle() => PeAuthenticodeCryptographicInterop.CryptMsgClose(handle);
}
