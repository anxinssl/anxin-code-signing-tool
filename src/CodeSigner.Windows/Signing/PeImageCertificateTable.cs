using System.Buffers.Binary;

namespace CodeSigner.Windows.Signing;

internal sealed record PeCertificateRecord(
    long FileOffset,
    uint DeclaredLength,
    uint AlignedLength,
    ushort Revision,
    ushort CertificateType,
    byte[] Content);

internal sealed record PeImageCertificateTable(
    long FileLength,
    long DirectoryFieldOffset,
    uint TableOffset,
    uint TableSize,
    IReadOnlyList<PeCertificateRecord> Records)
{
    private const int DosPeOffsetField = 0x3c;
    private const int CoffHeaderSize = 20;
    private const int PeSignatureSize = 4;
    private const int CertificateDirectoryIndex = 4;
    private const int DataDirectorySize = 8;
    private const int CertificateHeaderSize = 8;
    private const int MaximumCmsSize = 64 * 1024 * 1024;
    private const ushort Pe32Magic = 0x10b;
    private const ushort Pe32PlusMagic = 0x20b;
    private const ushort WinCertificateRevision2 = 0x0200;
    private const ushort WinCertificateTypePkcsSignedData = 0x0002;

    internal static PeImageCertificateTable Read(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > uint.MaxValue)
        {
            throw new InvalidDataException("PE images larger than the certificate-table address space are unsupported.");
        }

        Span<byte> dosHeader = stackalloc byte[DosPeOffsetField + sizeof(int)];
        ReadExactlyAt(stream, 0, dosHeader);
        if (dosHeader[0] != (byte)'M' || dosHeader[1] != (byte)'Z')
        {
            throw new InvalidDataException("The file does not contain a DOS header.");
        }

        int peOffset = BinaryPrimitives.ReadInt32LittleEndian(dosHeader[DosPeOffsetField..]);
        long coffOffset = checked((long)peOffset + PeSignatureSize);
        if (peOffset < dosHeader.Length || coffOffset > stream.Length - CoffHeaderSize)
        {
            throw new InvalidDataException("The PE header offset is outside the file.");
        }

        Span<byte> signatureAndCoff = stackalloc byte[PeSignatureSize + CoffHeaderSize];
        ReadExactlyAt(stream, peOffset, signatureAndCoff);
        if (!signatureAndCoff[..PeSignatureSize].SequenceEqual("PE\0\0"u8))
        {
            throw new InvalidDataException("The PE signature is missing.");
        }

        ReadOnlySpan<byte> coff = signatureAndCoff[PeSignatureSize..];
        ushort machine = BinaryPrimitives.ReadUInt16LittleEndian(coff);
        ushort sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(coff[2..]);
        ushort optionalHeaderSize = BinaryPrimitives.ReadUInt16LittleEndian(coff[16..]);
        if (machine == 0 || sectionCount == 0 || optionalHeaderSize < sizeof(ushort))
        {
            throw new InvalidDataException("The COFF header is incomplete.");
        }

        long optionalHeaderOffset = checked(coffOffset + CoffHeaderSize);
        long optionalHeaderEnd = checked(optionalHeaderOffset + optionalHeaderSize);
        if (optionalHeaderEnd > stream.Length)
        {
            throw new InvalidDataException("The optional header is truncated.");
        }

        byte[] optionalHeader = new byte[optionalHeaderSize];
        ReadExactlyAt(stream, optionalHeaderOffset, optionalHeader);
        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(optionalHeader);
        int numberOfDirectoriesOffset;
        int directoriesOffset;
        switch (magic)
        {
            case Pe32Magic:
                numberOfDirectoriesOffset = 92;
                directoriesOffset = 96;
                break;
            case Pe32PlusMagic:
                numberOfDirectoriesOffset = 108;
                directoriesOffset = 112;
                break;
            default:
                throw new InvalidDataException("The optional-header magic is unsupported.");
        }

        int certificateDirectoryOffset = checked(directoriesOffset + (CertificateDirectoryIndex * DataDirectorySize));
        int certificateDirectoryEnd = checked(certificateDirectoryOffset + DataDirectorySize);
        if (numberOfDirectoriesOffset > optionalHeader.Length - sizeof(uint) ||
            certificateDirectoryEnd > optionalHeader.Length)
        {
            throw new InvalidDataException("The optional header has no attribute certificate directory.");
        }

        uint directoryCount = BinaryPrimitives.ReadUInt32LittleEndian(optionalHeader.AsSpan(numberOfDirectoriesOffset));
        if (directoryCount <= CertificateDirectoryIndex)
        {
            throw new InvalidDataException("The attribute certificate directory is not declared.");
        }

        ReadOnlySpan<byte> directory = optionalHeader.AsSpan(certificateDirectoryOffset, DataDirectorySize);
        uint tableOffset = BinaryPrimitives.ReadUInt32LittleEndian(directory);
        uint tableSize = BinaryPrimitives.ReadUInt32LittleEndian(directory[sizeof(uint)..]);
        long directoryFieldOffset = checked(optionalHeaderOffset + certificateDirectoryOffset);
        IReadOnlyList<PeCertificateRecord> records = ReadRecords(
            stream,
            optionalHeaderEnd,
            tableOffset,
            tableSize);
        return new PeImageCertificateTable(
            stream.Length,
            directoryFieldOffset,
            tableOffset,
            tableSize,
            records);
    }

    internal static void Append(string path, ReadOnlySpan<byte> cms)
    {
        if (cms.IsEmpty || cms.Length > MaximumCmsSize)
        {
            throw new InvalidDataException("The Authenticode CMS record size is invalid.");
        }

        PeImageCertificateTable table = Read(path);
        uint declaredLength = checked((uint)(CertificateHeaderSize + cms.Length));
        uint alignedLength = Align8(declaredLength);
        using FileStream stream = new(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        long recordOffset;
        uint newTableOffset;
        uint newTableSize;
        if (table.TableSize == 0)
        {
            recordOffset = Align8(stream.Length);
            newTableOffset = checked((uint)recordOffset);
            newTableSize = alignedLength;
        }
        else
        {
            recordOffset = checked((long)table.TableOffset + table.TableSize);
            newTableOffset = table.TableOffset;
            newTableSize = checked(table.TableSize + alignedLength);
        }

        stream.Position = stream.Length;
        WriteZeros(stream, checked((int)(recordOffset - stream.Length)));
        Span<byte> certificateHeader = stackalloc byte[CertificateHeaderSize];
        BinaryPrimitives.WriteUInt32LittleEndian(certificateHeader, declaredLength);
        BinaryPrimitives.WriteUInt16LittleEndian(certificateHeader[sizeof(uint)..], WinCertificateRevision2);
        BinaryPrimitives.WriteUInt16LittleEndian(
            certificateHeader[(sizeof(uint) + sizeof(ushort))..],
            WinCertificateTypePkcsSignedData);
        stream.Write(certificateHeader);
        stream.Write(cms);
        WriteZeros(stream, checked((int)(alignedLength - declaredLength)));

        Span<byte> directory = stackalloc byte[DataDirectorySize];
        BinaryPrimitives.WriteUInt32LittleEndian(directory, newTableOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(directory[sizeof(uint)..], newTableSize);
        stream.Position = table.DirectoryFieldOffset;
        stream.Write(directory);
        stream.Flush(flushToDisk: true);
    }

    internal static void AlignUnsignedImageForAppend(string path)
    {
        PeImageCertificateTable table = Read(path);
        if (table.TableSize != 0 || table.Records.Count != 0)
        {
            throw new InvalidDataException("Only an unsigned PE image can be aligned for signing.");
        }

        long alignedLength = Align8(table.FileLength);
        if (alignedLength == table.FileLength)
        {
            return;
        }

        using FileStream stream = new(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        stream.Position = table.FileLength;
        WriteZeros(stream, checked((int)(alignedLength - table.FileLength)));
        stream.Flush(flushToDisk: true);
    }

    private static IReadOnlyList<PeCertificateRecord> ReadRecords(
        FileStream stream,
        long optionalHeaderEnd,
        uint tableOffset,
        uint tableSize)
    {
        if (tableOffset == 0 && tableSize == 0)
        {
            return Array.Empty<PeCertificateRecord>();
        }

        long tableEnd = checked((long)tableOffset + tableSize);
        if (tableOffset == 0 || tableSize == 0 ||
            (tableOffset & 7) != 0 || (tableSize & 7) != 0 ||
            tableOffset < optionalHeaderEnd || tableEnd != stream.Length)
        {
            throw new InvalidDataException("The PE attribute certificate table bounds or alignment are invalid.");
        }

        var records = new List<PeCertificateRecord>();
        long cursor = tableOffset;
        Span<byte> header = stackalloc byte[CertificateHeaderSize];
        Span<byte> padding = stackalloc byte[7];
        while (cursor < tableEnd)
        {
            ReadExactlyAt(stream, cursor, header);
            uint declaredLength = BinaryPrimitives.ReadUInt32LittleEndian(header);
            ushort revision = BinaryPrimitives.ReadUInt16LittleEndian(header[sizeof(uint)..]);
            ushort certificateType = BinaryPrimitives.ReadUInt16LittleEndian(
                header[(sizeof(uint) + sizeof(ushort))..]);
            if (declaredLength < CertificateHeaderSize || declaredLength - CertificateHeaderSize > MaximumCmsSize)
            {
                throw new InvalidDataException("A WIN_CERTIFICATE record length is invalid.");
            }

            uint alignedLength = Align8(declaredLength);
            long next = checked(cursor + alignedLength);
            if (next > tableEnd || revision != WinCertificateRevision2 ||
                certificateType != WinCertificateTypePkcsSignedData)
            {
                throw new InvalidDataException("A WIN_CERTIFICATE record is malformed or unsupported.");
            }

            int contentLength = checked((int)declaredLength - CertificateHeaderSize);
            byte[] content = new byte[contentLength];
            ReadExactlyAt(stream, cursor + CertificateHeaderSize, content);
            int paddingLength = checked((int)(alignedLength - declaredLength));
            if (paddingLength != 0)
            {
                ReadExactlyAt(stream, cursor + declaredLength, padding[..paddingLength]);
                if (padding[..paddingLength].IndexOfAnyExcept((byte)0) >= 0)
                {
                    throw new InvalidDataException("A WIN_CERTIFICATE record has nonzero alignment padding.");
                }
            }

            records.Add(new PeCertificateRecord(
                cursor,
                declaredLength,
                alignedLength,
                revision,
                certificateType,
                content));
            cursor = next;
        }

        if (cursor != tableEnd || records.Count == 0)
        {
            throw new InvalidDataException("The PE attribute certificate table does not contain complete records.");
        }

        return records.AsReadOnly();
    }

    private static uint Align8(uint value) => checked((value + 7U) & ~7U);

    private static long Align8(long value) => checked((value + 7L) & ~7L);

    private static void ReadExactlyAt(FileStream stream, long offset, Span<byte> destination)
    {
        if (offset < 0 || offset > stream.Length - destination.Length)
        {
            throw new InvalidDataException("The PE structure extends past the end of the file.");
        }

        stream.Position = offset;
        stream.ReadExactly(destination);
    }

    private static void WriteZeros(Stream stream, int count)
    {
        Span<byte> zeros = stackalloc byte[8];
        while (count > 0)
        {
            int length = Math.Min(count, zeros.Length);
            stream.Write(zeros[..length]);
            count -= length;
        }
    }
}
