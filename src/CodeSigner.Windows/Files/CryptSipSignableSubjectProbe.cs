using System.Runtime.InteropServices;
using CodeSigner.Core.Signing;

namespace CodeSigner.Windows.Files;

internal readonly record struct SipSubjectGuidLookup(
    bool IsAvailable,
    Guid SubjectGuid,
    int NativeErrorCode);

internal interface ICryptSipSubjectGuidRetriever
{
    SipSubjectGuidLookup Retrieve(string path);
}

public sealed class CryptSipSignableSubjectProbe : ISignableSubjectProbe
{
    private static readonly Guid PortableExecutableSubjectGuid = Guid.Parse("c689aab8-8e78-11d0-8c47-00c04fc295ee");
    private static readonly Guid WindowsInstallerSubjectGuid = Guid.Parse("000c10f1-0000-0000-c000-000000000046");
    private static readonly Guid CabinetSubjectGuid = Guid.Parse("c689aaba-8e78-11d0-8c47-00c04fc295ee");
    private static readonly Guid CatalogSubjectGuid = Guid.Parse("de351a43-8e59-11d0-8c47-00c04fc295ee");
    private static readonly Guid PowerShellSubjectGuid = Guid.Parse("603bcc1f-4b59-4e08-b724-d2c6297ef351");
    private static readonly Guid VbScriptSubjectGuid = Guid.Parse("1629f04e-2799-4db5-8fe5-ace10f17ebab");
    private static readonly Guid JScriptSubjectGuid = Guid.Parse("06c9e010-38ce-11d4-a2a3-00104bd35090");
    private static readonly Guid WsfSubjectGuid = Guid.Parse("1a610570-38ce-11d4-a2a3-00104bd35090");
    private readonly ICryptSipSubjectGuidRetriever subjectGuidRetriever;

    public CryptSipSignableSubjectProbe()
        : this(new NativeCryptSipSubjectGuidRetriever())
    {
    }

    internal CryptSipSignableSubjectProbe(ICryptSipSubjectGuidRetriever subjectGuidRetriever)
    {
        this.subjectGuidRetriever = subjectGuidRetriever ?? throw new ArgumentNullException(nameof(subjectGuidRetriever));
    }

    public SignableSubject Probe(string path)
    {
        string fullPath = Path.GetFullPath(path);
        ClassifiedSignableContent classified = SignableSubjectContentClassifier.Classify(fullPath);
        SipSubjectGuidLookup lookup = subjectGuidRetriever.Retrieve(fullPath);
        if (!lookup.IsAvailable || lookup.SubjectGuid == Guid.Empty)
        {
            throw new SignableSubjectProbeException(
                SignableSubjectProbeError.SipUnavailable,
                "Windows does not expose an Authenticode SIP for the validated file subject.",
                lookup.NativeErrorCode);
        }

        Guid? expectedSubjectGuid = ExpectedSubjectGuid(classified.PolicySubject, fullPath);
        if (expectedSubjectGuid is not null && lookup.SubjectGuid != expectedSubjectGuid.Value)
        {
            throw new SignableSubjectProbeException(
                SignableSubjectProbeError.SipSubjectMismatch,
                "The Windows SIP subject does not match the validated file family.");
        }

        return new SignableSubject(classified.PolicySubject, lookup.SubjectGuid, classified.ScriptProfile);
    }

    private static Guid? ExpectedSubjectGuid(SigningSubject subject, string path) => subject.FormatFamily switch
    {
        SigningFormatFamily.PeImage => PortableExecutableSubjectGuid,
        SigningFormatFamily.WindowsInstaller => WindowsInstallerSubjectGuid,
        SigningFormatFamily.Cabinet => CabinetSubjectGuid,
        SigningFormatFamily.Catalog => CatalogSubjectGuid,
        SigningFormatFamily.AppPackage => null,
        SigningFormatFamily.PowerShellScript when !Path.GetExtension(path).Equals(".xaml", StringComparison.OrdinalIgnoreCase) =>
            PowerShellSubjectGuid,
        SigningFormatFamily.PowerShellScript => null,
        SigningFormatFamily.WindowsScript => Path.GetExtension(path).ToLowerInvariant() switch
        {
            ".vbs" or ".vbe" => VbScriptSubjectGuid,
            ".js" or ".jse" => JScriptSubjectGuid,
            ".wsf" => WsfSubjectGuid,
            _ => null
        },
        _ => null
    };

    private sealed class NativeCryptSipSubjectGuidRetriever : ICryptSipSubjectGuidRetriever
    {
        public SipSubjectGuidLookup Retrieve(string path)
        {
            bool available = CryptSIPRetrieveSubjectGuid(path, IntPtr.Zero, out Guid subjectGuid);
            int error = available ? 0 : Marshal.GetLastWin32Error();
            return new SipSubjectGuidLookup(available, subjectGuid, error);
        }

        [DllImport("crypt32.dll", EntryPoint = "CryptSIPRetrieveSubjectGuid", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptSIPRetrieveSubjectGuid(
            string fileName,
            IntPtr fileHandle,
            out Guid subjectGuid);
    }
}
