using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CodeSigner.Core.Signing;
using CodeSigner.Windows.Files;
using Microsoft.Win32.SafeHandles;
using CoreSignatureLeg = CodeSigner.Core.Signing.SignatureLeg;

namespace CodeSigner.Windows.Signing;

public sealed class WindowsPowerShellSipBridge : IWindowsSipSigningBridge
{
    private const int InvalidArgumentHResult = unchecked((int)0x80070057);
    private const int FailureHResult = unchecked((int)0x80004005);
    private const int CancelledHResult = unchecked((int)0x800704C7);
    private const int MaximumResponseBytes = 32 * 1024;
    private const int SchemaVersion = 1;
    private static readonly SearchValues<char> InjectionCharacters =
        SearchValues.Create("\"'`;|&<>$(){}\r\n\t\0");
    // Copy-name parentheses are literal data in JSON/-LiteralPath, never command text.
    private static readonly SearchValues<char> UnsafePathCharacters =
        SearchValues.Create("\"'`;|&<>${}\r\n\t\0");
    private static readonly HashSet<string> ResponseFields = new(StringComparer.Ordinal)
    {
        "schemaVersion",
        "resultCode",
        "hresult",
        "signatureStatus",
        "fileDigest",
        "signerThumbprint",
        "timestampProtocol",
        "timestampDigest",
        "cmsVerified",
        "subjectVerified",
        "contentVerified",
        "existingSignatureDisposition"
    };
    private static readonly JsonSerializerOptions ResponseJsonOptions = new()
    {
        AllowTrailingCommas = false,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 4
    };

    private readonly IWindowsPowerShellProcessRunner processRunner;
    private readonly IWindowsPowerShellEnvironment environment;
    private readonly ISignableSubjectProbe subjectProbe;
    private readonly IWindowsSipSignatureVerifier verifier;
    private readonly IWindowsSipAtomicFileReplacer atomicFileReplacer;

    public WindowsPowerShellSipBridge()
    {
        var probe = new CryptSipSignableSubjectProbe();
        processRunner = new SystemWindowsPowerShellProcessRunner();
        environment = new SystemWindowsPowerShellEnvironment();
        subjectProbe = probe;
        verifier = new WindowsSipSignatureVerifier(probe);
        atomicFileReplacer = new SystemWindowsSipAtomicFileReplacer();
    }

    internal WindowsPowerShellSipBridge(
        IWindowsPowerShellProcessRunner processRunner,
        IWindowsPowerShellEnvironment environment,
        ISignableSubjectProbe subjectProbe,
        IWindowsSipSignatureVerifier verifier,
        IWindowsSipAtomicFileReplacer? atomicFileReplacer = null)
    {
        this.processRunner = processRunner ?? throw new ArgumentNullException(nameof(processRunner));
        this.environment = environment ?? throw new ArgumentNullException(nameof(environment));
        this.subjectProbe = subjectProbe ?? throw new ArgumentNullException(nameof(subjectProbe));
        this.verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        this.atomicFileReplacer = atomicFileReplacer ?? new SystemWindowsSipAtomicFileReplacer();
    }

    public async Task<WindowsSipSigningResult> ExecuteAsync(
        string originalPath,
        string stagedPath,
        SigningPlan plan,
        int stagingOwnerPid,
        DateTimeOffset stagingOwnerStartUtc,
        Func<WindowsSipSigningPhase, CancellationToken, ValueTask>? reportProgress,
        CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return Failure(WindowsSipSigningError.Cancelled, CancelledHResult);
        }

        if (!TryResolveExecutable(out string? executablePath))
        {
            return Failure(WindowsSipSigningError.PowerShellUnavailable, FailureHResult);
        }

        ValidatedSipInput input;
        try
        {
            input = ValidateInput(
                originalPath,
                stagedPath,
                plan,
                stagingOwnerPid,
                stagingOwnerStartUtc);
        }
        catch (SignableSubjectProbeException exception) when (exception.Error is
            SignableSubjectProbeError.SipUnavailable or
            SignableSubjectProbeError.SipSubjectMismatch)
        {
            return Failure(WindowsSipSigningError.SipUnavailable, FailureHResult);
        }
        catch (SignableSubjectProbeException exception) when (exception.Error is
            SignableSubjectProbeError.InvalidAppPackage or
            SignableSubjectProbeError.IncompatibleBlockMapHash or
            SignableSubjectProbeError.UnsafePackagePath)
        {
            return Failure(WindowsSipSigningError.PackageIncompatible, InvalidArgumentHResult);
        }
        catch (Exception exception) when (exception is
            ArgumentException or
            IOException or
            UnauthorizedAccessException or
            FilePipelineException or
            System.Security.SecurityException)
        {
            return Failure(WindowsSipSigningError.InvalidInput, InvalidArgumentHResult);
        }

        string originalHash = "";
        string stagedHash;
        LockedFileSnapshot? originalSnapshot = null;
        LockedFileSnapshot? stagedSnapshot = null;
        try
        {
            originalSnapshot = LockedFileSnapshot.Open(input.OriginalPath, FileShare.Read | FileShare.Delete);
            stagedSnapshot = LockedFileSnapshot.Open(input.StagedPath, FileShare.Read | FileShare.Delete);
            SignableSubject stagedSubject = ValidateSubjects(input, originalSnapshot, stagedSnapshot);
            input = input with { StagedSubject = stagedSubject };
            originalHash = await originalSnapshot.HashAsync(cancellationToken).ConfigureAwait(false);
            stagedHash = await stagedSnapshot.HashAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            if (stagedSnapshot is not null)
            {
                await stagedSnapshot.DisposeAsync().ConfigureAwait(false);
            }

            if (originalSnapshot is not null)
            {
                await originalSnapshot.DisposeAsync().ConfigureAwait(false);
            }

            return Failure(WindowsSipSigningError.Cancelled, CancelledHResult);
        }
        catch (SignableSubjectProbeException exception) when (exception.Error is
            SignableSubjectProbeError.SipUnavailable or
            SignableSubjectProbeError.SipSubjectMismatch)
        {
            if (stagedSnapshot is not null)
            {
                await stagedSnapshot.DisposeAsync().ConfigureAwait(false);
            }

            if (originalSnapshot is not null)
            {
                await originalSnapshot.DisposeAsync().ConfigureAwait(false);
            }

            return Failure(WindowsSipSigningError.SipUnavailable, FailureHResult);
        }
        catch (SignableSubjectProbeException exception) when (exception.Error is
            SignableSubjectProbeError.InvalidAppPackage or
            SignableSubjectProbeError.IncompatibleBlockMapHash or
            SignableSubjectProbeError.UnsafePackagePath)
        {
            if (stagedSnapshot is not null)
            {
                await stagedSnapshot.DisposeAsync().ConfigureAwait(false);
            }

            if (originalSnapshot is not null)
            {
                await originalSnapshot.DisposeAsync().ConfigureAwait(false);
            }

            return Failure(WindowsSipSigningError.PackageIncompatible, InvalidArgumentHResult);
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            if (stagedSnapshot is not null)
            {
                await stagedSnapshot.DisposeAsync().ConfigureAwait(false);
            }

            if (originalSnapshot is not null)
            {
                await originalSnapshot.DisposeAsync().ConfigureAwait(false);
            }

            return Failure(WindowsSipSigningError.InvalidInput, InvalidArgumentHResult);
        }

        if (!string.Equals(originalHash, stagedHash, StringComparison.Ordinal))
        {
            await originalSnapshot!.DisposeAsync().ConfigureAwait(false);
            await stagedSnapshot!.DisposeAsync().ConfigureAwait(false);
            return Failure(WindowsSipSigningError.OriginalChanged, FailureHResult, originalHash);
        }

        string bridgeDirectory = Path.Combine(
            Path.GetDirectoryName(input.StagedPath)!,
            $".sip-bridge-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(bridgeDirectory);
            PathSafety.EnsureNoReparsePoints(bridgeDirectory);
            string workPath = Path.Combine(
                bridgeDirectory,
                $"sip-work-{Guid.NewGuid():N}{input.Plan.Subject.Extension}");
            await CopySnapshotAsync(stagedSnapshot!, workPath, cancellationToken).ConfigureAwait(false);
            PathSafety.EnsureNoReparsePoints(workPath);
            WindowsSipFileIdentity workIdentity = ReadPathIdentity(workPath, FileShare.ReadWrite | FileShare.Delete);
            BridgeRequest request = CreateRequest(input, workPath);
            string requestPayload = JsonSerializer.Serialize(request);

            ProcessStartInfo startInfo = CreateStartInfo(executablePath!, bridgeDirectory);
            if (reportProgress is not null)
            {
                await reportProgress(WindowsSipSigningPhase.Signing, cancellationToken).ConfigureAwait(false);
            }

            WindowsPowerShellProcessResult processResult;
            try
            {
                processResult = await processRunner.RunAsync(
                    startInfo,
                    requestPayload,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return Failure(WindowsSipSigningError.Cancelled, CancelledHResult, originalHash);
            }

            WindowsSipSigningError? processFailure = MapStartFailure(processResult.StartFailure);
            if (processFailure is not null)
            {
                return Failure(processFailure.Value, FailureHResult, originalHash);
            }

            if (processResult.ExitCode == 51)
            {
                return Failure(WindowsSipSigningError.PowerShellUnavailable, FailureHResult, originalHash);
            }

            BridgeResponse response;
            try
            {
                if (processResult.StandardOutputLimitExceeded)
                {
                    throw new InvalidDataException("The SIP bridge response exceeds its bound.");
                }

                response = ReadResponse(processResult.StandardOutput ?? []);
            }
            catch (Exception exception) when (exception is JsonException or InvalidDataException)
            {
                return Failure(WindowsSipSigningError.MalformedResponse, FailureHResult, originalHash);
            }

            if (response.ResultCode is not ("signed" or "existingSignatureValid"))
            {
                return Failure(MapResponseFailure(response), NormalizeFailureHResult(response.HResult), originalHash);
            }

            if (processResult.ExitCode != 0 || !ValidateSuccessResponse(response, request))
            {
                return Failure(WindowsSipSigningError.VerificationFailed, FailureHResult, originalHash);
            }

            if (reportProgress is not null)
            {
                await reportProgress(WindowsSipSigningPhase.Verifying, cancellationToken).ConfigureAwait(false);
            }

            bool skipped = string.Equals(response.ResultCode, "existingSignatureValid", StringComparison.Ordinal);
            await using LockedFileSnapshot verifiedWork = LockedFileSnapshot.Open(
                workPath,
                FileShare.Read | FileShare.Delete);
            if (verifiedWork.Identity != workIdentity ||
                !PathIdentityMatches(workPath, workIdentity, FileShare.Read | FileShare.Delete))
            {
                return Failure(WindowsSipSigningError.ProcessFailed, FailureHResult, originalHash);
            }

            string verifiedWorkHash = await verifiedWork.HashAsync(cancellationToken).ConfigureAwait(false);
            WindowsSipVerificationResult verification = skipped
                ? verifier.VerifyExisting(input.OriginalPath, workPath, input.Plan)
                : verifier.VerifySigned(input.OriginalPath, workPath, input.Plan);
            if (!verification.Succeeded || verification.Error != WindowsSipVerificationError.None)
            {
                return Failure(MapVerificationFailure(verification.Error), FailureHResult, originalHash);
            }

            string postVerificationHash = await verifiedWork.HashAsync(cancellationToken).ConfigureAwait(false);
            if (!string.Equals(verifiedWorkHash, postVerificationHash, StringComparison.Ordinal) ||
                !PathIdentityMatches(workPath, workIdentity, FileShare.Read | FileShare.Delete))
            {
                return Failure(WindowsSipSigningError.VerificationFailed, FailureHResult, originalHash);
            }

            WindowsSipSigningError? revalidationError = await RevalidateForCommitAsync(
                input,
                originalSnapshot!,
                originalHash,
                stagedSnapshot!,
                stagedHash,
                cancellationToken).ConfigureAwait(false);
            if (revalidationError is not null)
            {
                return Failure(revalidationError.Value, FailureHResult, originalHash);
            }

            if (skipped)
            {
                if (!string.Equals(verifiedWorkHash, stagedHash, StringComparison.Ordinal))
                {
                    return Failure(WindowsSipSigningError.VerificationFailed, FailureHResult, originalHash);
                }

                return WindowsSipSigningResult.Success(originalHash, stagedHash, skippedExistingSignature: true);
            }

            cancellationToken.ThrowIfCancellationRequested();
            WindowsSipFileIdentity stagedIdentity = stagedSnapshot!.Identity;
            await verifiedWork.DisposeAsync().ConfigureAwait(false);
            await stagedSnapshot.DisposeAsync().ConfigureAwait(false);
            stagedSnapshot = null;
            await originalSnapshot!.DisposeAsync().ConfigureAwait(false);
            originalSnapshot = null;
            if (!atomicFileReplacer.TryReplace(
                    workPath,
                    workIdentity,
                    verifiedWorkHash,
                    input.StagedPath,
                    stagedIdentity,
                    stagedHash))
            {
                return Failure(WindowsSipSigningError.ProcessFailed, FailureHResult, originalHash);
            }

            if (!await PathHashMatchesAsync(
                    input.StagedPath,
                    verifiedWorkHash,
                    cancellationToken).ConfigureAwait(false))
            {
                return Failure(WindowsSipSigningError.ProcessFailed, FailureHResult, originalHash);
            }

            return WindowsSipSigningResult.Success(originalHash, verifiedWorkHash);
        }
        catch (OperationCanceledException)
        {
            return Failure(WindowsSipSigningError.Cancelled, CancelledHResult, originalHash);
        }
        catch (Exception exception) when (exception is
            ArgumentException or
            IOException or
            UnauthorizedAccessException or
            FilePipelineException or
            System.Security.SecurityException)
        {
            return Failure(WindowsSipSigningError.ProcessFailed, FailureHResult, originalHash);
        }
        finally
        {
            if (stagedSnapshot is not null)
            {
                await stagedSnapshot.DisposeAsync().ConfigureAwait(false);
            }

            if (originalSnapshot is not null)
            {
                await originalSnapshot.DisposeAsync().ConfigureAwait(false);
            }

            TryDeleteBridgeDirectory(bridgeDirectory);
        }
    }

    internal static ProcessStartInfo CreateStartInfo(
        string executablePath,
        string workingDirectory)
    {
        ProcessStartInfo startInfo = new(executablePath)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            ErrorDialog = false,
            WorkingDirectory = workingDirectory
        };
        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-Command");
        startInfo.ArgumentList.Add(WindowsPowerShellSipCommand.SignAndVerify);
        return startInfo;
    }

    private static ValidatedSipInput ValidateInput(
        string originalPath,
        string stagedPath,
        SigningPlan plan,
        int stagingOwnerPid,
        DateTimeOffset stagingOwnerStartUtc)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (!IsSafeCanonicalPath(originalPath, out string? original) ||
            !IsSafeCanonicalPath(stagedPath, out _) ||
            original!.Equals(stagedPath, StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(original))
        {
            throw new ArgumentException("The SIP signing paths are invalid.");
        }

        string staged = TransactionalStaging.EnsureActiveOwnedStagedFile(
            stagedPath,
            stagingOwnerPid,
            stagingOwnerStartUtc);
        ValidatePlan(plan);
        if (!string.Equals(Path.GetExtension(original), plan.Subject.Extension, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetExtension(staged), plan.Subject.Extension, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("The SIP signing path does not match the immutable plan.", nameof(plan));
        }

        return new ValidatedSipInput(
            original,
            staged,
            plan,
            null,
            stagingOwnerPid,
            stagingOwnerStartUtc);
    }

    private SignableSubject ValidateSubjects(
        ValidatedSipInput input,
        LockedFileSnapshot originalSnapshot,
        LockedFileSnapshot stagedSnapshot)
    {
        if (!PathIdentityMatches(input.OriginalPath, originalSnapshot.Identity, FileShare.Read | FileShare.Delete) ||
            !PathIdentityMatches(input.StagedPath, stagedSnapshot.Identity, FileShare.Read | FileShare.Delete))
        {
            throw new IOException("The validated SIP file identity changed.");
        }

        SignableSubject originalSubject = subjectProbe.Probe(input.OriginalPath);
        SignableSubject stagedSubject = subjectProbe.Probe(input.StagedPath);
        if (!MatchesPlan(originalSubject, input.Plan) || !MatchesPlan(stagedSubject, input.Plan) ||
            originalSubject.SubjectGuid == Guid.Empty ||
            originalSubject.SubjectGuid != stagedSubject.SubjectGuid ||
            originalSubject.ScriptProfile != stagedSubject.ScriptProfile)
        {
            throw new ArgumentException("The validated SIP subjects do not match the immutable plan.", nameof(input));
        }

        if (!PathIdentityMatches(input.OriginalPath, originalSnapshot.Identity, FileShare.Read | FileShare.Delete) ||
            !PathIdentityMatches(input.StagedPath, stagedSnapshot.Identity, FileShare.Read | FileShare.Delete))
        {
            throw new IOException("The probed SIP file identity changed.");
        }

        return stagedSubject;
    }

    private static BridgeRequest CreateRequest(ValidatedSipInput input, string workPath)
    {
        SignableSubject stagedSubject = input.StagedSubject
            ?? throw new InvalidOperationException("The SIP subject must be locked before request creation.");
        CoreSignatureLeg leg = input.Plan.Legs[0];
        return new BridgeRequest(
            SchemaVersion,
            "signAndVerify",
            workPath,
            FormatFamily(input.Plan.Subject.FormatFamily),
            input.Plan.Subject.Extension,
            stagedSubject.SubjectGuid.ToString("D"),
            "CurrentUser",
            "My",
            leg.Certificate.Thumbprint,
            "sha256",
            false,
            "rfc3161",
            "sha256",
            leg.Timestamp.Uri.AbsoluteUri,
            "skip",
            "fail",
            "fail",
            "fail",
            "fail",
            "fail",
            ScriptEncoding(stagedSubject.ScriptProfile),
            ScriptNewlines(stagedSubject.ScriptProfile),
            stagedSubject.ScriptProfile?.IsEncoded);
    }

    private static void ValidatePlan(SigningPlan plan)
    {
        if (plan.Version != SigningPlan.CurrentVersion ||
            plan.EffectiveMode != SigningMode.Single ||
            plan.Subject.Capability != SigningCapability.WindowsSipSingleOnly ||
            plan.Subject.FormatFamily == SigningFormatFamily.PeImage ||
            plan.Engine != SigningEngine.WindowsSip ||
            plan.Verification != SigningVerification.WindowsSip ||
            plan.Legs.Count != 1)
        {
            throw new ArgumentException("The plan is not an executable Windows SIP plan.", nameof(plan));
        }

        CoreSignatureLeg leg = plan.Legs[0];
        Uri timestampUri = leg.Timestamp.Uri;
        if (leg.FileDigest != FileDigestAlgorithm.Sha256 ||
            leg.Append ||
            leg.Certificate.StoreLocation != CertificateStoreLocation.CurrentUser ||
            !string.Equals(leg.Certificate.StoreName, "My", StringComparison.Ordinal) ||
            leg.Timestamp.Protocol != TimestampProtocol.Rfc3161 ||
            leg.Timestamp.TimestampDigest != TimestampDigestAlgorithm.Sha256 ||
            !IsSafeTimestampUri(timestampUri) ||
            plan.ExistingSignatures.Valid != ExistingSignatureDisposition.Skip ||
            plan.ExistingSignatures.Invalid != ExistingSignatureDisposition.Fail ||
            plan.ExistingSignatures.Untrusted != ExistingSignatureDisposition.Fail ||
            plan.ExistingSignatures.Expired != ExistingSignatureDisposition.Fail ||
            plan.ExistingSignatures.Partial != ExistingSignatureDisposition.Fail ||
            plan.ExistingSignatures.Malformed != ExistingSignatureDisposition.Fail)
        {
            throw new ArgumentException("The SIP plan violates the fixed SHA-256 policy.", nameof(plan));
        }
    }

    private bool TryResolveExecutable(out string? executablePath)
    {
        executablePath = null;
        try
        {
            if (!environment.IsWindows || string.IsNullOrWhiteSpace(environment.WindowsDirectory))
            {
                return false;
            }

            string windowsDirectory = Path.GetFullPath(environment.WindowsDirectory);
            string expected = Path.GetFullPath(Path.Combine(
                windowsDirectory,
                "System32",
                "WindowsPowerShell",
                "v1.0",
                "powershell.exe"));
            if (!expected.StartsWith(windowsDirectory + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
                !environment.FileExists(expected) ||
                (environment.GetAttributes(expected) & FileAttributes.ReparsePoint) != 0)
            {
                return false;
            }

            executablePath = expected;
            return true;
        }
        catch (Exception exception) when (exception is
            ArgumentException or
            IOException or
            UnauthorizedAccessException or
            System.Security.SecurityException)
        {
            return false;
        }
    }

    private static bool MatchesPlan(SignableSubject subject, SigningPlan plan) =>
        subject.PolicySubject.FormatFamily == plan.Subject.FormatFamily &&
        subject.PolicySubject.Capability == plan.Subject.Capability &&
        string.Equals(subject.PolicySubject.Extension, plan.Subject.Extension, StringComparison.Ordinal);

    private static bool IsSafeCanonicalPath(string? path, out string? canonical)
    {
        canonical = null;
        if (string.IsNullOrWhiteSpace(path) || path.AsSpan().IndexOfAny(UnsafePathCharacters) >= 0 ||
            !Path.IsPathFullyQualified(path))
        {
            return false;
        }

        try
        {
            canonical = Path.GetFullPath(path);
            return string.Equals(canonical, path, StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrEmpty(Path.GetFileName(canonical));
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            canonical = null;
            return false;
        }
    }

    private static bool IsSafeTimestampUri(Uri uri)
    {
        if (!uri.IsAbsoluteUri || uri.Scheme is not ("http" or "https") ||
            !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Fragment))
        {
            return false;
        }

        string unescaped = Uri.UnescapeDataString(uri.AbsoluteUri);
        return unescaped.AsSpan().IndexOfAny(InjectionCharacters) < 0;
    }

    private static string FormatFamily(SigningFormatFamily formatFamily) => formatFamily switch
    {
        SigningFormatFamily.WindowsInstaller => "windowsInstaller",
        SigningFormatFamily.Cabinet => "cabinet",
        SigningFormatFamily.Catalog => "catalog",
        SigningFormatFamily.AppPackage => "appPackage",
        SigningFormatFamily.PowerShellScript => "powerShellScript",
        SigningFormatFamily.WindowsScript => "windowsScript",
        _ => throw new ArgumentOutOfRangeException(nameof(formatFamily), formatFamily, "Unsupported SIP format family.")
    };

    private static string? ScriptEncoding(ScriptContentProfile? profile) => profile?.Encoding switch
    {
        ScriptEncodingKind.Utf8 => "utf8",
        ScriptEncodingKind.Utf8WithBom => "utf8Bom",
        ScriptEncodingKind.Utf16LittleEndian => "utf16Le",
        ScriptEncodingKind.Utf16BigEndian => "utf16Be",
        ScriptEncodingKind.WindowsScriptEncoded => "windowsScriptEncoded",
        null => null,
        _ => throw new ArgumentOutOfRangeException(nameof(profile), profile, "Unsupported script encoding.")
    };

    private static string? ScriptNewlines(ScriptContentProfile? profile) => profile?.Newlines switch
    {
        ScriptNewlineKind.None => "none",
        ScriptNewlineKind.CrLf => "crlf",
        ScriptNewlineKind.Lf => "lf",
        ScriptNewlineKind.Cr => "cr",
        ScriptNewlineKind.Mixed => "mixed",
        null => null,
        _ => throw new ArgumentOutOfRangeException(nameof(profile), profile, "Unsupported script newline profile.")
    };

    private static BridgeResponse ReadResponse(byte[] payload)
    {
        if (payload.Length is <= 0 or > MaximumResponseBytes)
        {
            throw new InvalidDataException("The SIP bridge response is missing or exceeds its bound.");
        }

        using JsonDocument document = JsonDocument.Parse(payload, new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 4
        });
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("The SIP bridge response is not an object.");
        }

        HashSet<string> fields = new(StringComparer.Ordinal);
        foreach (JsonProperty property in document.RootElement.EnumerateObject())
        {
            if (!fields.Add(property.Name) || !ResponseFields.Contains(property.Name))
            {
                throw new InvalidDataException("The SIP bridge response schema is invalid.");
            }
        }

        if (fields.Count != ResponseFields.Count || !ResponseFields.SetEquals(fields))
        {
            throw new InvalidDataException("The SIP bridge response is incomplete.");
        }

        return JsonSerializer.Deserialize<BridgeResponse>(payload, ResponseJsonOptions)
            ?? throw new InvalidDataException("The SIP bridge response could not be decoded.");
    }

    private static bool ValidateSuccessResponse(BridgeResponse response, BridgeRequest request)
    {
        if (response.SchemaVersion != SchemaVersion || response.HResult != 0 ||
            !string.Equals(response.SignatureStatus, "Valid", StringComparison.Ordinal) ||
            !response.CmsVerified || !response.SubjectVerified || !response.ContentVerified)
        {
            return false;
        }

        if (string.Equals(response.ResultCode, "existingSignatureValid", StringComparison.Ordinal))
        {
            return response.FileDigest is null &&
                response.SignerThumbprint is null &&
                response.TimestampProtocol is null &&
                response.TimestampDigest is null &&
                string.Equals(response.ExistingSignatureDisposition, "skip", StringComparison.Ordinal);
        }

        return string.Equals(response.ResultCode, "signed", StringComparison.Ordinal) &&
            string.Equals(response.FileDigest, "sha256", StringComparison.Ordinal) &&
            string.Equals(response.SignerThumbprint, request.CertificateThumbprint, StringComparison.Ordinal) &&
            string.Equals(response.TimestampProtocol, "rfc3161", StringComparison.Ordinal) &&
            string.Equals(response.TimestampDigest, "sha256", StringComparison.Ordinal) &&
            string.Equals(response.ExistingSignatureDisposition, "signed", StringComparison.Ordinal);
    }

    private static WindowsSipSigningError MapResponseFailure(BridgeResponse response)
    {
        if (response.SchemaVersion != SchemaVersion || response.HResult >= 0)
        {
            return WindowsSipSigningError.MalformedResponse;
        }

        return response.ResultCode switch
        {
            "invalidInput" => WindowsSipSigningError.InvalidInput,
            "executionDenied" => WindowsSipSigningError.ExecutionDenied,
            "sipUnavailable" => WindowsSipSigningError.SipUnavailable,
            "packageIncompatible" => WindowsSipSigningError.PackageIncompatible,
            "certificateMismatch" => WindowsSipSigningError.CertificateMismatch,
            "certificateNotFound" => WindowsSipSigningError.CertificateNotFound,
            "certificateHasNoPrivateKey" => WindowsSipSigningError.CertificateHasNoPrivateKey,
            "existingSignatureRejected" => WindowsSipSigningError.ExistingSignatureRejected,
            "providerCancelled" => WindowsSipSigningError.ProviderCancelled,
            "timestampUnavailable" => WindowsSipSigningError.TimestampUnavailable,
            "verificationFailed" => WindowsSipSigningError.VerificationFailed,
            "processFailed" => WindowsSipSigningError.ProcessFailed,
            _ => WindowsSipSigningError.MalformedResponse
        };
    }

    private static WindowsSipSigningError MapVerificationFailure(WindowsSipVerificationError error) => error switch
    {
        WindowsSipVerificationError.PackageIncompatible => WindowsSipSigningError.PackageIncompatible,
        WindowsSipVerificationError.CertificateMismatch => WindowsSipSigningError.CertificateMismatch,
        WindowsSipVerificationError.VerificationFailed => WindowsSipSigningError.VerificationFailed,
        _ => WindowsSipSigningError.VerificationFailed
    };

    private static WindowsSipSigningError? MapStartFailure(WindowsPowerShellProcessStartFailure failure) => failure switch
    {
        WindowsPowerShellProcessStartFailure.None => null,
        WindowsPowerShellProcessStartFailure.MissingExecutable => WindowsSipSigningError.PowerShellUnavailable,
        WindowsPowerShellProcessStartFailure.ExecutionDenied => WindowsSipSigningError.ExecutionDenied,
        _ => WindowsSipSigningError.ProcessFailed
    };

    private static int NormalizeFailureHResult(int hResult) => hResult < 0 ? hResult : FailureHResult;

    private static WindowsSipSigningResult Failure(
        WindowsSipSigningError error,
        int hResult,
        string originalHash = "") => WindowsSipSigningResult.Failure(error, hResult, originalHash);

    private static async Task CopySnapshotAsync(
        LockedFileSnapshot source,
        string destinationPath,
        CancellationToken cancellationToken)
    {
        await using FileStream destination = new(
            destinationPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan | FileOptions.WriteThrough);
        await source.CopyToAsync(destination, cancellationToken).ConfigureAwait(false);
        await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<WindowsSipSigningError?> RevalidateForCommitAsync(
        ValidatedSipInput input,
        LockedFileSnapshot originalSnapshot,
        string originalHash,
        LockedFileSnapshot stagedSnapshot,
        string stagedHash,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string ownedPath = TransactionalStaging.EnsureActiveOwnedStagedFile(
            input.StagedPath,
            input.StagingOwnerPid,
            input.StagingOwnerStartUtc);
        if (!string.Equals(ownedPath, input.StagedPath, StringComparison.OrdinalIgnoreCase))
        {
            return WindowsSipSigningError.ProcessFailed;
        }

        if (!await PathMatchesAsync(
                input.OriginalPath,
                originalSnapshot.Identity,
                originalHash,
                cancellationToken).ConfigureAwait(false))
        {
            return WindowsSipSigningError.OriginalChanged;
        }

        if (!await PathMatchesAsync(
                input.StagedPath,
                stagedSnapshot.Identity,
                stagedHash,
                cancellationToken).ConfigureAwait(false))
        {
            return WindowsSipSigningError.ProcessFailed;
        }

        return null;
    }

    private static async Task<bool> PathMatchesAsync(
        string path,
        WindowsSipFileIdentity identity,
        string hash,
        CancellationToken cancellationToken)
    {
        try
        {
            await using LockedFileSnapshot snapshot = LockedFileSnapshot.Open(
                path,
                FileShare.Read | FileShare.Delete);
            return snapshot.Identity == identity &&
                string.Equals(await snapshot.HashAsync(cancellationToken).ConfigureAwait(false), hash, StringComparison.Ordinal);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return false;
        }
    }

    private static async Task<bool> PathHashMatchesAsync(
        string path,
        string hash,
        CancellationToken cancellationToken)
    {
        try
        {
            await using LockedFileSnapshot snapshot = LockedFileSnapshot.Open(
                path,
                FileShare.Read | FileShare.Delete);
            return string.Equals(
                await snapshot.HashAsync(cancellationToken).ConfigureAwait(false),
                hash,
                StringComparison.Ordinal);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return false;
        }
    }

    private static bool PathIdentityMatches(string path, WindowsSipFileIdentity identity, FileShare share)
    {
        try
        {
            return ReadPathIdentity(path, share) == identity;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return false;
        }
    }

    private static WindowsSipFileIdentity ReadPathIdentity(string path, FileShare share)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, share);
        return ReadFileIdentity(stream.SafeFileHandle);
    }

    internal static bool ValidateAtomicReplacementCandidate(
        string path,
        WindowsSipFileIdentity expectedIdentity,
        string expectedSha256)
    {
        try
        {
            using FileStream stream = new(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read | FileShare.Delete,
                bufferSize: 64 * 1024,
                FileOptions.SequentialScan);
            if (ReadFileIdentity(stream.SafeFileHandle) != expectedIdentity)
            {
                return false;
            }

            string hash = Convert.ToHexString(SHA256.HashData(stream));
            return string.Equals(hash, expectedSha256, StringComparison.Ordinal) &&
                PathIdentityMatches(path, expectedIdentity, FileShare.Read | FileShare.Delete);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return false;
        }
    }

    private static void TryDeleteBridgeDirectory(string bridgeDirectory)
    {
        try
        {
            if (Directory.Exists(bridgeDirectory))
            {
                Directory.Delete(bridgeDirectory, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
        }
    }

    private sealed record ValidatedSipInput(
        string OriginalPath,
        string StagedPath,
        SigningPlan Plan,
        SignableSubject? StagedSubject,
        int StagingOwnerPid = 0,
        DateTimeOffset StagingOwnerStartUtc = default);

    private static WindowsSipFileIdentity ReadFileIdentity(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out ByHandleFileInformation information))
        {
            throw new IOException(
                "The SIP file identity could not be read.",
                new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()));
        }

        ulong fileIndex = ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow;
        return new WindowsSipFileIdentity(information.VolumeSerialNumber, fileIndex);
    }

    private sealed class LockedFileSnapshot : IAsyncDisposable
    {
        private readonly FileStream stream;

        private LockedFileSnapshot(FileStream stream)
        {
            this.stream = stream;
            Identity = ReadFileIdentity(stream.SafeFileHandle);
        }

        internal WindowsSipFileIdentity Identity { get; }

        internal static LockedFileSnapshot Open(string path, FileShare share) => new(new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            share,
            bufferSize: 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan));

        internal async Task<string> HashAsync(CancellationToken cancellationToken)
        {
            stream.Position = 0;
            return Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false));
        }

        internal async Task CopyToAsync(Stream destination, CancellationToken cancellationToken)
        {
            stream.Position = 0;
            await stream.CopyToAsync(destination, 64 * 1024, cancellationToken).ConfigureAwait(false);
        }

        public ValueTask DisposeAsync() => stream.DisposeAsync();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        internal uint FileAttributes;
        internal System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        internal System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        internal System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        internal uint VolumeSerialNumber;
        internal uint FileSizeHigh;
        internal uint FileSizeLow;
        internal uint NumberOfLinks;
        internal uint FileIndexHigh;
        internal uint FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation fileInformation);

    private sealed record BridgeRequest(
        [property: JsonPropertyName("schemaVersion")] int SchemaVersion,
        [property: JsonPropertyName("operation")] string Operation,
        [property: JsonPropertyName("stagedPath")] string StagedPath,
        [property: JsonPropertyName("formatFamily")] string FormatFamily,
        [property: JsonPropertyName("extension")] string Extension,
        [property: JsonPropertyName("subjectGuid")] string SubjectGuid,
        [property: JsonPropertyName("certificateStoreLocation")] string CertificateStoreLocation,
        [property: JsonPropertyName("certificateStoreName")] string CertificateStoreName,
        [property: JsonPropertyName("certificateThumbprint")] string CertificateThumbprint,
        [property: JsonPropertyName("fileDigest")] string FileDigest,
        [property: JsonPropertyName("appendSignature")] bool AppendSignature,
        [property: JsonPropertyName("timestampProtocol")] string TimestampProtocol,
        [property: JsonPropertyName("timestampDigest")] string TimestampDigest,
        [property: JsonPropertyName("timestampUri")] string TimestampUri,
        [property: JsonPropertyName("existingValid")] string ExistingValid,
        [property: JsonPropertyName("existingInvalid")] string ExistingInvalid,
        [property: JsonPropertyName("existingUntrusted")] string ExistingUntrusted,
        [property: JsonPropertyName("existingExpired")] string ExistingExpired,
        [property: JsonPropertyName("existingPartial")] string ExistingPartial,
        [property: JsonPropertyName("existingMalformed")] string ExistingMalformed,
        [property: JsonPropertyName("scriptEncoding")] string? ScriptEncoding,
        [property: JsonPropertyName("scriptNewlines")] string? ScriptNewlines,
        [property: JsonPropertyName("scriptIsEncoded")] bool? ScriptIsEncoded);

    private sealed record BridgeResponse(
        [property: JsonPropertyName("schemaVersion")] int SchemaVersion,
        [property: JsonPropertyName("resultCode")] string ResultCode,
        [property: JsonPropertyName("hresult")] int HResult,
        [property: JsonPropertyName("signatureStatus")] string? SignatureStatus,
        [property: JsonPropertyName("fileDigest")] string? FileDigest,
        [property: JsonPropertyName("signerThumbprint")] string? SignerThumbprint,
        [property: JsonPropertyName("timestampProtocol")] string? TimestampProtocol,
        [property: JsonPropertyName("timestampDigest")] string? TimestampDigest,
        [property: JsonPropertyName("cmsVerified")] bool CmsVerified,
        [property: JsonPropertyName("subjectVerified")] bool SubjectVerified,
        [property: JsonPropertyName("contentVerified")] bool ContentVerified,
        [property: JsonPropertyName("existingSignatureDisposition")] string? ExistingSignatureDisposition);
}

internal sealed class SystemWindowsSipAtomicFileReplacer : IWindowsSipAtomicFileReplacer
{
    public bool TryReplace(
        string sourcePath,
        WindowsSipFileIdentity expectedSourceIdentity,
        string expectedSourceSha256,
        string destinationPath,
        WindowsSipFileIdentity expectedDestinationIdentity,
        string expectedDestinationSha256)
    {
        if (!WindowsPowerShellSipBridge.ValidateAtomicReplacementCandidate(
                sourcePath,
                expectedSourceIdentity,
                expectedSourceSha256) ||
            !WindowsPowerShellSipBridge.ValidateAtomicReplacementCandidate(
                destinationPath,
                expectedDestinationIdentity,
                expectedDestinationSha256))
        {
            return false;
        }

        File.Replace(sourcePath, destinationPath, destinationBackupFileName: null);
        return true;
    }
}

internal sealed class SystemWindowsPowerShellEnvironment : IWindowsPowerShellEnvironment
{
    public bool IsWindows => OperatingSystem.IsWindows();

    public string WindowsDirectory => Environment.GetFolderPath(Environment.SpecialFolder.Windows);

    public bool FileExists(string path) => File.Exists(path);

    public FileAttributes GetAttributes(string path) => File.GetAttributes(path);
}

internal sealed class SystemWindowsPowerShellProcessRunner : IWindowsPowerShellProcessRunner
{
    private const int MaximumStandardOutputBytes = 32 * 1024;
    private const int MaximumStandardErrorBytes = 8 * 1024;

    public async Task<WindowsPowerShellProcessResult> RunAsync(
        ProcessStartInfo startInfo,
        string? standardInput,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(startInfo);
        using Process process = new() { StartInfo = startInfo };
        try
        {
            if (!process.Start())
            {
                return new WindowsPowerShellProcessResult(-1, WindowsPowerShellProcessStartFailure.Other);
            }
        }
        catch (Win32Exception exception) when (exception.NativeErrorCode is 2 or 3)
        {
            return new WindowsPowerShellProcessResult(-1, WindowsPowerShellProcessStartFailure.MissingExecutable);
        }
        catch (Win32Exception exception) when (exception.NativeErrorCode is 5 or 577 or 1260)
        {
            return new WindowsPowerShellProcessResult(-1, WindowsPowerShellProcessStartFailure.ExecutionDenied);
        }
        catch (Win32Exception)
        {
            return new WindowsPowerShellProcessResult(-1, WindowsPowerShellProcessStartFailure.Other);
        }

        Task<BoundedRead> output = startInfo.RedirectStandardOutput
            ? ReadBoundedAsync(process.StandardOutput.BaseStream, MaximumStandardOutputBytes, capture: true)
            : Task.FromResult(BoundedRead.Empty);
        Task<BoundedRead> error = startInfo.RedirectStandardError
            ? ReadBoundedAsync(process.StandardError.BaseStream, MaximumStandardErrorBytes, capture: false)
            : Task.FromResult(BoundedRead.Empty);
        try
        {
            await WriteStandardInputAsync(process, startInfo, standardInput, cancellationToken).ConfigureAwait(false);
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            TryKill(process);
            TryCloseStandardInput(process, startInfo);
            await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
            await Task.WhenAll(output, error).ConfigureAwait(false);
            throw;
        }
        catch
        {
            TryKill(process);
            TryCloseStandardInput(process, startInfo);
            await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
            await Task.WhenAll(output, error).ConfigureAwait(false);
            throw;
        }
        finally
        {
            TryCloseStandardInput(process, startInfo);
        }

        BoundedRead standardOutput = await output.ConfigureAwait(false);
        BoundedRead standardError = await error.ConfigureAwait(false);
        return new WindowsPowerShellProcessResult(
            process.ExitCode,
            StandardOutput: standardOutput.Payload,
            StandardOutputLimitExceeded: standardOutput.LimitExceeded,
            StandardErrorBytes: standardError.Bytes,
            StandardErrorLimitExceeded: standardError.LimitExceeded,
            StandardErrorDiagnostic: standardError.Bytes == 0 ? null : "StandardErrorRedacted");
    }

    private static async Task WriteStandardInputAsync(
        Process process,
        ProcessStartInfo startInfo,
        string? standardInput,
        CancellationToken cancellationToken)
    {
        if (!startInfo.RedirectStandardInput)
        {
            if (standardInput is not null)
            {
                throw new InvalidOperationException("Standard input must be redirected for a piped payload.");
            }

            return;
        }

        try
        {
            if (standardInput is not null)
            {
                byte[] payload = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetBytes(standardInput);
                await process.StandardInput.BaseStream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
                await process.StandardInput.BaseStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            TryCloseStandardInput(process, startInfo);
        }
    }

    private static async Task<BoundedRead> ReadBoundedAsync(Stream stream, int limit, bool capture)
    {
        byte[] buffer = new byte[4096];
        using var payload = capture ? new MemoryStream(Math.Min(limit, buffer.Length)) : null;
        int bytes = 0;
        int captured = 0;
        bool limitExceeded = false;
        int read;
        while ((read = await stream.ReadAsync(buffer).ConfigureAwait(false)) != 0)
        {
            if (bytes <= limit)
            {
                bytes = Math.Min(limit + 1, checked(bytes + read));
                limitExceeded = bytes > limit;
            }

            if (capture && captured < limit)
            {
                int count = Math.Min(read, limit - captured);
                payload!.Write(buffer, 0, count);
                captured += count;
            }
        }

        return new BoundedRead(payload?.ToArray() ?? [], bytes, limitExceeded);
    }

    private static void TryCloseStandardInput(Process process, ProcessStartInfo startInfo)
    {
        if (!startInfo.RedirectStandardInput)
        {
            return;
        }

        try
        {
            process.StandardInput.Close();
        }
        catch (Exception exception) when (exception is InvalidOperationException or IOException or ObjectDisposedException)
        {
        }
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception exception) when (exception is InvalidOperationException or Win32Exception or NotSupportedException)
        {
        }
    }

    private sealed record BoundedRead(byte[] Payload, int Bytes, bool LimitExceeded)
    {
        internal static BoundedRead Empty { get; } = new([], 0, false);
    }
}
