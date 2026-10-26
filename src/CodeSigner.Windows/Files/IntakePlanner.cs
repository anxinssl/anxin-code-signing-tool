using System.ComponentModel;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace CodeSigner.Windows.Files;

public sealed class IntakePlanner(ISignableSubjectProbe subjectProbe)
{
    public Task<IntakePlan> CreateAsync(
        IReadOnlyCollection<string> inputs,
        bool recurseDirectories,
        string? outputRoot,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        if (inputs.Count == 0)
        {
            throw new IntakeValidationException(IntakeError.InvalidInput, "At least one input is required.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        string[] canonicalInputs = inputs.Select(PathSafety.Canonicalize).ToArray();
        string canonicalOutputRoot = outputRoot is null
            ? DefaultOutputRoot(canonicalInputs[0])
            : PathSafety.Canonicalize(outputRoot);
        PathSafety.EnsureNoReparsePoints(canonicalOutputRoot);

        foreach (string input in canonicalInputs)
        {
            if (PathSafety.IsWithinOrEqual(input, canonicalOutputRoot))
            {
                throw new IntakeValidationException(
                    IntakeError.InputInsideOutputRoot,
                    "An input cannot be located inside the selected output root.",
                    input);
            }
        }

        QueuedSourceAdmissionResult admission = QueuedSourceAdmission.AdmitForCreateAsync(
            canonicalInputs,
            recurseDirectories,
            cancellationToken);
        if (admission.Failures.Count > 0)
        {
            QueuedSourceAdmissionFailure failure = admission.Failures[0];
            throw new IntakeValidationException(MapAdmissionError(failure.Error), "An input could not be safely admitted.", failure.Path);
        }

        HashSet<string> destinations = new(StringComparer.OrdinalIgnoreCase);
        List<IntakeFile> plannedFiles = [];
        foreach (QueuedSource source in admission.Sources)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (PathSafety.IsWithinOrEqual(source.CanonicalPath, canonicalOutputRoot))
            {
                continue;
            }

            DetectionOutcome outcome = DetectCore(source, cancellationToken);
            if (outcome.Result.Status != QueuedSourceDetectionStatus.Supported)
            {
                throw DetectionException(source, outcome);
            }

            IntakeFile planned = PlanOutput(outcome.Result.DetectedSource!, canonicalOutputRoot, cancellationToken);
            if (!destinations.Add(planned.DestinationPath))
            {
                throw new IntakeValidationException(
                    IntakeError.DestinationCollision,
                    "Multiple inputs resolve to the same destination.",
                    planned.DestinationPath);
            }

            plannedFiles.Add(planned);
        }

        if (plannedFiles.Count == 0)
        {
            throw new IntakeValidationException(IntakeError.NoSignableInputs, "No supported signable files were found.");
        }

        plannedFiles.Sort((left, right) => StringComparer.OrdinalIgnoreCase.Compare(left.RelativePath, right.RelativePath));
        return Task.FromResult(new IntakePlan(canonicalOutputRoot, plannedFiles.AsReadOnly()));
    }

    public QueuedSourceDetectionResult Detect(
        QueuedSource source,
        CancellationToken cancellationToken) => DetectCore(source, cancellationToken).Result;

    private DetectionOutcome DetectCore(
        QueuedSource source,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        cancellationToken.ThrowIfCancellationRequested();

        SafeFileHandle? handle = null;
        try
        {
            handle = WindowsFileIdentity.OpenForReadNoFollow(source.CanonicalPath);
            WindowsFileHandleInformation before = WindowsFileIdentity.GetInformation(handle);
            if ((before.Attributes & FileAttributes.ReparsePoint) != 0 ||
                (before.Attributes & FileAttributes.Directory) != 0 ||
                before.Identity != source.Identity)
            {
                return new DetectionOutcome(Changed(), Cause: null);
            }

            SignableSubject subject;
            try
            {
                subject = subjectProbe.Probe(source.CanonicalPath);
            }
            catch (SignableSubjectProbeException exception)
            {
                return new DetectionOutcome(Blocked(MapProbeError(exception.Error)), exception);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                return new DetectionOutcome(Blocked(IntakeError.NotSignableSubject), exception);
            }

            using FileStream stream = new(handle, FileAccess.Read, bufferSize: 64 * 1024, isAsync: false);
            handle = null;
            string sha256 = Convert.ToHexString(SHA256.HashData(stream));
            WindowsFileHandleInformation after = WindowsFileIdentity.GetInformation(stream.SafeFileHandle);
            cancellationToken.ThrowIfCancellationRequested();
            if (before.Identity != after.Identity ||
                before.Length != after.Length ||
                before.LastWriteTimeUtc != after.LastWriteTimeUtc)
            {
                return new DetectionOutcome(Changed(), Cause: null);
            }

            SourceFingerprint fingerprint = new(
                after.Identity,
                after.Length,
                after.LastWriteTimeUtc,
                sha256);
            return new DetectionOutcome(
                new QueuedSourceDetectionResult(
                    QueuedSourceDetectionStatus.Supported,
                    new DetectedQueuedSource(source, subject, fingerprint),
                    Error: null),
                Cause: null);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or Win32Exception)
        {
            return new DetectionOutcome(Unavailable(), exception);
        }
        finally
        {
            handle?.Dispose();
        }
    }

    public static QueuedSourceDetectionResult VerifyIntegrity(
        DetectedQueuedSource detectedSource,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(detectedSource);
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            using SafeFileHandle handle = WindowsFileIdentity.OpenForReadNoFollow(detectedSource.Source.CanonicalPath);
            WindowsFileHandleInformation before = WindowsFileIdentity.GetInformation(handle);
            if ((before.Attributes & FileAttributes.ReparsePoint) != 0 ||
                (before.Attributes & FileAttributes.Directory) != 0 ||
                before.Identity != detectedSource.Fingerprint.Identity)
            {
                return Changed();
            }

            using FileStream stream = new(handle, FileAccess.Read, bufferSize: 64 * 1024, isAsync: false);
            string sha256 = Convert.ToHexString(SHA256.HashData(stream));
            WindowsFileHandleInformation after = WindowsFileIdentity.GetInformation(stream.SafeFileHandle);
            cancellationToken.ThrowIfCancellationRequested();
            SourceFingerprint actual = new(after.Identity, after.Length, after.LastWriteTimeUtc, sha256);
            return actual == detectedSource.Fingerprint
                ? new QueuedSourceDetectionResult(
                    QueuedSourceDetectionStatus.Supported,
                    detectedSource,
                    Error: null)
                : Changed();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or Win32Exception)
        {
            return Unavailable();
        }
    }

    public static IntakeFile PlanOutput(
        DetectedQueuedSource detectedSource,
        string outputRoot,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(detectedSource);
        cancellationToken.ThrowIfCancellationRequested();
        string canonicalOutputRoot = PathSafety.Canonicalize(outputRoot);
        PathSafety.EnsureNoReparsePoints(canonicalOutputRoot);
        if (PathSafety.IsWithinOrEqual(detectedSource.Source.CanonicalPath, canonicalOutputRoot))
        {
            throw new IntakeValidationException(
                IntakeError.InputInsideOutputRoot,
                "An input cannot be located inside the selected output root.",
                detectedSource.Source.CanonicalPath);
        }

        string destination = Path.GetFullPath(Path.Combine(canonicalOutputRoot, detectedSource.Source.RelativePath));
        if (!PathSafety.IsWithinOrEqual(destination, canonicalOutputRoot))
        {
            throw new IntakeValidationException(IntakeError.InvalidInput, "The destination escapes the output root.", destination);
        }

        PathSafety.EnsureNoReparsePoints(destination);
        if (File.Exists(destination) || Directory.Exists(destination))
        {
            throw new IntakeValidationException(
                IntakeError.DestinationExists,
                "The destination already exists and will not be overwritten.",
                destination);
        }

        return new IntakeFile(
            detectedSource.Source.CanonicalPath,
            detectedSource.Source.RelativePath,
            destination,
            canonicalOutputRoot,
            detectedSource.Fingerprint.Identity,
            detectedSource.Subject);
    }

    private static string DefaultOutputRoot(string firstInput)
    {
        string directory = Directory.Exists(firstInput)
            ? firstInput
            : Path.GetDirectoryName(firstInput)
                ?? throw new IntakeValidationException(IntakeError.InvalidInput, "The first input has no parent directory.", firstInput);
        return Path.Combine(directory, "Signed");
    }

    private static IntakeValidationException DetectionException(
        QueuedSource source,
        DetectionOutcome outcome) => new(
            outcome.Result.Error ?? IntakeError.NotSignableSubject,
            "The file is not an approved content-validated signing subject.",
            source.CanonicalPath,
            outcome.Cause);

    private static IntakeError MapAdmissionError(QueuedSourceAdmissionError error) => error switch
    {
        QueuedSourceAdmissionError.InvalidInput => IntakeError.InvalidInput,
        QueuedSourceAdmissionError.InputNotFound => IntakeError.InputNotFound,
        QueuedSourceAdmissionError.ReparsePoint => IntakeError.ReparsePoint,
        _ => IntakeError.InaccessibleInput
    };

    private static IntakeError MapProbeError(SignableSubjectProbeError error) => error switch
    {
        SignableSubjectProbeError.UnsupportedExtension => IntakeError.UnsupportedExtension,
        SignableSubjectProbeError.SipUnavailable => IntakeError.SipUnavailable,
        _ => IntakeError.NotSignableSubject
    };

    private static QueuedSourceDetectionResult Blocked(IntakeError error) => new(
        QueuedSourceDetectionStatus.Blocked,
        DetectedSource: null,
        error);

    private static QueuedSourceDetectionResult Unavailable() => new(
        QueuedSourceDetectionStatus.Unavailable,
        DetectedSource: null,
        IntakeError.InaccessibleInput);

    private static QueuedSourceDetectionResult Changed() => new(
        QueuedSourceDetectionStatus.Changed,
        DetectedSource: null,
        Error: null);

    private sealed record DetectionOutcome(QueuedSourceDetectionResult Result, Exception? Cause);
}
