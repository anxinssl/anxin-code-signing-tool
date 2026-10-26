using System.Buffers;
using System.Text;
using System.Text.Json;

namespace CodeSigner.Core.Signing;

public static class SigningPlanJson
{
    private static readonly string[] RootFields =
        ["version", "requestedMode", "effectiveMode", "legs", "subject", "existingSignatures"];
    private static readonly string[] LegFields = ["certificate", "fileDigest", "append", "timestamp"];
    private static readonly string[] CertificateFields = ["storeLocation", "storeName", "thumbprint"];
    private static readonly string[] TimestampFields = ["protocol", "timestampDigest", "uri"];
    private static readonly string[] SubjectFields = ["formatFamily", "extension", "capability"];
    private static readonly string[] ExistingSignatureFields = ["valid", "invalid", "untrusted", "expired", "partial", "malformed"];

    public static string Serialize(SigningPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteNumber("version", plan.Version);
            writer.WriteString("requestedMode", Format(plan.RequestedMode));
            writer.WriteString("effectiveMode", Format(plan.EffectiveMode));
            writer.WriteStartArray("legs");
            foreach (SignatureLeg leg in plan.Legs)
            {
                WriteLeg(writer, leg);
            }

            writer.WriteEndArray();
            WriteSubject(writer, plan.Subject);
            WriteExistingSignatures(writer, plan.ExistingSignatures);
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    public static PolicyResult<SigningPlan> Parse(string? json)
    {
        if (json is null)
        {
            return Fail<SigningPlan>(PolicyErrorCode.MalformedJson, "$", "JSON input is required.");
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(
                json,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 32
                });
            return ParseRoot(document.RootElement);
        }
        catch (JsonException exception)
        {
            return Fail<SigningPlan>(
                PolicyErrorCode.MalformedJson,
                "$",
                $"The signing plan is not valid JSON: {exception.Message}");
        }
    }

    private static PolicyResult<SigningPlan> ParseRoot(JsonElement root)
    {
        const string path = "$";
        if (root.ValueKind != JsonValueKind.Object)
        {
            return InvalidType<SigningPlan>(path, "object");
        }

        if (!TryGetRequired(root, "version", path, out JsonElement versionElement, out PolicyError? error))
        {
            return Failure<SigningPlan>(error!);
        }

        if (versionElement.ValueKind != JsonValueKind.Number || !versionElement.TryGetInt32(out int version))
        {
            return InvalidType<SigningPlan>("$.version", "integer");
        }

        if (version != SigningPlan.CurrentVersion)
        {
            return Fail<SigningPlan>(
                PolicyErrorCode.UnsupportedVersion,
                "$.version",
                "The signing plan version is not supported.");
        }

        PolicyError? fieldError = ValidateFields(root, RootFields, path);
        if (fieldError is not null)
        {
            return Failure<SigningPlan>(fieldError);
        }

        if (!TryReadRequiredString(root, "requestedMode", path, out string requestedModeText, out error))
        {
            return Failure<SigningPlan>(error!);
        }

        SigningMode? requestedMode = ParseSigningMode(requestedModeText);
        if (requestedMode is null)
        {
            return Fail<SigningPlan>(
                PolicyErrorCode.InvalidSignatureOrder,
                "$.requestedMode",
                "The signing mode must be 'single' or 'dual'.");
        }

        if (!TryReadRequiredString(root, "effectiveMode", path, out string effectiveModeText, out error))
        {
            return Failure<SigningPlan>(error!);
        }

        SigningMode? effectiveMode = ParseSigningMode(effectiveModeText);
        if (effectiveMode is null)
        {
            return Fail<SigningPlan>(
                PolicyErrorCode.InvalidSignatureOrder,
                "$.effectiveMode",
                "The effective signing mode must be 'single' or 'dual'.");
        }

        PolicyResult<IReadOnlyList<SignatureLeg>> legsResult = ParseLegs(root, path);
        if (!legsResult.IsSuccess)
        {
            return CopyFailure<SigningPlan, IReadOnlyList<SignatureLeg>>(legsResult);
        }

        PolicyResult<SigningSubject> subjectResult = ParseSubject(root, path);
        if (!subjectResult.IsSuccess)
        {
            return CopyFailure<SigningPlan, SigningSubject>(subjectResult);
        }

        PolicyResult<ExistingSignaturePolicy> existingResult = ParseExistingSignatures(root, path);
        if (!existingResult.IsSuccess)
        {
            return CopyFailure<SigningPlan, ExistingSignaturePolicy>(existingResult);
        }

        return SigningPlan.TryCreateParsed(
            requestedMode.Value,
            effectiveMode.Value,
            legsResult.Value!,
            subjectResult.Value!,
            existingResult.Value!);
    }

    private static PolicyResult<IReadOnlyList<SignatureLeg>> ParseLegs(JsonElement root, string rootPath)
    {
        if (!TryGetRequired(root, "legs", rootPath, out JsonElement legsElement, out PolicyError? error))
        {
            return Failure<IReadOnlyList<SignatureLeg>>(error!);
        }

        if (legsElement.ValueKind != JsonValueKind.Array)
        {
            return InvalidType<IReadOnlyList<SignatureLeg>>("$.legs", "array");
        }

        var legs = new List<SignatureLeg>();
        int index = 0;
        foreach (JsonElement legElement in legsElement.EnumerateArray())
        {
            PolicyResult<SignatureLeg> legResult = ParseLeg(legElement, $"$.legs[{index}]");
            if (!legResult.IsSuccess)
            {
                return CopyFailure<IReadOnlyList<SignatureLeg>, SignatureLeg>(legResult);
            }

            legs.Add(legResult.Value!);
            index++;
        }

        return PolicyResult<IReadOnlyList<SignatureLeg>>.Success(legs.AsReadOnly());
    }

    private static PolicyResult<SignatureLeg> ParseLeg(JsonElement element, string path)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            return InvalidType<SignatureLeg>(path, "object");
        }

        PolicyError? fieldError = ValidateFields(element, LegFields, path);
        if (fieldError is not null)
        {
            return Failure<SignatureLeg>(fieldError);
        }

        if (!TryGetRequired(element, "certificate", path, out JsonElement certificateElement, out PolicyError? error))
        {
            return Failure<SignatureLeg>(error!);
        }

        PolicyResult<CertificateRef> certificateResult = ParseCertificate(certificateElement, $"{path}.certificate");
        if (!certificateResult.IsSuccess)
        {
            return CopyFailure<SignatureLeg, CertificateRef>(certificateResult);
        }

        if (!TryReadRequiredString(element, "fileDigest", path, out string digestText, out error))
        {
            return Failure<SignatureLeg>(error!);
        }

        FileDigestAlgorithm? digest = digestText switch
        {
            "sha1" => FileDigestAlgorithm.Sha1,
            "sha256" => FileDigestAlgorithm.Sha256,
            _ => null
        };
        if (digest is null)
        {
            return Fail<SignatureLeg>(
                PolicyErrorCode.InvalidSignatureOrder,
                $"{path}.fileDigest",
                "The file digest must be 'sha1' or 'sha256'.");
        }

        if (!TryReadRequiredBoolean(element, "append", path, out bool append, out error))
        {
            return Failure<SignatureLeg>(error!);
        }

        if (!TryGetRequired(element, "timestamp", path, out JsonElement timestampElement, out error))
        {
            return Failure<SignatureLeg>(error!);
        }

        PolicyResult<TimestampPolicy> timestampResult = ParseTimestamp(timestampElement, $"{path}.timestamp");
        if (!timestampResult.IsSuccess)
        {
            return CopyFailure<SignatureLeg, TimestampPolicy>(timestampResult);
        }

        return PolicyResult<SignatureLeg>.Success(
            SignatureLeg.Create(certificateResult.Value!, digest.Value, append, timestampResult.Value!));
    }

    private static PolicyResult<CertificateRef> ParseCertificate(JsonElement element, string path)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            return InvalidType<CertificateRef>(path, "object");
        }

        PolicyError? fieldError = ValidateFields(element, CertificateFields, path);
        if (fieldError is not null)
        {
            return Failure<CertificateRef>(fieldError);
        }

        if (!TryReadRequiredString(element, "storeLocation", path, out string locationText, out PolicyError? error))
        {
            return Failure<CertificateRef>(error!);
        }

        CertificateStoreLocation? location = locationText switch
        {
            "currentUser" => CertificateStoreLocation.CurrentUser,
            "localMachine" => CertificateStoreLocation.LocalMachine,
            _ => null
        };
        if (location is null)
        {
            return Fail<CertificateRef>(
                PolicyErrorCode.InvalidCertificate,
                $"{path}.storeLocation",
                "The certificate store location is unsupported.");
        }

        if (!TryReadRequiredString(element, "storeName", path, out string storeName, out error))
        {
            return Failure<CertificateRef>(error!);
        }

        if (!TryReadRequiredString(element, "thumbprint", path, out string thumbprint, out error))
        {
            return Failure<CertificateRef>(error!);
        }

        PolicyResult<CertificateRef> result = CertificateRef.TryCreate(location.Value, storeName, thumbprint);
        if (result.IsSuccess)
        {
            return result;
        }

        PolicyError certificateError = result.Errors[0];
        string suffix = certificateError.Path.StartsWith("certificate.", StringComparison.Ordinal)
            ? certificateError.Path["certificate".Length..]
            : string.Empty;
        return Fail<CertificateRef>(certificateError.Code, path + suffix, certificateError.Message);
    }

    private static PolicyResult<TimestampPolicy> ParseTimestamp(JsonElement element, string path)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            return InvalidType<TimestampPolicy>(path, "object");
        }

        PolicyError? fieldError = ValidateFields(element, TimestampFields, path);
        if (fieldError is not null)
        {
            return Failure<TimestampPolicy>(fieldError);
        }

        if (!TryReadRequiredString(element, "protocol", path, out string protocol, out PolicyError? error))
        {
            return Failure<TimestampPolicy>(error!);
        }

        if (!string.Equals(protocol, "rfc3161", StringComparison.Ordinal))
        {
            return Fail<TimestampPolicy>(
                PolicyErrorCode.UnsafePolicy,
                $"{path}.protocol",
                "Only RFC3161 timestamps are supported.");
        }

        if (!TryReadRequiredString(element, "timestampDigest", path, out string timestampDigest, out error))
        {
            return Failure<TimestampPolicy>(error!);
        }

        if (!string.Equals(timestampDigest, "sha256", StringComparison.Ordinal))
        {
            return Fail<TimestampPolicy>(
                PolicyErrorCode.InvalidTimestampDigest,
                $"{path}.timestampDigest",
                "The timestamp digest must be SHA-256.");
        }

        if (!TryReadRequiredString(element, "uri", path, out string uri, out error))
        {
            return Failure<TimestampPolicy>(error!);
        }

        PolicyResult<TimestampPolicy> result = TimestampPolicy.TryCreate(uri);
        if (!result.IsSuccess)
        {
            PolicyError timestampError = result.Errors[0];
            return Fail<TimestampPolicy>(timestampError.Code, $"{path}.uri", timestampError.Message);
        }

        return result;
    }

    private static PolicyResult<SigningSubject> ParseSubject(JsonElement root, string rootPath)
    {
        if (!TryGetRequired(root, "subject", rootPath, out JsonElement element, out PolicyError? error))
        {
            return Failure<SigningSubject>(error!);
        }

        const string path = "$.subject";
        if (element.ValueKind != JsonValueKind.Object)
        {
            return InvalidType<SigningSubject>(path, "object");
        }

        PolicyError? fieldError = ValidateFields(element, SubjectFields, path);
        if (fieldError is not null)
        {
            return Failure<SigningSubject>(fieldError);
        }

        if (!TryReadRequiredString(element, "formatFamily", path, out string formatFamilyText, out error))
        {
            return Failure<SigningSubject>(error!);
        }

        if (!TryReadRequiredString(element, "extension", path, out string extension, out error))
        {
            return Failure<SigningSubject>(error!);
        }

        if (!TryReadRequiredString(element, "capability", path, out string capabilityText, out error))
        {
            return Failure<SigningSubject>(error!);
        }

        SigningFormatFamily? formatFamily = ParseFormatFamily(formatFamilyText);
        if (formatFamily is null)
        {
            return Fail<SigningSubject>(
                PolicyErrorCode.UnsupportedFileType,
                "$.subject.formatFamily",
                "The subject format family is unsupported.");
        }

        SigningCapability? capability = ParseCapability(capabilityText);
        if (capability is null)
        {
            return Fail<SigningSubject>(
                PolicyErrorCode.UnsafePolicy,
                "$.subject.capability",
                "The signing capability is unsupported.");
        }

        return SigningSubject.TryCreateParsed(formatFamily.Value, extension, capability.Value);
    }

    private static PolicyResult<ExistingSignaturePolicy> ParseExistingSignatures(JsonElement root, string rootPath)
    {
        if (!TryGetRequired(root, "existingSignatures", rootPath, out JsonElement element, out PolicyError? error))
        {
            return Failure<ExistingSignaturePolicy>(error!);
        }

        const string path = "$.existingSignatures";
        if (element.ValueKind != JsonValueKind.Object)
        {
            return InvalidType<ExistingSignaturePolicy>(path, "object");
        }

        PolicyError? fieldError = ValidateFields(element, ExistingSignatureFields, path);
        if (fieldError is not null)
        {
            return Failure<ExistingSignaturePolicy>(fieldError);
        }

        foreach (string field in ExistingSignatureFields)
        {
            if (!TryReadRequiredString(element, field, path, out string disposition, out error))
            {
                return Failure<ExistingSignaturePolicy>(error!);
            }

            string expected = field == "valid" ? "skip" : "fail";
            if (!string.Equals(disposition, expected, StringComparison.Ordinal))
            {
                return Fail<ExistingSignaturePolicy>(
                    PolicyErrorCode.UnsafePolicy,
                    $"{path}.{field}",
                    "The existing-signature fail-closed policy is fixed and cannot be changed.");
            }
        }

        return PolicyResult<ExistingSignaturePolicy>.Success(ExistingSignaturePolicy.CreateFixed());
    }

    private static PolicyError? ValidateFields(JsonElement element, IReadOnlyList<string> allowed, string path)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonProperty property in element.EnumerateObject())
        {
            if (!allowed.Contains(property.Name, StringComparer.Ordinal) || !seen.Add(property.Name))
            {
                return new PolicyError(
                    PolicyErrorCode.UnknownField,
                    $"{path}.{property.Name}",
                    "Unknown and duplicate properties are rejected.");
            }
        }

        return null;
    }

    private static bool TryGetRequired(
        JsonElement element,
        string name,
        string parentPath,
        out JsonElement value,
        out PolicyError? error)
    {
        if (!element.TryGetProperty(name, out value))
        {
            error = new PolicyError(
                PolicyErrorCode.MissingField,
                $"{parentPath}.{name}",
                "A required property is missing.");
            return false;
        }

        error = null;
        return true;
    }

    private static bool TryReadRequiredString(
        JsonElement element,
        string name,
        string parentPath,
        out string value,
        out PolicyError? error)
    {
        value = string.Empty;
        if (!TryGetRequired(element, name, parentPath, out JsonElement property, out error))
        {
            return false;
        }

        if (property.ValueKind != JsonValueKind.String)
        {
            error = TypeError($"{parentPath}.{name}", "string");
            return false;
        }

        value = property.GetString()!;
        return true;
    }

    private static bool TryReadRequiredBoolean(
        JsonElement element,
        string name,
        string parentPath,
        out bool value,
        out PolicyError? error)
    {
        value = false;
        if (!TryGetRequired(element, name, parentPath, out JsonElement property, out error))
        {
            return false;
        }

        if (property.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            error = TypeError($"{parentPath}.{name}", "boolean");
            return false;
        }

        value = property.GetBoolean();
        return true;
    }

    private static PolicyError TypeError(string path, string expected) =>
        new(PolicyErrorCode.InvalidFieldType, path, $"The property must be a JSON {expected}.");

    private static PolicyResult<T> InvalidType<T>(string path, string expected) where T : class =>
        Failure<T>(TypeError(path, expected));

    private static PolicyResult<T> Fail<T>(
        PolicyErrorCode code,
        string path,
        string message) where T : class =>
        PolicyResult<T>.Failure(code, path, message);

    private static PolicyResult<T> Failure<T>(PolicyError error) where T : class =>
        PolicyResult<T>.Failure(error.Code, error.Path, error.Message);

    private static PolicyResult<TTarget> CopyFailure<TTarget, TSource>(PolicyResult<TSource> source)
        where TTarget : class
        where TSource : class => Failure<TTarget>(source.Errors[0]);

    private static void WriteLeg(Utf8JsonWriter writer, SignatureLeg leg)
    {
        writer.WriteStartObject();
        writer.WriteStartObject("certificate");
        writer.WriteString("storeLocation", Format(leg.Certificate.StoreLocation));
        writer.WriteString("storeName", leg.Certificate.StoreName);
        writer.WriteString("thumbprint", leg.Certificate.Thumbprint);
        writer.WriteEndObject();
        writer.WriteString("fileDigest", Format(leg.FileDigest));
        writer.WriteBoolean("append", leg.Append);
        writer.WriteStartObject("timestamp");
        writer.WriteString("protocol", "rfc3161");
        writer.WriteString("timestampDigest", "sha256");
        writer.WriteString("uri", leg.Timestamp.Uri.OriginalString);
        writer.WriteEndObject();
        writer.WriteEndObject();
    }

    private static void WriteSubject(Utf8JsonWriter writer, SigningSubject subject)
    {
        writer.WriteStartObject("subject");
        writer.WriteString("formatFamily", Format(subject.FormatFamily));
        writer.WriteString("extension", subject.Extension);
        writer.WriteString("capability", Format(subject.Capability));
        writer.WriteEndObject();
    }

    private static void WriteExistingSignatures(Utf8JsonWriter writer, ExistingSignaturePolicy policy)
    {
        writer.WriteStartObject("existingSignatures");
        writer.WriteString("valid", Format(policy.Valid));
        writer.WriteString("invalid", Format(policy.Invalid));
        writer.WriteString("untrusted", Format(policy.Untrusted));
        writer.WriteString("expired", Format(policy.Expired));
        writer.WriteString("partial", Format(policy.Partial));
        writer.WriteString("malformed", Format(policy.Malformed));
        writer.WriteEndObject();
    }

    private static string Format(SigningMode value) => value switch
    {
        SigningMode.Single => "single",
        SigningMode.Dual => "dual",
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Unknown signing mode.")
    };

    private static SigningMode? ParseSigningMode(string value) => value switch
    {
        "single" => SigningMode.Single,
        "dual" => SigningMode.Dual,
        _ => null
    };

    private static string Format(CertificateStoreLocation value) => value switch
    {
        CertificateStoreLocation.CurrentUser => "currentUser",
        CertificateStoreLocation.LocalMachine => "localMachine",
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Unknown store location.")
    };

    private static string Format(FileDigestAlgorithm value) => value switch
    {
        FileDigestAlgorithm.Sha1 => "sha1",
        FileDigestAlgorithm.Sha256 => "sha256",
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Unknown file digest.")
    };

    internal static string Format(SigningFormatFamily value) => value switch
    {
        SigningFormatFamily.PeImage => "peImage",
        SigningFormatFamily.WindowsInstaller => "windowsInstaller",
        SigningFormatFamily.Cabinet => "cabinet",
        SigningFormatFamily.Catalog => "catalog",
        SigningFormatFamily.AppPackage => "appPackage",
        SigningFormatFamily.PowerShellScript => "powerShellScript",
        SigningFormatFamily.WindowsScript => "windowsScript",
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Unknown signing format family.")
    };

    internal static string Format(SigningCapability value) => value switch
    {
        SigningCapability.PeImageDualCapable => "peImageDualCapable",
        SigningCapability.WindowsSipSingleOnly => "windowsSipSingleOnly",
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Unknown signing capability.")
    };

    private static SigningFormatFamily? ParseFormatFamily(string value) => value switch
    {
        "peImage" => SigningFormatFamily.PeImage,
        "windowsInstaller" => SigningFormatFamily.WindowsInstaller,
        "cabinet" => SigningFormatFamily.Cabinet,
        "catalog" => SigningFormatFamily.Catalog,
        "appPackage" => SigningFormatFamily.AppPackage,
        "powerShellScript" => SigningFormatFamily.PowerShellScript,
        "windowsScript" => SigningFormatFamily.WindowsScript,
        _ => null
    };

    private static SigningCapability? ParseCapability(string value) => value switch
    {
        "peImageDualCapable" => SigningCapability.PeImageDualCapable,
        "windowsSipSingleOnly" => SigningCapability.WindowsSipSingleOnly,
        _ => null
    };

    private static string Format(ExistingSignatureDisposition value) => value switch
    {
        ExistingSignatureDisposition.Skip => "skip",
        ExistingSignatureDisposition.Fail => "fail",
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Unknown existing-signature disposition.")
    };
}
