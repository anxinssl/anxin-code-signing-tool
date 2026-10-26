using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace CodeSigner.Core.Diagnostics;

public sealed record RedactedDiagnosticText(string? Value, bool Truncated);

public static partial class SigningDiagnosticRedactor
{
    public const int WorkerStderrTailCapacityBytes = 8192;
    public const string RedactedValue = "[redacted]";
    private const int DefaultTextCapacityBytes = 512;
    private const int DefaultFileNameCapacityBytes = 255;

    private static readonly HashSet<string> SecretMemberNames = new(StringComparer.Ordinal)
    {
        "apikey",
        "accesstoken",
        "bearertoken",
        "certificate",
        "certificateprivatekey",
        "certificatepayload",
        "clientsecret",
        "commandline",
        "credential",
        "fullcommandline",
        "keycontainer",
        "password",
        "passphrase",
        "pfx",
        "pfxpassword",
        "pin",
        "privatekey",
        "providerargs",
        "providerarguments",
        "providercommand",
        "provideroutput",
        "providertext",
        "providertranscript",
        "rawprovidertext",
        "rawprovidertranscript",
        "refreshtoken",
        "secret",
        "session",
        "sessiondata",
        "sessionid",
        "temporaryjson",
        "tempjson",
        "token"
    };

    public static string? RedactText(string? value, int maxUtf8Bytes = DefaultTextCapacityBytes)
    {
        ValidateCapacity(maxUtf8Bytes);
        return value is null
            ? null
            : TakeUtf8Prefix(RedactTextCore(value), maxUtf8Bytes);
    }

    public static string? RedactFileName(string? path, int maxUtf8Bytes = DefaultFileNameCapacityBytes)
    {
        ValidateCapacity(maxUtf8Bytes);
        if (path is null)
        {
            return null;
        }

        string trimmed = path.Trim();
        if (trimmed.Length == 0)
        {
            return string.Empty;
        }

        string fileName;
        try
        {
            fileName = Path.GetFileName(trimmed);
        }
        catch (Exception error) when (error is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return RedactedValue;
        }

        if (string.IsNullOrWhiteSpace(fileName) ||
            fileName.IndexOfAny(['/', '\\', '?', '#', ':']) >= 0)
        {
            return RedactedValue;
        }

        string redacted = RedactTextCore(fileName);
        return string.Equals(redacted, fileName, StringComparison.Ordinal)
            ? TakeUtf8Prefix(fileName, maxUtf8Bytes)
            : RedactedValue;
    }

    public static string? RedactJson(string? json, int maxUtf8Bytes = WorkerStderrTailCapacityBytes)
    {
        ValidateCapacity(maxUtf8Bytes);
        if (json is null)
        {
            return null;
        }

        JsonNode? root;
        try
        {
            root = JsonNode.Parse(json);
        }
        catch (System.Text.Json.JsonException)
        {
            return RedactedValue;
        }

        if (root is null)
        {
            return "null";
        }

        RedactJsonNode(root, memberName: null);
        string redacted = root.ToJsonString();
        return Encoding.UTF8.GetByteCount(redacted) <= maxUtf8Bytes
            ? redacted
            : RedactedValue;
    }

    public static RedactedDiagnosticText RedactWorkerStderrTail(ReadOnlySpan<byte> utf8Bytes)
    {
        bool truncated = utf8Bytes.Length > WorkerStderrTailCapacityBytes;
        string decoded = Encoding.UTF8.GetString(utf8Bytes);
        string redacted = RedactTextCore(decoded);
        string bounded = TakeUtf8Tail(redacted, WorkerStderrTailCapacityBytes, out bool redactedTruncated);
        return new RedactedDiagnosticText(bounded, truncated || redactedTruncated);
    }

    private static string RedactTextCore(string value)
    {
        if (value.Length == 0 || string.Equals(value, RedactedValue, StringComparison.Ordinal))
        {
            return value;
        }

        foreach (char character in value)
        {
            if (char.IsControl(character) && character is not ('\r' or '\n' or '\t'))
            {
                return RedactedValue;
            }
        }

        if (PemPayloadPattern().IsMatch(value) ||
            OpaqueSecretTextPattern().IsMatch(value) ||
            CommandLinePattern().IsMatch(value))
        {
            return RedactedValue;
        }

        string redacted = UrlPattern().Replace(value, static match => RedactUri(match.Value));
        redacted = WindowsPathPattern().Replace(
            redacted,
            static match => RedactFileName(match.Value, int.MaxValue) ?? RedactedValue);
        redacted = SensitiveAssignmentPattern().Replace(
            redacted,
            static match => match.Groups["key"].Value + "=" + RedactedValue);
        return redacted;
    }

    private static void RedactJsonNode(JsonNode node, string? memberName)
    {
        if (node is JsonObject jsonObject)
        {
            foreach (KeyValuePair<string, JsonNode?> property in jsonObject.ToList())
            {
                if (property.Value is null)
                {
                    continue;
                }

                string normalizedName = NormalizeMemberName(property.Key);
                if (SecretMemberNames.Contains(normalizedName))
                {
                    jsonObject[property.Key] = RedactedValue;
                }
                else if (IsPathMember(normalizedName) && property.Value is JsonValue pathValue &&
                    pathValue.TryGetValue(out string? path))
                {
                    jsonObject[property.Key] = RedactFileName(path);
                }
                else if (IsUriMember(normalizedName) && property.Value is JsonValue uriValue &&
                    uriValue.TryGetValue(out string? uri))
                {
                    jsonObject[property.Key] = RedactUri(uri);
                }
                else
                {
                    RedactJsonNode(property.Value, property.Key);
                }
            }

            return;
        }

        if (node is JsonArray array)
        {
            for (int index = 0; index < array.Count; index++)
            {
                if (array[index] is JsonNode child)
                {
                    RedactJsonNode(child, memberName);
                }
            }

            return;
        }

        if (node is JsonValue valueNode && valueNode.TryGetValue(out string? text))
        {
            valueNode.ReplaceWith(RedactTextCore(text));
        }
    }

    private static string RedactUri(string? value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) ||
            uri.Scheme is not ("http" or "https") ||
            string.IsNullOrWhiteSpace(uri.IdnHost))
        {
            return RedactedValue;
        }

        return uri.Scheme.ToLowerInvariant() + "://" + uri.IdnHost.ToLowerInvariant();
    }

    private static string NormalizeMemberName(string value)
    {
        var builder = new StringBuilder(value.Length);
        foreach (char character in value)
        {
            if (char.IsAsciiLetterOrDigit(character))
            {
                builder.Append(char.ToLowerInvariant(character));
            }
        }

        return builder.ToString();
    }

    private static bool IsPathMember(string normalizedName) =>
        normalizedName.EndsWith("path", StringComparison.Ordinal) ||
        normalizedName.EndsWith("filename", StringComparison.Ordinal);

    private static bool IsUriMember(string normalizedName) =>
        normalizedName.EndsWith("url", StringComparison.Ordinal) ||
        normalizedName.EndsWith("uri", StringComparison.Ordinal);

    private static string TakeUtf8Prefix(string value, int maxUtf8Bytes)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        if (bytes.Length <= maxUtf8Bytes)
        {
            return value;
        }

        int end = maxUtf8Bytes;
        while (end > 0 && IsUtf8ContinuationByte(bytes[end]))
        {
            end--;
        }

        return Encoding.UTF8.GetString(bytes, 0, end);
    }

    private static string TakeUtf8Tail(string value, int maxUtf8Bytes, out bool truncated)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        truncated = bytes.Length > maxUtf8Bytes;
        if (!truncated)
        {
            return value;
        }

        int start = bytes.Length - maxUtf8Bytes;
        while (start < bytes.Length && IsUtf8ContinuationByte(bytes[start]))
        {
            start++;
        }

        return Encoding.UTF8.GetString(bytes, start, bytes.Length - start);
    }

    private static bool IsUtf8ContinuationByte(byte value) => (value & 0xC0) == 0x80;

    private static void ValidateCapacity(int maxUtf8Bytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxUtf8Bytes);
    }

    [GeneratedRegex("https?://[^\\s\\\"']+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UrlPattern();

    [GeneratedRegex("(?:[A-Za-z]:\\\\|\\\\\\\\)[^\\r\\n\\\"'<>|?*]+", RegexOptions.CultureInvariant)]
    private static partial Regex WindowsPathPattern();

    [GeneratedRegex(
        "(?<![A-Za-z0-9])(?<key>--?(?:pin|password|passphrase|token|session(?:[-_]?id)?|api[-_]?key|private[-_]?key|key[-_]?container|certificate|provider[-_]?(?:command|arguments?)|temp(?:orary)?[-_]?json)|(?:pin|password|passphrase|token|session(?:[-_]?id)?|api[-_]?key|private[-_]?key|key[-_]?container|certificate|provider[-_]?(?:command|arguments?)|temp(?:orary)?[-_]?json))\\s*(?:=|:|\\s)\\s*(?:\\\"[^\\\"]*\\\"|'[^']*'|[^\\s,;]+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SensitiveAssignmentPattern();

    [GeneratedRegex(
        "(?:^|\\s)(?:signtool(?:\\.exe)?\\s+(?:sign|verify|remove|catdb)\\b|powershell(?:\\.exe)?\\s+-|pwsh(?:\\.exe)?\\s+-|cmd(?:\\.exe)?\\s+/|dotnet(?:\\.exe)?\\s+(?:exec|run|test|build|publish)\\b)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CommandLinePattern();

    [GeneratedRegex(
        "(?:provider\\s*(?:output|text|transcript|command|arguments?)|raw\\s+provider(?:\\s+transcript)?|command\\s*line|temp(?:orary)?\\s*json|session\\s*(?:data|token)|(?:certificate\\s+)?private\\s*key(?:\\s*(?:data|material))?)\\s*[:=]",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex OpaqueSecretTextPattern();

    [GeneratedRegex(
        "-----BEGIN\\s+(?:[A-Z ]*PRIVATE KEY|CERTIFICATE)-----",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PemPayloadPattern();
}
