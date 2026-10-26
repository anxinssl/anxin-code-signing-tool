namespace CodeSigner.Windows.Files;

internal static class PathSafety
{
    public static string Canonicalize(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new IntakeValidationException(IntakeError.InvalidInput, "An input path is required.", path);
        }

        try
        {
            return Path.GetFullPath(path);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new IntakeValidationException(IntakeError.InvalidInput, "The input path is invalid.", path, exception);
        }
    }

    public static bool IsWithinOrEqual(string candidate, string root)
    {
        string relative = Path.GetRelativePath(root, candidate);
        return relative == "." ||
            (!Path.IsPathRooted(relative) &&
             !relative.Equals("..", StringComparison.Ordinal) &&
             !relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal));
    }

    public static void EnsureNoReparsePoints(string path)
    {
        string fullPath = Path.GetFullPath(path);
        string? current = fullPath;
        while (current is not null)
        {
            if (File.Exists(current) || Directory.Exists(current))
            {
                FileAttributes attributes = File.GetAttributes(current);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    throw new IntakeValidationException(
                        IntakeError.ReparsePoint,
                        "Reparse points are not accepted in an input or output path.",
                        current);
                }
            }

            string? parent = Path.GetDirectoryName(current);
            if (parent is null || parent.Equals(current, StringComparison.OrdinalIgnoreCase))
            {
                break;
            }

            current = parent;
        }
    }
}
