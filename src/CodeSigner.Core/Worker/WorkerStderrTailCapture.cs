using CodeSigner.Core.Diagnostics;

namespace CodeSigner.Core.Worker;

internal readonly record struct WorkerStderrDiagnostic(string? Tail, bool Truncated)
{
    internal static WorkerStderrDiagnostic Empty { get; } = new(null, false);
}

internal sealed class WorkerStderrTailCapture
{
    private const int ReadBufferBytes = 4096;

    private readonly object sync = new();
    private readonly byte[] tail = new byte[SigningDiagnosticRedactor.WorkerStderrTailCapacityBytes];
    private int start;
    private int count;
    private bool truncated;

    private WorkerStderrTailCapture(Stream stream, CancellationToken cancellationToken)
    {
        Completion = DrainAsync(stream, cancellationToken);
    }

    internal Task Completion { get; }

    internal static WorkerStderrTailCapture Start(Stream stream, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead)
        {
            throw new ArgumentException("The stderr stream must be readable.", nameof(stream));
        }

        return new WorkerStderrTailCapture(stream, cancellationToken);
    }

    internal WorkerStderrDiagnostic Snapshot()
    {
        byte[] bytes;
        bool wasTruncated;
        lock (sync)
        {
            if (count == 0)
            {
                return WorkerStderrDiagnostic.Empty;
            }

            bytes = new byte[count];
            int firstPartLength = Math.Min(count, tail.Length - start);
            tail.AsSpan(start, firstPartLength).CopyTo(bytes);
            if (firstPartLength < count)
            {
                tail.AsSpan(0, count - firstPartLength).CopyTo(bytes.AsSpan(firstPartLength));
            }

            wasTruncated = truncated;
        }

        RedactedDiagnosticText redacted = SigningDiagnosticRedactor.RedactWorkerStderrTail(bytes);
        string? value = string.IsNullOrEmpty(redacted.Value) ? null : redacted.Value;
        return new WorkerStderrDiagnostic(value, wasTruncated || redacted.Truncated);
    }

    private async Task DrainAsync(Stream stream, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[ReadBufferBytes];
        try
        {
            while (true)
            {
                int bytesRead = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0)
                {
                    return;
                }

                Append(buffer.AsSpan(0, bytesRead));
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
    }

    private void Append(ReadOnlySpan<byte> bytes)
    {
        lock (sync)
        {
            foreach (byte value in bytes)
            {
                if (count < tail.Length)
                {
                    tail[(start + count) % tail.Length] = value;
                    count++;
                    continue;
                }

                tail[start] = value;
                start = (start + 1) % tail.Length;
                truncated = true;
            }
        }
    }
}
