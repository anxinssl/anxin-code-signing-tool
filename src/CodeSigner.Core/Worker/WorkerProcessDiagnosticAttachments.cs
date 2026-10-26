using System.Runtime.CompilerServices;

namespace CodeSigner.Core.Worker;

internal static class WorkerProcessDiagnosticAttachments
{
    private static readonly object Sync = new();
    private static readonly ConditionalWeakTable<Exception, Holder> Diagnostics = new();

    internal static void Attach(Exception error, WorkerStderrDiagnostic diagnostic)
    {
        ArgumentNullException.ThrowIfNull(error);
        if (diagnostic == WorkerStderrDiagnostic.Empty)
        {
            return;
        }

        lock (Sync)
        {
            Diagnostics.Remove(error);
            Diagnostics.Add(error, new Holder(diagnostic));
        }
    }

    internal static WorkerStderrDiagnostic Get(Exception error)
    {
        ArgumentNullException.ThrowIfNull(error);
        if (error is WorkerProcessTimeoutException timeout)
        {
            return new WorkerStderrDiagnostic(
                timeout.WorkerStderrTail,
                timeout.WorkerStderrTruncated);
        }

        if (error is WorkerProcessCrashedException crashed)
        {
            return new WorkerStderrDiagnostic(
                crashed.WorkerStderrTail,
                crashed.WorkerStderrTruncated);
        }

        lock (Sync)
        {
            return Diagnostics.TryGetValue(error, out Holder? holder)
                ? holder.Diagnostic
                : WorkerStderrDiagnostic.Empty;
        }
    }

    private sealed class Holder(WorkerStderrDiagnostic diagnostic)
    {
        internal WorkerStderrDiagnostic Diagnostic { get; } = diagnostic;
    }
}
