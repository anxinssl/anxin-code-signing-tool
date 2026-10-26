using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace CodeSigner.Core.Worker;

public sealed record WorkerProcessIdentity(string UserSid, int SessionId)
{
    public static WorkerProcessIdentity Capture(Process process)
    {
        ArgumentNullException.ThrowIfNull(process);
        if (!NativeMethods.OpenProcessToken(process.SafeHandle, NativeMethods.TokenQuery, out SafeAccessTokenHandle token))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not inspect the worker process token.");
        }

        using (token)
        using (WindowsIdentity identity = new(token.DangerousGetHandle()))
        {
            string sid = identity.User?.Value
                ?? throw new WorkerProcessSecurityException("missing_user_sid");
            return new WorkerProcessIdentity(sid, process.SessionId);
        }
    }
}

public sealed class WorkerProcessSecurityException(string code)
    : InvalidOperationException("The worker process failed its launch security policy.")
{
    public string Code { get; } = code;
}

public static class WorkerProcessLaunchPolicy
{
    public static void Validate(WorkerProcessIdentity launcher, WorkerProcessIdentity worker)
    {
        ArgumentNullException.ThrowIfNull(launcher);
        ArgumentNullException.ThrowIfNull(worker);
        if (!string.Equals(launcher.UserSid, worker.UserSid, StringComparison.Ordinal))
        {
            throw new WorkerProcessSecurityException("user_mismatch");
        }

        if (launcher.SessionId != worker.SessionId)
        {
            throw new WorkerProcessSecurityException("session_mismatch");
        }
    }
}

internal static class NativeMethods
{
    internal const uint TokenQuery = 0x0008;

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool OpenProcessToken(
        SafeProcessHandle processHandle,
        uint desiredAccess,
        out SafeAccessTokenHandle tokenHandle);
}
