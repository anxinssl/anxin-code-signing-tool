using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace CodeSigner.Core.Worker;

public sealed class WorkerJob : IDisposable
{
    public const uint TimeoutExitCode = 0xC0DE0001;
    private readonly SafeWorkerJobHandle handle;

    private WorkerJob(SafeWorkerJobHandle handle) => this.handle = handle;

    public static WorkerJob CreateKillOnClose()
    {
        SafeWorkerJobHandle handle = JobNativeMethods.CreateJobObject(IntPtr.Zero, null);
        if (handle.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not create the worker job.");
        }

        JobNativeMethods.JobObjectExtendedLimitInformation limits = new();
        limits.BasicLimitInformation.LimitFlags = JobNativeMethods.JobObjectLimitKillOnJobClose;
        int size = Marshal.SizeOf<JobNativeMethods.JobObjectExtendedLimitInformation>();
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(limits, buffer, false);
            if (!JobNativeMethods.SetInformationJobObject(
                    handle,
                    JobNativeMethods.ExtendedLimitInformation,
                    buffer,
                    (uint)size))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not configure the worker job.");
            }
        }
        catch
        {
            handle.Dispose();
            throw;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return new WorkerJob(handle);
    }

    public void Assign(Process process)
    {
        ArgumentNullException.ThrowIfNull(process);
        if (!JobNativeMethods.AssignProcessToJobObject(handle, process.SafeHandle))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not assign the worker to its job.");
        }
    }

    public void Terminate(uint exitCode)
    {
        if (!JobNativeMethods.TerminateJobObject(handle, exitCode))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not terminate the worker job.");
        }
    }

    public void Dispose() => handle.Dispose();
}

internal sealed class SafeWorkerJobHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SafeWorkerJobHandle() : base(true) { }

    protected override bool ReleaseHandle() => JobNativeMethods.CloseHandle(handle);
}

internal static class JobNativeMethods
{
    internal const int ExtendedLimitInformation = 9;
    internal const uint JobObjectLimitKillOnJobClose = 0x00002000;

    [StructLayout(LayoutKind.Sequential)]
    internal struct IoCounters
    {
        internal ulong ReadOperationCount;
        internal ulong WriteOperationCount;
        internal ulong OtherOperationCount;
        internal ulong ReadTransferCount;
        internal ulong WriteTransferCount;
        internal ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct BasicLimitInformation
    {
        internal long PerProcessUserTimeLimit;
        internal long PerJobUserTimeLimit;
        internal uint LimitFlags;
        internal UIntPtr MinimumWorkingSetSize;
        internal UIntPtr MaximumWorkingSetSize;
        internal uint ActiveProcessLimit;
        internal UIntPtr Affinity;
        internal uint PriorityClass;
        internal uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct JobObjectExtendedLimitInformation
    {
        internal BasicLimitInformation BasicLimitInformation;
        internal IoCounters IoInfo;
        internal UIntPtr ProcessMemoryLimit;
        internal UIntPtr JobMemoryLimit;
        internal UIntPtr PeakProcessMemoryUsed;
        internal UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateJobObjectW", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern SafeWorkerJobHandle CreateJobObject(IntPtr jobAttributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetInformationJobObject(
        SafeWorkerJobHandle job,
        int informationClass,
        IntPtr information,
        uint informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool AssignProcessToJobObject(SafeWorkerJobHandle job, SafeProcessHandle process);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool TerminateJobObject(SafeWorkerJobHandle job, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(IntPtr handle);
}
