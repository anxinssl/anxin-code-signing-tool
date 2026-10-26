using CodeSigner.Core.Worker;
using CodeSigner.Worker;

try
{
    return await WorkerProtocolHost.RunLoopAsync(
        Console.OpenStandardInput(),
        Console.OpenStandardOutput(),
        new ProductionSigningWorkerCommandHandler(),
        CancellationToken.None);
}
catch (Exception exception)
{
    Console.Error.WriteLine(
        $"worker_unhandled={exception.GetType().Name};hresult=0x{unchecked((uint)exception.HResult):X8}");
    return 3;
}
