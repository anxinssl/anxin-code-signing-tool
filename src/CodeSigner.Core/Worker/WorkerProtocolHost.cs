namespace CodeSigner.Core.Worker;

public interface IWorkerCommandHandler
{
    ValueTask<WorkerResponse> HandleAsync(WorkerRequest request, CancellationToken cancellationToken);
}

public interface IStreamingWorkerCommandHandler : IWorkerCommandHandler
{
    ValueTask<WorkerResponse> HandleAsync(
        WorkerRequest request,
        Func<WorkerProgress, CancellationToken, ValueTask> reportProgress,
        CancellationToken cancellationToken);
}

public sealed class ProbeWorkerCommandHandler : IWorkerCommandHandler
{
    public ValueTask<WorkerResponse> HandleAsync(WorkerRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        WorkerResponse response = string.Equals(request.Command, WorkerCommands.Probe, StringComparison.Ordinal)
            ? new WorkerResponse(WorkerProtocol.Version, true, WorkerResponseCodes.Ready)
            : new WorkerResponse(
                WorkerProtocol.Version,
                false,
                WorkerResponseCodes.UnsupportedCommand);
        return ValueTask.FromResult(response);
    }
}

public static class WorkerProtocolHost
{
    public static async Task<int> RunLoopAsync(
        Stream input,
        Stream output,
        IWorkerCommandHandler handler,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(handler);
        int lastExitCode = 0;
        while (true)
        {
            WorkerRequest request;
            try
            {
                request = await WorkerProtocol.ReadRequestAsync(input, cancellationToken).ConfigureAwait(false);
            }
            catch (WorkerEndOfStreamException error) when (error.IsCleanEof)
            {
                return lastExitCode;
            }
            catch (WorkerEndOfStreamException)
            {
                await WriteFailureAsync(output, WorkerResponseCodes.InvalidFrame, cancellationToken).ConfigureAwait(false);
                return 2;
            }
            catch (WorkerProtocolException error)
            {
                await WriteFailureAsync(output, error.Code, cancellationToken).ConfigureAwait(false);
                return 2;
            }

            WorkerResponse response;
            try
            {
                response = handler is IStreamingWorkerCommandHandler streaming
                    ? await streaming.HandleAsync(
                        request,
                        (progress, token) => new ValueTask(
                            WorkerProtocol.WriteProgressAsync(output, progress, token)),
                        cancellationToken).ConfigureAwait(false)
                    : await handler.HandleAsync(request, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception)
            {
                response = Failure(WorkerResponseCodes.HandlerFailure);
            }

            try
            {
                await WorkerProtocol.WriteResponseAsync(output, response, cancellationToken).ConfigureAwait(false);
            }
            catch (WorkerProtocolException error) when (error.Code == WorkerResponseCodes.ResponseTooLarge)
            {
                response = Failure(WorkerResponseCodes.ResponseTooLarge);
                await WorkerProtocol.WriteResponseAsync(output, response, cancellationToken).ConfigureAwait(false);
            }

            lastExitCode = response.Success ? 0 : 2;
        }
    }

    public static async Task<int> RunOnceAsync(
        Stream input,
        Stream output,
        IWorkerCommandHandler handler,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(handler);
        WorkerRequest request;
        try
        {
            request = await WorkerProtocol.ReadRequestAsync(input, cancellationToken).ConfigureAwait(false);
        }
        catch (WorkerEndOfStreamException error) when (error.IsCleanEof)
        {
            return 0;
        }
        catch (WorkerEndOfStreamException)
        {
            await WriteFailureAsync(output, WorkerResponseCodes.InvalidFrame, cancellationToken).ConfigureAwait(false);
            return 2;
        }
        catch (WorkerProtocolException error)
        {
            await WriteFailureAsync(output, error.Code, cancellationToken).ConfigureAwait(false);
            return 2;
        }

        WorkerResponse response;
        try
        {
            response = await handler.HandleAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            response = Failure(WorkerResponseCodes.HandlerFailure);
        }

        try
        {
            await WorkerProtocol.WriteResponseAsync(output, response, cancellationToken).ConfigureAwait(false);
        }
        catch (WorkerProtocolException error) when (error.Code == WorkerResponseCodes.ResponseTooLarge)
        {
            response = Failure(WorkerResponseCodes.ResponseTooLarge);
            await WorkerProtocol.WriteResponseAsync(output, response, cancellationToken).ConfigureAwait(false);
        }

        return response.Success ? 0 : 2;
    }

    private static WorkerResponse Failure(string code) =>
        new(WorkerProtocol.Version, false, code);

    private static Task WriteFailureAsync(Stream output, string code, CancellationToken cancellationToken) =>
        WorkerProtocol.WriteResponseAsync(output, Failure(code), cancellationToken);
}
