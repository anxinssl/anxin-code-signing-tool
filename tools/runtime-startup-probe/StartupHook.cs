using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;

// Test-only startup hook. Always terminate before the product's Main or any UI runs.
public static class StartupHook
{
    public static void Initialize()
    {
        int exitCode = 87;
        try
        {
            string receipt = Environment.GetEnvironmentVariable("CODESIGNER_STARTUP_PROBE_RECEIPT")
                ?? throw new InvalidOperationException("A probe receipt path is required.");
            string extractionRoot = Path.GetFullPath(
                Environment.GetEnvironmentVariable("DOTNET_BUNDLE_EXTRACT_BASE_DIR")
                ?? throw new InvalidOperationException("A private extraction root is required."));
            bool desktop = Environment.GetEnvironmentVariable("CODESIGNER_STARTUP_PROBE_DESKTOP") == "1";
            if (desktop)
            {
                _ = Assembly.Load("PresentationFramework");
                _ = Assembly.Load("PresentationCore");
                _ = Assembly.Load("WindowsBase");
            }
            using Process process = Process.GetCurrentProcess();
            ProcessModule? coreClrModule = process.Modules.Cast<ProcessModule>()
                .SingleOrDefault(module => string.Equals(module.ModuleName, "coreclr.dll", StringComparison.OrdinalIgnoreCase));
            ProcessModule host = process.MainModule ?? throw new InvalidOperationException("Missing executable module.");
            bool staticRuntime = coreClrModule is null &&
                NativeLibrary.TryGetExport(host.BaseAddress, "DotNetRuntimeInfo", out _) &&
                NativeLibrary.TryGetExport(host.BaseAddress, "DotNetRuntimeContractDescriptor", out _) &&
                NativeLibrary.TryGetExport(host.BaseAddress, "CLRJitAttachState", out _);
            string coreClrPath = coreClrModule?.FileName ?? host.FileName;
            bool privateRuntime = staticRuntime || Path.GetFullPath(coreClrPath).StartsWith(
                extractionRoot.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase);
            bool success = privateRuntime && Environment.Version.Major == 10;
            File.WriteAllText(receipt, JsonSerializer.Serialize(new
            {
                success,
                executable = Environment.ProcessPath,
                runtimeVersion = Environment.Version.ToString(),
                coreClrPath,
                privateRuntime,
                nativeRuntime = staticRuntime ? "statically-linked" : "bundled-libraries",
                desktopAssembliesLoaded = desktop,
                productMainExecuted = false,
                signingPerformed = false,
            }, new JsonSerializerOptions { WriteIndented = true }));
            exitCode = success ? 0 : 88;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception.ToString());
        }
        finally
        {
            Environment.Exit(exitCode);
        }
    }
}
