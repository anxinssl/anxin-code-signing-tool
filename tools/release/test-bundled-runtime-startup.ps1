[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AppPath,
    [Parameter(Mandatory = $true)]
    [string]$WorkerPath,
    [Parameter(Mandatory = $true)]
    [string]$HookPath,
    [Parameter(Mandatory = $true)]
    [string]$EvidenceDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$hook = (Resolve-Path -LiteralPath $HookPath).Path
$evidence = [IO.Path]::GetFullPath($EvidenceDirectory)
$null = New-Item -ItemType Directory -Path $evidence -Force
$run = Join-Path $evidence ([guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $run
$emptyRoot = Join-Path $run 'empty-dotnet'
$null = New-Item -ItemType Directory -Path $emptyRoot

& node (Join-Path $PSScriptRoot 'verify-self-contained-bundle.mjs') --app $AppPath --worker $WorkerPath
if ($LASTEXITCODE -ne 0) { throw 'Bundle verification failed; no executable was launched.' }

$results = foreach ($item in @(
    @{ Path = $AppPath; Name = 'app'; Desktop = '1' },
    @{ Path = $WorkerPath; Name = 'worker'; Desktop = '0' }
)) {
    $executable = (Resolve-Path -LiteralPath $item.Path).Path
    $receipt = Join-Path $run ($item.Name + '.json')
    $extract = Join-Path $run ($item.Name + '-extraction')
    $null = New-Item -ItemType Directory -Path $extract
    $start = [Diagnostics.ProcessStartInfo]::new($executable)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.WorkingDirectory = $run
    $start.Environment['PATH'] = Join-Path $env:SystemRoot 'System32'
    $start.Environment['DOTNET_ROOT'] = $emptyRoot
    $start.Environment['DOTNET_ROOT_X64'] = $emptyRoot
    $start.Environment['DOTNET_ROOT(x86)'] = $emptyRoot
    $start.Environment['DOTNET_MULTILEVEL_LOOKUP'] = '0'
    $start.Environment['DOTNET_DISABLE_GUI_ERRORS'] = '1'
    $start.Environment['DOTNET_BUNDLE_EXTRACT_BASE_DIR'] = $extract
    $start.Environment['DOTNET_STARTUP_HOOKS'] = $hook
    $start.Environment['DOTNET_HOST_TRACE'] = '1'
    $start.Environment['DOTNET_HOST_TRACEFILE'] = Join-Path $run ($item.Name + '-host.txt')
    $start.Environment['CODESIGNER_STARTUP_PROBE_RECEIPT'] = $receipt
    $start.Environment['CODESIGNER_STARTUP_PROBE_DESKTOP'] = $item.Desktop
    $process = [Diagnostics.Process]::Start($start)
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(45000)) {
            $process.Kill($true)
            $process.WaitForExit()
            throw "Runtime startup probe timed out: $($item.Name)"
        }
        $stdout.GetAwaiter().GetResult() | Set-Content -LiteralPath (Join-Path $run ($item.Name + '-stdout.txt'))
        $stderr.GetAwaiter().GetResult() | Set-Content -LiteralPath (Join-Path $run ($item.Name + '-stderr.txt'))
        if ($process.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $receipt)) {
            throw "Runtime startup probe failed: $($item.Name), exit=$($process.ExitCode). See $run"
        }
        $result = Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json
        if (-not $result.success -or -not $result.privateRuntime -or $result.productMainExecuted) {
            throw "Runtime isolation check failed: $($item.Name)"
        }
        $result
    }
    finally {
        $process.Dispose()
    }
}
$summary = [ordered]@{
    success = $true
    scope = 'Runtime initialization only; startup hook exits before product Main, UI, or signing.'
    emptyDotNetRoot = $emptyRoot
    results = @($results)
}
$summary | ConvertTo-Json -Depth 6 | Tee-Object -FilePath (Join-Path $run 'summary.json')
