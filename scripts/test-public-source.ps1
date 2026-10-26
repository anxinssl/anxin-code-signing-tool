[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Push-Location $root
try {
    function Invoke-Checked {
        param([string]$Program, [string[]]$Arguments)
        & $Program @Arguments
        if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
    }
    function Assert-TestResults {
        param([string]$Name)
        [xml]$result = Get-Content -LiteralPath "artifacts/public-source-tests/$Name.trx" -Raw
        $counts = $result.TestRun.ResultSummary.Counters
        if ([int]$counts.executed -le 0 -or [int]$counts.failed -ne 0 -or [int]$counts.notExecuted -ne 0) {
            throw "$Name test selection must execute tests without failures or skips."
        }
    }
    Invoke-Checked node @('scripts/check-public-source.mjs')
    Invoke-Checked node @('scripts/build-third-party-notices.mjs', '--check')
    Invoke-Checked node @('tools/release/verify-release-version.mjs', '--check')
    Invoke-Checked node @('scripts/check-markdown-links.mjs', 'README.md', 'AGENTS.md', 'CONTRIBUTING.md', 'SECURITY.md', 'LICENSE.md', 'THIRD-PARTY-NOTICES.md', 'docs')
    Invoke-Checked node @('--test',
        'tests/contract/public-source-tests.mjs',
        'tests/contract/nsis-contract-tests.mjs',
        'tests/contract/directory-layout-contract-tests.mjs',
        'tests/contract/release-version-guard-tests.mjs',
        'tests/contract/release-package-evidence-tests.mjs',
        'tests/contract/self-contained-bundle-tests.mjs')

    # Explicit allowlist: no real certificate, signing Worker or visible window tests.
    $appClasses = @(
        'UiPresentationSmokeTests', 'ReleaseIdentityMetadataTests',
        'SettingsWindowXamlContractTests', 'FileTaskQueueXamlContractTests',
        'ResolutionScalingContractTests', 'DesignTokenContractTests',
        'PrimitiveShowcaseContractTests', 'ProductIconContractTests', 'NsisMaintenanceTests',
        'SelectedFilePreflightTests', 'RefreshPresentationTests')
    $appFilter = ($appClasses | ForEach-Object { "FullyQualifiedName~CodeSigner.App.Tests.$_" }) -join '|'
    $appFilter += '|FullyQualifiedName=CodeSigner.App.Tests.Todo6SigningAvailabilityTests.ProductionShellCreatesAndPreservesChineseSpacePathAndTreatsNullStartAsFailure'
    $appFilter += '|Category=CommandIconsSource|Category=CommandIconsLicenseBytes|Category=CommandIconsNegative'
    $appFilter += '|FullyQualifiedName=CodeSigner.App.Tests.WorkerHealthRepairOrchestrationTests.SuccessfulMsiRepairWithFailedProbeKeepsRecoveryAvailableAndNeverAutoSigns'
    $appFilter += '|FullyQualifiedName=CodeSigner.App.Tests.WorkerHealthRepairOrchestrationTests.FailedMsiRepairDoesNotProbeOrSign'
    $appFilter += '|FullyQualifiedName=CodeSigner.App.Tests.WorkerHealthRepairOrchestrationTests.UacCancellationKeepsTheOriginalUnhealthyDiagnosticWithoutProbing'
    $appFilter += '|FullyQualifiedName=CodeSigner.App.Tests.WorkerHealthRepairOrchestrationTests.DisposalWaitsForActiveRepairWithoutCancellingIt'
    Invoke-Checked dotnet @('test', 'tests/CodeSigner.App.Tests/CodeSigner.App.Tests.csproj',
        '-c', 'Release', '--no-restore', '--filter', $appFilter,
        '--logger', 'trx;LogFileName=app.trx', '--results-directory', 'artifacts/public-source-tests')
    Assert-TestResults app
    $windowsClasses = @('SimplySignInstallationProbeTests', 'SimplySignExeInstallationProbeTests',
        'CodeSignerInstallationProbeTests', 'WindowsInstallerProductSourceTests', 'CertificateCatalogProbeTests')
    $windowsFilter = ($windowsClasses | ForEach-Object { "FullyQualifiedName~CodeSigner.Windows.Tests.$_" }) -join '|'
    Invoke-Checked dotnet @('test', 'tests/CodeSigner.Windows.Tests/CodeSigner.Windows.Tests.csproj',
        '-c', 'Release', '--no-restore', '--filter', $windowsFilter,
        '--logger', 'trx;LogFileName=windows.trx', '--results-directory', 'artifacts/public-source-tests')
    Assert-TestResults windows
    Invoke-Checked dotnet @('test', 'tests/CodeSigner.IntegrationTests/CodeSigner.IntegrationTests.csproj',
        '-c', 'Release', '--no-restore', '--filter', 'FullyQualifiedName~ProductionDependencyBoundaryTests',
        '--logger', 'trx;LogFileName=dependencies.trx', '--results-directory', 'artifacts/public-source-tests')
    Assert-TestResults dependencies
} finally {
    Pop-Location
}
