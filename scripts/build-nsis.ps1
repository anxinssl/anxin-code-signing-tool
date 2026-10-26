[CmdletBinding()]
param(
    [string]$MakeNsis = (Join-Path $PSScriptRoot '../.local/nsis/nsis-bundle/windows/makensis.exe'),
    [switch]$TestPackage,
    [switch]$SkipPublish
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Push-Location $root
try {
    function Checked([string]$Program, [string[]]$Arguments) {
        & $Program @Arguments
        if ($LASTEXITCODE -ne 0) { throw "$Program failed: $LASTEXITCODE" }
    }
    [xml]$props = Get-Content Directory.Build.props -Raw
    $version = [string]$props.Project.PropertyGroup[0].CodeSignerProductVersion
    $compiler = (Resolve-Path -LiteralPath $MakeNsis).Path
    $env:NSISDIR = Split-Path $compiler -Parent
    $payload = Join-Path $root "artifacts/nsis-payload/$version"
    $out = Join-Path $root "artifacts/nsis-build/$version"
    New-Item -ItemType Directory -Path $payload,$out -Force | Out-Null
    Checked node @('scripts/build-third-party-notices.mjs', '--check')
    Checked node @('tools/release/verify-release-version.mjs', '--check')
    Checked node @('scripts/check-public-source.mjs')
    Checked node @('scripts/verify-source-snapshot.mjs')
    $identity = (& node tools/release/verify-release-version.mjs --check | ConvertFrom-Json)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read release identity.' }
    $publishReceipt = Join-Path $out 'published-payloads.json'
    if (!$SkipPublish) {
        foreach ($project in @('App', 'Worker')) {
            $publish = Join-Path $root ".build/nsis-publish/$project"
            Checked dotnet @('publish', "src/CodeSigner.$project/CodeSigner.$project.csproj",
                '-c','Release','-r','win-x64','--self-contained','true',
                '--artifacts-path', ".build/installer-artifacts/$version",
                '-p:CodeSignerInstallerPublish=true','-p:PublishSingleFile=true',
                '-p:IncludeNativeLibrariesForSelfExtract=true','-p:RestoreLockedMode=true',
                '-o', $publish)
            Copy-Item -LiteralPath (Join-Path $publish "CodeSigner.$project.exe") -Destination $payload
        }
        [ordered]@{
            sourceFingerprint=$identity.sourceFingerprint
            appSha256=(Get-FileHash -LiteralPath (Join-Path $payload 'CodeSigner.App.exe')).Hash
            workerSha256=(Get-FileHash -LiteralPath (Join-Path $payload 'CodeSigner.Worker.exe')).Hash
        } | ConvertTo-Json | Set-Content -LiteralPath $publishReceipt -Encoding utf8NoBOM
    } else {
        $published = Get-Content -LiteralPath $publishReceipt -Raw | ConvertFrom-Json
        if ($published.sourceFingerprint -ne $identity.sourceFingerprint -or
            $published.appSha256 -ne (Get-FileHash -LiteralPath (Join-Path $payload 'CodeSigner.App.exe')).Hash -or
            $published.workerSha256 -ne (Get-FileHash -LiteralPath (Join-Path $payload 'CodeSigner.Worker.exe')).Hash) {
            throw 'Published payloads are stale or changed; rebuild without -SkipPublish.'
        }
    }
    Checked node @('tools/release/verify-self-contained-bundle.mjs',
        '--app', (Join-Path $payload 'CodeSigner.App.exe'),
        '--worker', (Join-Path $payload 'CodeSigner.Worker.exe'))
    foreach ($file in @('LICENSE','NOTICE','THIRD-PARTY-NOTICES.txt')) {
        Copy-Item -LiteralPath $file -Destination $payload
    }
    if (!(Test-Path -LiteralPath (Join-Path $payload 'source-manifest.json'))) {
        throw 'Run node scripts/source-snapshot.mjs before building the installer.'
    }
    $name = "Anxin-Code-Signing-Certificate-Tool-$version-win-x64-Setup.exe"
    $arguments = @('/V3','/WX','/INPUTCHARSET','UTF8',"/DVERSION=$version","/DPAYLOAD=$payload")
    if ($TestPackage) {
        $name = "INSTALLER-QA-ONLY-$version.exe"
        $arguments += '/DAUTOMATED_TEST'
    }
    $arguments += @("/DOUTPUT=$(Join-Path $out $name)", 'packaging/nsis/installer.nsi')
    Checked $compiler $arguments
    Checked node @('scripts/verify-source-snapshot.mjs')
    Checked node @('tools/release/verify-release-version.mjs', '--check')
    Get-FileHash -LiteralPath (Join-Path $out $name) -Algorithm SHA256
} finally {
    Pop-Location
}
