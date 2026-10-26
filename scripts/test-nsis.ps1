[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
[xml]$props = Get-Content (Join-Path $root 'Directory.Build.props') -Raw
$version = [string]$props.Project.PropertyGroup[0].CodeSignerProductVersion
$installer = Join-Path $root "artifacts/nsis-build/$version/INSTALLER-QA-ONLY-$version.exe"
$payload = Join-Path $root "artifacts/nsis-payload/$version"
$qa = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'AnxinCodeSigner-InstallerQA'
$key = 'HKCU:\Software\AnxinCodeSigner-InstallerQA\Uninstall'
if ((Test-Path -LiteralPath $qa) -or (Test-Path -LiteralPath $key)) {
    throw 'QA location already exists. Inspect it before running; this script never deletes an existing directory.'
}
$checks = [Collections.Generic.List[string]]::new()
function Run-Installer([string]$File, [string[]]$Arguments, [int]$Expected) {
    $process = Start-Process -FilePath $File -ArgumentList $Arguments -WindowStyle Hidden -PassThru
    if (!$process.WaitForExit(90000)) { throw 'Installer exceeded test timeout; inspect the test process.' }
    if ($process.ExitCode -ne $Expected) { throw "Expected $Expected, got $($process.ExitCode)" }
}
function Assert-Payload {
    foreach ($file in @('CodeSigner.App.exe','CodeSigner.Worker.exe','LICENSE','NOTICE','THIRD-PARTY-NOTICES.txt','source-manifest.json')) {
        $expected=(Get-FileHash -LiteralPath (Join-Path $payload $file)).Hash
        $actual=(Get-FileHash -LiteralPath (Join-Path $qa $file)).Hash
        if ($actual -ne $expected) { throw "Payload mismatch: $file" }
    }
}
New-Item -Path $key -Force | Out-Null
New-ItemProperty -LiteralPath $key -Name LegacyMsiStatus -Value 0 -PropertyType DWord | Out-Null
Run-Installer $installer @('/S') 20
if (Test-Path -LiteralPath $qa) { throw 'Legacy preflight unexpectedly wrote installation files.' }
$checks.Add('legacy-msi-blocks-install-without-removing-old-product')
Set-ItemProperty -LiteralPath $key -Name LegacyMsiStatus -Value 5
Run-Installer $installer @('/S') 30
$checks.Add('unknown-legacy-state-fails-closed')
Remove-ItemProperty -LiteralPath $key -Name LegacyMsiStatus
Run-Installer $installer @('/S') 0
Assert-Payload
$registration = Get-ItemProperty -LiteralPath $key
if ($registration.DisplayVersion -ne $version -or $registration.DisplayName -ne '安信代码签名证书工具') {
    throw 'Incorrect registration identity'
}
$checks.Add('fresh-install-and-payload-hashes')
Run-Installer $installer @('/S') 0
Assert-Payload
$checks.Add('same-version-reinstall')
$worker = Join-Path $qa 'CodeSigner.Worker.exe'
Remove-Item -LiteralPath $worker
Run-Installer (Join-Path $qa 'Maintenance/Setup.exe') @('/S','/REPAIR') 0
Assert-Payload
$checks.Add('cached-installer-restores-missing-worker')
$locked = [IO.File]::Open((Join-Path $qa 'CodeSigner.App.exe'), 'Open','Read','None')
try { Run-Installer $installer @('/S') 10 } finally { $locked.Dispose() }
Assert-Payload
$checks.Add('locked-file-aborts-without-overwriting-payload')
Set-ItemProperty -LiteralPath $key -Name DisplayVersion -Value '99.0.0'
try { Run-Installer $installer @('/S') 30 }
finally { Set-ItemProperty -LiteralPath $key -Name DisplayVersion -Value $version }
Assert-Payload
$checks.Add('downgrade-rejected')
$sentinel = Join-Path $qa 'user-file-must-survive.txt'
[IO.File]::WriteAllText($sentinel,'user data sentinel')
Run-Installer (Join-Path $qa 'Uninstall.exe') @('/S') 0
$deadline = [DateTime]::UtcNow.AddSeconds(30)
while ((Test-Path -LiteralPath $key) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 250 }
if (Test-Path -LiteralPath $key) { throw 'Uninstall registration was not removed.' }
foreach ($file in @('CodeSigner.App.exe','CodeSigner.Worker.exe','LICENSE','NOTICE','THIRD-PARTY-NOTICES.txt','source-manifest.json','Maintenance/Setup.exe','Uninstall.exe')) {
    if (Test-Path -LiteralPath (Join-Path $qa $file)) { throw "Uninstall residue: $file" }
}
if ([IO.File]::ReadAllText($sentinel) -ne 'user data sentinel') { throw 'User data was not preserved.' }
$checks.Add('uninstall-preserves-unrelated-user-file')
Run-Installer $installer @('/S','/REPAIR') 30
$checks.Add('repair-requires-existing-matching-registration')
# Delete only this test's exact sentinel and empty directories; never recursively remove a path.
Remove-Item -LiteralPath $sentinel
[IO.Directory]::Delete($qa, $false)
if (Test-Path -LiteralPath 'HKCU:\Software\AnxinCodeSigner-InstallerQA') {
    Remove-Item -LiteralPath 'HKCU:\Software\AnxinCodeSigner-InstallerQA'
}
$result = [ordered]@{
    success=$true; version=$version; scope='Isolated per-user QA build; no production installation, signing or certificate access'
    installerSha256=(Get-FileHash -LiteralPath $installer).Hash; checks=@($checks)
}
$evidence = Join-Path $root 'artifacts/tests'
New-Item -ItemType Directory -Path $evidence -Force | Out-Null
$result | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $evidence 'nsis-lifecycle.json') -Encoding utf8NoBOM
$result | ConvertTo-Json -Depth 5
