[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Installer,
    [string]$SevenZip = (Join-Path $PSScriptRoot '../.local/7zip-full/7z.exe')
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
[xml]$props = Get-Content (Join-Path $root 'Directory.Build.props') -Raw
$version = [string]$props.Project.PropertyGroup[0].CodeSignerProductVersion
$installerPath = (Resolve-Path -LiteralPath $Installer).Path
$payload = Join-Path $root "artifacts/nsis-payload/$version"
$scratch = Join-Path $root ("artifacts/extracted/" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch -Force | Out-Null
& $SevenZip x $installerPath "-o$scratch" -y
if ($LASTEXITCODE -ne 0) { throw 'NSIS extraction failed.' }
$extracted = Join-Path $scratch '$PLUGINSDIR/payload'
$expected = @('CodeSigner.App.exe','CodeSigner.Worker.exe','LICENSE','NOTICE','THIRD-PARTY-NOTICES.txt','source-manifest.json')
$actual = @(Get-ChildItem -LiteralPath $extracted -File | Select-Object -ExpandProperty Name)
if (@(Compare-Object ($expected | Sort-Object) ($actual | Sort-Object)).Count -ne 0) {
    throw 'Installer payload inventory mismatch.'
}
$hashes = [ordered]@{}
foreach ($file in $expected) {
    $staged = (Get-FileHash -LiteralPath (Join-Path $payload $file)).Hash
    $packaged = (Get-FileHash -LiteralPath (Join-Path $extracted $file)).Hash
    if ($staged -ne $packaged) { throw "Packaged bytes differ: $file" }
    $hashes[$file] = $packaged
}
$manifest = Get-Content (Join-Path $extracted 'source-manifest.json') -Raw | ConvertFrom-Json
$source = Join-Path $root "artifacts/source/$version/$($manifest.sourceArchive)"
if ((Get-FileHash -LiteralPath $source).Hash.ToLowerInvariant() -ne $manifest.sourceArchiveSha256) {
    throw 'Installer does not match the corresponding source archive.'
}
foreach ($file in @('CodeSigner.App.exe','CodeSigner.Worker.exe')) {
    $info = (Get-Item -LiteralPath (Join-Path $extracted $file)).VersionInfo
    if ($info.FileVersion -ne "$version.0") { throw "Incorrect embedded version: $file" }
}
$allowed = @(
    '$PLUGINSDIR/modern-wizard.bmp',
    '$PLUGINSDIR/nsDialogs.dll',
    '$PLUGINSDIR/System.dll',
    'Uninstall.exe'
) + @($expected | ForEach-Object { '$PLUGINSDIR/payload/' + $_ })
$all = @(Get-ChildItem -LiteralPath $scratch -File -Recurse | ForEach-Object {
    [IO.Path]::GetRelativePath($scratch, $_.FullName).Replace('\','/')
})
if (@(Compare-Object ($allowed | Sort-Object) ($all | Sort-Object)).Count -ne 0) {
    throw 'Unexpected installer runtime component or additional payload.'
}
$receipt = [ordered]@{
    success=$true; version=$version
    installerSha256=(Get-FileHash -LiteralPath $installerPath).Hash
    sourceArchiveSha256=$manifest.sourceArchiveSha256; sourceTree=$manifest.sourceTree
    payloadHashes=$hashes; extractedDirectory=$scratch
    scope='Static extraction only; no production installation or signing'
}
New-Item -ItemType Directory (Join-Path $root 'artifacts/tests') -Force | Out-Null
$receipt | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $root 'artifacts/tests/nsis-package.json') -Encoding utf8NoBOM
$receipt | ConvertTo-Json -Depth 6
