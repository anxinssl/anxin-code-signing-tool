$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$metadata = Get-Content (Join-Path $root 'release/metadata/nsis-toolchain.json') -Raw | ConvertFrom-Json
$cache = Join-Path $root '.local/nsis-download'
$target = Join-Path $root '.local/nsis'
New-Item -ItemType Directory -Path $cache,$target -Force | Out-Null
$archive = Join-Path $cache $metadata.archive
if (!(Test-Path -LiteralPath $archive)) {
    Invoke-WebRequest -Uri $metadata.url -OutFile $archive -TimeoutSec 180
}
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $metadata.sha256) {
    throw 'NSIS archive checksum mismatch. No compiler was executed.'
}
$entries = & tar -tf $archive
if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect NSIS archive.' }
foreach ($entry in $entries) {
    if ($entry -match '(^/|(^|/)\.\.(/|$)|^[A-Za-z]:)') { throw 'Unsafe archive path.' }
}
& tar -xf $archive -C $target
if ($LASTEXITCODE -ne 0) { throw 'Cannot extract NSIS archive.' }
$env:NSISDIR = Join-Path $target 'nsis-bundle/windows'
& (Join-Path $env:NSISDIR 'makensis.exe') /VERSION
if ($LASTEXITCODE -ne 0) { throw 'NSIS compiler is unavailable.' }
