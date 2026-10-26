[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$MsiPath,

    [string]$EvidencePath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-MsiTable {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Database,

        [Parameter(Mandatory = $true)]
        [string]$Table,

        [Parameter(Mandatory = $true)]
        [string[]]$Columns
    )

    $query = "SELECT * FROM ``$Table``"
    $view = $Database.GetType().InvokeMember(
        'OpenView',
        [System.Reflection.BindingFlags]::InvokeMethod,
        $null,
        $Database,
        @($query))
    try {
        $null = $view.GetType().InvokeMember(
            'Execute',
            [System.Reflection.BindingFlags]::InvokeMethod,
            $null,
            $view,
            $null)
        $rows = [System.Collections.Generic.List[object]]::new()
        while ($true) {
            $record = $view.GetType().InvokeMember(
                'Fetch',
                [System.Reflection.BindingFlags]::InvokeMethod,
                $null,
                $view,
                $null)
            if ($null -eq $record) {
                break
            }

            try {
                $row = [ordered]@{}
                for ($index = 0; $index -lt $Columns.Count; $index++) {
                    $row[$Columns[$index]] = [string]$record.GetType().InvokeMember(
                        'StringData',
                        [System.Reflection.BindingFlags]::GetProperty,
                        $null,
                        $record,
                        @($index + 1))
                }
                $rows.Add([pscustomobject]$row) | Out-Null
            }
            finally {
                [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($record) | Out-Null
            }
        }

        return ,$rows.ToArray()
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($view) | Out-Null
    }
}

function Add-Failure {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$Failures,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $Failures.Add($Message) | Out-Null
}

function Get-LongFileName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName
    )

    $separator = $FileName.IndexOf('|')
    if ($separator -lt 0) {
        return $FileName
    }
    return $FileName.Substring($separator + 1)
}

$resolvedMsiPath = [System.IO.Path]::GetFullPath($MsiPath)
if (-not (Test-Path -LiteralPath $resolvedMsiPath -PathType Leaf)) {
    throw "MSI path is missing: $resolvedMsiPath"
}

if ([string]::IsNullOrWhiteSpace($EvidencePath)) {
    $EvidencePath = $resolvedMsiPath + '.worker-feature-verification.json'
}
$resolvedEvidencePath = [System.IO.Path]::GetFullPath($EvidencePath)
$evidenceDirectory = [System.IO.Path]::GetDirectoryName($resolvedEvidencePath)
if (-not [string]::IsNullOrWhiteSpace($evidenceDirectory)) {
    $null = New-Item -ItemType Directory -Path $evidenceDirectory -Force
}

$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $null
$failures = [System.Collections.Generic.List[string]]::new()
$tables = $null
try {
    $database = $installer.GetType().InvokeMember(
        'OpenDatabase',
        [System.Reflection.BindingFlags]::InvokeMethod,
        $null,
        $installer,
        @($resolvedMsiPath, 0))

    $tables = [ordered]@{
        Feature = Read-MsiTable -Database $database -Table 'Feature' -Columns @('Feature', 'Feature_Parent', 'Title', 'Description', 'Display', 'Level', 'Directory_', 'Attributes')
        FeatureComponents = Read-MsiTable -Database $database -Table 'FeatureComponents' -Columns @('Feature', 'Component')
        Component = Read-MsiTable -Database $database -Table 'Component' -Columns @('Component', 'ComponentId', 'Directory_', 'Attributes', 'Condition', 'KeyPath')
        File = Read-MsiTable -Database $database -Table 'File' -Columns @('File', 'Component_', 'FileName', 'FileSize', 'Version', 'Language', 'Attributes', 'Sequence')
        Property = Read-MsiTable -Database $database -Table 'Property' -Columns @('Property', 'Value')
        InstallExecuteSequence = Read-MsiTable -Database $database -Table 'InstallExecuteSequence' -Columns @('Action', 'Condition', 'Sequence')
    }

    $workerFeatureRows = @($tables.Feature | Where-Object { $_.Feature -ceq 'WorkerFeature' })
    if ($workerFeatureRows.Count -ne 1) {
        Add-Failure -Failures $failures -Message "Expected exactly one case-sensitive WorkerFeature row; observed $($workerFeatureRows.Count)."
    }
    else {
        $workerFeature = $workerFeatureRows[0]
        if ($workerFeature.Level -cne '1') {
            Add-Failure -Failures $failures -Message "WorkerFeature Level must be 1; observed '$($workerFeature.Level)'."
        }
        if (-not [string]::IsNullOrEmpty($workerFeature.Feature_Parent)) {
            Add-Failure -Failures $failures -Message "WorkerFeature must be a root/default feature; observed parent '$($workerFeature.Feature_Parent)'."
        }
    }

    $mainFeatureRows = @($tables.Feature | Where-Object { $_.Feature -ceq 'MainFeature' })
    if ($mainFeatureRows.Count -ne 1) {
        Add-Failure -Failures $failures -Message "Expected exactly one case-sensitive MainFeature row; observed $($mainFeatureRows.Count)."
    }
    elseif ($mainFeatureRows[0].Level -cne '1') {
        Add-Failure -Failures $failures -Message "MainFeature Level must remain 1; observed '$($mainFeatureRows[0].Level)'."
    }

    $workerFeatureComponents = @($tables.FeatureComponents | Where-Object { $_.Feature -ceq 'WorkerFeature' })
    if ($workerFeatureComponents.Count -ne 1 -or $workerFeatureComponents[0].Component -cne 'WorkerComponent') {
        Add-Failure -Failures $failures -Message 'WorkerFeature must contain exactly WorkerComponent in the case-sensitive FeatureComponents table.'
    }

    $mainFeatureComponents = @($tables.FeatureComponents | Where-Object { $_.Feature -ceq 'MainFeature' })
    $expectedMainComponents = @('AppComponent', 'NoticesComponent', 'ShortcutComponent', 'DesktopShortcutComponent')
    if ($mainFeatureComponents.Count -ne $expectedMainComponents.Count) {
        Add-Failure -Failures $failures -Message "MainFeature must contain exactly AppComponent, NoticesComponent and shortcut components; observed $($mainFeatureComponents.Count) rows."
    }
    foreach ($expectedComponent in $expectedMainComponents) {
        $matches = @($mainFeatureComponents | Where-Object { $_.Component -ceq $expectedComponent })
        if ($matches.Count -ne 1) {
            Add-Failure -Failures $failures -Message "MainFeature must contain exactly one $expectedComponent row; observed $($matches.Count)."
        }
    }
    $workerInMain = @($mainFeatureComponents | Where-Object { $_.Component -ceq 'WorkerComponent' })
    if ($workerInMain.Count -ne 0) {
        Add-Failure -Failures $failures -Message 'WorkerComponent must be absent from MainFeature.'
    }

    $workerComponentRows = @($tables.Component | Where-Object { $_.Component -ceq 'WorkerComponent' })
    if ($workerComponentRows.Count -ne 1) {
        Add-Failure -Failures $failures -Message "Expected exactly one WorkerComponent row; observed $($workerComponentRows.Count)."
    }
    $workerFiles = @($tables.File | Where-Object { $_.Component_ -ceq 'WorkerComponent' })
    if ($workerFiles.Count -ne 1) {
        Add-Failure -Failures $failures -Message "WorkerComponent must key exactly one File row; observed $($workerFiles.Count)."
    }
    elseif ((Get-LongFileName -FileName $workerFiles[0].FileName) -cne 'CodeSigner.Worker.exe') {
        Add-Failure -Failures $failures -Message "WorkerComponent key file must be CodeSigner.Worker.exe; observed '$($workerFiles[0].FileName)'."
    }
    if ($workerComponentRows.Count -eq 1 -and $workerFiles.Count -eq 1 -and $workerComponentRows[0].KeyPath -cne $workerFiles[0].File) {
        Add-Failure -Failures $failures -Message "WorkerComponent KeyPath must reference its Worker file row; observed '$($workerComponentRows[0].KeyPath)' vs '$($workerFiles[0].File)'."
    }

    $appFiles = @($tables.File | Where-Object { $_.Component_ -ceq 'AppComponent' })
    if ($appFiles.Count -ne 1 -or (Get-LongFileName -FileName $appFiles[0].FileName) -cne 'CodeSigner.App.exe') {
        Add-Failure -Failures $failures -Message 'AppComponent must continue to key CodeSigner.App.exe.'
    }

    $properties = [ordered]@{}
    foreach ($propertyRow in $tables.Property) {
        $properties[$propertyRow.Property] = $propertyRow.Value
    }
    $expectedProperties = [ordered]@{
        ProductName = [string]::Concat([char]0x5B89, [char]0x4FE1, [char]0x8BC1, [char]0x4E66, [char]0x7B7E, [char]0x540D, [char]0x5DE5, [char]0x5177)
        Manufacturer = 'CodeSigner'
        UpgradeCode = '{C81BF087-67D0-41F3-8581-9E773813118B}'
        ARPNOREPAIR = '1'
        ARPNOMODIFY = '1'
    }
    foreach ($propertyName in $expectedProperties.Keys) {
        if (-not $properties.Contains($propertyName) -or $properties[$propertyName] -cne $expectedProperties[$propertyName]) {
            $observed = if ($properties.Contains($propertyName)) { [string]$properties[$propertyName] } else { '<missing>' }
            Add-Failure -Failures $failures -Message "Property $propertyName must be '$($expectedProperties[$propertyName])'; observed '$observed'."
        }
    }

    $removeExistingProducts = @($tables.InstallExecuteSequence | Where-Object { $_.Action -ceq 'RemoveExistingProducts' })
    if ($removeExistingProducts.Count -ne 1 -or $removeExistingProducts[0].Sequence -cne '1501') {
        $observedSequence = if ($removeExistingProducts.Count -eq 1) { [string]$removeExistingProducts[0].Sequence } else { '<missing-or-duplicate>' }
        Add-Failure -Failures $failures -Message "RemoveExistingProducts must remain sequence 1501; observed '$observedSequence'."
    }

    $success = $failures.Count -eq 0
    $receipt = [ordered]@{
        schema = 'codesigner-worker-feature-verification-v1'
        capturedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        msiPath = $resolvedMsiPath
        msiSha256 = (Get-FileHash -LiteralPath $resolvedMsiPath -Algorithm SHA256).Hash
        success = $success
        failures = @($failures)
        observed = [ordered]@{
            feature = @($tables.Feature)
            featureComponents = @($tables.FeatureComponents)
            component = @($tables.Component)
            file = @($tables.File)
            property = @($tables.Property)
            installExecuteSequence = @($tables.InstallExecuteSequence | Where-Object { $_.Action -ceq 'RemoveExistingProducts' })
        }
    }
    $receiptJson = $receipt | ConvertTo-Json -Depth 12
    Write-Host 'Worker feature verification preview before WriteAllText:'
    Write-Host $receiptJson
    [System.IO.File]::WriteAllText(
        $resolvedEvidencePath,
        $receiptJson + [Environment]::NewLine,
        [System.Text.UTF8Encoding]::new($false))
    Write-Output $resolvedEvidencePath
    if (-not $success) {
        throw ('Worker feature MSI verification failed: ' + [string]::Join('; ', $failures))
    }
}
finally {
    if ($null -ne $database) {
        [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($database) | Out-Null
    }
    [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer) | Out-Null
}
