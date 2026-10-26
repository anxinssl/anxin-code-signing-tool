namespace CodeSigner.Windows.Signing;

internal static class WindowsPowerShellSipCommand
{
    internal const string Probe = "if ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1) { exit 0 }; exit 51";

    internal const string SignAndVerify = """
        Set-StrictMode -Version 2.0
        $ErrorActionPreference = 'Stop'
        $utf8 = New-Object Text.UTF8Encoding($false)
        [Console]::InputEncoding = $utf8
        [Console]::OutputEncoding = $utf8

        if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { exit 51 }

        function Write-BridgeResponse {
            param(
                [string]$ResultCode,
                [int]$HResult,
                [AllowNull()][string]$SignatureStatus,
                [AllowNull()][string]$FileDigest,
                [AllowNull()][string]$SignerThumbprint,
                [AllowNull()][string]$TimestampProtocol,
                [AllowNull()][string]$TimestampDigest,
                [bool]$CmsVerified,
                [bool]$SubjectVerified,
                [bool]$ContentVerified,
                [AllowNull()][string]$ExistingSignatureDisposition
            )

            $response = [ordered]@{
                schemaVersion = 1
                resultCode = $ResultCode
                hresult = $HResult
                signatureStatus = $SignatureStatus
                fileDigest = $FileDigest
                signerThumbprint = $SignerThumbprint
                timestampProtocol = $TimestampProtocol
                timestampDigest = $TimestampDigest
                cmsVerified = $CmsVerified
                subjectVerified = $SubjectVerified
                contentVerified = $ContentVerified
                existingSignatureDisposition = $ExistingSignatureDisposition
            }
            $json = $response | ConvertTo-Json -Compress -Depth 3
            [Console]::Out.Write($json)
        }

        function Test-ByteArrayEqual {
            param([byte[]]$Left, [byte[]]$Right)
            if ($Left.Length -ne $Right.Length) { return $false }
            for ($index = 0; $index -lt $Left.Length; $index++) {
                if ($Left[$index] -ne $Right[$index]) { return $false }
            }
            return $true
        }

        function Test-BytePrefix {
            param([byte[]]$Prefix, [byte[]]$Value)
            if ($Value.Length -lt $Prefix.Length) { return $false }
            for ($index = 0; $index -lt $Prefix.Length; $index++) {
                if ($Prefix[$index] -ne $Value[$index]) { return $false }
            }
            return $true
        }

        function Test-PackageCompatibility {
            param([string]$Path, [string]$Extension, [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
            Add-Type -AssemblyName System.IO.Compression
            $maximumManifestBytes = 4194304
            $maximumBlockMapBytes = 67108864
            $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
            $archive = $null
            try {
                $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Read, $false)
                $manifestPath = 'AppxManifest.xml'
                if ($Extension -eq '.appxbundle' -or $Extension -eq '.msixbundle') { $manifestPath = 'AppxMetadata/AppxBundleManifest.xml' }
                $manifestEntry = $archive.GetEntry($manifestPath)
                $blockMapEntry = $archive.GetEntry('AppxBlockMap.xml')
                if ($null -eq $manifestEntry -or $null -eq $blockMapEntry) { return 'packageIncompatible' }
                if ($manifestEntry.Length -gt $maximumManifestBytes -or $blockMapEntry.Length -gt $maximumBlockMapBytes) { return 'packageIncompatible' }

                $xmlSettings = New-Object Xml.XmlReaderSettings
                $xmlSettings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
                $xmlSettings.XmlResolver = $null
                $publisherValue = $null
                $manifestStream = $manifestEntry.Open()
                try {
                    $manifestReader = [Xml.XmlReader]::Create($manifestStream, $xmlSettings)
                    try {
                        while ($manifestReader.Read()) {
                            if ($manifestReader.NodeType -eq [Xml.XmlNodeType]::Element -and $manifestReader.LocalName -eq 'Identity') {
                                $publisherValue = $manifestReader.GetAttribute('Publisher')
                                break
                            }
                        }
                    }
                    finally { $manifestReader.Dispose() }
                }
                finally { $manifestStream.Dispose() }

                if ([String]::IsNullOrWhiteSpace($publisherValue)) { return 'packageIncompatible' }
                $publisher = [Security.Cryptography.X509Certificates.X500DistinguishedName]::new($publisherValue)
                if (!(Test-ByteArrayEqual $publisher.RawData $Certificate.SubjectName.RawData)) { return 'certificateMismatch' }

                $hashMethodValid = $false
                $blockCount = 0
                $blockMapStream = $blockMapEntry.Open()
                try {
                    $blockMapReader = [Xml.XmlReader]::Create($blockMapStream, $xmlSettings)
                    try {
                        while ($blockMapReader.Read()) {
                            if ($blockMapReader.NodeType -ne [Xml.XmlNodeType]::Element) { continue }
                            if ($blockMapReader.LocalName -eq 'BlockMap') {
                                $hashMethodValid = $blockMapReader.GetAttribute('HashMethod') -eq 'http://www.w3.org/2001/04/xmlenc#sha256'
                            }
                            elseif ($blockMapReader.LocalName -eq 'Block') {
                                $blockCount++
                                $hashValue = $blockMapReader.GetAttribute('Hash')
                                if ([String]::IsNullOrWhiteSpace($hashValue)) { return 'packageIncompatible' }
                                try { $decoded = [Convert]::FromBase64String($hashValue) }
                                catch { return 'packageIncompatible' }
                                if ($decoded.Length -ne 32) { return 'packageIncompatible' }
                            }
                        }
                    }
                    finally { $blockMapReader.Dispose() }
                }
                finally { $blockMapStream.Dispose() }

                if (!$hashMethodValid -or $blockCount -eq 0) { return 'packageIncompatible' }
                return 'compatible'
            }
            finally {
                if ($null -ne $archive) { $archive.Dispose() }
                $stream.Dispose()
            }
        }

        $requestValidated = $false
        try {
            $maximumRequestBytes = 32768
            $requestBuilder = [Text.StringBuilder]::new()
            $requestBuffer = New-Object char[] 4096
            while (($requestRead = [Console]::In.Read($requestBuffer, 0, $requestBuffer.Length)) -gt 0) {
                [void]$requestBuilder.Append($requestBuffer, 0, $requestRead)
                if ($requestBuilder.Length -gt $maximumRequestBytes) { throw [FormatException]::new('Request exceeds size bound.') }
            }
            $requestJson = $requestBuilder.ToString()
            if ([Text.Encoding]::UTF8.GetByteCount($requestJson) -gt $maximumRequestBytes) { throw [FormatException]::new('Request exceeds size bound.') }
            $requestJson = $requestJson.Replace("`r`n", "`n").Replace("`r", "`n")
            if ([String]::IsNullOrWhiteSpace($requestJson)) { throw [FormatException]::new('Request is empty.') }

            $jsonDepth = 0
            $maximumJsonDepth = 0
            $insideJsonString = $false
            $jsonEscape = $false
            foreach ($jsonCharacter in $requestJson.ToCharArray()) {
                if ($insideJsonString) {
                    if ($jsonEscape) { $jsonEscape = $false }
                    elseif ($jsonCharacter -eq '\') { $jsonEscape = $true }
                    elseif ($jsonCharacter -eq '"') { $insideJsonString = $false }
                }
                elseif ($jsonCharacter -eq '"') { $insideJsonString = $true }
                elseif ($jsonCharacter -eq '{' -or $jsonCharacter -eq '[') {
                    $jsonDepth++
                    if ($jsonDepth -gt $maximumJsonDepth) { $maximumJsonDepth = $jsonDepth }
                    if ($maximumJsonDepth -gt 4) { throw [FormatException]::new('Request exceeds depth bound.') }
                }
                elseif ($jsonCharacter -eq '}' -or $jsonCharacter -eq ']') {
                    $jsonDepth--
                    if ($jsonDepth -lt 0) { throw [FormatException]::new('Invalid request JSON.') }
                }
            }
            if ($insideJsonString -or $jsonEscape -or $jsonDepth -ne 0) { throw [FormatException]::new('Invalid request JSON.') }

            try { $request = $requestJson | ConvertFrom-Json -ErrorAction Stop }
            catch { throw [FormatException]::new('Invalid request JSON.', $_.Exception) }
            $expectedProperties = @(
                'schemaVersion', 'operation', 'stagedPath', 'formatFamily', 'extension', 'subjectGuid',
                'certificateStoreLocation', 'certificateStoreName', 'certificateThumbprint',
                'fileDigest', 'appendSignature', 'timestampProtocol', 'timestampDigest', 'timestampUri',
                'existingValid', 'existingInvalid', 'existingUntrusted', 'existingExpired',
                'existingPartial', 'existingMalformed', 'scriptEncoding', 'scriptNewlines', 'scriptIsEncoded'
            )
            $requestProperties = @($request.PSObject.Properties)
            if ($requestProperties.Count -ne $expectedProperties.Count) { throw [FormatException]::new('Invalid request schema.') }
            foreach ($property in $requestProperties) {
                if (!$expectedProperties.Contains($property.Name)) { throw [FormatException]::new('Invalid request schema.') }
            }
            foreach ($propertyName in $expectedProperties) {
                if ($null -eq $request.PSObject.Properties[$propertyName]) { throw [FormatException]::new('Invalid request schema.') }
                $propertyPattern = [Regex]::Escape('"' + $propertyName + '"') + '\s*:'
                if ([Regex]::Matches($requestJson, $propertyPattern).Count -ne 1) { throw [FormatException]::new('Invalid request schema.') }
            }

            if ($request.schemaVersion -ne 1 -or $request.operation -ne 'signAndVerify') { throw [FormatException]::new('Invalid request version.') }
            if ($request.certificateStoreLocation -ne 'CurrentUser' -or $request.certificateStoreName -ne 'My') { throw [FormatException]::new('Invalid certificate store.') }
            if ($request.certificateThumbprint -notmatch '^[0-9A-F]{40}$') { throw [FormatException]::new('Invalid certificate thumbprint.') }
            if ($request.fileDigest -ne 'sha256' -or $request.appendSignature -ne $false) { throw [FormatException]::new('Invalid signature leg.') }
            if ($request.timestampProtocol -ne 'rfc3161' -or $request.timestampDigest -ne 'sha256') { throw [FormatException]::new('Invalid timestamp policy.') }
            if ($request.existingValid -ne 'skip' -or $request.existingInvalid -ne 'fail' -or $request.existingUntrusted -ne 'fail' -or $request.existingExpired -ne 'fail' -or $request.existingPartial -ne 'fail' -or $request.existingMalformed -ne 'fail') { throw [FormatException]::new('Invalid existing signature policy.') }
            $allowedFamilies = @('windowsInstaller', 'cabinet', 'catalog', 'appPackage', 'powerShellScript', 'windowsScript')
            if (!$allowedFamilies.Contains($request.formatFamily)) { throw [FormatException]::new('Invalid format family.') }
            $subjectGuid = [Guid]::Empty
            if (![Guid]::TryParse($request.subjectGuid, [ref]$subjectGuid) -or $subjectGuid -eq [Guid]::Empty) { throw [FormatException]::new('Invalid SIP subject identifier.') }
            if ($request.stagedPath -isnot [string] -or ![IO.Path]::IsPathRooted($request.stagedPath)) { throw [FormatException]::new('Invalid staged path.') }
            $stagedPath = [IO.Path]::GetFullPath($request.stagedPath)
            if (![String]::Equals($stagedPath, $request.stagedPath, [StringComparison]::OrdinalIgnoreCase) -or ![IO.File]::Exists($stagedPath)) { throw [FormatException]::new('Invalid staged path.') }
            if (![String]::Equals([IO.Path]::GetExtension($stagedPath), $request.extension, [StringComparison]::OrdinalIgnoreCase)) { throw [FormatException]::new('Invalid staged extension.') }
            $requestValidated = $true

            $beforeBytes = $null
            if ($request.formatFamily -eq 'powerShellScript' -or $request.formatFamily -eq 'windowsScript') {
                $beforeBytes = [IO.File]::ReadAllBytes($stagedPath)
            }
            $store = [Security.Cryptography.X509Certificates.X509Store]::new('My', [Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
            try {
                $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor [Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)
                $matches = $store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $request.certificateThumbprint, $false)
                if ($matches.Count -ne 1) {
                    Write-BridgeResponse 'certificateNotFound' -2147024809 $null $null $null $null $null $false $false $false $null
                    exit 1
                }
                $certificate = $matches[0]
                if (!$certificate.HasPrivateKey) {
                    Write-BridgeResponse 'certificateHasNoPrivateKey' -2146893811 $null $null $null $null $null $false $false $false $null
                    exit 1
                }

                if ($request.formatFamily -eq 'appPackage') {
                    $compatibility = Test-PackageCompatibility $stagedPath $request.extension $certificate
                    if ($compatibility -ne 'compatible') {
                        Write-BridgeResponse $compatibility -2147024809 $null $null $null $null $null $false $false $false $null
                        exit 1
                    }
                }

                $existing = Get-AuthenticodeSignature -LiteralPath $stagedPath
                $existingStatus = $existing.Status.ToString()
                if ($existingStatus -eq 'NotSupportedFileFormat') {
                    Write-BridgeResponse 'sipUnavailable' -2147467263 $existingStatus $null $null $null $null $false $false $false $null
                    exit 1
                }
                if ($existingStatus -eq 'Valid') {
                    Write-BridgeResponse 'existingSignatureValid' 0 $existingStatus $null $null $null $null $true $true $true 'skip'
                    exit 0
                }
                if ($existingStatus -ne 'NotSigned') {
                    Write-BridgeResponse 'existingSignatureRejected' -2146762485 $existingStatus $null $null $null $null $false $true $true 'fail'
                    exit 1
                }

                $signed = Set-AuthenticodeSignature -LiteralPath $stagedPath -Certificate $certificate -HashAlgorithm 'SHA256' -TimestampServer $request.timestampUri -ErrorAction Stop
                $verified = Get-AuthenticodeSignature -LiteralPath $stagedPath
                $verifiedStatus = $verified.Status.ToString()
                if ($verifiedStatus -eq 'NotSupportedFileFormat') {
                    Write-BridgeResponse 'sipUnavailable' -2147467263 $verifiedStatus $null $null $null $null $false $false $false $null
                    exit 1
                }
                if ($verifiedStatus -eq 'Incompatible' -and $request.formatFamily -eq 'appPackage') {
                    Write-BridgeResponse 'packageIncompatible' -2147024809 $verifiedStatus $null $null $null $null $false $false $false $null
                    exit 1
                }
                if ($verifiedStatus -ne 'Valid') {
                    Write-BridgeResponse 'verificationFailed' -2147467259 $verifiedStatus $null $null $null $null $false $false $false $null
                    exit 1
                }
                if ($null -eq $verified.SignerCertificate -or ![String]::Equals($verified.SignerCertificate.Thumbprint, $request.certificateThumbprint, [StringComparison]::OrdinalIgnoreCase)) {
                    Write-BridgeResponse 'certificateMismatch' -2146762486 $verifiedStatus $null $null $null $null $false $true $false $null
                    exit 1
                }
                if ($null -eq $verified.TimeStamperCertificate) {
                    Write-BridgeResponse 'timestampUnavailable' -2147467259 $verifiedStatus 'sha256' $verified.SignerCertificate.Thumbprint $null $null $false $true $false $null
                    exit 1
                }

                $contentVerified = $true
                if ($request.formatFamily -eq 'powerShellScript' -or $request.formatFamily -eq 'windowsScript') {
                    $afterBytes = [IO.File]::ReadAllBytes($stagedPath)
                    $contentVerified = Test-BytePrefix $beforeBytes $afterBytes
                }
                if (!$contentVerified) {
                    Write-BridgeResponse 'verificationFailed' -2147467259 $verifiedStatus 'sha256' $verified.SignerCertificate.Thumbprint 'rfc3161' 'sha256' $false $true $false $null
                    exit 1
                }

                Write-BridgeResponse 'signed' 0 $verifiedStatus 'sha256' $verified.SignerCertificate.Thumbprint 'rfc3161' 'sha256' $true $true $true 'signed'
                exit 0
            }
            finally {
                if ($null -ne $store) { $store.Dispose() }
            }
        }
        catch {
            $hresult = $_.Exception.HResult
            $resultCode = 'processFailed'
            if (!$requestValidated -or $_.Exception -is [FormatException]) { $resultCode = 'invalidInput' }
            elseif ($hresult -eq -2147023673) { $resultCode = 'providerCancelled' }
            elseif ($_.Exception -is [Net.WebException]) { $resultCode = 'timestampUnavailable' }
            elseif ($_.Exception -is [UnauthorizedAccessException] -or $_.Exception -is [Security.SecurityException]) { $resultCode = 'executionDenied' }
            Write-BridgeResponse $resultCode $hresult $null $null $null $null $null $false $false $false $null
            exit 1
        }
        """;
}
