# Evidence signatures authenticate bytes and a separately configured signer, not the truth of a collection.
$script:evidenceRecords = New-Object 'System.Runtime.CompilerServices.ConditionalWeakTable[object,object]'
$script:snapshotFields = @('SchemaVersion','CapturedAtUtc','ComputerName','ServiceName','DisplayName','State','StartMode',
    'ProcessId','ProcessStartedAtUtc','ExecutablePath','VersionPath','VersionSource','ProductName','CompanyName',
    'ProductVersion','FileVersion','FileSha256','FileModifiedAtUtc','SelectionReliable','Notes','ComputerIdentity')
$script:signatureFields = @('Status','SignerSubject','SignerThumbprint','Publisher','Issuer','NotBeforeUtc','NotAfterUtc',
    'CertificateTimeValid','TimestampSignerSubject')

function Get-PatchProperty($Value, [string]$Name, $Default = $null) {
    if ($null -ne $Value -and $Value.PSObject.Properties.Name -contains $Name) { return $Value.$Name }
    return $Default
}

function ConvertTo-PatchSnapshotData($Snapshot) {
    Assert-PatchSnapshot $Snapshot
    $data = [ordered]@{}
    foreach ($name in $script:snapshotFields) { $data[$name] = Get-PatchProperty $Snapshot $name }
    $data.Notes = @($Snapshot.Notes)
    $signature = Get-PatchProperty $Snapshot 'Authenticode'
    if ($null -ne $signature) {
        $values = [ordered]@{}
        foreach ($name in $script:signatureFields) { $values[$name] = Get-PatchProperty $signature $name }
        $data.Authenticode = [pscustomobject]$values
    }
    return [pscustomobject]$data
}

function Get-PatchEvidenceHash($Snapshot) {
    $json = ConvertTo-PatchSnapshotData $Snapshot | ConvertTo-Json -Depth 8 -Compress
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [Convert]::ToBase64String($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($json))) }
    finally { $sha.Dispose() }
}

function Register-PatchEvidence($Snapshot, [string]$Status, [string]$Signer) {
    [void]$script:evidenceRecords.Remove($Snapshot)
    $script:evidenceRecords.Add($Snapshot,[pscustomobject]@{Status=$Status;Signer=$Signer;Hash=(Get-PatchEvidenceHash $Snapshot)})
    # Display only. Comparison never trusts a status supplied inside a JSON file.
    $Snapshot | Add-Member -NotePropertyName EvidenceVerification -NotePropertyValue $Status -Force
}

function Get-PatchEvidenceState($Snapshot) {
    $record = $null
    if ($script:evidenceRecords.TryGetValue($Snapshot,[ref]$record)) {
        if ($record.Hash -cne (Get-PatchEvidenceHash $Snapshot)) { return 'Modified' }
        return $record.Status
    }
    # Module callers can construct in-memory objects. This does not authenticate their origin.
    if ($Snapshot.PSObject.Properties.Name -contains 'EvidenceVerification') { return 'Unverified' }
    return 'InMemory'
}

function Initialize-PatchCms {
    if (-not ('System.Security.Cryptography.Pkcs.SignedCms' -as [type])) {
        if ($PSVersionTable.PSEdition -eq 'Desktop') { Add-Type -AssemblyName System.Security }
        else { Add-Type -AssemblyName System.Security.Cryptography.Pkcs }
    }
}

function Get-PatchSigningCertificate {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$Thumbprint)
    # Private keys stay in the user's Windows certificate/key store. Never export them.
    $certificate = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $Thumbprint) -ErrorAction Stop
    if (-not $certificate.HasPrivateKey) { throw 'The selected evidence certificate has no accessible private key.' }
    return $certificate
}

function Assert-PatchCertificate($Certificate, [switch]$Signing) {
    if ($null -eq $Certificate) { throw 'An evidence signing certificate is required.' }
    if ($Signing -and -not $Certificate.HasPrivateKey) { throw 'The evidence certificate has no private key.' }
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Certificate)
    try { if ($null -eq $rsa -or $rsa.KeySize -lt 2048) { throw 'Evidence signing requires an RSA certificate with at least 2048 bits.' } }
    finally { if ($null -ne $rsa) { $rsa.Dispose() } }
    foreach ($extension in $Certificate.Extensions) {
        if ($extension -is [Security.Cryptography.X509Certificates.X509KeyUsageExtension] -and
            -not ($extension.KeyUsages -band [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature)) {
            throw 'The evidence certificate does not permit digital signatures.'
        }
    }
    if ($Signing -and ([DateTime]::UtcNow -lt $Certificate.NotBefore.ToUniversalTime() -or [DateTime]::UtcNow -gt $Certificate.NotAfter.ToUniversalTime())) {
        throw 'The evidence signing certificate is outside its validity period.'
    }
}

function Write-PatchEvidence {
    param($Document,[string]$Path,[Security.Cryptography.X509Certificates.X509Certificate2]$SigningCertificate,[switch]$RequireSignature)
    if ($null -eq $SigningCertificate) {
        if ($RequireSignature) { throw 'Signing is required. Select an evidence signing certificate before saving.' }
        Write-PatchJson -Value $Document -Path $Path
        return
    }
    Initialize-PatchCms
    Assert-PatchCertificate $SigningCertificate -Signing
    $bytes = [Text.Encoding]::UTF8.GetBytes(($Document | ConvertTo-Json -Depth 12 -Compress))
    $content = New-Object Security.Cryptography.Pkcs.ContentInfo -ArgumentList (,$bytes)
    $cms = New-Object Security.Cryptography.Pkcs.SignedCms -ArgumentList $content,$false
    $signer = New-Object Security.Cryptography.Pkcs.CmsSigner -ArgumentList $SigningCertificate
    $signer.DigestAlgorithm = New-Object Security.Cryptography.Oid('2.16.840.1.101.3.4.2.1')
    $signer.IncludeOption = [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
    $cms.ComputeSignature($signer,$true)
    $envelope = [pscustomobject][ordered]@{
        DocumentType='PatchValidatorSignedEvidence';SchemaVersion=1;Cms=[Convert]::ToBase64String($cms.Encode())
    }
    Write-PatchJson -Value $envelope -Path $Path
}

function ConvertFrom-PatchJson([string]$Json) {
    $options = @{ErrorAction='Stop'}
    if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) { $options.DateKind = 'String' }
    return ConvertFrom-Json -InputObject $Json @options
}

function Read-PatchEvidence {
    param([string]$Path,[string[]]$TrustedSignerThumbprint,[switch]$RequireSignature)
    # Read once, with a bounded allocation, so verification and parsing see the same bytes.
    $stream = [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if ($stream.Length -gt 4MB) { throw 'Evidence exceeds the 4 MiB size limit.' }
        $reader = New-Object IO.StreamReader($stream,[Text.Encoding]::UTF8,$true)
        try { $document = ConvertFrom-PatchJson $reader.ReadToEnd() } finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
    $status = 'Unsigned'
    $thumbprint = $null
    if ((Get-PatchProperty $document 'DocumentType') -eq 'PatchValidatorSignedEvidence') {
        if ($document.SchemaVersion -ne 1 -or $document.Cms -isnot [string]) { throw 'Unsupported signed evidence envelope.' }
        Initialize-PatchCms
        try {
            $cms = New-Object Security.Cryptography.Pkcs.SignedCms
            $cms.Decode([Convert]::FromBase64String($document.Cms))
            if ($cms.Detached -or $cms.SignerInfos.Count -ne 1) { throw 'Expected one attached evidence signature.' }
            if ($cms.SignerInfos[0].DigestAlgorithm.Value -ne '2.16.840.1.101.3.4.2.1') { throw 'Unsupported evidence digest.' }
            # Verify bytes first. Trust is established independently with an administrator-managed pin list.
            $cms.CheckSignature($true)
            $certificate = $cms.SignerInfos[0].Certificate
            Assert-PatchCertificate $certificate
            $thumbprint = $certificate.Thumbprint
            $status = 'UntrustedSigner'
            if (@($TrustedSignerThumbprint) -contains $thumbprint) {
                $status = 'Verified'
                if ([DateTime]::UtcNow -lt $certificate.NotBefore.ToUniversalTime() -or [DateTime]::UtcNow -gt $certificate.NotAfter.ToUniversalTime()) { $status = 'ExpiredSigner' }
            }
            $document = ConvertFrom-PatchJson ([Text.Encoding]::UTF8.GetString($cms.ContentInfo.Content))
        } catch { throw 'Evidence signature verification failed. The file is malformed, modified, or uses an unsupported signature.' }
    }
    if ($RequireSignature -and $status -ne 'Verified') { throw ('Trusted signed evidence is required. Verification status: ' + $status) }
    return [pscustomobject]@{Document=$document;Status=$status;Signer=$thumbprint}
}

function ConvertFrom-PatchSnapshotData($Snapshot) {
    foreach ($name in @('CapturedAtUtc','ProcessStartedAtUtc','FileModifiedAtUtc')) {
        if ($Snapshot.PSObject.Properties.Name -contains $name -and $Snapshot.$name -is [DateTime]) { $Snapshot.$name = $Snapshot.$name.ToUniversalTime().ToString('o') }
    }
    $signature = Get-PatchProperty $Snapshot 'Authenticode'
    foreach ($name in @('NotBeforeUtc','NotAfterUtc')) {
        if ($null -ne $signature -and $signature.PSObject.Properties.Name -contains $name -and $signature.$name -is [DateTime]) { $signature.$name = $signature.$name.ToUniversalTime().ToString('o') }
    }
    return ConvertTo-PatchSnapshotData $Snapshot
}

function Get-PatchErrorMessage {
    param([Parameter(Mandatory)]$ErrorRecord)
    # GUI messages deliberately do not echo raw remote exceptions, argument values, or credentials.
    $message = [string]$ErrorRecord.Exception.Message
    if ($message -match '(?i)evidence|signing|snapshot|baseline') { return 'Evidence validation or signing failed. Check the file format, signature, trusted signer list, and access to the configured signing key.' }
    if ($message -match 'Explicit Negotiate mode requires HTTPS') { return 'Negotiate authentication requires Use HTTPS (5986). Use Kerberos with a server FQDN for HTTP, or deliberately choose Default for an existing legacy WinRM policy.' }
    if ($message -match '(?i)certificate|SSL|TLS|0x80072f') { return 'HTTPS certificate validation or TLS connection failed. Check the server name, certificate trust, validity, and HTTPS listener. Certificate checks were not bypassed.' }
    if ($message -match '(?i)Kerberos|SPN|KDC') { return 'Kerberos authentication failed. Use the server FQDN and check DNS, time, domain trust, and SPN configuration. No NTLM fallback was attempted when Kerberos was selected.' }
    if ($message -match '(?i)access.*denied|logon|authentication|credential|password') { return 'Authentication or authorization failed. Check the selected account, authentication mode, and endpoint permissions. No alternate account was tried.' }
    if ($message -match '(?i)evidence|signature|signing|snapshot|baseline') { return 'Evidence validation or signing failed. Check the file format, signature, trusted signer list, and access to the configured signing key.' }
    if ($message -match '(?i)time.?out|pipeline.*stopped') { return 'The operation timed out or was cancelled. No completed capture was accepted.' }
    return 'The operation could not be completed. Check the target, service/component selection, file access, and connection settings. Sensitive exception details are not displayed.'
}
