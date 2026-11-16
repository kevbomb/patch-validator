Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'EvidenceSecurity.ps1')

function Get-PatchSnapshot {
    [CmdletBinding(DefaultParameterSetName='Computer')]
    param(
        [Parameter(Mandatory,Position=0)][ValidateNotNullOrEmpty()][string]$ServiceName,
        [Parameter(ParameterSetName='Computer')][string]$ComputerName = $env:COMPUTERNAME,
        [string]$VersionFile,
        [Parameter(ParameterSetName='Computer')][System.Management.Automation.PSCredential]$Credential,
        [Parameter(ParameterSetName='Computer')][switch]$UseSSL,
        [Parameter(ParameterSetName='Computer')][ValidateSet('Default','Kerberos','Negotiate')][string]$Authentication = 'Default',
        [Parameter(ParameterSetName='Computer')][string]$ConfigurationName,
        [Parameter(Mandatory,ParameterSetName='Session')][System.Management.Automation.Runspaces.PSSession]$Session,
        [switch]$CheckAuthenticode
    )
    if ($ServiceName.Trim().Length -eq 0 -or $ServiceName.Length -gt 256) { throw 'Enter a service name of 1 to 256 characters.' }
    if ([string]::IsNullOrWhiteSpace($ComputerName)) { $ComputerName = $env:COMPUTERNAME }
    $ComputerName = $ComputerName.Trim()
    $collectorPath = Join-Path $PSScriptRoot 'Collect-Service.ps1'
    if ($PSCmdlet.ParameterSetName -eq 'Computer' -and $ComputerName -in @('.', 'localhost', $env:COMPUTERNAME) -and $null -eq $Credential -and -not $UseSSL -and -not $ConfigurationName) {
        & $collectorPath -ServiceName $ServiceName.Trim() -VersionFile $VersionFile -CheckAuthenticode:$CheckAuthenticode
    } else {
        # Only this bundled collector is executed. User entries remain arguments.
        $parsedAddress = $null
        $isIp = [Net.IPAddress]::TryParse($ComputerName,[ref]$parsedAddress)
        if ($PSCmdlet.ParameterSetName -eq 'Computer' -and $Authentication -eq 'Kerberos' -and $isIp) {
            throw 'Kerberos requires a server DNS name, preferably its FQDN. An IP address is not accepted. No NTLM fallback was attempted.'
        }
        if ($PSCmdlet.ParameterSetName -eq 'Computer' -and $Authentication -eq 'Negotiate' -and -not $UseSSL) {
            throw 'Explicit Negotiate mode requires HTTPS with certificate validation. Use Kerberos for HTTP, or deliberately select Default for an existing legacy WinRM policy.'
        }
        if ($PSCmdlet.ParameterSetName -eq 'Computer' -and $isIp -and $null -eq $Credential) {
            throw 'Connecting by IP address requires explicit credentials. Set remote credentials, or use the server name with your current Windows identity.'
        }
        $collector = [scriptblock]::Create([IO.File]::ReadAllText($collectorPath))
        $options = New-PSSessionOption -OpenTimeout 10000 -OperationTimeout 20000
        $collectorArguments = @($ServiceName.Trim(),$VersionFile)
        if ($CheckAuthenticode) { $collectorArguments += $true }
        $remoteArguments = @{ScriptBlock=$collector;ArgumentList=$collectorArguments;ErrorAction='Stop'}
        if ($PSCmdlet.ParameterSetName -eq 'Session') { $remoteArguments.Session = $Session }
        else {
            $remoteArguments.ComputerName = $ComputerName
            $remoteArguments.SessionOption = $options
            if ($Authentication -ne 'Default') { $remoteArguments.Authentication = $Authentication }
            if ($ConfigurationName) { $remoteArguments.ConfigurationName = $ConfigurationName }
            if ($null -ne $Credential) { $remoteArguments.Credential = $Credential }
            if ($UseSSL) { $remoteArguments.UseSSL = $true }
        }
        # One attempt only. Never retry with a weaker authentication mode or different account.
        Invoke-Command @remoteArguments
    }
}

function Assert-PatchSnapshot {
    param([Parameter(Mandatory)]$Snapshot)
    $required = @('SchemaVersion','CapturedAtUtc','ComputerName','ServiceName','DisplayName','State','StartMode',
        'ProcessId','ProcessStartedAtUtc','ExecutablePath','VersionPath','VersionSource','ProductName','CompanyName',
        'ProductVersion','FileVersion','FileSha256','FileModifiedAtUtc','SelectionReliable','Notes')
    foreach ($name in $required) {
        if ($Snapshot.PSObject.Properties.Name -notcontains $name) { throw "Invalid snapshot: missing $name." }
    }
    if ($Snapshot.SchemaVersion -ne 1) { throw 'Unsupported snapshot format.' }
    foreach ($name in @('ComputerName','ServiceName','State','CapturedAtUtc')) {
        if ($Snapshot.$name -isnot [string] -or [string]::IsNullOrWhiteSpace($Snapshot.$name)) { throw "Invalid snapshot field: $name." }
    }
    foreach ($name in @('DisplayName','StartMode','ExecutablePath','VersionPath','VersionSource','ProductName','CompanyName','ProductVersion','FileVersion','FileSha256','FileModifiedAtUtc','ProcessStartedAtUtc')) {
        if ($null -ne $Snapshot.$name -and ($Snapshot.$name -isnot [string] -or $Snapshot.$name.Length -gt 8192)) { throw "Invalid snapshot field: $name." }
    }
    if ($Snapshot.SelectionReliable -isnot [bool]) { throw 'Invalid snapshot reliability flag.' }
    $identity = Get-PatchProperty $Snapshot 'ComputerIdentity'
    if ($identity -and ($identity -isnot [string] -or $identity -notmatch '^[a-fA-F0-9]{8}-(?:[a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')) { throw 'Invalid snapshot computer identity.' }
    if ($Snapshot.FileSha256 -and $Snapshot.FileSha256 -notmatch '^[A-Fa-f0-9]{64}$') { throw 'Invalid snapshot SHA-256.' }
    if ($Snapshot.Notes -is [string] -or $Snapshot.Notes -isnot [System.Collections.IEnumerable]) { throw 'Invalid snapshot notes collection.' }
    $signature = Get-PatchProperty $Snapshot 'Authenticode'
    if ($null -ne $signature) {
        if ((Get-PatchProperty $signature 'Status') -notin @('NotChecked','Valid','UnknownError','NotSigned','HashMismatch','NotTrusted','NotSupportedFileFormat','Incompatible','Unavailable')) { throw 'Invalid Authenticode status.' }
        foreach ($name in $script:signatureFields | Where-Object { $_ -ne 'CertificateTimeValid' }) {
            $value = Get-PatchProperty $signature $name
            if ($null -ne $value -and ($value -isnot [string] -or $value.Length -gt 8192)) { throw 'Invalid Authenticode certificate metadata.' }
        }
        $timeValid = Get-PatchProperty $signature 'CertificateTimeValid'
        if ($null -ne $timeValid -and $timeValid -isnot [bool]) { throw 'Invalid certificate validity flag.' }
        $certificateDates = @{}
        foreach ($name in @('NotBeforeUtc','NotAfterUtc')) {
            $value = Get-PatchProperty $signature $name
            $date = [DateTimeOffset]::MinValue
            if ($value) {
                if (-not [DateTimeOffset]::TryParse($value,[ref]$date)) { throw 'Invalid Authenticode certificate date.' }
                $certificateDates[$name] = $date
            }
        }
        if ($certificateDates.ContainsKey('NotBeforeUtc') -and $certificateDates.ContainsKey('NotAfterUtc') -and $certificateDates.NotBeforeUtc -gt $certificateDates.NotAfterUtc) { throw 'Invalid Authenticode certificate validity interval.' }
    }
    $parsedDate = [DateTimeOffset]::MinValue
    foreach ($name in @('CapturedAtUtc','ProcessStartedAtUtc','FileModifiedAtUtc')) {
        if ($Snapshot.$name -and -not [DateTimeOffset]::TryParse($Snapshot.$name, [ref]$parsedDate)) { throw "Invalid snapshot date: $name." }
    }
    $processIdNumber = [long]0
    if (-not [long]::TryParse([string]$Snapshot.ProcessId, [ref]$processIdNumber) -or $processIdNumber -lt 0) { throw 'Invalid process ID.' }
    if (@($Snapshot.Notes).Count -gt 100) { throw 'Too many snapshot notes.' }
    foreach ($note in $Snapshot.Notes) {
        if ($note -isnot [string] -or $note.Length -gt 8192) { throw 'Invalid snapshot note.' }
    }
}

function ConvertTo-PatchVersion {
    param([string]$Value)
    # Do not erase prerelease/build suffixes or compare version strings lexically.
    if ($Value -match '^\d+(?:\.\d+){0,3}$') {
        $parts = @($Value.Split('.'))
        while ($parts.Count -lt 4) { $parts += '0' }
        try { return [version]($parts -join '.') } catch { return $null }
    }
    return $null
}

function Test-PatchVersionEqual {
    param([string]$Left, [string]$Right)
    if ($Left.Trim() -ceq $Right.Trim()) { return $true }
    $a = ConvertTo-PatchVersion $Left.Trim()
    $b = ConvertTo-PatchVersion $Right.Trim()
    return ($null -ne $a -and $null -ne $b -and $a -eq $b)
}

function Compare-PatchSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Before,
        [Parameter(Mandatory)]$After,
        [string]$ExpectedVersion,
        [ValidateSet('Auto','ProductVersion','FileVersion')][string]$VersionField = 'Auto',
        [ValidateSet('Same as before','Running','Stopped','Paused')][string]$ExpectedState = 'Same as before',
        [switch]$RequireSignedBaseline,
        [switch]$RequireValidSignature,
        [string]$ExpectedPublisher
    )
    Assert-PatchSnapshot $Before
    Assert-PatchSnapshot $After
    if ($Before.ComputerName -ine $After.ComputerName -or $Before.ServiceName -ine $After.ServiceName) {
        throw 'The snapshots must identify the same computer and service.'
    }
    if ([DateTimeOffset]::Parse($After.CapturedAtUtc) -le [DateTimeOffset]::Parse($Before.CapturedAtUtc)) {
        throw 'The after snapshot must be newer than the baseline.'
    }
    $checks = New-Object 'System.Collections.Generic.List[object]'
    function Add-Check([string]$Name, [string]$Result, [string]$Detail) {
        $checks.Add([pscustomobject]@{Check=$Name;Result=$Result;Detail=$Detail})
    }
    $beforeIdentity = Get-PatchProperty $Before 'ComputerIdentity'
    $afterIdentity = Get-PatchProperty $After 'ComputerIdentity'
    if ($beforeIdentity -and $afterIdentity -and $beforeIdentity -ine $afterIdentity) { throw 'The snapshots identify different Windows machines despite matching computer names.' }
    if (-not $beforeIdentity -or -not $afterIdentity) { Add-Check 'Computer identity' 'Review' 'The Windows machine identity is unavailable in one or both captures, including legacy snapshots.' }
    $beforeIntegrity = Get-PatchEvidenceState $Before
    $afterIntegrity = Get-PatchEvidenceState $After
    foreach ($entry in @(@('Before',$beforeIntegrity),@('After',$afterIntegrity))) {
        if ($entry[1] -eq 'Modified') { Add-Check ($entry[0] + ' evidence integrity') 'Fail' 'Loaded evidence was modified in memory after verification.' }
        elseif ($entry[1] -notin @('InMemory','Verified')) { Add-Check ($entry[0] + ' evidence integrity') 'Review' ('Loaded evidence is unverified: ' + $entry[1]) }
    }
    if ($RequireSignedBaseline -and $beforeIntegrity -ne 'Verified') { Add-Check 'Baseline signature policy' 'Review' 'A baseline verified against the configured evidence signer list is required.' }
    $wantedState = if ($ExpectedState -eq 'Same as before') { $Before.State } else { $ExpectedState }
    if ($wantedState -notin @('Running','Stopped','Paused')) {
        Add-Check 'Service state' 'Review' 'The baseline captured a transitional state. Select a stable expected state.'
    } elseif ($After.State -ine $wantedState) {
        Add-Check 'Service state' 'Fail' ("Expected {0}; observed {1}." -f $wantedState,$After.State)
    } else { Add-Check 'Service state' 'Pass' ("Service is {0}, as expected." -f $After.State) }

    if ($Before.StartMode -ne $After.StartMode) { Add-Check 'Startup mode' 'Review' ("Changed from {0} to {1}." -f $Before.StartMode,$After.StartMode) }
    if ($Before.VersionPath -ine $After.VersionPath -or $Before.VersionSource -ne $After.VersionSource) {
        Add-Check 'Version source' 'Review' 'The selected component path or discovery method changed. Confirm that the files represent the same application.'
    }
    if (-not $Before.VersionPath -or -not $After.VersionPath -or -not $Before.ExecutablePath -or -not $After.ExecutablePath -or -not $Before.VersionSource -or -not $After.VersionSource) {
        Add-Check 'Component identity' 'Review' 'The intended executable/component identity is incomplete.'
    } elseif ($Before.ExecutablePath -ine $After.ExecutablePath) { Add-Check 'Component identity' 'Review' 'The service executable path changed. Confirm the intended application.' }
    if (-not $Before.StartMode -or -not $After.StartMode -or -not $Before.FileModifiedAtUtc -or -not $After.FileModifiedAtUtc) {
        Add-Check 'Required metadata' 'Review' 'Startup mode or component modification time is unavailable.'
    }
    if ($Before.FileSha256 -and $Before.FileSha256 -ieq $After.FileSha256 -and
        ($Before.ProductVersion -cne $After.ProductVersion -or $Before.FileVersion -cne $After.FileVersion)) {
        Add-Check 'Evidence consistency' 'Fail' 'Identical component SHA-256 hashes conflict with the reported embedded version metadata.'
    }
    foreach ($snapshot in @($Before,$After)) {
        if ($snapshot.ProcessStartedAtUtc -and [DateTimeOffset]::Parse($snapshot.ProcessStartedAtUtc) -gt [DateTimeOffset]::Parse($snapshot.CapturedAtUtc)) {
            Add-Check 'Evidence consistency' 'Review' 'A process start time is later than its capture time.'
        }
    }
    if ($After.State -in @('Running','Paused') -and [long]$After.ProcessId -eq 0) { Add-Check 'Evidence consistency' 'Review' 'A running service has no process ID.' }
    $authenticode = Get-PatchProperty $After 'Authenticode'
    $signatureStatus = Get-PatchProperty $authenticode 'Status' 'NotChecked'
    if ($signatureStatus -eq 'Valid' -and (
        -not (Get-PatchProperty $authenticode 'SignerSubject') -or
        (Get-PatchProperty $authenticode 'SignerThumbprint') -notmatch '^[A-Fa-f0-9]{40}$' -or
        -not (Get-PatchProperty $authenticode 'Issuer') -or
        -not (Get-PatchProperty $authenticode 'NotBeforeUtc') -or -not (Get-PatchProperty $authenticode 'NotAfterUtc'))) {
        Add-Check 'Authenticode evidence' 'Review' 'A valid signature was reported without complete signer certificate evidence.'
    }
    if ($signatureStatus -eq 'HashMismatch') { Add-Check 'Authenticode' 'Fail' 'The executable signature does not match the file contents.' }
    elseif ($signatureStatus -notin @('NotChecked','Valid')) { Add-Check 'Authenticode' 'Review' ('Executable signature status: ' + $signatureStatus + '. This alone does not classify the application as malicious.') }
    if (($RequireValidSignature -or $ExpectedPublisher) -and $signatureStatus -ne 'Valid') {
        Add-Check 'Publisher policy' 'Review' 'The publisher policy requires a valid Authenticode signature.'
    } elseif ($ExpectedPublisher -and (Get-PatchProperty $authenticode 'SignerSubject') -ine $ExpectedPublisher.Trim()) {
        Add-Check 'Publisher policy' 'Fail' 'The trusted executable signer subject does not match the expected publisher.'
    }
    if (-not $Before.SelectionReliable -or -not $After.SelectionReliable) {
        Add-Check 'Collection' 'Review' 'One or both snapshots could not reliably inspect the component. Review capture notes.'
    }
    foreach ($note in @($Before.Notes)) { Add-Check 'Before capture' 'Review' $note }
    foreach ($note in @($After.Notes)) { Add-Check 'After capture' 'Review' $note }

    if ($VersionField -eq 'Auto') {
        $VersionField = if ($Before.ProductVersion -or $After.ProductVersion) { 'ProductVersion' } else { 'FileVersion' }
    }
    $oldVersion = [string]$Before.$VersionField
    $newVersion = [string]$After.$VersionField
    $versionChanged = $false
    if (-not $oldVersion -or -not $newVersion) {
        Add-Check 'Version change' 'Review' ("{0} is unavailable in one or both snapshots." -f $VersionField)
    } else {
        $versionChanged = -not (Test-PatchVersionEqual $oldVersion $newVersion)
        $oldNumber = ConvertTo-PatchVersion $oldVersion
        $newNumber = ConvertTo-PatchVersion $newVersion
        if (-not $versionChanged) {
            Add-Check 'Version change' 'Review' ("{0} is unchanged ({1}). This alone does not prove that patching failed or succeeded." -f $VersionField,$newVersion)
        } elseif ($null -ne $oldNumber -and $null -ne $newNumber -and $newNumber -lt $oldNumber) {
            Add-Check 'Version change' 'Fail' ("Version decreased: {0} -> {1}." -f $oldVersion,$newVersion)
        } else { Add-Check 'Version change' 'Pass' ("{0}: {1} -> {2}." -f $VersionField,$oldVersion,$newVersion) }
    }
    if ([string]::IsNullOrWhiteSpace($ExpectedVersion)) {
        Add-Check 'Target version' 'Review' 'No target version was supplied. Changes are visible, but a particular patch cannot be confirmed.'
    } elseif (-not $newVersion) {
        Add-Check 'Target version' 'Review' 'The selected version could not be read.'
    } elseif (Test-PatchVersionEqual $newVersion $ExpectedVersion.Trim()) {
        Add-Check 'Target version' 'Pass' ("Matches expected {0}: {1}." -f $VersionField,$ExpectedVersion.Trim())
    } else {
        Add-Check 'Target version' 'Fail' ("Expected {0}; observed {1} ({2})." -f $ExpectedVersion.Trim(),$newVersion,$VersionField)
    }

    $binaryChanged = $false
    if ($Before.FileSha256 -and $After.FileSha256) {
        $binaryChanged = $Before.FileSha256 -ne $After.FileSha256
        $detail = if ($binaryChanged) { 'The component SHA-256 changed.' } else { 'The component SHA-256 is unchanged.' }
        Add-Check 'File contents' 'Info' $detail
    } else { Add-Check 'File contents' 'Review' 'A component hash is unavailable.' }
    if ($After.State -in @('Running','Paused')) {
        if (-not $After.ProcessStartedAtUtc) {
            Add-Check 'Process restart' 'Review' 'Process start time is unavailable; the loaded version cannot be inferred.'
        } elseif ($After.FileModifiedAtUtc -and [DateTimeOffset]::Parse($After.FileModifiedAtUtc) -gt [DateTimeOffset]::Parse($After.ProcessStartedAtUtc)) {
            Add-Check 'Process restart' 'Review' 'The component was modified after the current process started. Restart or verify the application runtime version.'
        } elseif ([DateTimeOffset]::Parse($After.ProcessStartedAtUtc) -gt [DateTimeOffset]::Parse($Before.CapturedAtUtc)) {
            Add-Check 'Process restart' 'Pass' 'The current service process started after the baseline was captured.'
        } elseif ($binaryChanged -or $versionChanged) {
            Add-Check 'Process restart' 'Review' 'The component changed, but its service process predates the baseline. A restart or application-specific runtime check may be needed.'
        } else { Add-Check 'Process restart' 'Info' 'The current process predates the baseline.' }
    } else { Add-Check 'Process restart' 'Info' 'The service is not running; only the installed file version was checked.' }

    $verdict = if (@($checks | Where-Object Result -eq 'Fail').Count) { 'Fail' }
        elseif (@($checks | Where-Object Result -eq 'Review').Count) { 'Review' } else { 'Pass' }
    $summary = switch ($verdict) {
        'Pass' { 'Expected version and service state verified against the baseline.' }
        'Fail' { 'One or more expected conditions were not met.' }
        default { 'Review required before confirming the patch.' }
    }
    [pscustomobject][ordered]@{
        DocumentType='PatchValidatorReport';SchemaVersion=1;CreatedAtUtc=[DateTime]::UtcNow.ToString('o')
        Verdict=$verdict;Summary=$summary;VersionField=$VersionField;ExpectedVersion=$ExpectedVersion
        ExpectedState=$wantedState;Checks=@($checks.ToArray());Before=$Before;After=$After
        RequireSignedBaseline=[bool]$RequireSignedBaseline;RequireValidSignature=[bool]$RequireValidSignature;ExpectedPublisher=$ExpectedPublisher
        BaselineVerification=$beforeIntegrity;AfterVerification=$afterIntegrity
        Scope='Installed component metadata and observed service/process state; not an application health test, proof of in-memory code version, or proof of CVE remediation.'
    }
}

function Write-PatchJson {
    param($Value, [string]$Path)
    $fullPath = [IO.Path]::GetFullPath($Path)
    $json = $Value | ConvertTo-Json -Depth 12
    if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 4MB) { throw 'Evidence exceeds the 4 MiB size limit.' }
    $temporary = Join-Path ([IO.Path]::GetDirectoryName($fullPath)) ([IO.Path]::GetRandomFileName())
    try {
        [IO.File]::WriteAllText($temporary,$json,(New-Object Text.UTF8Encoding($false)))
        if ([IO.File]::Exists($fullPath)) { [IO.File]::Replace($temporary,$fullPath,[System.Management.Automation.Language.NullString]::Value) }
        else { [IO.File]::Move($temporary,$fullPath) }
    } finally { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
}

function Save-PatchSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Snapshot,[Parameter(Mandatory)][string]$Path,
        [Security.Cryptography.X509Certificates.X509Certificate2]$SigningCertificate,[switch]$RequireSignature)
    if ($null -ne $SigningCertificate -and (Get-PatchEvidenceState $Snapshot) -notin @('InMemory','Verified')) {
        throw 'Unverified or modified imported evidence cannot be re-signed as a trusted baseline. Capture a new baseline or verify the original signer.'
    }
    $document = [pscustomobject]@{DocumentType='PatchValidatorSnapshot';SchemaVersion=1;Snapshot=(ConvertTo-PatchSnapshotData $Snapshot)}
    Write-PatchEvidence -Document $document -Path $Path -SigningCertificate $SigningCertificate -RequireSignature:$RequireSignature
}

function Read-PatchSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path,[string[]]$TrustedSignerThumbprint,[switch]$RequireSignature)
    $evidence = Read-PatchEvidence -Path $Path -TrustedSignerThumbprint $TrustedSignerThumbprint -RequireSignature:$RequireSignature
    $document = $evidence.Document
    if ($document.DocumentType -ne 'PatchValidatorSnapshot' -or $document.SchemaVersion -ne 1) { throw 'This is not a supported Patch Validator snapshot.' }
    $snapshot = ConvertFrom-PatchSnapshotData $document.Snapshot
    Register-PatchEvidence $snapshot $evidence.Status $evidence.Signer
    return $snapshot
}

function Save-PatchReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Report,[Parameter(Mandatory)][string]$Path,
        [Security.Cryptography.X509Certificates.X509Certificate2]$SigningCertificate,[switch]$RequireSignature)
    if ($Report.DocumentType -ne 'PatchValidatorReport') { throw 'Invalid comparison report.' }
    # Recompute the verdict and whitelist fields. Do not serialize arbitrary caller properties.
    $clean = Compare-PatchSnapshot -Before $Report.Before -After $Report.After -ExpectedVersion $Report.ExpectedVersion -VersionField $Report.VersionField -ExpectedState $Report.ExpectedState `
        -RequireSignedBaseline:([bool](Get-PatchProperty $Report 'RequireSignedBaseline' $false)) `
        -RequireValidSignature:([bool](Get-PatchProperty $Report 'RequireValidSignature' $false)) -ExpectedPublisher (Get-PatchProperty $Report 'ExpectedPublisher')
    $clean.Before = ConvertTo-PatchSnapshotData $Report.Before
    $clean.After = ConvertTo-PatchSnapshotData $Report.After
    Write-PatchEvidence -Document $clean -Path $Path -SigningCertificate $SigningCertificate -RequireSignature:$RequireSignature
}

function Read-PatchReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path,[string[]]$TrustedSignerThumbprint,[switch]$RequireSignature)
    $evidence = Read-PatchEvidence -Path $Path -TrustedSignerThumbprint $TrustedSignerThumbprint -RequireSignature:$RequireSignature
    $report = $evidence.Document
    if ($report.DocumentType -ne 'PatchValidatorReport' -or $report.SchemaVersion -ne 1) { throw 'Invalid comparison report.' }
    $report.Before = ConvertFrom-PatchSnapshotData $report.Before
    $report.After = ConvertFrom-PatchSnapshotData $report.After
    $report | Add-Member -NotePropertyName EvidenceVerification -NotePropertyValue $evidence.Status -Force
    if ($evidence.Status -ne 'Verified') {
        $report | Add-Member -NotePropertyName UnverifiedClaimedVerdict -NotePropertyValue $report.Verdict -Force
        $report.Verdict = 'Review'
        $report.Summary = 'Report integrity has not been authenticated against a trusted signer.'
    }
    return $report
}

. (Join-Path $PSScriptRoot 'Batch.ps1')
Export-ModuleMember -Function Get-PatchSnapshot,Compare-PatchSnapshot,Save-PatchSnapshot,Read-PatchSnapshot,Save-PatchReport,Read-PatchReport,Get-PatchSigningCertificate,Get-PatchErrorMessage,Import-PatchHostCsv,Import-PatchServiceCsv,New-PatchBatchPlan,Get-PatchBatchCapture,Save-PatchBatchBaseline,Read-PatchBatchBaseline,Save-PatchBatchReport,Read-PatchBatchReport
