Set-StrictMode -Version 2.0

function Get-PatchSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ServiceName,
        [string]$ComputerName = $env:COMPUTERNAME,
        [string]$VersionFile,
        [System.Management.Automation.PSCredential]$Credential,
        [switch]$UseSSL
    )
    if ($ServiceName.Trim().Length -eq 0 -or $ServiceName.Length -gt 256) { throw 'Enter a service name of 1 to 256 characters.' }
    if ([string]::IsNullOrWhiteSpace($ComputerName)) { $ComputerName = $env:COMPUTERNAME }
    $ComputerName = $ComputerName.Trim()
    $collectorPath = Join-Path $PSScriptRoot 'Collect-Service.ps1'
    if ($ComputerName -in @('.', 'localhost', $env:COMPUTERNAME) -and $null -eq $Credential -and -not $UseSSL) {
        & $collectorPath -ServiceName $ServiceName.Trim() -VersionFile $VersionFile
    } else {
        # Only this bundled collector is executed. User entries remain arguments.
        $parsedAddress = $null
        if ([Net.IPAddress]::TryParse($ComputerName,[ref]$parsedAddress) -and $null -eq $Credential) {
            throw 'Connecting by IP address requires explicit credentials. Set remote credentials, or use the server name with your current Windows identity.'
        }
        $collector = [scriptblock]::Create([IO.File]::ReadAllText($collectorPath))
        $options = New-PSSessionOption -OpenTimeout 10000 -OperationTimeout 20000
        $remoteArguments = @{
            ComputerName=$ComputerName;ScriptBlock=$collector;ArgumentList=@($ServiceName.Trim(),$VersionFile)
            SessionOption=$options;ErrorAction='Stop'
        }
        if ($null -ne $Credential) { $remoteArguments.Credential = $Credential }
        if ($UseSSL) { $remoteArguments.UseSSL = $true }
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
        [ValidateSet('Same as before','Running','Stopped','Paused')][string]$ExpectedState = 'Same as before'
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
        Scope='Installed component metadata and observed service/process state; not an application health test or proof of in-memory code version.'
    }
}

function Write-PatchJson {
    param($Value, [string]$Path)
    $fullPath = [IO.Path]::GetFullPath($Path)
    $json = $Value | ConvertTo-Json -Depth 12
    $temporary = Join-Path ([IO.Path]::GetDirectoryName($fullPath)) ([IO.Path]::GetRandomFileName())
    try {
        [IO.File]::WriteAllText($temporary,$json,(New-Object Text.UTF8Encoding($false)))
        if ([IO.File]::Exists($fullPath)) { [IO.File]::Replace($temporary,$fullPath,[System.Management.Automation.Language.NullString]::Value) }
        else { [IO.File]::Move($temporary,$fullPath) }
    } finally { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
}

function Save-PatchSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Snapshot,[Parameter(Mandatory)][string]$Path)
    Assert-PatchSnapshot $Snapshot
    Write-PatchJson -Value ([pscustomobject]@{DocumentType='PatchValidatorSnapshot';SchemaVersion=1;Snapshot=$Snapshot}) -Path $Path
}

function Read-PatchSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $file = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($file.Length -gt 1MB) { throw 'Snapshot exceeds the 1 MiB size limit.' }
    $jsonOptions = @{ErrorAction='Stop'}
    if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) { $jsonOptions.DateKind = 'String' }
    $document = [IO.File]::ReadAllText($file.FullName) | ConvertFrom-Json @jsonOptions
    if ($document.DocumentType -ne 'PatchValidatorSnapshot' -or $document.SchemaVersion -ne 1) { throw 'This is not a supported Patch Validator snapshot.' }
    # PowerShell 6 through 7.4 automatically turn JSON timestamp strings into dates.
    foreach ($name in @('CapturedAtUtc','ProcessStartedAtUtc','FileModifiedAtUtc')) {
        if ($document.Snapshot.PSObject.Properties.Name -contains $name -and $document.Snapshot.$name -is [DateTime]) {
            $document.Snapshot.$name = $document.Snapshot.$name.ToUniversalTime().ToString('o')
        }
    }
    Assert-PatchSnapshot $document.Snapshot
    return $document.Snapshot
}

function Save-PatchReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Report,[Parameter(Mandatory)][string]$Path)
    if ($Report.DocumentType -ne 'PatchValidatorReport') { throw 'Invalid comparison report.' }
    Write-PatchJson -Value $Report -Path $Path
}

Export-ModuleMember -Function Get-PatchSnapshot,Compare-PatchSnapshot,Save-PatchSnapshot,Read-PatchSnapshot,Save-PatchReport
