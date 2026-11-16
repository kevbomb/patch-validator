# CSV inputs are configuration only. Evidence remains signed/verified JSON.
function Read-PatchCsv {
    param([string]$Path,[string[]]$Required,[string[]]$Allowed)
    $stream = [IO.File]::Open([IO.Path]::GetFullPath($Path),[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if ($stream.Length -gt 1MB) { throw 'CSV input must be a file no larger than 1 MiB.' }
        $source = New-Object IO.StreamReader($stream,[Text.Encoding]::UTF8,$true)
        try { $csv = $source.ReadToEnd() } finally { $source.Dispose() }
    } finally { $stream.Dispose() }
    Add-Type -AssemblyName Microsoft.VisualBasic
    $reader = New-Object IO.StringReader($csv)
    $parser = New-Object Microsoft.VisualBasic.FileIO.TextFieldParser($reader)
    $parser.SetDelimiters(','); $parser.HasFieldsEnclosedInQuotes = $true
    $parser.TrimWhiteSpace = $true
    try {
        if ($parser.EndOfData) { throw 'CSV input is empty.' }
        $headers = @($parser.ReadFields())
        $seen = @{}
        foreach ($header in $headers) {
            if (-not $header -or $seen.ContainsKey($header) -or $header -notin $Allowed) { throw 'CSV has an empty, duplicate or unsupported column. Use the supplied template.' }
            $seen[$header] = $true
        }
        foreach ($name in $Required) { if ($name -notin $headers) { throw ('CSV is missing required column: ' + $name) } }
        $count = 0
        while (-not $parser.EndOfData) {
            $fields = @($parser.ReadFields())
            if ($fields.Count -ne $headers.Count) { throw 'CSV row has the wrong number of fields.' }
            if (@($fields | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -eq 0) { continue }
            $row = [ordered]@{}
            for ($i=0; $i -lt $headers.Count; $i++) { $row[$headers[$i]] = $fields[$i].Trim() }
            $count++
            if ($count -gt 500) { throw 'CSV has more than 500 data rows.' }
            [pscustomobject]$row
        }
        if ($count -eq 0) { throw 'CSV has no data rows.' }
    } catch [Microsoft.VisualBasic.FileIO.MalformedLineException] {
        throw 'CSV contains malformed quoting. Use a comma-separated UTF-8 CSV with a header.'
    } finally { $parser.Dispose(); $reader.Dispose() }
}

function Import-PatchHostCsv {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)
    $rows = @(Read-PatchCsv $Path @('ComputerName') @('ComputerName'))
    foreach ($row in $rows) { Assert-PatchHost $row.ComputerName }
    return $rows
}
function Import-PatchServiceCsv {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)
    $rows = @(Read-PatchCsv $Path @('DisplayName') @('DisplayName'))
    # The collector already accepts exact display names. Keep the CSV names-only.
    foreach ($row in $rows) { ConvertTo-PatchService ([pscustomobject]@{ServiceName=$row.DisplayName}) }
}
function Assert-PatchHost([string]$ComputerName) {
    if ([string]::IsNullOrWhiteSpace($ComputerName) -or $ComputerName.Length -gt 255 -or $ComputerName -notmatch '^[a-zA-Z0-9_.:%-]+$') {
        throw 'ComputerName must be a single DNS name or IP address, without a URL, spaces or wildcards.'
    }
}
function ConvertTo-PatchService($Service) {
    $name = [string](Get-PatchProperty $Service 'ServiceName')
    if ([string]::IsNullOrWhiteSpace($name) -or $name.Length -gt 256 -or $name -match '[\x00-\x1f]') { throw 'ServiceName must contain one exact service name or display name.' }
    $data = [ordered]@{ServiceName=$name.Trim()}
    foreach ($field in @('ExpectedVersion','VersionFile','VersionField','ExpectedState')) {
        $value = [string](Get-PatchProperty $Service $field)
        if ($value.Length -gt 8192 -or $value -match '[\x00-\x1f]') { throw 'Invalid service setting in the input list.' }
        $data[$field] = $value.Trim()
    }
    if (-not $data.VersionField) { $data.VersionField='Auto' }
    if (-not $data.ExpectedState) { $data.ExpectedState='Same as before' }
    if ($data.VersionField -notin @('Auto','ProductVersion','FileVersion') -or $data.ExpectedState -notin @('Same as before','Running','Stopped','Paused')) { throw 'Invalid VersionField or ExpectedState in the service list.' }
    return [pscustomobject]$data
}
function New-PatchBatchPlan {
    [CmdletBinding()] param([Parameter(Mandatory)][object[]]$Hosts,[Parameter(Mandatory)][object[]]$Services)
    if ($Hosts.Count -eq 0 -or $Services.Count -eq 0 -or ([long]$Hosts.Count * $Services.Count) -gt 500) { throw 'Choose at least one host and service, with at most 500 host/service pairs.' }
    $seen = @{}
    foreach ($computer in $Hosts) {
        $name = if ($computer -is [string]) { $computer.Trim() } else { ([string](Get-PatchProperty $computer 'ComputerName')).Trim() }
        Assert-PatchHost $name
        foreach ($service in $Services) {
            $source = if ($service -is [string]) { [pscustomobject]@{ServiceName=$service} } else { $service }
            $clean = ConvertTo-PatchService $source
            $key = $name.ToLowerInvariant() + '|' + $clean.ServiceName.ToLowerInvariant()
            if ($seen.ContainsKey($key)) { throw 'Duplicate host/service pair. Remove duplicate hosts or services before capture.' }
            $seen[$key] = $true
            [pscustomobject][ordered]@{ComputerName=$name;ServiceName=$clean.ServiceName;ExpectedVersion=$clean.ExpectedVersion;VersionFile=$clean.VersionFile;VersionField=$clean.VersionField;ExpectedState=$clean.ExpectedState}
        }
    }
}
function Assert-PatchBatchTargets($Targets) {
    if (@($Targets).Count -eq 0 -or @($Targets).Count -gt 500) { throw 'Batch evidence must contain between 1 and 500 targets.' }
    $seen = @{}
    foreach ($target in $Targets) {
        $clean = @(New-PatchBatchPlan -Hosts @($target.ComputerName) -Services @($target))[0]
        $key = $clean.ComputerName.ToLowerInvariant() + '|' + $clean.ServiceName.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { throw 'Duplicate target in batch evidence.' }
        $seen[$key]=$true
        $clean
    }
}
function Get-PatchBatchCapture {
    [CmdletBinding()] param([Parameter(Mandatory)]$Target,[hashtable]$Connection=@{})
    $clean = @(New-PatchBatchPlan @($Target.ComputerName) @($Target))[0]
    foreach ($key in $Connection.Keys) {
        if ($key -notin @('Credential','UseSSL','Authentication','ConfigurationName','CheckAuthenticode')) { throw 'Unsupported batch connection setting.' }
    }
    try {
        $snapshot = Get-PatchSnapshot -ServiceName $clean.ServiceName -ComputerName $clean.ComputerName -VersionFile $clean.VersionFile @Connection
        Assert-PatchSnapshot $snapshot
        [pscustomobject]@{Snapshot=$snapshot;Error=$null}
    } catch { [pscustomobject]@{Snapshot=$null;Error=(Get-PatchErrorMessage $_)} }
}
function Save-PatchBatchBaseline {
    [CmdletBinding()] param([Parameter(Mandatory)][object[]]$Items,[Parameter(Mandatory)][string]$Path,
        [Security.Cryptography.X509Certificates.X509Certificate2]$SigningCertificate,[switch]$RequireSignature)
    $targets = @(Assert-PatchBatchTargets @($Items | ForEach-Object { $_.Target }))
    $cleanItems = @()
    for ($i=0; $i -lt $Items.Count; $i++) {
        $snapshot = $Items[$i].Before
        if ($null -ne $snapshot -and $null -ne $SigningCertificate -and (Get-PatchEvidenceState $snapshot) -notin @('InMemory','Verified')) { throw 'Unverified or modified batch evidence cannot be re-signed. Capture a new baseline.' }
        $cleanSnapshot = if ($null -ne $snapshot) { ConvertTo-PatchSnapshotData $snapshot } else { $null }
        $cleanItems += [pscustomobject]@{Target=$targets[$i];Snapshot=$cleanSnapshot}
    }
    Write-PatchEvidence -Document ([pscustomobject]@{DocumentType='PatchValidatorBatchBaseline';SchemaVersion=1;Items=$cleanItems}) -Path $Path -SigningCertificate $SigningCertificate -RequireSignature:$RequireSignature
}
function Read-PatchBatchBaseline {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path,[string[]]$TrustedSignerThumbprint,[switch]$RequireSignature)
    $evidence = Read-PatchEvidence -Path $Path -TrustedSignerThumbprint $TrustedSignerThumbprint -RequireSignature:$RequireSignature
    $doc = $evidence.Document
    if ($doc.DocumentType -ne 'PatchValidatorBatchBaseline' -or $doc.SchemaVersion -ne 1) { throw 'Invalid batch baseline format.' }
    $targets = @(Assert-PatchBatchTargets @($doc.Items | ForEach-Object { $_.Target }))
    for ($i=0; $i -lt $targets.Count; $i++) {
        $snapshot = $null
        if ($null -ne $doc.Items[$i].Snapshot) {
            $snapshot = ConvertFrom-PatchSnapshotData $doc.Items[$i].Snapshot
            Register-PatchEvidence $snapshot $evidence.Status $evidence.Signer
        }
        [pscustomobject]@{Target=$targets[$i];Before=$snapshot;After=$null;Report=$null;Result='Review';Detail='Loaded baseline; after capture pending.'}
    }
}
function Save-PatchBatchReport {
    [CmdletBinding()] param([Parameter(Mandatory)][object[]]$Items,[Parameter(Mandatory)][string]$Path,
        [switch]$RequireSignedBaseline,[switch]$RequireValidSignature,[string]$ExpectedPublisher,
        [Security.Cryptography.X509Certificates.X509Certificate2]$SigningCertificate,[switch]$RequireSignature)
    $targets = @(Assert-PatchBatchTargets @($Items | ForEach-Object { $_.Target }))
    $results = @()
    for ($i=0; $i -lt $Items.Count; $i++) {
        $item=$Items[$i]; $target=$targets[$i]; $report=$null; $detail='Before or after capture is unavailable; validation is incomplete.'
        $verdict='Review'
        if ($null -ne $item.Before -and $null -ne $item.After) {
            try {
                $report = Compare-PatchSnapshot $item.Before $item.After -ExpectedVersion $target.ExpectedVersion -VersionField $target.VersionField -ExpectedState $target.ExpectedState -RequireSignedBaseline:$RequireSignedBaseline -RequireValidSignature:$RequireValidSignature -ExpectedPublisher $ExpectedPublisher
                $verdict=$report.Verdict; $detail=$report.Summary
                $report.Before=ConvertTo-PatchSnapshotData $item.Before; $report.After=ConvertTo-PatchSnapshotData $item.After
            } catch { $verdict='Review';$report=$null;$detail='Snapshot validation or target identity checks failed; this item cannot pass.' }
        }
        $results += [pscustomobject]@{Target=$target;Verdict=$verdict;Detail=$detail;Report=$report}
    }
    $overall = if (@($results | Where-Object Verdict -eq 'Fail').Count) { 'Fail' } elseif (@($results | Where-Object Verdict -eq 'Review').Count) { 'Review' } else { 'Pass' }
    Write-PatchEvidence -Document ([pscustomobject]@{DocumentType='PatchValidatorBatchReport';SchemaVersion=1;Verdict=$overall;Items=$results}) -Path $Path -SigningCertificate $SigningCertificate -RequireSignature:$RequireSignature
}
function Read-PatchBatchReport {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path,[string[]]$TrustedSignerThumbprint,[switch]$RequireSignature)
    $evidence=Read-PatchEvidence -Path $Path -TrustedSignerThumbprint $TrustedSignerThumbprint -RequireSignature:$RequireSignature
    $doc=$evidence.Document
    if ($doc.DocumentType -ne 'PatchValidatorBatchReport' -or $doc.SchemaVersion -ne 1) { throw 'Invalid batch report format.' }
    [void]@(Assert-PatchBatchTargets @($doc.Items | ForEach-Object { $_.Target }))
    $doc | Add-Member EvidenceVerification $evidence.Status -Force
    if ($evidence.Status -ne 'Verified') {
        $doc.Verdict='Review'
        foreach ($item in $doc.Items) { $item.Verdict='Review';$item.Detail='Report integrity is unverified.'; if ($item.Report) { $item.Report.Verdict='Review'; $item.Report.Summary='Report integrity is unverified.' } }
    }
    return $doc
}
