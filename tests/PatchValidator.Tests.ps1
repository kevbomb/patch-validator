Import-Module (Join-Path $PSScriptRoot '..\PatchValidator.psd1') -Force

# Pester 3's legacy Should Throw is incompatible with some PowerShell 7 releases.
function Assert-TestThrows {
    param([Parameter(ValueFromPipeline)][scriptblock]$Action)
    process {
        $didThrow = $false
        try { & $Action | Out-Null } catch { $didThrow = $true }
        $didThrow | Should Be $true
    }
}

function New-TestSnapshot {
    param([hashtable]$Changes = @{})
    $values = [ordered]@{
        SchemaVersion=1;CapturedAtUtc='2026-01-01T10:00:00Z';ComputerName='SERVER1'
        ServiceName='ExampleService';DisplayName='Example service';State='Running';StartMode='Auto'
        ProcessId=100;ProcessStartedAtUtc='2026-01-01T09:00:00Z';ExecutablePath='C:\App\service.exe'
        VersionPath='C:\App\service.exe';VersionSource='Service executable';ProductName='Example';CompanyName='Example'
        ProductVersion='1.0.0';FileVersion='1.0.0.0';FileSha256=('A' * 64)
        FileModifiedAtUtc='2026-01-01T08:00:00Z';SelectionReliable=$true;Notes=@()
    }
    foreach ($key in $Changes.Keys) { $values[$key] = $Changes[$key] }
    [pscustomobject]$values
}
function New-TestAfter {
    param([hashtable]$Changes = @{})
    $values = @{
        CapturedAtUtc='2026-01-01T10:10:00Z';ProductVersion='1.1.0';FileVersion='1.1.0.0'
        FileSha256=('B' * 64);ProcessId=200;ProcessStartedAtUtc='2026-01-01T10:05:00Z'
    }
    foreach ($key in $Changes.Keys) { $values[$key] = $Changes[$key] }
    New-TestSnapshot $values
}

Describe 'Before and after validation' {
    It 'passes when target, stable state, and restarted process agree' {
        $result = Compare-PatchSnapshot (New-TestSnapshot) (New-TestAfter) -ExpectedVersion '1.1.0'
        $result.Verdict | Should Be 'Pass'
        $result.VersionField | Should Be 'ProductVersion'
    }
    It 'normalizes dotted numeric versions without lexical ordering' {
        $result = Compare-PatchSnapshot (New-TestSnapshot @{ProductVersion='1.9'}) (New-TestAfter @{ProductVersion='1.10'}) -ExpectedVersion '1.10.0.0'
        $result.Verdict | Should Be 'Pass'
    }
    It 'does not erase prerelease suffixes when matching an expected version' {
        $result = Compare-PatchSnapshot (New-TestSnapshot) (New-TestAfter @{ProductVersion='1.1.0-beta'}) -ExpectedVersion '1.1.0'
        $result.Verdict | Should Be 'Fail'
    }
    It 'reports changes but requires review without an expected target' {
        $result = Compare-PatchSnapshot (New-TestSnapshot) (New-TestAfter)
        $result.Verdict | Should Be 'Review'
        ($result.Checks | Where-Object Check -eq 'Version change').Result | Should Be 'Pass'
    }
    It 'fails when the service stopped unexpectedly' {
        $result = Compare-PatchSnapshot (New-TestSnapshot) (New-TestAfter @{State='Stopped';ProcessId=0;ProcessStartedAtUtc=$null}) -ExpectedVersion '1.1.0'
        $result.Verdict | Should Be 'Fail'
    }
    It 'supports a service intentionally stopped before and after patching' {
        $result = Compare-PatchSnapshot (New-TestSnapshot @{State='Stopped'}) (New-TestAfter @{State='Stopped';ProcessId=0;ProcessStartedAtUtc=$null}) -ExpectedVersion '1.1.0'
        $result.Verdict | Should Be 'Pass'
    }
    It 'allows an explicit expected state different from baseline' {
        $result = Compare-PatchSnapshot (New-TestSnapshot @{State='Stopped'}) (New-TestAfter) -ExpectedVersion '1.1.0' -ExpectedState Running
        $result.Verdict | Should Be 'Pass'
    }
    It 'fails if the observed version does not match the target' {
        (Compare-PatchSnapshot (New-TestSnapshot) (New-TestAfter) -ExpectedVersion '2.0').Verdict | Should Be 'Fail'
    }
    It 'does not call an unchanged version a successful new patch' {
        $result = Compare-PatchSnapshot (New-TestSnapshot) (New-TestAfter @{ProductVersion='1.0.0'}) -ExpectedVersion '1.0.0'
        $result.Verdict | Should Be 'Review'
    }
    It 'can validate file version when product version does not change' {
        $result = Compare-PatchSnapshot (New-TestSnapshot) (New-TestAfter @{ProductVersion='1.0.0'}) -ExpectedVersion '1.1.0.0' -VersionField FileVersion
        $result.Verdict | Should Be 'Pass'
    }
    It 'falls back to file version only when product version is absent in both' {
        $result = Compare-PatchSnapshot (New-TestSnapshot @{ProductVersion=$null}) (New-TestAfter @{ProductVersion=$null}) -ExpectedVersion '1.1'
        $result.VersionField | Should Be 'FileVersion'
        $result.Verdict | Should Be 'Pass'
    }
    It 'requires review for missing version metadata' {
        $result = Compare-PatchSnapshot (New-TestSnapshot) (New-TestAfter @{ProductVersion=$null;FileVersion=$null}) -ExpectedVersion '1.1'
        $result.Verdict | Should Be 'Review'
    }
    It 'requires review when the component changed without a process restart' {
        $result = Compare-PatchSnapshot (New-TestSnapshot) (New-TestAfter @{ProcessStartedAtUtc='2026-01-01T09:00:00Z';ProcessId=100}) -ExpectedVersion '1.1'
        $result.Verdict | Should Be 'Review'
        ($result.Checks | Where-Object Check -eq 'Process restart').Result | Should Be 'Review'
    }
    It 'does not infer a restart from a different process ID alone' {
        $result = Compare-PatchSnapshot (New-TestSnapshot) (New-TestAfter @{ProcessStartedAtUtc=$null}) -ExpectedVersion '1.1'
        $result.Verdict | Should Be 'Review'
    }
    It 'does not infer a restart when a service returns the old process start time' {
        $result = Compare-PatchSnapshot (New-TestSnapshot) (New-TestAfter @{ProcessId=999;ProcessStartedAtUtc='2026-01-01T09:00:00Z'}) -ExpectedVersion '1.1'
        $result.Verdict | Should Be 'Review'
    }
    It 'requires review if the process restarted before the component was modified' {
        $result = Compare-PatchSnapshot (New-TestSnapshot) (New-TestAfter @{FileModifiedAtUtc='2026-01-01T10:06:00Z'}) -ExpectedVersion '1.1'
        $result.Verdict | Should Be 'Review'
        ($result.Checks | Where-Object Check -eq 'Process restart').Result | Should Be 'Review'
    }
    It 'requires review when an automatic version source changes' {
        $result = Compare-PatchSnapshot (New-TestSnapshot) (New-TestAfter @{VersionPath='C:\Other\service.exe'}) -ExpectedVersion '1.1'
        $result.Verdict | Should Be 'Review'
    }
    It 'requires review for collection warnings and unreliable metadata' {
        $result = Compare-PatchSnapshot (New-TestSnapshot) (New-TestAfter @{SelectionReliable=$false;Notes=@('File changed during capture.')}) -ExpectedVersion '1.1'
        $result.Verdict | Should Be 'Review'
    }
    It 'fails on a numerical version decrease' {
        $result = Compare-PatchSnapshot (New-TestSnapshot @{ProductVersion='2.0'}) (New-TestAfter) -ExpectedVersion '1.1'
        $result.Verdict | Should Be 'Fail'
    }
    It 'rejects comparisons across different computers' {
        { Compare-PatchSnapshot (New-TestSnapshot) (New-TestAfter @{ComputerName='SERVER2'}) } | Assert-TestThrows
    }
    It 'rejects comparisons across different services' {
        { Compare-PatchSnapshot (New-TestSnapshot) (New-TestAfter @{ServiceName='Other'}) } | Assert-TestThrows
    }
    It 'rejects an older or identical after capture timestamp' {
        { Compare-PatchSnapshot (New-TestSnapshot) (New-TestAfter @{CapturedAtUtc='2026-01-01T10:00:00Z'}) } | Assert-TestThrows
    }
    It 'does not pass a transitional state captured as a baseline' {
        $result = Compare-PatchSnapshot (New-TestSnapshot @{State='Start Pending'}) (New-TestAfter) -ExpectedVersion '1.1'
        $result.Verdict | Should Be 'Review'
    }
}

Describe 'Snapshot persistence' {
    It 'round trips a baseline as JSON' {
        $path = Join-Path $TestDrive 'baseline.json'
        Save-PatchSnapshot (New-TestSnapshot) $path
        $loaded = Read-PatchSnapshot $path
        $loaded.ServiceName | Should Be 'ExampleService'
        $loaded.ProductVersion | Should Be '1.0.0'
        $loaded.SelectionReliable | Should Be $true
        $loaded.CapturedAtUtc | Should Be '2026-01-01T10:00:00Z'
        ($loaded.CapturedAtUtc -is [string]) | Should Be $true
        (Compare-PatchSnapshot $loaded (New-TestAfter) -ExpectedVersion '1.1').Verdict | Should Be 'Pass'
    }
    It 'replaces an existing snapshot without leaving a temporary file' {
        $path = Join-Path $TestDrive 'replace.json'
        Save-PatchSnapshot (New-TestSnapshot) $path
        Save-PatchSnapshot (New-TestAfter) $path
        (Read-PatchSnapshot $path).ProductVersion | Should Be '1.1.0'
    }
    It 'rejects malformed and foreign JSON files' {
        $path = Join-Path $TestDrive 'invalid.json'
        [IO.File]::WriteAllText($path,'{"DocumentType":"Other","SchemaVersion":1}')
        { Read-PatchSnapshot $path } | Assert-TestThrows
        [IO.File]::WriteAllText($path,'not json')
        { Read-PatchSnapshot $path } | Assert-TestThrows
    }
    It 'rejects incomplete snapshot data' {
        { Save-PatchSnapshot ([pscustomobject]@{SchemaVersion=1}) (Join-Path $TestDrive 'missing.json') } | Assert-TestThrows
    }
    It 'rejects invalid timestamps and reliability flags' {
        { Save-PatchSnapshot (New-TestSnapshot @{CapturedAtUtc='yesterday'}) (Join-Path $TestDrive 'date.json') } | Assert-TestThrows
        { Save-PatchSnapshot (New-TestSnapshot @{SelectionReliable='true'}) (Join-Path $TestDrive 'flag.json') } | Assert-TestThrows
    }
    It 'exports both evidence snapshots and the comparison settings' {
        $path = Join-Path $TestDrive 'report.json'
        $report = Compare-PatchSnapshot (New-TestSnapshot) (New-TestAfter) -ExpectedVersion '1.1'
        Save-PatchReport $report $path
        $loaded = [IO.File]::ReadAllText($path) | ConvertFrom-Json
        $loaded.DocumentType | Should Be 'PatchValidatorReport'
        $loaded.Before.ProductVersion | Should Be '1.0.0'
        $loaded.After.ProductVersion | Should Be '1.1.0'
        $loaded.ExpectedVersion | Should Be '1.1'
    }
}
