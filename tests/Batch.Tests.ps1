Import-Module (Join-Path $PSScriptRoot '..\PatchValidator.psd1') -Force
function Assert-BatchThrows {
    [CmdletBinding()] param([Parameter(ValueFromPipeline)][scriptblock]$Action)
    process { $caught=$false;try { & $Action | Out-Null } catch { $caught=$true };$caught | Should Be $true }
}
function New-BatchFixture([switch]$After) {
    $snapshot=[pscustomobject]@{
        SchemaVersion=1;CapturedAtUtc='2026-01-01T10:00:00Z';ComputerName='SERVER1';ComputerIdentity='11111111-1111-1111-1111-111111111111'
        ServiceName='Svc1';DisplayName='Service 1';State='Running';StartMode='Auto';ProcessId=100
        ProcessStartedAtUtc='2026-01-01T09:00:00Z';ExecutablePath='C:\App\svc.exe';VersionPath='C:\App\svc.exe';VersionSource='Service executable'
        ProductName='Example';CompanyName='Example';ProductVersion='1.0';FileVersion='1.0';FileSha256=('A'*64)
        FileModifiedAtUtc='2026-01-01T08:00:00Z';SelectionReliable=$true;Notes=@()
    }
    if ($After) { $snapshot.CapturedAtUtc='2026-01-01T11:00:00Z';$snapshot.ProcessStartedAtUtc='2026-01-01T10:30:00Z';$snapshot.ProductVersion='2.0';$snapshot.FileVersion='2.0';$snapshot.FileSha256=('B'*64) }
    return $snapshot
}
Describe 'CSV host and service plans' {
    It 'combines two hosts and two services into four explicit pairs' {
        $plan=@(New-PatchBatchPlan @('a.example.com','b.example.com') @('Svc1','Svc2'))
        $plan.Count | Should Be 4
        $plan[2].ComputerName | Should Be b.example.com
        $plan[2].ServiceName | Should Be Svc1
    }
    It 'supports one host with many services and many hosts with one service' {
        @(New-PatchBatchPlan @('a') @('one','two')).Count | Should Be 2
        @(New-PatchBatchPlan @('a','b') @('one')).Count | Should Be 2
        @(New-PatchBatchPlan @('a') @('one')).Count | Should Be 1
    }
    It 'imports only display names and automatically defaults discovery settings' {
        $path=Join-Path $TestDrive 'services.csv'
        [IO.File]::WriteAllText($path,"DisplayName`r`n`"Service, one`"`r`nWindows Event Log")
        $services=@(Import-PatchServiceCsv $path)
        $plan=@(New-PatchBatchPlan @('a') $services)
        $plan[0].ServiceName | Should Be 'Service, one'
        $plan[1].ServiceName | Should Be 'Windows Event Log'
        $plan.Count | Should Be 2
        [string]::IsNullOrEmpty($plan[0].VersionFile) | Should Be $true
        [string]::IsNullOrEmpty($plan[0].ExpectedVersion) | Should Be $true
        $plan[0].VersionField | Should Be Auto
        $plan[0].ExpectedState | Should Be 'Same as before'
    }
    It 'rejects service CSVs with extra settings or without the DisplayName header' {
        $path=Join-Path $TestDrive 'displaynames.csv'
        foreach ($text in @("DisplayName,ExpectedVersion`nWindows Event Log,1.0","ServiceName`nEventLog","DisplayName,DisplayName`none,two",'DisplayName')) {
            [IO.File]::WriteAllText($path,$text)
            { Import-PatchServiceCsv $path } | Assert-BatchThrows
        }
    }
    It 'imports UTF8 BOM and ignores blank rows' {
        $path=Join-Path $TestDrive 'hosts.csv'
        [IO.File]::WriteAllText($path,"ComputerName`r`n a.example.com `r`n`r`nb.example.com",(New-Object Text.UTF8Encoding($true)))
        $hosts=@(Import-PatchHostCsv $path)
        $hosts.Count | Should Be 2
        $hosts[0].ComputerName | Should Be a.example.com
    }
    It 'rejects missing, duplicate and credential columns' {
        $path=Join-Path $TestDrive 'bad.csv'
        foreach ($text in @("Host`none","ComputerName,ComputerName`none,two","ComputerName,Password`none,secret")) {
            [IO.File]::WriteAllText($path,$text)
            { Import-PatchHostCsv $path } | Assert-BatchThrows
        }
    }
    It 'rejects malformed quoting and wrong field counts' {
        $path=Join-Path $TestDrive 'bad.csv'
        foreach ($text in @("ComputerName`n`"unclosed","ComputerName`none,two")) {
            [IO.File]::WriteAllText($path,$text)
            { Import-PatchHostCsv $path } | Assert-BatchThrows
        }
    }
    It 'rejects empty and header-only files' {
        $path=Join-Path $TestDrive 'empty.csv'
        foreach ($text in @('',"ComputerName`n")) { [IO.File]::WriteAllText($path,$text);{ Import-PatchHostCsv $path } | Assert-BatchThrows }
    }
    It 'rejects blank services, host URLs, wildcards and duplicate pairs' {
        { New-PatchBatchPlan @('server') @(' ') } | Assert-BatchThrows
        { New-PatchBatchPlan @('https://server') @('svc') } | Assert-BatchThrows
        { New-PatchBatchPlan @('*') @('svc') } | Assert-BatchThrows
        { New-PatchBatchPlan @('SERVER','server') @('svc') } | Assert-BatchThrows
        { New-PatchBatchPlan @('server') @('SVC','svc') } | Assert-BatchThrows
    }
    It 'enforces the pair limit and comparison setting values' {
        { New-PatchBatchPlan @('server') @(1..501 | ForEach-Object { 'svc'+$_ }) } | Assert-BatchThrows
        { New-PatchBatchPlan @('server') @([pscustomobject]@{ServiceName='svc';ExpectedState='Anything'}) } | Assert-BatchThrows
    }
}
Describe 'Batch collection isolation' {
    It 'returns a sanitized failed item so another item can still run' {
        Mock Get-PatchSnapshot -ModuleName PatchValidator { throw 'password=DummySecret access denied' }
        $plan=@(New-PatchBatchPlan @('a','b') @('svc'))
        $results=@($plan | ForEach-Object { Get-PatchBatchCapture $_ -Connection @{Authentication='Kerberos'} })
        $results.Count | Should Be 2
        $results[0].Error.Contains('DummySecret') | Should Be $false
        $results[1].Error | Should Match 'authorization'
        Assert-MockCalled Get-PatchSnapshot -ModuleName PatchValidator -Times 2 -Exactly -Scope It
    }
    It 'does not accept credential or script fields from a target as connection options' {
        $target=@(New-PatchBatchPlan @('a') @('svc'))[0]
        { Get-PatchBatchCapture $target -Connection @{ScriptBlock={ 'bad' }} } | Assert-BatchThrows
    }
}
Describe 'Batch baseline and report evidence' {
    BeforeEach {
        $path=Join-Path $TestDrive ([Guid]::NewGuid().ToString()+'.json')
        $target=@(New-PatchBatchPlan @('server1.example.com') @([pscustomobject]@{ServiceName='Svc1';ExpectedVersion='2.0'}))[0]
        $items=@([pscustomobject]@{Target=$target;Before=(New-BatchFixture);After=(New-BatchFixture -After)})
    }
    It 'round trips unsigned baselines without losing the connection FQDN or target settings' {
        Save-PatchBatchBaseline $items $path
        $loaded=@(Read-PatchBatchBaseline $path)
        $loaded.Count | Should Be 1
        $loaded[0].Target.ComputerName | Should Be server1.example.com
        $loaded[0].Target.ExpectedVersion | Should Be '2.0'
        $loaded[0].Before.EvidenceVerification | Should Be Unsigned
        (Compare-PatchSnapshot $loaded[0].Before $items[0].After -ExpectedVersion 2.0).Verdict | Should Be Review
    }
    It 'retains failed baseline targets so they cannot disappear from a later report' {
        $items[0].Before=$null
        Save-PatchBatchBaseline $items $path
        $loaded=@(Read-PatchBatchBaseline $path)
        $loaded.Count | Should Be 1
        ($null -eq $loaded[0].Before) | Should Be $true
        Save-PatchBatchReport $loaded $path
        (Read-PatchBatchReport $path).Items[0].Verdict | Should Be Review
    }
    It 'does not serialize arbitrary credential fields' {
        $items[0] | Add-Member Credential 'DummySecret'
        $items[0].Target | Add-Member Password 'DummySecret'
        Save-PatchBatchBaseline $items $path
        ([IO.File]::ReadAllText($path)).Contains('DummySecret') | Should Be $false
        Save-PatchBatchReport $items $path
        ([IO.File]::ReadAllText($path)).Contains('DummySecret') | Should Be $false
    }
    It 'requires the configured signing key and rejects the wrong evidence format' {
        { Save-PatchBatchBaseline $items $path -RequireSignature } | Assert-BatchThrows
        (Test-Path $path) | Should Be $false
        Save-PatchSnapshot $items[0].Before $path
        { Read-PatchBatchBaseline $path } | Assert-BatchThrows
    }
    It 'verifies signed batch evidence and rejects modified signatures' {
        $key=New-Object Security.Cryptography.RSACng(2048)
        $request=New-Object Security.Cryptography.X509Certificates.CertificateRequest('CN=Batch Test',$key,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $cert=$request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1),[DateTimeOffset]::UtcNow.AddHours(1))
        try {
            Save-PatchBatchBaseline $items $path -SigningCertificate $cert -RequireSignature
            $loaded=@(Read-PatchBatchBaseline $path -TrustedSignerThumbprint $cert.Thumbprint -RequireSignature)
            $loaded[0].Before.EvidenceVerification | Should Be Verified
            { Read-PatchBatchBaseline $path -TrustedSignerThumbprint ('0'*40) -RequireSignature } | Assert-BatchThrows
            $loaded[0].After=$items[0].After
            Save-PatchBatchReport $loaded $path -SigningCertificate $cert -RequireSignature -RequireSignedBaseline
            (Read-PatchBatchReport $path -TrustedSignerThumbprint $cert.Thumbprint -RequireSignature).Verdict | Should Be Pass
            $loaded[0].Before.ProductVersion='9.0'
            { Save-PatchBatchBaseline $loaded $path -SigningCertificate $cert } | Assert-BatchThrows
            { Read-PatchBatchReport $path -TrustedSignerThumbprint ('0'*40) -RequireSignature } | Assert-BatchThrows
            $envelope=Get-Content $path -Raw | ConvertFrom-Json
            $bytes=[Convert]::FromBase64String($envelope.Cms);$bytes[$bytes.Length-1]=$bytes[$bytes.Length-1] -bxor 1
            $envelope.Cms=[Convert]::ToBase64String($bytes);[IO.File]::WriteAllText($path,($envelope | ConvertTo-Json))
            { Read-PatchBatchReport $path -TrustedSignerThumbprint $cert.Thumbprint } | Assert-BatchThrows
        } finally { $cert.Dispose();$key.Dispose() }
    }
    It 'recomputes verdicts and never exports a fabricated successful incomplete item' {
        $items[0].After=$null;$items[0] | Add-Member Result Pass
        Save-PatchBatchReport $items $path
        $doc=Get-Content $path -Raw | ConvertFrom-Json
        $doc.Verdict | Should Be Review
        $doc.Items[0].Verdict | Should Be Review
    }
    It 'includes both successful and missing items in the overall verdict' {
        $otherTarget=@(New-PatchBatchPlan @('unavailable.example.com') @('Svc1'))[0]
        $mixedBatchItems=@($items[0],([pscustomobject]@{Target=$otherTarget;Before=$null;After=$null}))
        $mixedBatchItems.Count | Should Be 2
        Save-PatchBatchReport -Items $mixedBatchItems -Path $path
        $doc=Get-Content $path -Raw | ConvertFrom-Json
        $doc.Items.Count | Should Be 2
        $doc.Items[0].Verdict | Should Be Pass
        $doc.Items[1].Verdict | Should Be Review
        $doc.Verdict | Should Be Review
        $loaded=Read-PatchBatchReport $path
        $loaded.Items[0].Verdict | Should Be Review
        $loaded.Items[0].Report.Verdict | Should Be Review
    }
}
