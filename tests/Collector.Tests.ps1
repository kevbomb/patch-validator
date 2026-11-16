$collectorScript = Join-Path $PSScriptRoot '..\Collect-Service.ps1'

Describe 'Service component discovery' {
    AfterEach {
        # Pester 3's mocks execute in the collector's script scope; share only these fixtures.
        Remove-Variable -Scope Global -Name PatchValidatorTest_fixtureExe,PatchValidatorTest_fixtureDll,PatchValidatorTest_collectorService,PatchValidatorTest_collectorProcess,PatchValidatorTest_serviceReads,PatchValidatorTest_changeState -ErrorAction SilentlyContinue
    }
    BeforeEach {
        $global:PatchValidatorTest_fixtureExe = Join-Path $env:SystemRoot 'System32\winver.exe'
        $global:PatchValidatorTest_fixtureDll = Join-Path $env:SystemRoot 'System32\comdlg32.dll'
        $global:PatchValidatorTest_collectorService = [pscustomobject]@{
            Name='Fixture';DisplayName='Fixture display';State='Stopped';StartMode='Manual'
            ProcessId=0;PathName=('"{0}" --service' -f $global:PatchValidatorTest_fixtureExe)
        }
        $global:PatchValidatorTest_collectorProcess = $null
        $global:PatchValidatorTest_serviceReads = 0
        $global:PatchValidatorTest_changeState = $false
        Mock Get-CimInstance {
            param($ClassName)
            if ($ClassName -eq 'Win32_Process') { return $global:PatchValidatorTest_collectorProcess }
            $global:PatchValidatorTest_serviceReads++
            if ($global:PatchValidatorTest_changeState -and $global:PatchValidatorTest_serviceReads -gt 1) {
                $changed = $global:PatchValidatorTest_collectorService.PSObject.Copy()
                $changed.State = 'Running'
                return $changed
            }
            return $global:PatchValidatorTest_collectorService
        }
        Mock Get-ItemProperty {
            param($Name)
            if ($Name -eq 'MachineGuid') { return [pscustomobject]@{MachineGuid='11111111-1111-1111-1111-111111111111'} }
            [pscustomobject]@{ServiceDll=$global:PatchValidatorTest_fixtureDll}
        }
    }

    It 'automatically reads metadata from a quoted executable without launching it' {
        $snapshot = & $collectorScript -ServiceName Fixture
        $snapshot.VersionPath | Should Be $global:PatchValidatorTest_fixtureExe
        $snapshot.ProductVersion | Should Be ([Diagnostics.FileVersionInfo]::GetVersionInfo($global:PatchValidatorTest_fixtureExe).ProductVersion)
        $snapshot.SelectionReliable | Should Be $true
        $snapshot.FileSha256.Length | Should Be 64
    }
    It 'accepts an exact display name case insensitively' {
        (& $collectorScript -ServiceName 'FIXTURE DISPLAY').ServiceName | Should Be Fixture
    }
    It 'rejects wildcard names instead of inspecting an unintended service' {
        $didThrow = $false
        try { & $collectorScript -ServiceName 'Fix*' | Out-Null } catch { $didThrow = $_.Exception.Message -like '*was not found*' }
        $didThrow | Should Be $true
    }
    It 'expands an unquoted SystemRoot path and removes service arguments' {
        $global:PatchValidatorTest_collectorService.PathName = '\SystemRoot\System32\winver.exe --service'
        (& $collectorScript -ServiceName Fixture).VersionPath | Should Be $global:PatchValidatorTest_fixtureExe
    }
    It 'uses the live process executable if configuration points to an old location' {
        $global:PatchValidatorTest_collectorService.PathName = 'C:\Old\missing.exe'
        $global:PatchValidatorTest_collectorService.State = 'Running'
        $global:PatchValidatorTest_collectorService.ProcessId = 50
        $global:PatchValidatorTest_collectorProcess = [pscustomobject]@{ExecutablePath=$global:PatchValidatorTest_fixtureExe;CreationDate=[DateTime]::UtcNow.AddMinutes(-10)}
        $snapshot = & $collectorScript -ServiceName Fixture
        $snapshot.VersionPath | Should Be $global:PatchValidatorTest_fixtureExe
        [string]::IsNullOrWhiteSpace($snapshot.ProcessStartedAtUtc) | Should Be $false
    }
    It 'resolves shared-host services to their ServiceDll' {
        $global:PatchValidatorTest_collectorService.PathName = '%SystemRoot%\System32\svchost.exe -k LocalService'
        $snapshot = & $collectorScript -ServiceName Fixture
        $snapshot.VersionSource | Should Be 'Service DLL'
        $snapshot.VersionPath | Should Be $global:PatchValidatorTest_fixtureDll
        $snapshot.SelectionReliable | Should Be $true
    }
    It 'does not report a wrapper runtime version as the application version' {
        $global:PatchValidatorTest_collectorService.PathName = 'C:\Runtime\java.exe -jar app.jar'
        $snapshot = & $collectorScript -ServiceName Fixture
        [string]::IsNullOrWhiteSpace($snapshot.ProductVersion) | Should Be $true
        $snapshot.SelectionReliable | Should Be $false
    }
    It 'allows the actual component to be selected for a wrapped service' {
        $global:PatchValidatorTest_collectorService.PathName = 'C:\Runtime\java.exe -jar app.jar'
        $snapshot = & $collectorScript -ServiceName Fixture -VersionFile $global:PatchValidatorTest_fixtureDll
        $snapshot.VersionSource | Should Be 'Selected component'
        $snapshot.VersionPath | Should Be $global:PatchValidatorTest_fixtureDll
        $snapshot.SelectionReliable | Should Be $true
    }
    It 'records an inspection error when the component file is unavailable' {
        $snapshot = & $collectorScript -ServiceName Fixture -VersionFile (Join-Path $TestDrive 'missing.exe')
        $snapshot.SelectionReliable | Should Be $false
        ($snapshot.Notes.Count -gt 0) | Should Be $true
    }
    It 'rejects network component paths before reading a file' {
        $snapshot = & $collectorScript -ServiceName Fixture -VersionFile '\\example.invalid\share\service.exe'
        $snapshot.SelectionReliable | Should Be $false
        ($snapshot.Notes -join ' ') | Should Match 'UNC'
    }
    It 'flags service state changes during collection' {
        $global:PatchValidatorTest_changeState = $true
        $snapshot = & $collectorScript -ServiceName Fixture
        $snapshot.SelectionReliable | Should Be $false
        ($snapshot.Notes -join ' ') | Should Match 'state changed'
    }
    It 'flags an ambiguous unquoted path when no process can resolve it' {
        $global:PatchValidatorTest_collectorService.PathName = 'C:\Program Files\Example\service.exe --service'
        $snapshot = & $collectorScript -ServiceName Fixture
        $snapshot.SelectionReliable | Should Be $false
        ($snapshot.Notes -join ' ') | Should Match 'unquoted spaces'
    }
    It 'does not request Authenticode checks when the option is disabled' {
        Mock Get-AuthenticodeSignature { throw 'Unexpected signature request' }
        (& $collectorScript -ServiceName Fixture).Authenticode.Status | Should Be NotChecked
        Assert-MockCalled Get-AuthenticodeSignature -Times 0 -Exactly -Scope It
    }
    It 'records unsigned and invalid signatures without changing the file or service' {
        Mock Get-AuthenticodeSignature { [pscustomobject]@{Status='NotSigned';SignerCertificate=$null;TimeStamperCertificate=$null} }
        $snapshot = & $collectorScript -ServiceName Fixture -CheckAuthenticode
        $snapshot.Authenticode.Status | Should Be NotSigned
        $snapshot.FileSha256.Length | Should Be 64
        $snapshot.SelectionReliable | Should Be $true
        Mock Get-AuthenticodeSignature { [pscustomobject]@{Status='HashMismatch';SignerCertificate=$null;TimeStamperCertificate=$null} }
        (& $collectorScript -ServiceName Fixture -CheckAuthenticode).Authenticode.Status | Should Be HashMismatch
    }
    It 'records an unavailable signature check without leaking its exception' {
        Mock Get-AuthenticodeSignature { throw 'Dummy sensitive exception contents' }
        $snapshot = & $collectorScript -ServiceName Fixture -CheckAuthenticode
        $snapshot.Authenticode.Status | Should Be Unavailable
        ($snapshot.Notes -join ' ').Contains('Dummy sensitive') | Should Be $false
    }
    It 'does not report reliable mixed metadata while a component is open for writing' {
        $path=Join-Path $TestDrive 'locked.exe'
        [IO.File]::WriteAllText($path,'Fixture only')
        $writer=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite)
        try {
            $snapshot = & $collectorScript -ServiceName Fixture -VersionFile $path
            $snapshot.SelectionReliable | Should Be $false
        } finally { $writer.Dispose() }
    }
}
