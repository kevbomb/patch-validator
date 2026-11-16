Import-Module (Join-Path $PSScriptRoot '..\PatchValidator.psd1') -Force

Describe 'Remote authentication' {
    BeforeEach {
        $password = ConvertTo-SecureString 'Dummy test password only' -AsPlainText -Force
        $global:PatchValidatorRemoteTest_Credential = New-Object Management.Automation.PSCredential('EXAMPLE\test-user',$password)
        $global:PatchValidatorRemoteTest_Arguments = $null
        Mock Invoke-Command -ModuleName PatchValidator {
            param($ComputerName,$ScriptBlock,$ArgumentList,$SessionOption,$Credential,$UseSSL,$Authentication,$ConfigurationName,$Session)
            $global:PatchValidatorRemoteTest_Arguments = $PSBoundParameters
            [pscustomobject]@{ServiceName='Fixture';State='Running'}
        }
    }
    AfterEach {
        $global:PatchValidatorRemoteTest_Credential.Password.Dispose()
        Remove-Variable -Scope Global -Name PatchValidatorRemoteTest_Credential,PatchValidatorRemoteTest_Arguments -ErrorAction SilentlyContinue
    }
    It 'keeps current identity as the default for a hostname' {
        $result = Get-PatchSnapshot -ServiceName 'Fixture' -ComputerName 'server.example.invalid'
        $result.ServiceName | Should Be Fixture
        $global:PatchValidatorRemoteTest_Arguments.ContainsKey('Credential') | Should Be $false
        $global:PatchValidatorRemoteTest_Arguments.ContainsKey('UseSSL') | Should Be $false
        Assert-MockCalled Invoke-Command -ModuleName PatchValidator -Times 1 -Exactly -Scope It
    }
    It 'passes a credential to WinRM over HTTPS without including it in collector arguments' {
        $result = Get-PatchSnapshot -ServiceName ' Fixture ' -ComputerName '192.0.2.25' -VersionFile 'C:\App\service.dll' -Credential $global:PatchValidatorRemoteTest_Credential -UseSSL
        $arguments = $global:PatchValidatorRemoteTest_Arguments
        $arguments.ComputerName | Should Be '192.0.2.25'
        [object]::ReferenceEquals($arguments.Credential,$global:PatchValidatorRemoteTest_Credential) | Should Be $true
        [bool]$arguments.UseSSL | Should Be $true
        $arguments.ArgumentList.Count | Should Be 2
        $arguments.ArgumentList[0] | Should Be Fixture
        $arguments.ArgumentList[1] | Should Be 'C:\App\service.dll'
        ($result.PSObject.Properties.Name -contains 'Credential') | Should Be $false
        ($arguments.ScriptBlock.ToString().Contains('EXAMPLE\test-user')) | Should Be $false
    }
    It 'supports explicit credentials with existing HTTP remoting settings' {
        Get-PatchSnapshot -ServiceName Fixture -ComputerName '192.0.2.25' -Credential $global:PatchValidatorRemoteTest_Credential | Out-Null
        $global:PatchValidatorRemoteTest_Arguments.Credential.UserName | Should Be 'EXAMPLE\test-user'
        $global:PatchValidatorRemoteTest_Arguments.ContainsKey('UseSSL') | Should Be $false
    }
    It 'requires explicit credentials for an IP before making a connection' {
        foreach ($address in @('192.0.2.25','2001:db8::25')) {
            $didThrow = $false
            try { Get-PatchSnapshot -ServiceName Fixture -ComputerName $address | Out-Null }
            catch { $didThrow = $_.Exception.Message -like '*requires explicit credentials*' }
            $didThrow | Should Be $true
        }
        Assert-MockCalled Invoke-Command -ModuleName PatchValidator -Times 0 -Exactly -Scope It
    }
    It 'does not silently ignore supplied credentials for a local computer name' {
        Get-PatchSnapshot -ServiceName Fixture -ComputerName localhost -Credential $global:PatchValidatorRemoteTest_Credential | Out-Null
        $global:PatchValidatorRemoteTest_Arguments.ComputerName | Should Be localhost
        $global:PatchValidatorRemoteTest_Arguments.Credential.UserName | Should Be 'EXAMPLE\test-user'
        Assert-MockCalled Invoke-Command -ModuleName PatchValidator -Times 1 -Exactly -Scope It
    }
    It 'keeps service and component text as data rather than executable code' {
        $serviceText = 'Service; this is literal text'
        $fileText = 'C:\App\component $(literal).dll'
        Get-PatchSnapshot -ServiceName $serviceText -VersionFile $fileText -ComputerName 'server.example.invalid' | Out-Null
        $global:PatchValidatorRemoteTest_Arguments.ArgumentList[0] | Should Be $serviceText
        $global:PatchValidatorRemoteTest_Arguments.ArgumentList[1] | Should Be $fileText
        $global:PatchValidatorRemoteTest_Arguments.ScriptBlock.ToString().Contains($serviceText) | Should Be $false
    }
    It 'reports authentication failure without retrying as the current user' {
        Mock Invoke-Command -ModuleName PatchValidator { throw 'Test authentication failure' }
        $didThrow = $false
        try { Get-PatchSnapshot -ServiceName Fixture -ComputerName '192.0.2.25' -Credential $global:PatchValidatorRemoteTest_Credential | Out-Null }
        catch { $didThrow = $_.Exception.Message -eq 'Test authentication failure' }
        $didThrow | Should Be $true
        Assert-MockCalled Invoke-Command -ModuleName PatchValidator -Times 1 -Exactly -Scope It
    }
    It 'explicitly requires Kerberos over HTTP for a domain FQDN' {
        Get-PatchSnapshot Fixture -ComputerName server.example.invalid -Authentication Kerberos | Out-Null
        $global:PatchValidatorRemoteTest_Arguments.Authentication | Should Be Kerberos
        $global:PatchValidatorRemoteTest_Arguments.ContainsKey('UseSSL') | Should Be $false
        $global:PatchValidatorRemoteTest_Arguments.ContainsKey('Credential') | Should Be $false
    }
    It 'never falls back to NTLM after an explicit Kerberos failure' {
        Mock Invoke-Command -ModuleName PatchValidator { throw 'Kerberos SPN failure' }
        $didThrow = $false
        try { Get-PatchSnapshot Fixture -ComputerName server.example.invalid -Authentication Kerberos | Out-Null } catch { $didThrow = $true }
        $didThrow | Should Be $true
        Assert-MockCalled Invoke-Command -ModuleName PatchValidator -Times 1 -Exactly -Scope It -ParameterFilter { $Authentication -eq 'Kerberos' }
        Assert-MockCalled Invoke-Command -ModuleName PatchValidator -Times 1 -Exactly -Scope It
    }
    It 'rejects an IP target when Kerberos is required before connecting' {
        $didThrow = $false
        try { Get-PatchSnapshot Fixture -ComputerName 192.0.2.25 -Authentication Kerberos -Credential $global:PatchValidatorRemoteTest_Credential | Out-Null } catch { $didThrow = $_.Exception.Message -like '*Kerberos requires*' }
        $didThrow | Should Be $true
        Assert-MockCalled Invoke-Command -ModuleName PatchValidator -Times 0 -Exactly -Scope It
    }
    It 'requires HTTPS for explicit Negotiate and retains certificate checks' {
        $didThrow = $false
        try { Get-PatchSnapshot Fixture -ComputerName server.example.invalid -Authentication Negotiate | Out-Null } catch { $didThrow = $true }
        $didThrow | Should Be $true
        Get-PatchSnapshot Fixture -ComputerName server.example.invalid -Authentication Negotiate -UseSSL | Out-Null
        $arguments = $global:PatchValidatorRemoteTest_Arguments
        $arguments.Authentication | Should Be Negotiate
        [bool]$arguments.UseSSL | Should Be $true
        $arguments.SessionOption.SkipCACheck | Should Be $false
        $arguments.SessionOption.SkipCNCheck | Should Be $false
        $arguments.SessionOption.SkipRevocationCheck | Should Be $false
        $arguments.ContainsKey('AllowRedirection') | Should Be $false
        Assert-MockCalled Invoke-Command -ModuleName PatchValidator -Times 1 -Exactly -Scope It
    }
    It 'does not retry a certificate failure over HTTP' {
        Mock Invoke-Command -ModuleName PatchValidator { throw 'SSL certificate name mismatch' }
        $didThrow = $false
        try { Get-PatchSnapshot Fixture -ComputerName server.example.invalid -Authentication Negotiate -UseSSL | Out-Null } catch { $didThrow = $true }
        $didThrow | Should Be $true
        Assert-MockCalled Invoke-Command -ModuleName PatchValidator -Times 1 -Exactly -Scope It -ParameterFilter { $UseSSL }
    }
    It 'passes a configured endpoint and optional signature check as data' {
        Get-PatchSnapshot Fixture -ComputerName server.example.invalid -Authentication Kerberos -ConfigurationName ApprovedFullLanguage -CheckAuthenticode | Out-Null
        $global:PatchValidatorRemoteTest_Arguments.ConfigurationName | Should Be ApprovedFullLanguage
        $global:PatchValidatorRemoteTest_Arguments.ArgumentList[2] | Should Be $true
    }
    It 'uses an existing authorized session without reconnecting or changing its authentication' {
        # Uninitialized typed fixture: this tests dispatch only, not a live JEA/WinRM session.
        $session = [Runtime.Serialization.FormatterServices]::GetUninitializedObject([Management.Automation.Runspaces.PSSession])
        Get-PatchSnapshot Fixture -Session $session | Out-Null
        [object]::ReferenceEquals($session,$global:PatchValidatorRemoteTest_Arguments.Session[0]) | Should Be $true
        $global:PatchValidatorRemoteTest_Arguments.ContainsKey('ComputerName') | Should Be $false
        $global:PatchValidatorRemoteTest_Arguments.ContainsKey('Authentication') | Should Be $false
    }
}
