Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
. (Join-Path $PSScriptRoot '..\SecurityDialog.ps1')
Describe 'Security settings dialog' {
    BeforeEach {
        $settings = [pscustomobject]@{Authentication='Kerberos';ConfigurationName='';CheckAuthenticode=$false;RequireValidSignature=$false;ExpectedPublisher='';SigningCertificateThumbprint='';TrustedSignerThumbprint=@();RequireSignedEvidence=$false}
        $prompt = New-PatchSecurityDialog $settings
    }
    AfterEach { $prompt.Form.Dispose() }
    It 'exposes the configured authentication and evidence settings' {
        $prompt.Controls.Authentication.Text | Should Be Kerberos
        $prompt.Controls.Count | Should Be 8
        $prompt.Controls.RequireSignedEvidence.Checked | Should Be $false
    }
    It 'leaves settings unchanged when cancelled' {
        $prompt.Form.DialogResult='Cancel'
        ($null -eq (Read-PatchSecurityDialog $prompt)) | Should Be $true
    }
    It 'normalizes signer thumbprints and enables collection for a publisher policy' {
        $prompt.Controls.TrustedSignerThumbprint.Text=('a'*40)+','+('b'*40)
        $prompt.Controls.ExpectedPublisher.Text='CN=Example Publisher'
        $prompt.Form.DialogResult='OK'
        $result=Read-PatchSecurityDialog $prompt
        $result.TrustedSignerThumbprint.Count | Should Be 2
        $result.TrustedSignerThumbprint[0] | Should Be ('A'*40)
        $result.CheckAuthenticode | Should Be $true
    }
    It 'rejects malformed certificate identifiers and missing required pins' {
        $prompt.Form.DialogResult='OK'
        $prompt.Controls.SigningCertificateThumbprint.Text='not-a-certificate'
        $failed=$false
        try { Read-PatchSecurityDialog $prompt | Out-Null } catch { $failed=$true }
        $failed | Should Be $true
        $prompt.Controls.SigningCertificateThumbprint.Text=''
        $prompt.Controls.RequireSignedEvidence.Checked=$true
        $failed=$false
        try { Read-PatchSecurityDialog $prompt | Out-Null } catch { $failed=$true }
        $failed | Should Be $true
    }
}
