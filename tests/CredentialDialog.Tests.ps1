Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
. (Join-Path $PSScriptRoot '..\CredentialDialog.ps1')

Describe 'Credential entry' {
    BeforeEach { $prompt = New-PatchCredentialDialog -UserName 'EXAMPLE\test-user' }
    AfterEach { $prompt.Password.Clear(); $prompt.Form.Dispose() }

    It 'masks password input and never prepopulates a password' {
        $prompt.Password.UseSystemPasswordChar | Should Be $true
        $prompt.Password.TextLength | Should Be 0
        $prompt.UserName.Text | Should Be 'EXAMPLE\test-user'
    }
    It 'returns a typed credential and clears the password control after acceptance' {
        $prompt.UserName.Text = ' EXAMPLE\test-user '
        $prompt.Password.Text = ' Dummy password with spaces! '
        $prompt.Form.DialogResult = 'OK'
        $credential = Read-PatchCredentialDialog -Prompt $prompt
        try {
            ($credential -is [Management.Automation.PSCredential]) | Should Be $true
            $credential.UserName | Should Be 'EXAMPLE\test-user'
            $credential.Password.IsReadOnly() | Should Be $true
            $credential.GetNetworkCredential().Password | Should Be ' Dummy password with spaces! '
            $prompt.Password.TextLength | Should Be 0
        } finally { $credential.Password.Dispose() }
    }
    It 'returns nothing on cancellation and clears entered password text' {
        $prompt.Password.Text = 'Dummy password only'
        $prompt.Form.DialogResult = 'Cancel'
        $credential = Read-PatchCredentialDialog -Prompt $prompt
        ($null -eq $credential) | Should Be $true
        $prompt.Password.TextLength | Should Be 0
    }
    It 'rejects an empty username and clears the password' {
        $prompt.UserName.Text = '   '
        $prompt.Password.Text = 'Dummy password only'
        $prompt.Form.DialogResult = 'OK'
        $didThrow = $false
        try { Read-PatchCredentialDialog -Prompt $prompt | Out-Null } catch { $didThrow = $true }
        $didThrow | Should Be $true
        $prompt.Password.TextLength | Should Be 0
    }
    It 'rejects an empty password' {
        $prompt.Form.DialogResult = 'OK'
        $didThrow = $false
        try { Read-PatchCredentialDialog -Prompt $prompt | Out-Null } catch { $didThrow = $true }
        $didThrow | Should Be $true
    }
}
