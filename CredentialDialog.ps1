# GUI-only credential entry. Credentials never become collector arguments or report data.
function New-PatchCredentialDialog {
    param([string]$UserName)
    $dialog = New-Object Windows.Forms.Form
    $dialog.Text = 'Remote credentials'
    $dialog.ClientSize = New-Object Drawing.Size(530,245)
    $dialog.FormBorderStyle = 'FixedDialog'
    $dialog.MaximizeBox = $false
    $dialog.MinimizeBox = $false
    $dialog.ShowInTaskbar = $false
    $dialog.StartPosition = 'CenterParent'
    $dialog.Font = New-Object Drawing.Font('Segoe UI',10)
    $dialog.AutoScaleMode = 'Dpi'

    $credentialsLayout = New-Object Windows.Forms.TableLayoutPanel
    $credentialsLayout.Dock = 'Fill'
    $credentialsLayout.Padding = New-Object Windows.Forms.Padding(16)
    $credentialsLayout.ColumnCount = 2
    $credentialsLayout.RowCount = 5
    [void]$credentialsLayout.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle('Absolute',100)))
    [void]$credentialsLayout.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle('Percent',100)))
    $dialog.Controls.Add($credentialsLayout)
    $userLabel = New-Object Windows.Forms.Label
    $userLabel.Text = 'Username'
    $userLabel.AutoSize = $true
    $userLabel.Anchor = 'Left'
    $userBox = New-Object Windows.Forms.TextBox
    $userBox.Dock = 'Fill'
    $userBox.Text = $UserName
    $passwordLabel = New-Object Windows.Forms.Label
    $passwordLabel.Text = 'Password'
    $passwordLabel.AutoSize = $true
    $passwordLabel.Anchor = 'Left'
    $passwordBox = New-Object Windows.Forms.TextBox
    $passwordBox.Dock = 'Fill'
    $passwordBox.UseSystemPasswordChar = $true
    $credentialsLayout.Controls.Add($userLabel,0,0)
    $credentialsLayout.Controls.Add($userBox,1,0)
    $credentialsLayout.Controls.Add($passwordLabel,0,1)
    $credentialsLayout.Controls.Add($passwordBox,1,1)
    $accountHint = New-Object Windows.Forms.Label
    $accountHint.Text = 'Use DOMAIN\user, user@domain, or SERVER\user.'
    $accountHint.AutoSize = $true
    $accountHint.Margin = New-Object Windows.Forms.Padding(3,10,3,10)
    $credentialsLayout.Controls.Add($accountHint,0,2)
    $credentialsLayout.SetColumnSpan($accountHint,2)
    $storageHint = New-Object Windows.Forms.Label
    $storageHint.Text = 'Used for remote checks in this session only. Not saved to disk.'
    $storageHint.AutoSize = $true
    $credentialsLayout.Controls.Add($storageHint,0,3)
    $credentialsLayout.SetColumnSpan($storageHint,2)
    $credentialButtons = New-Object Windows.Forms.FlowLayoutPanel
    $credentialButtons.FlowDirection = 'RightToLeft'
    $credentialButtons.Dock = 'Fill'
    $credentialButtons.AutoSize = $true
    $confirm = New-Object Windows.Forms.Button
    $confirm.Text = 'Use credentials'
    $confirm.AutoSize = $true
    $confirm.DialogResult = 'OK'
    $cancel = New-Object Windows.Forms.Button
    $cancel.Text = 'Cancel'
    $cancel.AutoSize = $true
    $cancel.DialogResult = 'Cancel'
    $credentialButtons.Controls.AddRange(@($confirm,$cancel))
    $credentialsLayout.Controls.Add($credentialButtons,0,4)
    $credentialsLayout.SetColumnSpan($credentialButtons,2)
    $dialog.AcceptButton = $confirm
    $dialog.CancelButton = $cancel
    [pscustomobject]@{Form=$dialog;UserName=$userBox;Password=$passwordBox;Confirm=$confirm}
}

function Read-PatchCredentialDialog {
    param([Parameter(Mandatory)]$Prompt)
    # Cancellation returns nothing and leaves the existing credential untouched.
    if ($Prompt.Form.DialogResult -ne [Windows.Forms.DialogResult]::OK) { $Prompt.Password.Clear(); return }
    if ([string]::IsNullOrWhiteSpace($Prompt.UserName.Text) -or $Prompt.Password.TextLength -eq 0) {
        $Prompt.Password.Clear()
        throw 'Enter both a username and password. The existing credentials have not been changed.'
    }
    $securePassword = New-Object Security.SecureString
    try {
        foreach ($character in $Prompt.Password.Text.ToCharArray()) { $securePassword.AppendChar($character) }
        $securePassword.MakeReadOnly()
        return New-Object Management.Automation.PSCredential($Prompt.UserName.Text.Trim(),$securePassword)
    } catch { $securePassword.Dispose(); throw }
    finally { $Prompt.Password.Clear() }
}

function Show-PatchCredentialDialog {
    param([Windows.Forms.Form]$Owner,[string]$UserName)
    $prompt = New-PatchCredentialDialog -UserName $UserName
    try {
        [void]$prompt.Form.ShowDialog($Owner)
        Read-PatchCredentialDialog -Prompt $prompt
    } finally { $prompt.Password.Clear(); $prompt.Form.Dispose() }
}
