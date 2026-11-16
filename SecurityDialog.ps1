function New-PatchSecurityDialog {
    param($Settings)
    $dialog = New-Object Windows.Forms.Form
    $dialog.Text = 'Security settings'
    $dialog.ClientSize = New-Object Drawing.Size(760,500)
    $dialog.Font = New-Object Drawing.Font('Segoe UI',10)
    $dialog.FormBorderStyle = 'FixedDialog'
    $dialog.MaximizeBox = $false
    $dialog.MinimizeBox = $false
    $dialog.StartPosition = 'CenterParent'
    $table = New-Object Windows.Forms.TableLayoutPanel
    $table.Dock = 'Fill'
    $table.Padding = New-Object Windows.Forms.Padding(16)
    $table.ColumnCount = 2
    $table.RowCount = 9
    [void]$table.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle('Absolute',245)))
    [void]$table.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle('Percent',100)))
    $dialog.Controls.Add($table)
    $controls = @{}
    $fields = @(
        @('Authentication','Remote authentication','Choice'),
        @('ConfigurationName','Existing endpoint (optional)','Text'),
        @('CheckAuthenticode','Inspect executable signatures','Check'),
        @('RequireValidSignature','Require a valid executable signature','Check'),
        @('ExpectedPublisher','Expected signer subject (exact)','Text'),
        @('SigningCertificateThumbprint','Evidence signing certificate thumbprint','Text'),
        @('TrustedSignerThumbprint','Trusted evidence signer thumbprints','Text'),
        @('RequireSignedEvidence','Require signed baselines and reports','Check')
    )
    $row = 0
    foreach ($field in $fields) {
        $label = New-Object Windows.Forms.Label
        $label.Text = $field[1]
        $label.AutoSize = $true
        $label.Anchor = 'Left'
        $label.Margin = New-Object Windows.Forms.Padding(0,8,8,8)
        if ($field[2] -eq 'Choice') {
            $control = New-Object Windows.Forms.ComboBox
            $control.DropDownStyle = 'DropDownList'
            [void]$control.Items.AddRange(@('Kerberos','Negotiate','Default'))
            $control.SelectedItem = $Settings.Authentication
        } elseif ($field[2] -eq 'Check') {
            $control = New-Object Windows.Forms.CheckBox
            $control.Checked = [bool]$Settings.($field[0])
            $control.Anchor = 'Left'
        } else {
            $control = New-Object Windows.Forms.TextBox
            $control.Text = if ($field[0] -eq 'TrustedSignerThumbprint') { $Settings.TrustedSignerThumbprint -join ',' } else { [string]$Settings.($field[0]) }
        }
        $control.Dock = 'Fill'
        $control.Margin = New-Object Windows.Forms.Padding(0,8,0,8)
        $controls[$field[0]] = $control
        $table.Controls.Add($label,0,$row)
        $table.Controls.Add($control,1,$row)
        $row++
    }
    $footer = New-Object Windows.Forms.FlowLayoutPanel
    $footer.Dock = 'Fill'
    $footer.AutoSize = $true
    $footer.FlowDirection = 'TopDown'
    $hint = New-Object Windows.Forms.Label
    $hint.AutoSize = $true
    $hint.MaximumSize = New-Object Drawing.Size(700,0)
    $hint.Text = 'Kerberos: use the server FQDN. Negotiate requires HTTPS. Default preserves legacy WinRM policy and may use NTLM. Signer lists are comma-separated certificate thumbprints; obtain them independently from your administrator. Private keys stay in Current User > Personal.'
    $footer.Controls.Add($hint)
    $buttons = New-Object Windows.Forms.FlowLayoutPanel
    $buttons.AutoSize = $true
    $ok = New-Object Windows.Forms.Button
    $ok.Text = 'Apply'
    $ok.DialogResult = 'OK'
    $cancel = New-Object Windows.Forms.Button
    $cancel.Text = 'Cancel'
    $cancel.DialogResult = 'Cancel'
    $buttons.Controls.AddRange(@($ok,$cancel))
    $footer.Controls.Add($buttons)
    $table.Controls.Add($footer,0,8)
    $table.SetColumnSpan($footer,2)
    $dialog.AcceptButton = $ok
    $dialog.CancelButton = $cancel
    return [pscustomobject]@{Form=$dialog;Controls=$controls}
}

function Read-PatchSecurityDialog {
    param($Prompt)
    if ($Prompt.Form.DialogResult -ne [Windows.Forms.DialogResult]::OK) { return }
    $values = @{}
    foreach ($name in $Prompt.Controls.Keys) {
        $control = $Prompt.Controls[$name]
        $values[$name] = if ($control -is [Windows.Forms.CheckBox]) { $control.Checked } else { $control.Text.Trim() }
    }
    $values.TrustedSignerThumbprint = @($values.TrustedSignerThumbprint -split '[,;\s]+' | Where-Object { $_ } | ForEach-Object { $_.ToUpperInvariant() })
    foreach ($thumbprint in @($values.TrustedSignerThumbprint) + @($values.SigningCertificateThumbprint)) {
        if ($thumbprint -and $thumbprint -notmatch '^[A-Fa-f0-9]{40}$') { throw 'Use 40 hexadecimal characters for each certificate thumbprint.' }
    }
    if ($values.RequireSignedEvidence -and $values.TrustedSignerThumbprint.Count -eq 0) { throw 'Configure at least one independently trusted evidence signer.' }
    if ($values.ExpectedPublisher -or $values.RequireValidSignature) { $values.CheckAuthenticode = $true }
    return [pscustomobject]$values
}

function Show-PatchSecurityDialog {
    param([Windows.Forms.Form]$Owner,$Settings)
    $prompt = New-PatchSecurityDialog $Settings
    try {
        [void]$prompt.Form.ShowDialog($Owner)
        Read-PatchSecurityDialog $prompt
    } finally { $prompt.Form.Dispose() }
}
