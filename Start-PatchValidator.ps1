#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$SmokeTest, [string]$PreviewPath,
    [ValidateSet('Kerberos','Negotiate','Default')][string]$Authentication = 'Kerberos',
    [string]$ConfigurationName,
    [switch]$CheckAuthenticode, [switch]$RequireValidSignature, [string]$ExpectedPublisher,
    [string]$SigningCertificateThumbprint, [string[]]$TrustedSignerThumbprint,
    [switch]$RequireSignedEvidence
)

$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'The desktop client requires Windows.' }
if ([Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    throw 'Start the GUI with powershell.exe -NoProfile -STA -File .\Start-PatchValidator.ps1'
}
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Import-Module (Join-Path $PSScriptRoot 'PatchValidator.psd1') -Force
. (Join-Path $PSScriptRoot 'CredentialDialog.ps1')
. (Join-Path $PSScriptRoot 'SecurityDialog.ps1')
[Windows.Forms.Application]::EnableVisualStyles()

$script:beforeSnapshot = $null
$script:afterSnapshot = $null
$script:comparison = $null
$script:task = $null
$script:baselineSaved = $false
$script:remoteCredential = $null
$script:moduleFile = Join-Path $PSScriptRoot 'PatchValidator.psd1'
$script:security = [pscustomobject]@{
    Authentication=$Authentication;ConfigurationName=$ConfigurationName
    CheckAuthenticode=[bool]($CheckAuthenticode -or $RequireValidSignature -or $ExpectedPublisher)
    RequireValidSignature=[bool]$RequireValidSignature;ExpectedPublisher=$ExpectedPublisher
    SigningCertificateThumbprint=$SigningCertificateThumbprint;TrustedSignerThumbprint=@($TrustedSignerThumbprint)
    RequireSignedEvidence=[bool]$RequireSignedEvidence
}

function New-Label([string]$Text) {
    $label = New-Object Windows.Forms.Label
    $label.Text = $Text
    $label.AutoSize = $true
    $label.Anchor = 'Left'
    $label.Margin = New-Object Windows.Forms.Padding(0,8,12,8)
    return $label
}
function New-Button([string]$Text) {
    $button = New-Object Windows.Forms.Button
    $button.Text = $Text
    $button.AutoSize = $true
    $button.Height = 34
    $button.Padding = New-Object Windows.Forms.Padding(9,4,9,4)
    $button.Margin = New-Object Windows.Forms.Padding(0,4,8,4)
    return $button
}
function New-Input {
    $box = New-Object Windows.Forms.TextBox
    $box.Dock = 'Fill'
    $box.Margin = New-Object Windows.Forms.Padding(0,5,14,5)
    return $box
}
function Show-Problem([string]$Message) {
    [void][Windows.Forms.MessageBox]::Show($form,$Message,'Patch Validator','OK','Error')
}
function Format-Value($Value) {
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return 'Not available' }
    return [string]$Value
}

$form = New-Object Windows.Forms.Form
$form.Text = 'Patch Validator ' + (Get-Module PatchValidator).Version.ToString()
$form.Size = New-Object Drawing.Size(1120,894)
$form.MinimumSize = New-Object Drawing.Size(940,784)
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object Drawing.Font('Segoe UI',10)
$form.BackColor = [Drawing.Color]::FromArgb(245,247,250)
$form.AutoScaleMode = 'Dpi'

$layout = New-Object Windows.Forms.TableLayoutPanel
$layout.Dock = 'Fill'
$layout.Padding = New-Object Windows.Forms.Padding(20)
$layout.ColumnCount = 1
$layout.RowCount = 7
foreach ($height in @(62,273,46,65)) {
    [void]$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,$height)))
}
[void]$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,56)))
[void]$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,44)))
[void]$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,36)))
$form.Controls.Add($layout)

$header = New-Object Windows.Forms.Panel
$header.Dock = 'Fill'
$title = New-Label 'Patch Validator'
$title.Anchor = 'Top,Left'
$title.Font = New-Object Drawing.Font('Segoe UI',22,[Drawing.FontStyle]::Bold)
$title.Location = New-Object Drawing.Point(0,0)
$subtitle = New-Label 'Capture before. Apply the patch. Capture after. Compare the evidence.'
$subtitle.Anchor = 'Top,Left'
$subtitle.Location = New-Object Drawing.Point(2,40)
$subtitle.ForeColor = [Drawing.Color]::FromArgb(80,94,112)
$header.Controls.AddRange(@($title,$subtitle))
$batchButton = New-Button 'Multiple hosts / services...'
$batchButton.Dock = 'Right'
$header.Controls.Add($batchButton)
$batchButton.Add_Click({
    try { & (Join-Path $PSScriptRoot 'Start-BatchValidator.ps1') -Security $script:security -Owner $form }
    catch { Show-Problem (Get-PatchErrorMessage $_) }
})
$layout.Controls.Add($header,0,0)

$settings = New-Object Windows.Forms.TableLayoutPanel
$settings.Dock = 'Fill'
$settings.ColumnCount = 4
$settings.RowCount = 6
for ($row = 0; $row -lt 5; $row++) { [void]$settings.RowStyles.Add((New-Object Windows.Forms.RowStyle('AutoSize'))) }
[void]$settings.RowStyles.Add((New-Object Windows.Forms.RowStyle('Percent',100)))
foreach ($spec in @(@('Absolute',145),@('Percent',50),@('Absolute',148),@('Percent',50))) {
    [void]$settings.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::$($spec[0]),$spec[1])))
}
$computerBox = New-Input
$computerBox.Text = $env:COMPUTERNAME
$serviceBox = New-Input
$targetBox = New-Input
$componentBox = New-Input
$versionChoice = New-Object Windows.Forms.ComboBox
$versionChoice.DropDownStyle = 'DropDownList'
$versionChoice.Dock = 'Fill'
[void]$versionChoice.Items.AddRange(@('Auto','ProductVersion','FileVersion'))
$versionChoice.SelectedIndex = 0
$stateChoice = New-Object Windows.Forms.ComboBox
$stateChoice.DropDownStyle = 'DropDownList'
$stateChoice.Dock = 'Fill'
[void]$stateChoice.Items.AddRange(@('Same as before','Running','Stopped','Paused'))
$stateChoice.SelectedIndex = 0
$settings.Controls.Add((New-Label 'Computer'),0,0)
$settings.Controls.Add($computerBox,1,0)
$settings.Controls.Add((New-Label 'Service name'),2,0)
$settings.Controls.Add($serviceBox,3,0)
$settings.Controls.Add((New-Label 'Expected version'),0,1)
$settings.Controls.Add($targetBox,1,1)
$settings.Controls.Add((New-Label 'Compare version'),2,1)
$settings.Controls.Add($versionChoice,3,1)
$settings.Controls.Add((New-Label 'Expected state'),0,2)
$settings.Controls.Add($stateChoice,1,2)
$settings.Controls.Add((New-Label 'Version file (optional)'),2,2)
$settings.Controls.Add($componentBox,3,2)
$credentialPanel = New-Object Windows.Forms.FlowLayoutPanel
$credentialPanel.Dock = 'Fill'
$credentialPanel.AutoSize = $true
$credentialPanel.WrapContents = $false
$credentialButton = New-Button 'Set credentials...'
$clearCredentialButton = New-Button 'Clear'
$sslChoice = New-Object Windows.Forms.CheckBox
$sslChoice.Text = 'Use HTTPS (5986)'
$sslChoice.AutoSize = $true
$sslChoice.Margin = New-Object Windows.Forms.Padding(4,12,12,4)
$credentialLabel = New-Label 'Current Windows identity'
$credentialLabel.AutoSize = $false
$credentialLabel.AutoEllipsis = $true
$credentialLabel.Width = 300
$credentialLabel.Height = 25
$credentialPanel.Controls.AddRange(@($credentialButton,$clearCredentialButton,$sslChoice,$credentialLabel))
$settings.Controls.Add((New-Label 'Remote account'),0,3)
$settings.Controls.Add($credentialPanel,1,3)
$settings.SetColumnSpan($credentialPanel,3)
$securityPanel = New-Object Windows.Forms.FlowLayoutPanel
$securityPanel.Dock = 'Fill'
$securityPanel.AutoSize = $true
$securityPanel.WrapContents = $false
$securityButton = New-Button 'Security settings...'
$securityLabel = New-Label ''
$securityLabel.AutoSize = $false
$securityLabel.Width = 620
$securityLabel.Height = 30
$securityLabel.AutoEllipsis = $true
$securityPanel.Controls.AddRange(@($securityButton,$securityLabel))
$settings.Controls.Add((New-Label 'Security policy'),0,4)
$settings.Controls.Add($securityPanel,1,4)
$settings.SetColumnSpan($securityPanel,3)
$hint = New-Label 'Use a server FQDN with Kerberos. For IP/local-account connections, select Negotiate in Security settings, credentials, and HTTPS.'
$hint.ForeColor = [Drawing.Color]::FromArgb(80,94,112)
$hint.AutoSize = $false
$hint.Dock = 'Fill'
$settings.Controls.Add($hint,0,5)
$settings.SetColumnSpan($hint,4)
$layout.Controls.Add($settings,0,1)

$buttons = New-Object Windows.Forms.FlowLayoutPanel
$buttons.Dock = 'Fill'
$buttons.WrapContents = $false
$beforeButton = New-Button '1. Capture before'
$saveButton = New-Button 'Save baseline'
$loadButton = New-Button 'Load baseline'
$afterButton = New-Button '2. Capture after'
$reportButton = New-Button 'Export report'
$resetButton = New-Button 'New comparison'
$buttons.Controls.AddRange(@($beforeButton,$saveButton,$loadButton,$afterButton,$reportButton,$resetButton))
$layout.Controls.Add($buttons,0,2)

$resultPanel = New-Object Windows.Forms.Panel
$resultPanel.Dock = 'Fill'
$resultPanel.BackColor = [Drawing.Color]::FromArgb(226,232,240)
$resultLabel = New-Label 'Ready to capture a baseline'
$resultLabel.Anchor = 'Top,Left'
$resultLabel.Font = New-Object Drawing.Font('Segoe UI',13,[Drawing.FontStyle]::Bold)
$resultLabel.Location = New-Object Drawing.Point(12,7)
$resultDetail = New-Label 'Only a service name is required. Save the baseline before applying the patch or restarting.'
$resultDetail.Anchor = 'Top,Left'
$resultDetail.Location = New-Object Drawing.Point(12,35)
$resultPanel.Controls.AddRange(@($resultLabel,$resultDetail))
$layout.Controls.Add($resultPanel,0,3)

$snapshotGrid = New-Object Windows.Forms.DataGridView
$snapshotGrid.Dock = 'Fill'
$snapshotGrid.ReadOnly = $true
$snapshotGrid.AllowUserToAddRows = $false
$snapshotGrid.AllowUserToDeleteRows = $false
$snapshotGrid.RowHeadersVisible = $false
$snapshotGrid.AutoSizeColumnsMode = 'Fill'
$snapshotGrid.BackgroundColor = [Drawing.Color]::White
$snapshotGrid.BorderStyle = 'None'
$snapshotGrid.SelectionMode = 'FullRowSelect'
$snapshotGrid.AutoSizeRowsMode = 'AllCells'
$snapshotGrid.DefaultCellStyle.WrapMode = 'True'
[void]$snapshotGrid.Columns.Add('Field','Service / component')
[void]$snapshotGrid.Columns.Add('Before','Before patch')
[void]$snapshotGrid.Columns.Add('After','After patch')
$snapshotGrid.Columns[0].FillWeight = 56
$layout.Controls.Add($snapshotGrid,0,4)

$checksGrid = New-Object Windows.Forms.DataGridView
$checksGrid.Dock = 'Fill'
$checksGrid.ReadOnly = $true
$checksGrid.AllowUserToAddRows = $false
$checksGrid.AllowUserToDeleteRows = $false
$checksGrid.RowHeadersVisible = $false
$checksGrid.AutoSizeColumnsMode = 'Fill'
$checksGrid.AutoSizeRowsMode = 'AllCells'
$checksGrid.DefaultCellStyle.WrapMode = 'True'
$checksGrid.BackgroundColor = [Drawing.Color]::White
$checksGrid.BorderStyle = 'None'
[void]$checksGrid.Columns.Add('Check','Validation check')
[void]$checksGrid.Columns.Add('Result','Result')
[void]$checksGrid.Columns.Add('Detail','Evidence / next step')
$checksGrid.Columns[0].FillWeight = 55
$checksGrid.Columns[1].FillWeight = 30
$checksGrid.Columns[2].FillWeight = 160
$layout.Controls.Add($checksGrid,0,5)
$statusLabel = New-Label 'Read-only checks. File versions describe installed files; an application health check may still be needed.'
$statusLabel.ForeColor = [Drawing.Color]::FromArgb(80,94,112)
$statusLabel.Dock = 'Fill'
$layout.Controls.Add($statusLabel,0,6)

$tooltips = New-Object Windows.Forms.ToolTip
$tooltips.SetToolTip($componentBox,'Optional absolute EXE/DLL path on the target computer. Use this for service wrappers or an application-specific component.')
$tooltips.SetToolTip($targetBox,'Optional exact target version. Without it, the report shows changes but cannot confirm a specific patch.')
$tooltips.SetToolTip($versionChoice,'Auto uses ProductVersion when either snapshot has one, otherwise FileVersion. Choose FileVersion if the patch updates only the file version.')
$tooltips.SetToolTip($credentialButton,'Enter DOMAIN\user, user@domain, or SERVER\user and a password. Credentials are kept in memory for this computer only.')
$tooltips.SetToolTip($sslChoice,'Use the existing WinRM HTTPS listener on port 5986. Its certificate must be valid for the computer name or IP entered.')

function Update-Buttons {
    $busy = $null -ne $script:task
    $batchButton.Enabled = -not $busy
    $securityButton.Enabled = -not $busy -and $null -eq $script:beforeSnapshot
    foreach ($control in @($computerBox,$serviceBox,$componentBox)) { $control.Enabled = -not $busy -and $null -eq $script:beforeSnapshot }
    foreach ($control in @($targetBox,$versionChoice,$stateChoice,$loadButton,$resetButton,$credentialButton,$sslChoice)) { $control.Enabled = -not $busy }
    $clearCredentialButton.Enabled = -not $busy -and $null -ne $script:remoteCredential
    $beforeButton.Enabled = -not $busy -and $null -eq $script:beforeSnapshot
    $saveButton.Enabled = -not $busy -and $null -ne $script:beforeSnapshot
    $afterButton.Enabled = -not $busy -and $null -ne $script:beforeSnapshot
    $reportButton.Enabled = -not $busy -and $null -ne $script:comparison
}

function Update-SecuritySummary {
    $evidenceMode = if ($script:security.RequireSignedEvidence) { 'signed evidence required' } else { 'unsigned evidence allowed (unverified)' }
    $script:securityLabel.Text = $script:security.Authentication + '; ' + $evidenceMode
    $tooltips.SetToolTip($securityLabel,'Configure security before capture/loading. Settings are locked until New comparison. Default authentication may use NTLM; Kerberos never falls back.')
}
function Get-GuiSigningCertificate {
    if ($script:security.SigningCertificateThumbprint) { return Get-PatchSigningCertificate -Thumbprint $script:security.SigningCertificateThumbprint }
    return $null
}
$securityButton.Add_Click({
    try {
        $settingsResult = Show-PatchSecurityDialog -Owner $form -Settings $script:security
        if ($null -ne $settingsResult) { $script:security = $settingsResult; Update-SecuritySummary }
    } catch { Show-Problem (Get-PatchErrorMessage $_) }
})
Update-SecuritySummary

function Clear-RemoteCredential {
    if ($null -ne $script:remoteCredential) { $script:remoteCredential.Password.Dispose() }
    $script:remoteCredential = $null
    $credentialLabel.Text = 'Current Windows identity'
    $tooltips.SetToolTip($credentialLabel,'Current Windows identity')
    Update-Buttons
}

$credentialButton.Add_Click({
    try {
        $previousUser = if ($script:remoteCredential) { $script:remoteCredential.UserName } else { '' }
        $enteredCredential = Show-PatchCredentialDialog -Owner $form -UserName $previousUser
        if ($null -ne $enteredCredential) {
            Clear-RemoteCredential
            $script:remoteCredential = $enteredCredential
            $credentialLabel.Text = 'Using: ' + $enteredCredential.UserName
            $tooltips.SetToolTip($credentialLabel,$credentialLabel.Text)
            $statusLabel.Text = 'Remote credentials set for this session. Click Capture before or Capture after to connect.'
            Update-Buttons
        }
    } catch { Show-Problem (Get-PatchErrorMessage $_) }
    finally { $enteredCredential = $null }
})
$clearCredentialButton.Add_Click({ Clear-RemoteCredential; $statusLabel.Text = 'Remote credentials cleared. Checks will use your current Windows identity.' })
$computerBox.Add_TextChanged({ Clear-RemoteCredential })

function Update-Results {
    $snapshotGrid.Rows.Clear()
    $fields = [ordered]@{
        ComputerName='Computer';ServiceName='Service';DisplayName='Display name';CapturedAtUtc='Captured (UTC)'
        State='Service state';StartMode='Startup mode';ProductName='Product';ProductVersion='Product version'
        FileVersion='File version';VersionSource='Version source';VersionPath='Component file'
        ProcessId='Process ID';ProcessStartedAtUtc='Process started (UTC)';FileSha256='SHA-256';ComputerIdentity='Windows machine identity';Notes='Capture notes'
    }
    foreach ($field in $fields.Keys) {
        $beforeValue = if ($script:beforeSnapshot) { Format-Value $script:beforeSnapshot.$field } else { '-' }
        $afterValue = if ($script:afterSnapshot) { Format-Value $script:afterSnapshot.$field } else { '-' }
        if ($field -eq 'Notes') {
            $beforeValue = if ($script:beforeSnapshot) { $script:beforeSnapshot.Notes -join '; ' } else { '-' }
            $afterValue = if ($script:afterSnapshot) { $script:afterSnapshot.Notes -join '; ' } else { '-' }
        }
        [void]$snapshotGrid.Rows.Add($fields[$field],$beforeValue,$afterValue)
    }
    foreach ($signatureField in @('Status','SignerSubject','SignerThumbprint','Publisher','Issuer','NotBeforeUtc','NotAfterUtc','CertificateTimeValid','TimestampSignerSubject')) {
        $beforeValue = if ($script:beforeSnapshot -and $script:beforeSnapshot.PSObject.Properties.Name -contains 'Authenticode') { Format-Value $script:beforeSnapshot.Authenticode.$signatureField } else { 'Not checked' }
        $afterValue = if ($script:afterSnapshot -and $script:afterSnapshot.PSObject.Properties.Name -contains 'Authenticode') { Format-Value $script:afterSnapshot.Authenticode.$signatureField } else { 'Not checked' }
        [void]$snapshotGrid.Rows.Add(('Authenticode: ' + $signatureField),$beforeValue,$afterValue)
    }
    $baselineIntegrity = if ($script:beforeSnapshot -and $script:beforeSnapshot.PSObject.Properties.Name -contains 'EvidenceVerification') { $script:beforeSnapshot.EvidenceVerification } else { 'In-memory capture; not authenticated as saved evidence' }
    [void]$snapshotGrid.Rows.Add('Baseline integrity',$baselineIntegrity,'')
    $checksGrid.Rows.Clear()
    $script:comparison = $null
    if ($script:beforeSnapshot -and $script:afterSnapshot) {
        $script:comparison = Compare-PatchSnapshot -Before $script:beforeSnapshot -After $script:afterSnapshot `
            -ExpectedVersion $targetBox.Text -VersionField ([string]$versionChoice.SelectedItem) -ExpectedState ([string]$stateChoice.SelectedItem) `
            -RequireSignedBaseline:$script:security.RequireSignedEvidence -RequireValidSignature:$script:security.RequireValidSignature -ExpectedPublisher $script:security.ExpectedPublisher
        $resultLabel.Text = $script:comparison.Verdict.ToUpperInvariant() + ' - ' + $script:comparison.Summary
        $resultDetail.Text = 'Comparing ' + $script:comparison.VersionField + '. Export the report to preserve snapshots and validation results.'
        $resultPanel.BackColor = switch ($script:comparison.Verdict) {
            'Pass' { [Drawing.Color]::FromArgb(209,250,229) }
            'Fail' { [Drawing.Color]::FromArgb(254,226,226) }
            default { [Drawing.Color]::FromArgb(254,243,199) }
        }
        foreach ($check in $script:comparison.Checks) {
            $index = $checksGrid.Rows.Add($check.Check,$check.Result,$check.Detail)
            if ($check.Result -eq 'Fail') { $checksGrid.Rows[$index].DefaultCellStyle.ForeColor = [Drawing.Color]::DarkRed }
            elseif ($check.Result -eq 'Review') { $checksGrid.Rows[$index].DefaultCellStyle.ForeColor = [Drawing.Color]::SaddleBrown }
        }
    } elseif ($script:beforeSnapshot) {
        $resultLabel.Text = 'Baseline captured - ready for patching'
        $resultDetail.Text = if ($script:baselineSaved) { 'Baseline saved. Apply the patch, then use Capture after.' } else { 'Save this baseline before patching or restarting so it can be loaded later.' }
        $resultPanel.BackColor = [Drawing.Color]::FromArgb(219,234,254)
    } else {
        $resultLabel.Text = 'Ready to capture a baseline'
        $resultDetail.Text = 'Only a service name is required. Save the baseline before applying the patch or restarting.'
        $resultPanel.BackColor = [Drawing.Color]::FromArgb(226,232,240)
    }
    Update-Buttons
}

function Start-Capture([string]$Stage) {
    if ([string]::IsNullOrWhiteSpace($serviceBox.Text)) { Show-Problem 'Enter an exact service name or display name.'; return }
    if ($null -ne $script:task) { return }
    $worker = [PowerShell]::Create()
    [void]$worker.AddScript({
        param($ModuleFile,$ServiceName,$ComputerName,$VersionFile,$Credential,$UseSSL,$Authentication,$ConfigurationName,$CheckAuthenticode)
        $ErrorActionPreference = 'Stop'
        Import-Module $ModuleFile -Force
        Get-PatchSnapshot -ServiceName $ServiceName -ComputerName $ComputerName -VersionFile $VersionFile -Credential $Credential -UseSSL:$UseSSL -Authentication $Authentication -ConfigurationName $ConfigurationName -CheckAuthenticode:$CheckAuthenticode
    }).AddArgument($script:moduleFile).AddArgument($serviceBox.Text).AddArgument($computerBox.Text).AddArgument($componentBox.Text).AddArgument($script:remoteCredential).AddArgument($sslChoice.Checked).AddArgument($script:security.Authentication).AddArgument($script:security.ConfigurationName).AddArgument($script:security.CheckAuthenticode)
    try {
        if ($Stage -eq 'After') { $script:afterSnapshot = $null; $script:comparison = $null; Update-Results }
        $handle = $worker.BeginInvoke()
        $script:task = [pscustomobject]@{Worker=$worker;Handle=$handle;Stage=$Stage;Started=[DateTime]::UtcNow;Cancelling=$false}
        $statusLabel.Text = 'Reading service status and component metadata...'
        Update-Buttons
    } catch { $worker.Dispose(); Show-Problem (Get-PatchErrorMessage $_) }
}

$beforeButton.Add_Click({ Start-Capture 'Before' })
$afterButton.Add_Click({ Start-Capture 'After' })
$saveButton.Add_Click({
    $dialog = New-Object Windows.Forms.SaveFileDialog
    $dialog.Filter = 'Patch Validator snapshot (*.json)|*.json'
    $dialog.FileName = 'patch-baseline.json'
    try {
        if ($dialog.ShowDialog($form) -eq 'OK') {
            $certificate = Get-GuiSigningCertificate
            Save-PatchSnapshot -Snapshot $script:beforeSnapshot -Path $dialog.FileName -SigningCertificate $certificate -RequireSignature:$script:security.RequireSignedEvidence
            $script:beforeSnapshot = Read-PatchSnapshot -Path $dialog.FileName -TrustedSignerThumbprint $script:security.TrustedSignerThumbprint -RequireSignature:$script:security.RequireSignedEvidence
            $script:baselineSaved = $true
            $statusLabel.Text = 'Baseline saved: ' + $dialog.FileName
            Update-Results
        }
    } catch { Show-Problem (Get-PatchErrorMessage $_) } finally { $dialog.Dispose() }
})
$loadButton.Add_Click({
    if ($script:beforeSnapshot -and -not $script:baselineSaved) {
        if ([Windows.Forms.MessageBox]::Show($form,'Replace the unsaved baseline?','Load baseline','YesNo','Question') -ne 'Yes') { return }
    }
    $dialog = New-Object Windows.Forms.OpenFileDialog
    $dialog.Filter = 'Patch Validator snapshot (*.json)|*.json'
    try {
        if ($dialog.ShowDialog($form) -eq 'OK') {
            $loaded = Read-PatchSnapshot -Path $dialog.FileName -TrustedSignerThumbprint $script:security.TrustedSignerThumbprint -RequireSignature:$script:security.RequireSignedEvidence
            $script:beforeSnapshot = $loaded
            $script:afterSnapshot = $null
            $script:baselineSaved = $true
            $computerBox.Text = $loaded.ComputerName
            $serviceBox.Text = $loaded.ServiceName
            $componentBox.Text = if ($loaded.VersionSource -eq 'Selected component') { $loaded.VersionPath } else { '' }
            $statusLabel.Text = 'Loaded baseline: ' + $dialog.FileName
            Update-Results
        }
    } catch { Show-Problem (Get-PatchErrorMessage $_) } finally { $dialog.Dispose() }
})
$reportButton.Add_Click({
    $dialog = New-Object Windows.Forms.SaveFileDialog
    $dialog.Filter = 'Patch Validator report (*.json)|*.json'
    $dialog.FileName = 'patch-report.json'
    try {
        if ($dialog.ShowDialog($form) -eq 'OK') {
            Save-PatchReport -Report $script:comparison -Path $dialog.FileName -SigningCertificate (Get-GuiSigningCertificate) -RequireSignature:$script:security.RequireSignedEvidence
            $statusLabel.Text = 'Report exported: ' + $dialog.FileName
        }
    } catch { Show-Problem (Get-PatchErrorMessage $_) } finally { $dialog.Dispose() }
})
$resetButton.Add_Click({
    if ($script:beforeSnapshot -and -not $script:baselineSaved) {
        $answer = [Windows.Forms.MessageBox]::Show($form,'Discard the unsaved baseline?','New comparison','YesNo','Question')
        if ($answer -ne 'Yes') { return }
    }
    $script:beforeSnapshot = $null
    $script:afterSnapshot = $null
    $script:baselineSaved = $false
    Clear-RemoteCredential
    $statusLabel.Text = 'Ready for a new comparison.'
    Update-Results
})
foreach ($box in @($targetBox)) { $box.Add_TextChanged({ try { Update-Results } catch { Show-Problem (Get-PatchErrorMessage $_) } }) }
foreach ($choice in @($versionChoice,$stateChoice)) { $choice.Add_SelectedIndexChanged({ try { Update-Results } catch { Show-Problem (Get-PatchErrorMessage $_) } }) }

$timer = New-Object Windows.Forms.Timer
$timer.Interval = 150
$timer.Add_Tick({
    if ($null -eq $script:task) { return }
    if (-not $script:task.Handle.IsCompleted) {
        if (([DateTime]::UtcNow - $script:task.Started).TotalSeconds -gt 60) {
            # Stop asynchronously; never block the UI waiting for a remote host.
            if (-not $script:task.Cancelling) {
                [void]$script:task.Worker.BeginStop($null,$null)
                $script:task.Cancelling = $true
                $statusLabel.Text = 'Capture timed out. Waiting for the read-only query to stop...'
            }
        }
        return
    }
    $completed = $script:task
    $script:task = $null
    try {
        $output = @($completed.Worker.EndInvoke($completed.Handle))
        if ($completed.Worker.HadErrors) { throw ($completed.Worker.Streams.Error | Out-String) }
        if ($completed.Cancelling) { throw 'Capture timed out. Check the computer name, permissions, and remoting connection.' }
        if ($output.Count -ne 1) { throw 'The collector did not return one service snapshot.' }
        if ($completed.Stage -eq 'Before') {
            $script:beforeSnapshot = $output[0]
            $script:afterSnapshot = $null
            $script:baselineSaved = $false
            $serviceBox.Text = $script:beforeSnapshot.ServiceName
        } else { $script:afterSnapshot = $output[0] }
        $statusLabel.Text = 'Capture complete. No service or patch configuration was changed.'
        Update-Results
    } catch {
        if ($completed.Stage -eq 'After') { $script:afterSnapshot = $null; $script:comparison = $null }
        Update-Results
        $statusLabel.Text = 'Capture failed. Check the service/computer name and read permissions.'
        Show-Problem (Get-PatchErrorMessage $_)
    } finally { $completed.Worker.Dispose(); Update-Buttons }
})
$form.Add_FormClosing({
    param($sender,$eventArgs)
    if ($null -ne $script:task) {
        $eventArgs.Cancel = $true
        [void][Windows.Forms.MessageBox]::Show($form,'A read-only query is still running. Wait for it to finish or time out.','Capture in progress','OK','Information')
    } elseif ($script:beforeSnapshot -and -not $script:baselineSaved -and -not $SmokeTest) {
        if ([Windows.Forms.MessageBox]::Show($form,'Close without saving the baseline?','Unsaved baseline','YesNo','Question') -ne 'Yes') { $eventArgs.Cancel = $true }
    }
})

Update-Results
try {
    if ($SmokeTest) {
        # Instantiate and lay out real widgets without inspecting or modifying a service.
        $form.CreateControl()
        $form.PerformLayout()
        if ($snapshotGrid.Rows.Count -ne 26 -or $beforeButton.Enabled -ne $true -or $afterButton.Enabled -ne $false) { throw 'GUI initialization failed.' }
        if (-not $securityButton.Enabled -or $securityLabel.Text -notmatch $script:security.Authentication) { throw 'GUI security settings were not initialized.' }
        if (-not $batchButton.Enabled -or $batchButton.Right -gt $header.ClientSize.Width) { throw 'Batch launcher is unavailable or outside the header.' }
        if ($versionChoice.SelectedItem -ne 'Auto' -or $stateChoice.SelectedItem -ne 'Same as before') { throw 'GUI comparison defaults were not set.' }
        if (-not $credentialButton.Enabled -or $clearCredentialButton.Enabled -or $sslChoice.Checked) { throw 'GUI credential defaults were not set.' }
        $smokePassword = ConvertTo-SecureString 'Dummy GUI smoke test password' -AsPlainText -Force
        $script:remoteCredential = New-Object Management.Automation.PSCredential('EXAMPLE\test-user',$smokePassword)
        Update-Buttons
        if (-not $clearCredentialButton.Enabled) { throw 'GUI credential clearing is unavailable.' }
        $script:task = [pscustomobject]@{SmokeTest=$true}
        Update-Buttons
        if ($credentialButton.Enabled -or $clearCredentialButton.Enabled -or $sslChoice.Enabled -or $securityButton.Enabled) { throw 'Security settings can change during a capture.' }
        $script:task = $null
        $computerBox.Text = 'example.invalid'
        if ($null -ne $script:remoteCredential -or $clearCredentialButton.Enabled) { throw 'Credentials were retained when switching computers.' }
        $computerBox.Text = $env:COMPUTERNAME
        if ($PreviewPath) {
            # A detached visible control tree can render without displaying a window.
            $layout.Font = $form.Font
            $layout.BackColor = $form.BackColor
            $layout.Parent = $null
            $layout.Size = $form.ClientSize
            $layout.CreateControl()
            $layout.PerformLayout()
            $bitmap = New-Object Drawing.Bitmap($layout.Width,$layout.Height)
            try {
                $layout.DrawToBitmap($bitmap,(New-Object Drawing.Rectangle(0,0,$layout.Width,$layout.Height)))
                $bitmap.Save([IO.Path]::GetFullPath($PreviewPath),[Drawing.Imaging.ImageFormat]::Png)
            } finally { $bitmap.Dispose(); $layout.Dispose() }
        }
        Write-Output 'GUI smoke test passed.'
    } else {
        $timer.Start()
        [void]$form.ShowDialog()
    }
} finally {
    $timer.Stop(); $timer.Dispose()
    if ($script:remoteCredential) { $script:remoteCredential.Password.Dispose(); $script:remoteCredential = $null }
    $tooltips.Dispose(); $form.Dispose()
}
