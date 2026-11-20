#requires -Version 5.1
[CmdletBinding()] param($Security,$Owner,[switch]$SmokeTest,[string]$PreviewPath)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Import-Module (Join-Path $PSScriptRoot 'PatchValidator.psd1')
. (Join-Path $PSScriptRoot 'CredentialDialog.ps1')
. (Join-Path $PSScriptRoot 'SecurityDialog.ps1')
if ([Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') { throw 'Start the batch GUI with PowerShell -STA.' }
[Windows.Forms.Application]::EnableVisualStyles()
if ($null -eq $Security) {
    $Security=[pscustomobject]@{Authentication='Kerberos';ConfigurationName='';CheckAuthenticode=$false;RequireValidSignature=$false;ExpectedPublisher='';SigningCertificateThumbprint='';TrustedSignerThumbprint=@();RequireSignedEvidence=$false}
}
$batch=@{Items=@();Task=$null;Cursor=0;Stage='';Stop=$false;Locked=$false;Saved=$true;Credential=$null;Security=$Security}
$moduleFile=Join-Path $PSScriptRoot 'PatchValidator.psd1'
$captureScript={param($Module,$Target,$Connection);$ErrorActionPreference='Stop';Import-Module $Module;Get-PatchBatchCapture -Target $Target -Connection $Connection}
function New-BatchButton([string]$Text) {
    $control=New-Object Windows.Forms.Button; $control.Text=$Text; $control.AutoSize=$true
    $control.Padding=New-Object Windows.Forms.Padding(6); return $control
}
function New-BatchLabel([string]$Text) {
    $control=New-Object Windows.Forms.Label; $control.Text=$Text; $control.AutoSize=$true; $control.Anchor='Left'; return $control
}
function New-BatchBox([string]$Text='') {
    $control=New-Object Windows.Forms.TextBox; $control.Text=$Text; $control.Dock='Fill'; return $control
}
function Show-BatchProblem([string]$Text) { [void][Windows.Forms.MessageBox]::Show($window,$Text,'Batch validation','OK','Error') }
$window=New-Object Windows.Forms.Form
$window.Text='Patch Validator - Multiple hosts / services'
$window.Size=New-Object Drawing.Size(1160,850); $window.MinimumSize=New-Object Drawing.Size(1000,760)
$window.Font=New-Object Drawing.Font('Segoe UI',10); $window.StartPosition='CenterParent'; $window.AutoScaleMode='Dpi'
$layout=New-Object Windows.Forms.TableLayoutPanel
$layout.Dock='Fill'; $layout.Padding=New-Object Windows.Forms.Padding(14); $layout.ColumnCount=1; $layout.RowCount=7
foreach ($height in @(42,200,48,48)) { [void]$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle('Absolute',$height))) }
[void]$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle('Percent',60)))
[void]$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle('Percent',40)))
[void]$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle('Absolute',42)))
$window.Controls.Add($layout)
$title=New-BatchLabel 'Select hosts and services, preview the combinations, then capture before and after.'
$layout.Controls.Add($title,0,0)
$inputs=New-Object Windows.Forms.TableLayoutPanel
$inputs.Dock='Fill'; $inputs.ColumnCount=4; $inputs.RowCount=5
foreach ($spec in @(@('Absolute',180),@('Percent',100),@('Absolute',135),@('Absolute',90))) { [void]$inputs.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle($spec[0],$spec[1]))) }
for ($i=0;$i -lt 5;$i++) { [void]$inputs.RowStyles.Add((New-Object Windows.Forms.RowStyle('Percent',20))) }
$hostBox=New-BatchBox $env:COMPUTERNAME; $serviceBox=New-BatchBox
$hostFile=New-BatchBox; $hostFile.ReadOnly=$true; $serviceFile=New-BatchBox; $serviceFile.ReadOnly=$true
$hostBrowse=New-BatchButton 'Choose CSV...'; $hostClear=New-BatchButton 'Clear file'
$serviceBrowse=New-BatchButton 'Choose CSV...'; $serviceClear=New-BatchButton 'Clear file'
$expectedBox=New-BatchBox; $componentBox=New-BatchBox
$inputs.Controls.Add((New-BatchLabel 'Single computer'),0,0); $inputs.Controls.Add($hostBox,1,0); $inputs.SetColumnSpan($hostBox,3)
$inputs.Controls.Add((New-BatchLabel 'Or hosts CSV'),0,1); $inputs.Controls.Add($hostFile,1,1); $inputs.Controls.Add($hostBrowse,2,1); $inputs.Controls.Add($hostClear,3,1)
$inputs.Controls.Add((New-BatchLabel 'Single service'),0,2); $inputs.Controls.Add($serviceBox,1,2); $inputs.SetColumnSpan($serviceBox,3)
$inputs.Controls.Add((New-BatchLabel 'Or display names CSV'),0,3); $inputs.Controls.Add($serviceFile,1,3); $inputs.Controls.Add($serviceBrowse,2,3); $inputs.Controls.Add($serviceClear,3,3)
$inputs.Controls.Add((New-BatchLabel 'Single service settings'),0,4)
$serviceSettings=New-Object Windows.Forms.FlowLayoutPanel; $serviceSettings.Dock='Fill'; $serviceSettings.WrapContents=$false
$expectedBox.Dock='None';$expectedBox.Width=160;$componentBox.Dock='None';$componentBox.Width=280
$serviceSettings.Controls.AddRange(@((New-BatchLabel 'Expected version'),$expectedBox,(New-BatchLabel 'Version file'),$componentBox))
$inputs.Controls.Add($serviceSettings,1,4);$inputs.SetColumnSpan($serviceSettings,3)
$layout.Controls.Add($inputs,0,1)
$securityBar=New-Object Windows.Forms.FlowLayoutPanel; $securityBar.Dock='Fill';$securityBar.WrapContents=$false
$securityButton=New-BatchButton 'Security settings';$credentialButton=New-BatchButton 'Set credentials';$clearCredential=New-BatchButton 'Clear credentials'
$ssl=New-Object Windows.Forms.CheckBox;$ssl.Text='HTTPS';$ssl.AutoSize=$true
$identityLabel=New-BatchLabel 'Current Windows identity'
$securityBar.Controls.AddRange(@($securityButton,$credentialButton,$clearCredential,$ssl,$identityLabel));$layout.Controls.Add($securityBar,0,2)
$actions=New-Object Windows.Forms.FlowLayoutPanel;$actions.Dock='Fill';$actions.WrapContents=$false
$preview=New-BatchButton 'Preview list';$before=New-BatchButton 'Capture before';$save=New-BatchButton 'Save baseline'
$load=New-BatchButton 'Load baseline';$after=New-BatchButton 'Capture after';$export=New-BatchButton 'Export report'
$cancel=New-BatchButton 'Stop';$reset=New-BatchButton 'New batch'
$actions.Controls.AddRange(@($preview,$before,$save,$load,$after,$export,$cancel,$reset));$layout.Controls.Add($actions,0,3)
$grid=New-Object Windows.Forms.DataGridView;$grid.Dock='Fill';$grid.ReadOnly=$true;$grid.AllowUserToAddRows=$false;$grid.AllowUserToDeleteRows=$false
$grid.RowHeadersVisible=$false;$grid.SelectionMode='FullRowSelect';$grid.MultiSelect=$false;$grid.AutoSizeColumnsMode='Fill';$grid.BackgroundColor=[Drawing.Color]::White
foreach ($column in @('Computer','Service','Expected version','Before state','Before version','After state','After version','Result')) { [void]$grid.Columns.Add($column,$column) }
$layout.Controls.Add($grid,0,4)
$details=New-BatchBox;$details.Multiline=$true;$details.ReadOnly=$true;$details.ScrollBars='Vertical';$layout.Controls.Add($details,0,5)
$status=New-BatchLabel '';$status.Dock='Fill';$layout.Controls.Add($status,0,6)
function Update-BatchControls {
    $busy=$null -ne $batch.Task
    $inputs.Enabled=-not $busy -and -not $batch.Locked
    $hostBox.Enabled=-not [bool]$hostFile.Text;$serviceBox.Enabled=-not [bool]$serviceFile.Text;$serviceSettings.Enabled=-not [bool]$serviceFile.Text
    $preview.Enabled=-not $busy -and -not $batch.Locked
    $before.Enabled=-not $busy -and -not $batch.Locked -and $batch.Items.Count -gt 0
    $after.Enabled=-not $busy -and $batch.Locked -and @($batch.Items | Where-Object { $null -ne $_.Before }).Count -gt 0
    $save.Enabled=$after.Enabled;$export.Enabled=-not $busy -and $batch.Locked
    $load.Enabled=-not $busy;$reset.Enabled=-not $busy;$cancel.Enabled=$busy -and -not $batch.Stop
    $securityButton.Enabled=-not $busy -and -not $batch.Locked
    $credentialButton.Enabled=-not $busy;$clearCredential.Enabled=-not $busy -and $null -ne $batch.Credential;$ssl.Enabled=-not $busy -and -not $batch.Locked
}
function Clear-BatchCredential {
    if ($null -ne $batch.Credential) { $batch.Credential.Password.Dispose() };$batch.Credential=$null;$identityLabel.Text='Current Windows identity'
}
function Update-BatchGrid {
    $selected=if ($null -ne $grid.CurrentRow) { $grid.CurrentRow.Index } else { 0 }
    $grid.Rows.Clear()
    foreach ($item in $batch.Items) {
        $bState='';$bVersion='';$aState='';$aVersion=''
        if ($item.Before) { $bState=$item.Before.State; $bVersion=$item.Before.ProductVersion; if ($item.Target.VersionField -eq 'FileVersion' -or -not $bVersion) { $bVersion=$item.Before.FileVersion } }
        if ($item.After) { $aState=$item.After.State; $aVersion=$item.After.ProductVersion; if ($item.Target.VersionField -eq 'FileVersion' -or -not $aVersion) { $aVersion=$item.After.FileVersion } }
        [void]$grid.Rows.Add($item.Target.ComputerName,$item.Target.ServiceName,$item.Target.ExpectedVersion,$bState,$bVersion,$aState,$aVersion,$item.Result)
    }
    if ($grid.Rows.Count -gt 0) { $grid.CurrentCell=$grid.Rows[[Math]::Min($selected,$grid.Rows.Count-1)].Cells[0] }
    Update-BatchControls
}
function Get-BatchCertificate {
    if ($batch.Security.SigningCertificateThumbprint) { Get-PatchSigningCertificate $batch.Security.SigningCertificateThumbprint }
}
function Set-BatchPlan($Targets) {
    $batch.Items=@($Targets | ForEach-Object { [pscustomobject]@{Target=$_;Before=$null;After=$null;Report=$null;Result='Pending';Detail='Ready for before capture.'} })
    Update-BatchGrid
    $status.Text=('{0} host/service pairs. Authentication: {1}. Each listed service runs on every listed host.' -f $batch.Items.Count,$batch.Security.Authentication)
}
function Select-BatchCsv($Destination) {
    $dialog=New-Object Windows.Forms.OpenFileDialog;$dialog.Filter='CSV files (*.csv)|*.csv';$dialog.CheckFileExists=$true
    try { if ($dialog.ShowDialog($window) -eq 'OK') { $Destination.Text=$dialog.FileName } } finally { $dialog.Dispose() }
}
$hostBrowse.Add_Click({ Select-BatchCsv $hostFile });$serviceBrowse.Add_Click({ Select-BatchCsv $serviceFile })
$hostClear.Add_Click({ $hostFile.Clear() });$serviceClear.Add_Click({ $serviceFile.Clear() })
foreach ($box in @($hostBox,$hostFile,$serviceBox,$serviceFile,$expectedBox,$componentBox)) {
    $box.Add_TextChanged({ if (-not $batch.Locked) { $batch.Items=@();$grid.Rows.Clear();$details.Clear();$status.Text='Inputs changed. Preview the list before capture.';Clear-BatchCredential;Update-BatchControls } })
}
$preview.Add_Click({
    try {
        $hosts=if ($hostFile.Text) { @(Import-PatchHostCsv $hostFile.Text) } else { @($hostBox.Text) }
        $services=if ($serviceFile.Text) { @(Import-PatchServiceCsv $serviceFile.Text) } else { @([pscustomobject]@{ServiceName=$serviceBox.Text;ExpectedVersion=$expectedBox.Text;VersionFile=$componentBox.Text}) }
        Set-BatchPlan @(New-PatchBatchPlan -Hosts $hosts -Services $services)
    } catch { Show-BatchProblem $_.Exception.Message }
})
$credentialButton.Add_Click({
    $entered=$null
    try { $entered=Show-PatchCredentialDialog -Owner $window; if ($null -ne $entered) { Clear-BatchCredential;$batch.Credential=$entered;$identityLabel.Text='Using: '+$entered.UserName };Update-BatchControls }
    catch { Show-BatchProblem (Get-PatchErrorMessage $_) } finally { $entered=$null }
})
$clearCredential.Add_Click({ Clear-BatchCredential;Update-BatchControls })
$securityButton.Add_Click({
    try { $settings=Show-PatchSecurityDialog -Owner $window -Settings $batch.Security; if ($settings) { $batch.Security=$settings };$status.Text='Authentication: '+$batch.Security.Authentication }
    catch { Show-BatchProblem (Get-PatchErrorMessage $_) }
})
$grid.Add_SelectionChanged({
    if ($null -eq $grid.CurrentRow -or $grid.CurrentRow.Index -ge $batch.Items.Count) { return }
    $item=$batch.Items[$grid.CurrentRow.Index]
    $lines=@(($item.Target.ComputerName+' / '+$item.Target.ServiceName),$item.Detail)
    if ($item.Before) { $lines+=('Before component: '+$item.Before.VersionPath);$lines+=('Baseline integrity: '+$item.Before.EvidenceVerification) }
    if ($item.After) { $lines+=('After component: '+$item.After.VersionPath) }
    if ($item.Report) { $lines+=@($item.Report.Checks | ForEach-Object { $_.Result+' - '+$_.Check+': '+$_.Detail }) }
    $details.Text=$lines -join [Environment]::NewLine
})
function Start-NextBatchItem {
    while ($batch.Cursor -lt $batch.Items.Count -and -not $batch.Stop) {
        $item=$batch.Items[$batch.Cursor]
        if ($batch.Stage -eq 'After' -and $null -eq $item.Before) { $item.Result='Review';$item.Detail='No successful before capture. Start a new batch before patching to establish a baseline.';$batch.Cursor++;continue }
        $worker=[PowerShell]::Create()
        $connection=@{Authentication=$batch.Security.Authentication;UseSSL=$ssl.Checked;CheckAuthenticode=$batch.Security.CheckAuthenticode;ConfigurationName=$batch.Security.ConfigurationName}
        if ($batch.Credential) { $connection.Credential=$batch.Credential }
        [void]$worker.AddScript($captureScript).AddArgument($moduleFile).AddArgument($item.Target).AddArgument($connection)
        try {
            $handle=$worker.BeginInvoke();$batch.Task=@{Worker=$worker;Handle=$handle;Started=[DateTime]::UtcNow;Stopping=$false;TimedOut=$false}
            $item.Result='Capturing';$status.Text=('{0}: {1}/{2} - {3} / {4}' -f $batch.Stage,($batch.Cursor+1),$batch.Items.Count,$item.Target.ComputerName,$item.Target.ServiceName)
            Update-BatchGrid;return
        } catch { $worker.Dispose();$item.Result='Error';$item.Detail=Get-PatchErrorMessage $_;$batch.Cursor++ }
    }
    if ($batch.Stop) {
        for ($i=$batch.Cursor;$i -lt $batch.Items.Count;$i++) { $batch.Items[$i].Result='Review';$batch.Items[$i].Detail='Not captured: batch stopped.' }
    }
    $batch.Task=$null;Update-BatchGrid
    $status.Text=if ($batch.Stop) { 'Batch stopped. Completed results are retained; uncaptured items require Review.' } else { 'Batch finished. Select a row for details; save the baseline or export the report.' }
}
function Start-BatchStage([string]$Stage) {
    if ($null -ne $batch.Task -or $batch.Items.Count -eq 0) { return }
    $batch.Locked=$true;$batch.Stage=$Stage;$batch.Cursor=0;$batch.Stop=$false
    if ($Stage -eq 'Before') { $batch.Saved=$false }
    foreach ($item in $batch.Items) { $item.After=$null;$item.Report=$null;$item.Result='Pending';$item.Detail='Waiting for capture.' }
    Start-NextBatchItem
}
$before.Add_Click({ Start-BatchStage 'Before' });$after.Add_Click({ Start-BatchStage 'After' })
$cancel.Add_Click({ $batch.Stop=$true;$status.Text='Stopping the current read-only capture; remaining items will not run.';Update-BatchControls })
$timer=New-Object Windows.Forms.Timer;$timer.Interval=150
$onBatchTick={
    if ($null -eq $batch.Task) { return }
    $task=$batch.Task
    if (-not $task.Handle.IsCompleted) {
        if (-not $task.Stopping -and ($batch.Stop -or ([DateTime]::UtcNow-$task.Started).TotalSeconds -gt 60)) {
            $task.TimedOut=-not $batch.Stop;$task.Stopping=$true
            try { [void]$task.Worker.BeginStop($null,$null) } catch { $batch.Stop=$true }
        };return
    }
    $item=$batch.Items[$batch.Cursor];$batch.Task=$null
    try {
        $output=@($task.Worker.EndInvoke($task.Handle))
        if ($task.Stopping -or $task.Worker.HadErrors -or $output.Count -ne 1) { throw 'The pipeline was stopped or the capture did not complete.' }
        if ($null -eq $output[0].Snapshot) { $item.Result='Error';$item.Detail=$output[0].Error }
        elseif ($batch.Stage -eq 'Before') { $item.Before=$output[0].Snapshot;$item.Result='Captured';$item.Detail='Before captured. Save the baseline before patching.' }
        else {
            $item.After=$output[0].Snapshot
            $item.Report=Compare-PatchSnapshot $item.Before $item.After -ExpectedVersion $item.Target.ExpectedVersion -VersionField $item.Target.VersionField -ExpectedState $item.Target.ExpectedState -RequireSignedBaseline:$batch.Security.RequireSignedEvidence -RequireValidSignature:$batch.Security.RequireValidSignature -ExpectedPublisher $batch.Security.ExpectedPublisher
            $item.Result=$item.Report.Verdict;$item.Detail=$item.Report.Summary
        }
    } catch { $item.Report=$null;$item.Result='Review';$item.Detail=if ($task.TimedOut) { 'Capture timed out; no completed result was accepted.' } else { Get-PatchErrorMessage $_ } }
    finally { $task.Worker.Dispose() }
    $batch.Cursor++;Start-NextBatchItem
}
$timer.Add_Tick($onBatchTick)
$save.Add_Click({
    $dialog=New-Object Windows.Forms.SaveFileDialog;$dialog.Filter='Batch baseline (*.json)|*.json';$dialog.FileName='batch-baseline.json'
    try {
        if ($dialog.ShowDialog($window) -eq 'OK') {
            Save-PatchBatchBaseline -Items $batch.Items -Path $dialog.FileName -SigningCertificate (Get-BatchCertificate) -RequireSignature:$batch.Security.RequireSignedEvidence
            $loaded=@(Read-PatchBatchBaseline $dialog.FileName -TrustedSignerThumbprint $batch.Security.TrustedSignerThumbprint -RequireSignature:$batch.Security.RequireSignedEvidence)
            for ($i=0;$i -lt $batch.Items.Count;$i++) { $batch.Items[$i].Before=$loaded[$i].Before;$batch.Items[$i].After=$null;$batch.Items[$i].Report=$null;$batch.Items[$i].Result='Review';$batch.Items[$i].Detail='Baseline saved and reloaded. Capture after to compare.' }
            $batch.Saved=$true;Update-BatchGrid;$status.Text='Baseline saved and verification status applied.'
        }
    } catch { Show-BatchProblem (Get-PatchErrorMessage $_) } finally { $dialog.Dispose() }
})
function Confirm-BatchDiscard {
    if ($batch.Saved -or -not $batch.Locked) { return $true }
    return [Windows.Forms.MessageBox]::Show($window,'Discard the unsaved batch baseline?','Unsaved baseline','YesNo','Question') -eq 'Yes'
}
$load.Add_Click({
    if (-not (Confirm-BatchDiscard)) { return }
    $dialog=New-Object Windows.Forms.OpenFileDialog;$dialog.Filter='Batch baseline (*.json)|*.json'
    try {
        if ($dialog.ShowDialog($window) -eq 'OK') {
            $items=@(Read-PatchBatchBaseline $dialog.FileName -TrustedSignerThumbprint $batch.Security.TrustedSignerThumbprint -RequireSignature:$batch.Security.RequireSignedEvidence)
            $batch.Items=$items;$batch.Locked=$true;$batch.Saved=$true;Clear-BatchCredential;Update-BatchGrid;$status.Text='Batch loaded. Verify the target list, set credentials if needed, then Capture after.'
        }
    } catch { Show-BatchProblem (Get-PatchErrorMessage $_) } finally { $dialog.Dispose() }
})
$export.Add_Click({
    $dialog=New-Object Windows.Forms.SaveFileDialog;$dialog.Filter='Batch report (*.json)|*.json';$dialog.FileName='batch-report.json'
    try {
        if ($dialog.ShowDialog($window) -eq 'OK') {
            Save-PatchBatchReport $batch.Items $dialog.FileName -RequireSignedBaseline:$batch.Security.RequireSignedEvidence -RequireValidSignature:$batch.Security.RequireValidSignature -ExpectedPublisher $batch.Security.ExpectedPublisher -SigningCertificate (Get-BatchCertificate) -RequireSignature:$batch.Security.RequireSignedEvidence
            $status.Text='Batch report exported. Missing or failed captures are included as Review.'
        }
    } catch { Show-BatchProblem (Get-PatchErrorMessage $_) } finally { $dialog.Dispose() }
})
$reset.Add_Click({ if (Confirm-BatchDiscard) { $batch.Items=@();$batch.Locked=$false;$batch.Saved=$true;Clear-BatchCredential;Update-BatchGrid;$details.Clear();$status.Text='Choose inputs and preview a new batch.' } })
$window.Add_FormClosing({param($sender,$eventArgs)
    if ($null -ne $batch.Task) { $eventArgs.Cancel=$true;$batch.Stop=$true;$status.Text='Stopping capture. Close again after the batch stops.' }
    elseif (-not (Confirm-BatchDiscard)) { $eventArgs.Cancel=$true }
})
$status.Text='Services CSV: one DisplayName column. Credentials apply to the whole batch and stay in memory.'
Update-BatchControls
try {
    if ($SmokeTest) {
        Set-BatchPlan @(New-PatchBatchPlan @('host1.example.com','host2.example.com') @('Svc1','Svc2'))
        if ($grid.Rows.Count -ne 4 -or -not $before.Enabled -or $after.Enabled) { throw 'Batch preview controls failed.' }
        $batch.Task=@{SmokeTest=$true};Update-BatchControls
        if ($inputs.Enabled -or $securityButton.Enabled -or $credentialButton.Enabled -or -not $cancel.Enabled) { throw 'Batch controls are not locked during capture.' }
        $batch.Task=$null
        $batch.Credential=New-Object Management.Automation.PSCredential('EXAMPLE\test',(ConvertTo-SecureString 'Dummy test password' -AsPlainText -Force))
        $hostBox.Text='changed.example.com'
        if ($null -ne $batch.Credential -or $batch.Items.Count -ne 0) { throw 'Changed targets retained credentials or stale preview.' }
        # Exercise the real asynchronous queue without contacting any host.
        $captureScript={
            param($Module,$Target,$Connection)
            if ($Target.ComputerName -eq 'failed.example.com') { return [pscustomobject]@{Snapshot=$null;Error='Simulated connection failure.'} }
            $snapshot=[pscustomobject]@{SchemaVersion=1;CapturedAtUtc='2026-01-01T10:00:00Z';ComputerName='FIXTURE';ComputerIdentity='11111111-1111-1111-1111-111111111111';ServiceName=$Target.ServiceName;DisplayName='Fixture';State='Running';StartMode='Auto';ProcessId=10;ProcessStartedAtUtc='2026-01-01T09:00:00Z';ExecutablePath='C:\App\svc.exe';VersionPath='C:\App\svc.exe';VersionSource='Service executable';ProductName='Fixture';CompanyName='Fixture';ProductVersion='1.0';FileVersion='1.0';FileSha256=('A'*64);FileModifiedAtUtc='2026-01-01T08:00:00Z';SelectionReliable=$true;Notes=@()}
            [pscustomobject]@{Snapshot=$snapshot;Error=$null}
        }
        Set-BatchPlan @(New-PatchBatchPlan @('ok.example.com','failed.example.com','later.example.com') @('Svc1'))
        Start-BatchStage 'Before'
        $deadline=[DateTime]::UtcNow.AddSeconds(15)
        while ($null -ne $batch.Task -and [DateTime]::UtcNow -lt $deadline) { & $onBatchTick;[Threading.Thread]::Sleep(10) }
        if ($null -ne $batch.Task -or -not $batch.Items[0].Before -or $batch.Items[1].Before -or -not $batch.Items[2].Before) { throw 'Batch did not continue after a failed capture.' }
        $captureScript=[scriptblock]::Create($captureScript.ToString().Replace("CapturedAtUtc='2026-01-01T10:00:00Z'","CapturedAtUtc='2026-01-01T11:00:00Z'"))
        Start-BatchStage 'After'
        $deadline=[DateTime]::UtcNow.AddSeconds(15)
        while ($null -ne $batch.Task -and [DateTime]::UtcNow -lt $deadline) { & $onBatchTick;[Threading.Thread]::Sleep(10) }
        if ($null -ne $batch.Task -or -not $batch.Items[0].Report -or $batch.Items[1].Result -ne 'Review' -or -not $batch.Items[2].Report) { throw 'Batch comparison did not preserve per-item results.' }
        Start-BatchStage 'After';$batch.Stop=$true
        $deadline=[DateTime]::UtcNow.AddSeconds(15)
        while ($null -ne $batch.Task -and [DateTime]::UtcNow -lt $deadline) { & $onBatchTick;[Threading.Thread]::Sleep(10) }
        if ($null -ne $batch.Task -or $null -ne $batch.Items[2].After -or $batch.Items[2].Result -ne 'Review') { throw 'Stopped batch retained stale results or continued scanning.' }
        $batch.Locked=$false;$batch.Saved=$true;$batch.Stop=$false
        Set-BatchPlan @(New-PatchBatchPlan @('host1.example.com','host2.example.com') @('Svc1','Svc2'))
        if ($PreviewPath) {
            $layout.Font=$window.Font;$layout.Parent=$null;$layout.Size=$window.ClientSize;$layout.CreateControl();$layout.PerformLayout()
            $bitmap=New-Object Drawing.Bitmap($layout.Width,$layout.Height)
            try { $layout.DrawToBitmap($bitmap,(New-Object Drawing.Rectangle(0,0,$layout.Width,$layout.Height)));$bitmap.Save([IO.Path]::GetFullPath($PreviewPath)) } finally { $bitmap.Dispose();$layout.Dispose() }
        }
        'Batch GUI smoke test passed.'
    } else { $timer.Start(); if ($Owner) { [void]$window.ShowDialog($Owner) } else { [void]$window.ShowDialog() } }
} finally { $timer.Stop();$timer.Dispose();Clear-BatchCredential;$window.Dispose() }
