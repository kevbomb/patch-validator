# Patch Validator

A PowerShell desktop app that captures a Windows service before and after patching, automatically discovers its installed component version, and compares the results. It checks service state, startup mode, product/file version, SHA-256, and process start time. It does not install patches or change services.

## Start the GUI

Requires Windows with a desktop session and Windows PowerShell 5.1, or PowerShell 7 on Windows. The app uses built-in Windows Forms and CIM commands; no Python or third-party runtime modules are required.

From this directory:

```powershell
powershell.exe -NoProfile -STA -File .\Start-PatchValidator.ps1
```

For PowerShell 7:

```powershell
pwsh.exe -NoProfile -STA -File .\Start-PatchValidator.ps1
```

Scripts must be permitted by your organization's execution/signing policy. The app does not alter that policy. Run with an account that can read service/process information, the relevant service registry key, and the component file. Some services need an elevated session for complete process details; unavailable information is reported for review.

## Workflow

1. Enter the exact **Service name** (for example, `EventLog`) or its exact display name. **Computer** defaults to this machine. For a remote computer, click **Set credentials...** if you need another account (required when connecting by IP).
2. Click **Capture before**. Review the discovered component path and versions. You do not need to enter the current version.
3. Click **Save baseline** and save the JSON file before patching or restarting. Capture data is held in memory until saved.
4. Apply your patch through your normal patching process. Restart the service/computer if the patch requires it.
5. Reopen the app and **Load baseline** if needed. Click **Capture after**.
6. Optionally enter **Expected version** from the patch's documentation and choose the expected service state. Export the JSON report to retain both snapshots, comparison settings, and check results.

Computer, service, and component selection are locked after the baseline is captured. Use **New comparison** to choose another service or component. Expected version/state remain editable and recalculate the result. A saved baseline stores discovery data; enter the desired target criteria when you load it again. Exported reports store those criteria too.

The expected target version is distinct from automatic discovery of the installed version. Without a target, the app shows what changed and returns **Review** rather than confirming a specific patch.

## Results

| Result | Meaning |
| --- | --- |
| **Pass** | The selected version changed, matches the supplied target, the service has the expected state, and the available collection/restart evidence has no outstanding review condition. |
| **Fail** | A known expectation was not met, such as a target mismatch, unexpected service state, or numerical version decrease. |
| **Review** | Evidence is incomplete or ambiguous: no target supplied, unchanged version, unavailable metadata, changed component path/startup mode, or an uncertain process restart. |

The default expected state is **Same as before**. A service intentionally stopped before and after patching can pass the installed-version check; this does not claim that it was tested running.

**Auto** compares `ProductVersion` when either capture contains it; otherwise it compares `FileVersion`. It never compares one field against the other. Select **FileVersion** when a patch only changes that field. Pure dotted numeric versions are compared numerically and normalized to four components (`1.2` equals `1.2.0.0`). Other strings, including build/prerelease suffixes, must match exactly, including case. Unchanged metadata is inconclusive even when the file hash changes.

## How version discovery works

- For a normal executable service, resolve the configured executable and prefer the live process executable path when available.
- For `svchost.exe`, inspect the service's `Parameters\ServiceDll`, not the shared Windows host's version.
- Known generic runtimes/wrappers such as Java, .NET, Python, PowerShell, NSSM, and WinSW require an explicit **Version file** so their own runtime version is not mistaken for the application's version.
- **Version file** accepts an absolute EXE/DLL path on the target computer. It reads file metadata without executing the file. UNC paths are not supported. Files without version resources remain unknown; JARs, scripts, and container images need application-specific discovery that this initial version does not implement.

The resolver is generic, not an application inventory database. Renamed/custom wrappers and applications whose service EXE has a separate version from the patched product need the correct component selected. Review the displayed path before patching.

File versions describe files on disk. Process start time provides restart evidence, but cannot prove which DLL versions are loaded or whether an application is healthy. Services in shared host processes, preserved file timestamps, hot reloads, and updates to other components may require a product-specific runtime or health check. This app does not validate a KB number, installer exit code, every file in a product, or vulnerability remediation.

## Remote computers

Enter a Windows computer name or IP address that already supports PowerShell remoting through WinRM. By default, hostnames use your current Windows identity. Click **Set credentials...** to enter a username and masked password. Supported username forms include `DOMAIN\user`, `user@domain`, and `SERVER\user` for a server-local account. Both captures use that account until you clear/change credentials, switch computers, start a new comparison, or close the app. Click **Clear** to return to your current Windows identity. Credentials are held in memory as a `PSCredential`, never added to the collector's arguments, baselines, or reports. You must re-enter them after reopening the app.

**Connecting by IP requires explicit credentials** and either an existing WinRM HTTPS listener or an appropriate existing TrustedHosts entry on your client. Check **Use HTTPS (5986)** only when the server supports WinRM HTTPS and its certificate is valid for the name/IP entered. Without it, the app uses WinRM HTTP on port 5985 with Windows authentication. The app does not enable remoting, change firewall rules/TrustedHosts, disable certificate validation, or enable Basic/CredSSP authentication. See [Microsoft's IP-address remoting requirements](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_troubleshooting?view=powershell-5.1).

Supplying credentials or HTTPS for `localhost` or this computer's name uses WinRM too; it does not silently ignore the chosen account and run locally as you. Version-file paths are resolved on the target computer. The GUI runs the query in a background runspace and requests cancellation after 60 seconds.

Remote collection depends on your network, remoting configuration, and permissions. Only local collection has been exercised on this development machine; remote operation needs validation in your environment.

## PowerShell module

The collector, comparison engine, and GUI are separate. The module can also be used without the GUI:

```powershell
Import-Module .\PatchValidator.psd1

# Before patching:
$before = Get-PatchSnapshot -ServiceName 'MyService'
Save-PatchSnapshot -Snapshot $before -Path .\my-service.snapshot.json

# After patching (possibly in a new PowerShell session):
$before = Read-PatchSnapshot -Path .\my-service.snapshot.json
$after = Get-PatchSnapshot -ServiceName $before.ServiceName -ComputerName $before.ComputerName
$report = Compare-PatchSnapshot -Before $before -After $after -ExpectedVersion '2.4.1'
$report.Checks | Format-Table -Wrap
$report.Verdict
Save-PatchReport -Report $report -Path .\my-service.report.json
```

When using a selected component, pass the same `-VersionFile 'C:\Path\Application.dll'` to both captures. Reports and baselines contain computer names and file paths; store them with your maintenance records. Common output filenames are ignored by Git.

To supply credentials from PowerShell (enter the password only in the prompt):

```powershell
$credential = Get-Credential -UserName 'DOMAIN\user' -Message 'Remote service checks'
$before = Get-PatchSnapshot -ServiceName 'MyService' -ComputerName '192.0.2.25' -Credential $credential -UseSSL
# Apply the patch, then use the same target and credentials for the after capture.
$after = Get-PatchSnapshot -ServiceName 'MyService' -ComputerName '192.0.2.25' -Credential $credential -UseSSL
```

The sample IP is a placeholder. Use `-UseSSL` only for an already configured HTTPS endpoint.

## Project files and tests

```text
Start-PatchValidator.ps1    Windows Forms GUI and asynchronous capture
CredentialDialog.ps1       Masked, session-only credential entry
PatchValidator.psd1        Module manifest
PatchValidator.psm1        Capture orchestration, comparison, JSON persistence
Collect-Service.ps1        Read-only local/remote service collector
tests/
  Collector.Tests.ps1      Discovery and malformed/unavailable input cases
  CredentialDialog.Tests.ps1 Credential entry, cancellation, and clearing
  Remote.Tests.ps1         Credential forwarding and remoting options (mocked)
  PatchValidator.Tests.ps1 Comparison and persistence tests
  Run-Tests.ps1            Syntax check and test runner
```

Tests use Pester 3.4/4.x; Windows PowerShell commonly includes 3.4. Pester 5+ uses a different test syntax and is not supported by this suite. No test installs a patch or changes a service. Collector tests mock CIM/registry queries and read metadata from existing Windows files.

```powershell
powershell.exe -NoProfile -File .\tests\Run-Tests.ps1
powershell.exe -NoProfile -STA -File .\Start-PatchValidator.ps1 -SmokeTest
```

The GUI smoke test instantiates and lays out the real controls without opening a window. Add `-PreviewPath .\preview.png` to render a local layout preview.

## Platform references

- [Microsoft: Win32_Service fields](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service)
- [Microsoft: FileVersionInfo](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.fileversioninfo)
- [Microsoft: ConvertFrom-Json timestamp handling](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/convertfrom-json)
