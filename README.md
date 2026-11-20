# Patch Validator

A PowerShell desktop app that captures a Windows service before and after patching, automatically discovers its installed component version, and compares the results. It checks service state, startup mode, product/file version, SHA-256, and process start time. It does not install patches or change services.

Version 0.4.0 adds CSV-based batch validation while preserving the single-computer workflow and the 0.3.0 authentication/evidence controls. Read the [batch guide](docs/BATCH.md), [security review](SECURITY-REVIEW.md), [enterprise jump-server deployment guide](docs/ENTERPRISE.md), [optional JEA design](docs/JEA.md) and [infrastructure validation checklist](docs/INTEGRATION-TESTS.md) before enterprise rollout.

## Start the GUI

Requires Windows with a desktop session and Windows PowerShell 5.1, or PowerShell 7 on Windows. The app uses built-in Windows Forms and CIM commands; no third-party runtime modules are required.

Clone the repository, then start the GUI:

```powershell
git clone https://github.com/kevbomb/patch-validator.git
cd patch-validator
powershell.exe -NoProfile -STA -File .\Start-PatchValidator.ps1
```

For PowerShell 7:

```powershell
pwsh.exe -NoProfile -STA -File .\Start-PatchValidator.ps1
```

Scripts must be permitted by your organization's execution/signing policy. The app does not alter that policy. Run with an account that can read service/process information, the relevant service registry key, and the component file. Some services need an elevated session for complete process details; unavailable information is reported for review.

## Workflow

1. Enter the exact **Service name** (for example, `EventLog`) or its exact display name. **Computer** defaults to this machine. For a remote computer, click **Set credentials...** if you need another account (required when connecting by IP).
2. Configure **Security settings...** before capture: authentication, optional executable-signature/publisher policy, evidence signing certificate and independently approved signer thumbprints. For audit use, select **Require signed evidence**. Then click **Capture before** and review the discovered component path and versions. You do not need to enter the current version.
3. Click **Save baseline** and save the JSON file before patching or restarting. Capture data is held in memory until saved.
4. Apply your patch through your normal patching process. Restart the service/computer if the patch requires it.
5. Reopen the app and **Load baseline** if needed. Click **Capture after**.
6. Optionally enter **Expected version** from the patch's documentation and choose the expected service state. Export the JSON report to retain both snapshots, comparison settings, and check results.

Computer, service, and component selection are locked after the baseline is captured. Use **New comparison** to choose another service or component. Expected version/state remain editable and recalculate the result. A saved baseline stores discovery data; enter the desired target criteria when you load it again. Exported reports store those criteria too.

Security settings also lock after baseline selection. Legacy unsigned JSON remains readable but is labeled unverified and produces **Review**. For a trusted baseline, configure an approved certificate/key and signer pins, save a newly captured signed baseline, then verify it on loading. Signed exports remain JSON containers, with their content inside an attached CMS signature; use `Read-PatchSnapshot` or `Read-PatchReport` to verify/decode them. Editing the payload invalidates the signature.

The expected target version is distinct from automatic discovery of the installed version. Without a target, the app shows what changed and returns **Review** rather than confirming a specific patch.

## Multiple hosts and services

Click **Multiple hosts / services...** at the top right of the main window. Enter one computer or select a hosts CSV; independently enter one service or select a services CSV. **Preview list** shows every combination before any capture. Use Capture before, Save baseline, Capture after, and Export report for the batch. Select any result row for details. Failed captures do not stop subsequent items; **Stop** cancels the current query and skips remaining items.

The services file contains just one `DisplayName` column, with one exact Windows service display name per row. Use [services.csv](examples/services.csv) as a template. Host files use one `ComputerName` column. Versions and component paths are discovered automatically; no additional service CSV fields are needed or accepted. Full workflow, format rules and operational limits are in [BATCH.md](docs/BATCH.md).

| Hosts CSV ([template](examples/hosts.csv)) | Services CSV ([template](examples/services.csv)) |
| --- | --- |
| Header: `ComputerName` | Header: `DisplayName` |
| Example: `app01.example.com` | Example: `Windows Event Log` |

**Capture before stays disabled until you click Preview list and rows appear.** Preview validates the selected files and creates the capture list; selecting a CSV alone does not start a scan. If preview fails, check the header, delimiter and exact display names. A selected CSV overrides the corresponding single-entry field; Clear file restores that field.

With display-name-only service lists, the app discovers and compares installed versions but has no expected target version. Results therefore remain **Review** for patch confirmation. Use the single-service workflow when you need a specific expected version or an explicit component file. The batch limit is 500 host/service combinations, with one set of credentials and one connection policy per batch.

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

The GUI defaults to **Kerberos**: use the server FQDN. Kerberos can use HTTP/5985 with WinRM message encryption or verified HTTPS/5986. An explicit Kerberos failure is never retried using NTLM. IP addresses are rejected in this mode. [Microsoft WinRM security](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security).

For an IP address or local account, select **Negotiate** in Security settings, enter explicit credentials, and select **Use HTTPS (5986)**. The target needs an existing HTTPS listener and a valid certificate matching the requested name/IP. Explicit Negotiate requires HTTPS. The module retains **Default** authentication for compatibility, and the GUI offers it as a deliberate legacy choice; it can use NTLM and existing TrustedHosts policy. Neither mode silently overrides an explicit Kerberos choice. The app never changes TrustedHosts, firewall rules, listeners or certificate checks, and offers no Basic/CredSSP authentication. The GUI host needs outbound connectivity; inbound WinRM on the jump host is not a prerequisite.

Supplying credentials or HTTPS for `localhost` or this computer's name uses WinRM too; it does not silently ignore the chosen account and run locally as you. Version-file paths are resolved on the target computer. The GUI runs the query in a background runspace and requests cancellation after 60 seconds.

Remote collection depends on your network, remoting configuration, and permissions. Automated remoting tests use mocks and cannot prove real domain/TLS security; complete the integration checklist in your environment. `-Session` supports existing authorized FullLanguage PSSessions, while `-ConfigurationName` selects an existing compatible endpoint. The bundled script cannot run unchanged in NoLanguage JEA; see the deployment guide.

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
# This legacy unsigned-file example produces Review. For authenticated audit evidence,
# use the signed baseline/report workflow in docs/ENTERPRISE.md.
$report.Checks | Format-Table -Wrap
$report.Verdict
Save-PatchReport -Report $report -Path .\my-service.report.json
```

When using a selected component, pass the same `-VersionFile 'C:\Path\Application.dll'` to both captures. Reports and baselines contain computer names and file paths; store them with your maintenance records. Common output filenames are ignored by Git.

To supply credentials from PowerShell (enter the password only in the prompt):

```powershell
$credential = Get-Credential -UserName 'DOMAIN\user' -Message 'Remote service checks'
$before = Get-PatchSnapshot -ServiceName 'MyService' -ComputerName '192.0.2.25' -Credential $credential -Authentication Negotiate -UseSSL
# Apply the patch, then use the same target and credentials for the after capture.
$after = Get-PatchSnapshot -ServiceName 'MyService' -ComputerName '192.0.2.25' -Credential $credential -Authentication Negotiate -UseSSL
```

The sample IP is a placeholder. Use `-UseSSL` only for an already configured HTTPS endpoint.

## Executable signatures and evidence trust

`Get-PatchSnapshot -CheckAuthenticode` records Windows signature status, signer identity/thumbprint, publisher, issuer, validity dates, current certificate validity and timestamp signer. `Compare-PatchSnapshot -RequireValidSignature -ExpectedPublisher 'EXACT CERTIFICATE SUBJECT'` can require an approved publisher. Windows trust status and current certificate validity are distinct: a valid timestamped signature can outlive its signer certificate. Unsigned or untrusted applications require Review; a signature hash mismatch fails. This is optional and does not classify legitimate unsigned internal software as malicious.

`Save-PatchSnapshot` and `Save-PatchReport` accept `-SigningCertificate` and `-RequireSignature`. Their read counterparts accept `-TrustedSignerThumbprint` and `-RequireSignature`. Comparison can require a verified baseline with `-RequireSignedBaseline`. Private keys stay in the Windows key store; the GUI selects a CurrentUser Personal certificate by thumbprint. Provision keys and distribute trusted pins separately from evidence. No keys or trusted certificates are automatically created.

The signature scheme uses RSA >=2048/SHA-256 and explicit signer pins. It does not automatically validate an enterprise chain/revocation list or provide a trusted timestamp. Current signer validity is required; plan expiration, pin revocation and rotation. Signed data is not encrypted, cannot establish that source data was true, and does not prevent deletion/replay. Protect code, keys, trust policy and evidence with separate NTFS access controls. See ENTERPRISE.md for deployment decisions and limitations.

Credentials stay in memory as PSCredential/SecureString; exported fields exclude credential objects. Temporary mutable password buffers and GUI references are cleared, but managed strings, process dumps and external logging cannot be securely erased by this app. GUI errors deliberately omit raw exception text. Close the window normally after capture finishes; Ctrl+C is a pipeline interruption, not graceful GUI shutdown.

Older baselines lacking Windows machine identity now require Review. Identical hashes paired with conflicting embedded versions fail. Missing component/restart evidence cannot Pass. A Pass still does not establish application health or CVE remediation.

## Project files and tests

```text
Start-PatchValidator.ps1    Windows Forms GUI and asynchronous capture
Start-BatchValidator.ps1    CSV selection, preview and sequential batch capture GUI
Batch.ps1                  CSV validation, plans and signed batch persistence
CredentialDialog.ps1       Masked, session-only credential entry
SecurityDialog.ps1         Authentication, publisher and evidence policy controls
EvidenceSecurity.ps1       CMS signing/verification, allowlists, safe GUI errors
PatchValidator.psd1        Module manifest
PatchValidator.psm1        Capture orchestration, comparison, JSON persistence
Collect-Service.ps1        Read-only local/remote service collector
tests/
  Collector.Tests.ps1      Discovery and malformed/unavailable input cases
  CredentialDialog.Tests.ps1 Credential entry, cancellation, and clearing
  Remote.Tests.ps1         Credential forwarding and remoting options (mocked)
  Security.Tests.ps1       Real CMS tamper tests and comparison security regressions
  SecurityDialog.Tests.ps1 Security controls and policy validation
  PatchValidator.Tests.ps1 Comparison and persistence tests
  Run-Tests.ps1            Syntax check and test runner
  Batch.Tests.ps1          CSV, per-item failure and batch evidence regressions
```

Tests use Pester 3.4/4.x; Windows PowerShell commonly includes 3.4. Pester 5+ uses a different test syntax and is not supported by this suite. No test installs a patch or changes a service. Collector tests mock CIM/registry queries and read metadata from existing Windows files. Cryptographic tests generate ephemeral RSA certificates in memory and verify real CMS; they do not install keys or add certificates to trusted stores. Those test fixtures require .NET Framework 4.7.2 or newer on Windows PowerShell 5.1; use maintained Windows releases. Domain authentication, real HTTPS listeners, JEA and enterprise key permissions require the documented integration checks.

```powershell
powershell.exe -NoProfile -File .\tests\Run-Tests.ps1
powershell.exe -NoProfile -STA -File .\Start-PatchValidator.ps1 -SmokeTest
powershell.exe -NoProfile -STA -File .\Start-BatchValidator.ps1 -SmokeTest
```

The GUI smoke test instantiates and lays out the real controls without opening a window. Add `-PreviewPath .\preview.png` to render a local layout preview.

For v0.4.0, **120 tests passed with zero failures** on Windows PowerShell 5.1 and PowerShell 7.6.6. Single-target and batch GUI smoke checks passed on both. Remote authentication tests are mocked; production AD/HTTPS/JEA behavior still requires the [integration checklist](docs/INTEGRATION-TESTS.md). See the [validation record](docs/VALIDATION-RESULTS.md) and [changelog](CHANGELOG.md) for scope and compatibility changes.

Keep real host/service lists and exported evidence in your approved local storage. The local `Host List/` and `Service List/` directories are ignored by Git; the `examples/` directory contains generic public templates only.

## Platform references

- [Microsoft: Win32_Service fields](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service)
- [Microsoft: FileVersionInfo](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.fileversioninfo)
- [Microsoft: ConvertFrom-Json timestamp handling](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/convertfrom-json)
