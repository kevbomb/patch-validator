# CSV batch validation

The original main window still checks one computer/service. Open **Multiple hosts / services...** at its top right to use a list. The batch window has its own credentials and HTTPS selection; its initial security policy comes from the main window. Configure them before capture. Credentials are deliberately not copied from the single-computer window or saved in CSV/evidence.

## Inputs

Choose either a single typed computer or a hosts CSV. Independently choose either a single typed service or a services CSV. A selected file overrides its corresponding single-value fields; **Clear file** returns to typed input. Every service is checked on every host. Two hosts and three services produce six rows. There is no host-to-service mapping in this version; use separate batches for different host/service groups.

Hosts CSV, UTF-8 with a header:

Download/copy the generic [hosts template](../examples/hosts.csv) and [services template](../examples/services.csv), then edit your local copies.

```csv
ComputerName
app01.example.com
app02.example.com
```

Services CSV contains only display names:

```csv
DisplayName
Windows Event Log
Print Spooler
```

Use the exact **Display name** shown in Windows Services, without wildcard discovery. The collector resolves it on each target and discovers the component path and installed version. Names are passed as data. Put names containing commas in double quotes and escape embedded quotes by doubling them. Export as **CSV UTF-8 (Comma delimited)** from Excel; semicolon-delimited regional exports are not supported. Empty lines are ignored. Extra columns, duplicate headers, malformed quoting, blank required values and duplicate host/service pairs are rejected.

The service CSV accepts only `DisplayName`; version, path, state and credential columns are not used. List captures automatically use Auto version comparison and Same as before for service state. They show before/after versions and status; without an expected target version, patch confirmation remains Review. The optional settings beside the single-service input apply only when typing one service. Applications requiring an explicit component path can use that single-service workflow.

The app reads the CSV when you click Preview list. The preview is a fixed plan; editing the file afterward does not silently change it. Re-preview before capture to pick up edits. Inputs/security policy lock when capture begins. New batch unlocks them. Changing inputs clears batch credentials and any old preview. Preview limits are 500 host/service pairs, 500 rows per CSV, and 1 MiB per CSV.

## Workflow

1. Choose inputs and click **Preview list**. Review the full host/service grid. **Capture before is disabled until a valid preview produces rows.** If rows do not appear, correct the CSV error and preview again.
2. Select the authentication/security policy and credentials if required. One account and transport policy apply to the entire batch. Use separate batches for different accounts/policies. Explicit Kerberos needs DNS names, preferably FQDNs; use verified HTTPS/Negotiate for IP/local-account connections. No TrustedHosts/listener changes or authentication fallback are performed.
3. Click **Capture before**. Captures run sequentially in background runspaces. The window remains responsive and shows progress. Select a row to inspect the result.
4. Click **Save baseline** before patching. The batch JSON contains the original connection names, service criteria and all targets, including those with missing captures. It uses the existing CMS signing/verification policy. Saving reloads verified/unsigned evidence status and clears any previous after comparison; capture after again if necessary. Unsigned saved/loaded baselines produce Review.
5. Apply patches through your usual process. Reopen the batch window and Load baseline if needed, configure the same security/HTTPS policy beforehand, and re-enter credentials. Host FQDNs are preserved independently from the short Windows computer names in snapshots.
6. Click **Capture after**. Each successful capture compares only against its own before snapshot, using existing machine/service/component identity, hash, version and restart safeguards. A target without a successful before snapshot is explicitly skipped as Review; capture a new batch before patching to establish that missing baseline.
7. Click **Export report**. All targets are included. Missing, failed, cancelled and not-yet-attempted captures cannot produce Pass. The overall verdict is Fail if any comparison fails, otherwise Review if any item is incomplete/requires review, otherwise Pass. Export recomputes comparisons, rather than trusting grid labels.

The Stop button requests cancellation of the active query and does not start remaining rows. Completed results remain visible. A repeated Capture after clears previous after results first, preventing stale Pass results for skipped rows. Each capture requests cancellation after 60 seconds; cancellation still depends on PowerShell/providers responding. A timed-out item does not stop subsequent items once cancellation completes. Closing during capture requests Stop; close again once it has stopped. Before-capture failure recovery uses New batch; automatic retry/resume is not implemented.

Batch files are distinct from single-snapshot/report files. Select them in the batch window. They contain infrastructure metadata and are not encrypted. Protect them using the same NTFS/key/pin practices as single-target evidence. The existing 4 MiB evidence limit also applies to the full signed batch; split large or verbose batches if saving exceeds it. CSV is input only; reports remain JSON to preserve structured evidence and signature verification.

## PowerShell access

Launch the batch window directly:

```powershell
powershell.exe -NoProfile -STA -File .\Start-BatchValidator.ps1
```

Preview a plan without contacting any servers:

```powershell
Import-Module .\PatchValidator.psd1
$computers = Import-PatchHostCsv .\examples\hosts.csv
$services = Import-PatchServiceCsv .\examples\services.csv
$plan = @(New-PatchBatchPlan -Hosts $computers -Services $services)
$plan | Format-Table ComputerName,ServiceName,ExpectedVersion
```

`Get-PatchBatchCapture -Target $plan[0] -Connection @{Authentication='Kerberos'}` returns Snapshot/Error for one item. Module callers own scheduling/timeouts; the GUI implements the sequential queue and cancellation. Do not put credentials in a CSV; use Get-Credential when explicitly needed.

`Save-PatchBatchBaseline` takes an Items array containing Target and Before properties. `Read-PatchBatchBaseline` restores those plus empty After/Report fields. Populate After for each matching target, then `Save-PatchBatchReport` recomputes each result. Both save functions support SigningCertificate/RequireSignature; both read functions support TrustedSignerThumbprint/RequireSignature. `Save-PatchBatchReport` also supports RequireSignedBaseline, RequireValidSignature and ExpectedPublisher. Read unsigned reports with `Read-PatchBatchReport` to mark both aggregate and nested verdicts unverified/Review.

No scan runs merely from selecting a file or previewing it. No batch operation installs patches or controls services. Actual domain reachability and privileges must be validated against your approved target list.

## Local validation

The 0.4.0 change was validated on Windows PowerShell 5.1.26100.9444 and PowerShell 7.6.6: **120 Pester tests passed, zero failed**, including the existing 101 scenarios and 19 batch scenarios. Both single-target and batch GUI smoke checks passed on both runtimes. The batch smoke check uses real background runspaces with simulated captures to exercise queue continuation after a failure, before/after matching, cancellation, stale-result clearing and control/credential state. Main-window and batch layouts were rendered for visual inspection. These checks do not establish live multi-server WinRM behavior; complete the enterprise integration checklist with your authorized hosts.
