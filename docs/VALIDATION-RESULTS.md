# Local validation records

## v0.4.0 — security hardening and display-name CSV batches

Before publication, the complete suite passed **120 tests, 0 failed, 0 skipped** on Windows PowerShell 5.1.26100.9444 and PowerShell 7.6.6. Both the single-target and batch GUI smoke checks passed on both runtimes. The batch queue tests use real background runspaces with simulated results to check per-item failure continuation, before/after association, cancellation and stale-result clearing. CSV tests cover the one-column `DisplayName` format, invalid extra columns and normal parsing; signature tests use real ephemeral RSA/CMS signatures.

No live multi-server AD/HTTPS/JEA validation was performed. The real local capture recorded below belongs to the security review. This release retains its integration limitations and adds the batch validation described in [BATCH.md](BATCH.md).

## v0.3.0 security review — 2026-11-15

Base revision: `5a8a84b661b093106dc016e34c15086328220728`. Changes identify themselves as module version 0.3.0.

Executed on Windows during this review:

| Check | Result |
| --- | --- |
| `powershell.exe -NoProfile -File .\tests\Run-Tests.ps1` | Windows PowerShell 5.1.26100.9444: **101 passed, 0 failed, 0 skipped**. Includes PowerShell syntax parsing. |
| `pwsh.exe -NoProfile -File .\tests\Run-Tests.ps1` | PowerShell 7.6.6: **101 passed, 0 failed, 0 skipped**. |
| GUI `-SmokeTest` | Passed under both runtimes. Checks real control initialization, defaults, credential clearing and settings disabled during capture. |
| Layout preview | Rendered and visually inspected main window and security dialog control layout. This is not full interactive/DPI coverage. |
| Real local `Get-PatchSnapshot -ServiceName EventLog -CheckAuthenticode` | Passed on PowerShell 7: Running service, Service DLL source, reliable selection, Windows machine identity present, 64-character SHA-256, Valid Authenticode status and signer metadata, no notes. Read-only capture. |
| Git whitespace check | Passed with Windows checkout line-ending normalization. |

The real local capture initially received CIM Access denied inside the execution sandbox. It was repeated outside that sandbox with approval and succeeded. This does not establish collection success for a non-administrator domain account.

The suite retains the original 53 scenarios (with the intentional unsigned-baseline expectation updated) and adds 48. New coverage includes actual in-memory RSA/CMS round-trips, changed payload/signature rejection, unknown signers, weak/expired signing-key rejection, preservation of output on signing failure, untrusted legacy evidence, forged trust markers/verdicts, report integrity, credential-property exclusion, metadata contradictions, optional executable signatures, remoting dispatch and security controls.

Not executed: live AD Kerberos/NTLM telemetry, real WinRM HTTPS success/failure and revocation tests, actual remote PSSession reuse, JEA endpoint deployment, enterprise certificate-store key ACLs/provider compatibility, restricted-account collection, signing-pin deployment/rotation, production storage ACLs or application-specific patch/CVE validation. Remote and executable-signature failure tests use mocks; CMS cryptographic tests use real signatures. No tests installed certificates, modified Defender/WinRM/firewall policy, patched software or controlled services.

Run the [integration checklist](INTEGRATION-TESTS.md) in an authorized test environment before production approval. Retain the resulting deployment-specific evidence separately.
