# Enterprise deployment

## Recommended administrative jump server

Use a maintained domain-joined Windows jump server with an interactive desktop, approved PowerShell runtime, restricted sign-in, application control and monitored administrator access. Deploy reviewed/signed application scripts to an administrator-owned directory that ordinary operators cannot modify. Execution policy alone is not a security boundary. Protect the launcher and trusted-signer configuration with the same discipline as the code.

Connect outbound to approved target server FQDNs using explicit Kerberos. WinRM HTTP/5985 supports Kerberos message encryption; HTTPS/5986 may additionally be required by your organization. The GUI host does **not** need an inbound WinRM listener merely to connect to servers. Target listeners, firewall rules, SPNs, DNS and time synchronization are infrastructure prerequisites managed separately. The app changes none of them. [Microsoft WinRM security](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security).

In **Security settings**, select Kerberos, enable Authenticode collection, and configure evidence signing before Capture before or Load baseline. Specify an expected publisher only for applications with an approved signed component. Require signed evidence for audit use. Security settings lock once a baseline is selected; use New comparison to change them. The GUI defaults to Kerberos; this is a visible change from 0.2.0.

For a non-domain/local account, select Negotiate plus **Use HTTPS (5986)** and explicit credentials. The listener certificate must chain to a trusted root, be valid for the requested DNS name or IP SAN, and pass platform validity/revocation policy. Fix certificate deployment errors; do not bypass them. Explicit Kerberos rejects IP targets and never retries NTLM. Explicit Negotiate requires HTTPS. `Default` remains an explicitly available legacy option and may use NTLM/previously configured TrustedHosts; exclude it from your enterprise launcher/workflow when Kerberos is mandatory. Choosing Default is a policy decision, not automatic fallback. Existing sessions retain the authentication/TLS policy with which the caller created them.

## Rights needed for collection

Use a dedicated delegated account or the operator's authorized identity; do not use Domain Admin. Required rights depend on the target endpoint and service:

- Permission to connect to the selected PowerShell endpoint and execute its authorized collector.
- Read/query access to `Win32_Service` and selected `Win32_Process` properties through CIM. Reading another account's process path/start time may require privileges not granted to ordinary users.
- Read access to `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`, the selected service's configuration and (for shared hosts) `Parameters\ServiceDll`.
- Read access to the selected local EXE/DLL and metadata, plus Windows trust services for optional Authenticode verification.

No service start/stop, patch-install, filesystem write on the target, credential delegation, or Domain Admin right is required by the collector. A stock endpoint may independently require local administrator membership. Do not grant broad administrator rights merely to hide missing process data; delegate an approved endpoint/rights or accept Review. Verify the actual least-privilege account against each service family. JEA deployment is described separately. A disabled or inaccessible MachineGuid produces Review; it is never a substitute for Kerberos server identity.

## Signing keys and evidence storage

Enroll a dedicated RSA signing certificate (>=2048 bits, Digital Signature key usage) through your approved certificate process. Keep its non-exportable private key in the operator/service identity's Windows certificate key store, preferably hardware-backed where compatible. The GUI resolves the certificate from `Cert:\CurrentUser\My` by thumbprint. It does not create, export, install or trust certificates. Grant key access only to approved evidence signers; separate signing access from verification where possible. Test provider compatibility: silent CMS signing does not support every smart-card/PIN interaction.

Distribute approved certificate thumbprints independently, in an ACL-protected launcher or policy file. Never copy trust pins from an untrusted evidence file. Configure **Signing certificate thumbprint**, **Trusted evidence signers**, and **Require signed evidence**. A verifier needs trusted pins but no private key. The GUI needs a signing key for new baseline/report saves when signing is required.

Use a dedicated NTFS evidence directory. Have administrators provision ACLs: administrators/SYSTEM manage the directory, named operators write their collection area, and auditors read retained evidence. Remove inherited broad write access such as Users/Authenticated Users/Everyone; verify effective permissions before use. Keep keys, code and trust policy outside that directory. New temporary evidence files inherit parent-directory ACLs, so secure the directory before saving. Protect backups and shares equally. Use approved immutable retention/versioning for audit records; signatures detect content alteration but do not stop deletion/replay. Do not store operational evidence in the source repository or an uncontrolled synchronized folder.

Files contain hostnames, machine identifiers, service names, paths, versions, signatures and times. They are signed, **not encrypted**. Apply enterprise classification and storage encryption as appropriate. Credentials are not part of the format. Avoid secrets in service names, file paths, notes or command-line arguments; whitelisting cannot identify secrets embedded in legitimate metadata fields.

Evidence trust uses explicit pins and current certificate validity, not chain/revocation checks or trusted timestamps. Remove revoked/compromised pins and plan rotation/expiration before deployment. Preserve original evidence through retention; do not rewrite old unsigned files to manufacture a signed baseline. Capture a new baseline instead. See the trust limitations in the security review.

## Module examples

```powershell
Import-Module .\PatchValidator.psd1
# Values below come from your protected deployment configuration, not an evidence file.
$approvedSigner = 'REPLACE_WITH_APPROVED_40_HEX_CERTIFICATE_THUMBPRINT'
$certificate = Get-PatchSigningCertificate -Thumbprint $approvedSigner
$before = Get-PatchSnapshot -ServiceName 'MyService' -ComputerName 'app01.example.com' `
    -Authentication Kerberos -CheckAuthenticode
Save-PatchSnapshot $before .\before.snapshot.json -SigningCertificate $certificate -RequireSignature

# After patching: verify the original signed baseline before comparison.
$before = Read-PatchSnapshot .\before.snapshot.json -TrustedSignerThumbprint $approvedSigner -RequireSignature
$after = Get-PatchSnapshot -ServiceName 'MyService' -ComputerName 'app01.example.com' `
    -Authentication Kerberos -CheckAuthenticode
$report = Compare-PatchSnapshot $before $after -ExpectedVersion '2.4.1' -RequireSignedBaseline
Save-PatchReport $report .\after.report.json -SigningCertificate $certificate -RequireSignature
$verifiedReport = Read-PatchReport .\after.report.json -TrustedSignerThumbprint $approvedSigner -RequireSignature
$verifiedReport.Verdict
```

Use the same explicit `-VersionFile` on both captures when applicable. Add `-RequireValidSignature` and `-ExpectedPublisher 'CN=..., O=..., C=...'` only with an approved exact signer Subject. This is separate from the evidence-signing certificate.

```powershell
# Reuse an authorized FullLanguage session; caller owns its lifetime.
$session = New-PSSession -ComputerName 'app01.example.com' -Authentication Kerberos
try { $snapshot = Get-PatchSnapshot -Session $session -ServiceName 'MyService' -CheckAuthenticode }
finally { Remove-PSSession $session }
```

`-ConfigurationName` selects an existing compatible endpoint; it does not make the arbitrary collector compatible with NoLanguage JEA. See the JEA guide before using restricted endpoints.

## Credentials and operation

Use the current Windows identity where practical. The credential dialog masks entry and creates a PSCredential/SecureString; the password is not sent as a collector argument or persisted in evidence/settings. Mutable character buffers are cleared; credentials are disposed/released on Clear, target change, New comparison and exit. Immutable managed strings and copies inside PowerShell/WinRM cannot be reliably erased. Process dumps, malicious local administrators, third-party input capture and external logging remain outside this guarantee. Avoid `-Password` literals and manually logging credential objects.

Close the GUI normally with its X after capture completes. Ctrl+C interrupts the PowerShell pipeline and is not the GUI's graceful shutdown mechanism. The existing capture timeout requests cancellation after 60 seconds; it is not a guarantee that every remote/provider operation can terminate immediately.

Complete the integration checklist before rollout. A Pass concerns observed installed-component metadata and service/restart evidence; it does not prove runtime health, successful installer completion or CVE remediation.
