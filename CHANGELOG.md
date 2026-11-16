# Changelog

## 0.4.0

This release combines enterprise security hardening and CSV batch validation. It preserves the single-computer/service GUI and read-only collector.

### Batch validation

- Select one computer or a `ComputerName` CSV, independently of one service or a `DisplayName` CSV. Service files contain display names only.
- Preview all host/service combinations before enabling Capture before. Iterate sequentially with progress, per-item results, cancellation and continuation after capture failures.
- Save/load batch baselines and export signed or unsigned batch reports using the existing evidence policy. Missing captures remain visible and cannot produce Pass.
- Include generic CSV templates and detailed workflow documentation. Local operational lists are excluded from Git.

### Security hardening

- Explicit Kerberos without an NTLM retry; HTTPS Negotiate with normal certificate validation; existing authorized remoting sessions and endpoint selection.
- RSA/SHA-256 CMS signatures for evidence, with separately configured trusted signer pins. Reject malformed or modified signatures and mark unsigned/untrusted imported evidence unverified.
- Optional Authenticode collection and exact expected-publisher policy; unsigned internal applications require Review rather than being labeled malicious.
- Machine/component identity checks, contradictory hash/version detection, missing-evidence safeguards and stronger export/credential handling.
- Enterprise jump-server, key/storage, optional JEA design and integration-test guides.

### Compatibility and limitations

- The GUI defaults to Kerberos; module Default authentication remains available for existing callers. IP/local-account connections can use Negotiate with verified HTTPS. Legacy Default is a deliberate policy choice.
- Old JSON baselines remain readable but unsigned imports produce Review. Older captures without machine identity also need Review. Signed JSON files contain a CMS envelope and must be read with the verification functions.
- Display-name-only service lists have no expected target version, so they cannot confirm a specific patch. The single-service workflow retains expected-version/component selection.
- Evidence pins are explicit trust, without automatic revocation or trusted timestamps. Authenticode trusts the collecting Windows system's policy. No result proves CVE remediation or application health.
- The collector is not directly compatible with NoLanguage JEA; the supplied guide describes a restricted server-side wrapper.

Validation: 120 Pester tests and both GUI smoke checks passed on Windows PowerShell 5.1 and PowerShell 7.6.6. Real enterprise remoting/TLS/JEA integration remains a deployment check. See [validation records](docs/VALIDATION-RESULTS.md).

## 0.2.0

Initial Windows Forms client, read-only local/remote service collection, credential entry, JSON snapshots/reports, version/hash comparison and process restart checks.
