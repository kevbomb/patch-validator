# Optional JEA deployment design

The current collector is a bundled PowerShell script sent to `Invoke-Command`. It uses expressions, types, CIM, registry reads and local file APIs. A normal JEA endpoint uses NoLanguage for callers and does **not** permit this arbitrary script. Supplying its name through `-ConfigurationName` or passing its PSSession does not remove this limitation. Do not weaken the endpoint to FullLanguage to claim JEA compatibility.

An enterprise administrator can deploy a restricted server-side wrapper:

1. Install the reviewed collector and a trusted module in an administrator-owned target directory; operator accounts must not be able to replace them.
2. Implement one exported function such as `Get-ApprovedPatchSnapshot`. Give it a `ValidateSet` of approved service identifiers. Internally map each identifier to a fixed local service/component path and call the installed collector. Set Authenticode collection server-side. Return only the snapshot, with no ability to write files or invoke arbitrary commands.
3. Expose only that function in the role capability. Do not expose arbitrary script blocks, filesystem providers, `Invoke-Expression`, `Invoke-Command`, `Get-CimInstance`, unrestricted registry/file commands or unrestricted `VersionFile` parameters. Validate inputs inside the trusted function as well as in role metadata. Prevent aliases, wildcard service selection, UNC/device paths and caller-controlled module paths from expanding authority.
4. Map a dedicated AD group to that capability. Use a non-administrator execution identity with the exact read permissions documented in ENTERPRISE.md. On supported member servers, an explicitly selected `RunAsVirtualAccountGroups` set can restrict virtual-account privileges; alternatively review a dedicated gMSA's rights. Do not rely on JEA's default elevated virtual-account membership. In particular, domain controllers have different privileged defaults; require a separate security review before deployment there. No second-hop network access is needed.
5. Have administrators review and deploy the endpoint, role definitions, transcript retention/ACLs and network restrictions through normal configuration management. This repository does not create endpoints, grant privileges or change WinRM. Trusted wrapper code runs with endpoint authority and must itself be reviewed for injection/path bypasses.
6. Verify that authorized callers can request only approved snapshots, cannot change the service/path mapping, cannot execute arbitrary expressions/commands and cannot modify installed code. Test unauthorized accounts and every service family with the actual execution identity.

Use an authorized proxy for the server-side command, then the local module for evidence/comparison:

```powershell
$session = New-PSSession -ComputerName 'app01.example.com' -Authentication Kerberos `
    -ConfigurationName 'ApprovedPatchReadOnly'
$proxy = $null
try {
    $proxy = Import-PSSession $session -CommandName Get-ApprovedPatchSnapshot -DisableNameChecking
    $before = Get-ApprovedPatchSnapshot -ServiceName 'MyApprovedService'
    # Validate/save/sign locally with the PatchValidator module.
    # Do not call Get-PatchSnapshot -Session against this NoLanguage endpoint.
} finally {
    if ($null -ne $proxy) { Remove-Module $proxy }
    Remove-PSSession $session
}
```

The command and endpoint names above describe a deployment design, not shipped implementations. The present GUI does not invoke this custom proxy workflow; use the module workflow or implement a separately reviewed GUI adapter. This guide is the optional JEA deliverable, not a claim of tested JEA compatibility.

References: [role capabilities](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities), [security considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations), [using JEA and implicit remoting](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/using-jea).
