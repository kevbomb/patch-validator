# Executed locally or through an existing, authorized PowerShell remoting connection.
param([string]$ServiceName, [string]$VersionFile, [switch]$CheckAuthenticode)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$notes = New-Object 'System.Collections.Generic.List[string]'
$computerIdentity = $null
try {
    $identityValue = [string](Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
    $identityGuid = [guid]::Empty
    if ([guid]::TryParse($identityValue,[ref]$identityGuid) -and $identityGuid -ne [guid]::Empty) { $computerIdentity = $identityGuid.ToString() }
} catch { }
if (-not $computerIdentity) { $notes.Add('The Windows machine identity could not be read. Cross-capture device identity requires review.') }

function Resolve-ServiceFile([string]$CommandLine) {
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $expanded = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    if ($expanded.StartsWith('\??\')) { $expanded = $expanded.Substring(4) }
    if ($expanded.StartsWith('\SystemRoot\', [StringComparison]::OrdinalIgnoreCase)) {
        $expanded = Join-Path $env:SystemRoot $expanded.Substring(12)
    }
    if ($expanded -match '^"([^"\r\n]+)"') { return $Matches[1] }
    if ($expanded -match '^(.*?\.(?:exe|com|sys))(?=\s|$)') { return $Matches[1] }
    return $null
}

# Compare names as data, without interpolating a WQL expression or using wildcards.
$services = @(Get-CimInstance -ClassName Win32_Service -OperationTimeoutSec 20)
$matchesByName = @($services | Where-Object { $_.Name -ieq $ServiceName })
if ($matchesByName.Count -eq 0) {
    $matchesByName = @($services | Where-Object { $_.DisplayName -ieq $ServiceName })
}
if ($matchesByName.Count -ne 1) {
    if ($matchesByName.Count -eq 0) { throw "Service '$ServiceName' was not found on $env:COMPUTERNAME. Enter its exact service name or display name." }
    throw "More than one service has that display name. Use the service name from services.msc."
}
$service = $matchesByName[0]
$executable = Resolve-ServiceFile ([string]$service.PathName)
$processStart = $null
$processPath = $null
if ($service.ProcessId -gt 0) {
    try {
        $process = Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId = {0}' -f [uint32]$service.ProcessId) -OperationTimeoutSec 10
        if ($null -ne $process) {
            if ($process.CreationDate) { $processStart = $process.CreationDate.ToUniversalTime().ToString('o') }
            $processPath = [string]$process.ExecutablePath
        }
    } catch { $notes.Add('Could not read process details. Restart verification may be unavailable.') }
    if (-not [string]::IsNullOrWhiteSpace($processPath)) { $executable = $processPath }
}

$source = 'Service executable'
$versionPath = $executable
$selectionReliable = $true
if (-not $processPath -and $executable -match '\s' -and -not $service.PathName.Trim().StartsWith('"') -and -not $VersionFile) {
    $selectionReliable = $false
    $notes.Add('The configured executable path contains unquoted spaces, and the process path is unavailable. Select the actual component file to resolve the ambiguity.')
}
$hostName = if ($executable) { [IO.Path]::GetFileName($executable).ToLowerInvariant() } else { '' }
if (-not [string]::IsNullOrWhiteSpace($VersionFile)) {
    $versionPath = [Environment]::ExpandEnvironmentVariables($VersionFile.Trim().Trim('"'))
    $source = 'Selected component'
} elseif ($hostName -eq 'svchost.exe') {
    $versionPath = $null
    $source = 'Service DLL'
    try {
        $parametersKey = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{0}\Parameters' -f $service.Name
        $dll = Get-ItemProperty -LiteralPath $parametersKey -Name ServiceDll -ErrorAction Stop
        $versionPath = [Environment]::ExpandEnvironmentVariables([string]$dll.ServiceDll).Trim('"')
    } catch {
        $selectionReliable = $false
        $notes.Add('This is a shared-host service and its ServiceDll could not be resolved. Select the actual application component file.')
    }
} elseif ($hostName -in @('java.exe','javaw.exe','dotnet.exe','python.exe','pythonw.exe','powershell.exe','pwsh.exe','cmd.exe','rundll32.exe','dllhost.exe','nssm.exe','winsw.exe')) {
    $versionPath = $null
    $selectionReliable = $false
    $notes.Add('The executable is a runtime or service wrapper. Select the application EXE/DLL; the host version would not identify the application patch.')
}

$productVersion = $null
$fileVersion = $null
$hash = $null
$modified = $null
$product = $null
$company = $null
$authenticode = [pscustomobject][ordered]@{
    Status='NotChecked';SignerSubject=$null;SignerThumbprint=$null;Publisher=$null;Issuer=$null
    NotBeforeUtc=$null;NotAfterUtc=$null;CertificateTimeValid=$null;TimestampSignerSubject=$null
}
if ($versionPath) {
    $fileStream = $null
    try {
        if (-not [IO.Path]::IsPathRooted($versionPath)) { throw 'The component path is not absolute.' }
        if ($versionPath.StartsWith('\\')) { throw 'Use a file on the target computer, not a UNC path.' }
        $file = Get-Item -LiteralPath $versionPath -ErrorAction Stop
        if ($file.PSIsContainer) { throw 'The component path is a directory.' }
        $versionPath = $file.FullName
        # Deny concurrent writes/deletes while reading metadata, hash, and signature.
        # A file already open for writing produces an unreliable capture instead of mixed evidence.
        $fileStream = [IO.File]::Open($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $lengthBefore = $file.Length
        $modifiedBefore = $file.LastWriteTimeUtc
        $metadata = [Diagnostics.FileVersionInfo]::GetVersionInfo($file.FullName)
        $productVersion = ([string]$metadata.ProductVersion).Trim()
        $fileVersion = ([string]$metadata.FileVersion).Trim()
        $product = [string]$metadata.ProductName
        $company = [string]$metadata.CompanyName
        $modified = $file.LastWriteTimeUtc.ToString('o')
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
        if ($CheckAuthenticode) {
            try {
                $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName -ErrorAction Stop
                $authenticode.Status = [string]$signature.Status
                $certificate = $signature.SignerCertificate
                if ($null -ne $certificate) {
                    $authenticode.SignerSubject = $certificate.Subject
                    $authenticode.SignerThumbprint = $certificate.Thumbprint
                    $authenticode.Publisher = $certificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)
                    $authenticode.Issuer = $certificate.Issuer
                    $authenticode.NotBeforeUtc = $certificate.NotBefore.ToUniversalTime().ToString('o')
                    $authenticode.NotAfterUtc = $certificate.NotAfter.ToUniversalTime().ToString('o')
                    $authenticode.CertificateTimeValid = [DateTime]::UtcNow -ge $certificate.NotBefore.ToUniversalTime() -and [DateTime]::UtcNow -le $certificate.NotAfter.ToUniversalTime()
                }
                if ($null -ne $signature.TimeStamperCertificate) { $authenticode.TimestampSignerSubject = $signature.TimeStamperCertificate.Subject }
            } catch { $authenticode.Status = 'Unavailable'; $notes.Add('Authenticode validation was unavailable. Check file access and certificate trust services.') }
        }
        $file.Refresh()
        if ($file.Length -ne $lengthBefore -or $file.LastWriteTimeUtc -ne $modifiedBefore) {
            $selectionReliable = $false
            $notes.Add('The component changed during capture. Wait for patching to finish, then capture again.')
        }
        if (-not $productVersion -and -not $fileVersion) { $notes.Add('The selected file does not publish product or file version metadata.') }
    } catch {
        $selectionReliable = $false
        if ($versionPath.StartsWith('\\')) { $notes.Add('UNC component paths are not supported.') }
        else { $notes.Add('Could not inspect the component. Check the absolute local path, read permissions, and whether patching is still in progress.') }
    } finally {
        if ($null -ne $fileStream) { $fileStream.Dispose() }
    }
} else {
    $selectionReliable = $false
    if ($notes.Count -eq 0) { $notes.Add('Could not identify the service executable. Select its application component file.') }
}

# A snapshot taken while the service changes state must not become a confident pass.
$stateAtEnd = Get-CimInstance -ClassName Win32_Service -OperationTimeoutSec 20 |
    Where-Object { $_.Name -ieq $service.Name } | Select-Object -First 1
if ($null -eq $stateAtEnd -or $stateAtEnd.State -ne $service.State -or $stateAtEnd.ProcessId -ne $service.ProcessId) {
    $selectionReliable = $false
    $notes.Add('Service state changed during capture. Capture again when the service is stable.')
}

[pscustomobject][ordered]@{
    SchemaVersion = 1
    CapturedAtUtc = [DateTime]::UtcNow.ToString('o')
    ComputerName = $env:COMPUTERNAME
    ComputerIdentity = $computerIdentity
    ServiceName = [string]$service.Name
    DisplayName = [string]$service.DisplayName
    State = [string]$service.State
    StartMode = [string]$service.StartMode
    ProcessId = [long]$service.ProcessId
    ProcessStartedAtUtc = $processStart
    ExecutablePath = $executable
    VersionPath = $versionPath
    VersionSource = $source
    ProductName = $product
    CompanyName = $company
    ProductVersion = $productVersion
    FileVersion = $fileVersion
    FileSha256 = $hash
    FileModifiedAtUtc = $modified
    SelectionReliable = $selectionReliable
    Notes = @($notes.ToArray())
    Authenticode = $authenticode
}
