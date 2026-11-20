Import-Module (Join-Path $PSScriptRoot '..\PatchValidator.psd1') -Force

function New-SecuritySnapshot([switch]$After,[hashtable]$Changes=@{}) {
    $data = [ordered]@{
        SchemaVersion=1;CapturedAtUtc='2026-01-01T10:00:00Z';ComputerName='SERVER1';ComputerIdentity='11111111-1111-1111-1111-111111111111'
        ServiceName='ExampleService';DisplayName='Example';State='Running';StartMode='Auto';ProcessId=100
        ProcessStartedAtUtc='2026-01-01T09:00:00Z';ExecutablePath='C:\App\service.exe';VersionPath='C:\App\service.exe'
        VersionSource='Service executable';ProductName='Example';CompanyName='Example';ProductVersion='1.0.0';FileVersion='1.0.0.0'
        FileSha256=('A'*64);FileModifiedAtUtc='2026-01-01T08:00:00Z';SelectionReliable=$true;Notes=@()
    }
    if ($After) {
        $data.CapturedAtUtc='2026-01-01T10:10:00Z';$data.ProcessStartedAtUtc='2026-01-01T10:05:00Z'
        $data.ProductVersion='1.1.0';$data.FileVersion='1.1.0.0';$data.FileSha256=('B'*64)
    }
    foreach ($name in $Changes.Keys) { $data[$name]=$Changes[$name] }
    [pscustomobject]$data
}
function Assert-SecurityThrows([scriptblock]$Action,[string]$Message='*') {
    $caught = $null
    try { & $Action | Out-Null } catch { $caught = $_ }
    ($null -ne $caught) | Should Be $true
    if ($null -ne $caught -and $Message -ne '*') { $caught.Exception.Message | Should Match $Message }
}
function New-SecurityCertificate([int]$KeySize=2048,[switch]$Expired) {
    $key = New-Object Security.Cryptography.RSACng($KeySize)
    $request = New-Object Security.Cryptography.X509Certificates.CertificateRequest(
        'CN=Patch Validator Ephemeral Test',$key,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $validUntil = if ($Expired) { [DateTimeOffset]::UtcNow.AddMinutes(-1) } else { [DateTimeOffset]::UtcNow.AddHours(1) }
    $certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5),$validUntil)
    [pscustomobject]@{Certificate=$certificate;Key=$key}
}

Describe 'Real evidence signatures without installing keys or trusting certificates' {
    BeforeEach {
        $fixture = New-SecurityCertificate
        $path = Join-Path $TestDrive ([Guid]::NewGuid().ToString() + '.json')
        $before = New-SecuritySnapshot
        $after = New-SecuritySnapshot -After
    }
    AfterEach { if ($null -ne $fixture) { $fixture.Certificate.Dispose(); $fixture.Key.Dispose() } }
    It 'round trips a real CMS signed baseline with an independently pinned signer' {
        Save-PatchSnapshot $before $path -SigningCertificate $fixture.Certificate -RequireSignature
        $loaded = Read-PatchSnapshot $path -TrustedSignerThumbprint $fixture.Certificate.Thumbprint -RequireSignature
        $loaded.EvidenceVerification | Should Be Verified
        (Compare-PatchSnapshot $loaded $after -ExpectedVersion 1.1 -RequireSignedBaseline).Verdict | Should Be Pass
    }
    It 'rejects a modified signature instead of falling back to unsigned loading' {
        Save-PatchSnapshot $before $path -SigningCertificate $fixture.Certificate
        $envelope = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $bytes = [Convert]::FromBase64String($envelope.Cms)
        $bytes[$bytes.Length-1] = $bytes[$bytes.Length-1] -bxor 1
        $envelope.Cms = [Convert]::ToBase64String($bytes)
        [IO.File]::WriteAllText($path,($envelope | ConvertTo-Json))
        Assert-SecurityThrows { Read-PatchSnapshot $path -TrustedSignerThumbprint $fixture.Certificate.Thumbprint } 'signature verification failed'
    }
    It 'rejects a changed signed payload even though its JSON remains valid' {
        Save-PatchSnapshot $before $path -SigningCertificate $fixture.Certificate
        $envelope = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $bytes = [Convert]::FromBase64String($envelope.Cms)
        $needle = [Text.Encoding]::UTF8.GetBytes('ExampleService')
        $changed = $false
        for ($i=0;$i -le $bytes.Length-$needle.Length;$i++) {
            $match = $true
            for ($j=0;$j -lt $needle.Length;$j++) { if ($bytes[$i+$j] -ne $needle[$j]) { $match=$false;break } }
            if ($match) { $bytes[$i]=[byte][char]'X';$changed=$true;break }
        }
        $changed | Should Be $true
        $envelope.Cms=[Convert]::ToBase64String($bytes)
        [IO.File]::WriteAllText($path,($envelope | ConvertTo-Json))
        Assert-SecurityThrows { Read-PatchSnapshot $path -TrustedSignerThumbprint $fixture.Certificate.Thumbprint } 'signature verification failed'
    }
    It 'does not trust a valid self-signed file just because it includes its certificate' {
        Save-PatchSnapshot $before $path -SigningCertificate $fixture.Certificate
        $loaded = Read-PatchSnapshot $path
        $loaded.EvidenceVerification | Should Be UntrustedSigner
        (Compare-PatchSnapshot $loaded $after -ExpectedVersion 1.1).Verdict | Should Be Review
        Assert-SecurityThrows { Read-PatchSnapshot $path -TrustedSignerThumbprint ('0'*40) -RequireSignature } 'required'
    }
    It 'rejects an attacker certificate when another signer is pinned' {
        $attacker = New-SecurityCertificate
        try {
            Save-PatchSnapshot $before $path -SigningCertificate $attacker.Certificate
            Assert-SecurityThrows { Read-PatchSnapshot $path -TrustedSignerThumbprint $fixture.Certificate.Thumbprint -RequireSignature } 'required'
        } finally { $attacker.Certificate.Dispose();$attacker.Key.Dispose() }
    }
    It 'detects edits made to a verified object before comparison' {
        Save-PatchSnapshot $before $path -SigningCertificate $fixture.Certificate
        $loaded = Read-PatchSnapshot $path -TrustedSignerThumbprint $fixture.Certificate.Thumbprint
        $loaded.ProductVersion='9.0.0'
        (Compare-PatchSnapshot $loaded $after -ExpectedVersion 1.1).BaselineVerification | Should Be Modified
        (Compare-PatchSnapshot $loaded $after -ExpectedVersion 1.1).Verdict | Should Be Fail
        Assert-SecurityThrows { Save-PatchSnapshot $loaded $path -SigningCertificate $fixture.Certificate } 'cannot be re-signed'
    }
    It 'marks legacy files unverified and ignores a forged trust marker' {
        Save-PatchSnapshot $before $path
        $document = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $document.Snapshot | Add-Member EvidenceVerification Verified
        [IO.File]::WriteAllText($path,($document | ConvertTo-Json -Depth 8))
        $loaded = Read-PatchSnapshot $path
        $loaded.EvidenceVerification | Should Be Unsigned
        $loaded.EvidenceVerification='Verified'
        (Compare-PatchSnapshot $loaded $after -ExpectedVersion 1.1).Verdict | Should Be Review
        Assert-SecurityThrows { Read-PatchSnapshot $path -RequireSignature } 'required'
        Assert-SecurityThrows { Save-PatchSnapshot $loaded $path -SigningCertificate $fixture.Certificate } 'cannot be re-signed'
    }
    It 'does not write when a required signing key is missing' {
        Assert-SecurityThrows { Save-PatchSnapshot $before $path -RequireSignature } 'Signing is required'
        (Test-Path -LiteralPath $path) | Should Be $false
    }
    It 'rejects expired and weak evidence signing certificates' {
        foreach ($options in @(@{Expired=$true},@{KeySize=1024})) {
            $invalid = New-SecurityCertificate @options
            try { Assert-SecurityThrows { Save-PatchSnapshot $before $path -SigningCertificate $invalid.Certificate } }
            finally { $invalid.Certificate.Dispose();$invalid.Key.Dispose() }
        }
        (Test-Path -LiteralPath $path) | Should Be $false
    }
    It 'preserves existing evidence if a required signing key is missing' {
        Save-PatchSnapshot $before $path -SigningCertificate $fixture.Certificate
        $original = [IO.File]::ReadAllText($path)
        Assert-SecurityThrows { Save-PatchSnapshot $after $path -RequireSignature } 'Signing is required'
        [IO.File]::ReadAllText($path) | Should Be $original
    }
    It 'preserves single-note arrays through a signed round trip' {
        $before.Notes=@('An unresolved capture condition')
        Save-PatchSnapshot $before $path -SigningCertificate $fixture.Certificate
        $loaded=Read-PatchSnapshot $path -TrustedSignerThumbprint $fixture.Certificate.Thumbprint -RequireSignature
        $loaded.Notes.Count | Should Be 1
        (Compare-PatchSnapshot $loaded $after -ExpectedVersion 1.1).Verdict | Should Be Review
    }
    It 'rejects malformed CMS instead of treating the envelope as legacy JSON' {
        [IO.File]::WriteAllText($path,'{"DocumentType":"PatchValidatorSignedEvidence","SchemaVersion":1,"Cms":"Not valid base64!"}')
        Assert-SecurityThrows { Read-PatchSnapshot $path } 'signature verification failed'
    }
    It 'signs reports and verifies their complete payload' {
        Save-PatchSnapshot $before $path -SigningCertificate $fixture.Certificate
        $loaded = Read-PatchSnapshot $path -TrustedSignerThumbprint $fixture.Certificate.Thumbprint
        $report = Compare-PatchSnapshot $loaded $after -ExpectedVersion 1.1 -RequireSignedBaseline
        Save-PatchReport $report $path -SigningCertificate $fixture.Certificate -RequireSignature
        $verified = Read-PatchReport $path -TrustedSignerThumbprint $fixture.Certificate.Thumbprint -RequireSignature
        $verified.EvidenceVerification | Should Be Verified
        $verified.Verdict | Should Be Pass
    }
    It 'labels unsigned reports unverified even when they claim Pass' {
        Save-PatchReport (Compare-PatchSnapshot $before $after -ExpectedVersion 1.1) $path
        $loaded = Read-PatchReport $path
        $loaded.EvidenceVerification | Should Be Unsigned
        $loaded.Verdict | Should Be Review
        $loaded.UnverifiedClaimedVerdict | Should Be Pass
    }
    It 'rejects a modified report signature and an unapproved report signer' {
        Save-PatchReport (Compare-PatchSnapshot $before $after -ExpectedVersion 1.1) $path -SigningCertificate $fixture.Certificate
        Assert-SecurityThrows { Read-PatchReport $path -TrustedSignerThumbprint ('0'*40) -RequireSignature } 'required'
        $envelope = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $bytes = [Convert]::FromBase64String($envelope.Cms)
        $bytes[$bytes.Length-1] = $bytes[$bytes.Length-1] -bxor 1
        $envelope.Cms = [Convert]::ToBase64String($bytes)
        [IO.File]::WriteAllText($path,($envelope | ConvertTo-Json))
        Assert-SecurityThrows { Read-PatchReport $path -TrustedSignerThumbprint $fixture.Certificate.Thumbprint } 'signature verification failed'
    }
    It 'strips unexpected credential properties from both evidence formats' {
        $before | Add-Member Password 'Dummy secret must not be exported'
        Save-PatchSnapshot $before $path
        (Get-Content -LiteralPath $path -Raw).Contains('Dummy secret') | Should Be $false
        $report = Compare-PatchSnapshot $before $after -ExpectedVersion 1.1
        $report | Add-Member Credential 'Dummy secret must not be exported'
        Save-PatchReport $report $path
        (Get-Content -LiteralPath $path -Raw).Contains('Dummy secret') | Should Be $false
    }
    It 'recomputes a report rather than exporting an edited Pass verdict' {
        $report = Compare-PatchSnapshot $before $after -ExpectedVersion 9.0
        $report.Verdict='Pass'
        Save-PatchReport $report $path -SigningCertificate $fixture.Certificate
        (Read-PatchReport $path -TrustedSignerThumbprint $fixture.Certificate.Thumbprint).Verdict | Should Be Fail
    }
}

Describe 'Security comparison regressions' {
    BeforeEach { $before=New-SecuritySnapshot; $after=New-SecuritySnapshot -After }
    It 'fails identical hashes with conflicting embedded versions' {
        $after.FileSha256=$before.FileSha256
        (Compare-PatchSnapshot $before $after -ExpectedVersion 1.1).Verdict | Should Be Fail
    }
    It 'requires a component identity even if reliability was asserted' {
        $after.VersionPath=$null
        (Compare-PatchSnapshot $before $after -ExpectedVersion 1.1).Verdict | Should Be Review
    }
    It 'requires the component modification time for restart evidence' {
        $after.FileModifiedAtUtc=$null
        (Compare-PatchSnapshot $before $after -ExpectedVersion 1.1).Verdict | Should Be Review
    }
    It 'rejects two Windows identities with the same computer name' {
        $after.ComputerIdentity='22222222-2222-2222-2222-222222222222'
        Assert-SecurityThrows { Compare-PatchSnapshot $before $after -ExpectedVersion 1.1 } 'different Windows machines'
    }
    It 'reviews legacy captures without Windows machine identity' {
        $before.PSObject.Properties.Remove('ComputerIdentity')
        (Compare-PatchSnapshot $before $after -ExpectedVersion 1.1).Verdict | Should Be Review
    }
    It 'reviews a future process start and a running service without a PID' {
        $after.ProcessStartedAtUtc='2026-01-01T11:00:00Z';$after.ProcessId=0
        (Compare-PatchSnapshot $before $after -ExpectedVersion 1.1).Verdict | Should Be Review
    }
    It 'does not accept missing signature evidence under the required publisher policy' {
        (Compare-PatchSnapshot $before $after -ExpectedVersion 1.1 -RequireValidSignature).Verdict | Should Be Review
    }
    It 'reviews unsigned internal applications without labeling them malicious' {
        $after | Add-Member Authenticode ([pscustomobject]@{Status='NotSigned'})
        $report = Compare-PatchSnapshot $before $after -ExpectedVersion 1.1 -RequireValidSignature
        $report.Verdict | Should Be Review
    }
    It 'fails a mismatched file signature and reviews untrusted publishers' {
        $after | Add-Member Authenticode ([pscustomobject]@{Status='HashMismatch'})
        (Compare-PatchSnapshot $before $after -ExpectedVersion 1.1).Verdict | Should Be Fail
        $after.Authenticode.Status='NotTrusted'
        (Compare-PatchSnapshot $before $after -ExpectedVersion 1.1).Verdict | Should Be Review
    }
    It 'requires complete signer evidence and an exact expected subject' {
        $after | Add-Member Authenticode ([pscustomobject]@{Status='Valid';SignerSubject='CN=Example Publisher';SignerThumbprint=('A'*40);Issuer='CN=Example CA';NotBeforeUtc='2025-01-01T00:00:00Z';NotAfterUtc='2028-01-01T00:00:00Z';CertificateTimeValid=$true;TimestampSignerSubject=$null})
        (Compare-PatchSnapshot $before $after -ExpectedVersion 1.1 -ExpectedPublisher 'CN=Example Publisher').Verdict | Should Be Pass
        (Compare-PatchSnapshot $before $after -ExpectedVersion 1.1 -ExpectedPublisher 'CN=Different Publisher').Verdict | Should Be Fail
        $after.Authenticode.SignerThumbprint=$null
        (Compare-PatchSnapshot $before $after -ExpectedVersion 1.1 -RequireValidSignature).Verdict | Should Be Review
    }
    It 'does not trust a caller supplied Verified label' {
        $before | Add-Member EvidenceVerification Verified
        (Compare-PatchSnapshot $before $after -ExpectedVersion 1.1 -RequireSignedBaseline).Verdict | Should Be Review
    }
    It 'rejects malformed executable certificate dates' {
        $after | Add-Member Authenticode ([pscustomobject]@{Status='Valid';NotBeforeUtc='not-a-date'})
        Assert-SecurityThrows { Compare-PatchSnapshot $before $after -ExpectedVersion 1.1 } 'certificate date'
        $after.Authenticode.NotBeforeUtc='2030-01-01T00:00:00Z'
        $after.Authenticode | Add-Member NotAfterUtc '2020-01-01T00:00:00Z'
        Assert-SecurityThrows { Compare-PatchSnapshot $before $after -ExpectedVersion 1.1 } 'validity interval'
    }
    It 'rejects malformed hashes and flags missing hashes or unreliable data' {
        $after.FileSha256='not-a-sha256'
        Assert-SecurityThrows { Compare-PatchSnapshot $before $after -ExpectedVersion 1.1 } 'SHA-256'
        $after.FileSha256=$null;$after.SelectionReliable=$false
        (Compare-PatchSnapshot $before $after -ExpectedVersion 1.1).Verdict | Should Be Review
    }
    It 'does not claim that version comparison proves CVE remediation' {
        (Compare-PatchSnapshot $before $after -ExpectedVersion 1.1).Scope | Should Match 'not.*CVE remediation'
    }
}

Describe 'GUI error sanitization' {
    It 'does not echo remote error strings containing credentials or arbitrary input' {
        try { throw 'Authentication failed password=DummySensitiveValue token=DummyToken' }
        catch {
            $message = Get-PatchErrorMessage $_
            $message.Contains('DummySensitiveValue') | Should Be $false
            $message.Contains('DummyToken') | Should Be $false
            $message | Should Match 'Authentication or authorization'
        }
    }
    It 'gives certificate and Kerberos guidance without dumping exceptions' {
        try { throw 'SSL certificate invalid for secret-internal-name' } catch { (Get-PatchErrorMessage $_) | Should Match 'certificate validation' }
        try { throw 'Kerberos SPN error for secret-account' } catch { (Get-PatchErrorMessage $_) | Should Match 'No NTLM fallback' }
    }
}
