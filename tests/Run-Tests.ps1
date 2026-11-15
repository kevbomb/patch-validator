#requires -Version 5.1
$ErrorActionPreference = 'Stop'
$projectDirectory = Split-Path $PSScriptRoot -Parent
$parseProblems = @()
Get-ChildItem -LiteralPath $projectDirectory -Recurse -File | Where-Object Extension -in @('.ps1','.psm1','.psd1') | ForEach-Object {
    $parseTokens = $null
    $parseErrors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$parseTokens,[ref]$parseErrors)
    $parseProblems += @($parseErrors)
}
if ($parseProblems.Count -gt 0) { $parseProblems | Format-List; throw 'PowerShell syntax validation failed.' }
# Use the Pester generation bundled with Windows PowerShell. No download is required.
Import-Module Pester -MinimumVersion 3.4 -MaximumVersion 4.99 -Force -ErrorAction Stop
$result = Invoke-Pester -Script $PSScriptRoot -PassThru
if ($result.FailedCount -gt 0 -or $result.PassedCount -eq 0) { throw 'Patch Validator tests failed.' }
Write-Output ('Validated {0} tests on PowerShell {1}.' -f $result.PassedCount,$PSVersionTable.PSVersion)
