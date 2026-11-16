@{
    RootModule = 'PatchValidator.psm1'
    ModuleVersion = '0.4.0'
    GUID = 'd54bb3b4-4a59-4f86-bdd2-5909b9abced1'
    Author = 'Patch Validator contributors'
    Description = 'Read-only Windows service snapshots and before/after patch validation.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Get-PatchSnapshot', 'Compare-PatchSnapshot', 'Save-PatchSnapshot', 'Read-PatchSnapshot', 'Save-PatchReport', 'Read-PatchReport', 'Get-PatchSigningCertificate', 'Get-PatchErrorMessage', 'Import-PatchHostCsv', 'Import-PatchServiceCsv', 'New-PatchBatchPlan', 'Get-PatchBatchCapture', 'Save-PatchBatchBaseline', 'Read-PatchBatchBaseline', 'Save-PatchBatchReport', 'Read-PatchBatchReport')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
}
