<#
.SYNOPSIS
    Runs Integration Pester tests
.EXAMPLE
    .\Invoke-PesterTests.ps1

#>
param (
    $TestPath = $PSScriptRoot,
    $Username,
    $Secret
)
Write-Host "Running test files found in $TestPath"
if ($Secret.length -gt 0) {
    Write-Host "Creating credential object for $Username"
    $SecurePassword = $Secret | ConvertTo-SecureString -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential -ArgumentList $Username, $SecurePassword -ErrorAction Stop
    $PesterContainer = New-PesterContainer -Path $TestPath -Data @{ 'Credential' = $Credential }
} else {
    $PesterContainer = New-PesterContainer -Path $TestPath
}
$PesterResult = Invoke-Pester -Container $PesterContainer -ErrorAction Stop -Output Detailed -PassThru
if ($PesterResult.Result -ne 'Passed') { Exit 1; return }