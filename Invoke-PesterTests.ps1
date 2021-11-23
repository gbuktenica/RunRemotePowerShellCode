<#
.SYNOPSIS
    Runs Integration Pester tests
.EXAMPLE
    .\Invoke-PesterTests.ps1
#>
[CmdletBinding()]
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
    Write-Host "Creating Pester Container with Credentials"
    $PesterContainer = New-PesterContainer -Path $TestPath -Data @{ 'Credential' = $Credential }
} else {
    Write-Host "Creating Pester Container"
    $PesterContainer = New-PesterContainer -Path $TestPath
}
Write-Host "Invoking Pester Container"
$PesterResult = Invoke-Pester -Container $PesterContainer -ErrorAction Stop -Output Diagnostic -PassThru
if ($PesterResult.Result -ne 'Passed') { Exit 1; return }