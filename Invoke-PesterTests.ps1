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
    try {
        #$PesterContainer = New-PesterContainer -Path $TestPath -Data @{ 'Credential' = $Credential } -ErrorAction Stop
    } catch {
        $Error
        Write-Output "Failed to create PesterContainer"
        Exit 1
    }

} else {
    Write-Host "Creating Pester Container"
    try {
        $PesterContainer = New-PesterContainer -Path $TestPath -ErrorAction Stop
    } catch {
        $Error
        Write-Output "Failed to create PesterContainer"
        Exit 1
    }
}
Write-Host "Invoking Pester Container"
$PesterResult = Invoke-Pester -Container $PesterContainer -ErrorAction Stop -Output Diagnostic -PassThru
if ($PesterResult.Result -ne 'Passed') {
    $PesterResult
    Exit 1
    return
}