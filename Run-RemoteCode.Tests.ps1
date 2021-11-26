param(
    [PsCredential] $Credential
)
describe 'Connect to RA' {
    it 'attempts to connect to the remote computer' {
        $Parameters = @{
            Credential   = $Credential
            SourceType   = "Directory"
            Filter       = 'Name -like "ra*"'
            ScriptBlock  = { Write-Output "ArbitraryTestString" }
            FilterScript = { $_.PasswordLastSet -ge ((Get-Date).AddDays(-90)) }
            SkipDependencies = $true
        }
        $Result = .\Run-RemoteCode.ps1 @Parameters
        $Result | Should -Contain 'ArbitraryTestString'
    }
}
describe 'Copy to RA' {
    it 'attempts to copy files to the remote computer' {
        $Parameters = @{
            Credential       = $Credential
            SourceType       = "Directory"
            Filter           = 'Name -like "ra*"'
            ScriptBlock      = { Write-Output "ArbitraryCopyString" }
            SkipDependencies = $true
            SourcePath       = ".\working"
            DestinationPath  = "C:\Windows\Temp"
        }
        $Result = .\Run-RemoteCode.ps1 @Parameters
        $Result | Should -Contain 'ArbitraryCopyString'
    }
}