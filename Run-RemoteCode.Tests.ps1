param(
    [PsCredential] $Credential
)

describe 'Connect to RA' {
    it 'attempts to connect to the remote computer' {
        $Result = .\Run-RemoteCode.ps1 -SkipDependencies -Credential $Credential -Filter 'Name -like "ra*"' -SourceType "Directory" -ScriptBlock { Write-Output "ArbitraryTestString" }
        $Result | Should -Contain 'ArbitraryTestString'
    }
    it 'attempts to copy to the remote computer' {
        $Result = .\Run-RemoteCode.ps1 -SkipDependencies -Credential $Credential -Filter 'Name -like "ra*"' -SourceType "Directory" -ScriptBlock { Write-Output "ArbitraryCopyString" } -SourcePath ".\working" -DestinationPath "C:\windows\Temp\"
        $Result | Should -Contain 'ArbitraryCopyString'
    }
}