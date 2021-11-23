param(
    [PsCredential] $Credential
)
describe 'Connect to RA' {

    it 'attempts to connect to the remote computer' {
        $Result = .\Run-RemoteCode.ps1 -Credential $Credential -Filter 'Name -like "ra*"' -SourceType "Directory" -ScriptBlock { Write-Output "Testing" }
        $Result | Should -Be $true
    }
}
