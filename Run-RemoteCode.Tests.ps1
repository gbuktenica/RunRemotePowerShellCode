param(
    [PsCredential] $Credential
)
describe 'Connect to RA' {

    it 'attempts to create the home folder at the right path' {
        $Result = .\Run-RemoteCode.ps1 -Credential $Credential -Filter 'Name -like "ra*"' -SourceType "Directory" -ScriptBlock { Write-Output "Testing" }
        $Result | Should -Be $true
    }
}
