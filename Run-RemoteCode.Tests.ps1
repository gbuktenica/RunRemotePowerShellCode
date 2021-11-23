param(
    [PsCredential] $Credential
)
describe 'Change RA' {

    .\Run-RemoteCode.ps1 -Credential $Credential -Filter 'Name -like "ra*"' -SourceType "Directory" -ScriptBlock { New-Item $parameters.HomeFolderPath -ItemType "directory" }

    it 'attempts to create the home folder at the right path' {
        Test-Path -Path $parameters.HomeFolderPath | Should -Be $true
    }
}
