param(
    [PsCredential] $Credential
)
describe 'Change RA' {

    .\Run-RemoteCode.ps1 -Credential $Credential -Filter 'Name -like "ra*"' -SourceType "Directory" -ScriptBlockFilePath ".\ScriptBlock.ps1"

    it 'attempts to create the home folder at the right path' {

        Test-Path -Path $parameters.HomeFolderPath | should be $true
    }
}