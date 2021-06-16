param(
    [PsCredential] $Credential
)

Context "Basic Connectivity" {
    Describe "Response" {
        it "should return 0" {
            $Result = .\Run-RemoteCode.ps1 -Credential $Credential -ScriptBlock -Filter 'Name -like "ra*"' -SourceType "Directory" -ScriptBlockFilePath ".\ScriptBlock.ps1"
            $Result | Should -Be 0 -Because 'This indicates something worked.'
        }
    }
}