param(
    [PsCredential] $Credential
)

Context "Basic Connectivity" {
    Describe "Response" {
        it "should return Something" {
            $Result = & pwsh -File $PSScriptRoot\Run-RemoteCode.ps1 -Credential $Credential -Filter 'Name -like "ra*"' -SourceType "Directory" -ScriptBlockFilePath ".\ScriptBlock.ps1"
            $Result | Should -Be "something" -Because 'This indicates something worked.'
        }
    }
}
