# Working directory

This folder is ignored by git so that it can be used to save computer name lists and script block files.

## Examples

The following examples will call files temporarily stored in this folder.

### List

Run ScriptBlock on all computers in ComputerNames.txt file.

```powershell
.\Run-RemoteCode.ps1 -SourceType List -ListPath .\working\ComputerNames.txt -ScriptBlockFilePath .\working\ScriptBlock.ps1 -Verbose
```

### List with Copy

Run file copy and ScriptBlock on all computers in ComputerNames.txt file.

```powershell
.\Run-RemoteCode.ps1 -SourceType "List" -ListPath ".\working\ComputerNames.txt" -ScriptBlockFilePath ".\working\ScriptBlock.ps1" -SourcePath "\\FileServer\Folder" -DestinationPath "c$\Windows\Temp" -Verbose
```

## Directory

Run ScriptBlock on all computers in the Active Directory domain with no filter.

```powershell
.\Run-RemoteCode.ps1 -SourceType "Directory" -ScriptBlockFilePath ".\working\ScriptBlock.ps1" -Verbose
```
