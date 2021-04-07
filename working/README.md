# Working directory

This folder is ignored by git so that it can be used to save computername lists and script block files.

## Example

```powershell
.\Run-RemoteCode.ps1 -SourceType List -ListPath .\working\computername.txt -ScriptBlockFilePath .\working\ScriptBlock.ps1 
```

```powershell
.\Run-RemoteCode.ps1 -SourceType List -ListPath .\working\computername.txt -ScriptBlockFilePath .\working\ScriptBlock.ps1 -SourcePath \\FileServer\Folder -DestinationPath c$\Windows\Temp
```

These two examples call two files in the working folder without triggering a change to the git folder.
