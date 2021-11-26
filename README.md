# Run Remote PowerShell Code

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Copyright Glen Buktenica](https://img.shields.io/badge/Copyright-Glen_Buktenica-blue.svg)](http://buktenica.com)

## Overview

A very common operational task is to run a block of PowerShell code on a list of computers using a privileged administrator account. This repository generalises this process so that the only scripting required is the actual code to be run on the remote computers.

## Features

### Text file list of computer names

The names of the computers that will have the remote code execution can be passed to the script via a plain text file with one computer name or FQDN per line.

### Active Directory discovery of computer names

The names of the computers that will have the remote code execution can be discovered with an Active Directory search.

### Reusable privileged credentials

Remote code execution requires the use of privileged credentials. By default this script will save privileged credentials using the Windows Data Protection API (DAPI) so that the operator is only promoted for credentials the first time the script is executed.

### Remote PowerShell Core

By default remote sessions to a client computer with PowerShell Core installed will still connect via Windows PowerShell. This script can force a connection to PowerShell Core instead of the client default.

### Copy files

To be able to copy files from a remote server within a remote session CredSSP can be used as a work around. This is typically not recommended by most security teams.
This script can copy files to the remote server outside of the remote code execution session and removing the need for CredSSP.

## Usage

```powershell
Run-RemoteCode.ps1 -SourceType List -ScriptBlockFilePath ScriptBlock.ps1
```

This will run the contents of the file ScriptBlock.ps1 against a list of computers names that are contained in a plain text file.
As the ListPath parameter is not used the operator will be prompted for the path of the text file.

```powershell
Run-RemoteCode.ps1 -SourceType List -ListPath c:\scripts\computers.txt -ScriptBlock {Write-Output "Hello World"} -AsJob
```

This will run the inline Script Block:
    Write-Output "Hello World"
against a list of computers names that are contained in the plain text file "c:\scripts\computers.txt"
Each remote computer will be executed as a parallel job.
If this is the first run of the script the operator will be prompted to enter privileged credentials.

```powershell
Run-RemoteCode.ps1 -SourceType Directory -Filter 'OperatingSystem -like "*server*"' -ScriptBlock {Write-Output "Hello World"}
```

This will run the inline Script Block against all computer objects that are contained in the default Active Directory that have a server operating system.
If this is the first run of the script the operator will be prompted to enter privileged credentials.

```powershell
.\Run-RemoteCode.ps1 -SourceType Directory -Filter "*" -FilterScript {$_.PasswordLastSet -ge ((Get-Date).AddDays(-90))} -SourcePath C:\Scripts -DestinationPath C:\Windows\temp
```

This will copy the contents of C:\Scripts on the operator workstation to C:\Windows\temp on all computer objects that are contained in the default Active Directory that have been on the network in the last 90 days.
If this is the first run of the script the operator will be prompted to enter privileged credentials.
