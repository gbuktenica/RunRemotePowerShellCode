<#
.SYNOPSIS
    Runs a Script Block on a list of remote computers.

.DESCRIPTION
    This script runs an operator defined block of PowerShell code remotely against a list of computers.
    The list of computer can be either a plain text file of computer names or a filter of computer objects found in Active Directory.

.PARAMETER SourceType
    This string determines the source of computer names that the script will be actioned against.

.PARAMETER ListPath
    This string is the path to the plain text list of computer names that will be targeted.
    The text file should have one computer name per line.

.PARAMETER ScriptBlock
    This string is the code that will be run on the remote computers.

.PARAMETER Credential
    This PsCredential is the security context that will be used to run the remote code.
    If this is omitted the operator will be prompted for credential at first run.

.PARAMETER AsJob
This switch forces the remote script block to be actioned as a powershell job as a parallel thread.

.EXAMPLE
    .\Run-RemoteCode.ps1 -List
    Will run the internal Script Block against a list of computers names that are contained in a plain text file.
    As the ListPath parameter is not used the operator will be prompted for the path of the text file.

.EXAMPLE
    .\Run-RemoteCode.ps1 -List -ListPath c:\scripts\computers.txt -ScriptBlock {Write-Output "Hello World"} -AsJob
    Will run the external Script Block:
        Write-Output "Hello World"
    against a list of computers names that are contained in the plain text file "c:\scripts\computers.txt"
    Each remote computer will be executed as a parallel job.
    If this is the first run of the script the operator will be prompted to enter privileged credentials.

.LINK
    https://github.com/gbuktenica/RunRemotePowerShellCode

.NOTES
    License      : MIT License
    Copyright (c): 2021 Glen Buktenica
    Release      : v0.0.1 20210324
#>
[CmdletBinding()]
param (
    [Parameter()]
    [ValidateSet('List', 'Directory')]
    [string]
    $SourceType = 'List',
    [Parameter()]
    [string]
    $ListPath,
    [Parameter()]
    [string]
    $ScriptBlock,
    [Parameter()]
    [pscredential]
    $Credential,
    [Parameter()]
    [switch]
    $AsJob
)
if ($null -eq $ScriptBlock) {
    $ScriptBlock = {
        # This Code is executed on the Remote Machine
        Write-Output $env:COMPUTERNAME
        Write-Output "Hello World"
    }
}
function Get-SavedCredentials {
    <#
    .SYNOPSIS
        Returns a PSCredential from an encrypted file.
    .DESCRIPTION
        Returns a PSCredential from a file encrypted using Windows Data Protection API (DAPI).
        If the file does not exist the user will be prompted for the username and password the first time.
        The GPO setting Network Access: Do not allow storage of passwords and credentials for network authentication must be set to Disabled
        otherwise the password will only persist for the length of the user session.
    .PARAMETER Title
        The name of the username and password pair. This allows multiple accounts to be saved such as a normal account and an administrator account.
    .PARAMETER VaultPath
        The file path of the encrypted Json file for saving the username and password pair.
        Default value is c:\users\<USERNAME>\PowerShellHash.json"
    .PARAMETER Renew
        Prompts the user for a new password for an existing pair.
        To be used after a password change.
    .EXAMPLE
        Enter-PsSession -ComputerName Computer -Credential (Get-SavedCredentials)
    .EXAMPLE
        $Credential = Get-SavedCredentials -Title Normal -VaultPath c:\temp\myFile.json
    .LINK
        https://github.com/gbuktenica/GetSavedCredentials
    .NOTES
        License      : MIT License
        Copyright (c): 2020 Glen Buktenica
        Release      : v1.0.0 20200315
    #>
    [CmdletBinding()]
    Param(
        [string]$Title = "Default",
        [string]$VaultPath = "$env:USERPROFILE\PowerShellHash.json",
        [switch]$Renew
    )
    $JsonChanged = $false
    if (-not (Test-path -Path $VaultPath)) {
        # Create a new Json object if the file does not exist.
        $Json = "{`"$Title`": { `"username`": `"`", `"password`": `"`" }}" | ConvertFrom-Json
        $JsonChanged = $true
    } else {
        try {
            # Read the file if it already exists
            $Json = Get-Content -Raw -Path $VaultPath | ConvertFrom-Json -ErrorAction Stop
        } catch {
            # If the file is corrupt overwrite it.
            $Json = "{`"$Title`": { `"username`": `"`", `"password`": `"`" }}" | ConvertFrom-Json
            $JsonChanged = $true
        }
    }
    if ($Json.$Title.length -eq 0) {
        # Create a new Username \ Password key if it is new.
        $TitleContent = " { `"username`":`"`", `"password`":`"`" }"
        $Json | Add-Member -Name $Title -value (Convertfrom-Json $TitleContent) -MemberType NoteProperty
        $JsonChanged = $true
    }
    if ($Json.$Title.username.Length -eq 0) {
        #Prompt user for username if it is not saved.
        $Message = "Enter User name for> $Title"
        $Username = Read-Host $Message -ErrorAction Stop
        ($Json.$Title.username) = $Username
        $JsonChanged = $true
    }
    if ($Json.$Title.password.Length -eq 0 -or $Renew) {
        #Prompt user for Password if it is not saved.
        $Message = "Enter Password for> " + $Json.$Title.username
        $secureStringPwd = Read-Host $Message -AsSecureString -ErrorAction Stop
        $secureStringText = $secureStringPwd | ConvertFrom-SecureString
        $Json.$Title.password = $secureStringText
        $JsonChanged = $true
    }

    $Username = $Json.$Title.username
    Try {
        # Build the PSCredential object and export it.
        $SecurePassword = $Json.$Title.password | ConvertTo-SecureString -ErrorAction Stop
        New-Object System.Management.Automation.PSCredential -ArgumentList $Username, $SecurePassword -ErrorAction Stop
    } catch {
        # If building the credential failed for any reason delete it and run the function
        # again which will prompt the user for username and password.
        $TitleContent = " { `"username`":`"`", `"password`":`"`" }"
        $Json | Add-Member -Name $Title -value (Convertfrom-Json $TitleContent) -MemberType NoteProperty -Force
        $Json | ConvertTo-Json -depth 3 | Set-Content $VaultPath -ErrorAction Stop
        Get-SavedCredentials -Title $Title -VaultPath $VaultPath
    }
    if ($JsonChanged) {
        # Save the Json object to file if it has changed.
        $Json | ConvertTo-Json -depth 3 | Set-Content $VaultPath -ErrorAction Stop
    }
}

if ($null -eq $Credential) {
    $Credential = Get-SavedCredentials -Title Admin
}

# Generate List of servers
if ($SourceType -eq "List") {
    # List selected so read file.
    if ($ListPath.length -eq 0) {
        Write-Verbose "`$SourceType is list but `$ListPath is null so prompt operator for file path."
        if (-not (Get-Module -Name "FileSystemForms")) {
            if (((Get-PackageProvider -Name nuget -ErrorAction SilentlyContinue).version) -lt [version]"2.8.5.201") {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
            }
            if (-not (Get-PSRepository -Name PSGallery)) {
                Register-PSRepository -Default
            }
            Install-Module -Name FileSystemForms -ErrorAction Stop
        }
        $ListPath = Select-FileSystemForm -File -ext "txt"

    } else {
        Write-Verbose "ListPath not null. Continuing without operator input"
    }
    $ComputerNames = Get-Content $ListPath
} elseif ($SourceType -eq "Directory") {
    # Check for dependencies and install if missing.
    if (-not(Get-Module -Name "ActiveDirectory")) {
        if (((Get-CimInstance -ClassName Win32_OperatingSystem).ProductType) -eq 1) {
            Write-Verbose "Workstation Operating System detected"
            if ([Environment]::OSVersion.Version -ge [version]"10.0.18090") {
                Write-Verbose "Window 10 build greater than 1809 detected"
                Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
            } else {
                Write-Error "Install RSAT tools to enable PowerShell Active Directory Module to continue." -ErrorAction Stop
                exit 1
            }
        } else {
            Write-Verbose "Server Operating System detected"
            Import-Module ServerManager
            Install-WindowsFeature -Name RSAT-AD-PowerShell
        }
    }
    Import-Module -Name "ActiveDirectory"
    $ComputerNames = Get-ADComputer
}

# Run Scriptblock on all computers

foreach ($ComputerName in $ComputerNames) {
    Write-Output "======================================"
    if (Test-Connection $ComputerName -Count 1 -BufferSize 1 -ErrorAction SilentlyContinue) {
        Write-Output $ComputerName
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -AsJob:$AsJob -ScriptBlock $ScriptBlock
    } else {
        Write-Output "Computer $ComputerName not online"
    }
}
if ($AsJob) {
    Get-Job | Receive-Job | Remove-Job
}