<#
.SYNOPSIS
    Runs a Script Block and / or a file copy on a list of remote computers.

.DESCRIPTION
    This script runs an operator defined block of PowerShell code remotely against a list of computers.
    Optionally any locally required files can be copied first.
    The list of computer can be either a plain text file of computer names or a filter of computer objects found in Active Directory.

.PARAMETER SourceType
    This string determines the source of computer names that the script will be actioned against.
    Example: -SourceType List
    Example: -SourceType Directory

.PARAMETER ListPath
    This string is the path to the plain text list of computer names that will be targeted.
    The text file should have one computer name per line.
    Example -ListPath ".\ComputerNames.txt"

.PARAMETER Filter
    This string is the filter used to find computer objects in Active Directory.
    The text file should have one computer name per line.
    Example: -Filter 'Name -like "Computer01*"'
    Example: -Filter 'OperatingSystem -like "*server*"'

.PARAMETER SearchBase
    This string is the Active Directory Organisational Unit search filter.
    Example: -SearchBase "CN=Computers,DC=Company,DC=com"
    Example: -SearchBase "OU=Servers,OU=Region,DC=Company,DC=com"

.PARAMETER FilterScript
    This ScriptBlock is the FilterScript for the Active Directory search.
    Example: -FilterScript {$_.PasswordLastSet -ge ((Get-Date).AddDays(-90))}

.PARAMETER ScriptBlock
    This ScriptBlock is the code that will be run on the remote computers.
    Example: -ScriptBlock {Write-Output "Hello $env:COMPUTERNAME"}

.PARAMETER ScriptBlockFilePath
    This string this the path to a file that contains the code that will be run on the remote computers.
    Example: -ScriptBlockFilePath ".\ScriptBlock.ps1"

.PARAMETER SourcePath
    This string is the source path to a directory that contains file that need to be copied to the remote computers.
    This must be a whole UNC path accessible from the operator workstation.
    Example: -SourcePath \\FileServer\LocalFolder

.PARAMETER DestinationPath
    This string is the destination path to a directory on the remoter computers that will contain file that need to be copied to the remote computers.
    This must be a UNC path accessible from the operator workstation but excluding the remote computer hostname.
    Example: -DestinationPath "C$\Windows\TEMP"
    Example: -DestinationPath "LocalShare\LocalSubFolder"
    The script will loop through and copy the files to the remote computers.

.PARAMETER Keep
    The switch will not delete the local folder that was copied to the remote computer.
    By default this script will remove the local folder after the script block has completed execution.

.PARAMETER Credential
    This PsCredential is the security context that will be used to run the remote code.
    If this is omitted the operator will be prompted for credential at first run.

.PARAMETER Renew
    This switch prompts the user for a new password for an existing saved credential.
    To be used after a password change.

.PARAMETER NoSave
    This switch prevents credentials being saved and will prompt the operator every time for privileged credentials.

.PARAMETER ConfigurationName
    This string sets the PowerShell configuration that will be used to connect.
    "Default" uses the clients default which is typically Windows PowerShell.

.PARAMETER AsJob
    This switch forces the remote script block to be actioned as a powershell job as a parallel thread.

.EXAMPLE
    .\Run-RemoteCode.ps1 -SourceType List -ScriptBlockFilePath .\ScriptBlock.ps1

    Will run the contents of ScriptBlock.ps1 against a list of computers names that are contained in a plain text file.
    As the ListPath parameter is not used the operator will be prompted for the path of the text file.

.EXAMPLE
    .\Run-RemoteCode.ps1 -SourceType List -ListPath c:\scripts\computers.txt -ScriptBlock {Write-Output "Hello World"} -AsJob

    Will run the inline Script Block:
        Write-Output "Hello World"
    against a list of computers names that are contained in the plain text file "c:\scripts\computers.txt"
    Each remote computer will be executed as a parallel job.
    If this is the first run of the script the operator will be prompted to enter privileged credentials.

.EXAMPLE
    .\Run-RemoteCode.ps1 -SourceType Directory -Filter 'OperatingSystem -like "*server*"' -ScriptBlock {Write-Output "Hello World"}

    Will run the inline Script Block against all computer objects that are servers and contained in the default Active Directory.
    If this is the first run of the script the operator will be prompted to enter privileged credentials.

.EXAMPLE
    .\Run-RemoteCode.ps1 -SourceType Directory -SourcePath \\FileServer\Files -DestinationPath C$\Windows\temp

    Will copy the contents of \\FileServer\Files to C$\Windows\temp on all computer objects that are contained in the default Active Directory.
    No other script execution will take place.
    If this is the first run of the script the operator will be prompted to enter privileged credentials.

.EXAMPLE
    .\Run-RemoteCode.ps1 -SourceType Directory -SearchBase "OU=Servers,OU=Region,DC=Company,DC=com"`
     -FilterScript {$_.PasswordLastSet -ge ((Get-Date).AddDays(-90))} -ScriptBlock {Write-Output "Hello World"}

    Will run the inline Script Block against all computer objects that are contained in the Organisational Unit "Servers" that have had a password reset in the last 90 days.
    If this is the first run of the script the operator will be prompted to enter privileged credentials.

.EXAMPLE
    .\Run-RemoteCode.ps1 -SourceType List -ListPath .\computername.txt`
     -ScriptBlock {Start-Process -FilePath C:\Windows\Temp\Path\Example.exe -ArgumentList "/Q"}`
     -SourcePath \\FileServer\Path -DestinationPath C$\windows\Temp

    Will copy the folder \\FileServer\Files to C:\Windows\Temp to all of the remote computers.
    The Example.exe windows binary will be executed on the remote computer with the /Q switch
    If this is the first run of the script the operator will be prompted to enter privileged credentials.

.LINK
    https://github.com/gbuktenica/RunRemotePowerShellCode

.NOTES
    Requirements : Port TCP 445  for PsExec
                 : Port TCP 5985 for PowerShell Remoting
    License      : MIT License
    Copyright (c): 2021 Glen Buktenica
    Release      : v2.0.2 20210922
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
    $Filter = "*",
    [Parameter()]
    [string]
    $SearchBase,
    [Parameter()]
    [ScriptBlock]
    $FilterScript,
    [Parameter()]
    [ScriptBlock]
    $ScriptBlock,
    [Parameter()]
    [string]
    $ScriptBlockFilePath,
    [Parameter()]
    [string]
    $SourcePath,
    [Parameter()]
    [string]
    $DestinationPath,
    [Parameter()]
    [switch]
    $Keep,
    [Parameter()]
    [pscredential]
    $Credential,
    [Parameter()]
    [string]
    $Account = 'Admin',
    [Parameter()]
    [switch]
    $Renew,
    [Parameter()]
    [switch]
    $NoSave,
    [Parameter()]
    [ValidateSet('ClientDefault', 'Microsoft.PowerShell', 'Powershell.6', 'PowerShell.7')]
    [string]
    $ConfigurationName = 'ClientDefault',
    [Parameter()]
    [switch]
    $AsJob
)
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
        The default value is "Default"

    .PARAMETER VaultPath
        The file path of the encrypted Json file for saving the username and password pair.
        Default value is "c:\users\<USERNAME>\SavedCredentialsHash.json"

    .PARAMETER Renew
        Prompts the user for a new password for an existing pair.
        To be used after a password change.
        Default value is $false

    .PARAMETER SecureString
        Saves and returns a SecureString object instead of PSCredential Object.
        Used for non Credential secrets.
        Default value is $false

    .EXAMPLE
        Enter-PsSession -ComputerName Computer -Credential (Get-SavedCredentials)
        Returns a default PsCredential object into the Enter-PsSession command.

    .EXAMPLE
        $Credential = Get-SavedCredentials -Title Normal -VaultPath c:\temp\myFile.json
        Returns a PsCredential object to to the variable $Credential

    .EXAMPLE
        $SecureString = Get-SavedCredentials -SecureString
        Returns a SecureString object to to the variable $SecureString

    .LINK
        https://github.com/gbuktenica/GetSavedCredentials

    .NOTES
        License      : MIT License
        Copyright (c): 2021 Glen Buktenica
        Release      : v1.1.0 20210413
    #>
    [CmdletBinding()]
    Param(
        [string]$Title = "Default",
        [string]$VaultPath = "$env:USERPROFILE\SavedCredentialsHash.json",
        [switch]$Renew,
        [switch]$SecureString
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
    if ($Json.$Title.username.Length -eq 0 -and -not $SecureString) {
        #Prompt user for username if it is not saved.
        $Message = "Enter User name for> $Title"
        $Username = Read-Host $Message -ErrorAction Stop
        ($Json.$Title.username) = $Username
        $JsonChanged = $true
    }
    if ($Json.$Title.password.Length -eq 0 -or $Renew) {
        #Prompt user for Password if it is not saved.
        if ($SecureString) {
            $Message = "Enter Secret for> " + $Json.$Title
        } else {
            $Message = "Enter Password for> " + $Json.$Title.username
        }
        $Json.$Title.password = ((Read-Host $Message -AsSecureString -ErrorAction Stop))
        $JsonChanged = $true
    }
    if ($SecureString) {
        Try {
            # Build the SecureString object and export it.
            $Json.$Title.password | ConvertTo-SecureString -ErrorAction Stop
        } catch {
            # If building the SecureString failed for any reason delete it and run the function
            # again which will prompt the user for the secret.
            $TitleContent = " { `"username`":`"`", `"password`":`"`" }"
            $Json | Add-Member -Name $Title -value (Convertfrom-Json $TitleContent) -MemberType NoteProperty -Force
            $Json | ConvertTo-Json -depth 3 | Set-Content $VaultPath -ErrorAction Stop
            Get-SavedCredentials -Title $Title -VaultPath $VaultPath -SecureString
        }
    } else {
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
    }
    if ($JsonChanged) {
        # Save the Json object to file if it has changed.
        $Json | ConvertTo-Json -depth 3 | Set-Content $VaultPath -ErrorAction Stop
    }
}

# Obtain privileged credentials from an encrypted file or operator to use to connect to the remote computers.
if ($null -eq $Credential) {
    if ($NoSave) {
        $Credential = Get-Credential
    } else {
        $Credential = Get-SavedCredentials -Title $Account -Renew:$Renew
    }
}
# Download PsExec if not found
if (-not (Test-Path "$env:TEMP\PSExec64.exe")) {
    Write-Verbose "Downloading PsExec"
    Invoke-WebRequest -Uri "https://download.sysinternals.com/files/PSTools.zip" -OutFile $env:TEMP\PSTools.zip
    Expand-Archive -Path "$env:TEMP\PSTools.zip" -DestinationPath $env:TEMP
} else {
    Write-Verbose "PsExec already downloaded"
}

# If an external file has been set then read that file into an object of type scriptblock.
if ($ScriptBlockFilePath.length -gt 0) {
    Write-Verbose "Reading File: $ScriptBlockFilePath"
    [ScriptBlock]$ScriptBlock = [Scriptblock]::Create((Get-Content -Path $ScriptBlockFilePath -Raw -ErrorAction Stop))
}

# Generate the list of computer names.
if ($SourceType -eq "List") {
    # List SourceType selected, so read the text file.
    if ($ListPath.length -eq 0) {
        Write-Verbose "`$SourceType is list but `$ListPath is null so prompt operator for file path."
        # Check that GUI dependencies are installed.
        # If dependencies are missing and can be installed then do so.
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
    # Ignore the local machine as remote connection requests will be refused.
    $ComputerNames = $ComputerNames | Where-Object -FilterScript { $_ -notmatch "$env:COMPUTERNAME.*" -and $_ -ne $env:COMPUTERNAME }
} elseif ($SourceType -eq "Directory") {
    # Check that Active Directory dependencies are installed.
    # If dependencies are missing and can be installed then do so.
    if (-not(Get-Module -Name "ActiveDirectory")) {
        if (((Get-CimInstance -ClassName Win32_OperatingSystem).ProductType) -eq 1) {
            Write-Verbose "Workstation Operating System detected"
            if ([Environment]::OSVersion.Version -ge [version]"10.0.18090") {
                Write-Verbose "Window 10 build greater than 1809 detected"
                function Test-Admin {
                    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
                    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
                }
                if (-not(Test-Admin)) {
                    if ($PSVersionTable.PSEdition -eq "Core") {
                        Write-Verbose "Installing RSAT using Elevated PowerShell Core"
                        Start-Process -Wait -Verb RunAs -FilePath pwsh.exe -ArgumentList ('-NoProfile -Command { Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -ErrorAction Stop }')

                    } else {
                        Write-Verbose "Installing RSAT using Elevated Windows PowerShell"
                        Start-Process -Wait -Verb RunAs -FilePath powershell.exe -ArgumentList ('-NoProfile -Command { Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -ErrorAction Stop }')
                    }
                } else {
                    Write-Verbose "Installing RSAT"
                    Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -ErrorAction Stop
                }

            } else {
                Write-Error "`nActive Directory Module not found. `nInstall RSAT tools to enable: `nhttps://www.microsoft.com/en-us/download/details.aspx?id=45520" -ErrorAction Stop
                exit 1
            }
        } else {
            Write-Verbose "Server Operating System detected"
            Import-Module ServerManager
            Install-WindowsFeature -Name RSAT-AD-PowerShell
        }
    }
    $SavedPreference = $VerbosePreference
    $VerbosePreference = "SilentlyContinue"
    Import-Module -Name "ActiveDirectory" -ErrorAction Stop -Verbose:$false
    $VerbosePreference = $SavedPreference
    Write-Output "Reading Computer Objects from Active Directory"
    $ComputerNames = Get-ADComputer -Filter $Filter -Properties *
    if ($FilterScript) {
        Write-Verbose "Running FilterScript"
        $ComputerNames = $ComputerNames | Where-Object -FilterScript $FilterScript
    }
    $ComputerNames = $ComputerNames.DNSHostName
    # Export Computer list
    Add-Content -Path (($PSCommandPath).split(".")[0] + ".DirectoryList.txt") -Value $ComputerNames
    Write-Output "Finished Reading Computer Objects from Active Directory"
}

# Ignore the local machine as remote connection requests will be refused.
$ComputerNames = $ComputerNames | Where-Object -FilterScript { $_ -notmatch "$env:COMPUTERNAME.*" -and $_ -ne $env:COMPUTERNAME }

# If a file copy is being done map a drive with credentials
if ($SourcePath.Length -gt 0 -and $DestinationPath.Length -gt 0) {
    Write-Verbose "File copy requested"
    Write-Verbose "SourcePath: $SourcePath"
    Write-Verbose "DestinationPath: $DestinationPath"
    # Clean up old PSDrives if not cleaned up in previous execution
    if (Test-Path -Path "Source:\") {
        Remove-PSDrive -Name Source -ErrorAction Stop -Force
    }
    if (Test-Path -Path "Destination:\") {
        Remove-PSDrive -Name Destination -ErrorAction Stop -Force
    }
    # Clean up conflicting SMB drives
    $Drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.DisplayRoot -match (($SourcePath.replace("\\", "")).Split("\")[0]) }
    foreach ($Drive in $Drives) {
        $Message = "Removing drive " + $Drive.Name + " with path " + $Drive.DisplayRoot
        Write-Verbose $Message
        $Name = $drive.Name + ":"
        Remove-SmbMapping -LocalPath $Name -Force
    }
    New-PSDrive -Name Source -Root $SourcePath -PSProvider FileSystem -Credential $Credential | Out-Null
}

if ($AsJob) {
    # Remove any existing jobs from a previous run.
    Get-Job | Remove-Job
}
$ProgressCount = 0
$ProgressTotal = ($ComputerNames).count
# Run the remote jobs on all computers
foreach ($ComputerName in $ComputerNames) {
    Write-Output "======================================"
    $ProgressCount ++
    $StepPass = $true
    if (Test-Connection $ComputerName -Count 1 -BufferSize 1 -ErrorAction SilentlyContinue) {
        $error.clear()
        Write-Output "$ComputerName computer $ProgressCount of $ProgressTotal"
        if (-not([bool](Test-WSMan -ComputerName $ComputerName -ErrorAction SilentlyContinue))) {
            Write-Verbose "Remote PowerShell not enabled"
            Add-Content -Path (($PSCommandPath).split(".")[0] + ".EnablePsRemoting.txt") -Value $ComputerName
            Start-Process "$env:TEMP\PSExec64.exe" -ArgumentList "-NoBanner \\$ComputerName -s PowerShell.exe -Command Enable-PsRemoting -Force" -Wait -Credential $Credential
        }
        if ($SourcePath.Length -gt 0 -and $DestinationPath.Length -gt 0) {
            try {
                $Drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.DisplayRoot -match $ComputerName }
                foreach ($Drive in $Drives) {
                    $Message = "Removing drive " + $Drive.Name + " with path " + $Drive.DisplayRoot
                    Write-Verbose $Message
                    $Name = $drive.Name + ":"
                    Remove-SmbMapping -LocalPath $Name -Force
                }
                Write-Verbose "Mapping PSDrive \\$ComputerName\$DestinationPath"
                New-PSDrive -Name Destination -Root \\$ComputerName\$DestinationPath -PSProvider FileSystem -Credential $Credential -ErrorAction Stop | Out-Null
            } catch {
                Write-Warning "Computer $ComputerName destination drive mapping failed"
                Add-Content -Path (($PSCommandPath).split(".")[0] + ".CopyFailed.txt") -Value $ComputerName
                $StepPass = $false
                $debugActionPreference
                $Error[0].Exception.GetType().FullName
                Write-Debug $Error[0]
            }
            try {
                Write-Verbose "Starting file copy"
                Copy-Item -Path "Source:\" -Destination "Destination:\" -ErrorAction Stop -Recurse -Force
            } catch {
                Write-Warning "Computer $ComputerName copy failed"
                Add-Content -Path (($PSCommandPath).split(".")[0] + ".CopyFailed.txt") -Value $ComputerName
                $StepPass = $false
                $debugActionPreference
                $Error[0].Exception.GetType().FullName
                Write-Debug $Error[0]
            }
        }
        if ($ScriptBlock.length -gt 0 -and $StepPass ) {
            Write-Verbose "Creating new PsSession"
            if ($ConfigurationName -eq "ClientDefault") {
                try {
                    $Session = New-PsSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop
                } catch {
                    Write-Warning "Computer $ComputerName : $_.Exception.Message"
                    # Update error log
                    Add-Content -Path (($PSCommandPath).split(".")[0] + ".Error.txt") -Value $ComputerName
                    $Error[0].Exception.GetType().FullName
                    Write-Debug $Error[0]
                    $StepPass = $false
                }
            } else {
                try {
                    $Session = New-PsSession -ComputerName $ComputerName -Credential $Credential -ConfigurationName $ConfigurationName -ErrorAction Stop
                } catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
                    Write-Warning "ConfigurationName: $ConfigurationName not available. Falling back to default connection."
                    $Session = New-PsSession -ComputerName $ComputerName -Credential $Credential
                } catch {
                    Write-Warning "Computer $ComputerName : $_.Exception.Message"
                    # Update error log
                    Add-Content -Path (($PSCommandPath).split(".")[0] + ".Error.txt") -Value $ComputerName
                    $Error[0].Exception.GetType().FullName
                    Write-Debug $Error[0]
                    $StepPass = $false
                }
            }
            if ($StepPass) {
                Write-Verbose "Starting Invoke-Command"
                try {
                    Invoke-Command -Session $Session -AsJob:$AsJob -ScriptBlock $ScriptBlock -ErrorAction Stop
                } catch [System.Management.Automation.DriveNotFoundException] {
                    Write-Warning "Computer $ComputerName connection failed"
                    # Update error log
                    Add-Content -Path (($PSCommandPath).split(".")[0] + ".Error.txt") -Value $ComputerName
                    Write-Debug $Error[0]
                } catch {
                    Write-Warning "Computer $ComputerName : $_.Exception.Message"
                    Add-Content -Path (($PSCommandPath).split(".")[0] + ".Error.txt") -Value $ComputerName
                    Write-Debug $Error[0]
                    $Error[0].Exception.GetType().FullName
                }
            }
            if ($null -ne $Session) {
                Write-Verbose "Removing PsSession"
                Remove-PsSession -Session $Session
            }
            # Remove destination files
            if (Test-Path -Path "Destination:\") {
                if (-not $Keep) {
                    $SourcePathTail = $SourcePath -replace ("/","\") -split ("\\")
                    $SourcePathTail = $SourcePathTail[($SourcePathTail.length - 1)]
                    $RemoveFolder = "Destination:\" + $SourcePathTail
                    if (Test-Path -Path $RemoveFolder) {
                        Write-Verbose "Removing Folder: $RemoveFolder"
                        Remove-Item $RemoveFolder -Recurse
                    }
                }
                Write-Verbose "Removing PSDrive"
                Remove-PSDrive -Name Destination -ErrorAction Stop -Force
            }
        }
    } else {
        Write-Warning "Computer $ComputerName not online"
        # Update connection log
        Add-Content -Path (($PSCommandPath).split(".")[0] + ".NotOnline.txt") -Value $ComputerName
    }
}

if ($AsJob) {
    Write-Output "============================="
    Write-Output "Waiting for jobs to complete"
    Get-Job | Wait-Job
    Write-Output "============================="
    Write-Output "Jobs complete"
    Get-Job | Receive-Job
}