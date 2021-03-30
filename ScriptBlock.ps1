Write-Output "Hello $env:COMPUTERNAME.$env:USERDNSDOMAIN `nThis example code that is being run on the remote computer was passed from an external file."
Write-Output "`nThe PowerShell version used for the remote session is:"
$PSVersionTable.PSVersion