<#
.SYNOPSIS
    Sort and filter a computer list.
.EXAMPLE
    .\Sort-ComputerList.ps1 -FilterString "VDC" -Path ".\working\computernames.txt"

    Sorts the file .\working\computernames.txt and removes all lines with VDC.
.NOTES
    License      : MIT License
    Copyright (c): 2021 - 2022 Glen Buktenica
    Release      : 2022 02 17
#>
[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $FilterString = "VDC",
    [Parameter()]
    [string]
    $Path = ".\working\computernames.txt"
)
[String[]]$Text = Get-Content -Path $Path | Where-Object { $_ -notlike "*$FilterString*" } | Sort-Object
$Text | Out-File $Path
