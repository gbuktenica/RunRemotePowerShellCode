<#
.SYNOPSIS
    Sort and filter a computer list.
.EXAMPLE
    .\Sort-ComputerList.ps1 -FilterString "VDC" -Path ".\working\computernames.txt"

    Sorts the file .\working\computernames.txt and removes all lines with VDC.
.NOTES
    License      : MIT License
    Copyright (c): 2021 Glen Buktenica
    Release      : 2021 11 18
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
Get-Content -Path $Path | Where-Object { $_ -notlike "*$FilterString*" } | Sort-Object | Out-File $Path
