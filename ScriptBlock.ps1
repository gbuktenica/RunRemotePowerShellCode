Write-Output "Create Path"
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2" | Out-Null
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" | Out-Null
Write-Output "Create Keys"
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name  Enabled -Value 0x00000001 -Force -PropertyType DWord | Out-Null
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name DisabledByDefault -Value 0x00000000 -Force -PropertyType DWord | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name SchUseStrongCrypto  -Value 0x00000001 -Force -PropertyType DWord | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" -Name SchUseStrongCrypto  -Value 0x00000001 -Force -PropertyType DWord | Out-Null