<#
This Sample Code is provided for the purpose of illustration only
and is not intended to be used in a production environment.  THIS
SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
FOR A PARTICULAR PURPOSE.  We grant You a nonexclusive, royalty-free
right to use and modify the Sample Code and to reproduce and distribute
the object code form of the Sample Code, provided that You agree:
(i) to not use Our name, logo, or trademarks to market Your software
product in which the Sample Code is embedded; (ii) to include a valid
copyright notice on Your software product in which the Sample Code is
embedded; and (iii) to indemnify, hold harmless, and defend Us and
Our suppliers from and against any claims or lawsuits, including
attorneys' fees, that arise or result from the use or distribution
of the Sample Code.
#>
#requires -Version 5 -RunAsAdministrator 

#From https://gist.github.com/Apoc70/cf67890227d61416ee767729e3b881df
param (
    [switch]$DisableLegacyTls
)
# Last updated: 2025-05-13

if ($DisableLegacyTls) {
    #region Disable SSL 2.0 and 3.0

    # Disable SSL 2.0
    $null = New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" -Name "SSL 2.0" -ErrorAction SilentlyContinue
    $null = New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0" -Name "Client" -ErrorAction SilentlyContinue
    $null = New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0" -Name "Server" -ErrorAction SilentlyContinue
    $null = Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name "DisabledByDefault" -Value 1 -Type DWord
    $null = Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name "Enabled" -Value 0 -Type DWord
    $null = Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "DisabledByDefault" -Value 1 -Type DWord
    $null = Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "Enabled" -Value 0 -Type DWord

    # Disable SSL 3.0
    $null = New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" -Name "SSL 3.0" -ErrorAction SilentlyContinue
    $null = New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0" -Name "Client" -ErrorAction SilentlyContinue
    $null = New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0" -Name "Server" -ErrorAction SilentlyContinue
    $null = Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name "DisabledByDefault" -Value 1 -Type DWord
    $null = Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name "Enabled" -Value 0 -Type DWord
    $null = Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "DisabledByDefault" -Value 1 -Type DWord
    $null = Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "Enabled" -Value 0 -Type DWord

    Write-Host 'SSL 2.0 and 3.0 have been disabled.'
    #endregion 

    #region Disable TLS 1.0 and 1.1
    # Following https://learn.microsoft.com/exchange/plan-and-deploy/post-installation-tasks/security-best-practices/exchange-tls-configuration?view=exchserver-2019&WT.mc_id=M365-MVP-5003086

    # Disable TLS 1.0
    $null = New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" -Name "TLS 1.1" -ErrorAction SilentlyContinue
    $null = New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1" -Name "Client" -ErrorAction SilentlyContinue
    $null = New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1" -Name "Server" -ErrorAction SilentlyContinue
    $null = Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "DisabledByDefault" -Value 1 -Type DWord
    $null = Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "Enabled" -Value 0 -Type DWord
    $null = Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "DisabledByDefault" -Value 1 -Type DWord
    $null = Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -Value 0 -Type DWord

    # Disable TLS 1.1
    $null = New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" -Name "TLS 1.0" -ErrorAction SilentlyContinue
    $null = New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0" -Name "Client" -ErrorAction SilentlyContinue
    $null = New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0" -Name "Server" -ErrorAction SilentlyContinue
    $null = Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "DisabledByDefault" -Value 1 -Type DWord
    $null = Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "Enabled" -Value 0 -Type DWord
    $null = Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "DisabledByDefault" -Value 1 -Type DWord
    $null = Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Value 0 -Type DWord

    Write-Host 'TLS 1.0 and 1.1 have been disabled.'
    #endregion 
}
else {
    Write-Host 'Tls 1.0 and 1.1 will NOT be disabled. Use -DisableLegacyTls to disable them.'
}

# Create .NET Framework 2.0/3.5 32-bit hive and enable strong TLS encryption
If (-Not (Test-Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727')) {
    New-Item 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727' -Force | Out-Null
}
New-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727' -name 'SystemDefaultTlsVersions' -value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727' -name 'SchUseStrongCrypto' -value '1' -PropertyType 'DWord' -Force | Out-Null

# Create .NET Framework 2.0/3.5 64-bit hive and enable strong TLS encryption
If (-Not (Test-Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727')) {
    New-Item 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' -Force | Out-Null
}
New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' -name 'SystemDefaultTlsVersions' -value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' -name 'SchUseStrongCrypto' -value '1' -PropertyType 'DWord' -Force | Out-Null

# Create .NET Framework 4.0 32-bit hive and enable strong TLS encryption
If (-Not (Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319')) {
    New-Item 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Force | Out-Null
}
New-ItemProperty -path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -name 'SystemDefaultTlsVersions' -value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -name 'SchUseStrongCrypto' -value '1' -PropertyType 'DWord' -Force | Out-Null

# Create .NET Framework 4.0 64-bit hive and enable strong TLS encryption
If (-Not (Test-Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319')) {
    New-Item 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Force | Out-Null
}
New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -name 'SystemDefaultTlsVersions' -value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -name 'SchUseStrongCrypto' -value '1' -PropertyType 'DWord' -Force | Out-Null

# Create SCHANNEL Server hive (listenting to TLS connections) and enabled TLS 1.2
If (-Not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server')) {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
}
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'Enabled' -value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null

# Create SCHANNEL Client hive (opening TLS connections) and enabled TLS 1.2
If (-Not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client')) {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
}
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'Enabled' -value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null

Write-Host 'TLS 1.2 has been enabled. The script has not made any changes to the cipher suites.'
write-Host 'Please start the computer.'