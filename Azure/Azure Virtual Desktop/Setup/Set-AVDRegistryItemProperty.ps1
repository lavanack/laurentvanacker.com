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

[CmdletBinding()]
param(
)

Clear-Host

#region Network Settings
#From https://learn.microsoft.com/en-us/training/modules/configure-user-experience-settings/4-configure-user-settings-through-group-policies
Write-Verbose -Message "Setting some 'Network Settings' related registry values ..."
#From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.BITS::BITS_DisableBranchCache
$null = New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows\BITS' -Force
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\BITS' -Name "DisableBranchCache" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
#From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.PoliciesContentWindowsBranchCache::EnableWindowsBranchCache
$null = New-Item -Path 'HKLM:\Software\Policies\Microsoft\PeerDist\Service' -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\PeerDist\Service' -Name "Enable" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
#From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.HotspotAuthentication::HotspotAuth_Enable
$null = New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows\HotspotAuthentication' -Force
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\HotspotAuthentication' -Name "Enabled" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
#From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.PlugandPlay::P2P_Disabled
$null = New-Item -Path 'HKLM:\Software\Policies\Microsoft\Peernet' -Force
Set-ItemProperty -Path 'HKLM:\Software\policies\Microsoft\Peernet' -Name "Disabled" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
#From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.OfflineFiles::Pol_Enabled
$null = New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows\NetCache' -Force
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\NetCache' -Name "Enabled" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
#endregion

#region Session Time Settings
#From https://learn.microsoft.com/en-us/training/modules/configure-user-experience-settings/6-configure-session-timeout-properties
#From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_SESSIONS_Idle_Limit_1
Write-Verbose -Message "Setting some 'Session Time Settings' related registry values ..."
$null = New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services' -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name "MaxIdleTime" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 900000
#From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_SESSIONS_Disconnected_Timeout_1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name "MaxDisconnectionTime" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 900000
#From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_SESSIONS_Limits_2
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name "MaxConnectionTime" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
#From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_Session_End_On_Limit_2
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name "fResetBroken" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
#endregion

#region Enable Screen Capture Protection
#From https://learn.microsoft.com/en-us/training/modules/manage-access/5-configure-screen-capture-protection-for-azure-virtual-desktop
#Value 2 is for blocking screen capture on client and server.
Write-Verbose -Message "Setting some 'Enable Screen Capture Protection' related registry values ..."
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name "fEnableScreenCaptureProtection" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 2
#endregion

#region Enable Watermarking
#From https://learn.microsoft.com/en-us/azure/virtual-desktop/watermarking#enable-watermarking
Write-Verbose -Message "Setting some 'Enable Watermarking' related registry values ..."
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name "fEnableWatermarking" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1

Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name "WatermarkingHeightFactor" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 180
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name "WatermarkingOpacity" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 2000
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name "WatermarkingQrScale" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 4
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name "WatermarkingWidthFactor" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 320
#endregion

#region Enabling and using the new performance counters
#From https://learn.microsoft.com/en-us/training/modules/install-configure-apps-session-host/10-troubleshoot-application-issues-user-input-delay
Write-Verbose -Message "Setting some 'Performance Counters' related registry values ..."
$null = New-Item -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Force
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "EnableLagCounter" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
#endregion 

