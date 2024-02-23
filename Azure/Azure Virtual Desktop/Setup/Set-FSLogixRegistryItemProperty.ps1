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

param(
    [Parameter(Mandatory = $true)]
    [alias('StorageAccountName')]
    [string] $CurrentHostPoolStorageAccountName,

    [Parameter(Mandatory = $false)]
    [string] $StorageEndpointSuffix = "core.windows.net"
)

Clear-Host

#region FSLogix GPO Management: Dedicated GPO settings for FSLogix profiles for this HostPool 
#From https://learn.microsoft.com/en-us/fslogix/tutorial-configure-profile-containers#profile-container-configuration
Write-Verbose -Message "Setting some 'FSLogix' related registry values ..."
Set-ItemProperty -Path 'HKLM\SOFTWARE\FSLogix\Profiles' -Name "Enabled" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
Set-ItemProperty -Path 'HKLM\SOFTWARE\FSLogix\Profiles' -Name "DeleteLocalProfileWhenVHDShouldApply" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
Set-ItemProperty -Path 'HKLM\SOFTWARE\FSLogix\Profiles' -Name "FlipFlopProfileDirectoryName" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
Set-ItemProperty -Path 'HKLM\SOFTWARE\FSLogix\Profiles' -Name "LockedRetryCount" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 3
Set-ItemProperty -Path 'HKLM\SOFTWARE\FSLogix\Profiles' -Name "LockedRetryInterval" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 15
Set-ItemProperty -Path 'HKLM\SOFTWARE\FSLogix\Profiles' -Name "ProfileType" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 0
Set-ItemProperty -Path 'HKLM\SOFTWARE\FSLogix\Profiles' -Name "ReAttachIntervalSeconds" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 15
Set-ItemProperty -Path 'HKLM\SOFTWARE\FSLogix\Profiles' -Name "ReAttachRetryCount" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 3
Set-ItemProperty -Path 'HKLM\SOFTWARE\FSLogix\Profiles' -Name "SizeInMBs" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 30000
Set-ItemProperty -Path 'HKLM\SOFTWARE\FSLogix\Profiles' -Name "ProfileType" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 0

Set-ItemProperty -Path 'HKLM\SOFTWARE\FSLogix\Profiles' -Name "PreventLoginWithFailure" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
Set-ItemProperty -Path 'HKLM\SOFTWARE\FSLogix\Profiles' -Name "PreventLoginWithTempProfile" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
Set-ItemProperty -Path 'HKLM\SOFTWARE\FSLogix\Profiles' -Name "VolumeType" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "VHDX"
Set-ItemProperty -Path 'HKLM\SOFTWARE\FSLogix\Profiles' -Name "LogFileKeepingPeriod" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 10
Set-ItemProperty -Path 'HKLM\SOFTWARE\FSLogix\Profiles' -Name "IsDynamic" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
#From https://learn.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image#disable-automatic-updates
Set-ItemProperty -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name "NoAutoUpdate" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
#From https://learn.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image#set-up-time-zone-redirection
Set-ItemProperty -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name "fEnableTimeZoneRedirection" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
#From https://learn.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image#disable-storage-sense
Set-ItemProperty -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name "01" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
#From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.StorageSense::SS_AllowStorageSenseGlobal
Set-ItemProperty -Path 'HKLM\Software\Policies\Microsoft\Windows\StorageSense' -Name "AllowStorageSenseGlobal" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0

#region GPO Debug log file
#From https://blog.piservices.fr/post/2017/12/21/active-directory-debug-avance-de-l-application-des-gpos
Set-ItemProperty -Path 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics' -Name "GPSvcDebugLevel" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0x30002
#endregion

#region Microsoft Defender Endpoint A/V General Exclusions (the *.VHD and *.VHDX exclusions applies to FSLogix and MSIX) 
#From https://learn.microsoft.com/en-us/fslogix/overview-prerequisites#configure-antivirus-file-and-folder-exclusions
Write-Verbose -Message "Setting some 'Microsoft Defender Endpoint A/V Exclusions for this HostPool' related registry values ..."
Set-ItemProperty -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions' -Name "Exclusions_Paths" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
Set-ItemProperty -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -Name "%TEMP%\*\*.VHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
Set-ItemProperty -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -Name "%TEMP%\*\*.VHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
Set-ItemProperty -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -Name "%Windir%\TEMP\*\*.VHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
Set-ItemProperty -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -Name "%Windir%\TEMP\*\*.VHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
Set-ItemProperty -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -Name "%ProgramData%\FSLogix\Cache\*" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
Set-ItemProperty -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -Name "%ProgramData%\FSLogix\Proxy\*" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
Set-ItemProperty -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -Name "%ProgramFiles%\FSLogix\Apps\frxdrv.sys" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
Set-ItemProperty -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -Name "%ProgramFiles%\FSLogix\Apps\frxdrvvt.sys" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
Set-ItemProperty -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -Name "%ProgramFiles%\FSLogix\Apps\frxccd.sys" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0

Set-ItemProperty -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -Name "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
Set-ItemProperty -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -Name "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD.lock" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
Set-ItemProperty -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -Name "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD.meta" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
Set-ItemProperty -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -Name "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD.metadata" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
Set-ItemProperty -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -Name "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
Set-ItemProperty -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -Name "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX.lock" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
Set-ItemProperty -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -Name "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX.meta" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
Set-ItemProperty -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -Name "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX.metadata" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
Set-ItemProperty -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -Name "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.CIM" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0

#From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.WindowsDefender::Exclusions_Processesget-job
Set-ItemProperty -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions' -Name "Exclusions_Processes" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
Set-ItemProperty -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes' -Name "%ProgramFiles%\FSLogix\Apps\frxccd.exe" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
Set-ItemProperty -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes' -Name "%ProgramFiles%\FSLogix\Apps\frxccds.exe" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
Set-ItemProperty -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes' -Name "%ProgramFiles%\FSLogix\Apps\frxsvc.exe" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
Set-ItemProperty -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes' -Name "%ProgramFiles%\FSLogix\Apps\frxrobocopy.exe" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
#endregion

Write-Verbose -Message "Setting some 'FSLogix' related registry values ..."
Set-ItemProperty -Path 'HKLM\SOFTWARE\FSLogix\Profiles' -Name "VHDLocations" -Type ([Microsoft.Win32.RegistryValueKind]::MultiString) -Value "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles"
#Use Redirections.xml. Be careful : https://twitter.com/JimMoyle/status/1247843511413755904w
Set-ItemProperty -Path 'HKLM\SOFTWARE\FSLogix\Profiles' -Name "RedirXMLSourceFolder" -Type ([Microsoft.Win32.RegistryValueKind]::MultiString) -Value "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles"
