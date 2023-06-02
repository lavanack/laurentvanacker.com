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
##requires -Version 5 -Modules Az.Accounts, Az.DesktopVirtualization, Az.Network, Az.Resources, Az.Storage, PowerShellGet -RunAsAdministrator 
#requires -Version 5 -RunAsAdministrator 

#It is recommended not locate FSLogix on same storage as MSIX packages in production environment, 
#To run from a Domain Controller

#region Function definitions
function New-AzWvdPooledHostPoolSetup {
    [CmdletBinding()]
    Param(
        #The Word Document to convert
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [alias('Name')]
        [object[]]$PooledHostPool
    )
    begin {
        #region AVD OU Management
        $DefaultNamingContext = (Get-ADRootDSE).defaultNamingContext
        $AVDRootOU = Get-ADOrganizationalUnit -Filter 'Name -eq "AVD"' -SearchBase $DefaultNamingContext
        if (-not($AVDRootOU)) {
            $AVDRootOU = New-ADOrganizationalUnit -Name "AVD" -Path $DefaultNamingContext -ProtectedFromAccidentalDeletion $true -PassThru
        }
        #Blocking Inheritance
        $AVDRootOU | Set-GPInheritance -IsBlocked Yes

        $PersonalDesktopsOU = Get-ADOrganizationalUnit -Filter 'Name -eq "PersonalDesktops"' -SearchBase $AVDRootOU.DistinguishedName
        if (-not($PersonalDesktopsOU)) {
            $PersonalDesktopsOU = New-ADOrganizationalUnit -Name "PersonalDesktops" -Path $AVDRootOU.DistinguishedName -ProtectedFromAccidentalDeletion $false -PassThru
        }
        $PooledDesktopsOU = Get-ADOrganizationalUnit -Filter 'Name -eq "PooledDesktops"' -SearchBase $AVDRootOU.DistinguishedName
        if (-not($PooledDesktopsOU)) {
            $PooledDesktopsOU = New-ADOrganizationalUnit -Name "PooledDesktops" -Path $AVDRootOU.DistinguishedName -ProtectedFromAccidentalDeletion $false -PassThru
        }
        #endregion

        #region FSLogix GPO Management
        $FSLogixGPO = Get-GPO -Name "PooledDesktops - FSLogix Global Settings" -ErrorAction Ignore
        if (-not($FSLogixGPO)) {
            $FSLogixGPO = New-GPO -Name "PooledDesktops - FSLogix Global Settings" -ErrorAction Ignore
        }
        $FSLogixGPO | New-GPLink -Target $PooledDesktopsOU.DistinguishedName -LinkEnabled Yes -ErrorAction Ignore
        #region Top GPO used for setting up all configuration settings for FSLogix profiles but the VHDLocations that will be set per HostPool (1 storage account per HostPool)
        #From https://learn.microsoft.com/en-us/fslogix/tutorial-configure-profile-containers#profile-container-configuration
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "Enabled" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "DeleteLocalProfileWhenVHDShouldApply" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "FlipFlopProfileDirectoryName" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "LockedRetryCount" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 3
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "LockedRetryInterval" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 15
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "ProfileType" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 0
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "ReAttachIntervalSeconds" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 15
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "ReAttachRetryCount" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 3
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "SizeInMBs" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 30000

        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "PreventLoginWithFailure" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "PreventLoginWithTempProfile" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "VolumeType" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "VHDX"
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "LogFileKeepingPeriod" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 10
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "IsDynamic" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_SESSIONS_Idle_Limit_1
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "MaxIdleTime" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 900000
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_SESSIONS_Disconnected_Timeout_1
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "MaxDisconnectionTime" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 900000
        #From https://learn.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image#disable-automatic-updates
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueName "NoAutoUpdate" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
        #From https://learn.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image#set-up-time-zone-redirection
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "fEnableTimeZoneRedirection" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
        #From https://learn.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image#disable-storage-sense
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -ValueName "01" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0

        #region GPO "Local Users and Groups" Management via groups.xml
        #From https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/37722b69-41dd-4813-8bcd-7a1b4d44a13d
        #$GroupXMLGPOFilePath = "\\" + $((Get-ADDomain).DNSRoot) + "\SYSVOL\" + $((Get-ADDomain).DNSRoot) + "\Policies\{" + $FSLogixGPO.GpoId + "}\Machine\Preferences\Groups\Groups.xml"
        $GroupXMLGPOFilePath = "\\{0}\SYSVOL\{0}\Policies\{{{1}}}\Machine\Preferences\Groups\Groups.xml" -f ($(Get-ADDomain).DNSRoot), $($FSLogixGPO.Id)
        $Changed = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $ADGroupToExcludeFromFSLogix = @('Domain Admins', 'Enterprise Admins')
        $MembersLines = foreach ($CurrentADGroupToExcludeFromFSLogix in $ADGroupToExcludeFromFSLogix)
        {
            $CurrentADGroupToExcludeFromFSLogixSID = (Get-ADGroup -Filter "Name -eq '$CurrentADGroupToExcludeFromFSLogix'").SID.Value
            "<Member name=""$((Get-ADDomain).NetBIOSName)\$CurrentADGroupToExcludeFromFSLogix"" action=""ADD"" sid=""$CurrentADGroupToExcludeFromFSLogixSID""/>"
        }
        $MembersLines = $MembersLines -join "`r`n$("`t"*4)"

        #From https://jans.cloud/2019/08/microsoft-fslogix-profile-container/
$GroupXMLGPOFileContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
	<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" uid="{$((New-Guid).Guid)}" changed="$Changed" image="2" name="FSLogix Profile Exclude List">
		<Properties groupName="FSLogix Profile Exclude List" groupSid="" removeAccounts="0" deleteAllGroups="0" deleteAllUsers="0" description="" newName="" action="U">
			<Members>
				$MembersLines
			</Members>
		</Properties>
	</Group>
	<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" uid="{$((New-Guid).Guid)}" changed="$Changed" image="2" name="FSLogix Profile Include List">
		<Properties groupName="FSLogix Profile Include List" removeAccounts="0" deleteAllGroups="0" deleteAllUsers="0" description="" newName="" action="U"/>
	</Group>
	<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" uid="{$((New-Guid).Guid)}" changed="$Changed" image="2" name="FSLogix ODFC Include List">
		<Properties groupName="FSLogix ODFC Include List" removeAccounts="0" deleteAllGroups="0" deleteAllUsers="0" description="" newName="" action="U"/>
	</Group>
	<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" uid="{$((New-Guid).Guid)}" changed="$Changed" image="2" name="FSLogix ODFC Exclude List">
		<Properties groupName="FSLogix ODFC Exclude List" groupSid="" removeAccounts="0" deleteAllGroups="0" deleteAllUsers="0" description="" newName="" action="U">
			<Members>
				$MembersLines
			</Members>
		</Properties>
	</Group>
</Groups>
"@
        $null = New-Item -Path $GroupXMLGPOFilePath -ItemType File -Force
        #Set-Content -Path $GroupXMLGPOFilePath -Value $GroupXMLGPOFileContent -Encoding UTF8
        $GroupXMLGPOFileContent | Out-File $GroupXMLGPOFilePath -Encoding utf8
        #endregion
        <#
        #region Microsoft Defender Endpoint A/V General Exclusions
        #From https://learn.microsoft.com/en-us/fslogix/overview-prerequisites#configure-antivirus-file-and-folder-exclusions
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions' -ValueName "Exclusions_Paths" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "TempFolderVHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%TEMP%\*\*.VHD"
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "TempFolderVHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%TEMP%\*\*.VHDX"
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "WindirTempFolderVHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%Windir%\TEMP\*\*.VHD"
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "WindirTempFolderVHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%Windir%\TEMP\*\*.VHDX"
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "FSLogixCache" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%ProgramData%\FSLogix\Cache\*"
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "FSLogixProxy" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%ProgramData%\FSLogix\Proxy\*"
        #endregion
        #> 
        #endregion 
        #endregion 

        #region Variables
        $FSLogixContributor = "FSLogix Contributor"
        $FSLogixElevatedContributor = "FSLogix Elevated Contributor"
        $FSLogixReader = "FSLogix Reader"
        $FSLogixShareName = "profiles", "odfc" 

        $MSIXHosts = "MSIX Hosts"
        $MSIXShareAdmins = "MSIX Share Admins"
        $MSIXUsers = "MSIX Users"
        $MSIXShareName = "msix"  

        $SKUName = "Standard_ZRS"
        $CurrentPooledHostPoolStorageAccountNameMaxLength = 24

        #From https://www.youtube.com/watch?v=lvBiLj7oAG4&t=2s
        $RedirectionsXMLFileContent = @'
<?xml version="1.0"  encoding="UTF-8"?>
<FrxProfileFolderRedirection ExcludeCommonFolders="49">
<Excludes>
<Exclude Copy="0">AppData\Roaming\Microsoft\Teams\media-stack</Exclude>
<Exclude Copy="0">AppData\Local\Microsoft\Teams\meeting-addin\Cache</Exclude>
<Exclude Copy="0">AppData\Local\Microsoft\Outlook</Exclude>
<Exclude Copy="0">AppData\Local\Microsoft\OneDrive</Exclude>
<Exclude Copy="0">AppData\Local\Microsoft\Edge</Exclude>
</Excludes>
<Includes>
<Include>AppData\Local\Microsoft\Edge\User Data</Include>
</Includes>
</FrxProfileFolderRedirection>
'@
        #endregion 
    }
    process {
        Foreach ($CurrentPooledHostPool in $PooledHostPool) {
            #region General AD Management
            #region Host Pool Management: Dedicated AD OU Setup (1 OU per HostPool)
            $CurrentPooledHostPoolOU = Get-ADOrganizationalUnit -Filter "Name -eq '$($CurrentPooledHostPool.Name)'" -SearchBase $PooledDesktopsOU.DistinguishedName
            if (-not($CurrentPooledHostPoolOU)) {
                $CurrentPooledHostPoolOU = New-ADOrganizationalUnit -Name "$($CurrentPooledHostPool.Name)" -Path $PooledDesktopsOU.DistinguishedName -ProtectedFromAccidentalDeletion $false -PassThru
            }
            #endregion

            #region Host Pool Management: Dedicated AD users group
            $CurrentPooledHostPoolUsersADGroupName = "$($CurrentPooledHostPool.Name) - Users"
            $CurrentPooledHostPoolADGroup = Get-ADGroup -Filter "Name -eq '$CurrentPooledHostPoolUsersADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentPooledHostPoolOU.DistinguishedName
            if (-not($CurrentPooledHostPoolADGroup)) {
                $CurrentPooledHostPoolUsersADGroup = New-ADGroup -Name $CurrentPooledHostPoolUsersADGroupName -SamAccountName $CurrentPooledHostPoolUsersADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentPooledHostPoolUsersADGroupName -Path $CurrentPooledHostPoolOU.DistinguishedName -PassThru
            }
            #endregion
            #endregion

            #region FSLogix
            #region FSLogix AD Management

            #region Dedicated HostPool AD group
            #region Dedicated HostPool AD FSLogix groups
            $CurrentPooledHostPoolFSLogixContributorADGroupName = "$($CurrentPooledHostPool.Name) - $FSLogixContributor"
            $CurrentPooledHostPoolFSLogixContributorADGroup = Get-ADGroup -Filter "Name -eq '$CurrentPooledHostPoolFSLogixContributorADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentPooledHostPoolOU.DistinguishedName
            if (-not($CurrentPooledHostPoolFSLogixContributorADGroup)) {
                $CurrentPooledHostPoolFSLogixContributorADGroup = New-ADGroup -Name $CurrentPooledHostPoolFSLogixContributorADGroupName -SamAccountName $CurrentPooledHostPoolFSLogixContributorADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentPooledHostPoolFSLogixContributorADGroupName -Path $CurrentPooledHostPoolOU.DistinguishedName -PassThru
            }
            $CurrentPooledHostPoolFSLogixContributorADGroup | Add-ADGroupMember -Members $CurrentPooledHostPoolUsersADGroupName

            $CurrentPooledHostPoolFSLogixElevatedContributorADGroupName = "$($CurrentPooledHostPool.Name) - $FSLogixElevatedContributor"
            $CurrentPooledHostPoolFSLogixElevatedContributorADGroup = Get-ADGroup -Filter "Name -eq '$CurrentPooledHostPoolFSLogixElevatedContributorADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentPooledHostPoolOU.DistinguishedName
            if (-not($CurrentPooledHostPoolFSLogixElevatedContributorADGroup)) {
                $CurrentPooledHostPoolFSLogixElevatedContributorADGroup = New-ADGroup -Name $CurrentPooledHostPoolFSLogixElevatedContributorADGroupName -SamAccountName $CurrentPooledHostPoolFSLogixElevatedContributorADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentPooledHostPoolFSLogixElevatedContributorADGroupName -Path $CurrentPooledHostPoolOU.DistinguishedName -PassThru
            }

            $CurrentPooledHostPoolFSLogixReaderADGroupName = "$($CurrentPooledHostPool.Name) - $FSLogixReader"
            $CurrentPooledHostPoolFSLogixReaderADGroup = Get-ADGroup -Filter "Name -eq '$CurrentPooledHostPoolFSLogixReaderADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentPooledHostPoolOU.DistinguishedName
            if (-not($CurrentPooledHostPoolFSLogixReaderADGroup)) {
                $CurrentPooledHostPoolFSLogixReaderADGroup = New-ADGroup -Name $CurrentPooledHostPoolFSLogixReaderADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentPooledHostPoolFSLogixReaderADGroupName -Path $CurrentPooledHostPoolOU.DistinguishedName -PassThru
            }
            #endregion
            #endregion

            #region Run a sync with Azure AD
            Start-Service -Name ADSync -Verbose
            Import-Module -Name "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync"
            if (-not(Get-ADSyncConnectorRunStatus)) {
                Start-ADSyncSyncCycle -PolicyType Delta
            }
            #endregion 
            #endregion

            #region FSLogix Storage Account Management
            #region FSLogix Storage Account Name Setup
            $CurrentPooledHostPoolStorageAccountName = "fsl{0}" -f $($CurrentPooledHostPool.Name -replace "\W")
            $CurrentPooledHostPoolStorageAccountName = $CurrentPooledHostPoolStorageAccountName.Substring(0, [system.math]::min($CurrentPooledHostPoolStorageAccountNameMaxLength, $CurrentPooledHostPoolStorageAccountName.Length)).ToLower()

            #region Dedicated Host Pool AD GPO Management (1 GPO per Host Pool for setting up the dedicated VHDLocations value)
            $CurrentPooledHostPoolFSLogixGPO = Get-GPO -Name "$($CurrentPooledHostPool.Name) - FSLogix Settings" -ErrorAction Ignore
            if (-not($CurrentPooledHostPoolFSLogixGPO)) {
                $CurrentPooledHostPoolFSLogixGPO = New-GPO -Name "$($CurrentPooledHostPool.Name) - FSLogix Settings"
            }
            $CurrentPooledHostPoolFSLogixGPO | New-GPLink -Target $CurrentPooledHostPoolOU.DistinguishedName -LinkEnabled Yes -ErrorAction Ignore

            #region Dedicated GPO settings for FSLogix profiles for this HostPool 
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "VHDLocations" -Type ([Microsoft.Win32.RegistryValueKind]::MultiString) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles"
            #Use Redirections.xml. Be careful : https://twitter.com/JimMoyle/status/1247843511413755904w
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "RedirXMLSourceFolder" -Type ([Microsoft.Win32.RegistryValueKind]::MultiString) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles"
            #endregion

            #region Microsoft Defender Endpoint A/V General Exclusions
            #From https://learn.microsoft.com/en-us/fslogix/overview-prerequisites#configure-antivirus-file-and-folder-exclusions
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions' -ValueName "Exclusions_Paths" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "TempFolderVHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%TEMP%\*\*.VHD"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "TempFolderVHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%TEMP%\*\*.VHDX"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "WindirTempFolderVHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%Windir%\TEMP\*\*.VHD"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "WindirTempFolderVHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%Windir%\TEMP\*\*.VHDX"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "FSLogixCache" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%ProgramData%\FSLogix\Cache\*"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "FSLogixProxy" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%ProgramData%\FSLogix\Proxy\*"
            #endregion 

            #region Microsoft Defender Endpoint A/V Exclusions for this HostPool 
            #From https://learn.microsoft.com/en-us/fslogix/overview-prerequisites#configure-antivirus-file-and-folder-exclusions
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "ShareFolderVHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHD"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "ShareFolderVHDLock" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHD.lock"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "ShareFolderVHDMeta" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHD.meta"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "ShareFolderVHDMetaData" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHD.metadata"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "ShareFolderVHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHDX"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "ShareFolderVHDXLock" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHDX.lock"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "ShareFolderVHDXMeta" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHDX.meta"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "ShareFolderVHDXMetaData" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHDX.metadata"
            #endregion

            #endregion 

            #region Dedicated Resource Group Management (1 per HostPool)
            $CurrentPooledHostPoolResourceGroupName = "rg-avd-$($CurrentPooledHostPool.Name.ToLower())"

            $CurrentPooledHostPoolResourceGroup = Get-AzResourceGroup -Name $CurrentPooledHostPoolResourceGroupName -Location $CurrentPooledHostPool.Location -ErrorAction Ignore
            if (-not($CurrentPooledHostPoolResourceGroup)) {
                $CurrentPooledHostPoolResourceGroup = New-AzResourceGroup -Name $CurrentPooledHostPoolResourceGroupName -Location $CurrentPooledHostPool.Location -Force
            }
            #endregion

            #region Dedicated Storage Account Setup
            $CurrentPooledHostPoolStorageAccount = Get-AzStorageAccount -Name $CurrentPooledHostPoolStorageAccountName -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -ErrorAction Ignore
            if (-not($CurrentPooledHostPoolStorageAccount)) {
                if (-not(Get-AzStorageAccountNameAvailability -Name $CurrentPooledHostPoolStorageAccountName).NameAvailable) {
                    Write-Error "The storage account name '$CurrentPooledHostPoolStorageAccountName' is not available !" -ErrorAction Stop
                }
                $CurrentPooledHostPoolStorageAccount = New-AzStorageAccount -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -AccountName $CurrentPooledHostPoolStorageAccountName -Location $CurrentPooledHostPool.Location -SkuName $SKUName
            }
            #Registering the Storage Account with your active directory environment under the target
            if (-not(Get-ADComputer -Filter "Name -eq '$CurrentPooledHostPoolStorageAccountName'" -SearchBase $CurrentPooledHostPoolOU.DistinguishedName)) {
                if (-not(Get-Module -Name AzFilesHybrid -ListAvailable)) {
                    $AzFilesHybridZipName = 'AzFilesHybrid.zip'
                    $OutFile = Join-Path -Path $env:TEMP -ChildPath $AzFilesHybridZipName
                    Start-BitsTransfer https://github.com/Azure-Samples/azure-files-samples/releases/latest/download/AzFilesHybrid.zip -destination $OutFile
                    Expand-Archive -Path $OutFile -DestinationPath $env:TEMP\AzFilesHybrid -Force -Verbose
                    Push-Location -Path $env:TEMP\AzFilesHybrid
                    .\CopyToPSPath.ps1
                    Pop-Location
                }
                Import-Module AzFilesHybrid
                Join-AzStorageAccountForAuth -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -Name $CurrentPooledHostPoolStorageAccountName -DomainAccountType "ComputerAccount" -OrganizationUnitDistinguishedName $CurrentPooledHostPoolOU.DistinguishedName -Confirm:$false
            }

            # Get the target storage account
            #$storageaccount = Get-AzStorageAccount -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -Name $CurrentPooledHostPoolStorageAccountName

            # List the directory service of the selected service account
            $CurrentPooledHostPoolStorageAccount.AzureFilesIdentityBasedAuth.DirectoryServiceOptions

            # List the directory domain information if the storage account has enabled AD authentication for file shares
            $CurrentPooledHostPoolStorageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties

            $CurrentPooledHostPoolStorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -AccountName $CurrentPooledHostPoolStorageAccountName) | Where-Object -FilterScript { $_.KeyName -eq "key1" }

            # Save the password so the drive 
            Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "cmdkey /add:`"$CurrentPooledHostPoolStorageAccountName.file.core.windows.net`" /user:`"localhost\$CurrentPooledHostPoolStorageAccountName`" /pass:`"$($CurrentPooledHostPoolStorageAccountKey.Value)`""
            #endregion

            #region Dedicated Share Management
            $FSLogixShareName | ForEach-Object -Process { 
                $CurrentPooledHostPoolShareName = $_
                #Create a share for FSLogix
                $CurrentPooledHostPoolStorageShare = New-AzRmStorageShare -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -StorageAccountName $CurrentPooledHostPoolStorageAccountName -Name $CurrentPooledHostPoolShareName -AccessTier Hot -QuotaGiB 200

                # Mount the share
                New-PSDrive -Name Z -PSProvider FileSystem -Root "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\$CurrentPooledHostPoolShareName"

                #region NTFS permissions for FSLogix
                #From https://blue42.net/windows/changing-ntfs-security-permissions-using-powershell/
                #region Sample NTFS permissions for FSLogix
                $existingAcl = Get-Acl Z:

                #Disabling inheritance
                $existingAcl.SetAccessRuleProtection($true, $false)

                #Remove all inherited permissions from this object.
                $existingAcl.Access | ForEach-Object -Process { $null = $existingAcl.RemoveAccessRule($_) }

                #Add Modify for CREATOR OWNER Group for Subfolders and files only
                $identity = "CREATOR OWNER"
                $colRights = [System.Security.AccessControl.FileSystemRights]::Modify
                $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::InheritOnly           
                $objType = [System.Security.AccessControl.AccessControlType]::Allow
                # Create a new FileSystemAccessRule object
                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                # Modify the existing ACL to include the new rule
                $existingAcl.SetAccessRule($AccessRule)

                #Add Full Control for "Administrators" Group for This folder, subfolders and files
                $identity = "Administrators"
                $colRights = [System.Security.AccessControl.FileSystemRights]::FullControl
                $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
                $objType = [System.Security.AccessControl.AccessControlType]::Allow
                # Create a new FileSystemAccessRule object
                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                # Modify the existing ACL to include the new rule
                $existingAcl.SetAccessRule($AccessRule)

                #Add Modify for "Users" Group for This folder only
                #$identity = "Users"
                $identity = $CurrentPooledHostPoolUsersADGroupName
                $colRights = [System.Security.AccessControl.FileSystemRights]::Modify
                $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None
                $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
                $objType = [System.Security.AccessControl.AccessControlType]::Allow
                # Create a new FileSystemAccessRule object
                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                # Modify the existing ACL to include the new rule
                $existingAcl.SetAccessRule($AccessRule)

                #Enabling inheritance
                $existingAcl.SetAccessRuleProtection($false, $true)

                # Apply the modified access rule to the folder
                $existingAcl | Set-Acl -Path Z:
                #endregion

                #region redirection.xml file management
                #Creating the redirection.xml file
                New-Item -Path Z: -Name "redirections.xml" -ItemType "file" -Value $RedirectionsXMLFileContent
                $existingAcl = Get-Acl Z:\redirections.xml
                #Add Read for "Users" Group for This folder only
                #$identity = "Users"
                $identity = $CurrentPooledHostPoolUsersADGroupName
                $colRights = [System.Security.AccessControl.FileSystemRights]::Read
                $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None
                $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
                $objType = [System.Security.AccessControl.AccessControlType]::Allow
                # Create a new FileSystemAccessRule object
                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                # Modify the existing ACL to include the new rule
                $existingAcl.SetAccessRule($AccessRule)
                $existingAcl | Set-Acl -Path Z:
                #endregion

                # Unmount the share
                Remove-PSDrive -Name Z
                #endregion

                #region RBAC Management
                #Constrain the scope to the target file share
                $AzContext = Get-AzContext
                $SubscriptionId = $AzContext.Subscription.Id
                $scope = "/subscriptions/$SubscriptionId/resourceGroups/$CurrentPooledHostPoolResourceGroupName/providers/Microsoft.Storage/storageAccounts/$CurrentPooledHostPoolStorageAccountName/fileServices/default/fileshares/$CurrentPooledHostPoolShareName"

                #region Setting up the file share with right RBAC: FSLogix Contributor = "Storage File Data SMB Share Elevated Contributor"
                #Get the name of the custom role
                $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Contributor"
                #Assign the custom role to the target identity with the specified scope.
                $AzADGroup = Get-AzADGroup -SearchString $CurrentPooledHostPoolFSLogixContributorADGroupName
                if (-not(Get-AzRoleAssignment -RoleDefinitionName $FileShareContributorRole.Name)) {
                    New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $scope
                }
                #endregion

                #region Setting up the file share with right RBAC: FSLogix Elevated Contributor = "Storage File Data SMB Share Contributor"
                #Get the name of the custom role
                $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Elevated Contributor"
                #Assign the custom role to the target identity with the specified scope.
                $AzADGroup = Get-AzADGroup -SearchString $CurrentPooledHostPoolFSLogixElevatedContributorADGroupName
                if (-not(Get-AzRoleAssignment -RoleDefinitionName $FileShareContributorRole.Name)) {
                    New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $scope
                }
                #endregion

                #region Setting up the file share with right RBAC: FSLogix Reader = "Storage File Data SMB Share Reader"
                #Get the name of the custom role
                $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Reader"
                #Assign the custom role to the target identity with the specified scope.
                $AzADGroup = Get-AzADGroup -SearchString $CurrentPooledHostPoolFSLogixReaderADGroupName
                if (-not(Get-AzRoleAssignment -RoleDefinitionName $FileShareContributorRole.Name)) {
                    New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $scope
                }
                #endregion

                #endregion
            }
            #endregion
            #endregion
            #endregion

            #region MSIX
            #region Dedicated HostPool AD group

            #region Dedicated HostPool AD FSLogix groups
            $CurrentPooledHostPoolMSIXHostsADGroupName = "$($CurrentPooledHostPool.Name) - $MSIXHosts"
            $CurrentPooledHostPoolMSIXHostsADGroupName
            $CurrentPooledHostPoolMSIXHostsADGroup = Get-ADGroup -Filter "Name -eq '$CurrentPooledHostPoolMSIXHostsADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentPooledHostPoolOU.DistinguishedName
            if (-not($CurrentPooledHostPoolMSIXHostsADGroup)) {
                $CurrentPooledHostPoolMSIXHostsADGroup = New-ADGroup -Name $CurrentPooledHostPoolMSIXHostsADGroupName -SamAccountName $CurrentPooledHostPoolMSIXHostsADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentPooledHostPoolMSIXHostsADGroupName -Path $CurrentPooledHostPoolOU.DistinguishedName -PassThru
            }
            $CurrentPooledHostPoolMSIXHostsADGroup | Add-ADGroupMember -Members $CurrentPooledHostPoolUsersADGroupName

            $CurrentPooledHostPoolMSIXShareAdminsADGroupName = "$($CurrentPooledHostPool.Name) - $MSIXShareAdmins"
            $CurrentPooledHostPoolMSIXShareAdminsADGroup = Get-ADGroup -Filter "Name -eq '$CurrentPooledHostPoolMSIXShareAdminsADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentPooledHostPoolOU.DistinguishedName
            if (-not($CurrentPooledHostPoolMSIXShareAdminsADGroup)) {
                $CurrentPooledHostPoolMSIXShareAdminsADGroup = New-ADGroup -Name $CurrentPooledHostPoolMSIXShareAdminsADGroupName -SamAccountName $CurrentPooledHostPoolMSIXShareAdminsADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentPooledHostPoolMSIXShareAdminsADGroupName -Path $CurrentPooledHostPoolOU.DistinguishedName -PassThru
            }

            $CurrentPooledHostPoolMSIXUsersADGroupName = "$($CurrentPooledHostPool.Name) - $MSIXUsers"
            $CurrentPooledHostPoolMSIXUsersADGroup = Get-ADGroup -Filter "Name -eq '$CurrentPooledHostPoolMSIXUsersADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentPooledHostPoolOU.DistinguishedName
            if (-not($CurrentPooledHostPoolMSIXUsersADGroup)) {
                $CurrentPooledHostPoolMSIXUsersADGroup = New-ADGroup -Name $CurrentPooledHostPoolMSIXUsersADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentPooledHostPoolMSIXUsersADGroupName -Path $CurrentPooledHostPoolOU.DistinguishedName -PassThru
            }
            $CurrentPooledHostPoolMSIXUsersADGroup | Add-ADGroupMember -Members $CurrentPooledHostPoolUsersADGroupName
            #endregion
            #endregion

            #region Run a sync with Azure AD
            Start-Service -Name ADSync -Verbose
            Import-Module -Name "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync"
            if (-not(Get-ADSyncConnectorRunStatus)) {
                Start-ADSyncSyncCycle -PolicyType Delta
            }
            #endregion 
            #endregion

            #region FSLogix Storage Account Management
            #region FSLogix Storage Account Name Setup
            $CurrentPooledHostPoolStorageAccountName = "msix{0}" -f $($CurrentPooledHostPool.Name -replace "\W")
            $CurrentPooledHostPoolStorageAccountName = $CurrentPooledHostPoolStorageAccountName.Substring(0, [system.math]::min($CurrentPooledHostPoolStorageAccountNameMaxLength, $CurrentPooledHostPoolStorageAccountName.Length)).ToLower()
            #endregion 

            #region Dedicated Resource Group Management (1 per HostPool)
            $CurrentPooledHostPoolResourceGroupName = "rg-avd-$($CurrentPooledHostPool.Name.ToLower())"

            $CurrentPooledHostPoolResourceGroup = Get-AzResourceGroup -Name $CurrentPooledHostPoolResourceGroupName -Location $CurrentPooledHostPool.Location -ErrorAction Ignore
            if (-not($CurrentPooledHostPoolResourceGroup)) {
                $CurrentPooledHostPoolResourceGroup = New-AzResourceGroup -Name $CurrentPooledHostPoolResourceGroupName -Location $CurrentPooledHostPool.Location -Force
            }
            #endregion

            #region Dedicated Storage Account Setup
            $CurrentPooledHostPoolStorageAccount = Get-AzStorageAccount -Name $CurrentPooledHostPoolStorageAccountName -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -ErrorAction Ignore
            if (-not($CurrentPooledHostPoolStorageAccount)) {
                if (-not(Get-AzStorageAccountNameAvailability -Name $CurrentPooledHostPoolStorageAccountName).NameAvailable) {
                    Write-Error "The storage account name '$CurrentPooledHostPoolStorageAccountName' is not available !" -ErrorAction Stop
                }
                $CurrentPooledHostPoolStorageAccount = New-AzStorageAccount -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -AccountName $CurrentPooledHostPoolStorageAccountName -Location $CurrentPooledHostPool.Location -SkuName $SKUName
            }
            #Registering the Storage Account with your active directory environment under the target
            if (-not(Get-ADComputer -Filter "Name -eq '$CurrentPooledHostPoolStorageAccountName'" -SearchBase $CurrentPooledHostPoolOU.DistinguishedName)) {
                Import-Module AzFilesHybrid
                Join-AzStorageAccountForAuth -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -Name $CurrentPooledHostPoolStorageAccountName -DomainAccountType "ComputerAccount" -OrganizationUnitDistinguishedName $CurrentPooledHostPoolOU.DistinguishedName -Confirm:$false
            }

            # Get the target storage account
            #$storageaccount = Get-AzStorageAccount -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -Name $CurrentPooledHostPoolStorageAccountName

            # List the directory service of the selected service account
            $CurrentPooledHostPoolStorageAccount.AzureFilesIdentityBasedAuth.DirectoryServiceOptions

            # List the directory domain information if the storage account has enabled AD authentication for file shares
            $CurrentPooledHostPoolStorageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties

            $CurrentPooledHostPoolStorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -AccountName $CurrentPooledHostPoolStorageAccountName) | Where-Object -FilterScript { $_.KeyName -eq "key1" }

            # Save the password so the drive 
            Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "cmdkey /add:`"$CurrentPooledHostPoolStorageAccountName.file.core.windows.net`" /user:`"localhost\$CurrentPooledHostPoolStorageAccountName`" /pass:`"$($CurrentPooledHostPoolStorageAccountKey.Value)`""
            #endregion

            #region Dedicated Share Management
            $MSIXShareName | ForEach-Object -Process { 
                $CurrentPooledHostPoolShareName = $_
                #Create a share for FSLogix
                $CurrentPooledHostPoolStorageShare = New-AzRmStorageShare -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -StorageAccountName $CurrentPooledHostPoolStorageAccountName -Name $CurrentPooledHostPoolShareName -AccessTier Hot -QuotaGiB 200

                # Mount the share
                New-PSDrive -Name Z -PSProvider FileSystem -Root "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\$CurrentPooledHostPoolShareName"

                #region NTFS permissions for MSIX
                #From https://docs.microsoft.com/en-us/azure/virtual-desktop/app-attach-file-share#how-to-set-up-the-file-share
                #From https://blue42.net/windows/changing-ntfs-security-permissions-using-powershell/
                $existingAcl = Get-Acl Z:
                $existingAcl.Access | ForEach-Object -Process { $existingAcl.RemoveAccessRule($_) }
                #Disabling inheritance
                $existingAcl.SetAccessRuleProtection($true, $false)

                #Add Full Control for Administrators Group for This folder, subfolders and files
                $identity = "BUILTIN\Administrators"
                $colRights = [System.Security.AccessControl.FileSystemRights]::FullControl
                $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
                $objType = [System.Security.AccessControl.AccessControlType]::Allow
                # Create a new FileSystemAccessRule object
                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                # Modify the existing ACL to include the new rule
                $existingAcl.SetAccessRule($AccessRule)

                #Add Full Control for MSIXShareAdmins Group for This folder, subfolders and files
                $identity = $CurrentPooledHostPoolMSIXShareAdminsADGroupName
                $colRights = [System.Security.AccessControl.FileSystemRights]::FullControl
                $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
                $objType = [System.Security.AccessControl.AccessControlType]::Allow
                # Create a new FileSystemAccessRule object
                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                # Modify the existing ACL to include the new rule
                $existingAcl.SetAccessRule($AccessRule)

                #Add "Read And Execute" for MSIXUsers Group for This folder, subfolders and files
                $identity = $CurrentPooledHostPoolMSIXUsersADGroupName
                $colRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
                $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None           
                $objType = [System.Security.AccessControl.AccessControlType]::Allow
                # Create a new FileSystemAccessRule object
                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                # Modify the existing ACL to include the new rule
                $existingAcl.SetAccessRule($AccessRule)

                #Add "Read And Execute" for MSIXHosts Group for This folder, subfolders and files
                $identity = $CurrentPooledHostPoolMSIXHostsADGroupName
                $colRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
                $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
                $objType = [System.Security.AccessControl.AccessControlType]::Allow
                # Create a new FileSystemAccessRule object
                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                # Modify the existing ACL to include the new rule
                $existingAcl.SetAccessRule($AccessRule)

                #Enabling inheritance
                $existingAcl.SetAccessRuleProtection($false, $true)

                # Apply the modified access rule to the folder
                $existingAcl | Set-Acl -Path Z:
                #endregion

                # Unmount the share
                Remove-PSDrive -Name Z
                #endregion

                #region RBAC Management
                #Constrain the scope to the target file share
                $AzContext = Get-AzContext
                $SubscriptionId = $AzContext.Subscription.Id
                $scope = "/subscriptions/$SubscriptionId/resourceGroups/$CurrentPooledHostPoolResourceGroupName/providers/Microsoft.Storage/storageAccounts/$CurrentPooledHostPoolStorageAccountName/fileServices/default/fileshares/$CurrentPooledHostPoolShareName"

                #region Setting up the file share with right RBAC: MSIX Hosts & MSIX Users = "Storage File Data SMB Share Contributor" + MSIX Share Admins = Storage File Data SMB Share Elevated Contributor
                #https://docs.microsoft.com/en-us/azure/virtual-desktop/app-attach-file-share#how-to-set-up-the-file-share
                #Get the name of the custom role
                $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Contributor"
                #Assign the custom role to the target identity with the specified scope.
                $AzADGroup = Get-AzADGroup -SearchString $CurrentPooledHostPoolMSIXHostsADGroupName
                if (-not(Get-AzRoleAssignment -RoleDefinitionName $FileShareContributorRole.Name)) {
                    New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $scope
                }
                #Assign the custom role to the target identity with the specified scope.
                $AzADGroup = Get-AzADGroup -SearchString $CurrentPooledHostPoolMSIXUsersADGroupName
                if (-not(Get-AzRoleAssignment -RoleDefinitionName $FileShareContributorRole.Name)) {
                    New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $scope
                }
                #endregion

                #region Setting up the file share with right RBAC: FSLogix Elevated Contributor = "Storage File Data SMB Share Contributor"
                #Get the name of the custom role
                $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Elevated Contributor"
                #Assign the custom role to the target identity with the specified scope.
                $AzADGroup = Get-AzADGroup -SearchString $CurrentPooledHostPoolMSIXShareAdminsADGroupName
                if (-not(Get-AzRoleAssignment -RoleDefinitionName $FileShareContributorRole.Name)) {
                    New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $scope
                }
                #endregion

                #endregion
            }
            #endregion

            #region Host Pool Setup
            $parameters = @{
                Name                  = $CurrentPooledHostPool.Name
                ResourceGroupName     = $CurrentPooledHostPoolResourceGroupName
                HostPoolType          = 'Pooled'
                LoadBalancerType      = 'BreadthFirst'
                PreferredAppGroupType = 'Desktop'
                MaxSessionLimit       = $CurrentPooledHostPool.MaxSessionLimit
                Location              = $CurrentPooledHostPool.Location
                StartVMOnConnect      = $true
                # From https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/rdp-files?context=%2Fazure%2Fvirtual-desktop%2Fcontext%2Fcontext#device-redirection
                # No RDP redirection for COM ports, Local Drives and printers.
                CustomRdpProperty     = "redirectcomports:i:0;redirectlocation:i:0;redirectprinters:i:0;drivestoredirect:s:;usbdevicestoredirect:s:"
                Verbose               = $true
            }

            $CurrentAzWvdHostPool = New-AzWvdHostPool @parameters
            $RegistrationInfoExpirationTime = (Get-Date).AddDays(1)
            $RegistrationInfoToken = New-AzWvdRegistrationInfo -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -HostPoolName $CurrentPooledHostPool.Name -ExpirationTime $RegistrationInfoExpirationTime -Verbose -ErrorAction SilentlyContinue
            #endregion

            #region Application Group Setup
            $parameters = @{
                Name                 = "{0}-DAG" -f $CurrentPooledHostPool.Name
                ResourceGroupName    = $CurrentPooledHostPoolResourceGroupName
                Location             = $CurrentPooledHostPool.Location
                HostPoolArmPath      = $CurrentAzWvdHostPool.Id
                ApplicationGroupType = 'Desktop'
            }

            $CurrentAzWvdApplicationGroup = New-AzWvdApplicationGroup @parameters
            #region Assign groups to an application group
            # Get the object ID of the user group you want to assign to the application group
            $userGroupId = (Get-AzADGroup -DisplayName $CurrentPooledHostPoolUsersADGroupName).Id

            # Assign users to the application group
            $parameters = @{
                ObjectId           = $userGroupId
                ResourceName       = $CurrentAzWvdApplicationGroup.Name
                ResourceGroupName  = $CurrentPooledHostPoolResourceGroupName
                RoleDefinitionName = 'Desktop Virtualization User'
                ResourceType       = 'Microsoft.DesktopVirtualization/applicationGroups'
            }

            New-AzRoleAssignment @parameters
            #endregion 

            #endregion

            #region Workspace Setup
            $parameters = @{
                Name                      = "WS-{0}" -f $CurrentPooledHostPool.Name
                ResourceGroupName         = $CurrentPooledHostPoolResourceGroupName
                ApplicationGroupReference = $CurrentAzWvdApplicationGroup.Id
                Location                  = $CurrentPooledHostPool.Location
            }

            $CurrentAzWvdWorkspace = New-AzWvdWorkspace @parameters
            #endregion
        }    
    }
    end {}
}
#endregion

#region Main code
Clear-Host
$Error.Clear()
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir



#For installing required modules if needed
#Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Verbose
Get-PackageProvider -Name NuGet -Force -Verbose
$RequiredModules = 'Az.Accounts', 'Az.DesktopVirtualization', 'Az.Network', 'Az.Resources', 'Az.Storage', 'PowerShellGet'
$InstalledModule = Get-InstalledModule -Name $RequiredModules -ErrorAction Ignore
if (-not([String]::IsNullOrEmpty($InstalledModule)))
{
    $MissingModules  = (Compare-Object -ReferenceObject $RequiredModules -DifferenceObject (Get-InstalledModule -Name $RequiredModules -ErrorAction Ignore).Name).InputObject
}
else
{
    $MissingModules  = $RequiredModules
}
if (-not([String]::IsNullOrEmpty($MissingModules)))
{
    Install-Module -Name $MissingModules -Force -Verbose
}

#region Azure Connection
if (-not(Get-AzContext))
{
    Connect-AzAccount
}
Get-AzSubscription | Out-GridView -OutputMode Single | Select-AzSubscription
#endregion
#>

#region Installling FSLogix GPO Setti
if (-not(Test-Path -Path $env:SystemRoot\policyDefinitions\en-US\fslogix.adml -PathType Leaf) -or -not(Test-Path -Path $env:SystemRoot\policyDefinitions\fslogix.admx -PathType Leaf)) {
    $FSLogixLatestZipName = 'FSLogix_Apps_Latest.zip'
    $OutFile = Join-Path -Path $env:Temp -ChildPath $FSLogixLatestZipName
    $FSLogixLatestURI = 'https://download.microsoft.com/download/c/4/4/c44313c5-f04a-4034-8a22-967481b23975/FSLogix_Apps_2.9.8440.42104.zip'
    Start-BitsTransfer $FSLogixLatestURI -destination $OutFile
    Expand-Archive -Path $OutFile -DestinationPath $env:Temp\FSLogixLatest -Force
    Copy-Item -Path $env:Temp\FSLogixLatest\fslogix.adml $env:SystemRoot\policyDefinitions\en-US -Verbose
    Copy-Item -Path $env:Temp\FSLogixLatest\fslogix.admx $env:SystemRoot\policyDefinitions -Verbose
}
#endregion 

#region function calls
<#
$PooledHostPools = @(
    [PSCustomObject]@{Name="HP-Pool-HelpDesk-001"; Location="EastUS"; MaxSessionLimit=5}
    [PSCustomObject]@{Name="HP-Pool-HelpDesk-002"; Location="EastUS"; MaxSessionLimit=5}
    [PSCustomObject]@{Name="HP-Pool-HelpDesk-003"; Location="EastUS"; MaxSessionLimit=5}
)
#>

$PooledHostPools = 1..3 | ForEach-Object -Process {
    [PSCustomObject]@{Name = $("HP-Pool-HelpDesk-{0:D3}" -f $_); Location = "EastUS"; MaxSessionLimit = 5 }
}
#Uncomment the following block to remove all previously existing resources

<#
#region Cleanup of the previously existing resources
#region AD OU/GPO Cleanup
Get-ADOrganizationalUnit -Filter * | Where-Object -FilterScript {$_.Name -in $($PooledHostPools.Name) -or $_.Name -in 'AVD', 'PooledDesktops', 'PersonalDesktops'} | Set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $false -PassThru -ErrorAction Ignore | Remove-ADOrganizationalUnit -Recursive -Confirm:$false -Verbose #-WhatIf
Get-GPO -All | Where-Object -FilterScript {($_.DisplayName -match $($PooledHostPools.Name -join "|")) -or ($_.DisplayName -in 'PooledDesktops - FSLogix Global Settings')} | Remove-GPO -Verbose #-WhatIf
#endregion
#region Azure Cleanup
$RG = Get-AzResourceGroup | Where-Object -FilterScript {($_.ResourceGroupName -match $($PooledHostPools.Name -join "|"))}
$RG | Remove-AzResourceGroup -WhatIf
$RG | Remove-AzResourceLock -LockName DenyDelete -Force -ErrorAction Ignore

#$Jobs = $RG | Remove-AzResourceGroup -Force -AsJob -Verbose
$Jobs | Wait-Job
$Jobs | Remove-Job
#endregion
#region Run a sync with Azure AD
Start-Service -Name ADSync -Verbose
Import-Module -Name "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync"
if (-not(Get-ADSyncConnectorRunStatus))
{
    Start-ADSyncSyncCycle -PolicyType Delta
}
#endregion 
#endregion 
#>

New-AzWvdPooledHostPoolSetup -PooledHostPool $PooledHostPools -Verbose
#Or pipeline processing call
#$PooledHostPools | New-AzWvdPooledHostPoolSetup 
#endregion
#endregion