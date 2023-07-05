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
##requires -Version 5 -Modules Az.Accounts, Az.DesktopVirtualization, Az.Network, Az.KeyVault, Az.Resources, Az.Storage, PowerShellGet -RunAsAdministrator 
#requires -Version 5 -RunAsAdministrator 

#It is recommended not locate FSLogix on same storage as MSIX packages in production environment, 
#To run from a Domain Controller

#region Function definitions
function Get-AzKeyVaultNameAvailability {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [alias('Name')]
        [string]$VaultName
    )
    #region Azure Context
    # Log in first with Connect-AzAccount if not using Cloud Shell

    $azContext = Get-AzContext
    $SubcriptionID = $azContext.Subscription.Id
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
    $token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'='application/json'
        'Authorization'='Bearer ' + $token.AccessToken
    }
    #endregion
    $Body = [ordered]@{ 
        "name" = $VaultName
        "type" = "Microsoft.KeyVault/vaults"
    }

    $URI = "https://management.azure.com/subscriptions/$SubcriptionID/providers/Microsoft.KeyVault/checkNameAvailability?api-version=2022-07-01"
    try
    {
        # Invoke the REST API
        $Response = Invoke-RestMethod -Method POST -Headers $authHeader -Body $($Body | ConvertTo-Json) -ContentType "application/json" -Uri $URI -ErrorVariable ResponseError
    }
    catch [System.Net.WebException] {   
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        $respStream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($respStream)
        $Response = $reader.ReadToEnd() | ConvertFrom-Json
        Write-Warning -Message $Response.message
    }
    finally 
    {
    }
    return $Response
}

function New-AzWvdPooledHostPoolSetup {
    [CmdletBinding()]
    Param(
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

        #region AVD GPO Management
        $AVDGPO = Get-GPO -Name "AVD - Global Settings" -ErrorAction Ignore
        if (-not($AVDGPO)) {
            $AVDGPO = New-GPO -Name "AVD - Global Settings" -ErrorAction Ignore
        }
        $AVDGPO | New-GPLink -Target $AVDRootOU.DistinguishedName -LinkEnabled Yes -ErrorAction Ignore

        #region Network Settings
        #From https://learn.microsoft.com/en-us/training/modules/configure-user-experience-settings/4-configure-user-settings-through-group-policies
        Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\Windows\BITS' -ValueName "DisableBranchCache" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
        Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\PeerDist\Service' -ValueName "Enable" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
        Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\Windows\HotspotAuthentication' -ValueName "Enabled" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
        Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\Software\policies\Microsoft\Peernet' -ValueName "Disabled" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
        Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\Windows\NetCache' -ValueName "Enabled" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
        #endregion

        #region Session Time Settings
        #From https://learn.microsoft.com/en-us/training/modules/configure-user-experience-settings/6-configure-session-timeout-properties
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_SESSIONS_Idle_Limit_1
        Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "MaxIdleTime" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 900000
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_SESSIONS_Disconnected_Timeout_1
        Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "MaxDisconnectionTime" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 900000
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_SESSIONS_Limits_2
        Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "MaxConnectionTime" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_Session_End_On_Limit_2
        Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "fResetBroken" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
        #endregion

        #region Enabling and using the new performance counters
        #From https://learn.microsoft.com/en-us/training/modules/install-configure-apps-session-host/10-troubleshoot-application-issues-user-input-delay
        Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\System\CurrentControlSet\Control\Terminal Server' -ValueName "EnableLagCounter" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
        #endregion 

        $PersonalDesktopsOU = Get-ADOrganizationalUnit -Filter 'Name -eq "PersonalDesktops"' -SearchBase $AVDRootOU.DistinguishedName
        if (-not($PersonalDesktopsOU)) {
            $PersonalDesktopsOU = New-ADOrganizationalUnit -Name "PersonalDesktops" -Path $AVDRootOU.DistinguishedName -ProtectedFromAccidentalDeletion $false -PassThru
        }
        $PooledDesktopsOU = Get-ADOrganizationalUnit -Filter 'Name -eq "PooledDesktops"' -SearchBase $AVDRootOU.DistinguishedName
        if (-not($PooledDesktopsOU)) {
            $PooledDesktopsOU = New-ADOrganizationalUnit -Name "PooledDesktops" -Path $AVDRootOU.DistinguishedName -ProtectedFromAccidentalDeletion $false -PassThru
        }
        #region Starter GPOs Management
        try
        {
            $null = Get-GPStarterGPO -Name "Group Policy Reporting Firewall Ports"
            $null = Get-GPStarterGPO -Name "Group Policy Reporting Firewall Ports"
        }
        catch 
        {
            Write-Warning "The required starter GPOs are not installed. Please click on the 'Create Starter GPOs Folder' under Group Policy Management / Forest / Domains / $((Get-ADDomain).DNSRoot) / Starter GPOs "
            Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "gpmc.msc" -Wait
        }
        #region These Starter GPOs include policy settings to configure the firewall rules required for GPO operations
        if (-not(Get-GPO -Name "Group Policy Reporting Firewall Ports" -ErrorAction Ignore))
        {
            Get-GPStarterGPO -Name "Group Policy Reporting Firewall Ports" | New-GPO -Name "Group Policy Reporting Firewall Ports" | New-GPLink -Target $AVDRootOU.DistinguishedName -LinkEnabled Yes -ErrorAction Ignore
        }
        if (-not(Get-GPO -Name "Group Policy Remote Update Firewall Ports" -ErrorAction Ignore))
        {
            Get-GPStarterGPO -Name "Group Policy Remote Update Firewall Ports" | New-GPO -Name "Group Policy Remote Update Firewall Ports" | New-GPLink -Target $AVDRootOU.DistinguishedName -LinkEnabled Yes -ErrorAction Ignore
        }
        #endregion
        #endregion
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
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "ProfileType" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 0

        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "PreventLoginWithFailure" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "PreventLoginWithTempProfile" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "VolumeType" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "VHDX"
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "LogFileKeepingPeriod" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 10
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "IsDynamic" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
        #From https://learn.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image#disable-automatic-updates
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueName "NoAutoUpdate" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
        #From https://learn.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image#set-up-time-zone-redirection
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "fEnableTimeZoneRedirection" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
        #From https://learn.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image#disable-storage-sense
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -ValueName "01" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0

        #region GPO Debug log file
        #From https://blog.piservices.fr/post/2017/12/21/active-directory-debug-avance-de-l-application-des-gpos
        Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics' -ValueName "GPSvcDebugLevel" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0x30002
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
        $CurrentPooledHostPoolKeyVaultNameMaxLength = 24

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

        #region Assigning the Desktop Virtualization Power On Contributor
        #From https://learn.microsoft.com/en-us/azure/virtual-desktop/start-virtual-machine-connect?tabs=azure-portal#assign-the-desktop-virtualization-power-on-contributor-role-with-the-azure-portal
        $objId = (Get-AzADServicePrincipal -AppId "9cdead84-a844-4324-93f2-b2e6bb768d07").Id
        $SubscriptionId = (Get-AzContext).Subscription.Id
        $Scope="/subscriptions/$SubscriptionId"
        if (-not(Get-AzRoleAssignment -RoleDefinitionName "Desktop Virtualization Power On Contributor" -Scope $Scope)) {
            New-AzRoleAssignment -RoleDefinitionName "Desktop Virtualization Power On Contributor" -ObjectId $objId -Scope $Scope
        }
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
            if (Get-Service -Name ADSync -ErrorAction Ignore)
            {
                Start-Service -Name ADSync -Verbose
                Import-Module -Name "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync"
                if (-not(Get-ADSyncConnectorRunStatus)) {
                    Start-ADSyncSyncCycle -PolicyType Delta
                }
            }
            Write-Verbose -Message "Sleeping 30 seconds ..."
            Start-Sleep -Seconds 30
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
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "FSLogixSharedFolderVHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHD"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "FSLogixSharedFolderVHDLock" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHD.lock"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "FSLogixSharedFolderVHDMeta" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHD.meta"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "FSLogixSharedFolderVHDMetaData" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHD.metadata"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "FSLogixSharedFolderVHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHDX"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "FSLogixSharedFolderVHDXLock" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHDX.lock"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "FSLogixSharedFolderVHDXMeta" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHDX.meta"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "FSLogixSharedFolderVHDXMetaData" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHDX.metadata"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "FSLogixSharedFolderCIM" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.CIM"
            #endregion

            #region GPO "Local Users and Groups" Management via groups.xml
            #From https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/37722b69-41dd-4813-8bcd-7a1b4d44a13d
            #From https://jans.cloud/2019/08/microsoft-fslogix-profile-container/
            $GroupXMLGPOFilePath = "\\{0}\SYSVOL\{0}\Policies\{{{1}}}\Machine\Preferences\Groups\Groups.xml" -f ($(Get-ADDomain).DNSRoot), $($CurrentPooledHostPoolFSLogixGPO.Id)
            #Generating an UTC time stamp
            $Changed = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
            #$ADGroupToExcludeFromFSLogix = @('Domain Admins', 'Enterprise Admins')
            $ADGroupToExcludeFromFSLogix = @('Domain Admins')
            $Members = foreach ($CurrentADGroupToExcludeFromFSLogix in $ADGroupToExcludeFromFSLogix)
            {
                $CurrentADGroupToExcludeFromFSLogixSID = (Get-ADGroup -Filter "Name -eq '$CurrentADGroupToExcludeFromFSLogix'").SID.Value
                if (-not([string]::IsNullOrEmpty($CurrentADGroupToExcludeFromFSLogixSID)))
                {
                    "<Member name=""$((Get-ADDomain).NetBIOSName)\$CurrentADGroupToExcludeFromFSLogix"" action=""ADD"" sid=""$CurrentADGroupToExcludeFromFSLogixSID""/>"
                }
            }
            $Members = $Members -join ""

            $GroupXMLGPOFileContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
	<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="FSLogix ODFC Exclude List" image="2" changed="$Changed" uid="{$((New-Guid).Guid.ToUpper())}"><Properties action="U" newName="" description="Members of this group are on the exclude list for Outlook Data Folder Containers" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="" groupName="FSLogix ODFC Exclude List"><Members>$Members</Members></Properties></Group>
	<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="FSLogix ODFC Include List" image="2" changed="$Changed" uid="{$((New-Guid).Guid.ToUpper())}"><Properties action="U" newName="" description="Members of this group are on the include list for Outlook Data Folder Containers" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupName="FSLogix ODFC Include List"/></Group>
	<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="FSLogix Profile Exclude List" image="2" changed="$Changed" uid="{$((New-Guid).Guid.ToUpper())}" userContext="0" removePolicy="0"><Properties action="U" newName="" description="Members of this group are on the exclude list for dynamic profiles" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="" groupName="FSLogix Profile Exclude List"><Members>$Members</Members></Properties></Group>
	<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="FSLogix Profile Include List" image="2" changed="$Changed" uid="{$((New-Guid).Guid.ToUpper())}"><Properties action="U" newName="" description="Members of this group are on the include list for dynamic profiles" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupName="FSLogix Profile Include List"/></Group>
</Groups>

"@

            
            $null = New-Item -Path $GroupXMLGPOFilePath -ItemType File -Value $GroupXMLGPOFileContent -Force
            <#
            Set-Content -Path $GroupXMLGPOFilePath -Value $GroupXMLGPOFileContent -Encoding UTF8
            $GroupXMLGPOFileContent | Out-File $GroupXMLGPOFilePath -Encoding utf8
            #>
            #endregion
        
            #region GPT.INI Management
            $GPTINIGPOFilePath = "\\{0}\SYSVOL\{0}\Policies\{{{1}}}\GPT.INI" -f ($(Get-ADDomain).DNSRoot), $($CurrentPooledHostPoolFSLogixGPO.Id)
            Write-Verbose -Message "Processing [$GPTINIGPOFilePath]"
            $result =  Select-string -Pattern "(Version)=(\d+)" -AllMatches -Path $GPTINIGPOFilePath
            #Getting current version
            [int]$VersionNumber = $result.Matches.Groups[-1].Value
            Write-Verbose -Message "Version Number: $VersionNumber"
            #Increasing current version
            $VersionNumber+=2
            Write-Verbose -Message "New Version Number: $VersionNumber"
            #Updating file
            (Get-Content $GPTINIGPOFilePath -Encoding UTF8) -replace "(Version)=(\d+)", "`$1=$VersionNumber" | Set-Content $GPTINIGPOFilePath -Encoding UTF8
            Write-Verbose -Message $(Get-Content $GPTINIGPOFilePath -Encoding UTF8 | Out-String)
            #endregion 

            #region gPCmachineExtensionNames Management
            #From https://www.infrastructureheroes.org/microsoft-infrastructure/microsoft-windows/guid-list-of-group-policy-client-extensions/
            #[{00000000-0000-0000-0000-000000000000}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}][{17D89FEC-5C44-4972-B12D-241CAEF74509}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}]
            #[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]
            $gPCmachineExtensionNamesToAdd = "[{00000000-0000-0000-0000-000000000000}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}][{17D89FEC-5C44-4972-B12D-241CAEF74509}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}]"
            $RegExPattern = $gPCmachineExtensionNamesToAdd -replace "(\W)" , '\$1'
            $GPOADObject = Get-ADObject -LDAPFilter "CN={$($CurrentPooledHostPoolFSLogixGPO.Id.Guid)}" -Properties gPCmachineExtensionNames
            #if (-not($GPOADObject.gPCmachineExtensionNames.StartsWith($gPCmachineExtensionNamesToAdd)))
            if ($GPOADObject.gPCmachineExtensionNames -notmatch $RegExPattern)
            {
                $GPOADObject | Set-ADObject -Replace @{gPCmachineExtensionNames=$($gPCmachineExtensionNamesToAdd + $GPOADObject.gPCmachineExtensionNames)}
                Get-ADObject -LDAPFilter "CN={$($CurrentPooledHostPoolFSLogixGPO.Id.Guid)}" -Properties gPCmachineExtensionNames
            }
            #endregion
            
            #endregion 

            #region Dedicated Resource Group Management (1 per HostPool)
            $CurrentPooledHostPoolResourceGroupName = "rg-avd-$($CurrentPooledHostPool.Name.ToLower())"

            $CurrentPooledHostPoolResourceGroup = Get-AzResourceGroup -Name $CurrentPooledHostPoolResourceGroupName -Location $CurrentPooledHostPool.Location -ErrorAction Ignore
            if (-not($CurrentPooledHostPoolResourceGroup)) {
                $CurrentPooledHostPoolResourceGroup = New-AzResourceGroup -Name $CurrentPooledHostPoolResourceGroupName -Location $CurrentPooledHostPool.Location -Force
            }
            #endregion

            #region Scale session hosts using Azure Automation
            #TODO : https://learn.microsoft.com/en-us/training/modules/automate-azure-virtual-desktop-management-tasks/1-introduction
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
                New-Item -Path Z: -Name "redirections.xml" -ItemType "file" -Value $RedirectionsXMLFileContent -Force
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
                $existingAcl | Set-Acl -Path Z:\redirections.xml
                #endregion

                # Unmount the share
                Remove-PSDrive -Name Z
                #endregion

                #region Run a sync with Azure AD
                if (Get-Service -Name ADSync -ErrorAction Ignore)
                {
                    Start-Service -Name ADSync -Verbose
                    Import-Module -Name "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync"
                    if (-not(Get-ADSyncConnectorRunStatus)) {
                        Start-ADSyncSyncCycle -PolicyType Delta
                    }
                }
                #endregion 

                #region RBAC Management
                #Constrain the scope to the target file share
                $AzContext = Get-AzContext
                $SubscriptionId = $AzContext.Subscription.Id
                $Scope = "/subscriptions/$SubscriptionId/resourceGroups/$CurrentPooledHostPoolResourceGroupName/providers/Microsoft.Storage/storageAccounts/$CurrentPooledHostPoolStorageAccountName/fileServices/default/fileshares/$CurrentPooledHostPoolShareName"

                #region Setting up the file share with right RBAC: FSLogix Contributor = "Storage File Data SMB Share Elevated Contributor"
                #Get the name of the custom role
                $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Contributor"
                #Assign the custom role to the target identity with the specified scope.
                Do 
                {
                    $AzADGroup = $null
                    $AzADGroup = Get-AzADGroup -SearchString $CurrentPooledHostPoolFSLogixContributorADGroupName
                    Write-Verbose -Message "Sleeping 10 seconds ..."
                    Start-Sleep -Seconds 10
                } While (-not($AzADGroup.Id))
                if (-not(Get-AzRoleAssignment -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                    New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                }
                #endregion

                #region Setting up the file share with right RBAC: FSLogix Elevated Contributor = "Storage File Data SMB Share Contributor"
                #Get the name of the custom role
                $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Elevated Contributor"
                #Assign the custom role to the target identity with the specified scope.
                Do 
                {
                    $AzADGroup = $null
                    $AzADGroup = Get-AzADGroup -SearchString $CurrentPooledHostPoolFSLogixElevatedContributorADGroupName
                    Write-Verbose -Message "Sleeping 10 seconds ..."
                    Start-Sleep -Seconds 10
                } While (-not($AzADGroup.Id))

                if (-not(Get-AzRoleAssignment -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                    New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                }
                #endregion

                #region Setting up the file share with right RBAC: FSLogix Reader = "Storage File Data SMB Share Reader"
                #Get the name of the custom role
                $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Reader"
                #Assign the custom role to the target identity with the specified scope.
                Do 
                {
                    $AzADGroup = $null
                    $AzADGroup = Get-AzADGroup -SearchString $CurrentPooledHostPoolFSLogixReaderADGroupName
                    Write-Verbose -Message "Sleeping 10 seconds ..."
                    Start-Sleep -Seconds 10
                } While (-not($AzADGroup.Id))
                if (-not(Get-AzRoleAssignment -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                    New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                }
                #endregion

                #endregion
            }
            #endregion
            #endregion
            #endregion

            #endregion

            #region MSIX

            #region MSIX AD Management
            #region Dedicated HostPool AD group

            #region Dedicated HostPool AD FSLogix groups
            $CurrentPooledHostPoolMSIXHostsADGroupName = "$($CurrentPooledHostPool.Name) - $MSIXHosts"
            $CurrentPooledHostPoolMSIXHostsADGroupName
            $CurrentPooledHostPoolMSIXHostsADGroup = Get-ADGroup -Filter "Name -eq '$CurrentPooledHostPoolMSIXHostsADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentPooledHostPoolOU.DistinguishedName
            if (-not($CurrentPooledHostPoolMSIXHostsADGroup)) {
                $CurrentPooledHostPoolMSIXHostsADGroup = New-ADGroup -Name $CurrentPooledHostPoolMSIXHostsADGroupName -SamAccountName $CurrentPooledHostPoolMSIXHostsADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentPooledHostPoolMSIXHostsADGroupName -Path $CurrentPooledHostPoolOU.DistinguishedName -PassThru
            }
            #$CurrentPooledHostPoolMSIXHostsADGroup | Add-ADGroupMember -Members $CurrentPooledHostPoolUsersADGroupName

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
            if (Get-Service -Name ADSync -ErrorAction Ignore)
            {
                Start-Service -Name ADSync -Verbose
                Import-Module -Name "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync"
                if (-not(Get-ADSyncConnectorRunStatus)) {
                    Start-ADSyncSyncCycle -PolicyType Delta
                }
            }
            #endregion 
            #endregion 

            #region MSIX Storage Account Management
            #region MSIX Storage Account Name Setup
            $CurrentPooledHostPoolStorageAccountName = "msix{0}" -f $($CurrentPooledHostPool.Name -replace "\W")
            $CurrentPooledHostPoolStorageAccountName = $CurrentPooledHostPoolStorageAccountName.Substring(0, [system.math]::min($CurrentPooledHostPoolStorageAccountNameMaxLength, $CurrentPooledHostPoolStorageAccountName.Length)).ToLower()
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
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "MSixSharedFolderVHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHD"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "MSixSharedFolderVHDLock" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHD.lock"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "MSixSharedFolderVHDMeta" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHD.meta"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "MSixSharedFolderVHDMetaData" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHD.metadata"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "MSixSharedFolderVHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHDX"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "MSixSharedFolderVHDXLock" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHDX.lock"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "MSixSharedFolderVHDXMeta" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHDX.meta"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "MSixSharedFolderVHDXMetaData" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHDX.metadata"
            Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "MSixSharedFolderCIM" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.CIM"
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
                $Scope = "/subscriptions/$SubscriptionId/resourceGroups/$CurrentPooledHostPoolResourceGroupName/providers/Microsoft.Storage/storageAccounts/$CurrentPooledHostPoolStorageAccountName/fileServices/default/fileshares/$CurrentPooledHostPoolShareName"

                #region Setting up the file share with right RBAC: MSIX Hosts & MSIX Users = "Storage File Data SMB Share Contributor" + MSIX Share Admins = Storage File Data SMB Share Elevated Contributor
                #https://docs.microsoft.com/en-us/azure/virtual-desktop/app-attach-file-share#how-to-set-up-the-file-share
                #Get the name of the custom role
                $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Contributor"
                #Assign the custom role to the target identity with the specified scope.
                Do 
                {
                    $AzADGroup = $null
                    $AzADGroup = Get-AzADGroup -SearchString $CurrentPooledHostPoolMSIXHostsADGroupName
                    Write-Verbose -Message "Sleeping 10 seconds ..."
                    Start-Sleep -Seconds 10
                } While (-not($AzADGroup.Id))
                if (-not(Get-AzRoleAssignment -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                    New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                }
                #Assign the custom role to the target identity with the specified scope.
                Do 
                {
                    $AzADGroup = $null
                    $AzADGroup = Get-AzADGroup -SearchString $CurrentPooledHostPoolMSIXUsersADGroupName
                    Write-Verbose -Message "Sleeping 10 seconds ..."
                    Start-Sleep -Seconds 10
                } While (-not($AzADGroup.Id))
                if (-not(Get-AzRoleAssignment -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                    New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                }
                #endregion

                #region Setting up the file share with right RBAC: FSLogix Elevated Contributor = "Storage File Data SMB Share Contributor"
                #Get the name of the custom role
                $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Elevated Contributor"
                #Assign the custom role to the target identity with the specified scope.
                Do 
                {
                    $AzADGroup = $null
                    $AzADGroup = Get-AzADGroup -SearchString $CurrentPooledHostPoolMSIXShareAdminsADGroupName
                    Write-Verbose -Message "Sleeping 10 seconds ..."
                    Start-Sleep -Seconds 10
                } While (-not($AzADGroup.Id))
                if (-not(Get-AzRoleAssignment -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                    New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                }
                #endregion

                #endregion
            }
            #endregion

            #endregion

            #region Key Vault
            #region Key Vault Name Setup
            $CurrentPooledHostPoolKeyVaultName = "kv{0}" -f $($CurrentPooledHostPool.Name -replace "\W")
            $CurrentPooledHostPoolKeyVaultName = $CurrentPooledHostPoolKeyVaultName.Substring(0, [system.math]::min($CurrentPooledHostPoolKeyVaultNameMaxLength, $CurrentPooledHostPoolKeyVaultName.Length)).ToLower()
            #endregion 

            #region Dedicated Resource Group Management (1 per HostPool)
            $CurrentPooledHostPoolResourceGroupName = "rg-avd-$($CurrentPooledHostPool.Name.ToLower())"

            $CurrentPooledHostPoolResourceGroup = Get-AzResourceGroup -Name $CurrentPooledHostPoolResourceGroupName -Location $CurrentPooledHostPool.Location -ErrorAction Ignore
            if (-not($CurrentPooledHostPoolResourceGroup)) {
                $CurrentPooledHostPoolResourceGroup = New-AzResourceGroup -Name $CurrentPooledHostPoolResourceGroupName -Location $CurrentPooledHostPool.Location -Force
            }
            #endregion

            #region Dedicated Key Vault Setup
            $CurrentPooledHostPoolKeyVault = Get-AzKeyVault -VaultName $CurrentPooledHostPoolKeyVaultName -ErrorAction Ignore
            if (-not($CurrentPooledHostPoolKeyVault)) {
                if (-not(Get-AzKeyVaultNameAvailability -Name $CurrentPooledHostPoolKeyVaultName).NameAvailable) {
                    Write-Error "The key vault name '$CurrentPooledHostPoolKeyVaultName' is not available !" -ErrorAction Stop
                }
                $CurrentPooledHostPoolKeyVault = New-AzKeyVault -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -VaultName $CurrentPooledHostPoolKeyVaultName -Location $CurrentPooledHostPool.Location -EnabledForDiskEncryption
            }
            #endregion
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

            #region Desktop Application Group Setup
            $parameters = @{
                Name                 = "{0}-DAG" -f $CurrentPooledHostPool.Name
                ResourceGroupName    = $CurrentPooledHostPoolResourceGroupName
                Location             = $CurrentPooledHostPool.Location
                HostPoolArmPath      = $CurrentAzWvdHostPool.Id
                ApplicationGroupType = 'Desktop'
            }

            $CurrentAzDesktopApplicationGroup = New-AzWvdApplicationGroup @parameters

            #region Assign groups to an application group
            # Get the object ID of the user group you want to assign to the application group
            Do 
            {
                $AzADGroup = $null
                $AzADGroup = Get-AzADGroup -DisplayName $CurrentPooledHostPoolUsersADGroupName
                Write-Verbose -Message "Sleeping 10 seconds ..."
                Start-Sleep -Seconds 10
            } While (-not($AzADGroup.Id))

            # Assign users to the application group
            $parameters = @{
                ObjectId           = $AzADGroup.Id
                ResourceName       = $CurrentAzDesktopApplicationGroup.Name
                ResourceGroupName  = $CurrentPooledHostPoolResourceGroupName
                RoleDefinitionName = 'Desktop Virtualization User'
                ResourceType       = 'Microsoft.DesktopVirtualization/applicationGroups'
            }

            New-AzRoleAssignment @parameters
            #endregion 

            #endregion

            #region Remote Application Group Setup
            $parameters = @{
                Name                 = "{0}-RAG" -f $CurrentPooledHostPool.Name
                ResourceGroupName    = $CurrentPooledHostPoolResourceGroupName
                Location             = $CurrentPooledHostPool.Location
                HostPoolArmPath      = $CurrentAzWvdHostPool.Id
                ApplicationGroupType = 'RemoteApp'
            }

            $CurrentAzRemoteApplicationGroup = New-AzWvdApplicationGroup @parameters

            <#
            #region Adding Some Remote Apps
            $RemoteApps = "Edge","Excel"
            $FilteredAzWvdStartMenuItem = (Get-AzWvdStartMenuItem -ApplicationGroupName $CurrentAzRemoteApplicationGroup.Name -ResourceGroupName $CurrentPooledHostPoolResourceGroupName | Where-Object -FilterScript {$_.Name -match $($RemoteApps -join '|')} | Select-Object -Property *)

            foreach($CurrentFilteredAppAlias in $FilteredAzWvdStartMenuItem)
            {
                #$Name = $CurrentFilteredAppAlias.Name -replace "(.*)/"
                $Name = $CurrentFilteredAppAlias.Name -replace "$($CurrentAzRemoteApplicationGroup.Name)/"
                New-AzWvdApplication -AppAlias $CurrentFilteredAppAlias.appAlias -GroupName $CurrentAzRemoteApplicationGroup.Name -Name $Name -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -CommandLineSetting DoNotAllow
            }
            #endregion
            #>

            #region Assign groups to an application group
            # Get the object ID of the user group you want to assign to the application group
            Do 
            {
                $AzADGroup = $null
                $AzADGroup = Get-AzADGroup -DisplayName $CurrentPooledHostPoolUsersADGroupName
                Write-Verbose -Message "Sleeping 10 seconds ..."
                Start-Sleep -Seconds 10
            } While (-not($AzADGroup.Id))

            # Assign users to the application group
            $parameters = @{
                ObjectId           = $AzADGroup.Id
                ResourceName       = $CurrentAzRemoteApplicationGroup.Name
                ResourceGroupName  = $CurrentPooledHostPoolResourceGroupName
                RoleDefinitionName = 'Desktop Virtualization User'
                ResourceType       = 'Microsoft.DesktopVirtualization/applicationGroups'
            }

            New-AzRoleAssignment @parameters
            #endregion 

            #endregion

            #region Workspace Setup
            $parameters = @{
                Name                      = "ws-{0}" -f $CurrentPooledHostPool.Name
                ResourceGroupName         = $CurrentPooledHostPoolResourceGroupName
                ApplicationGroupReference = $CurrentAzRemoteApplicationGroup.Id, $CurrentAzDesktopApplicationGroup.Id
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
$RequiredModules = 'Az.Accounts', 'Az.DesktopVirtualization', 'Az.Network', 'Az.KeyVault', 'Az.Resources', 'Az.Storage', 'PowerShellGet'
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

#region Azure Provider Registration
#To use Azure Virtual Desktop, you have to register for the providers and to ensure that RegistrationState will be set to Registered.
Register-AzResourceProvider -ProviderNamespace Microsoft.DesktopVirtualization

#Important: Wait until RegistrationState is set to Registered. 
While (Get-AzResourceProvider -ProviderNamespace Microsoft.DesktopVirtualization | Where-Object -FilterScript {$_.RegistrationState -ne 'Registered'})
{
    Write-Verbose -Message "Sleeping 10 seconds ..."
    Start-Sleep -Seconds 10
}
#endregion

#region Azure Connection
if (-not(Get-AzContext))
{
    Connect-AzAccount
    Get-AzSubscription | Out-GridView -OutputMode Single | Select-AzSubscription
}
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
    [PSCustomObject]@{Name="hp-ad-helpdesk-eu-001"; Location="EastUS"; MaxSessionLimit=5}
    [PSCustomObject]@{Name="hp-ad-helpdesk-eu-002"; Location="EastUS"; MaxSessionLimit=5}
    [PSCustomObject]@{Name="hp-ad-helpdesk-eu-003"; Location="EastUS"; MaxSessionLimit=5}
)
#>

$PooledHostPools = 1..3 | ForEach-Object -Process {
    [PSCustomObject]@{Name = $("hp-ad-helpdesk-eu-{0:D3}" -f $_); Location = "EastUS"; MaxSessionLimit = 5 }
}
#Uncomment the following block to remove all previously existing resources

<#
#region Cleanup of the previously existing resources
#region DNS Cleanup
(Get-ADOrganizationalUnit -Filter * | Where-Object -FilterScript {$_.Name -in $($PooledHostPools.Name)}).DistinguishedName | ForEach-Object -Process {(Get-ADComputer -Filter 'DNSHostName -like "*"' -SearchBase $_).Name } | ForEach-Object -Process { try {Remove-DnsServerResourceRecord -ZoneName $((Get-ADDomain).DNSRoot) -RRType "A" -Name "$_" -Force -Verbose -ErrorAction Ignore} catch {} }
#endregion
#region AD OU/GPO Cleanup
Get-ADOrganizationalUnit -Filter * | Where-Object -FilterScript {$_.Name -in $($PooledHostPools.Name) -or $_.Name -in 'AVD', 'PooledDesktops', 'PersonalDesktops'} | Set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $false -PassThru -ErrorAction Ignore | Remove-ADOrganizationalUnit -Recursive -Confirm:$false -Verbose #-WhatIf
Get-GPO -All | Where-Object -FilterScript {($_.DisplayName -match $($PooledHostPools.Name -join "|")) -or ($_.DisplayName -in 'AVD - Global Settings', 'PooledDesktops - FSLogix Global Settings', 'Group Policy Reporting Firewall Ports', 'Group Policy Remote Update Firewall Ports')} | Remove-GPO -Verbose #-WhatIf
#endregion
#region Azure Cleanup
$HP = (Get-AzWvdHostPool | Where-Object -FilterScript {$_.Name -in $($PooledHostPools.Name)})
$RG = $HP | ForEach-Object { Get-AzResourceGroup $_.Id.split('/')[4]}
$RG | Remove-AzResourceGroup -WhatIf
$RG | Foreach-Object -Process {Get-AzResourceLock -ResourceGroupName $_.ResourceGroupName -AtScope | Where-Object -FilterScript {$_.Properties.level -eq 'CanNotDelete'}} | Remove-AzResourceLock -Force -Verbose -ErrorAction Ignore

$Jobs = $RG | Remove-AzResourceGroup -Force -AsJob -Verbose
$Jobs | Wait-Job
$Jobs | Remove-Job

#region
#Removing Dedicated HostPool Key vault in removed state
$Jobs = Get-AzKeyVault -InRemovedState | Where-Object -FilterScript {($_.VaultName -match $($(($PooledHostPools.Name -replace "\W").ToLower()) -join "|"))} | Remove-AzKeyVault -InRemovedState -AsJob -Force -Verbose 
$Jobs | Wait-Job
$Jobs | Remove-Job
#endregion
#endregion
#region Run a sync with Azure AD
if (Get-Service -Name ADSync -ErrorAction Ignore)
{
    Start-Service -Name ADSync -Verbose
    Import-Module -Name "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync"
    if (-not(Get-ADSyncConnectorRunStatus)) {
        Start-ADSyncSyncCycle -PolicyType Delta
    }
}
#endregion 
#endregion 
#>

New-AzWvdPooledHostPoolSetup -PooledHostPool $PooledHostPools -Verbose
#Or pipeline processing call
#$PooledHostPools | New-AzWvdPooledHostPoolSetup 
#(Get-ADComputer -Filter 'DNSHostName -like "*"').Name | Invoke-GPUpdate -Force -Verbose
Invoke-Command -ComputerName $((Get-ADComputer -Filter 'DNSHostName -like "*"').Name) -ScriptBlock { gpupdate /force /wait:-1 /target:computer} 
Invoke-Command -ComputerName $((Get-ADComputer -Filter 'DNSHostName -like "*"').Name) -ScriptBlock { Get-LocalGroupMember -Group "FSLogix Profile Exclude List" -ErrorAction Ignore}
#endregion
#endregion