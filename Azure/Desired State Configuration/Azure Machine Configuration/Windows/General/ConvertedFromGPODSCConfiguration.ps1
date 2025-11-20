<#
This Sample Code is provided for the purpose of illustration only
and is not intended to be used in a production environment.  THIS
SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
# WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
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

Configuration ConvertedFromGPODSCConfiguration {

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'
	Node $AllNodes.NodeName
	{
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators'
         {
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI'
              ValueName = 'EnumerateAdministrators'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoWebServices'
         {
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueName = 'NoWebServices'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun'
         {
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueName = 'NoDriveTypeAutoRun'
              ValueData = 255
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun'
         {
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueName = 'NoAutorun'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\PreXPSP2ShellProtocolBehavior'
         {
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueName = 'PreXPSP2ShellProtocolBehavior'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'DEL_\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableBkGndGroupPolicy'
         {
              Ensure = 'Absent'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
              ValueName = 'DisableBkGndGroupPolicy'
              ValueData = ''
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional'
         {
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
              ValueName = 'MSAOptional'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn'
         {
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
              ValueName = 'DisableAutomaticRestartSignOn'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy'
         {
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
              ValueName = 'LocalAccountTokenFilterPolicy'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled'
         {
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
              ValueName = 'ProcessCreationIncludeCmdLine_Enabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters\AllowEncryptionOracle'
         {
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters'
              ValueName = 'AllowEncryptionOracle'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon'
         {
              Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
              ValueName = 'AutoAdminLogon'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScreenSaverGracePeriod'
         {
              Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
              ValueName = 'ScreenSaverGracePeriod'
              ValueData = '5'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Biometrics\FacialFeatures\EnhancedAntiSpoofing'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Biometrics\FacialFeatures'
              ValueName = 'EnhancedAntiSpoofing'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\InputPersonalization\AllowInputPersonalization'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\InputPersonalization'
              ValueName = 'AllowInputPersonalization'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds'
              ValueName = 'DisableEnclosureDownload'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\MicrosoftAccount\DisableUserAuth'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\MicrosoftAccount'
              ValueName = 'DisableUserAuth'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
              ValueName = 'ACSettingIndex'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
              ValueName = 'DCSettingIndex'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CloudContent\DisableWindowsConsumerFeatures'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CloudContent'
              ValueName = 'DisableWindowsConsumerFeatures'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Connect\RequirePinForPairing'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Connect'
              ValueName = 'RequirePinForPairing'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowProtectedCreds'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation'
              ValueName = 'AllowProtectedCreds'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CredUI\DisablePasswordReveal'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CredUI'
              ValueName = 'DisablePasswordReveal'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DataCollection\AllowTelemetry'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\DataCollection'
              ValueName = 'AllowTelemetry'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DataCollection\DoNotShowFeedbackNotifications'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\DataCollection'
              ValueName = 'DoNotShowFeedbackNotifications'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DataCollection\EnableOneSettingsAuditing'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\DataCollection'
              ValueName = 'EnableOneSettingsAuditing'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DataCollection\LimitDiagnosticLogCollection'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\DataCollection'
              ValueName = 'LimitDiagnosticLogCollection'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DataCollection\LimitDumpCollection'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\DataCollection'
              ValueName = 'LimitDumpCollection'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Device Metadata\PreventDeviceMetadataFromNetwork'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Device Metadata'
              ValueName = 'PreventDeviceMetadataFromNetwork'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application'
              ValueName = 'MaxSize'
              ValueData = 32768
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\Retention'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application'
              ValueName = 'Retention'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security\MaxSize'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'
              ValueName = 'MaxSize'
              ValueData = 196608
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security\Retention'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'
              ValueName = 'Retention'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup\MaxSize'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup'
              ValueName = 'MaxSize'
              ValueData = 32768
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup\Retention'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup'
              ValueName = 'Retention'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\System\Retention'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\System'
              ValueName = 'Retention'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\System\MaxSize'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\System'
              ValueName = 'MaxSize'
              ValueData = 32768
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer'
              ValueName = 'NoAutoplayfornonVolume'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer'
              ValueName = 'NoDataExecutionPrevention'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoHeapTerminationOnCorruption'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer'
              ValueName = 'NoHeapTerminationOnCorruption'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
              ValueName = 'NoBackgroundPolicy'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
              ValueName = 'NoGPOListChanges'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\EnableUserControl'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Installer'
              ValueName = 'EnableUserControl'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Installer'
              ValueName = 'AlwaysInstallElevated'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection\DeviceEnumerationPolicy'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection'
              ValueName = 'DeviceEnumerationPolicy'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation'
              ValueName = 'AllowInsecureGuestAuth'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Network Connections\NC_AllowNetBridge_NLA'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Network Connections'
              ValueName = 'NC_AllowNetBridge_NLA'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Network Connections\NC_ShowSharedAccessUI'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Network Connections'
              ValueName = 'NC_ShowSharedAccessUI'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Network Connections\NC_StdDomainUserSetLocation'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Network Connections'
              ValueName = 'NC_StdDomainUserSetLocation'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\NETLOGON'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
              ValueName = '\\*\NETLOGON'
              ValueData = 'RequireMutualAuthentication=1, RequireIntegrity=1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\SYSVOL'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
              ValueName = '\\*\SYSVOL'
              ValueData = 'RequireMutualAuthentication=1, RequireIntegrity=1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\OneDrive\DisableFileSyncNGSC'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\OneDrive'
              ValueName = 'DisableFileSyncNGSC'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
              ValueName = 'EnableScriptBlockLogging'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging'
         {
              Ensure = 'Absent'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
              ValueName = 'EnableScriptBlockInvocationLogging'
              ValueData = ''
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription'
              ValueName = 'EnableTranscripting'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\PowerShell\Transcription\OutputDirectory'
         {
              Ensure = 'Absent'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription'
              ValueName = 'OutputDirectory'
              ValueData = ''
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\PowerShell\Transcription\EnableInvocationHeader'
         {
              Ensure = 'Absent'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription'
              ValueName = 'EnableInvocationHeader'
              ValueData = ''
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds\AllowBuildPreview'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds'
              ValueName = 'AllowBuildPreview'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\EnableCdp'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
              ValueName = 'EnableCdp'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\AllowDomainPINLogon'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
              ValueName = 'AllowDomainPINLogon'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\BlockDomainPicturePassword'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
              ValueName = 'BlockDomainPicturePassword'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\BlockUserFromShowingAccountDetailsOnSignin'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
              ValueName = 'BlockUserFromShowingAccountDetailsOnSignin'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\DisableLockScreenAppNotifications'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
              ValueName = 'DisableLockScreenAppNotifications'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
              ValueName = 'DontDisplayNetworkSelectionUI'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\DontEnumerateConnectedUsers'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
              ValueName = 'DontEnumerateConnectedUsers'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\EnumerateLocalUsers'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
              ValueName = 'EnumerateLocalUsers'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fMinimizeConnections'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
              ValueName = 'fMinimizeConnections'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search'
              ValueName = 'AllowIndexingEncryptedStoresOrItems'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\DeferFeatureUpdates'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
              ValueName = 'DeferFeatureUpdates'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\DeferFeatureUpdatesPeriodInDays'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
              ValueName = 'DeferFeatureUpdatesPeriodInDays'
              ValueData = 180
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\PauseFeatureUpdatesStartTime'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
              ValueName = 'PauseFeatureUpdatesStartTime'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\DeferQualityUpdates'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
              ValueName = 'DeferQualityUpdates'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\DeferQualityUpdatesPeriodInDays'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
              ValueName = 'DeferQualityUpdatesPeriodInDays'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\PauseQualityUpdatesStartTime'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
              ValueName = 'PauseQualityUpdatesStartTime'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\ManagePreviewBuilds'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
              ValueName = 'ManagePreviewBuilds'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\ManagePreviewBuildsPolicyValue'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
              ValueName = 'ManagePreviewBuildsPolicyValue'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\BranchReadinessLevel'
         {
              Ensure = 'Absent'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
              ValueName = 'BranchReadinessLevel'
              ValueData = ''
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\WUServer'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
              ValueName = 'WUServer'
              ValueData = 'http://france.wsus.project.corp.ssg:8530'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\WUStatusServer'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
              ValueName = 'WUStatusServer'
              ValueData = 'http://france.wsus.project.corp.ssg:8530'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\UpdateServiceUrlAlternate'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
              ValueName = 'UpdateServiceUrlAlternate'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\FillEmptyContentUrls'
         {
              Ensure = 'Absent'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
              ValueName = 'FillEmptyContentUrls'
              ValueData = ''
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\DoNotEnforceEnterpriseTLSCertPinningForUpdateDetection'
         {
              Ensure = 'Absent'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
              ValueName = 'DoNotEnforceEnterpriseTLSCertPinningForUpdateDetection'
              ValueData = ''
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\SetProxyBehaviorForUpdateDetection'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
              ValueName = 'SetProxyBehaviorForUpdateDetection'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\DoNotConnectToWindowsUpdateInternetLocations'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
              ValueName = 'DoNotConnectToWindowsUpdateInternetLocations'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\DisableDualScan'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
              ValueName = 'DisableDualScan'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\TargetGroupEnabled'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
              ValueName = 'TargetGroupEnabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\TargetGroup'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
              ValueName = 'TargetGroup'
              ValueData = 'Week 3'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoRebootWithLoggedOnUsers'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
              ValueName = 'NoAutoRebootWithLoggedOnUsers'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\AlwaysAutoRebootAtScheduledTime'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
              ValueName = 'AlwaysAutoRebootAtScheduledTime'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\AlwaysAutoRebootAtScheduledTimeMinutes'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
              ValueName = 'AlwaysAutoRebootAtScheduledTimeMinutes'
              ValueData = 15
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
              ValueName = 'NoAutoUpdate'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\AUOptions'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
              ValueName = 'AUOptions'
              ValueData = 4
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\AutomaticMaintenanceEnabled'
         {
              Ensure = 'Absent'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
              ValueName = 'AutomaticMaintenanceEnabled'
              ValueData = ''
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallDay'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
              ValueName = 'ScheduledInstallDay'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallTime'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
              ValueName = 'ScheduledInstallTime'
              ValueData = 12
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallEveryWeek'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
              ValueName = 'ScheduledInstallEveryWeek'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallFirstWeek'
         {
              Ensure = 'Absent'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
              ValueName = 'ScheduledInstallFirstWeek'
              ValueData = ''
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallSecondWeek'
         {
              Ensure = 'Absent'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
              ValueName = 'ScheduledInstallSecondWeek'
              ValueData = ''
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallThirdWeek'
         {
              Ensure = 'Absent'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
              ValueName = 'ScheduledInstallThirdWeek'
              ValueData = ''
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallFourthWeek'
         {
              Ensure = 'Absent'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
              ValueName = 'ScheduledInstallFourthWeek'
              ValueData = ''
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\AllowMUUpdateService'
         {
              Ensure = 'Absent'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
              ValueName = 'AllowMUUpdateService'
              ValueData = ''
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\UseWUServer'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
              ValueName = 'UseWUServer'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\DetectionFrequencyEnabled'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
              ValueName = 'DetectionFrequencyEnabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\DetectionFrequency'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
              ValueName = 'DetectionFrequency'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\RescheduleWaitTimeEnabled'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
              ValueName = 'RescheduleWaitTimeEnabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\RescheduleWaitTime'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
              ValueName = 'RescheduleWaitTime'
              ValueData = 5
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowBasic'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'
              ValueName = 'AllowBasic'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'
              ValueName = 'AllowUnencryptedTraffic'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowDigest'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'
              ValueName = 'AllowDigest'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowBasic'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
              ValueName = 'AllowBasic'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
              ValueName = 'AllowUnencryptedTraffic'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\DisableRunAs'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
              ValueName = 'DisableRunAs'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\PUAProtection'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender'
              ValueName = 'PUAProtection'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\DisableAntiSpyware'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender'
              ValueName = 'DisableAntiSpyware'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Exclusions_Paths'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions'
              ValueName = 'Exclusions_Paths'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Exclusions_Processes'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions'
              ValueName = 'Exclusions_Processes'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths\D:\Microsoft Configuration Manager\inboxes'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths'
              ValueName = 'D:\Microsoft Configuration Manager\inboxes'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths\D:\Microsoft Configuration Manager'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths'
              ValueName = 'D:\Microsoft Configuration Manager'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths\%programfiles%\FireEye\xagt'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths'
              ValueName = '%programfiles%\FireEye\xagt'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths\%programfiles(x86)%\FireEye\xagt'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths'
              ValueName = '%programfiles(x86)%\FireEye\xagt'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths\%systemroot%\FireEye'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths'
              ValueName = '%systemroot%\FireEye'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths\%systemroot%\System32\drivers\FeKern.sys'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths'
              ValueName = '%systemroot%\System32\drivers\FeKern.sys'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths\%programdata%\FireEye\xagt'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths'
              ValueName = '%programdata%\FireEye\xagt'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths\%allusersprofile%\ApplicationData\FireEye\xagt\exts'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths'
              ValueName = '%allusersprofile%\ApplicationData\FireEye\xagt\exts'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths\%programfiles(x86)%\Trend Micro\iService\iAC'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths'
              ValueName = '%programfiles(x86)%\Trend Micro\iService\iAC'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths\%programfiles(x86)%\Trend Micro\iService\iVP'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths'
              ValueName = '%programfiles(x86)%\Trend Micro\iService\iVP'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths\%programfiles(x86)%\Trend Micro\Endpoint Basecamp'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths'
              ValueName = '%programfiles(x86)%\Trend Micro\Endpoint Basecamp'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths\%programfiles(x86)%\Trend Micro\Security Agent'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths'
              ValueName = '%programfiles(x86)%\Trend Micro\Security Agent'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths\%programfiles(x86)%\Trend Micro\OfficeScan Client'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths'
              ValueName = '%programfiles(x86)%\Trend Micro\OfficeScan Client'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths\%programfiles(x86)%\Trend Micro\OfficeScan Client\Temp'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths'
              ValueName = '%programfiles(x86)%\Trend Micro\OfficeScan Client\Temp'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths\%programfiles(x86)%\Trend Micro\Security Agent\Temp'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths'
              ValueName = '%programfiles(x86)%\Trend Micro\Security Agent\Temp'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles%\FireEye\xagt\xagt.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles%\FireEye\xagt\xagt.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\FireEye\xagt\xagt.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\FireEye\xagt\xagt.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%systemroot%\FireEye\xagtnotif.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%systemroot%\FireEye\xagtnotif.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\OfficeScan Client\Ntrtscan.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\OfficeScan Client\Ntrtscan.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\OfficeScan Client\TmListen.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\OfficeScan Client\TmListen.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\OfficeScan Client\CNTAoSMgr.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\OfficeScan Client\CNTAoSMgr.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\OfficeScan Client\patch64.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\OfficeScan Client\patch64.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\OfficeScan Client\PccNt.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\OfficeScan Client\PccNt.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\OfficeScan Client\PccNTMon.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\OfficeScan Client\PccNTMon.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\OfficeScan Client\PccNTUpd.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\OfficeScan Client\PccNTUpd.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\OfficeScan Client\TmExtIns.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\OfficeScan Client\TmExtIns.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\OfficeScan Client\TmExtIns32.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\OfficeScan Client\TmExtIns32.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\OfficeScan Client\TmPfw.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\OfficeScan Client\TmPfw.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\OfficeScan Client\upgrade.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\OfficeScan Client\upgrade.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\OfficeScan Client\Misc\xpupg.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\OfficeScan Client\Misc\xpupg.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\OfficeScan Client\CCSF\TmCCSF.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\OfficeScan Client\CCSF\TmCCSF.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\Security Agent\Ntrtscan.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\Security Agent\Ntrtscan.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\Security Agent\TmListen.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\Security Agent\TmListen.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\Security Agent\CNTAoSMgr.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\Security Agent\CNTAoSMgr.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\Security Agent\patch64.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\Security Agent\patch64.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\Security Agent\PccNt.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\Security Agent\PccNt.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\Security Agent\PccNTMon.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\Security Agent\PccNTMon.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\Security Agent\PccNTUpd.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\Security Agent\PccNTUpd.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\Security Agent\TmExtIns.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\Security Agent\TmExtIns.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\Security Agent\TmExtIns32.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\Security Agent\TmExtIns32.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\Security Agent\TmPfw.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\Security Agent\TmPfw.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\Security Agent\upgrade.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\Security Agent\upgrade.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\Security Agent\Misc\xpupg.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\Security Agent\Misc\xpupg.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\Security Agent\CCSF\TmCCSF.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\Security Agent\CCSF\TmCCSF.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\BM\TMBMSRV.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\BM\TMBMSRV.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\iService\iAC\ac_bin\iac-rulemapping-builder.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\iService\iAC\ac_bin\iac-rulemapping-builder.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\iService\iAC\ac_bin\iac-ruledata-builder.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\iService\iAC\ac_bin\iac-ruledata-builder.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\iService\iAC\ac_bin\iac-sodata-reader.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\iService\iAC\ac_bin\iac-sodata-reader.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\iService\iAC\ac_bin\iac-source-builder.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\iService\iAC\ac_bin\iac-source-builder.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\iService\iAC\ac_bin\PolicyUpdater.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\iService\iAC\ac_bin\PolicyUpdater.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\iService\iAC\ac_bin\TMiACAgentSvc.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\iService\iAC\ac_bin\TMiACAgentSvc.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\iService\iAC\ac_bin\TMiACHashGen.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\iService\iAC\ac_bin\TMiACHashGen.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\iService\iVP\dsc.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\iService\iVP\dsc.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\iService\iVP\iVPAgent.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\iService\iVP\iVPAgent.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes\%programfiles(x86)%\Trend Micro\Endpoint Basecamp\EndpointBasecamp.exe'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
              ValueName = '%programfiles(x86)%\Trend Micro\Endpoint Basecamp\EndpointBasecamp.exe'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableBehaviorMonitoring'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
              ValueName = 'DisableBehaviorMonitoring'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableIOAVProtection'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
              ValueName = 'DisableIOAVProtection'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
              ValueName = 'DisableRealtimeMonitoring'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableScriptScanning'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
              ValueName = 'DisableScriptScanning'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\DisableEmailScanning'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
              ValueName = 'DisableEmailScanning'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\DisableRemovableDriveScanning'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
              ValueName = 'DisableRemovableDriveScanning'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\LocalSettingOverrideSpynetReporting'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
              ValueName = 'LocalSettingOverrideSpynetReporting'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\EnableNetworkProtection'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
              ValueName = 'EnableNetworkProtection'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender Security Center\App and Browser protection\DisallowExploitProtectionOverride'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender Security Center\App and Browser protection'
              ValueName = 'DisallowExploitProtectionOverride'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24\Category'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24'
              ValueName = 'Category'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0020000000F0000F0ABA0226144020107D469B778399BF3083A7EBB37586084F5B7A71A633E24B5AF\Category'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0020000000F0000F0ABA0226144020107D469B778399BF3083A7EBB37586084F5B7A71A633E24B5AF'
              ValueName = 'Category'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient'
              ValueName = 'EnableMulticast'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient\DoHPolicy'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient'
              ValueName = 'DoHPolicy'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers'
              ValueName = 'DisableWebPnPDownload'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\EnableAuthEpResolution'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Rpc'
              ValueName = 'EnableAuthEpResolution'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueName = 'fAllowToGetHelp'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows NT\Terminal Services\fAllowFullControl'
         {
              Ensure = 'Absent'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueName = 'fAllowFullControl'
              ValueData = ''
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiry'
         {
              Ensure = 'Absent'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueName = 'MaxTicketExpiry'
              ValueData = ''
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiryUnits'
         {
              Ensure = 'Absent'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueName = 'MaxTicketExpiryUnits'
              ValueData = ''
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows NT\Terminal Services\fUseMailto'
         {
              Ensure = 'Absent'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueName = 'fUseMailto'
              ValueData = ''
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicited'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueName = 'fAllowUnsolicited'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicitedFullControl'
         {
              Ensure = 'Absent'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueName = 'fAllowUnsolicitedFullControl'
              ValueData = ''
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueName = 'DisablePasswordSaving'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueName = 'MinEncryptionLevel'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueName = 'fPromptForPassword'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueName = 'fEncryptRPCTraffic'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\SecurityLayer'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueName = 'SecurityLayer'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\UserAuthentication'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueName = 'UserAuthentication'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\DeleteTempDirsOnExit'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueName = 'DeleteTempDirsOnExit'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\PerSessionTempDir'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueName = 'PerSessionTempDir'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         <#RegistryPolicyFile 'DELVALS_\Software\Policies\Microsoft\Windows NT\Terminal Services\RAUnsolicit'
         {
              Ensure = 'Present'
              Exclusive = $True
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\RAUnsolicit'
              ValueName = ''
              ValueData = ''
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
         }#>

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace\AllowWindowsInkWorkspace'
         {
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace'
              ValueName = 'AllowWindowsInkWorkspace'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
         {
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
              ValueName = 'UseLogonCredential'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode'
         {
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
              ValueName = 'SafeDllSearchMode'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\DisableExceptionChainValidation'
         {
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
              ValueName = 'DisableExceptionChainValidation'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy'
         {
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
              ValueName = 'DriverLoadPolicy'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security\WarningLevel'
         {
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security'
              ValueName = 'WarningLevel'
              ValueData = 90
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
         {
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
              ValueName = 'SMB1'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10\Start'
         {
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10'
              ValueName = 'Start'
              ValueData = 4
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\NoNameReleaseOnDemand'
         {
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'
              ValueName = 'NoNameReleaseOnDemand'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\NodeType'
         {
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'
              ValueName = 'NodeType'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting'
         {
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
              ValueName = 'DisableIPSourceRouting'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect'
         {
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
              ValueName = 'EnableICMPRedirect'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting'
         {
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
              ValueName = 'DisableIPSourceRouting'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
         }

         AuditPolicySubcategory 'IPsec Driver (Success) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Success'
              Name = 'IPsec Driver'
         }

          AuditPolicySubcategory 'IPsec Driver (Failure) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Failure'
              Name = 'IPsec Driver'
         }

         AuditPolicySubcategory 'System Integrity (Success) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Success'
              Name = 'System Integrity'
         }

          AuditPolicySubcategory 'System Integrity (Failure) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Failure'
              Name = 'System Integrity'
         }

         AuditPolicySubcategory 'Security System Extension (Success) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Success'
              Name = 'Security System Extension'
         }

          AuditPolicySubcategory 'Security System Extension (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Security System Extension'
         }

         AuditPolicySubcategory 'Security State Change (Success) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Success'
              Name = 'Security State Change'
         }

          AuditPolicySubcategory 'Security State Change (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Security State Change'
         }

         AuditPolicySubcategory 'Other System Events (Success) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Success'
              Name = 'Other System Events'
         }

          AuditPolicySubcategory 'Other System Events (Failure) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Failure'
              Name = 'Other System Events'
         }

         AuditPolicySubcategory 'Group Membership (Success) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Success'
              Name = 'Group Membership'
         }

          AuditPolicySubcategory 'Group Membership (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Group Membership'
         }

         AuditPolicySubcategory 'User / Device Claims (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'User / Device Claims'
         }

          AuditPolicySubcategory 'User / Device Claims (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'User / Device Claims'
         }

         AuditPolicySubcategory 'Network Policy Server (Success) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Success'
              Name = 'Network Policy Server'
         }

          AuditPolicySubcategory 'Network Policy Server (Failure) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Failure'
              Name = 'Network Policy Server'
         }

         AuditPolicySubcategory 'Other Logon/Logoff Events (Success) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Success'
              Name = 'Other Logon/Logoff Events'
         }

          AuditPolicySubcategory 'Other Logon/Logoff Events (Failure) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Failure'
              Name = 'Other Logon/Logoff Events'
         }

         AuditPolicySubcategory 'Special Logon (Success) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Success'
              Name = 'Special Logon'
         }

          AuditPolicySubcategory 'Special Logon (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Special Logon'
         }

         AuditPolicySubcategory 'IPsec Extended Mode (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'IPsec Extended Mode'
         }

          AuditPolicySubcategory 'IPsec Extended Mode (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'IPsec Extended Mode'
         }

         AuditPolicySubcategory 'IPsec Quick Mode (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'IPsec Quick Mode'
         }

          AuditPolicySubcategory 'IPsec Quick Mode (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'IPsec Quick Mode'
         }

         AuditPolicySubcategory 'IPsec Main Mode (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'IPsec Main Mode'
         }

          AuditPolicySubcategory 'IPsec Main Mode (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'IPsec Main Mode'
         }

         AuditPolicySubcategory 'Account Lockout (Failure) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Failure'
              Name = 'Account Lockout'
         }

          AuditPolicySubcategory 'Account Lockout (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Account Lockout'
         }

         AuditPolicySubcategory 'Logoff (Success) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Success'
              Name = 'Logoff'
         }

          AuditPolicySubcategory 'Logoff (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Logoff'
         }

         AuditPolicySubcategory 'Logon (Success) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Success'
              Name = 'Logon'
         }

          AuditPolicySubcategory 'Logon (Failure) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Failure'
              Name = 'Logon'
         }

         AuditPolicySubcategory 'Handle Manipulation (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Handle Manipulation'
         }

          AuditPolicySubcategory 'Handle Manipulation (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Handle Manipulation'
         }

         AuditPolicySubcategory 'Central Policy Staging (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Central Policy Staging'
         }

          AuditPolicySubcategory 'Central Policy Staging (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Central Policy Staging'
         }

         AuditPolicySubcategory 'Removable Storage (Success) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Success'
              Name = 'Removable Storage'
         }

          AuditPolicySubcategory 'Removable Storage (Failure) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Failure'
              Name = 'Removable Storage'
         }

         AuditPolicySubcategory 'Detailed File Share (Failure) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Failure'
              Name = 'Detailed File Share'
         }

          AuditPolicySubcategory 'Detailed File Share (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Detailed File Share'
         }

         AuditPolicySubcategory 'Other Object Access Events (Success) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Success'
              Name = 'Other Object Access Events'
         }

          AuditPolicySubcategory 'Other Object Access Events (Failure) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Failure'
              Name = 'Other Object Access Events'
         }

         AuditPolicySubcategory 'Filtering Platform Connection (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Filtering Platform Connection'
         }

          AuditPolicySubcategory 'Filtering Platform Connection (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Filtering Platform Connection'
         }

         AuditPolicySubcategory 'Filtering Platform Packet Drop (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Filtering Platform Packet Drop'
         }

          AuditPolicySubcategory 'Filtering Platform Packet Drop (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Filtering Platform Packet Drop'
         }

         AuditPolicySubcategory 'File Share (Success) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Success'
              Name = 'File Share'
         }

          AuditPolicySubcategory 'File Share (Failure) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Failure'
              Name = 'File Share'
         }

         AuditPolicySubcategory 'Application Generated (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Application Generated'
         }

          AuditPolicySubcategory 'Application Generated (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Application Generated'
         }

         AuditPolicySubcategory 'Certification Services (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Certification Services'
         }

          AuditPolicySubcategory 'Certification Services (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Certification Services'
         }

         AuditPolicySubcategory 'SAM (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'SAM'
         }

          AuditPolicySubcategory 'SAM (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'SAM'
         }

         AuditPolicySubcategory 'Kernel Object (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Kernel Object'
         }

          AuditPolicySubcategory 'Kernel Object (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Kernel Object'
         }

         AuditPolicySubcategory 'Registry (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Registry'
         }

          AuditPolicySubcategory 'Registry (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Registry'
         }

         AuditPolicySubcategory 'File System (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'File System'
         }

          AuditPolicySubcategory 'File System (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'File System'
         }

         AuditPolicySubcategory 'Other Privilege Use Events (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Other Privilege Use Events'
         }

          AuditPolicySubcategory 'Other Privilege Use Events (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Other Privilege Use Events'
         }

         AuditPolicySubcategory 'Non Sensitive Privilege Use (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Non Sensitive Privilege Use'
         }

          AuditPolicySubcategory 'Non Sensitive Privilege Use (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Non Sensitive Privilege Use'
         }

         AuditPolicySubcategory 'Sensitive Privilege Use (Success) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Success'
              Name = 'Sensitive Privilege Use'
         }

          AuditPolicySubcategory 'Sensitive Privilege Use (Failure) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Failure'
              Name = 'Sensitive Privilege Use'
         }

         AuditPolicySubcategory 'RPC Events (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'RPC Events'
         }

          AuditPolicySubcategory 'RPC Events (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'RPC Events'
         }

         AuditPolicySubcategory 'Process Creation (Success) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Success'
              Name = 'Process Creation'
         }

          AuditPolicySubcategory 'Process Creation (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Process Creation'
         }

         AuditPolicySubcategory 'Process Termination (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Process Termination'
         }

          AuditPolicySubcategory 'Process Termination (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Process Termination'
         }

         AuditPolicySubcategory 'Plug and Play Events (Success) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Success'
              Name = 'Plug and Play Events'
         }

          AuditPolicySubcategory 'Plug and Play Events (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Plug and Play Events'
         }

         AuditPolicySubcategory 'DPAPI Activity (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'DPAPI Activity'
         }

          AuditPolicySubcategory 'DPAPI Activity (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'DPAPI Activity'
         }

         AuditPolicySubcategory 'Other Policy Change Events (Failure) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Failure'
              Name = 'Other Policy Change Events'
         }

          AuditPolicySubcategory 'Other Policy Change Events (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Other Policy Change Events'
         }

         AuditPolicySubcategory 'Authentication Policy Change (Success) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Success'
              Name = 'Authentication Policy Change'
         }

          AuditPolicySubcategory 'Authentication Policy Change (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Authentication Policy Change'
         }

         AuditPolicySubcategory 'Audit Policy Change (Success) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Success'
              Name = 'Audit Policy Change'
         }

          AuditPolicySubcategory 'Audit Policy Change (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Audit Policy Change'
         }

         AuditPolicySubcategory 'Filtering Platform Policy Change (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Filtering Platform Policy Change'
         }

          AuditPolicySubcategory 'Filtering Platform Policy Change (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Filtering Platform Policy Change'
         }

         AuditPolicySubcategory 'Authorization Policy Change (Success) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Success'
              Name = 'Authorization Policy Change'
         }

          AuditPolicySubcategory 'Authorization Policy Change (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Authorization Policy Change'
         }

         AuditPolicySubcategory 'MPSSVC Rule-Level Policy Change (Success) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Success'
              Name = 'MPSSVC Rule-Level Policy Change'
         }

          AuditPolicySubcategory 'MPSSVC Rule-Level Policy Change (Failure) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Failure'
              Name = 'MPSSVC Rule-Level Policy Change'
         }

         AuditPolicySubcategory 'Other Account Management Events (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Other Account Management Events'
         }

          AuditPolicySubcategory 'Other Account Management Events (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Other Account Management Events'
         }

         AuditPolicySubcategory 'Application Group Management (Success) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Success'
              Name = 'Application Group Management'
         }

          AuditPolicySubcategory 'Application Group Management (Failure) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Failure'
              Name = 'Application Group Management'
         }

         AuditPolicySubcategory 'Distribution Group Management (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Distribution Group Management'
         }

          AuditPolicySubcategory 'Distribution Group Management (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Distribution Group Management'
         }

         AuditPolicySubcategory 'Security Group Management (Success) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Success'
              Name = 'Security Group Management'
         }

          AuditPolicySubcategory 'Security Group Management (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Security Group Management'
         }

         AuditPolicySubcategory 'Computer Account Management (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Computer Account Management'
         }

          AuditPolicySubcategory 'Computer Account Management (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Computer Account Management'
         }

         AuditPolicySubcategory 'User Account Management (Success) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Success'
              Name = 'User Account Management'
         }

          AuditPolicySubcategory 'User Account Management (Failure) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Failure'
              Name = 'User Account Management'
         }

         AuditPolicySubcategory 'Directory Service Replication (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Directory Service Replication'
         }

          AuditPolicySubcategory 'Directory Service Replication (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Directory Service Replication'
         }

         AuditPolicySubcategory 'Directory Service Access (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Directory Service Access'
         }

          AuditPolicySubcategory 'Directory Service Access (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Directory Service Access'
         }

         AuditPolicySubcategory 'Detailed Directory Service Replication (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Detailed Directory Service Replication'
         }

          AuditPolicySubcategory 'Detailed Directory Service Replication (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Detailed Directory Service Replication'
         }

         AuditPolicySubcategory 'Directory Service Changes (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Directory Service Changes'
         }

          AuditPolicySubcategory 'Directory Service Changes (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Directory Service Changes'
         }

         AuditPolicySubcategory 'Other Account Logon Events (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Other Account Logon Events'
         }

          AuditPolicySubcategory 'Other Account Logon Events (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Other Account Logon Events'
         }

         AuditPolicySubcategory 'Kerberos Service Ticket Operations (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Kerberos Service Ticket Operations'
         }

          AuditPolicySubcategory 'Kerberos Service Ticket Operations (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Kerberos Service Ticket Operations'
         }

         AuditPolicySubcategory 'Credential Validation (Success) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Success'
              Name = 'Credential Validation'
         }

          AuditPolicySubcategory 'Credential Validation (Failure) - Inclusion'
         {
              Ensure = 'Present'
              AuditFlag = 'Failure'
              Name = 'Credential Validation'
         }

         AuditPolicySubcategory 'Kerberos Authentication Service (Success) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Kerberos Authentication Service'
         }

          AuditPolicySubcategory 'Kerberos Authentication Service (Failure) - Inclusion'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Kerberos Authentication Service'
         }

         AuditPolicyOption 'AuditPolicyOption: CrashOnAuditFail'
         {
              Value = 'Disabled'
              Name = 'CrashOnAuditFail'
         }

         AuditPolicyOption 'AuditPolicyOption: FullPrivilegeAuditing'
         {
              Value = 'Disabled'
              Name = 'FullPrivilegeAuditing'
         }

         AuditPolicyOption 'AuditPolicyOption: AuditBaseObjects'
         {
              Value = 'Disabled'
              Name = 'AuditBaseObjects'
         }

         AuditPolicyOption 'AuditPolicyOption: AuditBaseDirectories'
         {
              Value = 'Disabled'
              Name = 'AuditBaseDirectories'
         }

         <#AuditPolicySubcategory 'EventAuditing(INF): Process Termination: NoAuditing(Failure)'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Process Termination'
         }#>

          <#AuditPolicySubcategory 'EventAuditing(INF): Process Termination: NoAuditing(Success)'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Process Termination'
         }#>

         <#AuditPolicySubcategory 'EventAuditing(INF): User Account Management: NoAuditing(Failure)'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'User Account Management'
         }#>

          <#AuditPolicySubcategory 'EventAuditing(INF): User Account Management: NoAuditing(Success)'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'User Account Management'
         }#>

         <#AuditPolicySubcategory 'EventAuditing(INF): Kerberos Service Ticket Operations: NoAuditing(Failure)'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Kerberos Service Ticket Operations'
         }#>

          <#AuditPolicySubcategory 'EventAuditing(INF): Kerberos Service Ticket Operations: NoAuditing(Success)'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Kerberos Service Ticket Operations'
         }#>

         <#AuditPolicySubcategory 'EventAuditing(INF): Audit Policy Change: NoAuditing(Failure)'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Audit Policy Change'
         }#>

          <#AuditPolicySubcategory 'EventAuditing(INF): Audit Policy Change: NoAuditing(Success)'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Audit Policy Change'
         }#>

         <#AuditPolicySubcategory 'EventAuditing(INF): Directory Service Changes: NoAuditing(Failure)'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Directory Service Changes'
         }#>

          <#AuditPolicySubcategory 'EventAuditing(INF): Directory Service Changes: NoAuditing(Success)'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Directory Service Changes'
         }#>

         <#AuditPolicySubcategory 'EventAuditing(INF): Security System Extension: Success'
         {
              Name = 'Security System Extension'
              AuditFlag = 'Success'
         }#>

          <#AuditPolicySubcategory 'EventAuditing(INF): Security System Extension: Failure'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Security System Extension'
         }#>

          <#AuditPolicySubcategory 'EventAuditing(INF): System Integrity: Success'
         {
              Name = 'System Integrity'
              AuditFlag = 'Success'
         }#>

          <#AuditPolicySubcategory 'EventAuditing(INF): System Integrity: Failure'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'System Integrity'
         }#>

          <#AuditPolicySubcategory 'EventAuditing(INF): IPsec Driver: Success'
         {
              Name = 'IPsec Driver'
              AuditFlag = 'Success'
         }#>

          <#AuditPolicySubcategory 'EventAuditing(INF): IPsec Driver: Failure'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'IPsec Driver'
         }#>

          <#AuditPolicySubcategory 'EventAuditing(INF): Other System Events: Success'
         {
              Name = 'Other System Events'
              AuditFlag = 'Success'
         }#>

          <#AuditPolicySubcategory 'EventAuditing(INF): Other System Events: Failure'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Other System Events'
         }#>

          <#AuditPolicySubcategory 'EventAuditing(INF): Security State Change: Success'
         {
              Name = 'Security State Change'
              AuditFlag = 'Success'
         }#>

          <#AuditPolicySubcategory 'EventAuditing(INF): Security State Change: Failure'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Security State Change'
         }#>

         <#AuditPolicySubcategory 'EventAuditing(INF): File System: NoAuditing(Failure)'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'File System'
         }#>

          <#AuditPolicySubcategory 'EventAuditing(INF): File System: NoAuditing(Success)'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'File System'
         }#>

         <#AuditPolicySubcategory 'EventAuditing(INF): Logon: NoAuditing(Failure)'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Logon'
         }#>

          <#AuditPolicySubcategory 'EventAuditing(INF): Logon: NoAuditing(Success)'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Logon'
         }#>

         <#AuditPolicySubcategory 'EventAuditing(INF): Sensitive Privilege Use: NoAuditing(Failure)'
         {
              Ensure = 'Absent'
              AuditFlag = 'Failure'
              Name = 'Sensitive Privilege Use'
         }#>

          <#AuditPolicySubcategory 'EventAuditing(INF): Sensitive Privilege Use: NoAuditing(Success)'
         {
              Ensure = 'Absent'
              AuditFlag = 'Success'
              Name = 'Sensitive Privilege Use'
         }#>

         AccountPolicy 'SecuritySetting(INF): PasswordComplexity'
         {
              Name = 'Password_must_meet_complexity_requirements'
              Password_must_meet_complexity_requirements = 'Enabled'
         }

         AccountPolicy 'SecuritySetting(INF): MinimumPasswordAge'
         {
              Name = 'Minimum_Password_Age'
              Minimum_Password_Age = 1
         }

         AccountPolicy 'SecuritySetting(INF): ClearTextPassword'
         {
              Store_passwords_using_reversible_encryption = 'Disabled'
              Name = 'Store_passwords_using_reversible_encryption'
         }

         AccountPolicy 'SecuritySetting(INF): LockoutDuration'
         {
              Name = 'Account_lockout_duration'
              Account_lockout_duration = 30
         }

         SecurityOption 'SecuritySetting(INF): EnableAdminAccount'
         {
              Name = 'Accounts_Administrator_account_status'
              Accounts_Administrator_account_status = 'Enabled'
         }

         SecurityOption 'SecuritySetting(INF): LSAAnonymousNameLookup'
         {
              Name = 'Network_access_Allow_anonymous_SID_Name_translation'
              Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'
         }

         AccountPolicy 'SecuritySetting(INF): MaximumPasswordAge'
         {
              Maximum_Password_Age = 90
              Name = 'Maximum_Password_Age'
         }

         SecurityOption 'SecuritySetting(INF): EnableGuestAccount'
         {
              Name = 'Accounts_Guest_account_status'
              Accounts_Guest_account_status = 'Disabled'
         }

         SecurityOption 'SecuritySetting(INF): NewGuestName'
         {
              Name = 'Accounts_Rename_guest_account'
              Accounts_Rename_guest_account = 'SSGGUEST'
         }

         SecurityOption 'SecuritySetting(INF): ForceLogoffWhenHourExpire'
         {
              Network_security_Force_logoff_when_logon_hours_expire = 'Enabled'
              Name = 'Network_security_Force_logoff_when_logon_hours_expire'
         }

         AccountPolicy 'SecuritySetting(INF): LockoutBadCount'
         {
              Name = 'Account_lockout_threshold'
              Account_lockout_threshold = 5
         }

         AccountPolicy 'SecuritySetting(INF): ResetLockoutCount'
         {
              Name = 'Reset_account_lockout_counter_after'
              Reset_account_lockout_counter_after = 15
         }

         AccountPolicy 'SecuritySetting(INF): MinimumPasswordLength'
         {
              Minimum_Password_Length = 14
              Name = 'Minimum_Password_Length'
         }

         AccountPolicy 'SecuritySetting(INF): PasswordHistorySize'
         {
              Enforce_password_history = 24
              Name = 'Enforce_password_history'
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_a_token_object'
         {
              Force = $True
              Policy = 'Create_a_token_object'
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Manage_auditing_and_security_log'
         {
              Force = $True
              Policy = 'Manage_auditing_and_security_log'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_batch_job'
         {
              Force = $True
              Policy = 'Deny_log_on_as_a_batch_job'
              Identity = @('*S-1-5-32-546')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Profile_system_performance'
         {
              Force = $True
              Policy = 'Profile_system_performance'
              Identity = @('*S-1-5-32-544', '*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_permanent_shared_objects'
         {
              Force = $True
              Policy = 'Create_permanent_shared_objects'
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Load_and_unload_device_drivers'
         {
              Force = $True
              Policy = 'Load_and_unload_device_drivers'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Adjust_memory_quotas_for_a_process'
         {
              Force = $True
              Policy = 'Adjust_memory_quotas_for_a_process'
              Identity = @('*S-1-5-19', '*S-1-5-20', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_global_objects'
         {
              Force = $True
              Policy = 'Create_global_objects'
              Identity = @('*S-1-5-19', '*S-1-5-20', '*S-1-5-32-544', '*S-1-5-6')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Synchronize_directory_service_data'
         {
              Force = $True
              Policy = 'Synchronize_directory_service_data'
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_locally'
         {
              Force = $True
              Policy = 'Allow_log_on_locally'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Modify_firmware_environment_values'
         {
              Force = $True
              Policy = 'Modify_firmware_environment_values'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Restore_files_and_directories'
         {
              Force = $True
              Policy = 'Restore_files_and_directories'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_through_Remote_Desktop_Services'
         {
              Force = $True
              Policy = 'Deny_log_on_through_Remote_Desktop_Services'
              Identity = @('*S-1-5-32-546')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Increase_a_process_working_set'
         {
              Force = $True
              Policy = 'Increase_a_process_working_set'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
         {
              Force = $True
              Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_access_to_this_computer_from_the_network'
         {
              Force = $True
              Policy = 'Deny_access_to_this_computer_from_the_network'
              Identity = @('*S-1-5-32-546')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Change_the_system_time'
         {
              Force = $True
              Policy = 'Change_the_system_time'
              Identity = @('*S-1-5-19', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_a_pagefile'
         {
              Force = $True
              Policy = 'Create_a_pagefile'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Access_this_computer_from_the_network'
         {
              Force = $True
              Policy = 'Access_this_computer_from_the_network'
              Identity = @('*S-1-5-11', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_locally'
         {
              Force = $True
              Policy = 'Deny_log_on_locally'
              Identity = @('*S-1-5-32-546')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Access_Credential_Manager_as_a_trusted_caller'
         {
              Force = $True
              Policy = 'Access_Credential_Manager_as_a_trusted_caller'
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Back_up_files_and_directories'
         {
              Force = $True
              Policy = 'Back_up_files_and_directories'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Log_on_as_a_service'
         {
              Force = $True
              Policy = 'Log_on_as_a_service'
              Identity = @('*S-1-5-80-0')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_service'
         {
              Force = $True
              Policy = 'Deny_log_on_as_a_service'
              Identity = @('*S-1-5-32-546')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Add_workstations_to_domain'
         {
              Force = $True
              Policy = 'Add_workstations_to_domain'
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Force_shutdown_from_a_remote_system'
         {
              Force = $True
              Policy = 'Force_shutdown_from_a_remote_system'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Act_as_part_of_the_operating_system'
         {
              Force = $True
              Policy = 'Act_as_part_of_the_operating_system'
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Shut_down_the_system'
         {
              Force = $True
              Policy = 'Shut_down_the_system'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Generate_security_audits'
         {
              Force = $True
              Policy = 'Generate_security_audits'
              Identity = @('*S-1-5-19', '*S-1-5-20')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Lock_pages_in_memory'
         {
              Force = $True
              Policy = 'Lock_pages_in_memory'
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_through_Remote_Desktop_Services'
         {
              Force = $True
              Policy = 'Allow_log_on_through_Remote_Desktop_Services'
              Identity = @('*S-1-5-32-544', '*S-1-5-32-555')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Perform_volume_maintenance_tasks'
         {
              Force = $True
              Policy = 'Perform_volume_maintenance_tasks'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Bypass_traverse_checking'
         {
              Force = $True
              Policy = 'Bypass_traverse_checking'
              Identity = @('*S-1-5-19', '*S-1-5-20', '*S-1-5-32-544', '*S-1-5-32-545', '*S-1-5-32-551')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Debug_programs'
         {
              Force = $True
              Policy = 'Debug_programs'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Log_on_as_a_batch_job'
         {
              Force = $True
              Policy = 'Log_on_as_a_batch_job'
              Identity = @('*S-1-5-32-544', '*S-1-5-32-551', '*S-1-5-32-559')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Take_ownership_of_files_or_other_objects'
         {
              Force = $True
              Policy = 'Take_ownership_of_files_or_other_objects'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Impersonate_a_client_after_authentication'
         {
              Force = $True
              Policy = 'Impersonate_a_client_after_authentication'
              Identity = @('*S-1-5-19', '*S-1-5-20', '*S-1-5-32-544', '*S-1-5-6')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Change_the_time_zone'
         {
              Force = $True
              Policy = 'Change_the_time_zone'
              Identity = @('*S-1-5-19', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Increase_scheduling_priority'
         {
              Force = $True
              Policy = 'Increase_scheduling_priority'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Modify_an_object_label'
         {
              Force = $True
              Policy = 'Modify_an_object_label'
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_symbolic_links'
         {
              Force = $True
              Policy = 'Create_symbolic_links'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Remove_computer_from_docking_station'
         {
              Force = $True
              Policy = 'Remove_computer_from_docking_station'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Profile_single_process'
         {
              Force = $True
              Policy = 'Profile_single_process'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Replace_a_process_level_token'
         {
              Force = $True
              Policy = 'Replace_a_process_level_token'
              Identity = @('*S-1-5-19', '*S-1-5-20')
         }

         SecurityOption 'SecurityRegistry(INF): System_settings_Use_Certificate_Rules_on_Windows_Executables_for_Software_Restriction_Policies'
         {
              Name = 'System_settings_Use_Certificate_Rules_on_Windows_Executables_for_Software_Restriction_Policies'
              System_settings_Use_Certificate_Rules_on_Windows_Executables_for_Software_Restriction_Policies = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_executables_that_are_signed_and_validated'
         {
              Name = 'User_Account_Control_Only_elevate_executables_that_are_signed_and_validated'
              User_Account_Control_Only_elevate_executables_that_are_signed_and_validated = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Server_SPN_target_name_validation_level'
         {
              Microsoft_network_server_Server_SPN_target_name_validation_level = 'Accept if provided by client'
              Name = 'Microsoft_network_server_Server_SPN_target_name_validation_level'
         }

         SecurityOption 'SecurityRegistry(INF): Devices_Allow_undock_without_having_to_log_on'
         {
              Devices_Allow_undock_without_having_to_log_on = 'Enabled'
              Name = 'Devices_Allow_undock_without_having_to_log_on'
         }

         SecurityOption 'SecurityRegistry(INF): Recovery_console_Allow_automatic_administrative_logon'
         {
              Recovery_console_Allow_automatic_administrative_logon = 'Disabled'
              Name = 'Recovery_console_Allow_automatic_administrative_logon'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_sign_secure_channel_data_when_possible'
         {
              Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
              Name = 'Domain_member_Digitally_sign_secure_channel_data_when_possible'
         }

         SecurityOption 'SecurityRegistry(INF): Devices_Prevent_users_from_installing_printer_drivers'
         {
              Name = 'Devices_Prevent_users_from_installing_printer_drivers'
              Devices_Prevent_users_from_installing_printer_drivers = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation'
         {
              User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation = 'Enabled'
              Name = 'User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation'
         }

         SecurityOption 'SecurityRegistry(INF): System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
         {
              Name = 'System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
              System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_always'
         {
              Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
              Name = 'Microsoft_network_server_Digitally_sign_communications_always'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
         {
              Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'
              Name = 'Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
         }

         SecurityOption 'SecurityRegistry(INF): Accounts_Block_Microsoft_accounts'
         {
              Name = 'Accounts_Block_Microsoft_accounts'
              Accounts_Block_Microsoft_accounts = 'Users cant add or log on with Microsoft accounts'
         }

         SecurityOption 'SecurityRegistry(INF): Audit_Shut_down_system_immediately_if_unable_to_log_security_audits'
         {
              Audit_Shut_down_system_immediately_if_unable_to_log_security_audits = 'Disabled'
              Name = 'Audit_Shut_down_system_immediately_if_unable_to_log_security_audits'
         }

         SecurityOption 'SecurityRegistry(INF): Audit_Audit_the_access_of_global_system_objects'
         {
              Audit_Audit_the_access_of_global_system_objects = 'Disabled'
              Name = 'Audit_Audit_the_access_of_global_system_objects'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Maximum_machine_account_password_age'
         {
              Domain_member_Maximum_machine_account_password_age = '30'
              Name = 'Domain_member_Maximum_machine_account_password_age'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
         {
              Name = 'User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
              User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_always'
         {
              Name = 'Microsoft_network_client_Digitally_sign_communications_always'
              Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
         {
              Name = 'User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
              User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
         {
              Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = '10'
              Name = 'Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
         {
              Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
              User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Require_smart_card'
         {
              Name = 'Interactive_logon_Require_smart_card'
              Interactive_logon_Require_smart_card = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Machine_inactivity_limit'
         {
              Interactive_logon_Machine_inactivity_limit = '1800'
              Name = 'Interactive_logon_Machine_inactivity_limit'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Smart_card_removal_behavior'
         {
              Interactive_logon_Smart_card_removal_behavior = 'Lock workstation'
              Name = 'Interactive_logon_Smart_card_removal_behavior'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
         {
              Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
              User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Remotely_accessible_registry_paths'
         {
              Name = 'Network_access_Remotely_accessible_registry_paths'
              Network_access_Remotely_accessible_registry_paths = 'System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion'
         }

         SecurityOption 'SecurityRegistry(INF): Shutdown_Clear_virtual_memory_pagefile'
         {
              Shutdown_Clear_virtual_memory_pagefile = 'Disabled'
              Name = 'Shutdown_Clear_virtual_memory_pagefile'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_LDAP_client_signing_requirements'
         {
              Network_security_LDAP_client_signing_requirements = 'Negotiate Signing'
              Name = 'Network_security_LDAP_client_signing_requirements'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
         {
              User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop = 'Disabled'
              Name = 'User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
         {
              Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
              Name = 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
         {
              Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'
              Name = 'Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_title_for_users_attempting_to_log_on'
         {
              Interactive_logon_Message_title_for_users_attempting_to_log_on = 'DSI Logon Warning'
              Name = 'Interactive_logon_Message_title_for_users_attempting_to_log_on'
         }

         SecurityOption 'SecurityRegistry(INF): Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
         {
              Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
              Name = 'Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
         {
              Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'
              Name = 'Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Prompt_user_to_change_password_before_expiration'
         {
              Interactive_logon_Prompt_user_to_change_password_before_expiration = '14'
              Name = 'Interactive_logon_Prompt_user_to_change_password_before_expiration'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
         {
              Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
              User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Named_Pipes_that_can_be_accessed_anonymously'
         {
              Network_access_Named_Pipes_that_can_be_accessed_anonymously = 'String'
              Name = 'Network_access_Named_Pipes_that_can_be_accessed_anonymously'
         }

         SecurityOption 'SecurityRegistry(INF): Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
         {
              Name = 'Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
              Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Require_Domain_Controller_authentication_to_unlock_workstation'
         {
              Name = 'Interactive_logon_Require_Domain_Controller_authentication_to_unlock_workstation'
              Interactive_logon_Require_Domain_Controller_authentication_to_unlock_workstation = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Sharing_and_security_model_for_local_accounts'
         {
              Name = 'Network_access_Sharing_and_security_model_for_local_accounts'
              Network_access_Sharing_and_security_model_for_local_accounts = 'Classic - Local users authenticate as themselves'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
         {
              Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
              Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_Allow_LocalSystem_NULL_session_fallback'
         {
              Name = 'Network_security_Allow_LocalSystem_NULL_session_fallback'
              Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Shares_that_can_be_accessed_anonymously'
         {
              Network_access_Shares_that_can_be_accessed_anonymously = 'String'
              Name = 'Network_access_Shares_that_can_be_accessed_anonymously'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
         {
              Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
              Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Disable_machine_account_password_changes'
         {
              Name = 'Domain_member_Disable_machine_account_password_changes'
              Domain_member_Disable_machine_account_password_changes = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): System_objects_Require_case_insensitivity_for_non_Windows_subsystems'
         {
              Name = 'System_objects_Require_case_insensitivity_for_non_Windows_subsystems'
              System_objects_Require_case_insensitivity_for_non_Windows_subsystems = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on'
         {
              Name = 'Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on'
              Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
         {
              Name = 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
              User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session'
         {
              Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session = '30'
              Name = 'Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session'
         }

         SecurityOption 'SecurityRegistry(INF): System_settings_Optional_subsystems'
         {
              System_settings_Optional_subsystems = 'String'
              Name = 'System_settings_Optional_subsystems'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Require_strong_Windows_2000_or_later_session_key'
         {
              Name = 'Domain_member_Require_strong_Windows_2000_or_later_session_key'
              Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
         {
              Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'
              Name = 'Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
         }

         SecurityOption 'SecurityRegistry(INF): Recovery_console_Allow_floppy_copy_and_access_to_all_drives_and_folders'
         {
              Recovery_console_Allow_floppy_copy_and_access_to_all_drives_and_folders = 'Disabled'
              Name = 'Recovery_console_Allow_floppy_copy_and_access_to_all_drives_and_folders'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Remotely_accessible_registry_paths_and_subpaths'
         {
              Network_access_Remotely_accessible_registry_paths_and_subpaths = 'Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog'
              Name = 'Network_access_Remotely_accessible_registry_paths_and_subpaths'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
         {
              User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
              Name = 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
         }

         SecurityOption 'SecurityRegistry(INF): Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
         {
              Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'
              Name = 'Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Disconnect_clients_when_logon_hours_expire'
         {
              Name = 'Microsoft_network_server_Disconnect_clients_when_logon_hours_expire'
              Microsoft_network_server_Disconnect_clients_when_logon_hours_expire = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
         {
              Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'
              Name = 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
         }

         SecurityOption 'SecurityRegistry(INF): Devices_Allowed_to_format_and_eject_removable_media'
         {
              Name = 'Devices_Allowed_to_format_and_eject_removable_media'
              Devices_Allowed_to_format_and_eject_removable_media = 'Administrators'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
         {
              Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
              Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
         {
              Name = 'Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
              Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Do_not_require_CTRL_ALT_DEL'
         {
              Name = 'Interactive_logon_Do_not_require_CTRL_ALT_DEL'
              Interactive_logon_Do_not_require_CTRL_ALT_DEL = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_LAN_Manager_authentication_level'
         {
              Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
              Name = 'Network_security_LAN_Manager_authentication_level'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_text_for_users_attempting_to_log_on'
         {
              Name = 'Interactive_logon_Message_text_for_users_attempting_to_log_on'
              Interactive_logon_Message_text_for_users_attempting_to_log_on = 'This system is for the use of authorized users only. Individuals using this computer system without authority,or in excess of their authority,are subject to having all of their activities on this system monitored and recorded by system personnel. In the course of monitoring individuals improperly using this system,or in the course of system maintenance,the activities of authorized users may also be monitored. Anyone using this system expressly consents to such monitoring and is advised that if such monitoring reveals possible evidence of criminal activity,system personnel may provide the evidence of such monitoring to law enforcement officials.'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
         {
              Name = 'Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
              Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_Configure_encryption_types_allowed_for_Kerberos'
         {
              Network_security_Configure_encryption_types_allowed_for_Kerberos = 'AES256_HMAC_SHA1'
              Name = 'Network_security_Configure_encryption_types_allowed_for_Kerberos'
         }

         SecurityOption 'SecurityRegistry(INF): Audit_Audit_the_use_of_Backup_and_Restore_privilege'
         {
              Name = 'Audit_Audit_the_use_of_Backup_and_Restore_privilege'
              Audit_Audit_the_use_of_Backup_and_Restore_privilege = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
         {
              Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'
              Name = 'Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
         }

         SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
         {
              Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
              System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
         {
              Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'
              Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_storage_of_passwords_and_credentials_for_network_authentication'
         {
              Name = 'Network_access_Do_not_allow_storage_of_passwords_and_credentials_for_network_authentication'
              Network_access_Do_not_allow_storage_of_passwords_and_credentials_for_network_authentication = 'Disabled'
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}

#region Main Code
$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName                    = 'localhost'
            #PSDscAllowPlainTextPassword = $true
        }
    )
}


<#
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 
#>

ConvertedFromGPODSCConfiguration -ConfigurationData $ConfigurationData

<#
Start-DscConfiguration -Path .\ConvertedFromGPODSCConfiguration -Force -Wait -Verbose
Test-DscConfiguration -Detailed
#>
#endregion
