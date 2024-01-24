#requires -Version 5 -Modules AutomatedLab, iSCSIDsc -RunAsAdministrator 
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

trap {
    Write-Host "Stopping Transcript ..."
    Stop-Transcript
    $VerbosePreference = $PreviousVerbosePreference
    $ErrorActionPreference = $PreviousErrorActionPreference
    [console]::beep(3000, 750)
    Send-ALNotification -Activity 'Lab started' -Message ('Lab deployment failed !') -Provider (Get-LabConfigurationItem -Name Notifications.SubscribedProviders)
    break
} 
Clear-Host
$PreviousVerbosePreference = $VerbosePreference
$VerbosePreference = 'SilentlyContinue'
$PreviousErrorActionPreference = $ErrorActionPreference
#$ErrorActionPreference = 'Stop'
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$TranscriptFile = $CurrentScript -replace ".ps1$", "$("_{0}.txt" -f (Get-Date -Format 'yyyyMMddHHmmss'))"
Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader

#region Global variables definition
$Logon = 'Administrator'
$ClearTextPassword = 'P@ssw0rd'
$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$NetBiosDomainName = 'CONTOSO'
$FQDNDomainName = 'contoso.com'
$FileShareWitnessFolderName = "FileShareWitness"
$SourcesFolderName = 'Sources'
$BackupFolderName = 'Backup'
$SQLAdmin = 'SQLAdministrator' 
$DBAADGroup = 'DBA_SQL'
$gMSASqlServiceName = "gMSASqlService"
$gMSASqlServiceDNSHostName = "$gMSASqlServiceName.$FQDNDomainName"
$SQLServerSADGroup = "SQLServers"
$SQLServicesADGroup = "SQLServices"
$ClusterNameObjectsADGroup = "ClusterNameObjects"

#region SQL Server
#SQL Server Management Studio
$SQLServerManagementStudioURI = 'https://aka.ms/ssmsfullsetup'

#region SQL Server 2019
$SQLServer2019EnterpriseISO = "$labSources\ISOs\en_sql_server_2019_enterprise_x64_dvd_5e1ecc6b.iso"
#SQL Server 2019 Latest GDR: KB4583458 when writing/updating this script (January 2024)
$SQLServer2019LatestGDRURI = ($(Invoke-WebRequest -Uri https://www.microsoft.com/en-us/download/confirmation.aspx?id=102618 -UseBasicParsing).Links | Where-Object -FilterScript { $_.outerHTML -match "click here to download manually"}).href
#SQL Server 2019 Latest Cumulative Update: KB5031908 when writing/updating this script (January 2024)
$SQLServer2019LatestCUURI = ($(Invoke-WebRequest -Uri https://www.microsoft.com/en-us/download/confirmation.aspx?id=100809 -UseBasicParsing).Links | Where-Object -FilterScript { $_.outerHTML -match "click here to download manually"}).href
#endregion

#region SQL Server 2022
$SQLServer2022EnterpriseISO = "$labSources\ISOs\enu_sql_server_2022_enterprise_edition_x64_dvd_aa36de9e"
#SQL Server 2022 Latest GDR: KB5021522 when writing/updating this script (January 2024)
$SQLServer2022LatestGDRURI = ($(Invoke-WebRequest -Uri https://www.microsoft.com/en-us/download/details.aspx?id=105003 -UseBasicParsing).Links | Where-Object -FilterScript { $_.outerHTML -match "KB.*\.exe"}).href
#SQL Server 2022 Latest Cumulative Update: KB5032679 when writing/updating this script (January 2024)
$SQLServer2022LatestCUURI = ($(Invoke-WebRequest -Uri https://www.microsoft.com/en-us/download/details.aspx?id=105013 -UseBasicParsing).Links | Where-Object -FilterScript { $_.outerHTML -match "KB.*\.exe"}).href
#endregion
#endregion

$NetworkID='10.0.0.0/24' 
$Ipv4Gateway = '10.0.0.254'
$DC01IPv4Address = '10.0.0.1'
$FS01IPv4Address = '10.0.0.21'
$SQLNODE01IPv4Address = '10.0.0.11'
$SQLNODE02IPv4Address = '10.0.0.12'
$SQLNODE03IPv4Address = '10.0.0.13'

#Using half of the logical processors to speed up the deployement
[int]$LabMachineDefinitionProcessors = [math]::Max(1, (Get-CimInstance -ClassName Win32_Processor).NumberOfLogicalProcessors/2)

#Latest Edge version URI
$MSEdgeEntUri = "http://go.microsoft.com/fwlink/?LinkID=2093437"

#For Job tracking
$Job = @()

$LabName = 'SQLDSC'
$iSCSIVirtualDiskNumber = 3 

$WorkSpace = Join-Path -Path $env:SystemDrive -ChildPath $LabName
#endregion

#Cleaning previously existing lab
if ($LabName -in (Get-Lab -List))
{
    Remove-Lab -name $LabName -confirm:$false -ErrorAction SilentlyContinue
}

#create an empty lab template and define where the lab XML files and the VMs will be stored
New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV

#make the network definition
Add-LabVirtualNetworkDefinition -Name $LabName -HyperVProperties @{
    SwitchType = 'Internal'
} -AddressSpace $NetworkID
Add-LabVirtualNetworkDefinition -Name 'Default Switch' -HyperVProperties @{ SwitchType = 'External'; AdapterName = 'Wi-Fi' }


#and the domain definition with the domain admin account
Add-LabDomainDefinition -Name $FQDNDomainName -AdminUser $Logon -AdminPassword $ClearTextPassword

#these credentials are used for connecting to the machines. As this is a lab we use clear-text passwords
Set-LabInstallationCredential -Username $Logon -Password $ClearTextPassword

#defining default parameter values, as these ones are the same for all the machines
$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:Network'         = $LabName
    'Add-LabMachineDefinition:DomainName'      = $FQDNDomainName
    'Add-LabMachineDefinition:MinMemory'       = 1GB
    'Add-LabMachineDefinition:MaxMemory'       = 4GB
    'Add-LabMachineDefinition:Memory'          = 2GB
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2022 Datacenter (Desktop Experience)'
    #'Add-LabMachineDefinition:Processors'      = $LabMachineDefinitionProcessors
}

$FS01NetAdapter = @()
$FS01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $FS01IPv4Address -InterfaceName Corp
#Adding an Internet Connection
$FS01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp -InterfaceName Internet

#region server definitions
#Domain controller
Add-LabMachineDefinition -Name DC01 -Roles RootDC -IpAddress $DC01IPv4Address -Memory 1GB -MaxMemory 1GB -Processors 1
#SQL Servers
Add-LabDiskDefinition -Name DataSQLNODE01 -DiskSizeInGb 10 -Label "SQL" -DriveLetter D
Add-LabMachineDefinition -Name SQLNODE01 -IpAddress $SQLNODE01IPv4Address -Disk DataSQLNODE01

Add-LabDiskDefinition -Name DataSQLNODE02 -DiskSizeInGb 10 -Label "SQL" -DriveLetter D
Add-LabMachineDefinition -Name SQLNODE02 -IpAddress $SQLNODE02IPv4Address -Disk DataSQLNODE02

Add-LabDiskDefinition -Name DataSQLNODE03 -DiskSizeInGb 10 -Label "SQL" -DriveLetter D
Add-LabMachineDefinition -Name SQLNODE03 -IpAddress $SQLNODE03IPv4Address -Disk DataSQLNODE03

#File Server
Add-LabDiskDefinition -Name LunDriveFS01 -DiskSizeInGb 10 -Label "LunDrive" -DriveLetter D
Add-LabDiskDefinition -Name DataFS01 -DiskSizeInGb 10 -Label "Data" -SkipInitialize
Add-LabMachineDefinition -Name FS01 -Roles FileServer -NetworkAdapter $FS01NetAdapter -Disk DataFS01, LunDriveFS01 -Memory 1GB -MaxMemory 2GB -Processors 2
#endregion

#Installing servers
Install-Lab -Verbose
$AllLabVMs = Get-LabVM -All
Restart-LabVM -ComputerName $AllLabVMs -Wait -Verbose

#Taking a snapshot/checkpoint
Checkpoint-LabVM -SnapshotName FreshInstall -All -Verbose
#Restore-LabVMSnapshot -SnapshotName 'FreshInstall' -All -Verbose

#region Installing Required Windows Features
$SQLServerNodes = $AllLabVMs | Where-Object -FilterScript { $_.Name -match "^SQLNode"}
$Job += Install-LabWindowsFeature -FeatureName Telnet-Client -ComputerName $AllLabVMs -IncludeManagementTools -AsJob -PassThru
#endregion

Invoke-LabCommand -ActivityName "Disabling IE ESC" -ComputerName $AllLabVMs -ScriptBlock {
    #Disabling IE ESC
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
    Stop-Process -Name Explorer -Force
    #Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green

    #Setting the Keyboard to French
    Set-WinUserLanguageList -LanguageList "fr-FR" -Force

    #Removing IE
    #Disable-WindowsOptionalFeature -FeatureName Internet-Explorer-Optional-amd64 –Online -NoRestart

    #Renaming the main NIC adapter to Corp
    Rename-NetAdapter -Name "$using:labName 0" -NewName 'Corp' -PassThru -ErrorAction SilentlyContinue
    Rename-NetAdapter -Name "Ethernet" -NewName 'Corp' -PassThru -ErrorAction SilentlyContinue
    Rename-NetAdapter -Name "Default Switch 0" -NewName 'Internet' -PassThru -ErrorAction SilentlyContinue
}


#Installing and setting up DNS
Invoke-LabCommand -ActivityName 'DNS, AD & GPO Settings on DC' -ComputerName DC01 -ScriptBlock {
    New-ADUser -Name "$Using:SQLAdmin" -PasswordNeverExpires $True -AccountPassword $Using:SecurePassword -CannotChangePassword $True -Enabled $True
    New-ADGroup -Name "$Using:DBAADGroup" -GroupScope Global -GroupCategory Security

    #region DNS management
    #Reverse lookup zone creation
    Add-DnsServerPrimaryZone -NetworkID $using:NetworkID -ReplicationScope 'Forest' 
    #endregion

    #Creating a GPO at the domain level for certificate autoenrollment
    $DefaultNamingContext = (Get-ADRootDSE).defaultNamingContext

    #region IE Settings
    $GPO = New-GPO -Name "IE Settings" | New-GPLink -Target $DefaultNamingContext
    #Disabling IE ESC
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -ValueName IsInstalled -Type Dword -value 1
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -ValueName IsInstalled -Type Dword -value 1
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap' -ValueName IEHarden -Type Dword -value 0
    #endregion

    #region WireShark : (Pre)-Master-Secret Log Filename
    $GPO = New-GPO -Name "(Pre)-Master-Secret Log Filename" | New-GPLink -Target $DefaultNamingContext
    #For decrypting SSL traffic via network tools : https://support.f5.com/csp/article/K50557518
    $SSLKeysFile = '%USERPROFILE%\AppData\Local\ssl-keys.log'
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Environment' -ValueName "SSLKEYLOGFILE" -Type ([Microsoft.Win32.RegistryValueKind]::ExpandString) -Value $SSLKeysFile
    #endregion

    #Creating dedicated AD security group for SQL servers
    $ADGroup = New-ADGroup -Name "$using:SQLServersADGroup" -SamAccountName $using:SQLServersADGroup -GroupCategory Security -GroupScope Global -DisplayName "$using:SQLServersADGroup" -Path "CN=Computers,DC=$($using:FQDNDomainName -split "\." -join ",DC=")" -Description "SQL Servers AD Group" -PassThru
    #Only the SQLServerNode* servers used as target nodes
    #$ADGroup | Add-ADGroupMember -Members $(Get-ADComputer -Filter 'Name -like "SQLNode*"' | ForEach-Object -Process { "$($_.Name)$"})
    #All SQL Servers (DSC Target Nodes + DSC Pull/Report server)
    $ADGroup | Add-ADGroupMember -Members $(Get-ADComputer -Filter 'Name -like "*SQL*"' | ForEach-Object -Process { "$($_.Name)$"})

    #Creating dedicated AD security group for SQL Server services account
    $ADGroup = New-ADGroup -Name "$using:SQLServicesADGroup" -SamAccountName $using:SQLServicesADGroup -GroupCategory Security -GroupScope Global -DisplayName "$using:SQLServicesADGroup" -Path "CN=Users,DC=$($using:FQDNDomainName -split "\." -join ",DC=")" -Description "SQL Services AD Group" -PassThru
    $ADGroup | Add-ADGroupMember -Members $using:SQLAdmin

    #Creating dedicated AD security group for SQL servers
    $ADGroup = New-ADGroup -Name "$using:ClusterNameObjectsADGroup" -SamAccountName $using:ClusterNameObjectsADGroup -GroupCategory Security -GroupScope Global -DisplayName "$using:ClusterNameObjectsADGroup" -Path "CN=Computers,DC=$($using:FQDNDomainName -split "\." -join ",DC=")" -Description "Cluster Name Objects AD Group" -PassThru

    #Configuring key distribution service (KDS)
    $KdsRootKey = Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))

    #Creating a new group managed service account
    New-ADServiceAccount -name $using:gMSASqlServiceName -DNSHostName $using:gMSASqlServiceDNSHostName -PrincipalsAllowedToRetrieveManagedPassword "$using:SQLServerSADGroup" 

    #Allowing the gMSA account to register its service principal name (SPN) for Kerberos authentication in SQL Server.
    dsacls (Get-ADServiceAccount -Identity $using:gMSASqlServiceName).DistinguishedName /G "SELF:RPWP;servicePrincipalName" 
}

#Restart if required to use Install-ADServiceAccount later
Restart-LabVM -ComputerName $SQLServerNodes -Wait

#Mouting the SQL Server ISO for Copying SQL Server setup binaries on the file server
$WindowsServer2019StandardISO = ($SQLServerNodes | Select-Object -First 1).OperatingSystem.IsoPath

#$SQLServer2019StandardMountedVolume = Mount-LabIsoImage -IsoPath $SQLServer2019StandardISO -ComputerName FS01 -PassThru
$SQLServer2022EnterpriseMountedVolume = Mount-LabIsoImage -IsoPath $SQLServer2022EnterpriseISO -ComputerName FS01 -PassThru
$SQLServer2019EnterpriseMountedVolume = Mount-LabIsoImage -IsoPath $SQLServer2019EnterpriseISO -ComputerName FS01 -PassThru
$WindowsServer2019StandardMountedVolume = Mount-LabIsoImage -IsoPath $WindowsServer2019StandardISO -ComputerName FS01 -PassThru

#region Installing Edge on all machines
$MSEdgeEnt = Get-LabInternetFile -Uri $MSEdgeEntUri -Path $labSources\SoftwarePackages -PassThru -Force
$Job += Install-LabSoftwarePackage -ComputerName $AllLabVMs -Path $MSEdgeEnt.FullName -CommandLine "/passive /norestart" -AsJob -PassThru
#endregion


#region Installing SQL Management Studio on the SQL Server Nodes
$SQLServerManagementStudio = Get-LabInternetFile -Uri $SQLServerManagementStudioURI -Path $labSources\SoftwarePackages -FileName 'SSMS-Setup-ENU.exe' -PassThru -Force
$Job += Install-LabSoftwarePackage -ComputerName $SQLServerNodes -Path $SQLServerManagementStudio.FullName -CommandLine "/install /passive /norestart" -AsJob -PassThru
#endregion

Invoke-LabCommand -ActivityName 'Configuring Storage & Copying SQL Server 2019 and 2022 ISOs & Tools' -ComputerName FS01 -ScriptBlock {
    <#
    Get-VirtualDisk | Remove-VirtualDisk -Confirm:$false
    Get-StoragePool | Remove-StoragePool -Confirm:$false
    #>
    #Creating a dedicated storage pool and disk
    $PhysicalDisks = Get-StorageSubSystem -FriendlyName "Windows Storage*" | Get-PhysicalDisk -CanPool $True
    $StoragePool = New-StoragePool -FriendlyName "CompanyData" -StorageSubsystemFriendlyName "Windows Storage*" -PhysicalDisks $PhysicalDisks | New-VirtualDisk -FriendlyName "UserData" -ResiliencySettingName Simple -ProvisioningType Thin -Size 10GB | Initialize-Disk -PassThru | New-Partition -AssignDriveLetter -UseMaximumSize | Format-Volume

    #region Creating dedicated folders for SQL Server Backup
    $BackupFolder = New-Item -Path "$($StoragePool.DriveLetter):\$using:BackupFolderName" -ItemType Directory
    #From https://blue42.net/windows/changing-ntfs-security-permissions-using-powershell/
    $existingAcl = Get-Acl $BackupFolder

    #region Add Full Control access for the SQL Services AD Group Group for "This folder, subfolders and files"
    $identity = $using:SQLServicesADGroup
    $colRights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
    $objType = [System.Security.AccessControl.AccessControlType]::Allow
    # Create a new FileSystemAccessRule object
    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity,$colRights,$InheritanceFlag,$PropagationFlag, $objType)
    # Modify the existing ACL to include the new rule
    $existingAcl.SetAccessRule($AccessRule)
    #endregion 

    # Apply the modified access rule to the folder
    $existingAcl | Set-Acl -Path $BackupFolder

    New-SmbShare -Name $using:BackupFolderName -Path $BackupFolder.FullName -FullAccess "Administrators", "$using:SQLServicesADGroup"
    #endregion 
    
    #region Creating dedicated folders for File Share Witness
    $FileShareWitness = New-Item -Path "$($StoragePool.DriveLetter):\$using:FileShareWitnessFolderName" -ItemType Directory
    #From https://blue42.net/windows/changing-ntfs-security-permissions-using-powershell/
    $existingAcl = Get-Acl $FileShareWitness
    <#
    #region Add Full Control access for the SQL Server nodes AD Group Group for "This folder, subfolders and files"
    $identity = $using:SQLServersADGroup
    $colRights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
    $objType = [System.Security.AccessControl.AccessControlType]::Allow
    # Create a new FileSystemAccessRule object
    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity,$colRights,$InheritanceFlag,$PropagationFlag, $objType)
    # Modify the existing ACL to include the new rule
    $existingAcl.SetAccessRule($AccessRule)
    #endregion 
    #>
    #region Add Full Control access for the Cluster Name Objects AD Group Group for "This folder, subfolders and files"
    $identity = $using:ClusterNameObjectsADGroup
    $colRights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
    $objType = [System.Security.AccessControl.AccessControlType]::Allow
    # Create a new FileSystemAccessRule object
    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity,$colRights,$InheritanceFlag,$PropagationFlag, $objType)
    # Modify the existing ACL to include the new rule
    $existingAcl.SetAccessRule($AccessRule)
    #endregion 

    # Apply the modified access rule to the folder
    $existingAcl | Set-Acl -Path $FileShareWitness

    New-SmbShare -Name $using:FileShareWitnessFolderName -Path $FileShareWitness.FullName -FullAccess "Administrators", "$using:SQLServersADGroup", "$using:ClusterNameObjectsADGroup"
    #endregion 

    #region Creating dedicated folders for sources files
    $SourcesFolder = New-Item -Path "$($StoragePool.DriveLetter):\$($using:SourcesFolderName)" -ItemType Directory
    #region Add Read access for the SQL Server nodes AD Group Group for "This folder, subfolders and files"
    #From https://blue42.net/windows/changing-ntfs-security-permissions-using-powershell/
    $existingAcl = Get-Acl $SourcesFolder
    $identity = $using:SQLServersADGroup
    $colRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
    $objType = [System.Security.AccessControl.AccessControlType]::Allow
    # Create a new FileSystemAccessRule object
    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity,$colRights,$InheritanceFlag,$PropagationFlag, $objType)
    # Modify the existing ACL to include the new rule
    $existingAcl.SetAccessRule($AccessRule)

    # Apply the modified access rule to the folder
    $existingAcl | Set-Acl -Path $SourcesFolder
    #endregion

    #Creating a dedicated file share
    New-SmbShare -Name $($using:SourcesFolderName) -Path $SourcesFolder.FullName -ReadAccess "$using:SQLServerSADGroup" -FullAccess "Administrators"
    #region Creating dedicated folders for SQL, Windows binairies and Powershell module
    $PowerShellModules = New-Item -Path $SourcesFolder -Name "PowerShellModules" -ItemType Directory -Force
    $SQLServerTools = New-Item -Path $SourcesFolder -Name "SQLServerTools" -ItemType Directory -Force
    $SQLScripts = New-Item -Path $SourcesFolder -Name "SQLScripts" -ItemType Directory -Force    
    $QLogic = New-Item -Path $SourcesFolder -Name "QLogic" -ItemType Directory -Force    
    $WindowsServer2019SourcesFolder = New-Item -Path $SourcesFolder -Name "WindowsServer2019\sources" -ItemType Directory -Force
    $WindowsServer2019ISOContent = Join-Path -Path $using:WindowsServer2019StandardMountedVolume.DriveLetter -ChildPath 'sources\sxs'
    $SQLServer2019Folder = New-Item -Path $SourcesFolder -Name "SQLServer2019" -ItemType Directory -Force
    $SQLServer2019UpdatesFolder = New-Item -Path $SQLServer2019Folder -Name "Updates" -ItemType Directory -Force
    #$SQLServer2019ISOContent = Join-Path -Path $using:SQLServer2019StandardMountedVolume.DriveLetter -ChildPath '*'
    $SQLServer2019ISOContent = Join-Path -Path $using:SQLServer2019EnterpriseMountedVolume.DriveLetter -ChildPath '*'
    $SQLServer2022Folder = New-Item -Path $SourcesFolder -Name "SQLServer2022" -ItemType Directory -Force
    $SQLServer2022UpdatesFolder = New-Item -Path $SQLServer2022Folder -Name "Updates" -ItemType Directory -Force
    #$SQLServer2022ISOContent = Join-Path -Path $using:SQLServer2022StandardMountedVolume.DriveLetter -ChildPath '*'
    $SQLServer2022ISOContent = Join-Path -Path $using:SQLServer2022EnterpriseMountedVolume.DriveLetter -ChildPath '*'

    #Copying SQL Server ISO content
    Copy-Item -Path $SQLServer2019ISOContent -Destination $SQLServer2019Folder -Recurse -Force
    Copy-Item -Path $SQLServer2022ISOContent -Destination $SQLServer2022Folder -Recurse -Force

    #Copying Sources\Sxs folder from the OS ISO
    #Copy-Item -Path $WindowsServer2019ISOContent -Destination $WindowsServer2019SourcesFolder -Recurse -Force
    #Copy-Item -Path $WindowsServer2022ISOContent -Destination $WindowsServer2022SourcesFolder -Recurse -Force

    #SQL Server Management Studio
    $SQLServerManagementStudioInstaller = Join-Path -Path $SQLServerTools -ChildPath 'SSMS-Setup-ENU.exe'
    #Invoke-WebRequest -Uri $using:SQLServerManagementStudioURI -OutFile $SQLServerManagementStudioInstaller -Verbose
    #Start-BitsTransfer -Source $using:SQLServerManagementStudioURI -Destination $SQLServerManagementStudioInstaller -Verbose

    #SQL Server 2019 Latest GDR: KB4583458 when writing
    $SQLServer2019LatestGDRInstaller = Join-Path -Path $SQLServer2019UpdatesFolder -ChildPath $(Split-Path -Path $using:SQLServer2019LatestGDRURI -Leaf)
    #Invoke-WebRequest -Uri $using:SQLServer2019LatestGDRURI -OutFile $SQLServer2019LatestGDRInstaller -Verbose
    #Start-BitsTransfer -Source $using:SQLServer2019LatestGDRURI -Destination $SQLServer2019LatestGDRInstaller -Verbose

    #SQL Server 2019 Latest Cumulative Update: KB5017593 - Cumulative Update 18 when writing/updating this script (October 2022)
    $SQLServer2019LatestCUInstaller = Join-Path -Path $SQLServer2019UpdatesFolder -ChildPath $(Split-Path -Path $using:SQLServer2019LatestCUURI -Leaf)
    #Invoke-WebRequest -Uri $using:SQLServer2019LatestCUURI -OutFile $SQLServer2019LatestCUInstaller -Verbose
    #Start-BitsTransfer -Source $using:SQLServer2019LatestCUURI -Destination $SQLServer2019LatestCUInstaller -Verbose

    #SQL Server 2022 Latest GDR
    $SQLServer2022LatestGDRInstaller = Join-Path -Path $SQLServer2022UpdatesFolder -ChildPath $(Split-Path -Path $using:SQLServer2022LatestGDRURI -Leaf)
    #Invoke-WebRequest -Uri $using:SQLServer2022LatestGDRURI -OutFile $SQLServer2022LatestGDRInstaller -Verbose
    #Start-BitsTransfer -Source $using:SQLServer2022LatestGDRURI -Destination $SQLServer2022LatestGDRInstaller -Verbose

    #SQL Server 2022 Latest Cumulative Update
    $SQLServer2022LatestCUInstaller = Join-Path -Path $SQLServer2022UpdatesFolder -ChildPath $(Split-Path -Path $using:SQLServer2022LatestCUURI -Leaf)
    #Invoke-WebRequest -Uri $using:SQLServer2022LatestCUURI -OutFile $SQLServer2022LatestCUInstaller -Verbose
    #Start-BitsTransfer -Source $using:SQLServer2022LatestCUURI -Destination $SQLServer2022LatestCUInstaller -Verbose

    Start-BitsTransfer -Source $using:SQLServerManagementStudioURI, $using:SQLServer2019LatestGDRURI, $using:SQLServer2019LatestCUURI, $using:SQLServer2022LatestGDRURI, $using:SQLServer2022LatestCUURI  -Destination $SQLServerManagementStudioInstaller, $SQLServer2019LatestGDRInstaller, $SQLServer2019LatestCUInstaller, $SQLServer2022LatestGDRInstaller, $SQLServer2022LatestCUInstaller -Verbose  

    #Installing required PowerShell modules from PowerShell Gallery
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    #Save-Module -Name ActiveDirectoryDsc, SqlServerDsc, SqlServer, ComputerManagementDsc, xPSDesiredStateConfiguration, xFailOverCluster -Path $PowerShellModules -Repository PSGallery -Verbose
    Save-Module -Name ActiveDirectoryDsc, SqlServerDsc, SqlServer, ComputerManagementDsc, xPSDesiredStateConfiguration, FailOverClusterDsc -Path $PowerShellModules -Repository PSGallery -Verbose
    #endregion
    #endregion

    #Installing SQL Management Studio for remote administrative purpose
    Start-Process -FilePath $SQLServerManagementStudioInstaller -ArgumentList "/install", "/passive", "/norestart" -Wait

    #To return the local path of the shared folder
    #$SourcesFolder
}

#Enabling AD Windows feature for the target servers
$Job += Install-LabWindowsFeature -FeatureName RSAT-AD-PowerShell -ComputerName $SQLServerNodes -IncludeManagementTools -AsJob -PassThru

#Enabling iSCSI Target with Admin Tools
Install-LabWindowsFeature -FeatureName FS-iSCSITarget-Server -ComputerName FS01 -IncludeManagementTools

#Getting SQL Nodes Initiator Ids
$InitiatorIds = Invoke-LabCommand -ActivityName 'Getting SQL Nodes Initiator Ids' -ComputerName $SQLServerNodes -PassThru -ScriptBlock {
    #Configuring MSiSCSI service
    Start-Service -Name MSiSCSI -PassThru | Set-Service -StartupType Automatic
    #Connecting to iSCSI
    "IQN:$((Get-WmiObject -Namespace root\wmi -Class MSiSCSIInitiator_MethodClass).iSCSINodeName)"
}

#Restore-LabVMSnapshot -SnapshotName 'BeforeiSCSI' -All -Verbose

Invoke-LabCommand -ActivityName 'Setting up iSCSI' -ComputerName FS01 -ScriptBlock {
    #$InitiatorIds = $using:SQLServerNodes | ForEach-Object -Process { "IQN:iqn.1991-05.com.microsoft:$($_.FQDN)"}
    $iSCSIVirtualDiskFolder = New-Item -Path D:\iSCSIVirtualDisks -ItemType Directory -Force
    foreach($i in 1..$using:iSCSIVirtualDiskNumber) {
        $Index = "{0:D2}" -f $i
        $IscsiVirtualDisk = Join-Path -Path $iSCSIVirtualDiskFolder -ChildPath "iSCSIVDisk$($Index).vhdx"
        $TargetName = "TargetName$($Index)"
        New-IscsiVirtualDisk -Path $IscsiVirtualDisk -Size 10GB
        New-IscsiServerTarget -TargetName $TargetName -InitiatorId $using:InitiatorIds
        Add-IscsiVirtualDiskTargetMapping -TargetName $TargetName -DevicePath $IscsiVirtualDisk
    }
}

Invoke-LabCommand -ActivityName 'Installing required PowerShell modules from the file share & Configuring MSiSCSI service' -ComputerName $SQLServerNodes -ScriptBlock {
    #Adding the SQLAdmin as local administrator for all SQL servers
    Add-LocalGroupMember -Group Administrators -Member $using:NetBiosDomainName\$using:SQLAdmin
    #Installing the required PowerShell Modules via the file share (offline mode)
    Copy-Item \\FS01\$($using:SourcesFolderName)\PowerShellModules\* $env:ProgramFiles\WindowsPowerShell\Modules -Recurse -Force

    #Installing Group Managed Service account on the target node for SQL Server Always On Availability Group
    Install-ADServiceAccount $using:gMSASqlServiceName
    #Test-ADServiceAccount $using:gMSASqlService
    #Get-ADServiceAccount $using:gMSASqlService -Property PasswordLastSet
}

Invoke-LabCommand -ActivityName 'Setting up iSCSI' -ComputerName $SQLServerNodes -ScriptBlock {
    #Start-Process -FilePath "iscsicli" -ArgumentList "addTargetPortal", "FS01", "3260"
    New-IscsiTargetPortal -TargetPortalAddress "FS01"
    Get-IscsiTarget | Connect-IscsiTarget -IsPersistent $true
}

#Unmouting the ISOs
Dismount-LabIsoImage -ComputerName $AllLabVMs -Verbose

Invoke-LabCommand -ActivityName 'Taking the disk online and initialize it' -ComputerName SQLNODE01 -ScriptBlock {
    #Last drive letter in the alphabetical order
    $DriveLetter = (Get-PSDrive -PSProvider FileSystem | Sort-Object -Property Name -Descending | Select-Object -Property Name -First 1).Name
    $OfflineDisks = Get-Disk | Sort-Object -Property Number | Where-Object -FilterScript { $_.IsOffline -eq $true }
    #Get-Disk -Number 2,3,4 | Clear-Disk -RemoveData -Confirm:$false -PassThru | Set-Disk -IsOffline $True
    $OfflineDisks | Initialize-Disk -PassThru | ForEach-Object -Process {
        if ($DriveLetter -eq 'Z')
        {
                break   
        }
        #Next drive letter (in the alphabetical order)
        $DriveLetter = [char](([int][char]$DriveLetter)+1)
        $_ | New-Volume -FileSystem NTFS -DriveLetter $DriveLetter -FriendlyName "FCI_$DriveLetter"
    }
}

#Copying the DSC Script to the dedicated folder
Copy-LabFileItem -Path $(Join-Path -Path $CurrentDir -ChildPath "SQLServer2022\AG") -ComputerName $SQLServerNodes -DestinationFolderPath $WorkSpace -Recurse
Copy-LabFileItem -Path $(Join-Path -Path $CurrentDir -ChildPath "SQLServer2022\FCI") -ComputerName $SQLServerNodes -DestinationFolderPath $WorkSpace -Recurse

Invoke-LabCommand -ActivityName 'Disabling Windows Update service' -ComputerName $AllLabVMs -ScriptBlock {
    Stop-Service WUAUSERV -PassThru | Set-Service -StartupType Disabled
} 

$Job | Wait-Job | Out-Null

<#
Invoke-LabCommand -ActivityName 'Clearing "Microsoft-Windows-Dsc/Operational" eventlog' -ComputerName $SQLServerNodes -ScriptBlock {
    [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog("Microsoft-Windows-Dsc/Operational")
}
#>

Show-LabDeploymentSummary -Detailed
Checkpoint-LabVM -SnapshotName 'FullInstall' -All
<#
Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All
Invoke-LabCommand -ActivityName "Removing $Labname folder" -ComputerName $SQLServerNodes -ScriptBlock { Remove-Item -Path $using:WorkSpace -Recurse -Force} -Verbose
Copy-LabFileItem -Path $(Join-Path -Path $CurrentDir -ChildPath "SQLServer2022\AG") -ComputerName $SQLServerNodes -DestinationFolderPath $WorkSpace -Recurse
Copy-LabFileItem -Path $(Join-Path -Path $CurrentDir -ChildPath "SQLServer2022\FCI") -ComputerName $SQLServerNodes -DestinationFolderPath $WorkSpace -Recurse
#>

<#
Invoke-LabCommand -ActivityName 'Setting up AG Cluster' -ComputerName SQLNode01 -ScriptBlock {
    & "$($using:Workspace)\AG\CreateClusterWithTwoNodes.ps1"
} -AsJob
#>

<#
Invoke-LabCommand -ActivityName 'Setting up FCI Cluster' -ComputerName SQLNode01 -ScriptBlock {
    & "$($using:Workspace)\FCI\CreateClusterWithThreeNodes.ps1"
} -AsJob
#>
$VerbosePreference = $PreviousVerbosePreference
$ErrorActionPreference = $PreviousErrorActionPreference

Stop-Transcript