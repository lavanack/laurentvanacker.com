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
#requires -Version 5 -Modules AutomatedLab, iSCSIDsc -RunAsAdministrator

[CmdletBinding()]
param
(
    [switch] $WindowsUpdate
)

trap {
    Write-Host "Stopping Transcript ..."
    Stop-Transcript
    $VerbosePreference = $PreviousVerbosePreference
    $ErrorActionPreference = $PreviousErrorActionPreference
    [console]::beep(3000, 750)
    Send-ALNotification -Activity 'Lab started' -Message ('Lab deployment failed !') -Provider (Get-LabConfigurationItem -Name Notifications.SubscribedProviders)
    break
}

#region Function Definition(s)
Function Get-LatestSQLServerUpdate {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [ValidateSet('SQLServer2019', 'SQLServer2022')]
        [Alias('SQLServerVersion')]
        [string[]] $Version = @('SQLServer2019', 'SQLServer2022'),
        [string] $DownloadFolder
    )
    $DataURI = @{
        "SQLServer2019" = "https://raw.githubusercontent.com/MicrosoftDocs/SupportArticles-docs/refs/heads/main/support/sql/releases/sqlserver-2019/build-versions.md"
        "SQLServer2022" = "https://raw.githubusercontent.com/MicrosoftDocs/SupportArticles-docs/refs/heads/main/support/sql/releases/sqlserver-2022/build-versions.md"
    }
    $LatestSQLServerUpdate = foreach ($CurrentVersion in $Version) {
        $CurrentDataURI = $DataURI[$CurrentVersion]
        $LatestCUData = $LatestCUData = (Invoke-RestMethod -Uri $CurrentDataURI) -split "`r|`n" | Select-String -Pattern "(?<CU>CU\d+)\s+\(Latest\)(.*)\[(?<KB>KB\d+)\]\((?<Link>.*)\).*\|(?<Date>.*)\|"
        $LatestCU = ($LatestCUData.Matches.Groups.Captures | Where-Object -FilterScript { $_.Name -eq 'CU' }).Value
        $LatestCUKB = ($LatestCUData.Matches.Groups.Captures | Where-Object -FilterScript { $_.Name -eq 'KB' }).Value
        $LatestCUKBURI = ($LatestCUData.Matches.Groups.Captures | Where-Object -FilterScript { $_.Name -eq 'Link' }).Value
        $LatestCUDate = [datetime]::Parse(($LatestCUData.Matches.Groups.Captures | Where-Object -FilterScript { $_.Name -eq 'Date' }).Value)
        $LatestGDRData = (Invoke-RestMethod -Uri $CurrentDataURI) -split "`r|`n" | Select-String -Pattern "\|\s+GDR\s+\|(.*)\[(?<KB>KB\d+)\]\((?<Link>.*)\).*\|(?<Date>.*)\|" | Select-Object -First 1
        $LatestGDRKB = ($LatestGDRData.Matches.Groups.Captures | Where-Object -FilterScript { $_.Name -eq 'KB' }).Value
        $LatestGDRKBURI = ($LatestGDRData.Matches.Groups.Captures | Where-Object -FilterScript { $_.Name -eq 'Link' }).Value
        $LatestGDRDate = [datetime]::Parse(($LatestGDRData.Matches.Groups.Captures | Where-Object -FilterScript { $_.Name -eq 'Date' }).Value)

        $LatestCUKBURI = ($(Split-Path -Path $CurrentDataURI -Parent) + "/" + $LatestCUKBURI) -replace "\\", "/"
        $LatestCUKBURIData = (Invoke-RestMethod -Uri $LatestCUKBURI) -split "`r|`n" | Select-String -Pattern "\((?<LatestCUURI>https://www.microsoft.com/download/details.aspx.*)\)"
        $LatestCUURI = ($LatestCUKBURIData.Matches.Groups.Captures | Where-Object -FilterScript { $_.Name -eq 'LatestCUURI' }).Value
        $LatestGDRURI = ((Invoke-WebRequest  -Uri $LatestGDRKBURI -UseBasicParsing).Links | Where-Object -FilterScript { $_.outerHTML -match "Download the package now" }).href

        #Sometimes Invoke-WebRequest returns a WebException
        Do {
            try {
                $LatestCUURI = ($(Invoke-WebRequest -Uri $LatestCUURI -UseBasicParsing).Links | Where-Object -FilterScript { $_.outerHTML -match "KB.*\.exe" } | Select-Object -Unique).href
                $Success = $true
            }
            catch {
                $Success = $false
            }
        } While (-not($Success))

        #Sometimes Invoke-WebRequest returns a WebException
        Do {
            try {
                $LatestGDRURI = ($(Invoke-WebRequest -Uri $LatestGDRURI -UseBasicParsing).Links | Where-Object -FilterScript { $_.outerHTML -match "KB.*\.exe" } | Select-Object -Unique).href
            }
            catch {
                $Success = $false
            }
        } While (-not($Success))


        if ($DownloadFolder) {
            [PSCustomObject]@{
                Version = $CurrentVersion
                GDR     = [PSCustomObject]@{
                    KB        = $LatestGDRKB
                    Date      = $LatestGDRDate
                    URI       = $LatestGDRURI
                    LocalFile = Join-Path -Path $DownloadFolder -ChildPath $(Split-Path -Path $LatestGDRURI -Leaf)
                }
                CU      = [PSCustomObject]@{
                    Number    = $LatestCU
                    KB        = $LatestCUKB
                    Date      = $LatestCUDate
                    URI       = $LatestCUURI; 
                    LocalFile = Join-Path -Path $DownloadFolder -ChildPath $(Split-Path -Path $LatestCUURI -Leaf)
                }
            }
        }
        else {
            [PSCustomObject]@{
                Version = $CurrentVersion
                GDR     = [PSCustomObject]@{
                    KB   = $LatestGDRKB
                    Date = $LatestGDRDate
                    URI  = $LatestGDRURI; 
                }
                CU      = [PSCustomObject]@{
                    Number = $LatestCU
                    KB     = $LatestCUKB
                    Date   = $LatestCUDate
                    URI    = $LatestCUURI; 
                }
            }
        }
    }
    $LatestSQLServerUpdate

    if ($DownloadFolder) {
        [string[]]$Source = $LatestSQLServerUpdate.CU.URI
        $Source += $LatestSQLServerUpdate.GDR.URI

        [string[]]$Destination = $LatestSQLServerUpdate.CU.LocalFile
        $Destination += $LatestSQLServerUpdate.GDR.LocalFile

        Start-BitsTransfer -Source $Source -Destination $Destination
    }

}
#endregion

#region Main code
Clear-Host

$PreviousVerbosePreference = $VerbosePreference
$VerbosePreference = 'SilentlyContinue'
$PreviousErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = 'SilentlyContinue'
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$TranscriptFile = $CurrentScript -replace ".ps1$", "$("_{0}.txt" -f (Get-Date -Format 'yyyyMMddHHmmss'))"
Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader

#region Global variables definition
$Now = Get-Date
$5YearsFromNow = $Now.AddYears(5)
$CertValidityPeriod = New-TimeSpan -Start $Now -End $5YearsFromNow
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
$PSWSAppPoolUsr = 'PSWSAppPoolUsr'

#region SQL Server
#SQL Server Management Studio
$SQLServerManagementStudioURI = 'https://aka.ms/ssms/21/release/vs_SSMS.exe'
$SQLServerManagementStudioSetupFileName = Split-Path -Path $SQLServerManagementStudioURI -Leaf

#region SQL Server 2019
$SQLServer2019EnterpriseISO = "$labSources\ISOs\en_sql_server_2019_enterprise_x64_dvd_5e1ecc6b.iso"
#SQL Server 2019 Latest GDR: KB5046859 when writing/updating this script (May 2025)
#$SQLServer2019LatestGDRURI = ($(Invoke-WebRequest -Uri https://www.microsoft.com/en-us/download/details.aspx?id=106324 -UseBasicParsing).Links | Where-Object -FilterScript { $_.outerHTML -match "KB.*\.exe" } | Select-Object -Unique).href
#SQL Server 2019 Latest Cumulative Update: KB5054833 when writing/updating this script (May 2025)
#$SQLServer2019LatestCUURI = ($(Invoke-WebRequest -Uri https://www.microsoft.com/en-us/download/details.aspx?id=100809 -UseBasicParsing).Links | Where-Object -FilterScript { $_.outerHTML -match "KB.*\.exe" } | Select-Object -Unique).href
#endregion

#region SQL Server 2022
$SQLServer2022EnterpriseISO = "$labSources\ISOs\enu_sql_server_2022_enterprise_edition_x64_dvd_aa36de9e.iso"
#SQL Server 2022 Latest GDR: KB5021522 when writing/updating this script (May 2025)
#$SQLServer2022LatestGDRURI = ($(Invoke-WebRequest -Uri https://www.microsoft.com/en-us/download/details.aspx?id=106322 -UseBasicParsing).Links | Where-Object -FilterScript { $_.outerHTML -match "KB.*\.exe" } | Select-Object -Unique).href
#SQL Server 2022 Latest Cumulative Update: KB5032679 when writing/updating this script (May 2025)
#$SQLServer2022LatestCUURI = ($(Invoke-WebRequest -Uri https://www.microsoft.com/en-us/download/details.aspx?id=105013 -UseBasicParsing).Links | Where-Object -FilterScript { $_.outerHTML -match "KB.*\.exe" } | Select-Object -Unique).href
#endregion

#region Alternative by using the Get-LatestSQLServerUpdate function
$LatestSQLServerUpdateHT = Get-LatestSQLServerUpdate | Group-Object -Property Version -AsHashTable -AsString
$SQLServer2019LatestGDRURI = $LatestSQLServerUpdateHT["SQLServer2019"].GDR.URI
$SQLServer2019LatestCUURI = $LatestSQLServerUpdateHT["SQLServer2019"].CU.URI
$SQLServer2022LatestGDRURI = $LatestSQLServerUpdateHT["SQLServer2022"].GDR.URI
$SQLServer2022LatestCUURI = $LatestSQLServerUpdateHT["SQLServer2022"].CU.URI
#endregion

#endregion

$NetworkID = '10.0.0.0/24' 
$DC01IPv4Address = '10.0.0.1'
$FS01IPv4Address = '10.0.0.21'
$PULLIPv4Address = '10.0.0.31'
$SQLIPv4Address = '10.0.0.41'
$SQLNODE01IPv4Address = '10.0.0.11'
$SQLNODE02IPv4Address = '10.0.0.12'
$SQLNODE03IPv4Address = '10.0.0.13'

#Using half of the logical processors to speed up the deployement
[int]$LabMachineDefinitionProcessors = [math]::Max(1, (Get-CimInstance -ClassName Win32_Processor).NumberOfLogicalProcessors / 2)

#Latest Edge version URI
$MSEdgeEntUri = "http://go.microsoft.com/fwlink/?LinkID=2093437"
#URI for the PowerBI Desktop
$PBIDesktopX64Uri = "https://download.microsoft.com/download/8/8/0/880BCA75-79DD-466A-927D-1ABF1F5454B0/PBIDesktopSetup_x64.exe"

#For Job tracking
$Job = @()

$LabName = 'SQLDSCSQLReporting'
$iSCSIVirtualDiskNumber = 3 

$WorkSpace = Join-Path -Path $env:SystemDrive -ChildPath $LabName
#endregion

#Cleaning previously existing lab
if ($LabName -in (Get-Lab -List)) {
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
    'Add-LabMachineDefinition:Processors'      = 2
}

#region Net Adapter definitions
$DC01NetAdapter = @()
$DC01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $DC01IPv4Address -InterfaceName Corp
#Adding an Internet Connection
$DC01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp -InterfaceName Internet

$SQLNetAdapter = @()
$SQLNetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $SQLIPv4Address -InterfaceName Corp
#Adding an Internet Connection
$SQLNetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp -InterfaceName Internet

$SQLNODE01NetAdapter = @()
$SQLNODE01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $SQLNODE01IPv4Address -InterfaceName Corp
#Adding an Internet Connection
$SQLNODE01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp -InterfaceName Internet

$SQLNODE02NetAdapter = @()
$SQLNODE02NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $SQLNODE02IPv4Address -InterfaceName Corp
#Adding an Internet Connection
$SQLNODE02NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp -InterfaceName Internet

$SQLNODE03NetAdapter = @()
$SQLNODE03NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $SQLNODE03IPv4Address -InterfaceName Corp
#Adding an Internet Connection
$SQLNODE03NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp -InterfaceName Internet

$FS01NetAdapter = @()
$FS01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $FS01IPv4Address -InterfaceName Corp
#Adding an Internet Connection
$FS01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp -InterfaceName Internet

$PULLNetAdapter = @()
$PULLNetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $PULLIPv4Address -InterfaceName Corp
#Adding an Internet Connection on the DC (Required for PowerShell Gallery)
$PULLNetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp -InterfaceName Internet
#endregion 

#region server definitions
#Domain controller + Certificate Authority
Add-LabMachineDefinition -Name DC01 -Roles RootDC, CARoot -NetworkAdapter $DC01NetAdapter -Memory 1GB -MaxMemory 2GB
#PULL Server
Add-LabMachineDefinition -Name PULL -NetworkAdapter $PULLNetAdapter
#SQL Servers
#SQL Server for DSC Reporting
$SQLServer2022Role = Get-LabMachineRoleDefinition -Role SQLServer2022
Add-LabIsoImageDefinition -Name SQLServer2022 -Path $SQLServer2022EnterpriseISO
Add-LabMachineDefinition -Name SQL -Roles $SQLServer2022Role -NetworkAdapter $SQLNetAdapter #-Processors 4 #-Memory 4GB -MinMemory 2GB -MaxMemory 4GB

Add-LabDiskDefinition -Name DataSQLNODE01 -DiskSizeInGb 10 -Label "SQL" -DriveLetter D
Add-LabMachineDefinition -Name SQLNODE01 -NetworkAdapter $SQLNODE01NetAdapter -Disk DataSQLNODE01

Add-LabDiskDefinition -Name DataSQLNODE02 -DiskSizeInGb 10 -Label "SQL" -DriveLetter D
Add-LabMachineDefinition -Name SQLNODE02 -NetworkAdapter $SQLNODE02NetAdapter -Disk DataSQLNODE02

Add-LabDiskDefinition -Name DataSQLNODE03 -DiskSizeInGb 10 -Label "SQL" -DriveLetter D
Add-LabMachineDefinition -Name SQLNODE03 -NetworkAdapter $SQLNODE03NetAdapter -Disk DataSQLNODE03

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
$InternetConnectedVMs = ($AllLabVMs | Get-VMNetworkAdapter -Name "Default Switch").VMName
$SQLServerNodes = $AllLabVMs | Where-Object -FilterScript { $_.Name -match "^SQL" }
$SQLServerTargetNodes = $AllLabVMs | Where-Object -FilterScript { $_.Name -match "^SQLNode" }
$Job += Install-LabWindowsFeature -FeatureName Telnet-Client -ComputerName $AllLabVMs -IncludeManagementTools -AsJob -PassThru

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

    #Creating user for the PSWS application pool used for the Pull web site to replace localsystem by this user
    New-ADUser -Name $Using:PSWSAppPoolUsr -AccountPassword $using:SecurePassword -PasswordNeverExpires $true -CannotChangePassword $True -Enabled $true -Description "PSWS Application Pool User"

    #region DNS management
    #Reverse lookup zone creation
    #Add-DnsServerPrimaryZone -NetworkID $using:NetworkID -ReplicationScope 'Forest' 
    #endregion

    #Creating a GPO at the domain level for certificate autoenrollment
    $DefaultNamingContext = (Get-ADRootDSE).defaultNamingContext

    #region IE Settings
    $GPO = New-GPO -Name "IE Settings" | New-GPLink -Target $DefaultNamingContext
    #Disabling IE ESC
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -ValueName IsInstalled -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -value 0
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -ValueName IsInstalled -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -value 0
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap' -ValueName IEHarden -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -value 0
    #endregion

    #region Edge Settings
    $GPO = New-GPO -Name "Edge Settings" | New-GPLink -Target $DefaultNamingContext
    # https://devblogs.microsoft.com/powershell-community/how-to-change-the-start-page-for-the-edge-browser/
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Software\Policies\Microsoft\Edge' -ValueName "RestoreOnStartup" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 4

    #Bonus : To open the .net core website on all machines
    $StartPage = "https://pull.$($using:FQDNDomainName)/PSDSCPullServer.svc/`$metadata"
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Software\Policies\Microsoft\Edge\RestoreOnStartupURLs' -ValueName 0 -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "$StartPage"

    #Hide the First-run experience and splash screen on Edge : https://docs.microsoft.com/en-us/deployedge/microsoft-edge-policies#hidefirstrunexperience
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\SOFTWARE\Policies\Microsoft\Edge' -ValueName "HideFirstRunExperience" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
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
    $ADGroup | Add-ADGroupMember -Members $(Get-ADComputer -Filter 'Name -like "*SQL*"' | ForEach-Object -Process { "$($_.Name)$" })

    #Creating dedicated AD security group for SQL Server services account
    $ADGroup = New-ADGroup -Name "$using:SQLServicesADGroup" -SamAccountName $using:SQLServicesADGroup -GroupCategory Security -GroupScope Global -DisplayName "$using:SQLServicesADGroup" -Path "CN=Users,DC=$($using:FQDNDomainName -split "\." -join ",DC=")" -Description "SQL Services AD Group" -PassThru
    $ADGroup | Add-ADGroupMember -Members $using:SQLAdmin

    #Creating dedicated AD security group for SQL servers
    $ADGroup = New-ADGroup -Name "$using:ClusterNameObjectsADGroup" -SamAccountName $using:ClusterNameObjectsADGroup -GroupCategory Security -GroupScope Global -DisplayName "$using:ClusterNameObjectsADGroup" -Path "CN=Computers,DC=$($using:FQDNDomainName -split "\." -join ",DC=")" -Description "Cluster Name Objects AD Group" -PassThru

    #Configuring key distribution service (KDS)
    #From https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/create-the-key-distribution-services-kds-root-key#to-create-the-kds-root-key-using-the-add-kdsrootkey-cmdlet
    $KdsRootKey = Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))

    #Creating a new group managed service account
    New-ADServiceAccount -name $using:gMSASqlServiceName -DNSHostName $using:gMSASqlServiceDNSHostName -PrincipalsAllowedToRetrieveManagedPassword "$using:SQLServerSADGroup" 

    #Allowing the gMSA account to register its service principal name (SPN) for Kerberos authentication in SQL Server.
    dsacls (Get-ADServiceAccount -Identity $using:gMSASqlServiceName).DistinguishedName /G "SELF:RPWP;servicePrincipalName" 
}

Copy-LabFileItem -Path $CurrentDir\CreateDscSqlDatabase.ps1 -DestinationFolderPath C:\Temp -ComputerName SQL
Invoke-LabCommand -ActivityName 'Add Permissions to SQL Database for DSC Reporting' -ComputerName SQL -ScriptBlock {
    C:\Temp\CreateDscSqlDatabase.ps1 -DomainAndComputerName $using:NetBiosDomainName\$using:PSWSAppPoolUsr
} -Verbose

#region Certification Authority : Creation and SSL Certificate Generation
#Get the CA
$CertificationAuthority = Get-LabIssuingCA
#Generating a new template for 5-year SSL Web Server certificate
New-LabCATemplate -TemplateName WebServer5Years -DisplayName 'WebServer5Years' -SourceTemplateName WebServer -ApplicationPolicy 'Server Authentication' -EnrollmentFlags Autoenrollment -PrivateKeyFlags AllowKeyExport -Version 2 -SamAccountName 'Domain Computers' -ValidityPeriod $CertValidityPeriod -ComputerName $CertificationAuthority -Verbose
#Generating a new template for 5-year document encryption certificate
New-LabCATemplate -TemplateName DocumentEncryption5Years -DisplayName 'DocumentEncryption5Years' -SourceTemplateName CEPEncryption -ApplicationPolicy 'Document Encryption' -KeyUsage KEY_ENCIPHERMENT, DATA_ENCIPHERMENT -EnrollmentFlags Autoenrollment -PrivateKeyFlags AllowKeyExport -SamAccountName 'Domain Computers' -ValidityPeriod $CertValidityPeriod -ComputerName $CertificationAuthority

#Requesting a Web Server Certificate for the IIS Pull Server
$PULLWebSiteSSLCert = Request-LabCertificate -Subject "CN=pull.$FQDNDomainName" -SAN "pull", "pull.$FQDNDomainName" -TemplateName WebServer5Years -ComputerName PULL -PassThru
$PULLDocumentEncryptionCert = Request-LabCertificate -Subject "CN=pull.$FQDNDomainName" -SAN "pull", "pull.$FQDNDomainName" -TemplateName DocumentEncryption5Years -ComputerName PULL -PassThru

foreach ($CurrentSQLServerTargetNodeName in $SQLServerTargetNodes.Name) {
    Write-Verbose -Message "Requesting a Document Encryption Certificate for '$CurrentSQLServerTargetNodeName' ..."
    $null = Request-LabCertificate -Subject "CN=$CurrentSQLServerTargetNodeName.$FQDNDomainName" -SAN "$CurrentSQLServerTargetNodeName", "$CurrentSQLServerTargetNodeName.$FQDNDomainName" -TemplateName DocumentEncryption5Years -ComputerName $CurrentSQLServerTargetNodeName -PassThru
}
#endregion

#Restart if required to use Install-ADServiceAccount later
Restart-LabVM -ComputerName $SQLServerTargetNodes -Wait

#Mouting the SQL Server ISO for Copying SQL Server setup binaries on the file server
$WindowsServer2022ISO = ($SQLServerTargetNodes | Select-Object -First 1).OperatingSystem.IsoPath

#$SQLServer2019StandardMountedVolume = Mount-LabIsoImage -IsoPath $SQLServer2019StandardISO -ComputerName FS01 -PassThru
$SQLServer2022EnterpriseMountedVolume = Mount-LabIsoImage -IsoPath $SQLServer2022EnterpriseISO -ComputerName FS01 -PassThru
$SQLServer2019EnterpriseMountedVolume = Mount-LabIsoImage -IsoPath $SQLServer2019EnterpriseISO -ComputerName FS01 -PassThru
$WindowsServer2022ISOMountedVolume = Mount-LabIsoImage -IsoPath $WindowsServer2022ISO -ComputerName FS01 -PassThru

#region Installing Edge on all machines
$MSEdgeEnt = Get-LabInternetFile -Uri $MSEdgeEntUri -Path $labSources\SoftwarePackages -PassThru -Force
$Job += Install-LabSoftwarePackage -ComputerName $AllLabVMs -Path $MSEdgeEnt.FullName -CommandLine "/passive /norestart" -AsJob -PassThru
#endregion

#region Installing PowerBI on PULL server
$PBIDesktopX64 = Get-LabInternetFile -Uri $PBIDesktopX64Uri -Path $labSources\SoftwarePackages -PassThru -Force
$Job += Install-LabSoftwarePackage -ComputerName PULL -Path $PBIDesktopX64.FullName -CommandLine "-passive -norestart LANGUAGE=en-us ACCEPT_EULA=1 INSTALLDESKTOPSHORTCUT=0" -AsJob -PassThru
#endregion

#region Copying PowerBI Dashboard on PULL server
#cf. https://docs.microsoft.com/en-us/archive/blogs/fieldcoding/visualize-dsc-reporting-with-powerbi#powerbi---the-interesting-part
#Copying the DSC Dashboard on the machine where you have installed PowerBI Desktop 
Copy-LabFileItem -Path "$CurrentDir\DSC Dashboard.pbix" -ComputerName PULL
#Coping the PowerShell Script to have a local report of the DSC deployments
Copy-LabFileItem -Path "$CurrentDir\Get-DSC*.ps1" -ComputerName $SQLServerTargetNodes
#endregion

<#
#region Installing SQL Management Studio on the SQL Server Nodes
$SQLServerManagementStudio = Get-LabInternetFile -Uri $SQLServerManagementStudioURI -Path $labSources\SoftwarePackages -FileName $SQLServerManagementStudioSetupFileName -PassThru -Force
$Job += Install-LabSoftwarePackage -ComputerName $SQLServerNodes -Path $SQLServerManagementStudio.FullName -CommandLine " --passive --norestart" -AsJob -PassThru
#endregion
#>

$null = $Job | Receive-Job -Wait #-AutoRemoveJob
#Taking a snapshot/checkpoint
Checkpoint-LabVM -SnapshotName BeforeStorage -All -Verbose
#Restore-LabVMSnapshot -SnapshotName 'BeforeStorage' -All -Verbose

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
    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
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
    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
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
    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
    # Modify the existing ACL to include the new rule
    $existingAcl.SetAccessRule($AccessRule)

    # Apply the modified access rule to the folder
    $existingAcl | Set-Acl -Path $SourcesFolder
    #endregion

    #Creating a dedicated file share
    New-SmbShare -Name $($using:SourcesFolderName) -Path $SourcesFolder.FullName -ReadAccess "$using:SQLServerSADGroup" -FullAccess "Administrators"
    #region Creating dedicated folders for SQL Server, Windows binairies and Powershell modules
    $PowerShellModules = New-Item -Path $SourcesFolder -Name "PowerShellModules" -ItemType Directory -Force
    $SQLServerTools = New-Item -Path $SourcesFolder -Name "SQLServerTools" -ItemType Directory -Force
    $SQLScripts = New-Item -Path $SourcesFolder -Name "SQLScripts" -ItemType Directory -Force    
    $QLogic = New-Item -Path $SourcesFolder -Name "QLogic" -ItemType Directory -Force    
    $WindowsServer2022SourcesFolder = New-Item -Path $SourcesFolder -Name "WindowsServer2022\sources" -ItemType Directory -Force
    $WindowsServer2022ISOContent = Join-Path -Path $using:WindowsServer2022ISOMountedVolume.DriveLetter -ChildPath 'sources\sxs'
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
    Copy-Item -Path $WindowsServer2022ISOContent -Destination $WindowsServer2022SourcesFolder -Recurse -Force

    #SQL Server Management Studio
    $SQLServerManagementStudioInstaller = Join-Path -Path $SQLServerTools -ChildPath $using:SQLServerManagementStudioSetupFileName
    #Invoke-WebRequest -Uri $using:SQLServerManagementStudioURI -OutFile $SQLServerManagementStudioInstaller -Verbose
    #Start-BitsTransfer -Source $using:SQLServerManagementStudioURI -Destination $SQLServerManagementStudioInstaller -Verbose

    #SQL Server 2019 Latest GDR
    $SQLServer2019LatestGDRInstaller = Join-Path -Path $SQLServer2019UpdatesFolder -ChildPath $(Split-Path -Path $using:SQLServer2019LatestGDRURI -Leaf)
    #Invoke-WebRequest -Uri $using:SQLServer2019LatestGDRURI -OutFile $SQLServer2019LatestGDRInstaller -Verbose
    #Start-BitsTransfer -Source $using:SQLServer2019LatestGDRURI -Destination $SQLServer2019LatestGDRInstaller -Verbose

    #SQL Server 2019 Latest Cumulative Update
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
    #Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Get-PackageProvider -Name Nuget -ForceBootstrap -Force
    Save-Module -Name ActiveDirectoryDsc, SqlServerDsc, SqlServer, ComputerManagementDsc, xPSDesiredStateConfiguration, FailOverClusterDsc -Path $PowerShellModules -Repository PSGallery -Verbose
    #endregion
    #endregion

    #Installing SQL Management Studio for remote administrative purpose
    Start-Process -FilePath $SQLServerManagementStudioInstaller -ArgumentList " --passive --norestart" -Wait

    #To return the local path of the shared folder
    #$SourcesFolder
}

#Enabling AD Windows feature for the target servers
$Job += Install-LabWindowsFeature -FeatureName RSAT-AD-PowerShell -ComputerName $SQLServerTargetNodes -IncludeManagementTools -AsJob -PassThru

#Enabling iSCSI Target with Admin Tools
Install-LabWindowsFeature -FeatureName FS-iSCSITarget-Server -ComputerName FS01 -IncludeManagementTools

#Getting SQL Nodes Initiator Ids
$InitiatorIds = Invoke-LabCommand -ActivityName 'Getting SQL Nodes Initiator Ids' -ComputerName $SQLServerTargetNodes -PassThru -ScriptBlock {
    #Configuring MSiSCSI service
    Start-Service -Name MSiSCSI -PassThru | Set-Service -StartupType Automatic
    #Connecting to iSCSI
    "IQN:$((Get-WmiObject -Namespace root\wmi -Class MSiSCSIInitiator_MethodClass).iSCSINodeName)"
}

#Restore-LabVMSnapshot -SnapshotName 'BeforeiSCSI' -All -Verbose

Invoke-LabCommand -ActivityName 'Setting up iSCSI' -ComputerName FS01 -ScriptBlock {
    #$InitiatorIds = $using:SQLServerTargetNodes | ForEach-Object -Process { "IQN:iqn.1991-05.com.microsoft:$($_.FQDN)"}
    $iSCSIVirtualDiskFolder = New-Item -Path D:\iSCSIVirtualDisks -ItemType Directory -Force
    foreach ($i in 1..$using:iSCSIVirtualDiskNumber) {
        $Index = "{0:D2}" -f $i
        $IscsiVirtualDisk = Join-Path -Path $iSCSIVirtualDiskFolder -ChildPath "iSCSIVDisk$($Index).vhdx"
        $TargetName = "TargetName$($Index)"
        New-IscsiVirtualDisk -Path $IscsiVirtualDisk -Size 10GB
        New-IscsiServerTarget -TargetName $TargetName -InitiatorId $using:InitiatorIds
        Add-IscsiVirtualDiskTargetMapping -TargetName $TargetName -DevicePath $IscsiVirtualDisk
    }
}

Invoke-LabCommand -ActivityName 'Installing required PowerShell modules from the file share & Configuring MSiSCSI service' -ComputerName $SQLServerTargetNodes -ScriptBlock {
    #Adding the SQLAdmin as local administrator for all SQL servers
    Add-LocalGroupMember -Group Administrators -Member $using:NetBiosDomainName\$using:SQLAdmin
    #Installing the required PowerShell Modules via the file share (offline mode)
    Copy-Item \\FS01\$($using:SourcesFolderName)\PowerShellModules\* $env:ProgramFiles\WindowsPowerShell\Modules -Recurse -Force

    #Installing Group Managed Service account on the target node for SQL Server Always On Availability Group
    Install-ADServiceAccount $using:gMSASqlServiceName
    #Test-ADServiceAccount $using:gMSASqlService
    #Get-ADServiceAccount $using:gMSASqlService -Property PasswordLastSet
}

Invoke-LabCommand -ActivityName 'Setting up iSCSI' -ComputerName $SQLServerTargetNodes -ScriptBlock {
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
        if ($DriveLetter -eq 'Z') {
            #No drive letter available
            break   
        }
        #Next drive letter (in the alphabetical order)
        $DriveLetter = [char](([int][char]$DriveLetter) + 1)
        $_ | New-Volume -FileSystem NTFS -DriveLetter $DriveLetter -FriendlyName "FCI_$DriveLetter"
    }
}

Invoke-LabCommand -ActivityName 'Installing preprequisites for PULL server' -ComputerName PULL -ScriptBlock {
    #Adding TLS 1.2 to the supported protocol list
    Get-PackageProvider -Name Nuget -ForceBootstrap -Force
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Install-Module -Name xPSDesiredStateConfiguration -Scope AllUsers -Force -Verbose
    Install-WindowsFeature -Name Web-Server -IncludeManagementTools 
}

$null = $Job | Receive-Job -Wait #-AutoRemoveJob
#Taking a snapshot/checkpoint
Checkpoint-LabVM -SnapshotName BeforePullSetup -All -Verbose
#Restore-LabVMSnapshot -SnapshotName 'BeforePullSetup' -All -Verbose

Invoke-LabCommand -ActivityName 'Setting up the HTTPS Pull Server' -ComputerName PULL -ScriptBlock {
    Get-Website -Name "Default Web Site" | Remove-Website
    Configuration CreateHTTPSPullServer
    {
        param
        (
            [string[]] $ComputerName = 'localhost',
            [string] $Guid = $((New-Guid).Guid),
            [Parameter(Mandatory = $true)]
            [string] $CertificateThumbPrint
        )

        Import-DSCResource -ModuleName PSDesiredStateConfiguration
        Import-DSCResource -ModuleName xPSDesiredStateConfiguration

        Node $ComputerName
        {
            WindowsFeature DSCServiceFeature {
                Ensure = 'Present'
                Name   = 'DSC-Service'
            }
            WindowsFeature IISConsole {
                Ensure    = 'Present'
                Name      = 'Web-Mgmt-Console'
                DependsOn = '[WindowsFeature]DSCServiceFeature'
            }
            xDscWebService PSDSCPullServer {
                Ensure                       = 'Present'
                EndpointName                 = 'PSDSCPullServer'
                Port                         = 443
                PhysicalPath                 = "$env:SystemDrive\inetpub\wwwroot\PSDSCPullServer"
                CertificateThumbPrint        = $CertificateThumbPrint
                ModulePath                   = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Modules"
                ConfigurationPath            = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Configuration"
                State                        = 'Started'
                DependsOn                    = '[WindowsFeature]DSCServiceFeature'
                UseSecurityBestPractices     = $false
                AcceptSelfSignedCertificates = $false
                SqlProvider                  = $true
                SqlConnectionString          = "Provider=SQLOLEDB.1;Integrated Security=SSPI;Persist Security Info=False;Initial Catalog=master;Data Source=SQL"
            }
            File RegistrationKeyFile {
                Ensure          = "Present"
                Type            = "File"
                DestinationPath = "C:\Program Files\WindowsPowerShell\DscService\RegistrationKeys.txt"
                Contents        = $Guid
                DependsOn       = "[xDscWebService]PSDSCPullServer"
            }
        }
    }

    # Build the MOF
    CreateHTTPSPullServer -CertificateThumbPrint $PULLWebSiteSSLCert.Thumbprint

    # Apply the configuration.
    Start-DscConfiguration .\CreateHTTPSPullServer -Wait -Verbose -Force

    #Changing the application pool identity from localsystem to a domain account
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/applicationPools/add[@name='PSWS']/processModel" -name "identityType" -value "SpecificUser"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/applicationPools/add[@name='PSWS']/processModel" -name "userName" -value "$using:NetBiosDomainName\$using:PSWSAppPoolUsr"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/applicationPools/add[@name='PSWS']/processModel" -name "password" -value $using:ClearTextPassword
    Stop-WebAppPool -Name PSWS -ErrorAction Ignore
    Start-WebAppPool -Name PSWS
    
    #Disabling TLS 1.3 at the website level
    #Import-Module -Name IISAdministration
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Web.Administration") | Out-Null
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/site[@name='PSDSCPullServer']/bindings/binding[@protocol='https' and @bindingInformation='*:443:']" -name "sslFlags" -value $([Microsoft.Web.Administration.SslFlags]::DisableTLS13)
    #Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/site[@name='PSDSCPullServer']/bindings/binding[@protocol='https' and @bindingInformation='*:443:']" -name "sslFlags" -value 32

    <#
        #Disabling TLS 1.3 at the website level
        $DisableTLS13 = [Microsoft.Web.Administration.SslFlags]::DisableTLS13
        $BindingInformation = "*:443:secure.contoso.com"
        $siteName = "contoso"
        PhysicalPath = "$env:systemdrive\inetpub\wwwroot"
        $Thumbprint = $certificate.ThumbPrint
        $IISSite = New-IISSite -Name $siteName -PhysicalPath $PhysicalPath -BindingInformation $BindingInformation -Protocol https -CertificateThumbPrint $certificate.Thumbprint -SslFlag $DisableTLS13 -CertStoreLocation $storeLocation -passthru
    #>
} -Variable (Get-Variable -Name PULLWebSiteSSLCert) -Verbose

#Copying the DSC Script to the dedicated folder
Copy-LabFileItem -Path $(Join-Path -Path $CurrentDir -ChildPath "SQLServer2022\AG") -ComputerName $SQLServerTargetNodes -DestinationFolderPath $WorkSpace -Recurse
Copy-LabFileItem -Path $(Join-Path -Path $CurrentDir -ChildPath "SQLServer2022\FCI") -ComputerName $SQLServerTargetNodes -DestinationFolderPath $WorkSpace -Recurse
Copy-LabFileItem -Path $(Join-Path -Path $CurrentDir -ChildPath "SQLServer2022\DefaultInstance") -ComputerName $SQLServerTargetNodes -DestinationFolderPath $WorkSpace -Recurse
#Copy-LabFileItem -Path $(Join-Path -Path $CurrentDir -ChildPath "SQLServer2022\") -ComputerName $SQLServerTargetNodes -DestinationFolderPath $WorkSpace -Recurse


<#
Invoke-LabCommand -ActivityName 'Clearing "Microsoft-Windows-Dsc/Operational" eventlog' -ComputerName $SQLServerTargetNodes -ScriptBlock {
    [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog("Microsoft-Windows-Dsc/Operational")
}
#>

#$Job | Wait-Job | Out-Null
$null = $Job | Receive-Job -Wait #-AutoRemoveJob
if ($WindowsUpdate) {
    #region Windows Update
    Invoke-LabCommand -ActivityName 'Windows Udpate via the PSWindowsUpdate PowerShell Module' -ComputerName $InternetConnectedVMs -ScriptBlock {
        #Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        Get-PackageProvider -Name Nuget -ForceBootstrap -Force
        Install-Module -Name PSWindowsUpdate -Scope AllUsers -Force -AllowClobber
        Import-Module -Name PSWindowsUpdate 
        #From https://windows-hexerror.linestarve.com/q/so58570077-how-to-install-windows-updates-on-remote-computer-with-powershell: You can't Download or Install Updates on a machine from another remote machine. 
        #Get-WindowsUpdate -Install -AcceptAll -AutoReboot
        Invoke-WUJob -ComputerName localhost -Script { Import-Module PSWindowsUpdate ; Get-WindowsUpdate -Install -AcceptAll -AutoReboot -Verbose | Out-File "C:\PSWindowsUpdate_$('{0:yyyyMMddHHmmss}' -f (Get-Date)).log" -Append } -Confirm:$false -Verbose -RunNow
        #Start-ScheduledTask -TaskName PSWindowsUpdate -Verbose
        Do { Start-Sleep -Seconds 60 } While ((Get-ScheduledTask -TaskName PSWindowsUpdate).State -eq 'Running') 
    }
    #endregion

    $null = $Job | Receive-Job -Wait #-AutoRemoveJob
    #Taking a snapshot/checkpoint
    Checkpoint-LabVM -SnapshotName 'WindowsUpdate' -All
    #Restore-LabVMSnapshot -SnapshotName 'WindowsUpdate' -All -Verbose
}

Invoke-LabCommand -ActivityName 'Disabling Windows Update service' -ComputerName $AllLabVMs -ScriptBlock {
    Stop-Service WUAUSERV -PassThru | Set-Service -StartupType Disabled
} 

#Removing the Internet Connection on all VMS
Get-VM -Name $AllLabVMs | Where-Object -filterScript { $_.Name -notin "PULL" } | Remove-VMNetworkAdapter -Name 'Default Switch' -ErrorAction SilentlyContinue

$null = $Job | Receive-Job -Wait #-AutoRemoveJob
#Taking a snapshot/checkpoint
Checkpoint-LabVM -SnapshotName 'FullInstall' -All
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose

Show-LabDeploymentSummary
<#
Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All
Invoke-LabCommand -ActivityName "Removing '$WorkSpace' folder" -ComputerName $SQLServerTargetNodes -ScriptBlock { Remove-Item -Path $using:WorkSpace -Recurse -Force} -Verbose
Copy-LabFileItem -Path $(Join-Path -Path $CurrentDir -ChildPath "SQLServer2022\AG") -ComputerName $SQLServerTargetNodes -DestinationFolderPath $WorkSpace -Recurse
Copy-LabFileItem -Path $(Join-Path -Path $CurrentDir -ChildPath "SQLServer2022\DefaultInstance") -ComputerName $SQLServerTargetNodes -DestinationFolderPath $WorkSpace -Recurse
Copy-LabFileItem -Path $(Join-Path -Path $CurrentDir -ChildPath "SQLServer2022\FCI") -ComputerName $SQLServerTargetNodes -DestinationFolderPath $WorkSpace -Recurse
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
#endregion
#endregion