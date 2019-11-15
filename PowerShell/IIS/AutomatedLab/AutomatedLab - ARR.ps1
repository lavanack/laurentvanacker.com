#requires -Version 5 -RunAsAdministrator
Clear-Host
$PreviousVerbosePreference = $VerbosePreference
$VerbosePreference = 'Continue'
$ErrorActionPreference = 'Stop'
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$TranscriptFile = $CurrentScript -replace ".ps1$", "_$("{0:yyyyMMddHHmmss}" -f (get-date)).txt"
Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader

#region Global variables definition
$Logon = 'Administrator'
$ClearTextPassword = 'P@ssw0rd'
$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$NetBiosDomainName = 'CONTOSO'
$FQDNDomainName = 'contoso.com'
$IISAppPoolUser = 'IISAppPoolUser'
$WebSiteName="arr.$FQDNDomainName"

$LabName = 'ARRLab'
#endregion

#Dirty Clean up
If (Test-Path -Path C:\ProgramData\AutomatedLab\Labs\$LabName\Lab.xml)
{
    $Lab = Import-Lab -Path C:\ProgramData\AutomatedLab\Labs\$LabName\Lab.xml -ErrorAction SilentlyContinue -PassThru
    if ($Lab)
    {
        #Get-LabVM | Get-VM | Restore-VMCheckpoint -Name "FullInstall" -Confirm:$false
        $HyperVLabVM = Get-LabVM | Get-VM -ErrorAction SilentlyContinue
        if ($HyperVLabVM)
        {
            $HyperVLabVMPath = (Get-Item $($HyperVLabVM.Path)).Parent.FullName
            $HyperVLabVM | Stop-VM -TurnOff -Force -Passthru | Remove-VM -Force -Verbose
            Remove-Item $HyperVLabVMPath -Recurse -Force -Verbose #-WhatIf
        }
        try
        {
            Remove-Lab -Name $LabName -Verbose -Confirm:$false -ErrorAction SilentlyContinue
        }
        catch 
        {

        }
    }
}

#create an empty lab template and define where the lab XML files and the VMs will be stored
New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV

#make the network definition
Add-LabVirtualNetworkDefinition -Name $LabName -HyperVProperties @{
    SwitchType = 'Internal'
}  -AddressSpace 10.0.0.0/16

#and the domain definition with the domain admin account
Add-LabDomainDefinition -Name $FQDNDomainName -AdminUser $Logon -AdminPassword $ClearTextPassword

#these credentials are used for connecting to the machines. As this is a lab we use clear-text passwords
Set-LabInstallationCredential -Username $Logon -Password $ClearTextPassword

#defining default parameter values, as these ones are the same for all the machines
$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:Network'       = $LabName
    'Add-LabMachineDefinition:DomainName'    = $FQDNDomainName
    'Add-LabMachineDefinition:Memory'        = 2GB
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2016 Standard (Desktop Experience)'
    'Add-LabMachineDefinition:Processors'    = 2
}

#Domain controller
Add-LabMachineDefinition -Name DC01 -Roles RootDC -IpAddress 10.0.0.1
Add-LabMachineDefinition -Name CA01 -Roles CARoot -IpAddress 10.0.0.2

#IIS Front End
Add-LabMachineDefinition -Name IISNODE01 -IpAddress 10.0.0.11
Add-LabMachineDefinition -Name IISNODE02 -IpAddress 10.0.0.12

#3 NICS for ARR servers (1 for server communications, 1 for NLB and Default Switch for Internet)
$netAdapter = @()
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address 10.0.0.21/16
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address 10.0.0.201/16
Add-LabMachineDefinition -Name ARRNODE01 -NetworkAdapter $netAdapter

$netAdapter = @()
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address 10.0.0.22/16
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address 10.0.0.202/16
Add-LabMachineDefinition -Name ARRNODE02 -NetworkAdapter $netAdapter

#Installing servers
Install-Lab
#Checkpoint-LabVM -SnapshotName FreshInstall -All -Verbose


$machines = Get-LabVM
Install-LabWindowsFeature -FeatureName Telnet-Client -ComputerName $machines -IncludeManagementTools
Install-LabWindowsFeature -FeatureName FS-DFS-Replication, Web-Server, Web-Asp-Net45, Web-Request-Monitor -ComputerName IISNODE01, IISNODE02, ARRNODE01, ARRNODE02 -IncludeManagementTools
Install-LabWindowsFeature -FeatureName FS-DFS-Replication -ComputerName DC01 -IncludeManagementTools
Install-LabWindowsFeature -FeatureName NLB, Web-CertProvider -ComputerName ARRNODE01, ARRNODE02 -IncludeManagementTools
Install-LabWindowsFeature -FeatureName Web-Windows-Auth -ComputerName IISNODE01, IISNODE02 -IncludeManagementTools


$CertificationAuthority = Get-LabIssuingCA
New-LabCATemplate -TemplateName WebServerSSL -DisplayName 'Web Server SSL' -SourceTemplateName WebServer -ApplicationPolicy 'Server Authentication' -EnrollmentFlags Autoenrollment -PrivateKeyFlags AllowKeyExport -Version 2 -SamAccountName 'Domain Computers' -ComputerName $CertificationAuthority -ErrorAction Stop
$WebServerSSLCert = Request-LabCertificate -Subject "CN=$WebSiteName" -SAN "arr", "$WebSiteName", "ARRNODE01", "ARRNODE01.$FQDNDomainName", "ARRNODE02", "ARRNODE02.$FQDNDomainName" -TemplateName WebServerSSL -ComputerName ARRNODE01 -PassThru -ErrorAction Stop
Get-LabCertificate -ComputerName ARRNODE01 -SearchString "$WebSiteName" -FindType FindBySubjectName  -ExportPrivateKey -Password $SecurePassword | Add-LabCertificate -ComputerName ARRNODE02 -Store My -Password $ClearTextPassword

Invoke-LabCommand -ActivityName 'Exporting the Web Server Certificate into the future "Central Certificate Store" directory' -ComputerName ARRNODE01, ARRNODE02 -ScriptBlock {
    New-Item -Path C:\CentralCertificateStore -ItemType Directory -Force
    $WebServerSSLCert = Get-ChildItem -Path Cert:\LocalMachine\My\ -DnsName "$using:WebSiteName" -SSLServerAuthentication | Where-Object -FilterScript {
        $_.hasPrivateKey 
    }  
    if ($WebServerSSLCert)
    {
        $WebServerSSLCert | Export-PfxCertificate -FilePath "C:\CentralCertificateStore\$using:WebSiteName.pfx" -Password $Using:SecurePassword
        $WebServerSSLCert | Remove-Item -Force
        Import-PfxCertificate -FilePath "C:\CentralCertificateStore\$using:WebSiteName.pfx" -Password $Using:SecurePassword -CertStoreLocation Cert:\LocalMachine\My\ -Exportable 
    }
}

Invoke-LabCommand -ActivityName "Disabling IE ESC and Adding $WebSiteName to the IE intranet zone" -ComputerName $machines -ScriptBlock {
    #Disabling IE ESC
    $AdminKey = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}'
    $UserKey = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}'
    Set-ItemProperty -Path $AdminKey -Name 'IsInstalled' -Value 0 -Force
    Set-ItemProperty -Path $UserKey -Name 'IsInstalled' -Value 0 -Force

    #Setting arr.contoso.com, IISNODE01.contoso.com and IISNODE02.contoso.com in the Local Intranet Zone for all servers : mandatory for Kerberos authentication       
    $null = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$using:WebSiteName" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$using:WebSiteName" -Name http -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$using:WebSiteName" -Name https -Value 1 -Type DWord -Force
    $null = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\IISNODE01.$using:FQDNDomainName" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\IISNODE01.$using:FQDNDomainName" -Name http -Value 1 -Type DWord -Force
    #Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\IISNODE01.$using:FQDNDomainName" -Name https -Value 1 -Type DWord -Force
    $null = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\IISNODE02.$using:FQDNDomainName" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\IISNODE02.$using:FQDNDomainName" -Name http -Value 1 -Type DWord -Force
    #Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\IISNODE02.$using:FQDNDomainName" -Name https -Value 1 -Type DWord -Force
    $null = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\ARRNODE01.$using:FQDNDomainName" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\ARRNODE01.$using:FQDNDomainName" -Name http -Value 1 -Type DWord -Force
    #Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\ARRNODE01.$using:FQDNDomainName" -Name https -Value 1 -Type DWord -Force
    $null = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\ARRNODE02.$using:FQDNDomainName" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\ARRNODE02.$using:FQDNDomainName" -Name http -Value 1 -Type DWord -Force
    #Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\ARRNODE02.$using:FQDNDomainName" -Name https -Value 1 -Type DWord -Force

    #Changing the start page for IE
    $path = "HKCU:\Software\Microsoft\Internet Explorer\Main\"
    $name = "start page"
    $value = "https://$using:WebSiteName/"
    Set-ItemProperty -Path $path -Name $name -Value $value -Force
}

#Copying Web site content on all IIS & ARR servers
Copy-LabFileItem -Path $CurrentDir\arr.contoso.com.zip -DestinationFolderPath C:\Temp -ComputerName ARRNODE01, ARRNODE02, IISNODE01, IISNODE02

#Installing IIS and ASP.Net on all servers excepts DC
Invoke-LabCommand -ActivityName 'IIS Setup' -ComputerName IISNODE01, IISNODE02, ARRNODE01, ARRNODE02 -ScriptBlock {
    #Install-WindowsFeature FS-DFS-Replication, Web-Server,Web-Asp-Net45,Web-Request-Monitor -includeManagementTools
    #Removing "Default Web Site"
    Remove-WebSite -Name 'Default Web Site'

    #Creating a dedicated application pool
    New-WebAppPool -Name "$using:WebSiteName" -Force

    #Changing the application pool identity to classic mode (for ASP.Net impersonation)
    #Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='$using:WebSiteName']" -name "managedPipelineMode" -value "Classic"
    #Changing the application pool identity for an AD Account : mandatory for Kerberos authentication
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='$using:WebSiteName']/processModel" -name 'identityType' -value 3
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='$using:WebSiteName']/processModel" -name 'userName' -value "$Using:NetBiosDomainName\$Using:IISAppPoolUser"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='$using:WebSiteName']/processModel" -name 'password' -value $Using:ClearTextPassword

    #Creating a dedicated web site 
    New-WebSite -Name "$using:WebSiteName" -Port 80 -PhysicalPath "$env:systemdrive\inetpub\wwwroot" -Force
    #Assigning the the arr.contoso.com application pool to the arr.contoso.com web sitre
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:WebSiteName']/application[@path='/']" -name 'applicationPool' -value "$using:WebSiteName"
    #Enabling the Windows useAppPoolCredentials
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:WebSiteName" -filter 'system.webServer/security/authentication/windowsAuthentication' -name 'useAppPoolCredentials' -value 'True'

    #setting default.aspx as first default page
    Remove-WebconfigurationProperty -Filter 'system.webserver/defaultdocument/files' -Location "IIS:\sites\$using:WebSiteName" -name collection -AtElement @{
        value = 'default.aspx'
    } -Force
    Add-WebConfiguration -Filter 'system.webserver/defaultdocument/files' -Location "IIS:\sites\$using:WebSiteName" -atIndex 0 -Value @{
        value = 'default.aspx'
    } -Force
    
    Expand-Archive 'C:\Temp\arr.contoso.com.zip' -DestinationPath C:\inetpub\wwwroot -Force
    '<%=HttpContext.Current.Server.MachineName%>' | Out-File -FilePath 'C:\inetpub\wwwroot\server.aspx' -Force
    'ok' | Out-File -FilePath 'C:\inetpub\wwwroot\healthcheck.aspx' -Force
}

#Installing and setting up DFS-R on DC for replicated folder on ARR Servers for shared confguration
Invoke-LabCommand -ActivityName 'DNS & DFS-R Setup on DC' -ComputerName DC01 -ScriptBlock {
    New-ADUser -Name "$Using:IISAppPoolUser" -PasswordNeverExpires $True -AccountPassword $Using:SecurePassword -CannotChangePassword $True -Enabled $True

    #Reverse lookup zone creation
    Add-DnsServerPrimaryZone -NetworkID '10.0.0.0/16' -ReplicationScope 'Forest' 
    #DNS Host entry for the arr.contoso.com website 
    Add-DnsServerResourceRecordA -Name 'arr' -ZoneName $using:FQDNDomainName -IPv4Address '10.0.0.101' -CreatePtr
    #Installing DFS-R on ARR for the shared configuration
    #Install-WindowsFeature FS-DFS-Replication -includeManagementTools

    #Removing any DFS Replication group with the same name
    Get-DfsReplicationGroup -GroupName 'ARR Shared Configuration' | Remove-DfsReplicationGroup -Force -RemoveReplicatedFolders
    #Creating the DFS Replication group for the shared configuration
    New-DfsReplicationGroup -GroupName 'ARR Shared Configuration' |
    New-DfsReplicatedFolder -FolderName 'C:\ARRSharedConfiguration' |
    Add-DfsrMember -ComputerName ARRNODE01, ARRNODE02
    #Adding the member (replication in both ways)
    Add-DfsrConnection -GroupName 'ARR Shared Configuration' -SourceComputerName 'ARRNODE01' -DestinationComputerName 'ARRNODE02'
    #Adding the members and specifiyng the primary server
    Set-DfsrMembership -GroupName 'ARR Shared Configuration' -FolderName 'C:\ARRSharedConfiguration' -ContentPath 'C:\ARRSharedConfiguration' -ComputerName 'ARRNODE01' -PrimaryMember $True -Force
    Set-DfsrMembership -GroupName 'ARR Shared Configuration' -FolderName 'C:\ARRSharedConfiguration' -ContentPath 'C:\ARRSharedConfiguration' -ComputerName 'ARRNODE02' -Force

    #Removing any DFS Replication group with the same name
    Get-DfsReplicationGroup -GroupName 'IIS Shared Configuration' | Remove-DfsReplicationGroup -Force -RemoveReplicatedFolders
    #Creating the DFS Replication group for the shared configuration
    New-DfsReplicationGroup -GroupName 'IIS Shared Configuration' |
    New-DfsReplicatedFolder -FolderName 'C:\IISSharedConfiguration' |
    Add-DfsrMember -ComputerName IISNODE01, IISNODE02
    #Adding the member (replication in both ways)
    Add-DfsrConnection -GroupName 'IIS Shared Configuration' -SourceComputerName 'IISNODE01' -DestinationComputerName 'IISNODE02'
    #Adding the members and specifiyng the primary server
    Set-DfsrMembership -GroupName 'IIS Shared Configuration' -FolderName 'C:\IISSharedConfiguration' -ContentPath 'C:\IISSharedConfiguration' -ComputerName 'IISNODE01' -PrimaryMember $True -Force
    Set-DfsrMembership -GroupName 'IIS Shared Configuration' -FolderName 'C:\IISSharedConfiguration' -ContentPath 'C:\IISSharedConfiguration' -ComputerName 'IISNODE02' -Force
    Get-DfsReplicationGroup -GroupName 'Central Certificate Store' | Remove-DfsReplicationGroup -Force -RemoveReplicatedFolders

    #Creating the DFS Replication group for the shared configuration
    New-DfsReplicationGroup -GroupName 'Central Certificate Store' |
    New-DfsReplicatedFolder -FolderName 'C:\CentralCertificateStore' |
    Add-DfsrMember -ComputerName ARRNODE01, ARRNODE02
    #Adding the member (replication in both ways)
    Add-DfsrConnection -GroupName 'Central Certificate Store' -SourceComputerName 'ARRNODE01' -DestinationComputerName 'ARRNODE02'
    #Adding the members and specifiyng the primary server
    Set-DfsrMembership -GroupName 'Central Certificate Store' -FolderName 'C:\CentralCertificateStore' -ContentPath 'C:\CentralCertificateStore' -ComputerName 'ARRNODE01' -PrimaryMember $True -Force
    Set-DfsrMembership -GroupName 'Central Certificate Store' -FolderName 'C:\CentralCertificateStore' -ContentPath 'C:\CentralCertificateStore' -ComputerName 'ARRNODE02' -Force

    #Setting SPN on the Application Pool Identity
    setspn.exe -S "HTTP/$using:WebSiteName" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    setspn.exe -S "HTTP/arr" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    setspn.exe -S "HTTP/IISNODE01.$using:FQDNDomainName" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    setspn.exe -S "HTTP/IISNODE01" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    setspn.exe -S "HTTP/IISNODE02.$using:FQDNDomainName" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    setspn.exe -S "HTTP/IISNODE02" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    setspn.exe -S "HTTP/ARRNODE01.$using:FQDNDomainName" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    setspn.exe -S "HTTP/ARRNODE01" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    setspn.exe -S "HTTP/ARRNODE02.$using:FQDNDomainName" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    setspn.exe -S "HTTP/ARRNODE02" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
}

#Copying required IIS extensions on the ARR servers for ARR
Copy-LabFileItem -Path $CurrentDir\Extensions.zip -DestinationFolderPath C:\Temp -ComputerName ARRNODE01, ARRNODE02

Invoke-LabCommand -ActivityName 'IIS Extensions, NLB, IIS Central Certificate Store and ARR Shared Configuration Setup on ARR servers' -ComputerName ARRNODE01, ARRNODE02 -ScriptBlock {
    Expand-Archive 'C:\Temp\Extensions.zip' -DestinationPath C:\ -Force
    C:\Extensions\Install-IISExtension.ps1

    #Installing and setting up DFS-R, NLB and Windows Authentication on ARR Servers
    #Install-WindowsFeature NLB, Web-CertProvider -includeManagementTools
    #Renaming the NIC and setting up the metric for NLB management
    Rename-NetAdapter -Name "$using:labName 0" -NewName 'Internal' -PassThru | Set-NetIPInterface -InterfaceMetric 1
    Rename-NetAdapter -Name "$using:labName 1" -NewName 'NLB' -PassThru | Set-NetIPInterface -InterfaceMetric 2
    #Creating replicated folder for shared configuration
    New-Item -Path C:\ARRSharedConfiguration -ItemType Directory -Force
    Enable-WebCentralCertProvider -CertStoreLocation 'C:\CentralCertificateStore\' -UserName $Using:Logon -Password $Using:ClearTextPassword -PrivateKeyPassword $Using:ClearTextPassword

    #Adding handler for image watermark
    Add-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:WebSiteName"  -filter 'system.webServer/handlers' -name '.' -value @{
        name          = 'JpgHttpHandler'
        path          = '*.jpg'
        type          = 'JpgHttpHandler'
        verb          = '*'
        resourceType  = 'Unspecified'
        requireAccess = 'Script'
    }
    Add-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:WebSiteName"  -filter 'system.webServer/handlers' -name '.' -value @{
        name          = 'GifHttpHandler'
        path          = '*.gif'
        type          = 'JpgHttpHandler'
        verb          = '*'
        resourceType  = 'Unspecified'
        requireAccess = 'Script'
    }
    Add-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:WebSiteName"  -filter 'system.webServer/handlers' -name '.' -value @{
        name          = 'PngHttpHandler'
        path          = '*.png'
        type          = 'JpgHttpHandler'
        verb          = '*'
        resourceType  = 'Unspecified'
        requireAccess = 'Script'
    }
}

Invoke-LabCommand -ActivityName 'NLB Setup' -ComputerName ARRNODE01 {
    #Creating new NLB cluster
    New-NlbCluster -HostName ARRNODE01 -ClusterName "$using:WebSiteName" -InterfaceName NLB -ClusterPrimaryIP 10.0.0.101 -SubnetMask 255.255.0.0 -OperationMode 'Multicast'
    #Removing default port rule for the new cluster
    #Get-NlbClusterPortRule -HostName . | Remove-NlbClusterPortRule -Force
    #Adding port rules
    #Add-NlbClusterPortRule -Protocol Tcp -Mode Multiple -Affinity Single -StartPort 80 -EndPort 80 -InterfaceName $InterfaceName | Out-Null
    #Add-NlbClusterPortRule -Protocol Tcp -Mode Multiple -Affinity Single -StartPort 443 -EndPort 443 -InterfaceName $InterfaceName | Out-Null
    #Adding the second node to the cluster
    Get-NlbCluster | Add-NlbClusterNode -NewNodeName ARRNODE02 -NewNodeInterface NLB
    #Client Affinity: Do not enable it to see the load balacing between the two ARR Servers    
    Get-NlbClusterPortRule | Set-NlbClusterPortRule -NewAffinity None
}

#Installing and setting up ARR and NLB on ARR Servers
Invoke-LabCommand -ActivityName 'SNI/CSS, ARR and URL Rewrite Setup' -ComputerName ARRNODE01, ARRNODE02 {
    Import-Module -Name WebAdministration
    #Adding a HTTP:443 Binding
    #0: Regular certificate in Windows certificate storage.
    #1: SNI certificate.
    #2: Central certificate store.
    #3: SNI certificate in central certificate store.
    #New-WebBinding -Name "$using:WebSiteName" -Port 443 -IPAddress * -Protocol https -sslFlags 3 -HostHeader "$using:WebSiteName"
    New-WebBinding -Name "$using:WebSiteName" -sslFlags 3 -Protocol https -HostHeader "$using:WebSiteName"
    New-Item -Path "IIS:\SslBindings\!443!$using:WebSiteName" -sslFlags 3 -Store CentralCertStore
    #Removing Default Binding
    #Get-WebBinding -Port 80 -Name "$using:WebSiteName" | Remove-WebBinding

    #Require SSL
    Get-IISConfigSection -SectionPath 'system.webServer/security/access' -Location "$using:WebSiteName" | Set-IISConfigAttributeValue -AttributeName sslFlags -AttributeValue Ssl

    Do 
    {
        #ARR Webfarm
        Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'webFarms' -Name '.' -Value @{
            name    = "$using:WebSiteName"
            enabled = $True
        }
        Write-Verbose -Message 'Waiting the creation of the ARR web farm. Sleeping 10 seconds ...'
        Start-Sleep -Seconds 10
    } While (-not(Get-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "webFarms/webFarm[@name='arr.contoso.com']"))

    Add-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "webFarms/webFarm[@name='$using:WebSiteName']" -Value @(
        @{
            address = 'IISNODE01'
            enabled = $True
        }, 
        @{
            address = 'IISNODE02'
            enabled = $True
        }
    )

    #Port 80 and 443 only (default settings)
    #Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "webFarms/webFarm[@name='$using:WebSiteName']/server[@address='ARRNODE01']" -Name 'applicationRequestRouting' -Value @{ httpPort = 80 }
    #Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "webFarms/webFarm[@name='$using:WebSiteName']/server[@address='ARRNODE02']" -Name 'applicationRequestRouting' -Value @{ httpPort = 80 }
    #Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "webFarms/webFarm[@name='$using:WebSiteName']/server[@address='ARRNODE01']" -Name 'applicationRequestRouting' -Value @{ httpPort = 443 }
    #Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "webFarms/webFarm[@name='$using:WebSiteName']/server[@address='ARRNODE02']" -Name 'applicationRequestRouting' -Value @{ httpPort = 443 }

    #Heatlcheck test page and pattern to found if ok
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "webFarms/webFarm[@name='$using:WebSiteName']/applicationRequestRouting" -Name 'healthcheck' -Value @{
        url           = "http://$using:WebSiteName/healthcheck.aspx"
        interval      = '00:00:05'
        responseMatch = 'ok'
    }

    #Adding and URL Rewrite rule to redirect http traffic to HTTPS
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webserver/rewrite/globalRules' -name '.' -value @{
        name           = 'HTTP to HTTPS Redirect'
        patternSyntax  = 'Regular Expressions'
        stopProcessing = 'True'
    }
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webserver/rewrite/globalRules/rule[@name='HTTP to HTTPS Redirect']/match" -name url -value '(.*)'
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webserver/rewrite/globalRules/rule[@name='HTTP to HTTPS Redirect']/conditions" -name '.' -value @{
        input   = '{HTTPS}'
        pattern = '^OFF$'
    }
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/rewrite/globalRules/rule[@name='HTTP to HTTPS Redirect']/action" -name 'type' -value 'Redirect'
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/rewrite/globalRules/rule[@name='HTTP to HTTPS Redirect']/action" -name 'url' -value 'https://{HTTP_HOST}/{R:1}'
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/rewrite/globalRules/rule[@name='HTTP to HTTPS Redirect']/action" -name 'redirectType' -value 'Permanent' 

    #URL Rewrite for ARR
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter 'system.webServer/rewrite/globalRules' -name '.' -value @{
        name           = "ARR_$($using:WebSiteName)_loadbalance"
        patternSyntax  = 'Wildcard'
        stopProcessing = 'True'
        enabled        = $True
    }
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/rewrite/globalRules/rule[@name='ARR_$($using:WebSiteName)_loadbalance']/match" -name 'url' -value '*'
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/rewrite/globalRules/rule[@name='ARR_$($using:WebSiteName)_loadbalance']/action" -name 'type' -value 'Rewrite'
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/rewrite/globalRules/rule[@name='ARR_$($using:WebSiteName)_loadbalance']/action" -name 'url' -value "http://$using:WebSiteName/{R:0}"
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/rewrite/globalRules/rule[@name='ARR_$($using:WebSiteName)_loadbalance']/conditions" -name '.' -value @{
        input   = '{HTTP_HOST}'
        pattern = "$using:WebSiteName"
    }

    #Client Affinity: Do not enable it to see the load balacing between the two IIS Servers
    #Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "webFarms/webFarm[@name='$using:WebSiteName']/applicationRequestRouting/affinity" -name "useCookie" -value "True"

    #Extensions not forwarded
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/rewrite/globalRules/rule[@name='ARR_$($using:WebSiteName)_loadbalance']/conditions" -name '.' -value @{
        input   = 'EXT_{URL}'
        pattern = '*.css'
        negate  = 'True'
    }
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/rewrite/globalRules/rule[@name='ARR_$($using:WebSiteName)_loadbalance']/conditions" -name '.' -value @{
        input   = 'EXT_{URL}'
        pattern = '*.jpg'
        negate  = 'True'
    }
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/rewrite/globalRules/rule[@name='ARR_$($using:WebSiteName)_loadbalance']/conditions" -name '.' -value @{
        input   = 'EXT_{URL}'
        pattern = '*.gif'
        negate  = 'True'
    }
    
    #Patterns not forwarded
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/rewrite/globalRules/rule[@name='ARR_$($using:WebSiteName)_loadbalance']/conditions" -name '.' -value @{
        input   = '{URL}'
        pattern = '/images/*'
        negate  = 'True'
    }
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/rewrite/globalRules/rule[@name='ARR_$($using:WebSiteName)_loadbalance']/conditions" -name '.' -value @{
        input   = '{URL}'
        pattern = '/css/*'
        negate  = 'True'
    }
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/rewrite/globalRules/rule[@name='ARR_$($using:WebSiteName)_loadbalance']/conditions" -name '.' -value @{
        input   = '{URL}'
        pattern = '/javascript/*'
        negate  = 'True'
    }
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/rewrite/globalRules/rule[@name='ARR_$($using:WebSiteName)_loadbalance']/conditions" -name '.' -value @{
        input   = '{URL}'
        pattern = '/js/*'
        negate  = 'True'
    }
}

Invoke-LabCommand -ActivityName 'Exporting IIS Shared Configuration and Windows Authentication Setup' -ComputerName IISNODE01 -ScriptBlock {
    #Changing the application pool identity for an AD Account : mandatory for Kerberos authentication
    Import-Module -Name WebAdministration
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='$using:WebSiteName']/processModel" -name 'identityType' -value 3
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='$using:WebSiteName']/processModel" -name 'userName' -value "$Using:NetBiosDomainName\$Using:IISAppPoolUser"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='$using:WebSiteName']/processModel" -name 'password' -value $Using:ClearTextPassword

    #Disabling the Anonymous authentication
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:WebSiteName" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'False'
    #Enabling the Windows authentication
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:WebSiteName" -filter 'system.webServer/security/authentication/windowsAuthentication' -name 'enabled' -value 'True'

    #Enabling the Anonymous authentication for the healthcheck test page
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:WebSiteName/healthcheck.aspx" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'True'
    #Disabling the Windows authentication for the healthcheck test page
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:WebSiteName/healthcheck.aspx" -filter 'system.webServer/security/authentication/windowsAuthentication' -name 'enabled' -value 'False'

    #Disabling validation for application pool in integrated mode due to ASP.Net impersonation incompatibility
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:WebSiteName"  -filter 'system.webServer/validation' -name 'validateIntegratedModeConfiguration' -value 'False' -verbose

    New-Item -Path C:\IISSharedConfiguration -ItemType Directory -Force
    #Exporting the configuration
    Export-IISConfiguration -PhysicalPath C:\IISSharedConfiguration -KeyEncryptionPassword $Using:SecurePassword -Force
}

Invoke-LabCommand -ActivityName 'Enabling IIS Shared Configuration on IIS servers' -ComputerName IISNODE01, IISNODE02 -ScriptBlock {
    #Install-WindowsFeature Web-Windows-Auth  -includeManagementTools
    New-Item -Path C:\IISSharedConfiguration -ItemType Directory -Force

    #Enabling ASP.Net Impersonation (local web.config)
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:WebSiteName"  -filter 'system.web/identity' -name 'impersonate' -value 'True'

    While (-not(Test-Path -Path C:\IISSharedConfiguration\applicationHost.config))
    {
        Write-Verbose -Message 'Waiting the replication via DFS-R of applicationHost.config. Sleeping 10 seconds ...'
        Start-Sleep -Seconds 10
    }
    #Enabling the shared configuration
    Enable-IISSharedConfig  -PhysicalPath C:\IISSharedConfiguration -KeyEncryptionPassword $Using:SecurePassword -Force
}

Invoke-LabCommand -ActivityName 'Exporting IIS Shared Configuration and Windows Authentication Setup' -ComputerName ARRNODE01 -ScriptBlock {
    #Changing the application pool identity for an AD Account : mandatory for Kerberos authentication
    New-Item -Path C:\ARRSharedConfiguration -ItemType Directory -Force
    #Exporting the configuration
    Export-IISConfiguration -PhysicalPath C:\ARRSharedConfiguration -KeyEncryptionPassword $Using:SecurePassword -Force
    Enable-IISSharedConfig  -PhysicalPath C:\ARRSharedConfiguration -KeyEncryptionPassword $Using:SecurePassword -Force
}

Invoke-LabCommand -ActivityName 'Enabling IIS Shared Configuration on ARR servers' -ComputerName ARRNODE02 -ScriptBlock {
    New-Item -Path C:\ARRSharedConfiguration -ItemType Directory -Force
    #Enabling the shared configuration
    While (-not(Test-Path -Path C:\ARRSharedConfiguration\applicationHost.config))
    {
        Write-Verbose -Message 'Waiting the replication via DFS-R of applicationHost.config. Sleeping 10 seconds ...'
        Start-Sleep -Seconds 10
    }
    Enable-IISSharedConfig  -PhysicalPath C:\ARRSharedConfiguration -KeyEncryptionPassword $Using:SecurePassword -Force
}

Show-LabDeploymentSummary -Detailed
Checkpoint-LabVM -SnapshotName 'FullInstall' -All -Verbose
$VerbosePreference = $PreviousVerbosePreference
#Get-LabVM | Get-VM | Restore-VMCheckpoint -Name "FullInstall" -Confirm:$false
Stop-Transcript