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
$WebSiteName="nlb.$FQDNDomainName"

$LabName = 'NLBIISLab'
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
#Certificate Authority
Add-LabMachineDefinition -Name CA01 -Roles CARoot -IpAddress 10.0.0.2

#IIS Front End

#2 NICS for IIS servers (1 for server communications and 1 for NLB)
$netAdapter = @()
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address 10.0.0.21/16
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address 10.0.0.201/16
Add-LabMachineDefinition -Name IISNODE01 -NetworkAdapter $netAdapter

$netAdapter = @()
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address 10.0.0.22/16
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address 10.0.0.202/16
Add-LabMachineDefinition -Name IISNODE02 -NetworkAdapter $netAdapter

#Installing servers
Install-Lab
#Checkpoint-LabVM -SnapshotName FreshInstall -All -Verbose


$machines = Get-LabVM
Install-LabWindowsFeature -FeatureName Telnet-Client -ComputerName $machines -IncludeManagementTools
Install-LabWindowsFeature -FeatureName FS-DFS-Replication, Web-Server, Web-Asp-Net45, Web-Request-Monitor, Web-Windows-Auth  -ComputerName IISNODE01, IISNODE02 -IncludeManagementTools
Install-LabWindowsFeature -FeatureName FS-DFS-Replication -ComputerName DC01 -IncludeManagementTools
Install-LabWindowsFeature -FeatureName NLB, Web-CertProvider -ComputerName IISNODE01, IISNODE02 -IncludeManagementTools

Invoke-LabCommand -ActivityName "Disabling IE ESC and Adding $WebSiteName to the IE intranet zone" -ComputerName $machines -ScriptBlock {
    #Disabling IE ESC
    $AdminKey = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}'
    $UserKey = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}'
    Set-ItemProperty -Path $AdminKey -Name 'IsInstalled' -Value 0 -Force
    Set-ItemProperty -Path $UserKey -Name 'IsInstalled' -Value 0 -Force

    #Setting nlb.contoso.com, IISNODE01.contoso.com and IISNODE02.contoso.com in the Local Intranet Zone for all servers : mandatory for Kerberos authentication       
    $null = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$using:WebSiteName" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$using:WebSiteName" -Name http -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$using:WebSiteName" -Name https -Value 1 -Type DWord -Force
    $null = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\IISNODE01.$using:FQDNDomainName" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\IISNODE01.$using:FQDNDomainName" -Name http -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\IISNODE01.$using:FQDNDomainName" -Name https -Value 1 -Type DWord -Force
    $null = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\IISNODE02.$using:FQDNDomainName" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\IISNODE02.$using:FQDNDomainName" -Name http -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\IISNODE02.$using:FQDNDomainName" -Name https -Value 1 -Type DWord -Force

    #Changing the start page for IE
    $path = "HKCU:\Software\Microsoft\Internet Explorer\Main\"
    $name = "start page"
    $value = "https://$using:WebSiteName/"
    Set-ItemProperty -Path $path -Name $name -Value $value -Force
    #Bonus : To open all the available websites accross all nodes
    $name = "Secondary Start Pages"
    $value="https://iisnode01.$using:FQDNDomainName", "https://iisnode02.$using:FQDNDomainName"
    New-ItemProperty -Path $path -PropertyType MultiString -Name $name -Value $value -Force
}


#Installing and setting up DFS-R on DC for replicated folder on IIS Servers for shared confguration
Invoke-LabCommand -ActivityName 'DNS & DFS-R Setup on DC' -ComputerName DC01 -ScriptBlock {
    New-ADUser -Name "$Using:IISAppPoolUser" -PasswordNeverExpires $True -AccountPassword $Using:SecurePassword -CannotChangePassword $True -Enabled $True

    #Reverse lookup zone creation
    Add-DnsServerPrimaryZone -NetworkID '10.0.0.0/16' -ReplicationScope 'Forest' 
    #DNS Host entry for the nlb.contoso.com website 
    Add-DnsServerResourceRecordA -Name 'nlb' -ZoneName $using:FQDNDomainName -IPv4Address '10.0.0.101' -CreatePtr
    #Installing DFS-R on IIS servers for the shared configuration
    #Install-WindowsFeature FS-DFS-Replication -includeManagementTools

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

    #Creating the DFS Replication group for the shared configuration
    New-DfsReplicationGroup -GroupName 'Central Certificate Store' |
    New-DfsReplicatedFolder -FolderName 'C:\CentralCertificateStore' |
    Add-DfsrMember -ComputerName IISNODE01, IISNODE02
    #Adding the member (replication in both ways)
    Add-DfsrConnection -GroupName 'Central Certificate Store' -SourceComputerName 'IISNODE01' -DestinationComputerName 'IISNODE02'
    #Adding the members and specifiyng the primary server
    Set-DfsrMembership -GroupName 'Central Certificate Store' -FolderName 'C:\CentralCertificateStore' -ContentPath 'C:\CentralCertificateStore' -ComputerName 'IISNODE01' -PrimaryMember $True -Force
    Set-DfsrMembership -GroupName 'Central Certificate Store' -FolderName 'C:\CentralCertificateStore' -ContentPath 'C:\CentralCertificateStore' -ComputerName 'IISNODE02' -Force

    #Setting SPN on the Application Pool Identity
    setspn.exe -S "HTTP/$using:WebSiteName" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    setspn.exe -S "HTTP/nlb" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    setspn.exe -S "HTTP/IISNODE01.$using:FQDNDomainName" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    setspn.exe -S "HTTP/IISNODE01" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    setspn.exe -S "HTTP/IISNODE02.$using:FQDNDomainName" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    setspn.exe -S "HTTP/IISNODE02" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
}

Invoke-LabCommand -ActivityName 'NLB, IIS Central Certificate Store and IIS Shared Configuration Directory Creation on IIS servers' -ComputerName IISNODE01, IISNODE02 -ScriptBlock {

    #Renaming the NIC and setting up the metric for NLB management
    Rename-NetAdapter -Name "$using:labName 0" -NewName 'Internal' -PassThru | Set-NetIPInterface -InterfaceMetric 1
    Rename-NetAdapter -Name "$using:labName 1" -NewName 'NLB' -PassThru | Set-NetIPInterface -InterfaceMetric 2

    #Creating replicated folder for Central Certificate Store
    New-Item -Path C:\CentralCertificateStore -ItemType Directory -Force
    Enable-WebCentralCertProvider -CertStoreLocation 'C:\CentralCertificateStore\' -UserName $Using:Logon -Password $Using:ClearTextPassword -PrivateKeyPassword $Using:ClearTextPassword

    #Creating replicated folder for shared configuration
    New-Item -Path C:\IISSharedConfiguration -ItemType Directory -Force

    #Restarting DFSR service
    Restart-Service -Name DFSR -Force
    Start-Sleep -Seconds 10
}

Invoke-LabCommand -ActivityName 'NLB Setup and IIS Shared Configuration Export' -ComputerName IISNODE01 {
    #Creating new NLB cluster
    New-NlbCluster -HostName IISNODE01 -ClusterName "$using:WebSiteName" -InterfaceName NLB -ClusterPrimaryIP 10.0.0.101 -SubnetMask 255.255.0.0 -OperationMode 'Multicast'
    #Removing default port rule for the new cluster
    #Get-NlbClusterPortRule -HostName . | Remove-NlbClusterPortRule -Force
    #Adding port rules
    #Add-NlbClusterPortRule -Protocol Tcp -Mode Multiple -Affinity Single -StartPort 80 -EndPort 80 -InterfaceName $InterfaceName | Out-Null
    #Add-NlbClusterPortRule -Protocol Tcp -Mode Multiple -Affinity Single -StartPort 443 -EndPort 443 -InterfaceName $InterfaceName | Out-Null
    #Adding the second node to the cluster
    Get-NlbCluster | Add-NlbClusterNode -NewNodeName IISNODE02 -NewNodeInterface NLB
    #Client Affinity: Do not enable it to see the load balacing between the two IIS Servers    
    Get-NlbClusterPortRule | Set-NlbClusterPortRule -NewAffinity None

    #Exporting the configuration only from one node
    Export-IISConfiguration -PhysicalPath C:\IISSharedConfiguration -KeyEncryptionPassword $Using:SecurePassword -Force
}


$CertificationAuthority = Get-LabIssuingCA
New-LabCATemplate -TemplateName WebServerSSL -DisplayName 'Web Server SSL' -SourceTemplateName WebServer -ApplicationPolicy 'Server Authentication' -EnrollmentFlags Autoenrollment -PrivateKeyFlags AllowKeyExport -Version 2 -SamAccountName 'Domain Computers' -ComputerName $CertificationAuthority -ErrorAction Stop
$WebServerSSLCert = Request-LabCertificate -Subject "CN=$WebSiteName" -SAN "nlb", "$WebSiteName", "IISNODE01", "IISNODE01.$FQDNDomainName", "IISNODE02", "IISNODE02.$FQDNDomainName" -TemplateName WebServerSSL -ComputerName IISNODE01 -PassThru -ErrorAction Stop
Get-LabCertificate -ComputerName IISNODE01 -SearchString "$WebSiteName" -FindType FindBySubjectName  -ExportPrivateKey -Password $SecurePassword #| Add-LabCertificate -ComputerName IISNODE02 -Location CERT_SYSTEM_STORE_LOCAL_MACHINE -Store My -Password $ClearTextPassword

#Copying Web site content on all IIS servers
Copy-LabFileItem -Path $CurrentDir\nlb.contoso.com.zip -DestinationFolderPath C:\Temp -ComputerName IISNODE01, IISNODE02

Invoke-LabCommand -ActivityName 'Exporting the Web Server Certificate into Central Certificate Store Directory' -ComputerName IISNODE01 -ScriptBlock {
    $WebServerSSLCert = Get-ChildItem -Path Cert:\LocalMachine\My\ -DnsName "$using:WebSiteName" -SSLServerAuthentication | Where-Object -FilterScript {
        $_.hasPrivateKey 
    }  
    if ($WebServerSSLCert)
    {    
        $WebServerSSLCert | Export-PfxCertificate -FilePath "C:\CentralCertificateStore\$using:WebSiteName.pfx" -Password $Using:SecurePassword
        #Bonus : To access directly to the SSL web site hosted on IIS nodes
        Copy-Item "C:\CentralCertificateStore\$using:WebSiteName.pfx" "C:\CentralCertificateStore\iisnode01.$using:FQDNDomainName.pfx"
        Copy-Item "C:\CentralCertificateStore\$using:WebSiteName.pfx" "C:\CentralCertificateStore\iisnode02.$using:FQDNDomainName.pfx"
        #$WebServerSSLCert | Remove-Item -Force
    }
    else
    {
        Write-Error -Exception "[ERROR] Unable to get the 'Web Server SSL' certificate for $using:WebSiteName"
    }
}

Invoke-LabCommand -ActivityName 'Unzipping Web Site Content and Enabling IIS Shared Configuration' -ComputerName IISNODE01, IISNODE02 -ScriptBlock {
    Expand-Archive 'C:\Temp\nlb.contoso.com.zip' -DestinationPath C:\inetpub\wwwroot -Force
    '<%=HttpContext.Current.Server.MachineName%>' | Out-File -FilePath 'C:\inetpub\wwwroot\server.aspx' -Force
    'ok' | Out-File -FilePath 'C:\inetpub\wwwroot\healthcheck.aspx' -Force

    #Enabling the shared configuration for all IIS nodes
    While (-not(Test-Path -Path C:\IISSharedConfiguration\applicationHost.config))
    {
        Write-Verbose -Message 'Waiting the replication via DFS-R of applicationHost.config. Sleeping 10 seconds ...'
        Start-Sleep -Seconds 10
    }
    Enable-IISSharedConfig  -PhysicalPath C:\IISSharedConfiguration -KeyEncryptionPassword $Using:SecurePassword -Force
}

#Setting up IIS web site 
Invoke-LabCommand -ActivityName 'IIS Website Setup' -ComputerName IISNODE01, IISNODE02 -ScriptBlock {
    Import-Module -Name WebAdministration
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
    #Assigning the the nlb.contoso.com application pool to the nlb.contoso.com web sitre
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
    
    #Adding a HTTP:443 Binding
    #0: Regular certificate in Windows certificate storage.
    #1: SNI certificate.
    #2: Central certificate store.
    #3: SNI certificate in central certificate store.
    #New-WebBinding -Name "$using:WebSiteName" -Port 443 -IPAddress * -Protocol https -sslFlags 3 -HostHeader "$using:WebSiteName"
    New-WebBinding -Name "$using:WebSiteName" -sslFlags 3 -Protocol https -HostHeader "$using:WebSiteName"
    New-WebBinding -Name "$using:WebSiteName" -sslFlags 3 -Protocol https -HostHeader "iisnode01.$using:FQDNDomainName"
    New-WebBinding -Name "$using:WebSiteName" -sslFlags 3 -Protocol https -HostHeader "iisnode02.$using:FQDNDomainName"
    New-Item -Path "IIS:\SslBindings\!443!$using:WebSiteName" -sslFlags 3 -Store CentralCertStore
    #Removing Default Binding
    #Get-WebBinding -Port 80 -Name "$using:WebSiteName" | Remove-WebBinding
    #Bonus : To access directly to the SSL web site hosted on IIS nodes

    #Require SSL
    Get-IISConfigSection -SectionPath 'system.webServer/security/access' -Location "$using:WebSiteName" | Set-IISConfigAttributeValue -AttributeName sslFlags -AttributeValue Ssl

    #Changing the application pool identity for an AD Account : mandatory for Kerberos authentication

    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='$using:WebSiteName']/processModel" -name 'identityType' -value 3
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='$using:WebSiteName']/processModel" -name 'userName' -value "$Using:NetBiosDomainName\$Using:IISAppPoolUser"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='$using:WebSiteName']/processModel" -name 'password' -value $Using:ClearTextPassword

    #Disabling the Anonymous authentication
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:WebSiteName" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'False'
    #Enabling the Windows authentication
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:WebSiteName" -filter 'system.webServer/security/authentication/windowsAuthentication' -name 'enabled' -value 'True'
    #Enabling ASP.Net Impersonation (local web.config)
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:WebSiteName"  -filter 'system.web/identity' -name 'impersonate' -value 'True'

    #Enabling the Anonymous authentication for the healthcheck test page
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:WebSiteName/healthcheck.aspx" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'True'
    #Disabling the Windows authentication for the healthcheck test page
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:WebSiteName/healthcheck.aspx" -filter 'system.webServer/security/authentication/windowsAuthentication' -name 'enabled' -value 'False'

    #Disabling validation for application pool in integrated mode due to ASP.Net impersonation incompatibility
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:WebSiteName"  -filter 'system.webServer/validation' -name 'validateIntegratedModeConfiguration' -value 'False' -verbose
}

Show-LabDeploymentSummary -Detailed
Checkpoint-LabVM -SnapshotName 'FullInstall' -All -Verbose
$VerbosePreference = $PreviousVerbosePreference
#Get-LabVM | Get-VM | Restore-VMCheckpoint -Name "FullInstall" -Confirm:$false
Stop-Transcript