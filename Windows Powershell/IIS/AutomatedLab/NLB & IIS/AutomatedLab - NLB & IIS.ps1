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
#requires -Version 5 -Modules AutomatedLab -RunAsAdministrator 
trap {
    Write-Host "Stopping Transcript ..."
    Stop-Transcript
    $VerbosePreference = $PreviousVerbosePreference
    $ErrorActionPreference = $PreviousErrorActionPreference
    [console]::beep(3000, 750)
    Send-ALNotification -Activity 'Lab started' -Message ('Lab deployment failed !') -Provider (Get-LabConfigurationItem -Name Notifications.SubscribedProviders)
} 
Clear-Host
$PreviousVerbosePreference = $VerbosePreference
$VerbosePreference = 'SilentlyContinue'
$PreviousErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = 'Stop'
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$TranscriptFile = $CurrentScript -replace ".ps1$", "$("_{0}.txt" -f (Get-Date -Format 'yyyyMMddHHmmss'))"
Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader

#region Helper function
# Generates a <machineKey> element that can be copied + pasted into a Web.config file.
#From https://support.microsoft.com/en-us/help/2915218/resolving-view-state-message-authentication-code-mac-errors#AppendixA. 
#Modified to return an object instead of a XML block
function New-MachineKey {
    [CmdletBinding()]
    param (
        [ValidateSet("AES", "DES", "3DES")]
        [string]$decryptionAlgorithm = 'AES',
        [ValidateSet("MD5", "SHA1", "HMACSHA256", "HMACSHA384", "HMACSHA512")]
        [string]$validationAlgorithm = 'HMACSHA256'
    )
    process {
        function BinaryToHex {
            [CmdLetBinding()]
            param($bytes)
            process {
                $builder = New-Object System.Text.StringBuilder
                foreach ($b in $bytes) {
                    $builder = $builder.AppendFormat([System.Globalization.CultureInfo]::InvariantCulture, "{0:X2}", $b)
                }
                $builder
            }
        }
        switch ($decryptionAlgorithm) {
            "AES" {
                $decryptionObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider 
            }
            "DES" {
                $decryptionObject = New-Object System.Security.Cryptography.DESCryptoServiceProvider 
            }
            "3DES" {
                $decryptionObject = New-Object System.Security.Cryptography.TripleDESCryptoServiceProvider 
            }
        }
        $decryptionObject.GenerateKey()
        $decryptionKey = BinaryToHex($decryptionObject.Key)
        $decryptionObject.Dispose()
        switch ($validationAlgorithm) {
            "MD5" {
                $validationObject = New-Object System.Security.Cryptography.HMACMD5 
            }
            "SHA1" {
                $validationObject = New-Object System.Security.Cryptography.HMACSHA1 
            }
            "HMACSHA256" {
                $validationObject = New-Object System.Security.Cryptography.HMACSHA256 
            }
            "HMACSHA385" {
                $validationObject = New-Object System.Security.Cryptography.HMACSHA384 
            }
            "HMACSHA512" {
                $validationObject = New-Object System.Security.Cryptography.HMACSHA512 
            }
        }
        $validationKey = BinaryToHex($validationObject.Key)
        $validationObject.Dispose()
        <#
    [string]::Format([System.Globalization.CultureInfo]::InvariantCulture,
      "<machineKey decryption=`"{0}`" decryptionKey=`"{1}`" validation=`"{2}`" validationKey=`"{3}`" />",
      $decryptionAlgorithm.ToUpperInvariant(), $decryptionKey,
      $validationAlgorithm.ToUpperInvariant(), $validationKey)
    #>
        [PSCustomObject]@{
            "decryption"    = [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "{0}", $decryptionAlgorithm.ToUpperInvariant(), $decryptionKey, $validationAlgorithm.ToUpperInvariant(), $validationKey)
            "decryptionKey" = [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "{0}", $decryptionKey)
            "validation"    = [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "{0}", $validationAlgorithm.ToUpperInvariant())
            "validationKey" = [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "{0}", $validationKey)
        }
    }
}
#endregion

#region Global variables definition
$Logon = 'Administrator'
$ClearTextPassword = 'P@ssw0rd'
$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$NetBiosDomainName = 'CONTOSO'
$FQDNDomainName = 'contoso.com'
$IISAppPoolUser = 'IISAppPoolUser'

$NetworkID = '10.0.0.0/16' 

$DCIPv4Address = '10.0.0.1'
$CAIPv4Address = '10.0.0.2'
$IISNODE01IPv4Address = '10.0.0.21/16'
$IISNODE02IPv4Address = '10.0.0.22/16'
$NLBIISNODE01IPv4Address = '10.0.0.201/16'
$NLBIISNODE02IPv4Address = '10.0.0.202/16'

$NLBNetBiosName = 'nlb'
$NLBWebSiteName = "$NLBNetBiosName.$FQDNDomainName"
$NLBIPv4Address = '10.0.0.101'

$MSEdgeEntUri = "http://go.microsoft.com/fwlink/?LinkID=2093437"
$LabName = 'NLBIISLab'
#endregion

#Cleaning previously existing lab
if ($LabName -in (Get-Lab -List)) {
    Remove-Lab -Name $LabName -Confirm:$false -ErrorAction SilentlyContinue
}

#create an empty lab template and define where the lab XML files and the VMs will be stored
New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV

#make the network definition
Add-LabVirtualNetworkDefinition -Name $LabName -HyperVProperties @{
    SwitchType = 'Internal'
} -AddressSpace $NetworkID

#and the domain definition with the domain admin account
Add-LabDomainDefinition -Name $FQDNDomainName -AdminUser $Logon -AdminPassword $ClearTextPassword

#these credentials are used for connecting to the machines. As this is a lab we use clear-text passwords
Set-LabInstallationCredential -Username $Logon -Password $ClearTextPassword

#defining default parameter values, as these ones are the same for all the machines
$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:Network'         = $LabName
    'Add-LabMachineDefinition:DomainName'      = $FQDNDomainName
    'Add-LabMachineDefinition:MinMemory'       = 1GB
    'Add-LabMachineDefinition:MaxMemory'       = 2GB
    'Add-LabMachineDefinition:Memory'          = 2GB
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2019 Datacenter (Desktop Experience)'
    'Add-LabMachineDefinition:Processors'      = 4
}

#Domain controller
Add-LabMachineDefinition -Name DC01 -Roles RootDC -IpAddress $DCIPv4Address
#Certificate Authority
Add-LabMachineDefinition -Name CA01 -Roles CARoot -IpAddress $CAIPv4Address

#region IIS front-end servers : 2 NICS for  (1 for server communications and 1 for NLB)
$netAdapter = @()
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $IISNODE01IPv4Address -InterfaceName 'Internal'
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $NLBIISNODE01IPv4Address -InterfaceName 'NLB'
Add-LabMachineDefinition -Name IISNODE01 -NetworkAdapter $netAdapter
$netAdapter = @()
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $IISNODE02IPv4Address -InterfaceName 'Internal'
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $NLBIISNODE02IPv4Address -InterfaceName 'NLB'
Add-LabMachineDefinition -Name IISNODE02 -NetworkAdapter $netAdapter
#endregion

#Installing servers
Install-Lab -DelayBetweenComputers 120
#Checkpoint-LabVM -SnapshotName FreshInstall -All -Verbose

#region Installing Required Windows Features
$machines = Get-LabVM -All
$Job = @()
$Job += Install-LabWindowsFeature -FeatureName Telnet-Client -ComputerName $machines -IncludeManagementTools -AsJob
Install-LabWindowsFeature -FeatureName FS-DFS-Replication, Web-Server, Web-Asp-Net45, Web-Request-Monitor, Web-Windows-Auth, NLB, Web-CertProvider -ComputerName IISNODE01, IISNODE02 -IncludeManagementTools
#Install-LabWindowsFeature -FeatureName FS-DFS-Replication -ComputerName DC01 -IncludeManagementTools
#endregion

$MSEdgeEnt = Get-LabInternetFile -Uri $MSEdgeEntUri -Path $labSources\SoftwarePackages -PassThru -Force
$Job += Install-LabSoftwarePackage -ComputerName $machines -Path $MSEdgeEnt.FullName -CommandLine "/passive /norestart" -AsJob

Invoke-LabCommand -ActivityName "Disabling IE ESC and Adding $NLBWebSiteName to the IE intranet zone" -ComputerName $machines -ScriptBlock {
    #region Disabling IE ESC
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
    Stop-Process -Name Explorer
    #Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green
    #endregion 

    #region IE Settings
    $MainKey = 'HKCU:\Software\Microsoft\Internet Explorer\Main'
    Remove-ItemProperty -Path $MainKey -Name 'First Home Page' -Force -ErrorAction Ignore
    Set-ItemProperty -Path $MainKey -Name 'Default_Page_URL' -Value "http://$using:NLBWebSiteName" -Force
    Set-ItemProperty -Path $MainKey -Name 'Start Page' -Value "http://$using:NLBWebSiteName" -Force

    #Setting nlb.contoso.com, IISNODE01.contoso.com and IISNODE02.contoso.com in the Local Intranet Zone for all servers : mandatory for Kerberos authentication       
    $null = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$using:NLBWebSiteName" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$using:NLBWebSiteName" -Name http -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$using:NLBWebSiteName" -Name https -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Force
    $null = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\IISNODE01.$using:FQDNDomainName" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\IISNODE01.$using:FQDNDomainName" -Name http -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\IISNODE01.$using:FQDNDomainName" -Name https -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Force
    $null = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\IISNODE02.$using:FQDNDomainName" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\IISNODE02.$using:FQDNDomainName" -Name http -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\IISNODE02.$using:FQDNDomainName" -Name https -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Force

    #Changing the start page for IE
    $path = "HKCU:\Software\Microsoft\Internet Explorer\Main\"
    $name = "start page"
    $value = "https://$using:NLBWebSiteName/"
    Set-ItemProperty -Path $path -Name $name -Value $value -Force
    #Bonus : To open all the available websites accross all nodes
    $name = "Secondary Start Pages"
    $value = "https://IISNODE01.$using:FQDNDomainName", "https://IISNODE02.$using:FQDNDomainName"
    New-ItemProperty -Path $path -PropertyType MultiString -Name $name -Value $value -Force
    #endregion
}

#Installing and setting up DFS-R on DC for replicated folder on IIS Servers for shared configuration
Invoke-LabCommand -ActivityName 'DNS & DFS-R Setup on DC' -ComputerName DC01 -ScriptBlock {
    New-ADUser -Name "$Using:IISAppPoolUser" -PasswordNeverExpires $True -AccountPassword $Using:SecurePassword -CannotChangePassword $True -Enabled $True

    #region DNS management
    #Reverse lookup zone creation
    Add-DnsServerPrimaryZone -NetworkID $using:NetworkID -ReplicationScope 'Forest' 
    #DNS Host entry for the nlb.contoso.com website 
    Add-DnsServerResourceRecordA -Name $using:NLBNetBiosName -ZoneName $using:FQDNDomainName -IPv4Address $using:NLBIPv4Address -CreatePtr
    #endregion

    #region Setting SPN on the Application Pool Identity
    Set-ADUser -Identity "$Using:IISAppPoolUser" -ServicePrincipalNames @{Add = "HTTP/$using:NLBWebSiteName", "HTTP/$using:NLBNetBiosName", "HTTP/IISNODE01.$using:FQDNDomainName", "HTTP/IISNODE01", "HTTP/IISNODE02.$using:FQDNDomainName", "HTTP/IISNODE02" }
    #endregion
}

Invoke-LabCommand -ActivityName 'DFS-R Setup' -ComputerName IISNODE01 -ScriptBlock {
    #region IIS Shared Configuration
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
    #endregion

    #region Central Certificate Store
    #Removing any DFS Replication group with the same name
    Get-DfsReplicationGroup -GroupName 'Central Certificate Store' | Remove-DfsReplicationGroup -Force -RemoveReplicatedFolders
    #Creating the DFS Replication group for the shared configuration
    New-DfsReplicationGroup -GroupName 'Central Certificate Store' |
    New-DfsReplicatedFolder -FolderName 'C:\CentralCertificateStore' |
    Add-DfsrMember -ComputerName IISNODE01, IISNODE02
    #Adding the member (replication in both ways)
    Add-DfsrConnection -GroupName 'Central Certificate Store' -SourceComputerName 'IISNODE01' -DestinationComputerName 'IISNODE02'
    #Adding the members and specifiyng the primary server
    Set-DfsrMembership -GroupName 'Central Certificate Store' -FolderName 'C:\CentralCertificateStore' -ContentPath 'C:\CentralCertificateStore' -ComputerName 'IISNODE01' -PrimaryMember $True -Force
    Set-DfsrMembership -GroupName 'Central Certificate Store' -FolderName 'C:\CentralCertificateStore' -ContentPath 'C:\CentralCertificateStore' -ComputerName 'IISNODE02' -Force
    #endregion
}

Invoke-LabCommand -ActivityName 'Restarting the DFSR Service' -ComputerName IISNODE01, IISNODE02 -ScriptBlock {
    Restart-Service -Name DFSR -Force
}
#IIS front-end servers : Setting up the metric for NLB management
Invoke-LabCommand -ActivityName 'Setting up the metric for NLB management' -ComputerName IISNODE01, IISNODE02 -ScriptBlock {
    Get-NetAdapter -Name 'Internal' | Set-NetIPInterface -InterfaceMetric 1
    Get-NetAdapter -Name 'NLB'| Set-NetIPInterface -InterfaceMetric 2
}

Invoke-LabCommand -ActivityName 'NLB Setup' -ComputerName IISNODE01 {
    #Creating new NLB cluster
    New-NlbCluster -HostName IISNODE01 -ClusterName "$using:NLBWebSiteName" -InterfaceName NLB -ClusterPrimaryIP $using:NLBIPv4Address -SubnetMask 255.255.0.0 -OperationMode 'Multicast'
    #Removing default port rule for the new cluster
    #Get-NlbClusterPortRule -HostName . | Remove-NlbClusterPortRule -Force
    #Adding port rules
    #Add-NlbClusterPortRule -Protocol Tcp -Mode Multiple -Affinity Single -StartPort 80 -EndPort 80 -InterfaceName $InterfaceName | Out-Null
    #Add-NlbClusterPortRule -Protocol Tcp -Mode Multiple -Affinity Single -StartPort 443 -EndPort 443 -InterfaceName $InterfaceName | Out-Null
    #Adding the second node to the cluster
    Get-NlbCluster | Add-NlbClusterNode -NewNodeName IISNODE02 -NewNodeInterface NLB
    #Client Affinity: Do not enable it to see the load balacing between the two IIS Servers    
    Get-NlbClusterPortRule | Set-NlbClusterPortRule -NewAffinity None
}

#region Certification Authority : Creation and SSL Certificate Generation
#Get the CA
$CertificationAuthority = Get-LabIssuingCA
#Generating a new template for SSL Web Server certificate
New-LabCATemplate -TemplateName WebServerSSL -DisplayName 'Web Server SSL' -SourceTemplateName WebServer -ApplicationPolicy 'Server Authentication' -EnrollmentFlags Autoenrollment -PrivateKeyFlags AllowKeyExport -Version 2 -SamAccountName 'Domain Computers' -ComputerName $CertificationAuthority -ErrorAction Stop
#Getting a New SSL Web Server Certificate
$WebServerSSLCert = Request-LabCertificate -Subject "CN=$NLBWebSiteName" -SAN $NLBWebSiteName, $NLBNetBiosName, "IISNODE01", "IISNODE01.$FQDNDomainName", "IISNODE02", "IISNODE02.$FQDNDomainName" -TemplateName WebServerSSL -ComputerName IISNODE01 -OnlineCA $CertificationAuthority.Name -PassThru -ErrorAction Stop
#endregion

#Copying Web site content on all IIS servers
Copy-LabFileItem -Path $CurrentDir\nlb.contoso.com.zip -DestinationFolderPath C:\Temp -ComputerName IISNODE01, IISNODE02

#Generating machine key (to standardize across all Web farm nodes)
$MachineKey = New-MachineKey

Invoke-LabCommand -ActivityName 'Exporting the Web Server Certificate into the future "Central Certificate Store" directory' -ComputerName IISNODE01 -ScriptBlock {
    $WebServerSSLCert = Get-ChildItem -Path Cert:\LocalMachine\My\ -DnsName "$using:NLBWebSiteName" -SSLServerAuthentication | Where-Object -FilterScript {
        $_.hasPrivateKey 
    }  

    $PFXFilePath = "C:\CentralCertificateStore\$using:NLBWebSiteName.pfx"
    if ($WebServerSSLCert) {
        $WebServerSSLCert | Export-PfxCertificate -FilePath $PFXFilePath -Password $Using:SecurePassword
        #Bonus : To access directly to the SSL web site hosted on IIS nodes by using the node names
    }
    else {
        Write-Error -Exception "[ERROR] Unable to get or export the 'Web Server SSL' certificate for $using:NLBWebSiteName"
    }
}

Invoke-LabCommand -ActivityName 'Duplicating the Web Server Certificate into the future "Central Certificate Store" directory for SAN, Unzipping Web Site Content and Setting up the Website' -ComputerName IISNODE01, IISNODE02 -ScriptBlock {
    $PFXFilePath = "C:\CentralCertificateStore\$using:NLBWebSiteName.pfx"

    Copy-Item $PFXFilePath "C:\CentralCertificateStore\$env:COMPUTERNAME.$using:FQDNDomainName.pfx" -Force
    #$WebServerSSLCert | Remove-Item -Force

    #Enabling the Central Certificate Store
    Enable-WebCentralCertProvider -CertStoreLocation 'C:\CentralCertificateStore\' -UserName $Using:Logon -Password $Using:ClearTextPassword -PrivateKeyPassword $Using:ClearTextPassword

    #Creating replicated folder for shared configuration
    New-Item -Path C:\IISSharedConfiguration -ItemType Directory -Force

    Expand-Archive 'C:\Temp\nlb.contoso.com.zip' -DestinationPath C:\inetpub\wwwroot -Force

    #PowerShell module for IIS Management
    Import-Module -Name WebAdministration
    #Removing "Default Web Site"
    Remove-WebSite -Name 'Default Web Site'

    #Creating a dedicated application pool
    New-WebAppPool -Name "$using:NLBWebSiteName" -Force

    #Changing the application pool identity to classic mode (for ASP.Net impersonation)
    #Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/applicationPools/add[@name='$using:NLBWebSiteName']" -name "managedPipelineMode" -value "Classic"
    #Changing the application pool identity for an AD Account : mandatory for Kerberos authentication
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/applicationPools/add[@name='$using:NLBWebSiteName']/processModel" -name 'identityType' -value 3
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/applicationPools/add[@name='$using:NLBWebSiteName']/processModel" -name 'userName' -value "$Using:NetBiosDomainName\$Using:IISAppPoolUser"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/applicationPools/add[@name='$using:NLBWebSiteName']/processModel" -name 'password' -value $Using:ClearTextPassword

    #Creating a dedicated web site 
    #New-WebSite -Name "$using:NLBWebSiteName" -Port 80 -PhysicalPath "$env:systemdrive\inetpub\wwwroot" -ApplicationPool $using:NLBWebSiteName -Force
    #Adding a HTTP:443 Binding
    #0: Regular certificate in Windows certificate storage.
    #1: SNI certificate.
    #2: Central certificate store.
    #3: SNI certificate in central certificate store.
    New-WebSite -Name "$using:NLBWebSiteName" -Port 443 -PhysicalPath "$env:systemdrive\inetpub\wwwroot" -ApplicationPool $using:NLBWebSiteName -Ssl -SslFlags 3 -HostHeader "$using:NLBWebSiteName" -Force
    #Assigning the nlb.contoso.com application pool to the nlb.contoso.com web site
    #Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/site[@name='$using:NLBWebSiteName']/application[@path='/']" -name 'applicationPool' -value "$using:NLBWebSiteName"
    #Enabling the Windows useAppPoolCredentials
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:NLBWebSiteName" -filter 'system.webServer/security/authentication/windowsAuthentication' -name 'useAppPoolCredentials' -value 'True'

    #setting default.aspx as first default page
    Remove-WebconfigurationProperty -Filter 'system.webserver/defaultdocument/files' -Location "IIS:\sites\$using:NLBWebSiteName" -name collection -AtElement @{
        value = 'default.aspx'
    } -Force
    Add-WebConfiguration -Filter 'system.webserver/defaultdocument/files' -Location "IIS:\sites\$using:NLBWebSiteName" -atIndex 0 -Value @{
        value = 'default.aspx'
    } -Force
    
    #Adding a HTTP:443 Binding
    #0: Regular certificate in Windows certificate storage.
    #1: SNI certificate.
    #2: Central certificate store.
    #3: SNI certificate in central certificate store.
    #New-WebBinding -Name "$using:NLBWebSiteName" -Port 443 -IPAddress * -Protocol https -sslFlags 3 -HostHeader "$using:NLBWebSiteName"
    #Binding for the Web site
    #New-WebBinding -Name "$using:NLBWebSiteName" -sslFlags 3 -Protocol https -HostHeader "$using:NLBWebSiteName"
    #Binding for every IIS nodes
    New-WebBinding -Name "$using:NLBWebSiteName" -sslFlags 3 -Protocol https -HostHeader "IISNODE01.$using:FQDNDomainName"
    New-WebBinding -Name "$using:NLBWebSiteName" -sslFlags 3 -Protocol https -HostHeader "IISNODE02.$using:FQDNDomainName"
    New-Item -Path "IIS:\SslBindings\!443!$using:NLBWebSiteName" -sslFlags 3 -Store CentralCertStore
    #Removing Default Binding
    #Get-WebBinding -Port 80 -Name "$using:NLBWebSiteName" | Remove-WebBinding

    #Require SSL
    Get-IISConfigSection -SectionPath 'system.webServer/security/access' -location "$using:NLBWebSiteName" | Set-IISConfigAttributeValue -AttributeName sslFlags -AttributeValue Ssl

    #Disabling the Anonymous authentication
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:NLBWebSiteName" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'False'
    #Enabling the Windows authentication
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:NLBWebSiteName" -filter 'system.webServer/security/authentication/windowsAuthentication' -name 'enabled' -value 'True'
    #Enabling ASP.Net Impersonation 
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:NLBWebSiteName" -filter 'system.web/identity' -name 'impersonate' -value 'True'

    #Disabling validation for application pool in integrated mode due to ASP.Net impersonation incompatibility
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:NLBWebSiteName" -filter 'system.webServer/validation' -name 'validateIntegratedModeConfiguration' -value 'False' -Verbose

    #Standardizing up machine keys across the web farm nodes
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:NLBWebSiteName" -filter '/system.web/machinekey' -Name Decryption -Value $using:MachineKey
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:NLBWebSiteName" -filter '/system.web/machinekey' -Name DecryptionKey -Value $using:MachineKey
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:NLBWebSiteName" -filter '/system.web/machinekey' -Name Validation -Value $using:MachineKey
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:NLBWebSiteName" -filter '/system.web/machinekey' -Name ValidationKey -Value $using:MachineKey
}

#Exporting IIS Shared Configuration From The First IIS Node
Invoke-LabCommand -ActivityName 'Exporting IIS Shared Configuration' -ComputerName IISNODE01 {
    #Exporting the configuration only from one node
    Export-IISConfiguration -PhysicalPath C:\IISSharedConfiguration -KeyEncryptionPassword $Using:SecurePassword -Force
}

#Enabling the shared configuration for all IIS nodes
Invoke-LabCommand -ActivityName 'Enabling IIS Shared Configuration' -ComputerName IISNODE01, IISNODE02 -ScriptBlock {
    #Waiting the DFS replication completes
    While (-not(Test-Path -Path C:\IISSharedConfiguration\applicationHost.config)) {
        Write-Verbose -Message 'Waiting the replication via DFS-R of applicationHost.config. Sleeping 10 seconds ...'
        Start-Sleep -Seconds 10
    }
    Enable-IISSharedConfig -PhysicalPath C:\IISSharedConfiguration -KeyEncryptionPassword $Using:SecurePassword -Force
    
}

#Waiting for background jobs
$Job | Wait-Job | Out-Null

Show-LabDeploymentSummary
Checkpoint-LabVM -SnapshotName 'FullInstall' -All -Verbose
$VerbosePreference = $PreviousVerbosePreference
$ErrorActionPreference = $PreviousErrorActionPreference
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose

Stop-Transcript