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
$TranscriptFile = $CurrentScript -replace ".ps1$", "_$("{0:yyyyMMddHHmmss}" -f (Get-Date)).txt"
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
            $builder = new-object System.Text.StringBuilder
            foreach ($b in $bytes) {
              $builder = $builder.AppendFormat([System.Globalization.CultureInfo]::InvariantCulture, "{0:X2}", $b)
            }
            $builder
        }
    }
    switch ($decryptionAlgorithm) {
      "AES" { $decryptionObject = new-object System.Security.Cryptography.AesCryptoServiceProvider }
      "DES" { $decryptionObject = new-object System.Security.Cryptography.DESCryptoServiceProvider }
      "3DES" { $decryptionObject = new-object System.Security.Cryptography.TripleDESCryptoServiceProvider }
    }
    $decryptionObject.GenerateKey()
    $decryptionKey = BinaryToHex($decryptionObject.Key)
    $decryptionObject.Dispose()
    switch ($validationAlgorithm) {
      "MD5" { $validationObject = new-object System.Security.Cryptography.HMACMD5 }
      "SHA1" { $validationObject = new-object System.Security.Cryptography.HMACSHA1 }
      "HMACSHA256" { $validationObject = new-object System.Security.Cryptography.HMACSHA256 }
      "HMACSHA385" { $validationObject = new-object System.Security.Cryptography.HMACSHA384 }
      "HMACSHA512" { $validationObject = new-object System.Security.Cryptography.HMACSHA512 }
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
        "decryption" = [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "{0}", $decryptionAlgorithm.ToUpperInvariant(), $decryptionKey, $validationAlgorithm.ToUpperInvariant(), $validationKey)
        "decryptionKey" = [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "{0}", $decryptionKey)
        "validation" = [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "{0}", $validationAlgorithm.ToUpperInvariant())
        "validationKey" = [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "{0}", $validationKey)
    }
  }
}
#endregion

#region Global variables definition
$Logon = 'Administrator'
$ClearTextPassword = 'P@ssw0rd'
$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$FQDNDomainName = 'contoso.com'
#$NetBiosDomainName = 'CONTOSO'
$NetBiosDomainName = $FQDNDomainName.split('\.')[0].ToUpper()
$IISAppPoolUser = 'IISAppPoolUser'

$NetworkID='10.0.0.0/16' 

$DCIPv4Address = '10.0.0.1'
$CAIPv4Address = '10.0.0.2'

$IISNODE01IPv4Address = '10.0.0.11'
$IISNODE02IPv4Address = '10.0.0.12'

$ARRNODE01IPv4Address = '10.0.0.21/16'
$ARRNODE02IPv4Address = '10.0.0.22/16'
$NLBARRNODE01IPv4Address = '10.0.0.201/16'
$NLBARRNODE02IPv4Address = '10.0.0.202/16'

$ARRNetBiosName='arr'
$ARRWebSiteName="$ARRNetBiosName.$FQDNDomainName"
$ARRIPv4Address = '10.0.0.101'

$MSEdgeEntUri = "http://go.microsoft.com/fwlink/?LinkID=2093437"
$LabName = 'NLBARRLab'
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
}  -AddressSpace $NetworkID

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
    'Add-LabMachineDefinition:Processors'      = 2
}

#Domain controller
Add-LabMachineDefinition -Name DC01 -Roles RootDC -IpAddress $DCIPv4Address
#Certificate Authority
Add-LabMachineDefinition -Name CA01 -Roles CARoot -IpAddress $CAIPv4Address

#region IIS front-end servers
Add-LabMachineDefinition -Name IISNODE01 -IpAddress $IISNODE01IPv4Address
Add-LabMachineDefinition -Name IISNODE02 -IpAddress $IISNODE02IPv4Address
#endregion

#region ARR servers : 2 NICS for  (1 for server communications and 1 for NLB)
$netAdapter = @()
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $ARRNODE01IPv4Address -InterfaceName 'Internal'
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $NLBARRNODE01IPv4Address -InterfaceName 'NLB'
Add-LabMachineDefinition -Name ARRNODE01 -NetworkAdapter $netAdapter

$netAdapter = @()
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $ARRNODE02IPv4Address -InterfaceName 'Internal'
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $NLBARRNODE02IPv4Address -InterfaceName 'NLB'
Add-LabMachineDefinition -Name ARRNODE02 -NetworkAdapter $netAdapter
#endregion

#Installing servers
Install-Lab -DelayBetweenComputers 30
Checkpoint-LabVM -SnapshotName FreshInstall -All -Verbose


#region Installing Required Windows Features
$machines = Get-LabVM
Install-LabWindowsFeature -FeatureName Telnet-Client -ComputerName $machines -IncludeManagementTools
Install-LabWindowsFeature -FeatureName FS-DFS-Replication, Web-Server, Web-Asp-Net45, Web-Request-Monitor -ComputerName IISNODE01, IISNODE02, ARRNODE01, ARRNODE02 -IncludeManagementTools
Install-LabWindowsFeature -FeatureName FS-DFS-Replication -ComputerName DC01 -IncludeManagementTools
Install-LabWindowsFeature -FeatureName NLB, Web-CertProvider -ComputerName ARRNODE01, ARRNODE02 -IncludeManagementTools
Install-LabWindowsFeature -FeatureName Web-Windows-Auth -ComputerName IISNODE01, IISNODE02 -IncludeManagementTools
#endregion

$MSEdgeEnt = Get-LabInternetFile -Uri $MSEdgeEntUri -Path $labSources\SoftwarePackages -PassThru
Install-LabSoftwarePackage -ComputerName $machines -Path $MSEdgeEnt.FullName -CommandLine "/passive /norestart" -AsJob

Invoke-LabCommand -ActivityName "Disabling IE ESC and Adding $ARRWebSiteName to the IE intranet zone" -ComputerName $machines -ScriptBlock {
    #Disabling IE ESC
    $AdminKey = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}'
    $UserKey = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}'
    Set-ItemProperty -Path $AdminKey -Name 'IsInstalled' -Value 0 -Force
    Set-ItemProperty -Path $UserKey -Name 'IsInstalled' -Value 0 -Force
    Rundll32 iesetup.dll, IEHardenLMSettings
    Rundll32 iesetup.dll, IEHardenUser
    Rundll32 iesetup.dll, IEHardenAdmin
    Remove-Item -Path $AdminKey -Force
    Remove-Item -Path $UserKey -Force

    $MainKey = 'HKCU:\Software\Microsoft\Internet Explorer\Main'
    Remove-ItemProperty -Path $MainKey -Name 'First Home Page' -Force -ErrorAction Ignore
    Set-ItemProperty -Path $MainKey -Name 'Default_Page_URL' -Value "http://$using:ARRWebSiteName" -Force
    Set-ItemProperty -Path $MainKey -Name 'Start Page' -Value "http://$using:ARRWebSiteName" -Force

    #Setting arr.contoso.com (and optionally all nodes) in the Local Intranet Zone for all servers : mandatory for Kerberos authentication       
    $null = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$using:ARRWebSiteName" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$using:ARRWebSiteName" -Name http -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$using:ARRWebSiteName" -Name https -Value 1 -Type DWord -Force
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
    $value = "https://$using:ARRWebSiteName/"
    Set-ItemProperty -Path $path -Name $name -Value $value -Force
    #Bonus : To open all the available websites accross all nodes
    $name = "Secondary Start Pages"
    $value = "https://ARRNODE01.$using:FQDNDomainName", "https://ARRNODE02.$using:FQDNDomainName", "http://iisnode01.$using:FQDNDomainName", "http://iisnode02.$using:FQDNDomainName"
    New-ItemProperty -Path $path -PropertyType MultiString -Name $name -Value $value -Force
}


#Installing and setting up DFS-R on DC for replicated folder on ARR Servers for shared confguration
Invoke-LabCommand -ActivityName 'DNS & DFS-R Setup on DC' -ComputerName DC01 -ScriptBlock {
    New-ADUser -Name "$Using:IISAppPoolUser" -PasswordNeverExpires $True -AccountPassword $Using:SecurePassword -CannotChangePassword $True -Enabled $True

    #region DNS management
    #Reverse lookup zone creation
    Add-DnsServerPrimaryZone -NetworkID $using:NetworkID -ReplicationScope 'Forest' 
    #DNS Host entry for the arr.contoso.com website 
    Add-DnsServerResourceRecordA -Name $using:ARRNetBiosName -ZoneName $using:FQDNDomainName -IPv4Address $using:ARRIPv4Address -CreatePtr
    #Installing DFS-R on ARR servers for the shared configuration
    #Install-WindowsFeature FS-DFS-Replication -includeManagementTools
    #endregion

    #region ARR servers : IIS Shared Configuration
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
    #endregion

    #region IIS front-end servers : IIS Shared Configuration
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
    Add-DfsrMember -ComputerName ARRNODE01, ARRNODE02
    #Adding the member (replication in both ways)
    Add-DfsrConnection -GroupName 'Central Certificate Store' -SourceComputerName 'ARRNODE01' -DestinationComputerName 'ARRNODE02'
    #Adding the members and specifiyng the primary server
    Set-DfsrMembership -GroupName 'Central Certificate Store' -FolderName 'C:\CentralCertificateStore' -ContentPath 'C:\CentralCertificateStore' -ComputerName 'ARRNODE01' -PrimaryMember $True -Force
    Set-DfsrMembership -GroupName 'Central Certificate Store' -FolderName 'C:\CentralCertificateStore' -ContentPath 'C:\CentralCertificateStore' -ComputerName 'ARRNODE02' -Force
    #endregion

    #region Setting SPN on the Application Pool Identity
    <#
    setspn.exe -S "HTTP/$using:ARRWebSiteName" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    setspn.exe -S "HTTP/$using:ARRNetBiosName" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    setspn.exe -S "HTTP/IISNODE01.$using:FQDNDomainName" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    setspn.exe -S "HTTP/IISNODE01" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    setspn.exe -S "HTTP/IISNODE02.$using:FQDNDomainName" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    setspn.exe -S "HTTP/IISNODE02" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    setspn.exe -S "HTTP/ARRNODE01.$using:FQDNDomainName" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    setspn.exe -S "HTTP/ARRNODE01" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    setspn.exe -S "HTTP/ARRNODE02.$using:FQDNDomainName" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    setspn.exe -S "HTTP/ARRNODE02" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    #>
    Set-ADUser -Identity "$Using:IISAppPoolUser" -ServicePrincipalNames @{Add="HTTP/$using:ARRWebSiteName", "HTTP/$using:ARRNetBiosName", "HTTP/IISNODE01.$using:FQDNDomainName", "HTTP/IISNODE01", "HTTP/IISNODE02.$using:FQDNDomainName", "HTTP/IISNODE02", "HTTP/ARRNODE01.$using:FQDNDomainName", "HTTP/ARRNODE01", "HTTP/ARRNODE02.$using:FQDNDomainName", "HTTP/ARRNODE02"}
    #endregion
}

#ARR servers : Renaming the NIC and setting up the metric for NLB management
Invoke-LabCommand -ActivityName 'Renaming NICs' -ComputerName ARRNODE01, ARRNODE02 -ScriptBlock {

    #Renaming the NIC and setting up the metric for NLB management
    #Rename-NetAdapter -Name "$using:labName 0" -NewName 'Internal' -PassThru | Set-NetIPInterface -InterfaceMetric 1
    #Rename-NetAdapter -Name "$using:labName 1" -NewName 'NLB' -PassThru | Set-NetIPInterface -InterfaceMetric 2

    Get-NetAdapter -Name 'Internal' | Set-NetIPInterface -InterfaceMetric 1
    Get-NetAdapter -Name 'NLB'| Set-NetIPInterface -InterfaceMetric 2
}

Invoke-LabCommand -ActivityName 'NLB Setup' -ComputerName ARRNODE01 {
    #Creating new NLB cluster
    New-NlbCluster -HostName ARRNODE01 -ClusterName "$using:ARRWebSiteName" -InterfaceName NLB -ClusterPrimaryIP $using:ARRIPv4Address  -SubnetMask 255.255.0.0 -OperationMode 'Multicast'
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

#region Certification Authority : Creation and SSL Certificate Generation
#Get the CA
$CertificationAuthority = Get-LabIssuingCA
#Generating a new template for SSL Web Server certificate
New-LabCATemplate -TemplateName WebServerSSL -DisplayName 'Web Server SSL' -SourceTemplateName WebServer -ApplicationPolicy 'Server Authentication' -EnrollmentFlags Autoenrollment -PrivateKeyFlags AllowKeyExport -Version 2 -SamAccountName 'Domain Computers' -ComputerName $CertificationAuthority -ErrorAction Stop
#Getting a New SSL Web Server Certificate
$WebServerSSLCert = Request-LabCertificate -Subject "CN=$ARRWebSiteName" -SAN $ARRWebSiteName, $ARRNetBiosName, "ARRNODE01", "ARRNODE01.$FQDNDomainName", "ARRNODE02", "ARRNODE02.$FQDNDomainName" -TemplateName WebServerSSL -ComputerName ARRNODE01, ARRNODE02 -OnlineCA $CertificationAuthority.Name -PassThru -ErrorAction Stop
#endregion

#Copying Web site content on all IIS & ARR servers
Copy-LabFileItem -Path $CurrentDir\arr.contoso.com.zip -DestinationFolderPath C:\Temp -ComputerName ARRNODE01, ARRNODE02, IISNODE01, IISNODE02
#Copying required IIS extensions on the ARR servers for ARR
Copy-LabFileItem -Path $CurrentDir\Extensions.zip -DestinationFolderPath C:\Temp -ComputerName ARRNODE01, ARRNODE02

Invoke-LabCommand -ActivityName 'Exporting the Web Server Certificate into the future "Central Certificate Store" directory' -ComputerName ARRNODE01, ARRNODE02 -ScriptBlock {
    #Restarting DFSR service
    Restart-Service -Name DFSR -Force
    Start-Sleep -Seconds 10

    #Creating replicated folder for Central Certificate Store
    New-Item -Path C:\CentralCertificateStore -ItemType Directory -Force

    #Creating replicated folder for shared configuration
    New-Item -Path C:\ARRSharedConfiguration -ItemType Directory -Force

    $WebServerSSLCert = Get-ChildItem -Path Cert:\LocalMachine\My\ -DnsName "$using:ARRWebSiteName" -SSLServerAuthentication | Where-Object -FilterScript {
        $_.hasPrivateKey 
    }  

    $PFXFilePath = "C:\CentralCertificateStore\$using:ARRWebSiteName.pfx"
    if ($WebServerSSLCert) {
        $WebServerSSLCert | Export-PfxCertificate -FilePath $PFXFilePath -Password $Using:SecurePassword
        #Bonus : To access directly to the SSL web site hosted on IIS nodes by using the node names
        Copy-Item $PFXFilePath "C:\CentralCertificateStore\$env:COMPUTERNAME.$using:FQDNDomainName.pfx"
        $WebServerSSLCert | Remove-Item -Force
    }
    else {
        Write-Error -Exception "[ERROR] Unable to get or export the 'Web Server SSL' certificate for $using:ARRWebSiteName"
    }

    #Enabling the Central Certificate Store
    Enable-WebCentralCertProvider -CertStoreLocation 'C:\CentralCertificateStore\' -UserName $Using:Logon -Password $Using:ClearTextPassword -PrivateKeyPassword $Using:ClearTextPassword
}

#Installing IIS and ASP.Net on all servers excepts DC
Invoke-LabCommand -ActivityName 'IIS Setup' -ComputerName IISNODE01, IISNODE02, ARRNODE01, ARRNODE02 -ScriptBlock {
    Expand-Archive 'C:\Temp\arr.contoso.com.zip' -DestinationPath C:\inetpub\wwwroot -Force

    #PowerShell module for IIS Management
    Import-Module -Name WebAdministration

    #Removing "Default Web Site"
    Remove-WebSite -Name 'Default Web Site'

    #Creating a dedicated application pool
    New-WebAppPool -Name "$using:ARRWebSiteName" -Force

    #Changing the application pool identity to classic mode (for ASP.Net impersonation)
    #Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='$using:ARRWebSiteName']" -name "managedPipelineMode" -value "Classic"
    #Changing the application pool identity for an AD Account : mandatory for Kerberos authentication
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='$using:ARRWebSiteName']/processModel" -name 'identityType' -value 3
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='$using:ARRWebSiteName']/processModel" -name 'userName' -value "$Using:NetBiosDomainName\$Using:IISAppPoolUser"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='$using:ARRWebSiteName']/processModel" -name 'password' -value $Using:ClearTextPassword

    #Creating a dedicated web site 
    New-WebSite -Name "$using:ARRWebSiteName" -Port 80 -PhysicalPath "$env:systemdrive\inetpub\wwwroot" -ApplicationPool $using:ARRWebSiteName -Force
    #Assigning the arr.contoso.com application pool to the arr.contoso.com web site
    #Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:ARRWebSiteName']/application[@path='/']" -name 'applicationPool' -value "$using:ARRWebSiteName"
    #Enabling the Windows useAppPoolCredentials
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:ARRWebSiteName" -filter 'system.webServer/security/authentication/windowsAuthentication' -name 'useAppPoolCredentials' -value 'True'

    #setting default.aspx as first default page
    Remove-WebconfigurationProperty -Filter 'system.webserver/defaultdocument/files' -Location "IIS:\sites\$using:ARRWebSiteName" -name collection -AtElement @{
        value = 'default.aspx'
    } -Force
    Add-WebConfiguration -Filter 'system.webserver/defaultdocument/files' -Location "IIS:\sites\$using:ARRWebSiteName" -atIndex 0 -Value @{
        value = 'default.aspx'
    } -Force
    
}

Invoke-LabCommand -ActivityName 'IIS Extensions, SNI/CSS Setup, ARR and URL Rewrite Setup' -ComputerName ARRNODE01, ARRNODE02 -ScriptBlock {
    Expand-Archive 'C:\Temp\Extensions.zip' -DestinationPath C:\ -Force
    C:\Extensions\Install-IISExtension.ps1

    #Adding handler for image watermark
    Add-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:ARRWebSiteName"  -filter 'system.webServer/handlers' -name '.' -value @{
        name          = 'JpgHttpHandler'
        path          = '*.jpg'
        type          = 'JpgHttpHandler'
        verb          = '*'
        resourceType  = 'Unspecified'
        requireAccess = 'Script'
    }
    Add-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:ARRWebSiteName"  -filter 'system.webServer/handlers' -name '.' -value @{
        name          = 'GifHttpHandler'
        path          = '*.gif'
        type          = 'JpgHttpHandler'
        verb          = '*'
        resourceType  = 'Unspecified'
        requireAccess = 'Script'
    }
    Add-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:ARRWebSiteName"  -filter 'system.webServer/handlers' -name '.' -value @{
        name          = 'PngHttpHandler'
        path          = '*.png'
        type          = 'JpgHttpHandler'
        verb          = '*'
        resourceType  = 'Unspecified'
        requireAccess = 'Script'
    }

    Import-Module -Name WebAdministration
    #Adding a HTTP:443 Binding
    #0: Regular certificate in Windows certificate storage.
    #1: SNI certificate.
    #2: Central certificate store.
    #3: SNI certificate in central certificate store.
    New-WebBinding -Name "$using:ARRWebSiteName" -sslFlags 3 -Protocol https -HostHeader "$using:ARRWebSiteName"
    #Binding for every ARR server nodes
    New-WebBinding -Name "$using:ARRWebSiteName" -sslFlags 3 -Protocol https -HostHeader "ARRNODE01.$using:FQDNDomainName"
    New-WebBinding -Name "$using:ARRWebSiteName" -sslFlags 3 -Protocol https -HostHeader "ARRNODE02.$using:FQDNDomainName"
    New-Item -Path "IIS:\SslBindings\!443!$using:ARRWebSiteName" -sslFlags 3 -Store CentralCertStore


    #Removing Default Binding
    #Get-WebBinding -Port 80 -Name "$using:ARRWebSiteName" | Remove-WebBinding

    #Require SSL
    Get-IISConfigSection -SectionPath 'system.webServer/security/access' -Location "$using:ARRWebSiteName" | Set-IISConfigAttributeValue -AttributeName sslFlags -AttributeValue Ssl

    Do {
        #ARR Webfarm
        Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'webFarms' -Name '.' -Value @{
            name    = "$using:ARRWebSiteName"
            enabled = $True
        }
        Write-Verbose -Message 'Waiting the creation of the ARR web farm. Sleeping 10 seconds ...'
        Start-Sleep -Seconds 10
    } While (-not(Get-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "webFarms/webFarm[@name='$using:ARRWebSiteName']"))

    Add-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "webFarms/webFarm[@name='$using:ARRWebSiteName']" -Value @(
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
    #Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "webFarms/webFarm[@name='$using:ARRWebSiteName']/server[@address='ARRNODE01']" -Name 'applicationRequestRouting' -Value @{ httpPort = 80 }
    #Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "webFarms/webFarm[@name='$using:ARRWebSiteName']/server[@address='ARRNODE02']" -Name 'applicationRequestRouting' -Value @{ httpPort = 80 }
    #Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "webFarms/webFarm[@name='$using:ARRWebSiteName']/server[@address='ARRNODE01']" -Name 'applicationRequestRouting' -Value @{ httpPort = 443 }
    #Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "webFarms/webFarm[@name='$using:ARRWebSiteName']/server[@address='ARRNODE02']" -Name 'applicationRequestRouting' -Value @{ httpPort = 443 }

    #Healthcheck test page and pattern to found if ok
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "webFarms/webFarm[@name='$using:ARRWebSiteName']/applicationRequestRouting" -Name 'healthcheck' -Value @{
        url           = "http://$using:ARRWebSiteName/healthcheck/default.aspx"
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
        name           = "ARR_$($using:ARRWebSiteName)_loadbalance"
        patternSyntax  = 'Wildcard'
        stopProcessing = 'True'
        enabled        = $True
    }
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/rewrite/globalRules/rule[@name='ARR_$($using:ARRWebSiteName)_loadbalance']/match" -name 'url' -value '*'
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/rewrite/globalRules/rule[@name='ARR_$($using:ARRWebSiteName)_loadbalance']/action" -name 'type' -value 'Rewrite'
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/rewrite/globalRules/rule[@name='ARR_$($using:ARRWebSiteName)_loadbalance']/action" -name 'url' -value "http://$using:ARRWebSiteName/{R:0}"
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/rewrite/globalRules/rule[@name='ARR_$($using:ARRWebSiteName)_loadbalance']/conditions" -name '.' -value @{
        input   = '{HTTP_HOST}'
        pattern = "$using:ARRWebSiteName"
    }

    #Client Affinity: Do not enable it to see the load balacing between the two IIS Servers
    #Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "webFarms/webFarm[@name='$using:ARRWebSiteName']/applicationRequestRouting/affinity" -name "useCookie" -value "True"

    #Extensions not forwarded
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/rewrite/globalRules/rule[@name='ARR_$($using:ARRWebSiteName)_loadbalance']/conditions" -name '.' -value @{
        input   = 'EXT_{URL}'
        pattern = '*.css'
        negate  = 'True'
    }
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/rewrite/globalRules/rule[@name='ARR_$($using:ARRWebSiteName)_loadbalance']/conditions" -name '.' -value @{
        input   = 'EXT_{URL}'
        pattern = '*.jpg'
        negate  = 'True'
    }
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/rewrite/globalRules/rule[@name='ARR_$($using:ARRWebSiteName)_loadbalance']/conditions" -name '.' -value @{
        input   = 'EXT_{URL}'
        pattern = '*.gif'
        negate  = 'True'
    }
    
    #Patterns not forwarded
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/rewrite/globalRules/rule[@name='ARR_$($using:ARRWebSiteName)_loadbalance']/conditions" -name '.' -value @{
        input   = '{URL}'
        pattern = '/images/*'
        negate  = 'True'
    }
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/rewrite/globalRules/rule[@name='ARR_$($using:ARRWebSiteName)_loadbalance']/conditions" -name '.' -value @{
        input   = '{URL}'
        pattern = '/css/*'
        negate  = 'True'
    }
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/rewrite/globalRules/rule[@name='ARR_$($using:ARRWebSiteName)_loadbalance']/conditions" -name '.' -value @{
        input   = '{URL}'
        pattern = '/javascript/*'
        negate  = 'True'
    }
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/rewrite/globalRules/rule[@name='ARR_$($using:ARRWebSiteName)_loadbalance']/conditions" -name '.' -value @{
        input   = '{URL}'
        pattern = '/js/*'
        negate  = 'True'
    }
}

#Generating machine key (to standardize across all IIS nodes)
$MachineKey = New-MachineKey
Invoke-LabCommand -ActivityName 'Windows Authentication and Machine Keys Setup' -ComputerName IISNODE01, IISNODE02 -ScriptBlock {
    #Changing the application pool identity for an AD Account : mandatory for Kerberos authentication
    Import-Module -Name WebAdministration
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='$using:ARRWebSiteName']/processModel" -name 'identityType' -value 3
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='$using:ARRWebSiteName']/processModel" -name 'userName' -value "$Using:NetBiosDomainName\$Using:IISAppPoolUser"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='$using:ARRWebSiteName']/processModel" -name 'password' -value $Using:ClearTextPassword

    #Disabling the Anonymous authentication
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:ARRWebSiteName" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'False'
    #Enabling the Windows authentication
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:ARRWebSiteName" -filter 'system.webServer/security/authentication/windowsAuthentication' -name 'enabled' -value 'True'
    
    #Enabling ASP.Net Impersonation
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:ARRWebSiteName" -filter 'system.web/identity' -name 'impersonate' -value 'True'

    #Enabling the Anonymous authentication for the healthcheck folder
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:ARRWebSiteName/healthcheck/" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'True'
    #Disabling the Windows authentication for the healthcheck folder
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:ARRWebSiteName/healthcheck/" -filter 'system.webServer/security/authentication/windowsAuthentication' -name 'enabled' -value 'False'

    #Disabling validation for application pool in integrated mode due to ASP.Net impersonation incompatibility
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:ARRWebSiteName"  -filter 'system.webServer/validation' -name 'validateIntegratedModeConfiguration' -value 'False' -verbose

    #Standardizing up machine keys across the IIS nodes
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:ARRWebSiteName" -filter '/system.web/machinekey' -Name Decryption -Value $using:MachineKey
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:ARRWebSiteName" -filter '/system.web/machinekey' -Name DecryptionKey -Value $using:MachineKey
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:ARRWebSiteName" -filter '/system.web/machinekey' -Name Validation -Value $using:MachineKey
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:ARRWebSiteName" -filter '/system.web/machinekey' -Name ValidationKey -Value $using:MachineKey
}

#Exporting IIS Shared Configuration from the first IIS node
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
    Enable-IISSharedConfig  -PhysicalPath C:\IISSharedConfiguration -KeyEncryptionPassword $Using:SecurePassword -Force   
}

#Exporting IIS Shared Configuration from the first ARR server node
Invoke-LabCommand -ActivityName 'Exporting IIS Shared Configuration' -ComputerName ARRNODE01 {
    #Exporting the configuration only from one node
    Export-IISConfiguration -PhysicalPath C:\ARRSharedConfiguration -KeyEncryptionPassword $Using:SecurePassword -Force
}

#Enabling the shared configuration for all ARR server nodes
Invoke-LabCommand -ActivityName 'Enabling IIS Shared Configuration' -ComputerName ARRNODE01, ARRNODE02 -ScriptBlock {
    #Waiting the DFS replication completes
    While (-not(Test-Path -Path C:\ARRSharedConfiguration\applicationHost.config)) {
        Write-Verbose -Message 'Waiting the replication via DFS-R of applicationHost.config. Sleeping 10 seconds ...'
        Start-Sleep -Seconds 10
    }
    Enable-IISSharedConfig  -PhysicalPath C:\ARRSharedConfiguration -KeyEncryptionPassword $Using:SecurePassword -Force
}

#Waiting for background jobs
Get-Job -Name 'Installation of*' | Wait-Job | Out-Null

Show-LabDeploymentSummary -Detailed
Checkpoint-LabVM -SnapshotName 'FullInstall' -All -Verbose
$VerbosePreference = $PreviousVerbosePreference
$ErrorActionPreference = $PreviousErrorActionPreference
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose

Stop-Transcript