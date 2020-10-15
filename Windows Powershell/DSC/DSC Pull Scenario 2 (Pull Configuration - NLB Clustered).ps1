#requires -Version 5 -Modules AutomatedLab -RunAsAdministrator 
trap {
    Write-Host "Stopping Transcript ..."; Stop-Transcript
    [console]::beep(3000,750)
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

#region Global variables definition
$Logon = 'Administrator'
$ClearTextPassword = 'P@ssw0rd'
$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$NetBiosDomainName = 'CONTOSO'
$FQDNDomainName = 'contoso.com'

$NetworkID = '10.0.0.0/16' 
$DC01IPv4Address = '10.0.0.1'
$CA01IPv4Address = '10.0.0.11'
$ROUTER01IPv4Address = '10.0.0.21'
$SQL01IPv4Address = '10.0.0.31'
$PULL01IPv4Address = '10.0.0.41'
$PULL02IPv4Address = '10.0.0.42'
$SERVER01IPv4Address = '10.0.0.51'
$SERVER02IPv4Address = '10.0.0.52'
$NLBPULL01IPv4Address = '10.0.0.101/16'
$NLBPULL02IPv4Address = '10.0.0.102/16'

$NLBNetBiosName='pull'
$NLBWebSiteName="$NLBNetBiosName.$FQDNDomainName"
$NLBIPv4Address = '10.0.0.100'
$ServerComment='PSDSCPullServer'

$RegistrationKey = Get-LabConfigurationItem -Name DscPullServerRegistrationKey

#Using half of the logical processors to speed up the deployement
[int]$LabMachineDefinitionProcessors = [math]::Max(1, (Get-CimInstance -ClassName Win32_Processor).NumberOfLogicalProcessors)

$LabName = 'DSCPullNLB'
#endregion


#Cleaning previously existing lab
if ($LabName -in (Get-Lab -List))
{
    Remove-Lab -name $LabName -confirm:$false -ErrorAction SilentlyContinue
}

#create an empty lab template and define where the lab XML files and the VMs will be stored
New-LabDefinition -Name $labName -DefaultVirtualizationEngine HyperV

#make the network definition
Add-LabVirtualNetworkDefinition -Name $LabName -HyperVProperties @{
    SwitchType = 'Internal'
} -AddressSpace $NetworkID

Add-LabVirtualNetworkDefinition -Name 'Default Switch' -HyperVProperties @{ SwitchType = 'External'; AdapterName = 'Ethernet' }

#and the domain definition with the domain admin account
Add-LabDomainDefinition -Name $FQDNDomainName -AdminUser $Logon -AdminPassword $ClearTextPassword

#these credentials are used for connecting to the machines. As this is a lab we use clear-text passwords
Set-LabInstallationCredential -Username $Logon -Password $ClearTextPassword

#defining default parameter values, as these ones are the same for all the machines
$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:Network'         = $labName
    'Add-LabMachineDefinition:DomainName'      = $FQDNDomainName
    'Add-LabMachineDefinition:MinMemory'       = 1GB
    'Add-LabMachineDefinition:MaxMemory'       = 2GB
    'Add-LabMachineDefinition:Memory'          = 2GB
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2019 Standard (Desktop Experience)'
    #'Add-LabMachineDefinition:Processors'      = $LabMachineDefinitionProcessors
}

$postInstallActivity = Get-LabPostInstallationActivity -ScriptFileName PrepareRootDomain.ps1 -DependencyFolder $labSources\PostInstallationActivities\PrepareRootDomain
#DC + CA
#Add-LabMachineDefinition -Name CA01 -Roles CaRoot -IpAddress $CA01IPv4Address
Add-LabMachineDefinition -Name DC01 -Roles RootDC, CaRoot -PostInstallationActivity $postInstallActivity -OperatingSystem 'Windows Server 2012 Datacenter (Server with a GUI)'

#Router
$netAdapter = @()
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $labName -Ipv4Address $ROUTER01IPv4Address
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp
Add-LabMachineDefinition -Name ROUTER01 -Roles Routing -NetworkAdapter $netAdapter

#SQL Server
$role = Get-LabMachineRoleDefinition -Role SQLServer2017
Add-LabIsoImageDefinition -Name SQLServer2017 -Path $labSources\ISOs\en_sql_server_2019_standard_x64_dvd_cdcd4b9f.iso
Add-LabMachineDefinition -Name SQL01 -Roles $role -IpAddress $SQL01IPv4Address

#DSC Pull Servers
$role = Get-LabMachineRoleDefinition -Role DSCPullServer -Properties @{ DatabaseEngine = 'sql'; SqlServer = "SQL01"; DatabaseName = "DSC" }

#region IIS front-end servers : 2 NICS for  (1 for server communications and 1 for NLB)
$netAdapter = @()
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $PULL01IPv4Address -InterfaceName 'Internal'
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $NLBPULL01IPv4Address -InterfaceName 'NLB'
Add-LabMachineDefinition -Name PULL01 -Roles $role -NetworkAdapter $netAdapter
$netAdapter = @()
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $PULL02IPv4Address -InterfaceName 'Internal'
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $NLBPULL02IPv4Address -InterfaceName 'NLB'
Add-LabMachineDefinition -Name PULL02 -Roles $role -NetworkAdapter $netAdapter
#endregion


#DSC Pull Clients
Add-LabMachineDefinition -Name SERVER01 -IpAddress $SERVER01IPv4Address
Add-LabMachineDefinition -Name SERVER02 -IpAddress $SERVER02IPv4Address

Install-Lab

$AllMachines = Get-LabVM
$PullServers = Get-LabVM -Role DSCPullServer
$DSCClients = Get-LabVM | Where-Object -FilterScript { -not($_.Roles) }

Get-Job -Name 'Installation of*' | Wait-Job | Out-Null

Checkpoint-LabVM -SnapshotName $LabName -All #-Verbose

#Installing NLB on the PUll Servers
Install-LabWindowsFeature -FeatureName FS-DFS-Replication, NLB -ComputerName $PullServers -IncludeManagementTools
Install-LabWindowsFeature -FeatureName FS-DFS-Replication, RSAT-DFS-Mgmt-Con -ComputerName DC01 -Verbose

Invoke-LabCommand -ActivityName "Keyboard management" -ComputerName $AllMachines -ScriptBlock {
    #Setting the Keyboard to French
    Set-WinUserLanguageList -LanguageList "fr-FR" -Force
}

#Installing and setting up DFS-R on DC for replicated folder on IIS Servers for shared configuration
Invoke-LabCommand -ActivityName 'DNS & DFS-R Setup on DC' -ComputerName DC01 -ScriptBlock {
    #region DNS management
    #Reverse lookup zone creation
    Add-DnsServerPrimaryZone -NetworkID $using:NetworkID -ReplicationScope 'Forest' 
    #DNS Host entry for the nlb.contoso.com website 
    Add-DnsServerResourceRecordA -Name $using:NLBNetBiosName -ZoneName $using:FQDNDomainName -IPv4Address $using:NLBIPv4Address -CreatePtr
    #endregion
}

#IIS front-end servers : Renaming the NIC and setting up the metric for NLB management
Invoke-LabCommand -ActivityName 'Creating junction to DSC Modules and Configurations Folders' -ComputerName $PullServers -ScriptBlock {
    New-Item -ItemType Junction -Path "C:\DscService\Modules" -Target "C:\Program Files\WindowsPowerShell\DscService\Modules"
    New-Item -ItemType Junction -Path "C:\DscService\Configuration" -Target "C:\Program Files\WindowsPowerShell\DscService\Configuration"
}

Invoke-LabCommand -ActivityName 'DNS & DFS-R Setup on DC' -ComputerName DC01 -Verbose -ScriptBlock {
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c dfsradmin RG Delete /Rgname:`"DSC Module Path`"" -Wait
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c dfsradmin RG New /Rgname:`"DSC Module Path`"" -Wait
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c dfsradmin rf New /Rgname:`"DSC Module Path`" /rfname:`"DSCModulePath`"" -Wait
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c dfsradmin Mem New /Rgname:`"DSC Module Path`" /memname:PULL01" -Wait
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c dfsradmin Mem New /Rgname:`"DSC Module Path`" /memname:PULL02" -Wait
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c dfsradmin Conn New /Rgname:`"DSC Module Path`" /sendmem:PULL01 /recvmem:PULL02" -Wait
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c dfsradmin Conn New /Rgname:`"DSC Module Path`" /sendmem:PULL02 /recvmem:PULL01" -Wait
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c dfsradmin Membership Set /Rgname:`"DSC Module Path`" /rfname:`"DSCModulePath`" /memname:PULL01 /localpath:`"C:\DscService\Modules`" /isprimary:true /membershipEnabled:true" -Wait
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c dfsradmin Membership Set /Rgname:`"DSC Module Path`" /rfname:`"DSCModulePath`" /memname:PULL02 /localpath:`"C:\DscService\Modules`" /membershipEnabled:true" -Wait

    Start-Process -FilePath "$env:comspec" -ArgumentList "/c dfsradmin RG Delete /Rgname:`"Configuration Path`"" -Wait
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c dfsradmin RG New /Rgname:`"Configuration Path`"" -Wait
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c dfsradmin rf New /Rgname:`"Configuration Path`" /rfname:`"Configuration Path`"" -Wait
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c dfsradmin Mem New /Rgname:`"Configuration Path`" /memname:PULL01" -Wait
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c dfsradmin Mem New /Rgname:`"Configuration Path`" /memname:PULL02" -Wait
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c dfsradmin Conn New /Rgname:`"Configuration Path`" /sendmem:PULL01 /recvmem:PULL02" -Wait
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c dfsradmin Conn New /Rgname:`"Configuration Path`" /sendmem:PULL02 /recvmem:PULL01" -Wait
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c dfsradmin Membership Set /Rgname:`"Configuration Path`" /rfname:`"Configuration Path`" /memname:PULL01 /localpath:`"C:\DscService\Configuration`" /isprimary:true /membershipEnabled:true" -Wait
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c dfsradmin Membership Set /Rgname:`"Configuration Path`" /rfname:`"Configuration Path`" /memname:PULL02 /localpath:`"C:\DscService\Configuration`" /membershipEnabled:true" -Wait
}

#IIS front-end servers : Renaming the NIC and setting up the metric for NLB management
Invoke-LabCommand -ActivityName 'Renaming NICs' -ComputerName $PullServers -ScriptBlock {
    #Restarting DFSR service
    Restart-Service -Name DFSR -Force
    Start-Sleep -Seconds 10

    #Renaming the NIC and setting up the metric for NLB management
    Rename-NetAdapter -Name "$using:labName 0" -NewName 'Internal' -PassThru | Set-NetIPInterface -InterfaceMetric 1
    Rename-NetAdapter -Name "$using:labName 1" -NewName 'NLB' -PassThru | Set-NetIPInterface -InterfaceMetric 2
}

Invoke-LabCommand -ActivityName 'NLB Setup' -ComputerName PULL01 {
    #Creating New  NLB cluster
    New-NlbCluster -HostName PULL01 -ClusterName "$using:ServerComment" -InterfaceName NLB -ClusterPrimaryIP $using:NLBIPv4Address -SubnetMask 255.255.0.0 -OperationMode 'Multicast'
    #Removing default port rule for the New  cluster
    #Get-NlbClusterPortRule -HostName . | Remove-NlbClusterPortRule -Force
    #Adding port rules
    #Add-NlbClusterPortRule -Protocol Tcp -Mode Multiple -Affinity Single -StartPort 80 -EndPort 80 -InterfaceName $InterfaceName | Out-Null
    #Add-NlbClusterPortRule -Protocol Tcp -Mode Multiple -Affinity Single -StartPort 443 -EndPort 443 -InterfaceName $InterfaceName | Out-Null
    #Adding the second node to the cluster
    Get-NlbCluster | Add-NlbClusterNode -NewNodeName PULL02 -NewNodeInterface NLB
    #Client Affinity: Do not enable it to see the load balacing between the two IIS Servers    
    Get-NlbClusterPortRule | Set-NlbClusterPortRule -NewAffinity None
    #Stop-NlbClusterNode PULL02
}

#region Certification Authority : Creation and SSL Certificate Generation
#Get the CA
$CertificationAuthority = Get-LabIssuingCA
#Generating a New  template for SSL Web Server certificate
#New-LabCATemplate -TemplateName WebServerSSL -DisplayName 'Web Server SSL' -SourceTemplateName WebServer -ApplicationPolicy 'Server Authentication' -EnrollmentFlags Autoenrollment -PrivateKeyFlags AllowKeyExport -Version 2 -SamAccountName 'Domain Computers' -ComputerName $CertificationAuthority -ErrorAction Stop
#Getting a New  SSL Web Server Certificate
$WebServerSSLCert = Request-LabCertificate -Subject "CN=$NLBWebSiteName" -SAN $NLBWebSiteName, $NLBNetBiosName, "PULL01", "PULL01.$FQDNDomainName", "PULL02", "PULL02.$FQDNDomainName" -TemplateName DscPullSsl -ComputerName "PULL01" -PassThru -ErrorAction Stop
#endregion

Invoke-LabCommand -ActivityName 'Exporting the Web Server Certificate ' -ComputerName PULL01 -ScriptBlock {

    #Creating replicated folder for Central Certificate Store
    New-Item -Path C:\CertificateExport -ItemType Directory -Force

    #Getting the local SSL Certificate
    $WebServerSSLCert = Get-ChildItem -Path Cert:\LocalMachine\My\ -DnsName "$using:NLBWebSiteName" -SSLServerAuthentication | Where-Object -FilterScript {
        $_.hasPrivateKey 
    }  
    $PFXFilePath = "\\PULL01\C$\CertificateExport\$using:NLBWebSiteName.pfx"
    if ($WebServerSSLCert)
    {    
        #Exporting the local SSL Certificate to a local (replicated via DFS-R) PFX file
        $WebServerSSLCert | Export-PfxCertificate -FilePath $PFXFilePath -Password $Using:SecurePassword -Force
        #removing the local SSL Certificate
        $WebServerSSLCert | Remove-Item -Force
    }
}

Invoke-LabCommand -ActivityName 'Importing the Web Server Certificate & Setting up the Website' -ComputerName $PullServers -ScriptBlock {
    $PFXFilePath = "\\PULL01\C$\CertificateExport\$using:NLBWebSiteName.pfx"
    if (Test-Path $PFXFilePath -PathType Leaf)
    {
        Import-PfxCertificate -FilePath $PFXFilePath -Password $Using:SecurePassword -Exportable -CertStoreLocation Cert:\LocalMachine\My
        #Getting the local SSL Certificate
        $WebServerSSLCert = Get-ChildItem -Path Cert:\LocalMachine\My\ -DnsName "$using:NLBWebSiteName" -SSLServerAuthentication | Where-Object -FilterScript {
            $_.hasPrivateKey 
        }  
    }
    else
    {
        Write-Error -Exception "[ERROR] Unable to import the 'Web Server SSL' certificate for $using:NLBWebSiteName"
    }
    #Removing Default Binding
    Get-WebBinding -Port 8080 -Name "$using:ServerComment" | Remove-WebBinding
    Remove-Item -Path "IIS:\SslBindings\0.0.0.0!8080" -Force -ErrorAction Ignore
    New-WebBinding -Name "$using:ServerComment" -sslFlags 0 -Protocol https -Port 8080
    New-Item -Path "IIS:\SslBindings\!8080!$using:NLBWebSiteName" -Thumbprint $($using:WebServerSSLCert).Thumbprint -sslFlags 0
    
    #ASPX Page to view the server running the request
    "<%=HttpContext.Current.Server.MachineName%>" | Out-File -FilePath $(Join-Path -Path $(Get-Website -Name $using:ServerComment).PhysicalPath -ChildPath "default.aspx")
}

#Copy-LabFileItem -Path $labSources\PostInstallationActivities\SetupDscPullServer\CreateDscSqlDatabase.ps1 -DestinationFolderPath C:\Temp -ComputerName SQL01
Copy-LabFileItem -Path $CurrentDir\CreateDscSqlDatabase.ps1 -DestinationFolderPath C:\Temp -ComputerName SQL01
Invoke-LabCommand -ActivityName 'Create SQL Database for DSC Reporting' -ComputerName SQL01 -ScriptBlock {
    C:\Temp\CreateDscSqlDatabase.ps1 -DomainAndComputerName CONTOSO\PULL01, CONTOSO\PULL02
}

Install-LabDscClient -ComputerName $DSCClients -PullServer PULL01 -Verbose 

Invoke-LabCommand -ActivityName 'Installing Community Ressources modules' -ComputerName $PullServers -ScriptBlock {
    Install-Module -Name xWebAdministration -RequiredVersion 3.2.0
}

Invoke-LabCommand -ActivityName 'Updating Test DSC Configuration' -ComputerName PULL01 -ScriptBlock {

    Configuration IISConfigPull
    {
	    param (
            [string[]]$ComputerName = 'localhost'
        )

        Import-DSCResource -ModuleName PSDesiredStateConfiguration
        Import-DSCResource -ModuleName xWebAdministration -ModuleVersion 3.2.0

	    Node $ComputerName 
        {
		    WindowsFeature IIS {
			    Ensure = 'Present'
			    Name   = 'Web-Server'
		    }

		    WindowsFeature IISConsole {
			    Ensure = 'Present'
			    Name   = 'Web-Mgmt-Console'
                DependsOn = '[WindowsFeature]IIS'
		    }

            xIisLogging IISLogging
            {
                LogPath = 'C:\IISLogFiles'
                Logflags = @('Date', 'Time', 'ClientIP', 'UserName', 'SiteName', 'ComputerName', 'ServerIP', 'Method', 'UriStem', 'UriQuery', 'HttpStatus', 'Win32Status', 'BytesSent', 'BytesRecv', 'TimeTaken', 'ServerPort', 'ProtocolVersion', 'Host', 'HttpSubStatus')
                LoglocalTimeRollover = $True
                LogFormat = 'W3C'
                DependsOn = '[WindowsFeature]IISConsole'
            }
        
            File IISDefaultPage
            {
                DestinationPath = "C:\inetpub\wwwroot\iisstart.htm"
                Contents = "<HTML><HEAD><TITLE>Installed via DSC</TITLE></HEAD><BODY><H1>If you are seeing this page. It means DSC Rocks !!!<BR>Generated at $(Get-Date)</H1></BODY></HTML>"
                Ensure = "Present"
                Type = "File" 
                Force = $True
	        }
        }
    }

    IISConfigPull -OutputPath C:\DscTestConfig | Out-Null
    #Remove-Item "C:\DscTestConfig\IISConfigPull.mof" -Force
    Rename-Item -Path C:\DscTestConfig\localhost.mof -NewName "IISConfigPull.mof"
    Publish-DscModuleAndMof -Source C:\DscTestConfig  -ModuleNameList xWebAdministration -Verbose
}

Invoke-LabCommand -ActivityName 'Updating the LCM Configuration to use the NLB VIP' -ComputerName $DSCClients -ScriptBlock {
    [DSCLocalConfigurationManager()]
    Configuration PullClient
    {
        Node localhost
        {
            Settings
            {
                RefreshMode          = 'Pull'
                RefreshFrequencyMins = 30
                ConfigurationModeFrequencyMins = 15
                ConfigurationMode = 'ApplyAndAutoCorrect'
                RebootNodeIfNeeded   = $true
            }

            ConfigurationRepositoryWeb "PullServer_1"
            {
                ServerURL          = "https://pull.contoso.com:8080/PSDSCPullServer.svc"
                RegistrationKey    = $using:RegistrationKey
                ConfigurationNames = @("TestConfigPULL01", "IISConfigPull")
                #AllowUnsecureConnection = $true
            }

	        PartialConfiguration TestConfigPULL01
	        {
		        Description = 'Test Configuration'
		        ConfigurationSource = '[ConfigurationRepositoryWeb]PullServer_1'
	        }
 
	        PartialConfiguration IISConfigPull
	        {
		        Description = 'Configuration for the IIS Server'
		        ConfigurationSource = '[ConfigurationRepositoryWeb]PullServer_1'
		        DependsOn = '[PartialConfiguration]TestConfigPULL01'
	        }

            ReportServerWeb CONTOSO-PullSrv
            {
                ServerURL       = "https://pull.contoso.com:8080/PSDSCPullServer.svc"
                RegistrationKey = $using:RegistrationKey
                #AllowUnsecureConnection = $true
            }
        }
    }

    PullClient -OutputPath c:\Dsc
    Set-DscLocalConfigurationManager -Path C:\Dsc -ComputerName localhost -Verbose
    Update-DscConfiguration -Wait -Verbose
}

#Installing PowerBI Desktop on the SQL Server (or any machine in the lab)
$PBIDesktopX64Uri = "https://download.microsoft.com/download/8/8/0/880BCA75-79DD-466A-927D-1ABF1F5454B0/PBIDesktopSetup_x64.exe"
$PBIDesktopX64 = Get-LabInternetFile -Uri $PBIDesktopX64Uri -Path $labSources\SoftwarePackages -PassThru
Install-LabSoftwarePackage -ComputerName SQL01 -Path $labSources\SoftwarePackages\PBIDesktopSetup_x64.exe -CommandLine "-quiet -norestart LANGUAGE=en-us ACCEPT_EULA=1 INSTALLDESKTOPSHORTCUT=0" -AsJob
#cf. https://docs.microsoft.com/en-us/archive/blogs/fieldcoding/visualize-dsc-reporting-with-powerbi#powerbi---the-interesting-part
#Copying the DSC Dashboard on the machine where you have installed PowerBI Desktop 
Copy-LabFileItem -Path "$CurrentDir\DSC Dashboard.pbix" -ComputerName SQL01

#Coping the PowerShell Script to have a local report of the DSC deployments
Copy-LabFileItem -Path "$CurrentDir\Get-DSCReport.ps1" -ComputerName $DSCClients

Show-LabDeploymentSummary -Detailed
Checkpoint-LabVM -SnapshotName 'FullInstall' -All

$VerbosePreference = $PreviousVerbosePreference
$ErrorActionPreference = $PreviousErrorActionPreference
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose

Stop-Transcript