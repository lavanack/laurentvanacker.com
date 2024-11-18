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
#$ErrorActionPreference = 'Stop'
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$TranscriptFile = $CurrentScript -replace ".ps1$", "$("_{0}.txt" -f (Get-Date -Format 'yyyyMMddHHmmss'))"
Set-Location -Path $CurrentDir
Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader

#region Global variables definition
$Logon = 'Administrator'
$ClearTextPassword = 'P@ssw0rd'
$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$NetBiosDomainName = 'CONTOSO'
$FQDNDomainName = 'contoso.com'

$NetworkID = '10.0.0.0/16' 
$DC01IPv4Address = '10.0.0.1'
$DOCKER01IPv4Address = '10.0.0.11'

$IISDockerFileContentWithPowershellCommandLines = @"
# final stage/image
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app ./
ENTRYPOINT ["dotnet", "aspnetapp.dll"]
"@

$DockerFileName = 'DockerFile'

$LabName = 'NetCoreDocker2025'

#Dynamically get the latest version
#region Latest DotNet Core Hosting Bundle
$LatestDotNetCoreHostingBundleURI = (Invoke-WebRequest https://dotnet.microsoft.com/permalink/dotnetcore-current-windows-runtime-bundle-installer).links.href | Where-Object -FilterScript { $_ -match "\.exe$" } | Select-Object -Unique
$LatestDotNetCoreHostingBundleFilePath = Join-Path -Path $CurrentDir -ChildPath $(($LatestDotNetCoreHostingBundleURI -split "/")[-1])
#endregion

#region Latest DotNet SDK
$LatestDotNetCoreSDKURI = (Invoke-WebRequest https://dotnet.microsoft.com/en-us/download).links.href | Where-Object -FilterScript { $_ -match "sdk.*windows.*-x64" } | Sort-Object -Descending | Select-Object -First 1
$LatestDotNetCoreSDKURI = "https://dotnet.microsoft.com$($LatestDotNetCoreSDKURI)"
$LatestDotNetCoreSDKURI = (Invoke-WebRequest $LatestDotNetCoreSDKURI).links.href | Where-Object -FilterScript { $_ -match "sdk.*win.*-x64" } | Select-Object -Unique
#endregion

$DockerIISRootFolder = "$env:SystemDrive\Docker\AspNetApp"
$GitURI = ((Invoke-WebRequest -Uri 'https://git-scm.com/download/win').Links | Where-Object -FilterScript { $_.InnerText -eq "64-bit Git For Windows Setup" }).href
$GitURI = "https://github.com/git-for-windows/git/releases/download/v2.47.0.windows.2/Git-2.47.0.2-64-bit.exe"

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
    'Add-LabMachineDefinition:MaxMemory'       = 2GB
    'Add-LabMachineDefinition:Memory'          = 2GB
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2022 Datacenter (Desktop Experience)'
    #'Add-LabMachineDefinition:Processors'      = 4
}

$DOCKER01NetAdapter = @()
$DOCKER01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $DOCKER01IPv4Address -InterfaceName 'Corp'
$DOCKER01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp -InterfaceName 'Internet'

#region server definitions
#Domain controller + Certificate Authority
Add-LabMachineDefinition -Name DC01 -Roles RootDC -IpAddress $DC01IPv4Address
#DOCKER
Add-LabMachineDefinition -Name DOCKER01 -NetworkAdapter $DOCKER01NetAdapter -MinMemory 6GB -MaxMemory 6GB -Memory 6GB -Processors 2
#endregion

#Installing servers
Install-Lab -Verbose
Checkpoint-LabVM -SnapshotName FreshInstall -All
#Restore-LabVMSnapshot -SnapshotName 'FreshInstall' -All -Verbose

#region Enabling Nested Virtualization on DOCKER01
#Restarting all VMs
Stop-LabVM -All -Wait
Set-VMProcessor -VMName DOCKER01 -ExposeVirtualizationExtensions $true
Start-LabVM -All -Wait
#endregion

#region Installing Required Windows Features
$machines = Get-LabVM -All
$Jobs = @()
$Jobs += Install-LabWindowsFeature -FeatureName Telnet-Client -ComputerName $machines -IncludeManagementTools -PassThru -AsJob
#endregion

#region Installing Git
$Git = Get-LabInternetFile -Uri $GitUri -Path $labSources\SoftwarePackages -PassThru -Force
$Jobs += Install-LabSoftwarePackage -ComputerName DOCKER01 -Path $Git.FullName -CommandLine " /SILENT /CLOSEAPPLICATIONS" -AsJob -PassThru
#endregion


#Installing and setting up DNS
Invoke-LabCommand -ActivityName 'DNS, AD Setup & GPO Settings on DC' -ComputerName DC01 -ScriptBlock {
    #region DNS management
    #Reverse lookup zone creation
    Add-DnsServerPrimaryZone -NetworkID $using:NetworkID -ReplicationScope 'Forest' 

    $DefaultNamingContext = (Get-ADRootDSE).defaultNamingContext
    #region Edge Settings
    $GPO = New-GPO -Name "Edge Settings" | New-GPLink -Target $DefaultNamingContext
    # https://devblogs.microsoft.com/powershell-community/how-to-change-the-start-page-for-the-edge-browser/
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\Edge' -ValueName "RestoreOnStartup" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 4

    #https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.MicrosoftEdge::PreventFirstRunPage
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main' -ValueName "PreventFirstRunPage" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1

    #Hide the First-run experience and splash screen on Edge : https://docs.microsoft.com/en-us/deployedge/microsoft-edge-policies#hidefirstrunexperience
    #https://admx.help/?Category=EdgeChromium&Policy=Microsoft.Policies.Edge::HideFirstRunExperience
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Edge' -ValueName "HideFirstRunExperience" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1

    #Bonus : To open all the available websites accross all nodes
    $StartPage = "http://DOCKER01"
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Software\Policies\Microsoft\Edge\RestoreOnStartupURLs' -ValueName 0 -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "$StartPage"
    #Hide the First-run experience and splash screen on Edge : https://docs.microsoft.com/en-us/deployedge/microsoft-edge-policies#hidefirstrunexperience
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\SOFTWARE\Policies\Microsoft\Edge' -ValueName "HideFirstRunExperience" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
    #endregion

    #region WireShark : (Pre)-Master-Secret Log Filename
    $GPO = New-GPO -Name "(Pre)-Master-Secret Log Filename" | New-GPLink -Target $DefaultNamingContext
    #For decrypting SSL traffic via network tools : https://support.f5.com/csp/article/K50557518
    $SSLKeysFile = '%USERPROFILE%\AppData\Local\WireShark\ssl-keys.log'
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Environment' -ValueName "SSLKEYLOGFILE" -Type ([Microsoft.Win32.RegistryValueKind]::ExpandString) -Value $SSLKeysFile
    #endregion
}

#Checkpoint-LabVM -SnapshotName BeforeDockerSetup -All
#Restore-LabVMSnapshot -SnapshotName BeforeDockerSetup -All -Verbose

1..2 | ForEach-Object -Process {
    #We have to run twice : 1 run form the HyperV and containers setup (reboot required) and 1 run for the docker setup
    Invoke-LabCommand -ActivityName 'Docker Setup' -ComputerName DOCKER01 -ScriptBlock {
        #From https://learn.microsoft.com/en-us/virtualization/windowscontainers/quick-start/set-up-environment?tabs=dockerce#windows-server-1
        Invoke-Expression -Command "& { $(Invoke-RestMethod https://raw.githubusercontent.com/microsoft/Windows-Containers/Main/helpful_tools/Install-DockerCE/install-docker-ce.ps1) } -HyperV -NoRestart -Verbose"
        <#
        Set-Location -Path $env:Temp
        Invoke-WebRequest -UseBasicParsing "https://raw.githubusercontent.com/microsoft/Windows-Containers/Main/helpful_tools/Install-DockerCE/install-docker-ce.ps1" -OutFile install-docker-ce.ps1
        #.\install-docker-ce.ps1 -HyperV -Force -Verbose
        .\install-docker-ce.ps1 -NoRestart -HyperV
        #>
    } -Verbose
    Restart-LabVM -ComputerName DOCKER01 -Wait
}

$Jobs | Wait-Job | Out-Null

Checkpoint-LabVM -SnapshotName DockerSetup -All
#Restore-LabVMSnapshot -SnapshotName 'DockerSetup' -All -Verbose

#region .Net Core pre-requisites
#region Downloading and Installing .Net Hosting Bundle Installer for hosting the web app
$LatestDotNetCoreHostingBundle = Get-LabInternetFile -Uri $LatestDotNetCoreHostingBundleURI -Path $labSources\SoftwarePackages -PassThru -Force
Install-LabSoftwarePackage -ComputerName DOCKER01 -Path $LatestDotNetCoreHostingBundle.FullName -CommandLine "/install /passive /norestart"
#endregion 

#region Downloading and Installing .Net SDK for creating the web app
$LatestDotNetCoreSDK = Get-LabInternetFile -Uri $LatestDotNetCoreSDKURI -Path $labSources\SoftwarePackages -PassThru -Force
Install-LabSoftwarePackage -ComputerName DOCKER01 -Path $LatestDotNetCoreSDK.FullName -CommandLine "/install /passive /norestart"
#endregion

Restart-LabVM -ComputerName DOCKER01 -Wait
#endregion

<#
Invoke-LabCommand -ActivityName '.DotNet Setup' -ComputerName DOCKER01 -ScriptBlock {
    #region Install .NET on Windows
    #From https://learn.microsoft.com/en-us/dotnet/core/install/windows?WT.mc_id=dotnet-35129-website#install-with-powershell
    #SDK
    Invoke-Expression -Command "& { $(Invoke-RestMethod https://dot.net/v1/dotnet-install.ps1) } -Channel 8.0 -Quality GA #-Verbose"
    #Desktop runtime 
    Invoke-Expression -Command "& { $(Invoke-RestMethod https://dot.net/v1/dotnet-install.ps1) } -Channel 8.0 -Quality GA -Runtime windowsdesktop #-Verbose"
    #ASP.NET Core runtime 
    Invoke-Expression -Command "& { $(Invoke-RestMethod https://dot.net/v1/dotnet-install.ps1) } -Channel 8.0 -Quality GA -Runtime aspnetcore #-Verbose"

    #winget install Microsoft.DotNet.SDK.9
    #winget install Microsoft.DotNet.DesktopRuntime.9
    #winget install Microsoft.DotNet.AspNetCore.9
    #endregion
}
#>

Checkpoint-LabVM -SnapshotName DotNetSetup -All
#Restore-LabVMSnapshot -SnapshotName 'DotNetSetup' -All -Verbose

Invoke-LabCommand -ActivityName 'Git Setup' -ComputerName DOCKER01 -ScriptBlock {
    Remove-Item -Path \dotnet-docker -Recurse -Force -ErrorAction Ignore
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "git clone https://github.com/dotnet/dotnet-docker.git" -Wait
    Set-Location -Path \dotnet-docker\samples\aspnetapp\aspnetapp
    dotnet build
} -Verbose


Invoke-LabCommand -ActivityName 'Docker Configuration' -ComputerName DOCKER01 -ScriptBlock {
    Set-WinUserLanguageList fr-fr -Force

    Start-Service Docker
    #Pulling IIS image
    #docker pull mcr.microsoft.com/dotnet/aspnet:8.0

    #Stopping all previously running containers if any
    if ($(docker ps -a -q)) {
        docker stop 
        #To delete all containers
        docker rm -f $(docker ps -a -q)
    }
    
    #From https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/docker/building-net-docker-images?view=aspnetcore-8.0
    Set-Location -Path \dotnet-docker\samples\aspnetapp
    Rename-Item -Path DockerFile -NewName DockerFile.old
    Copy-Item -Path .\Dockerfile.windowsservercore -Destination .\Dockerfile

    #Building the image only once
    if ($(docker image ls) -notmatch "\s*aspnetapp\s*") {
        Write-Verbose -Message "Building the Docker image ..."
        docker build -t aspnetapp .
    }
    $Name = "aspnetcore_sample"
    docker run -d -p "80:8080" --name $Name aspnetapp --restart always #--rm

    #Getting the IP v4 address of the container
    $ContainerIPv4Address = (docker inspect -f "{{ .NetworkSettings.Networks.nat.IPAddress }}" $Name | Out-String) -replace "`r|`n"
    Write-Host "The internal IPv4 address for the container [$Name] is [$ContainerIPv4Address]" -ForegroundColor Yellow

    #Pulling ASP.Net Sample image
    #docker run -d -p 8080:80 --name aspnet_sample --rm -it mcr.microsoft.com/dotnet/framework/samples:aspnetapp

    #To list some properties with the comma as separator
    #docker inspect -f "{{.ID}},{{.Name}},{{ .NetworkSettings.Networks.nat.IPAddress }},{{ .NetworkSettings.Ports}}" $(docker ps -a -q)       
    #To list internal IPs of the running docker images (useful for IIS Remote Management):
    #docker inspect -f "{{ .NetworkSettings.Networks.nat.IPAddress }}" $(docker ps -a -q)
    #To convert docker config into PowerShell object
    #docker inspect $(docker ps -a -q) | ConvertFrom-Json
    #To delete all containers
    #docker rm -f $(docker ps -a -q)
    #docker update --restart unless-stopped $(docker ps -q)
    docker update --restart always $(docker ps -q)
} -Verbose

Invoke-LabCommand -ActivityName 'Disabling Windows Update service' -ComputerName DOCKER01 -ScriptBlock {
    Stop-Service WUAUSERV -PassThru | Set-Service -StartupType Disabled
} 


<#
Invoke-LabCommand -ActivityName 'Pushing Docker images' -ComputerName DOCKER01 -ScriptBlock {
    docker login --username lavanack --password ...
    docker tag iis-website lavanack/iis-website
    docker push lavanack/iis-website
}
#>
#Waiting for background jobs
$Jobs | Wait-Job | Out-Null

#For updating the GPO
Restart-LabVM -ComputerName $machines -Wait

Show-LabDeploymentSummary -Detailed
Checkpoint-LabVM -SnapshotName 'FullInstall' -All

$VerbosePreference = $PreviousVerbosePreference
$ErrorActionPreference = $PreviousErrorActionPreference
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose

Start-Process -FilePath "http://DOCKER01"

Stop-Transcript