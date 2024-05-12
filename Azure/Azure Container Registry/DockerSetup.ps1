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

[CmdletBinding()]
Param (
    #We will create an IIS container listening for every port we specify here
	[Parameter(Mandatory = $false)]
    #Using int[] broke the code !????. ==> https://stackoverflow.com/questions/58057107/passing-an-array-in-an-invoke-azurermvmruncommand-parameter-hash-table-not-worki
    #[int[]] $IISWebSitePort = @(80..82),
    [string] $IISWebSitePort = "[80,81,82]",
    [Parameter(Mandatory = $false)]
    [string] $ImageName = 'iis-website',
    [Parameter(Mandatory = $true)]
    [string] $ContainerRegistryName 
)

trap {
    Write-Output -InputObject "Stopping Transcript ..."
    Stop-Transcript
} 
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$TranscriptFile = $CurrentScript -replace ".ps1$", "$("_{0}.txt" -f (Get-Date -Format 'yyyyMMddHHmmss'))"
Set-Location -Path $CurrentDir
Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader

#region Global variables definition
$IISSetupPowerShellScriptFileURI = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Container%20Registry/IISSetup.ps1"
$IISSetupFileName = Split-Path -Path $IISSetupPowerShellScriptFileURI -Leaf

$IISDockerFileContentCallingPowershellScript = @"
FROM mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2022
COPY $IISSetupFileName C:\\
SHELL [ "powershell" ]
#File for a custom IIS setup
RUN C:\$IISSetupFileName; \
#Removing file after setup
Remove-Item -Path C:\$IISSetupFileName -Force
"@

$DockerFileName = 'DockerFile'

#We want to customize the IIS setup we will use this Powershell script
$DockerIISRootFolder = "$env:SystemDrive\Docker\IIS"
$null = New-Item -Path $DockerIISRootFolder -ItemType Directory -Force
$IISSetupPowerShellScriptFile = Join-Path -Path $DockerIISRootFolder -ChildPath $IISSetupFileName
Invoke-RestMethod -Uri $IISSetupPowerShellScriptFileURI  -OutFile $IISSetupPowerShellScriptFile
#endregion

#Installing required PowerShell modules.
Get-PackageProvider -Name Nuget -ForceBootstrap -Force
Install-Module -Name Az.ContainerRegistry -Scope AllUsers -Force -Verbose


$null = Install-WindowsFeature -Name Web-Mgmt-Console -IncludeManagementTools

$null = Start-Service Docker
#Pulling IIS image
#docker pull mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2022

$Containers = $(docker ps -a -q)
#Stopping all previously running containers if any
if ($Containers) {
    docker stop $Containers
    #To delete all containers
    docker rm -f $Containers
}
#Creating an IIS container per HTTP(S) port
$($IISWebSitePort | ConvertFrom-Json) | ForEach-Object {
    $CurrentIISWebSiteHostPort = $_
    $TimeStamp = "{0:yyyyMMddHHmmss}" -f (Get-Date)
    $Name = "MyRunningWebSite_$($TimeStamp)"
    $ContainerLocalRootFolder = Join-Path -Path $DockerIISRootFolder -ChildPath "$Name"
    $ContainerLocalContentFolder = Join-Path -Path $ContainerLocalRootFolder -ChildPath "Content"
    $ContainerLocalLogFolder = Join-Path -Path $ContainerLocalRootFolder -ChildPath "LogFiles"
    $ContainerLocalDockerFile = Join-Path -Path $ContainerLocalRootFolder -ChildPath $DockerFileName
    $null = New-Item -Path $ContainerLocalContentFolder, $ContainerLocalLogFolder -ItemType Directory -Force
        
    #Customizing default page
    "<html><title>Docker Test Page</title><body>This page was generated at $(Get-Date) via Powershell.<BR>Current Time is <%=Now%> (via ASP.Net).<BR>Your are listening on port <b>$CurrentIISWebSiteHostPort</b>.<BR>You are using a <b>PowerShell script</b> for setting up IIS</body></html>" | Out-File -FilePath $(Join-Path -Path $ContainerLocalContentFolder -ChildPath "default.aspx")
    $null = New-Item -Path $ContainerLocalDockerFile -ItemType File -Value $IISDockerFileContentCallingPowershellScript -Force
    Copy-Item -Path $(Join-Path -Path $DockerIISRootFolder -ChildPath $IISSetupFileName) -Destination $ContainerLocalRootFolder -Force -Recurse
        
    Set-Location -Path $ContainerLocalRootFolder
    if ($(docker image ls) -notmatch "\s*$($ImageName)\s*") {
        Write-Verbose -Message "Building the Docker image ..."
        docker build -t $ImageName .
    }
    #Mapping the remote IIS log files directory locally for every container for easier management
    #docker run -d -p "$($CurrentIISWebSiteHostPort):80" -v $ContainerLocalLogFolder\:C:\inetpub\logs\LogFiles -v $ContainerLocalContentFolder\:C:\inetpub\wwwroot --name $Name $ImageName --restart unless-stopped #--rm
    docker run -d -p "$($CurrentIISWebSiteHostPort):80" -v $ContainerLocalLogFolder\:C:\inetpub\logs\LogFiles -v $ContainerLocalContentFolder\:C:\inetpub\wwwroot --name $Name $ImageName --restart always #--rm
    #Getting the IP v4 address of the container
    $ContainerIPv4Address = (docker inspect -f "{{ .NetworkSettings.Networks.nat.IPAddress }}" $Name | Out-String) -replace "`n|`r"
    Write-Output -InputObject "The internal IPv4 address for the container [$Name] is [$ContainerIPv4Address]"
    #Generating traffic : 10 web requests to have some entries in the IIS log files
    1..10 | ForEach-Object -Process { $null = Invoke-RestMethod -Uri http://localhost:$CurrentIISWebSiteHostPort }
}
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

#Remove-Item -Path $IISSetupPowerShellScriptFile -Force
$DockerPort = [Regex]::Matches($(docker container ls --format "{{.Ports}}" -a), ":(?<Port>\d+)") | ForEach-Object -Process { $_.Groups["Port"].Value}
$DockerPort

#region Pushing Docker image into the Azure Container Registry
Connect-AzAccount -Identity

$Result = Connect-AzContainerRegistry -Name $ContainerRegistryName
$Result
if ($Result -ne 'Login Succeeded') {
    Write-Error -Message "Login Failed !" -ErrorAction Stop
}

Get-AzContext

$Destination = "{0}.azurecr.io/samples/{1}" -f $ContainerRegistryName, $ImageName
docker tag $ImageName $Destination
docker push $Destination

#endregion

Write-Output -InputObject "`$TranscriptFile: $TranscriptFile"
Stop-Transcript
Get-Content -Path $TranscriptFile -Raw