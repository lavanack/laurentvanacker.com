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
product in which the Sample Code is embedded; (ii) to include a valid<
copyright notice on Your software product in which the Sample Code is
embedded; and (iii) to indemnify, hold harmless, and defend Us and
Our suppliers from and against any claims or lawsuits, including
attorneys' fees, that arise or result from the use or distribution
of the Sample Code.
#>
#Installing DockerBuildX

#region Getting the latest release of DockerBuildX 
$DockerBuildXVersion = (Invoke-RestMethod  -Uri "https://api.github.com/repos/docker/buildx/releases/latest").tag_name -replace "v"
#endregion 

#region Downloading DockerBuildX 
$DockerBuildXUri = $(((Invoke-RestMethod  -Uri "https://api.github.com/repos/docker/buildx/releases/latest").assets | Where-Object -FilterScript { $_.name.EndsWith("amd64.exe") }).browser_download_url)
$OutFile = Join-Path -Path $env:TEMP -ChildPath $(Split-Path -Path $DockerBuildXUri -Leaf)
If (-not(Test-Path -Path $OutFile)) {
    Write-Verbose -Message "Downloading DockerBuildX v$DockerBuildXVersion ..."
    Invoke-WebRequest -Uri $DockerBuildXUri -UseBasicParsing -OutFile $OutFile -Verbose
}
#endregion 

#region Installing DockerBuildX 
#From https://richardbrunt.co.uk/til/installing-docker-buildx-on-windows-without-docker-desktop/
$DestinationPath = "C:\Tools"
$null = New-Item -Path $DestinationPath -ItemType Directory -Force
Rename-Item -Path $OutFile -NewName "docker-buildx.exe" -Force
Move-Item -Path $OutFile -Destination $DestinationPath -Force
#endregion

#region Updating System Path
$Path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if ($DestinationPath -notin ($Path -split ';')) {
    [Environment]::SetEnvironmentVariable('Path', "$Path;$DestinationPath", 'Machine')
}
#endregion 
