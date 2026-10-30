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
#Installing DockerCLI

#region Getting the latest release of DockerCLI 
$DockerCLIRootUri = "https://download.docker.com/win/static/stable/x86_64/"
$DockerCLIUri = (Invoke-WebRequest -Uri $DockerCLIRootUri -UseBasicParsing).Links.href | Sort-Object -Descending | Select-Object -First 1
$DockerCLIUri = "{0}{1}" -f $DockerCLIRootUri, $DockerCLIUri
#endregion 

#region Downloading DockerCLI 
$OutFile = Join-Path -Path $env:TEMP -ChildPath $(Split-Path -Path $DockerCLIUri -Leaf)
If (-not(Test-Path -Path $OutFile)) {
    Write-Verbose -Message "Downloading DockerCLI ..."
    Invoke-WebRequest -Uri $DockerCLIUri -UseBasicParsing -OutFile $OutFile -Verbose
}
#endregion 

#region Installing/Unzipping DockerCLI
$DestinationPath = "C:\Tools"
$null = New-Item -Path $DestinationPath -ItemType Directory -Force
Expand-Archive -Path $OutFile -DestinationPath $DestinationPath -Force
#endregion

#region Updating System Path
$Path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if ($DestinationPath -notin ($Path -split ';')) {
    [Environment]::SetEnvironmentVariable('Path', "$Path;$DestinationPath", 'Machine')
}
#endregion 

#region Cleanup
Remove-Item -Path $OutFile -Force
#endregion 