<#
This Sample Code is provided for the purpose of illustration only
and is not intended to be used in a production environment.  THIS
SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
WARRANTY OF ANY KIND,  EITHER EXPRESSED OR IMPLIED,  INCLUDING BUT NOT
LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
FOR A PARTICULAR PURPOSE.  We grant You a nonexclusive,  royalty-free
right to use and modify the Sample Code and to reproduce and distribute
the object code form of the Sample Code,  provided that You agree:
(i) to not use Our name,  logo,  or trademarks to market Your software
product in which the Sample Code is embedded; (ii) to include a valid
copyright notice on Your software product in which the Sample Code is
embedded; and (iii) to indemnify,  hold harmless,  and defend Us and
Our suppliers from and against any claims or lawsuits,  including
attorneys' fees,  that arise or result from the use or distribution
of the Sample Code.
#>
#Installing MOMAgent
Clear-Host
$MicrosoftMonitoringAgentX64URI = "https://go.microsoft.com/fwlink/?LinkId=828603"
$TempDir = Join-Path $env:Temp -ChildPath $([System.IO.Path]::GetRandomFileName())

$null = New-Item -Path $TempDir -ItemType Directory -Force
$OutFile = Join-Path $TempDir -ChildPath "MMASetup-AMD64.exe"
$MOMAgentMSIFilePath = Join-Path $TempDir -ChildPath "MOMAgent.msi"

Invoke-WebRequest -Uri $MicrosoftMonitoringAgentX64URI -OutFile $OutFile -UseBasicParsing
Start-Process -FilePath "$OutFile" -ArgumentList "/c", "/t:$($TempDir)" -Wait

#From https://github.com/brianbar-MSFT/Install-MMA/blob/master/Install-MMA.ps1
#From https://learn.microsoft.com/en-us/system-center/scom/manage-deploy-windows-agent-manually?view=sc-om-2022#deploy-the-operations-manager-agent-from-the-command-line
Start-Process -FilePath $MOMAgentMSIFilePath -ArgumentList "/qn", "/l*v", "$MOMAgentMSIFilePath.log", "NOAPM=1", "AcceptEndUserLicenseAgreement=1" -Wait

Remove-Item -Path $TempDir -Recurse -Force