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
$MicrosoftMonitoringAgentX64URI = "https://go.microsoft.com/fwlink/?LinkId=828603"

$OutFile = Join-Path $env:TEMP -ChildPath "MOMAgent.msi"
Invoke-WebRequest -Uri $MicrosoftMonitoringAgentX64URI -OutFile $OutFile -UseBasicParsing

#From https://github.com/brianbar-MSFT/Install-MMA/blob/master/Install-MMA.ps1
#From https://learn.microsoft.com/en-us/system-center/scom/manage-deploy-windows-agent-manually?view=sc-om-2022#deploy-the-operations-manager-agent-from-the-command-line
Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i", $OutFile, "/qn", "/l*v", "$OutFile.log", "NOAPM=1", "AcceptEndUserLicenseAgreement=1" -Wait -NoNewWindow

Remove-Item -Path $OutFile -Force
