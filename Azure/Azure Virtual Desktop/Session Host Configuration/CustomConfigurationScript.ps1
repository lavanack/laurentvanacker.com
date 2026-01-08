<#
This Sample Code is provided for the purpose of illustration only
and is not intended to be used in a production environment.  THIS
SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
# WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
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

$CustomConfigurationScriptUrls = @(
    "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/refs/heads/master/Azure/Azure%20VM%20Image%20Builder/Install-VSCode.ps1"
    "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/refs/heads/master/Azure/Azure%20VM%20Image%20Builder/Install-PowerShell.ps1"
)

foreach ($CustomConfigurationScriptUrl in $CustomConfigurationScriptUrls) {
    $LocalScriptName = Split-Path -Path $CustomConfigurationScriptUrl -Leaf
    $LocalScriptPath = Join-Path -Path $env:TEMP -ChildPath $LocalScriptName
    Invoke-RestMethod -Uri $CustomConfigurationScriptUrl -OutFile $LocalScriptPath -UseBasicParsing
    & $LocalScriptPath  
    $null = Remove-Item -Path $LocalScriptPath -Force
}