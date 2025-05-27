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

[CmdletBinding()]
param
(
)

trap {
    Write-Host "Stopping Transcript ..."
    Stop-Transcript
    $VerbosePreference = $PreviousVerbosePreference
    $ErrorActionPreference = $PreviousErrorActionPreference
    [console]::beep(3000, 750)
    Send-ALNotification -Activity 'Lab started' -Message ('Lab deployment failed !') -Provider (Get-LabConfigurationItem -Name Notifications.SubscribedProviders)
    break
} 
Import-Module -Name AutomatedLab -Verbose
try { while (Stop-Transcript) {} } catch {}
Clear-Host

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$TranscriptFile = $CurrentScript -replace ".ps1$", "$("_{0}.txt" -f (Get-Date -Format 'yyyyMMddHHmmss'))"
Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader

#region Listing the OS in a hashtable (for getting the latest version)
try {
    $OperatingSystemHT = (Get-LabAvailableOperatingSystem -ErrorAction Stop | Where-Object -FilterScript { $_.OperatingSystemImageName -match "DataCenter.*Desktop|Enterprise$" }) | Group-Object -Property OperatingSystemImageName -AsHashTable -AsString
}
catch {
    Clear-LabCache
    $OperatingSystemHT = (Get-LabAvailableOperatingSystem -ErrorAction Stop | Where-Object -FilterScript { $_.OperatingSystemImageName -match "DataCenter.*Desktop|Enterprise$" }) | Group-Object -Property OperatingSystemImageName -AsHashTable -AsString
}
$LastestOperatingSystem = foreach ($OperatingSystemName in $OperatingSystemHT.Keys) {
    if ($OperatingSystemHT[$OperatingSystemName].Count -eq 1) {
        Write-Host -Object "'$OperatingSystemName' exists only in one version" -ForegroundColor Green
        $OperatingSystemHT[$OperatingSystemName]
    }
    else {
        $Latest = $OperatingSystemHT[$OperatingSystemName] | Sort-Object -Property Version -Descending | Select-Object -First 1
        $ToRemove = $OperatingSystemHT[$OperatingSystemName] | Sort-Object -Property Version -Descending | Select-Object -Skip 1
        Write-Host -Object "'$OperatingSystemName' exists only in multiple versions. We will keep only the '$Latest' version"
        #Removing the old ISO files
        Write-Warning -Message "Removing: $($ToRemove | Out-String)"
        Remove-Item -Path $ToRemove.IsoPath
        $Latest
    }
}
#endregion


#region Global variables definition
$Logon = 'Administrator'
$ClearTextPassword = 'P@ssw0rd'
$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force

$NetworkID = '10.0.0.0/16' 

$LabName = 'ALImages'
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
c:
#these credentials are used for connecting to the machines. As this is a lab we use clear-text passwords
Set-LabInstallationCredential -Username $Logon -Password $ClearTextPassword

#defining default parameter values, as these ones are the same for all the machines
$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:Network'   = $LabName
    'Add-LabMachineDefinition:MinMemory' = 1GB
    'Add-LabMachineDefinition:MaxMemory' = 2GB
    'Add-LabMachineDefinition:Memory'    = 2GB
    #'Add-LabMachineDefinition:Processors'      = 4
}


#region Creating a VM per OS (Latest version) 
$Index = 0
foreach ($CurrentOperatingSystem in $LastestOperatingSystem) {
    $Index++
    $IPv4Address = "10.0.0.{0}" -f $Index
    $Name = $CurrentOperatingSystem.OperatingSystemName -replace "\s*", "" -replace "Windows", "Win" -replace "Server*" -replace "(\d+).*", '$1'
    Add-LabMachineDefinition -Name $Name -IpAddress $IPv4Address -OperatingSystem $CurrentOperatingSystem.OperatingSystemName
}
#endregion

#Installing servers
Install-Lab

Show-LabDeploymentSummary
#Cleanup
Remove-Lab -Name $LabName -Confirm:$false -ErrorAction SilentlyContinue
Stop-Transcript

#region Cleaning up the old base images
$BaseImages = Get-ChildItem -Path C:\AutomatedLab-VMs\ -Filter *.vhdx |  Select-Object -Property *, @{Name = "Prefix"; Expression = { $_.BaseName -replace "_\d.*" } } | Group-Object -Property Prefix  -AsHashTable -AsString
foreach ($CurrentBaseImage in $BaseImages.Keys) {
    if ($BaseImages[$CurrentBaseImage].Count -gt 1) {
        $BaseImages[$CurrentBaseImage] | Sort-Object -Property FullName -Descending | Select-Object -Skip 1 | Remove-Item
    }
}
#endregion