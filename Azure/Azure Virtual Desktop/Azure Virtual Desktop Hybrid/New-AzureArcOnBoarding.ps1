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

#requires -Version 5

[CmdletBinding(PositionalBinding = $false)]
param
(
    [Parameter(Mandatory)]
    [string]$ResourceGroupName,
    [Parameter(Mandatory)]
    [string]$SubscriptionId,
    [switch]$EntraIDJoin
)

$null = Get-PackageProvider -Name Nuget -ForceBootstrap -Force
#Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
$RequiredModules = 'Az.Accounts', 'Az.Resources', 'Az.ConnectedMachine'
$InstalledModule = Get-InstalledModule -Name $RequiredModules -ErrorAction Ignore
if (-not([String]::IsNullOrEmpty($InstalledModule))) {
    $MissingModules = (Compare-Object -ReferenceObject $RequiredModules -DifferenceObject (Get-InstalledModule -Name $RequiredModules -ErrorAction Ignore).Name).InputObject
}
else {
    $MissingModules = $RequiredModules
}
if (-not([String]::IsNullOrEmpty($MissingModules))) {
    Install-Module -Name $MissingModules -AllowClobber -Force -Verbose 
}

#region Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount -Subscription $SubscriptionId -UseDeviceAuthentication
}

$Location = (Get-AzResourceGroup -ResourceGroupName $ResourceGroupName).Location

#region Azure Arc Join
#removing any existing Azure Arc Hybrid Machine with the same name
$Parameters = @{
    ResourceGroupName = $ResourceGroupName
    Name = $env:COMPUTERNAME
}
if (Get-AzConnectedMachine @Parameters -ErrorAction Ignore) {
    Remove-AzConnectedMachine @Parameters -ErrorAction Ignore
    start-Sleep -Seconds 30
}
#Connecting
Connect-AzConnectedMachine @Parameters -Location $Location
#~Checking
Get-AzConnectedMachine @Parameters
#endregion

#region EntraID Join
if ($EntraIDJoin) {
    $settings = @{
        # IMPORTANT: must be present even empty
        mdmId = ""   
    }
    #Connecting
    $Parameters = @{
        Name = "aadlogin"
        ResourceGroupName = $ResourceGroupName
        MachineName = $env:COMPUTERNAME
        Location = $Location
        Publisher = "Microsoft.Azure.ActiveDirectory" 
        ExtensionType = "AADLoginForWindows" 
        Settings = $settings
    }
    New-AzConnectedMachineExtension @Parameters

    #Checking
    $Parameters = @{
        Name = "aadlogin"
        ResourceGroupName = $ResourceGroupName
        MachineName = $env:COMPUTERNAME
    }
    Get-AzConnectedMachineExtension @Parameters    
    
    dsregcmd /status
}
#endregion

Write-Host -Object "`r`nDone ..." -ForegroundColor Green
