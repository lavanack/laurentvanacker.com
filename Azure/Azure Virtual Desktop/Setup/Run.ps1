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
)

Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
#$LogDir = [Environment]::GetFolderPath("MyDocuments")
$LogDir = $CurrentDir
Set-Location -Path $CurrentDir

try { while (Stop-Transcript) {} } catch {}
#Get-Job | Remove-Job -Force
Get-Job | Where-Object -FilterScript {$_.PSJobTypeName -eq "ThreadJob"} | Remove-Job -Force -Verbose
$null = Remove-Module -Name PSAzureVirtualDesktop -Force -ErrorAction Ignore
$Global:MaximumFunctionCount = 32768
Import-Module -Name PSAzureVirtualDesktop -Force -Verbose

Connect-MgGraph -NoWelcome
try { 
    $null = Get-AzAccessToken -ErrorAction Stop
} catch {
    Connect-AzAccount
    Get-AzSubscription | Out-GridView -OutputMode Single | Select-AzSubscription
}

#region Dirty Cleanup - Removing everything for a complete restart
try {
    Get-ChildItem -Path $LogDir -Filter HostPool_* -Directory | Remove-Item -Force -Recurse -ErrorAction Stop
}
catch {
    Stop-Process -Name notepad, powershell* -Force -ErrorAction Ignore
    Get-ChildItem -Path $LogDir -Filter HostPool_* -Directory | Remove-Item -Force -Recurse -ErrorAction Stop
}

$null = Get-AzResourceGroup | Where-Object -FilterScript { $_.ResourceGroupName -match '^rg-avd-.*-poc-.*-\d+'} | Remove-AzResourceGroup -AsJob -Force -Verbose | Receive-Job -Wait -AutoRemoveJob
Get-MgBetaGroup -Filter "DisplayName eq 'No-MFA Users'" | ForEach-Object -Process { Remove-MgBetaGroup -GroupId $_.Id -Verbose }
Get-MgBetaIdentityConditionalAccessPolicy -Filter "displayName eq '[AVD] Require multifactor authentication for all users'" | ForEach-Object -Process { Remove-MgBetaIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $_.Id -Verbose }
Get-AzKeyVault -InRemovedState | Remove-AzKeyVault -InRemovedState -AsJob -Force
& '.\Tests\Clear-WindowsCredentials.ps1' -Verbose
#endregion

#Set-PSDebug -Trace 2
$PSBreakpoints = @() 
$LatestPSAzureVirtualDesktopModule = Get-Module -Name PSAzureVirtualDesktop -ListAvailable | Sort-Object -Property Version -Descending | Select-Object -First 1
#$PSBreakpoints += Set-PSBreakpoint -Command Get-Credential
#$PSBreakpoints += Set-PSBreakpoint -Script $(Join-Path -Path $LatestPSAzureVirtualDesktopModule.ModuleBase -ChildPath $LatestPSAzureVirtualDesktopModule.RootModule) -Line 4889
#$PSBreakpoints += Set-PSBreakpoint -Script $(Join-Path -Path $LatestPSAzureVirtualDesktopModule.ModuleBase -ChildPath $LatestPSAzureVirtualDesktopModule.RootModule) -Command New-PsAvdPrivateEndpointSetup
#$PSBreakpoints += Set-PSBreakpoint -Script $(Join-Path -Path $LatestPSAzureVirtualDesktopModule.ModuleBase -ChildPath $LatestPSAzureVirtualDesktopModule.RootModule) -Variable $ThisDomainControllerVirtualNetwork -Mode ReadWrite
if ($PSBreakpoints.Count -le 0) {
    & '.\Scenarios\0 - Full - Tests' -LogDir $LogDir -Verbose -AsJob
}
else {
    & '.\Scenarios\0 - Full - Tests' -LogDir $LogDir -Verbose
    $PSBreakpoints | Remove-PSBreakpoint
}
#Set-PSDebug -Off
