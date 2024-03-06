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
#requires -Version 5

param (
    [ValidateSet("Enabled", "Disabled")]
    [String] $Status = "Disabled"
)

if ($Status -eq "Disabled") {
    $RegistryValue = 0
}
else {
    $RegistryValue = 1
}
foreach ($CurrentHostPool in Get-AzWvdHostPool) {
    $CurrentHostPoolResourceGroupName = ((Get-AzWvdHostPool).Id -split "/")[4]
    $SessionHosts = Get-AzWvdSessionHost -HostpoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName
    $SessionHostNames = $SessionHosts.ResourceId -replace ".*/"
    #region Configure the clients to disable FSLogix
    $Jobs = foreach ($CurrentSessionHostName in $SessionHostNames) {
        Write-Host "Processing '$CurrentSessionHostName' ..."
        $ScriptString = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\FSLogix\Profiles' -Name 'Enabled' -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value $RegistryValue"
        # Run PowerShell script on the VM
        Invoke-AzVMRunCommand -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentSessionHostName -CommandId 'RunPowerShellScript' -ScriptString $ScriptString -AsJob
    }
    $Jobs | Wait-Job | Out-Null
    $Jobs | Remove-Job -Force
    #endregion

    #region Restarting the Session Hosts
    $Jobs = foreach ($CurrentSessionHostName in $SessionHostNames) {
        Write-Host "Restarting '$CurrentSessionHostName' ..."
        Restart-AzVM -Name $CurrentSessionHostName -ResourceGroupName $CurrentHostPoolResourceGroupName -Confirm:$false -AsJob
    }
    $Jobs | Wait-Job | Out-Null
    $Jobs | Remove-Job -Force
}
#endregion
