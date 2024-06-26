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
foreach ($CurrentHostPool in Get-AzWvdHostPool)
{
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
    $Jobs | Remove-Job -Force}
    #endregion
