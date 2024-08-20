Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$LogDir = Join-Path -Path $CurrentDir -ChildPath "HostPool*"
$LatestLogDir = Get-ChildItem -Path $LogDir | Sort-Object -Descending | Select-Object -First 1
$BackupDir = Join-Path -Path $CurrentDir -ChildPath "Backup"

#region Error Management
#Get-Content -Path $(Join-Path -Path $LatestLogDir -ChildPath "New*.txt") -Tail 10 -Wait | Select-String -Pattern "~~" -Context 1

Set-Location -Path $CurrentDir
Get-Job | Remove-Job -Force
try { while (Stop-Transcript) {} } catch {}
#Looking for error in the log files
$LogFiles = Get-ChildItem -Path $LatestLogDir -Filter New*.txt -File
if ($LogFiles) {
    $Errors = Select-String -Pattern "~~" -Path $LogFiles -Context 1
    $Errors
    #Editing the files with errors.
    if ($Errors) {
        $Errors.Path | Select-Object -Unique | ForEach-Object -Process { & $_ }
    }
}
#endregion

break

#region Cleanup
Get-AzResourceGroup | Where-Object -FilterScript { $_.ResourceGroupName -match 'poc' } | Remove-AzResourceGroup -AsJob -Force

#region Removing previously existing resources
$LatestHostPoolJSONFile = Get-ChildItem -Path $BackupDir -Filter "HostPool_*.json" -File | Sort-Object -Property Name -Descending
if ($LatestHostPoolJSONFile) {
    #region Removing the latest deployed resources
    Remove-AzAvdHostPoolSetup -FullName $LatestHostPoolJSONFile.FullName -Verbose
}
else {
    Remove-AzAvdHostPoolSetup -HostPool $HostPools -Verbose
}
#endregion

<#
if ($LogFiles) {
    #Doing some cleanups
    Remove-Item -Path $LogFiles -Force
}
#>
#endregion

