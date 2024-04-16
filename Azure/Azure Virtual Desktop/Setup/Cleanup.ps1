Clear-Host
#Get-Content -Path $(Join-Path -Path $([Environment]::GetFolderPath("MyDocuments")) -ChildPath "New*.txt") -Tail 10 -Wait | Select-String -Pattern "~~" -Context 1

Set-Location -Path $([Environment]::GetFolderPath("MyDocuments"))
Get-Job | Remove-Job -Force
try { while (Stop-Transcript) {} } catch {}
#Looking for error in the log files
$LogFiles = Get-ChildItem -Path $([Environment]::GetFolderPath("MyDocuments")) -Filter New*.txt -File
if ($LogFiles) {
    $Errors = Select-String -Pattern "~~" -Path $LogFiles -Context 1
    $Errors
    if ($Errors) {
        psedit $Errors.Path | Select-Object -Unique
    }
    #Doing some cleanups
    Remove-Item -Path $LogFiles -Force
}
Get-AzResourceGroup | Where-Object -FilterScript { $_.ResourceGroupName -match 'poc' } | Remove-AzResourceGroup -AsJob -Force

#region Removing previously existing resources
$LatestHostPoolJSONFile = Get-ChildItem -Path $CurrentDir -Filter "HostPool_*.json" -File | Sort-Object -Property Name -Descending | Select-Object -First 1
if ($LatestHostPoolJSONFile) {
    #region Removing the latest deployed resources
    Remove-AzAvdHostPoolSetup -FullName $LatestHostPoolJSONFile -Verbose
}
else {
    Remove-AzAvdHostPoolSetup -HostPool $HostPools -Verbose
}
#endregion

#Set-PSBreakpoint -Command New-AzDataCollectionRuleAssociation 
