Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

#region Customizing Taksbar 
#There is an invisible char (BOM) insite the double quotes. Do not remove It
Invoke-Expression -Command "& { $((Invoke-RestMethod https://raw.githubusercontent.com/Ccmexec/PowerShell/master/Customize%20TaskBar%20and%20Start%20Windows%2011/CustomizeTaskbar.ps1) -replace "﻿") } -MoveStartLeft -RemoveWidgets -RemoveChat -RemoveSearch -RunForExistingUsers" -Verbose
#endregion

#My Github Repo Local Setup
$SourceControlDir = (Get-ChildItem -Path (Get-PSDrive -PSProvider FileSystem | Where-Object -FilterScript { $_.Used }).Root -Directory -Filter "Source Control").FullName
$LabSourcesDir = (Get-ChildItem -Path (Get-PSDrive -PSProvider FileSystem | Where-Object -FilterScript { $_.Used }).Root -Directory -Filter "LabSources").FullName

Set-Location -Path $(Join-Path -Path $SourceControlDir -ChildPath "GitHub")
git lfs install
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "git clone https://github.com/lavanack/laurentvanacker.com.git" -Wait
Set-Location -Path "laurentvanacker.com"
git lfs pull

#region AutomatedLab ISO downloads
Connect-AzAccount
$StartTime = Get-Date
$EndTime = $StartTime.AddDays(1)
$storageAccountName = "labsources"
$ShareName = "isos"
$ResourceGroup = "rg-automatedlab-storage-use-001"
$storageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroup -AccountName $storageAccountName).Value[0]

#region Get Download URL - Version #1
$Context = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $storageAccountKey
$StorageShareSASToken = New-AzStorageShareSASToken -Context $context -ExpiryTime $EndTime -Permission "rl" -ShareName $ShareName -FullUri
#endregion
#>

#region Get Download URL - Version #2
$env:AZURE_STORAGE_CONNECTION_STRING = "DefaultEndpointsProtocol=https;AccountName=$storageAccountName;AccountKey=$storageAccountKey;EndpointSuffix=core.windows.net"
$StorageShareSASToken = New-AzStorageShareSASToken -ExpiryTime $EndTime -Permission "rl" -ShareName $ShareName -FullUri 
#endregion

#region Get Download URL - Version #3
$Context = New-AzStorageContext -ConnectionString "DefaultEndpointsProtocol=https;AccountName=$StorageAccountName;AccountKey=$StorageAccountKey"
$StorageShareSASToken = New-AzStorageShareSASToken -Context $Context -ExpiryTime $EndTime -Permission rl -ShareName $ShareName -FullUri 
#endregion

#Adding /* add the end of the URI to avoid to copy the container name in the local destination folder
$StorageShareSASToken = $StorageShareSASToken -replace "\?", "/*?"

Set-Location -Path "C:\Tools\azcopy_windows*"
$DestinationFolder = $(Join-Path -Path $LabSourcesDir -ChildPath "ISOs")
$env:AZCOPY_CRED_TYPE = "Anonymous";
$env:AZCOPY_CONCURRENCY_VALUE = "AUTO";
./azcopy.exe copy $StorageShareSASToken $DestinationFolder --overwrite=ifSourceNewer --check-md5 FailIfDifferent --from-to=FileLocal --preserve-smb-info=true --recursive --log-level=INFO #--trailing-dot=Enable
$env:AZCOPY_CRED_TYPE = "";
$env:AZCOPY_CONCURRENCY_VALUE = "";
#endregion