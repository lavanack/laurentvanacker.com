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
#requires -Version 5 -Modules Az.Compute, Az.Storage, Az.Resources

[CmdletBinding()]
param
(
    [string] $ResourceGroupName = "rg-automatedlab-storage-use-001",
    [string] $StorageAccountName = "automatedlablabsources",
    [string] $ShareName = "isos",
    [Parameter(Mandatory = $true)]
    [ValidateSet("Pull", "Push")]
    [string] $Mode
)

Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

#region Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount
    #Get-AzSubscription | Out-GridView -OutputMode Single -Title "Select your Azure Subscription" | Select-AzSubscription
    #$Subscription = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction Ignore
    #Select-AzSubscription -SubscriptionName $SubscriptionName | Select-Object -Property *
}
#endregion

#region Set Storage Account Configuration
$MyPublicIp = (Invoke-WebRequest -uri "https://ipv4.seeip.org").Content
$null = Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -PublicNetworkAccess Enabled -AllowSharedKeyAccess $true -NetworkRuleSet (@{ipRules = (@{IPAddressOrRange = $MyPublicIp; Action = "allow" }); defaultAction = "deny" })
Start-Sleep -Seconds 10
#endregion

#region Installing AzCopy
$AzCopyURI = 'https://aka.ms/downloadazcopy-v10-windows'
$OutputFile = Join-Path -Path $CurrentDir -ChildPath 'azcopy_windows_amd64_latest.zip'
Invoke-WebRequest -Uri $AzCopyURI -OutFile $OutputFile
Expand-Archive -Path $OutputFile -DestinationPath C:\Tools -Force
Remove-Item -Path $OutputFile -Force
#endregion

#region AutomatedLab ISO uploads
$StartTime = Get-Date
$ExpiryTime = $StartTime.AddDays(1)
$storageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -AccountName $StorageAccountName).Value[0]

#region $Get Upload URL - Version #1
$Context = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $storageAccountKey
$StorageShareSASToken = New-AzStorageShareSASToken -Context $context -ExpiryTime $ExpiryTime -Permission "rwdl" -ShareName $ShareName -FullUri
#endregion

#region $Get Upload URL - Version #2
$env:AZURE_STORAGE_CONNECTION_STRING = "DefaultEndpointsProtocol=https;AccountName=$StorageAccountName;AccountKey=$storageAccountKey;EndpointSuffix=core.windows.net"
$StorageShareSASToken = New-AzStorageShareSASToken -ExpiryTime $ExpiryTime -Permission "rwdl" -ShareName $ShareName -FullUri 
#endregion

#region $Get Upload URL - Version #3
$Context = New-AzStorageContext -ConnectionString "DefaultEndpointsProtocol=https;AccountName=$StorageAccountName;AccountKey=$StorageAccountKey"
$StorageShareSASToken = New-AzStorageShareSASToken -Context $Context -ExpiryTime $ExpiryTime -Permission "rwdl" -ShareName $ShareName -FullUri 
#endregion

#Looking for the LabSources Folder across the drives
$LabSourcesDir = (Get-ChildItem -Path (Get-PSDrive -PSProvider FileSystem | Where-Object -FilterScript { $_.Used }).Root -Directory -Filter "LabSources").FullName
#Creating the ISOs path
$ISOFolder = Join-Path -Path $LabSourcesDir -ChildPath "\ISOs"

<#
#region Building the input file with iso file list
$AzCopyLogFile = Join-Path -Path $env:Temp -ChildPath $("azcopy_{0}.log" -f (Get-Date -Format 'yyyyMMddHHmmss'))
(Get-ChildItem -Path $ISOFolder).Name | Out-File -FilePath $AzCopyLogFile -Encoding utf8
#& $AzCopyLogFile
#endregion
#>

#Go to the latest azcopy folder
Get-ChildItem -Path "C:\Tools\azcopy_windows*" | Sort-Object -Property Name -Descending | Select-Object -First 1 | Push-Location
$env:AZCOPY_CRED_TYPE = "Anonymous"
$env:AZCOPY_CONCURRENCY_VALUE = "AUTO"
Switch ($Mode) {
    "Pull" {
        ./azcopy.exe sync $ISOFolder $StorageShareSASToken --delete-destination=true --log-level=INFO --put-md5
    }
    "Push" {
        ./azcopy.exe sync  $StorageShareSASToken $ISOFolder --delete-destination=true --log-level=INFO --put-md5
    }
}
$env:AZCOPY_CRED_TYPE = ""
$env:AZCOPY_CONCURRENCY_VALUE = ""
Pop-Location
#endregion

#region Set Storage Account Configuration
$null = Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -PublicNetworkAccess Disabled -AllowSharedKeyAccess $false
#endregion
