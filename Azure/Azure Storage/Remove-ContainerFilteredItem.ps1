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
#requires -Version 5 -Modules Az.Accounts, Az.Storage

[CmdletBinding()]
param
(
)


#region function definitions
function New-AzTestStorageContainer {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [datetime] $StartTime = [DateTime]::ParseExact("{0}0101" -f ([Datetime]::Today).Year, 'yyyyMMdd', [CultureInfo]::InvariantCulture),
        [ValidateScript({ $_ -ge $StartTime })]
        [datetime] $EndTime = $StartTime.AddYears(1).AddDays(-1),
        [ValidateScript({ $_ -in $((Get-AzLocation).Location) })]
        [string] $Location = "eastus2",
        [ValidateRange(0, 10)]
        [Alias('FolderDepth')]
        [uint16] $Depth = 0
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$StartTime: $StartTime"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$EndTime: $EndTime"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Location: $Location"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Depth: $Depth"
    #region Defining variables 
    #region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
    $AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
    $ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
    $shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
    #endregion

    #region Building an Hashtable to get the shortname of every Azure resource based on a JSON file on the Github repository of the Azure Naming Tool
    $Result = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/refs/heads/main/src/repository/resourcetypes.json 
    $ResourceTypeShortNameHT = $Result | Where-Object -FilterScript { $_.property -in @('', 'Windows') } | Select-Object -Property resource, shortName, lengthMax | Group-Object -Property resource -AsHashTable -AsString
    #endregion


    #Naming convention based on https://github.com/mspnp/AzureNamingTool/blob/main/src/repository/resourcetypes.json
    $AzureVMNameMaxLength = $ResourceTypeShortNameHT["Compute/virtualMachines"].lengthMax
    $ResourceGroupPrefix = $ResourceTypeShortNameHT["Resources/resourcegroups"].ShortName
    $StorageAccountPrefix = $ResourceTypeShortNameHT["Storage/storageAccounts"].ShortName
    $ContainerPrefix = $ResourceTypeShortNameHT["Storage/blob"].ShortName
    $VirtualMachinePrefix = $ResourceTypeShortNameHT["Compute/virtualMachines"].ShortName
    $NetworkSecurityGroupPrefix = $ResourceTypeShortNameHT["Network/networkSecurityGroups"].ShortName
    $LocationShortName = $shortNameHT[$Location].shortName

    $Project = "blob"
    $Role = "test"
    #$DigitNumber = 4
    $DigitNumber = $AzureVMNameMaxLength - ($VirtualMachinePrefix + $Project + $Role + $LocationShortName).Length
    $StorageAccountSkuName = "Standard_LRS"

    Do {
        $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
        $StorageAccountName = "{0}{1}{2}{3}{4:D$DigitNumber}" -f $StorageAccountPrefix, $Project, $Role, $LocationShortName, $Instance                       
        #$ContainerName = "{0}{1}{2}{3}{4:D$DigitNumber}" -f $ContainerPrefix, $Project, $Role, $LocationShortName, $Instance                       
    } While ((-not(Get-AzStorageAccountNameAvailability -Name $StorageAccountName).NameAvailable))

    $ContainerName = "clientdatauploads"
    $ResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       

    $StorageAccountName = $StorageAccountName.ToLower()
    $ContainerName = $ContainerName.ToLower()
    $ResourceGroupName = $ResourceGroupName.ToLower()

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$StorageAccountName: $StorageAccountName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ContainerName: $ContainerName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ResourceGroupName: $ResourceGroupName"

    $Prefix = "commercial_policy"
    #endregion


    #region ResourceGroup
    $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
    if ($ResourceGroup) {
        #Step 0: Remove previously existing Azure Resource Group with the same name
        $ResourceGroup | Remove-AzResourceGroup -Force -Verbose
    }
    $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
    #endregion

    #region StorageAccount
    $StorageAccount = New-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -Location $Location -SkuName $StorageAccountSkuName -MinimumTlsVersion TLS1_2 -EnableHttpsTrafficOnly $true -AllowBlobPublicAccess $true

    #Getting context for blob upload
    $StorageContext = $StorageAccount.Context
    #endregion

    #Performing blob upload
    $StorageContainer = New-AzStorageContainer -Name $ContainerName -Context $StorageContext

    #region Assigning the 'Storage Blob Data Contributor' RBAC Role to logged in user on the Storage Account
    $RoleDefinition = Get-AzRoleDefinition -Name "Storage Blob Data Contributor"
    $Parameters = @{
        SignInName         = (Get-AzContext).Account.Id
        RoleDefinitionName = $RoleDefinition.Name
        Scope              = $StorageAccount.Id
    }
    while (-not(Get-AzRoleAssignment @Parameters)) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.SignInName)' Identity on the '$($Parameters.Scope)' scope"
        $RoleAssignment = New-AzRoleAssignment @Parameters
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
        Start-Sleep -Seconds 30
    }
    #endregion 

    $CurrentTime = $StartTime
    $FolderIndex = 0
    $DayNumber = ($EndTime - $StartTime).Days + 1
    $ProcessingStartTime = Get-Date
    $RootLocalFolderPath = Join-Path -Path $env:TEMP -ChildPath $("{0}_{1:yyyyMMddHHmmss}" -f $MyInvocation.MyCommand, $(Get-Date))
    #Creating a dummy.txt file a the $RootLocalFolderPath because without it the recurse copy won't include the Uploads folder
    $null = New-Item -Path $(Join-Path -Path $RootLocalFolderPath -ChildPath "dummy.txt") -ItemType File -Force
    $UploadsLocalFolderPath = Join-Path -Path $RootLocalFolderPath -ChildPath "Uploads"
    While ($CurrentTime -le $EndTime) {
        $FolderIndex++
        $LocalFolderName = "{0:yyyyMMdd}" -f $CurrentTime
        Write-Progress -Id 1 -Activity "[$FolderIndex/$DayNumber] Processing '$LocalFolderName'" -Status "Percent : $('{0:N0}' -f $($FolderIndex/$DayNumber * 100)) %" -PercentComplete ($FolderIndex / $DayNumber * 100)
        $LocalFolderPath = Join-Path -Path $UploadsLocalFolderPath -ChildPath $LocalFolderName
        $null = New-Item -Path $LocalFolderPath -ItemType Directory -Force
        $FileNbToGenerate = Get-Random -Minimum 10 -Maximum 25
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$LocalFolderName: $LocalFolderName"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$LocalFolderPath: $LocalFolderPath"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$FileNbToGenerate: $FileNbToGenerate"
        foreach ($FileIndex in 1..$FileNbToGenerate) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$FileIndex: $FileIndex/$FileNbToGenerate"
            #Randomy generating a filename with the prefix or something else
            $FileName = ([System.IO.Path]::GetRandomFileName() -replace "\.", $("_{0:D2}." -f $FileIndex)), $("{0}_keys_table_{1}_{2}_0.parquet" -f $Prefix, $(Get-Random -Minimum 1 -Maximum 10), $(Get-Random -Minimum 1 -Maximum 10)) | Get-Random
            #Generating a random folder structure
            #$SubFolders = (1..(Get-Random -Minimum 1 -Maximum 3) | ForEach-Object -Process { (-join ((48..57) + (65..90) + (97..122) | Get-Random -Count $(Get-Random -Minimum 3 -Maximum 20) | % {[char]$_})) }) -join $([System.IO.Path]::DirectorySeparatorChar)
            
            $SubFolders = & { $FolderNames = for ($i = 0; $i -lt $Depth; $i++) { ( -join ((48..57) + (65..90) + (97..122) | Get-Random -Count $(Get-Random -Minimum 3 -Maximum 20) | ForEach-Object -Process { [char]$_ })) }; $FolderNames -join $([System.IO.Path]::DirectorySeparatorChar) }
            $RandomFolderStructure = Join-Path -Path $LocalFolderPath -ChildPath $SubFolders

            $null = New-Item -Path $RandomFolderStructure -ItemType Directory -Force
            $LocalFilePath = Join-Path -Path $RandomFolderStructure -ChildPath $FileName
            Write-Progress -Id 2 -Activity "[$FileIndex/$FileNbToGenerate] Creating '$LocalFilePath'" -Status "Percent : $('{0:N0}' -f $($FileIndex/$FileNbToGenerate * 100)) %" -PercentComplete ($FileIndex / $FileNbToGenerate * 100)
            $BlobFilePath = Join-Path -Path $LocalFolderName -ChildPath $FileName
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$FileName: $FileName"
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$LocalFilePath: $LocalFilePath"
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$BlobFilePath: $BlobFilePath"
            #region Generating Random File Content
            $Size = Get-Random -Minimum 10KB -Maximum 1MB
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Size: $Size"
            $Content = New-Object byte[] $Size
            (New-Object System.Random).NextBytes($content)
            #endregion
            # Set-Content is very slow, use .NET method directly
            [System.IO.File]::WriteAllBytes($LocalFilePath, $content)
        }
        Write-Progress -Id 2 -Activity "Completed !" -Completed
        $CurrentTime = $CurrentTime.AddDays(1)
    }
    Write-Progress -Id 1 -Activity "Completed !" -Completed

    #region Upload Testing: To be sure the RBAC role are well assigned
    $Attempts = 0
    $AttemptLimit = 5
    $BlobFilePath = [System.IO.Path]::GetRandomFileName()
    $LocalFilePath = Join-Path -Path $env:TEMP -ChildPath $BlobFilePath
    $null = New-Item -Path $LocalFilePath -ItemType File -Force
    Do {
        $Attempts++
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
        Start-Sleep -Seconds 30
        try {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Upload Test #$Attempts"
            $Result = Set-AzStorageBlobContent -Context $StorageContext -Container $ContainerName -File $LocalFilePath -Blob $BlobFilePath -ServerTimeoutPerRequest 10 -ClientTimeoutPerRequest 10 -Force
            $Success = $True
            $null = Remove-AzStorageBlob -Context $StorageContext -Container $ContainerName -Blob $BlobFilePath
        }
        catch [Microsoft.Azure.Storage.StorageException] {
            Write-Warning -Message $_.Exception-Message
            $Success = $False
        }
    } While (-not($Success) -and ($Attempts -le $AttemptLimit))
    if (-not($Success)) {
        Write-Error -Exception "Upload Testing Failed after $Attempts attempts" -ErrorAction Stop
    }
    else {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Upload Test successfully completed !"
    }
    #endregion

    #Uploading data to the Container
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Uploading Content"
    $null = Get-ChildItem -Path $RootLocalFolderPath -File -Recurse | Set-AzStorageBlobContent -Context $StorageContext -Container $ContainerName -ServerTimeoutPerRequest 10 -ClientTimeoutPerRequest 10 -Force
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Content Uploaded"

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing '$RootLocalFolderPath' Folder"
    $null = Remove-Item -Path $RootLocalFolderPath -Force -Recurse

    $ProcessingEndTime = Get-Date
    $TimeSpan = New-TimeSpan -Start $ProcessingStartTime -End $ProcessingEndTime
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing Time: $TimeSpan"

    return $StorageContainer
}

function Remove-AzStorageContainerFilteredItem {
    [CmdletBinding(PositionalBinding = $false, SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Microsoft.WindowsAzure.Commands.Common.Storage.ResourceModel.AzureStorageContainer] $StorageContainer,
        [Parameter(Mandatory = $true)]
        [datetime] $StartTime,
        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_ -ge $StartTime })]
        [datetime] $EndTime,
        [Parameter(Mandatory = $true)]
        [string] $Prefix
    )

    #Set Time To Midnight
    $StartTime = $StartTime.Date
    #Set Time To 23:59:59.999
    $EndTime = $EndTime.Date.AddDays(1).AddMilliseconds(-1)

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$StorageContainer: $($StorageContainer.Name)"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$StorageAccountName: $($StorageContainer.Context.StorageAccountName)"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$StartTime: $StartTime"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$EndTime: $EndTime"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Prefix: $Prefix"

    $RegPattern = "^.*/$Prefix"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$RegPattern: $RegPattern"

    #Getting the Blobs
    $StorageBlob = $StorageContainer | Get-AzStorageBlob
    #Getting the blobs where the folder name (under the yyyyMMdd format is between $StartTime and $EndTime (included)
    $FilteredStorageBlob = $StorageBlob | Where-Object -FilterScript { 
        if ($_.Name -match "/(?<Date>\d{8})/") {
            $Date = [DateTime]::ParseExact($Matches['Date'], 'yyyyMMdd', [CultureInfo]::InvariantCulture)
            #Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Date: $Date"
            (($Date -ge $StartTime) -and ($Date -le $EndTime)) 
        }
        else {
            Write-Warning -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] No date found (under the format: yyyyMMdd) in '$($_.Name)'"
            $false
        }
    }

    #Getting the blob where the name is matching the regular expression pattern
    $FilteredStorageBlobToDelete = foreach ($CurrentFilteredStorageBlob in $FilteredStorageBlob) {
        if ($CurrentFilteredStorageBlob.Name -match $RegPattern) {
            $CurrentFilteredStorageBlob
        }
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing blobs:`r`n"
    if ($PSCmdlet.ShouldProcess("`r`n{0}" -f $($FilteredStorageBlobToDelete.Name -join "`r`n"), "Removing Storage Blob")) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing blobs ..."
        $FilteredStorageBlobToDelete | Remove-AzStorageBlob -ServerTimeoutPerRequest 10 -ClientTimeoutPerRequest 10 -Force
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Blobs removed !"
    }
}
#endregion

Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir
$Timestamp = Get-Date
$BeforeCleanupCSVFile = $CurrentScript -replace "\.ps1", $("_BeforeCleanup_{0:yyyyMMddHHmmss}.csv" -f $Timestamp)
$AfterCleanupCSVFile = $CurrentScript -replace "\.ps1", $("_AfterCleanup_{0:yyyyMMddHHmmss}.csv" -f $Timestamp)

#region Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount
}
#endregion

$Location = "eastus2"

#region Generating a Test Container with a folder per day for the 2025 year (and with dummy files and contents)
#$NewStartTime = [DateTime]::ParseExact("{0}0101" -f ([Datetime]::Today).Year, 'yyyyMMdd',[CultureInfo]::InvariantCulture)
$NewStartTime = [DateTime]::ParseExact("20250101", 'yyyyMMdd', [CultureInfo]::InvariantCulture)
$NewEndTime = $NewStartTime.AddYears(1).AddDays(-1)
$StorageContainer = New-AzTestStorageContainer -Location $Location -StartTime $NewStartTime -EndTime $NewEndTime -Depth 0 -Verbose
#endregion 

#region Cleaning up
#region Exporting Data Before Cleanup
$StorageBlob = $StorageContainer | Get-AzStorageBlob
$StorageBlob | Select-Object -Property Name | Sort-Object -Property Name | Export-Csv -Path $BeforeCleanupCSVFile -NoTypeInformation
#endregion 

$RemoveStartTime = [DateTime]::ParseExact("20250623", 'yyyyMMdd', [CultureInfo]::InvariantCulture)
$RemoveEndTime = [DateTime]::ParseExact("20251116", 'yyyyMMdd', [CultureInfo]::InvariantCulture)
$Prefix = "commercial_policy"
#-WhatIf invoked ==> Simulation Mode (No Deletion)
$StorageContainer | Remove-AzStorageContainerFilteredItem -StartTime $RemoveStartTime -EndTime $RemoveEndTime -Prefix $Prefix -Verbose -WhatIf

#Uncomment the line below when you are sure. You will be prompted before the deletion
#$StorageContainer | Remove-AzStorageContainerFilteredItem -StartTime $RemoveStartTime -EndTime $RemoveEndTime -Prefix $Prefix -Verbose

#Uncomment the line below when you are REALLY sure. You WON'T be prompted before the deletion !!!
#$StorageContainer | Remove-AzStorageContainerFilteredItem -StartTime $RemoveStartTime -EndTime $RemoveEndTime -Prefix $Prefix -Confirm:$false -Verbose

#region Exporting Data After Cleanup
$StorageBlob = $StorageContainer | Get-AzStorageBlob
$StorageBlob | Select-Object -Property Name | Sort-Object -Property Name | Export-Csv -Path $AfterCleanupCSVFile -NoTypeInformation
#endregion 

#region Comparison Before vs After Cleanup
$DeletedBlobs = Compare-Object -ReferenceObject $(Get-Content -Path $BeforeCleanupCSVFile) -DifferenceObject $(Get-Content -Path $AfterCleanupCSVFile)
$DeletedBlobs
#endregion 
#endregion 
