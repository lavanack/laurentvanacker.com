#region Function definitions
#Get The Azure VM Compute Object for the VM executing this function
function Get-AzVMCompute {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    #Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $uri = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

    try {
        $response = Invoke-RestMethod -Uri $uri -Headers @{"Metadata" = "true" } -Method GET -TimeoutSec 5
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] VM Compute Object:`r`n$($response.compute | Out-String)"
        return $response.compute
    }
    catch {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        return $null
    }
}

function Get-MyAzAccessToken {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Parameter(Mandatory = $false)]
        [string] $identityClientId
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    #Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $uri = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource=https://management.azure.com/"

    try {
        if ([string]::IsNullOrEmpty($identityClientId)) {
            #Works because the VM has only one User Managed Identity (else you have to specify -Body @{client_id=$identityClientId} in the Invoke-RestMethod call)
            $MyAzAccessToken = Invoke-RestMethod -Uri $uri -Headers @{"Metadata" = "true" } -Method GET -TimeoutSec 5
        } 
        else {
            $MyAzAccessToken = Invoke-RestMethod -Uri $uri -Headers @{"Metadata" = "true" } -Body @{client_id = $identityClientId } -Method GET -TimeoutSec 5
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Azure Access Token:`r`n$($MyAzAccessToken | Out-String)"
        return $MyAzAccessToken
    }
    catch {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        return $null
    }
}

function Get-MyAzResourceGroup {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $SubscriptionId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $AccessToken
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    #Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $uri = "https://management.azure.com/subscriptions/{0}/resourceGroups/{1}?api-version=2016-06-01" -f $SubscriptionId, $resourceGroupName

    try {
        $MyAzResourceGroup = Invoke-WebRequest -Uri $uri -Method GET -Headers @{ Authorization = "Bearer $AccessToken" }
        #From https://pachehra.blogspot.com/2019/08/managed-identities-azure-ad.html
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] ResourceGroup:`r`n$($MyAzResourceGroup | Out-String)"
        return $MyAzResourceGroup
    }
    catch {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        return $null
    }
}
#endregion

#region Powershell Pre-requisites
#Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Get-PackageProvider -Name Nuget -ForceBootstrap -Force
Install-Module Az.Accounts, Az.Compute -Force -Verbose -AllowClobber
#"Az.Accounts", "Az.Compute" |  Where-Object -FilterScript { $_ -notin $(Get-Module -ListAvailable).Name } | ForEach-Object -Process { Install-Module -Name $_ -Force -Verbose -AllowClobber }
#endregion

#region Azure connection
$ThisVMCompute = Get-AzVMCompute -Verbose
$MyAzAccessToken = Get-MyAzAccessToken -Verbose
$MyAzResourceGroup = Get-MyAzResourceGroup -SubscriptionId $ThisVMCompute.subscriptionId -ResourceGroupName $ThisVMCompute.resourceGroupName -AccessToken $MyAzAccessToken.access_token -Verbose

$null = Connect-AzAccount -AccessToken $MyAzAccessToken.access_token -AccountId $MyAzAccessToken.client_id
$null = Disable-AzContextAutosave -Scope Process # Ensures you do not inherit an AzContext
$AzureContext = $Connection.context  # Connect to Azure with user-assigned managed identity
$connectionResult = Set-AzContext -SubscriptionId $ThisVMCompute.subscriptionId -DefaultProfile $AzureContext
#endregion

#region Variable definitions
$ThisVM = $ThisVMCompute | Get-AzVM
$Location = $ThisVM.Location
$DataDiskName = "{0}-DataDisk01" -f $ThisVM.Name
$DataDiskSizeGB = 512
#$OSDiskType = "Premium_LRS"
$OSDiskType = $ThisVM.StorageProfile.OsDisk.ManagedDisk.StorageAccountType 
$ResourceGroupName = $ThisVM.ResourceGroupName
#endregion

#region Adding Data Disk
$ThisVMDataDisk01Config = New-AzDiskConfig -SkuName $OSDiskType -Location $Location -CreateOption Empty -DiskSizeGB $DataDiskSizeGB
$ThisVMDataDisk01 = New-AzDisk -DiskName $DataDiskName -Disk $ThisVMDataDisk01Config -ResourceGroupName $ResourceGroupName
$ThisVM = Add-AzVMDataDisk -VM $ThisVM -Name $DataDiskName -Caching 'ReadWrite' -CreateOption Attach -ManagedDiskId $ThisVMDataDisk01.Id -Lun 0
$ThisVM | Update-AzVM
$Disk = Get-Disk -Number 1 | Where-Object PartitionStyle -EQ "RAW" | Initialize-Disk -PassThru | New-Partition -AssignDriveLetter -UseMaximumSize | Format-Volume -NewFileSystemLabel Data
#endregion

#region Generating Sample file
$TimeStamp = Get-Date -Format "yyyyMMddHHmmss"
$Path = "{0}:\{1}.txt" -f $Disk.DriveLetter, $TimeStamp
New-Item -Path $Path -ItemType File -Value "This file has been generated at $TimeStamp"
#endregion