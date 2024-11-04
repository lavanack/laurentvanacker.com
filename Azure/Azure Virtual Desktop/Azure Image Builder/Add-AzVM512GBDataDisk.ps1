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
#endregion

#region Powershell Pre-requisites
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module Az.Accounts, Az.Compute -Force -Verbose -AllowClobber
#endregion

#region Azure connection
#Works because the VM has only one User Managed Identity (else you have to specify -Body @{client_id=$identityClientId} in the Invoke-RestMethod call)
$Token = Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource=https://management.azure.com/" -Method GET -Headers @{Metadata="true"} -TimeoutSec 5
Connect-AzAccount -AccessToken $Token.access_token -AccountId $Token.client_id
#endregion

#region Variable definitions
$ThisVM = Get-AzVMCompute | Get-AzVM
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
