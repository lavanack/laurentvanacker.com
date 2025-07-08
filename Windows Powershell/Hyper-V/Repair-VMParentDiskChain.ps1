#region function definitions
function Repair-VMParentDiskChain {
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [string[]]$Path,
        [switch]$Passthru
    )
    process {
        foreach ($CurrentPath in $Path) {
            $VHD = Get-VHD -Path $CurrentPath
            Write-Verbose -Message "Path: $($VHD.Path)"
            Write-Verbose -Message "ParentPath: $($VHD.ParentPath)"
            if ($VHD.ParentPath) {
                Write-Verbose -Message "$($VHD.Path) ==> $($VHD.ParentPath)"
                Set-VHD -Path $VHD.Path -ParentPath $VHD.ParentPath -IgnoreIdMismatch -Passthru:$Passthru
                Repair-VMParentDiskChain -Path $VHD.ParentPath
            }
        }
    }
}
#endregion


#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

#Getting Running VMs
$RunningVM = Get-VM | Where-Object -FilterScript { $_.State -eq "Running" }
#Stopping Running VMs
$RunningVM | Stop-VM -Force -AsJob | Receive-Job -Wait -AutoRemoveJob

#Getting Disk Chain
Get-VM | Get-VMHardDiskDrive | Get-VHD | Select-Object -Property Path, ParentPath

#Fixing Disk Chain
Get-VM | Get-VMHardDiskDrive | Get-VHD | Repair-VMParentDiskChain -Passthru -Verbose

#Getting Disk Chain
Get-VM | Get-VMHardDiskDrive | Get-VHD | Select-Object -Property Path, ParentPath


#Restarting Running VMs
$RunningVM | Start-VM -AsJob | Receive-Job -Wait -AutoRemoveJob
#endregion
