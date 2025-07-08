#region function definitions
function Repair-VMParentDiskChain {
    [CmdletBinding(PositionalBinding = $false, DefaultParameterSetName = 'Passthru')]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [string[]]$Path,
        [Parameter(ParameterSetName='Passthru')]
        [switch]$Passthru,
        [Parameter(ParameterSetName='Link')]
        [switch]$Link
    )
    begin {
    }
    process {
        foreach ($CurrentPath in $Path) {
            $VHD = Get-VHD -Path $CurrentPath
            Write-Verbose -Message "Path: $($VHD.Path)"
            Write-Verbose -Message "ParentPath: $($VHD.ParentPath)"
            if ($VHD.ParentPath) {
                Write-Verbose -Message "$($VHD.Path) -> $($VHD.ParentPath)"
                Set-VHD -Path $VHD.Path -ParentPath $VHD.ParentPath -IgnoreIdMismatch -Passthru:$Passthru
                if ($Link) {
                    "{0} -> {1}" -f $($VHD.Path), $(Repair-VMParentDiskChain -Path $VHD.ParentPath -Link)
                }
                else {
                    #Recursive call to fix the parent disk
                    Repair-VMParentDiskChain -Path $VHD.ParentPath
                }
                #Recursive call to fix the parent disk
                Repair-VMParentDiskChain -Path $VHD.ParentPath -Passthru:$Passthru
            }
            else {
                if ($Link) {
                    "{0}" -f $($VHD.Path)
                }
            }
        }
    }
    end {
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
Get-VM | Get-VMHardDiskDrive | Get-VHD | Repair-VMParentDiskChain -Link #-Verbose

#Getting Disk Chain
Get-VM | Get-VMHardDiskDrive | Get-VHD | Select-Object -Property Path, ParentPath


#Restarting Running VMs
$RunningVM | Start-VM -AsJob | Receive-Job -Wait -AutoRemoveJob
#endregion
