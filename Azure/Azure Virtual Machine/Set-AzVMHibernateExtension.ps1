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
attorneys' fees, th
at arise or result from the use or distribution
of the Sample Code.
#>

#requires -Version 5 -Modules Az.Accounts, Az.Compute

function Set-AzVMHibernateExtension {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $false)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachineList[]] $CurrentVM
    )
    begin {}
    process {
        $RunningVMs = @()
        foreach ($CurrentVM in $CurrentVM) {
            Write-Verbose -Message "Processing '$($CurrentVM.Name)' Azure VM"
            if (($CurrentVM | Get-AzVMExtension).ExtensionType -notcontains "WindowsHibernateExtension") {

                if ($CurrentVM.Priority -eq "Spot") {
                    Write-Warning -Message "The '$($CurrentVM.Name)' is a Spot Azure VM. Skipping it. Hibernation capability is not supported for Spot VMs. For more information, see https://aka.ms/hibernate-resume/errors."
                }
                else {
                    Write-Verbose -Message "The 'WindowsHibernateExtension' extension is NOT installed on the '$($CurrentVM.Name)' Azure VM"
                    #From https://learn.microsoft.com/en-us/azure/virtual-machines/windows/hibernate-resume-windows?tabs=enableWithPortal%2CenableWithPSExisting%2CPortalDoHiber%2CPortalStatCheck%2CPortalStartHiber%2CPortalImageGallery#enabling-hibernation-on-an-existing-windows-vm
                    #region Stopping the VM
                    if ((($CurrentVM | Get-AzVM -Status).Statuses | Where-Object -FilterScript { $_.code -eq "PowerState/running" }).DisplayStatus -eq "VM running") {
                        Write-Warning -Message "The '$($CurrentVM.Name)' Azure VM is running. Stopping it. The script will continue when the VM will be stopped. (The VM will be restarted at the end of the script)"
                        $null = $CurrentVM | Stop-AzVM -Force
                        $RunningVMs += $CurrentVM
                    }
                    #endregion 

                    #From https://learn.microsoft.com/en-us/azure/virtual-machines/windows/hibernate-resume-windows?tabs=enableWithPortal%2CenableWithPSExisting%2CPortalDoHiber%2CPortalStatCheck%2CPortalStartHiber%2CPortalImageGallery#enabling-hibernation-on-an-existing-windows-vm
                    #region Updating OS Disk
                    Write-Verbose -Message "Updating the OS disk of the '$($CurrentVM.Name)' Azure VM"
                    $CurrentVMOSDisk = ($CurrentVM | Get-AzVM).StorageProfile.OSDisk | Get-AzDisk
                    $CurrentVMOSDisk.SupportsHibernation = $True
                    $null = $CurrentVMOSDisk | Update-AzDisk
                    #endregion

                    #region Enabling hibernation on the VM
                    Write-Verbose -Message "Updating the '$($CurrentVM.Name)' Azure VM"
                    $null = $CurrentVM | Update-AzVM -HibernationEnabled
                    #endregion
                }
            }
            else {
                Write-Verbose -Message "The 'WindowsHibernateExtension' extension is already installed on the '$($CurrentVM.Name)' Azure VM. Skipping it"
            }
        }
        #region Restarting the VMs (if started at the beginning of the script)
        foreach ($CurrentRunningVM in $RunningVMs) {
            Write-Warning -Message "The '$($CurrentRunningVM.Name)' Azure VM was running at the beginning of the script. Restarting it (Compute Costs will apply !)."
            $null = $CurrentRunningVM | Start-AzVM -NoWait
        }
        #endregion
    }
    end {}
}

Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

$CurrentVM = Get-AzVM
$CurrentVM | Set-AzVMHibernateExtension -Verbose
