<#
This Sample Code is provided for the purpose of illustration only
and is not intended to be used in a production environment.  THIS
SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
# WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
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

#requires -Version 5 #-Modules Az.Accounts, Az.Compute, Az.Resources, Az.StackHCI
[CmdletBinding(PositionalBinding = $false)]
param
(
)

#region Function Definitions
function Get-AzStackHciClusterVM {
[CmdletBinding(PositionalBinding = $false)]
param
(
    [Parameter(Mandatory=$true)]
    [string] $ResourceGroupName
)

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    $subscriptionId = (Get-AzContext).Subscription.Id

    # All the Arc machines of the RG
    $response = Invoke-AzRestMethod -Method GET -Path "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.HybridCompute/machines?api-version=2026-07-15"

    $machines = ($response.Content | ConvertFrom-Json).value
    $vms = foreach ($machine in $machines) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$machine : $machine'"
        $path = "$($machine.id)/providers/Microsoft.AzureStackHCI/virtualMachineInstances?api-version=2024-01-01"

        try {
            $response = Invoke-AzRestMethod -Method GET -Path $path
            $instances = ($response.Content | ConvertFrom-Json).value
            foreach ($instance in $instances) {
                [PSCustomObject]@{
                    Name               = $machine.name
                    LocalVMName        = $instance.properties.localVmName
                    ResourceGroupName  = ($machine.id -split '/')[4]
                    Location           = $machine.location
                    CustomLocation     = $instance.extendedLocation.name
                    ProvisioningState  = $instance.properties.provisioningState
                    MachineId          = $machine.id
                    VMInstanceId       = $instance.id
                }
            }
        }
        catch {
            # This is an Arc-enabled machine, but not necessarily an Azure Local VM.
        }
    }

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $vms
}

function Set-AzVMEntraIDJoin {
[CmdletBinding(PositionalBinding = $false)]
    param
    (
		[Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $false)]
        [PSCustomObject[]] $VM
    )

    begin {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
        $settings = @{
            # IMPORTANT: must be present even empty
            mdmId = ""   
        }
    }
    process {
        foreach ($CurrentVM in $VM) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing '$($CurrentVM.Name)' ..."
            #region checking we have at least the "Name", "Location", "ResourceGroupName" members
            $DifferenceObject = ($CurrentVM.Psobject.Members | Where-Object -FilterScript { $_.MemberType -eq "NoteProperty"}).Name
            $ReferenceObject = "Name", "Location", "ResourceGroupName"
            $Succeeded = ((Compare-Object -ReferenceObject $ReferenceObject -DifferenceObject $DifferenceObject).SideIndicator | Select-Object -Unique) -eq "=>"
            if (-not($Succeeded)) {
                Write-Warning -Message "The following object doesn't have the Name, Location, ResourceGroupName members (We skip it):`r`n$($DifferenceObject | Out-String)"
                continue
            }
            #endregion

            #Connecting
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Registering '($CurrentVM.Name)' into EntraID ..."
            $Parameters = @{
                Name = "aadlogin"
                ResourceGroupName = $VM.ResourceGroupName
                MachineName = $VM.Name
                Location = $VM.Location
                Publisher = "Microsoft.Azure.ActiveDirectory" 
                ExtensionType = "AADLoginForWindows" 
                Settings = $settings
            }
            New-AzConnectedMachineExtension @Parameters

            <#
            #Checking
            $Parameters = @{
                Name = "aadlogin"
                ResourceGroupName = $VM.ResourceGroupName
                MachineName = $VM.Name
            }
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Checking '($CurrentVM.Name)' EntraID Registration ..."
            Get-AzConnectedMachineExtension @Parameters           
            #>
        }
    }
    end{
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    }

}
#endregion

#region Main code
Clear-Host
$Error.Clear()
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir
$ResourceGroupName = "rg-az-local-*"
$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName
if ($ResourceGroup) {
    if ($ResourceGroup.count -gt 1) {
        $ResourceGroup = $ResourceGroup | Out-GridView -OutputMode Single
    }
}

<#
$ClusterName = "localboxcluster"
#$Cluster = Get-AzResource -ResourceType "microsoft.azurestackhci/clusters"
$Cluster = Get-AzStackHciCluster -ResourceGroupName $ResourceGroupName -Name $ClusterName
if ($Cluster.count -gt 1) {
    $Cluster = $Cluster | Out-GridView -OutputMode Single
}
#>


$StackHciClusterVMs = Get-AzStackHciClusterVM -ResourceGroupName $ResourceGroup.ResourceGroupName -Verbose
$StackHciClusterVMs | Set-AzVMEntraIDJoin -Verbose
