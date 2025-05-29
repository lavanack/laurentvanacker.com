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
#requires -Version 5 -Modules Az.Accounts, Az.Compute, Az.Resources

#region function definitions 
#From https://learn.microsoft.com/en-us/azure/virtual-machines/move-virtual-machines-regional-zonal-powershell?tabs=PowerShell
#From https://4sysops.com/archives/move-resources-with-azure-resource-mover-using-powershell/
function Move-AzResource {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [Alias("ResourceGroupName")]
        [string] $SourceResourceGroupName,
        [Parameter(Mandatory = $true)]
        [ValidateSet(1, 2, 3)]
        [Alias("AvailabilityZone")]
        [string] $TargetAvailabilityZone
    )

    #region Registering provider
    $null = Register-AzResourceProvider -ProviderNamespace Microsoft.Migrate
    While (((Get-AzResourceProvider -ProviderNamespace Microsoft.Migrate) | Where-Object -FilterScript { ($_.RegistrationState -eq "Registered") -and ($_.ResourceTypes.ResourceTypeName -eq "moveCollections") } | Measure-Object).Count -eq 0) {
        Start-Sleep -Seconds 5
        Write-Host "Waiting for registration to complete."
    }
    #endregion

    $SourceResourceGroup = Get-AzResourceGroup -ResourceGroupName $SourceResourceGroupName
    $MoveCollectionName = "RegionToZone-$SourceResourceGroupName"
    
    #Removing any existing MoveCollection with same Name and ResourceGroupName
    if (Get-AzResourceMoverMoveCollection -Name $MoveCollectionName -ResourceGroupName $SourceResourceGroupName -ErrorAction Ignore) {
        $Result = Remove-AzResourceMoverMoveCollection -Name $MoveCollectionName -ResourceGroupName $SourceResourceGroupName -PassThru
        if ($Result) {
            Write-Verbose -Message "$MoveCollectionName MoveCollection (ResourceGroupName: '$SourceResourceGroupName') successfully removed ..."
        }
        else {
            Write-Warning -Message "Unable to remove $MoveCollectionName MoveCollection (ResourceGroupName: '$SourceResourceGroupName') ..."
        }
    }
    #Creating a MoveCollection object
    $MoveCollection = New-AzResourceMoverMoveCollection -Name $MoveCollectionName -ResourceGroupName $SourceResourceGroupName -MoveRegion $SourceResourceGroup.Location -Location $SourceResourceGroup.Location -IdentityType "SystemAssigned" -MoveType "RegionToZone"

    $IdentityPrincipalId = $MoveCollection.IdentityPrincipalId
    $SubcriptionId = (Get-AzContext).Subscription.Id
    $Scope = "/subscriptions/$SubcriptionId"

    #region RBAC Role Assignment 
    #Granting access to the managed identity  

    $RBACRole = Get-AzRoleDefinition "Contributor"
    While (-not(Get-AzRoleAssignment -ObjectId $identityPrincipalId -RoleDefinitionName $RBACRole.Name -Scope $Scope)) {
        Write-Verbose -Message "Assigning the '$($RBACRole.Name)' RBAC role to the '$identityPrincipalId' identity on the '$($Scope)' Subcription"
        $null = New-AzRoleAssignment -ObjectId $identityPrincipalId -RoleDefinitionName $RBACRole.Name -Scope $Scope
        Write-Verbose -Message "Sleeping 30 seconds"
        Start-Sleep -Seconds 30
    }
    $RBACRole = Get-AzRoleDefinition "User Access Administrator"
    While (-not(Get-AzRoleAssignment -ObjectId $identityPrincipalId -RoleDefinitionName $RBACRole.Name -Scope $Scope)) {
        Write-Verbose -Message "Assigning the '$($RBACRole.Name)' RBAC role to the '$identityPrincipalId' identity on the '$($Scope)' Subcription"
        $null = New-AzRoleAssignment -ObjectId $identityPrincipalId -RoleDefinitionName $RBACRole.Name -Scope $Scope
        Write-Verbose -Message "Sleeping 30 seconds"
        Start-Sleep -Seconds 30
    }
    #endregion

    $SourceId = "/subscriptions/$SubcriptionId/resourcegroups/$SourceResourceGroupName/providers/Microsoft.Compute/virtualMachines/RegionToZone-demoSourceVm"
    #$MoveResourceName = "MoveResource-$SourceResourceGroupName"
    
    #Adding regional VMs to the move collection
    $SourceVMs = Get-AzVM -ResourceGroupName $SourceResourceGroupName
    $MoveResource = foreach ($CurrentSourceVM in $SourceVMs) {
        Write-Host -Object "Processing the '$($CurrentSourceVM.Name)' VM (ResourceGroupName: '$SourceResourceGroupName') ..."

        #region Creating target resource setting object 
        $TargetResourceSettings = New-Object Microsoft.Azure.PowerShell.Cmdlets.ResourceMover.Models.Api20230801.VirtualMachineResourceSettings
        $TargetResourceSettings.ResourceType = $CurrentSourceVM.Type
        #$TargetResourceSettings.TargetResourceGroupName = $SourceResourceGroupName		
        $TargetResourceSettings.TargetResourceName = "{0}" -f $CurrentSourceVM.Name
        $TargetResourceSettings.TargetAvailabilityZone = $TargetAvailabilityZone
        #endregion

        $MoveResourceName = "MoveResource-{0}" -f $CurrentSourceVM.Name

        try {
            Add-AzResourceMoverMoveResource -ResourceGroupName $SourceResourceGroupName -MoveCollectionName $MoveCollectionName -SourceId $CurrentSourceVM.Id -Name $MoveResourceName -ResourceSetting $TargetResourceSettings -ErrorAction Stop
        }
        catch {
            Write-Warning "Unable to add the '$($CurrentSourceVM.Name)' VM (ResourceGroupName: '$SourceResourceGroupName') to the Resource Mover"
            $_
        }
    }

    if ($MoveResource) {
        Write-Verbose -Message "`$MoveResource:`r`n$($MoveResource | Out-String)"
        #Resolving dependencies
        Write-Host -Object "Resolving dependencies ..."
        $Resolve = Resolve-AzResourceMoverMoveCollectionDependency -ResourceGroupName $SourceResourceGroupName -MoveCollectionName $MoveCollectionName
        Write-Verbose -Message "`$Resolve:`r`n$($Resolve | Out-String)"

        #Retrieving a list of all missing dependencies:
        $UnresolvedDependency = Get-AzResourceMoverUnresolvedDependency -ResourceGroupName $SourceResourceGroupName -MoveCollectionName $MoveCollectionName -DependencyLevel Descendant
        Write-Verbose -Message "`$UnresolvedDependency:`r`n$($UnresolvedDependency | Out-String)"

        if ($Resolve.Status -eq "Succeeded") {
            #Getting a list of resources added to the move collection:
            $List = Get-AzResourceMoverMoveResource -ResourceGroupName $SourceResourceGroupName -MoveCollectionName $MoveCollectionName
            Write-Verbose -Message "List of resources added to the move collection:`r`n$($List | Out-String)"

            #Validating the dependencies before Initiate Move for the resources.
            $Validate = Invoke-AzResourceMoverInitiateMove -ResourceGroupName $SourceResourceGroupName -MoveCollectionName $MoveCollectionName -MoveResource $MoveResource.Name -MoveResourceInputType "MoveResourceId" -ValidateOnly
            Write-Verbose -Message "`$Validate:`r`n$($Validate | Out-String)"
            if ($Validate.Status -eq "Succeeded") {
                Write-Host -Object "Move Validation Completed !"
                try {
                    #Initiating move of VM resources
                    Write-Host -Object "Initiating the move ..."
                    $MoveStatus = Invoke-AzResourceMoverInitiateMove -ResourceGroupName $SourceResourceGroupName -MoveCollectionName $MoveCollectionName -MoveResource $MoveResource.Name -MoveResourceInputType "MoveResourceId" -ErrorAction Stop
                    Write-Verbose -Message "`$MoveStatus:`r`n$($MoveStatus | Out-String)"
                    #Committing
                    Write-Verbose -Message "Completing the move ..."
                    $CommitStatus = Invoke-AzResourceMoverCommit -ResourceGroupName $SourceResourceGroupName -MoveCollectionName $MoveCollectionName -MoveResource $MoveResource.Name
                    Write-Verbose -Message "`$CommitStatus:`r`n$($CommitStatus | Out-String)"
                }
                catch {
                    Write-Error -Message $($_.ErrorDetails.Message) -ErrorAction Stop
                }
                Write-Host -Object "Move Completed !"
            }
            else {
                Write-Error -Message "Unable to validate the dependencies before Initiate Move for the resources."
            }

        }
        else {
            Write-Error -Message "Unable to to Compute, resolve and validate the dependencies of the moveResources in the move collection."
        }

    }
    else {
        Write-Warning "No Azure VM to move"
    }
}
#endregion 

#region Main Cpode
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

#$SourceResourceGroupName = (Get-AzResourceGroup -ResourceGroupName "rg-al-hypv*" | Where-Object { $_.ResourceGroupName -notmatch "744$"}).ResourceGroupName
#Excluding RG already processed for a move (ie. having a duplicate RG with a name ending with -<location>)
$SourceResourceGroupName = (Get-AzResourceGroup -ResourceGroupName "rg-vm-rand-*" | Where-Object -FilterScript {$_.ProvisioningState -eq "Succeeded" } | Select-Object -Property ResourceGroupName, @{Name="Prefix"; Expression = {$_.ResourceGroupName -replace "(rg-.*-\d+)-.*$", '$1'}} | Group-Object -Property Prefix -NoElement | Where-Object -FilterScript { $_.Count -eq 1 } | Get-Random).Name
if ($SourceResourceGroupName) {
    Write-Host -Object "ResourceGroupName: $SourceResourceGroupName"
    Move-AzResource -SourceResourceGroupName $SourceResourceGroupName -TargetAvailabilityZone 3 -Verbose
} else {
    Write-Warning -Message "No Resource Group available"
}
#endregion 