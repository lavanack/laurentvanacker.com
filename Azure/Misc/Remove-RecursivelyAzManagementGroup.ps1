#Better alternative : https://github.com/jtracey93/PublicScripts/tree/master/Azure/PowerShell/Enterprise-scale
#.\Wipe-ESLZAzTenant.ps1 -tenantRootGroupID "fd91810c-57b4-43e3-b513-c2a81e8d6a27" -intermediateRootGroupID "lavanack" -resetMdfcTierOnSubs:$true

Clear-Host

#region Variables definitions
$ResourcePrefix = "lavanack"
$SubscriptionPrefix = "alz-Laurent-VAN-ACKER"

$TenantRootGroupId = (Get-AzManagementGroup | Where-Object -FilterScript {$_.DisplayName -eq 'Tenant Root Group'}).Name
$MySubscriptions = Get-AzSubscription | Where-Object -FilterScript {$_.Name -match "^$($SubscriptionPrefix)"}
#endregion

#region Move all my subscriptions to the 'Tenant Root Group'
$MySubscriptions | ForEach-Object -Process { 
	New-AzManagementGroupSubscription -GroupId $TenantRootGroupId -SubscriptionId $_.Id -Verbose
}
#endregion 

#region Remove My Resource Groups
$MySubscriptions | ForEach-Object -Process { 
	$null = Set-AzContext -Subscription $_
    #Get-AzResourceGroup | Where-Object -FilterScript {$_.ResourceGroupName -match "^$($ResourcePrefix)"} | Remove-AzResourceGroup -Force -Verbose -WhatIf
    Get-AzResourceGroup | Remove-AzResourceGroup -Force -Verbose -WhatIf
}

$Jobs = $MySubscriptions | ForEach-Object -Process { 
	$null = Set-AzContext -Subscription $_
    #Get-AzResourceGroup | Where-Object -FilterScript {$_.ResourceGroupName -match "^$($ResourcePrefix)"} | Remove-AzResourceGroup -Force -Verbose -AsJob
    Get-AzResourceGroup | Remove-AzResourceGroup -Force -Verbose -AsJob
}
#endregion

#REGION Remove My Management Group Tree
function Remove-RecursivelyAzManagementGroup
{
	[CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$GroupName
    )
    Write-Verbose "Processing $GroupName ..."
    $AzManagementGroup = (Get-AzManagementGroup -GroupName $GroupName -Expand -Recurse -ErrorAction Ignore -Verbose)
    foreach($Child in $AzManagementGroup.Children)
    {
        if ($Child.Children)
        {
            Write-Verbose "Processing Child $($Child.Name) ..."
            Remove-RecursivelyAzManagementGroup -GroupName $Child.Name
        }
        else
        {
            If ($pscmdlet.ShouldProcess($Child.Name, 'Removing'))
            {
                Write-Verbose "Removing $($Child.Name) ..."
                Remove-AzManagementGroup -GroupName $($Child.Name) #-WhatIf
            }
        }
    }
    if ($AzManagementGroup)
    {
        If ($pscmdlet.ShouldProcess($AzManagementGroup.Name, 'Removing'))
        {
            Write-Verbose "Removing $($AzManagementGroup.Name) ..."
            Remove-AzManagementGroup -GroupName $AzManagementGroup.Name #-WhatIf    
        }
    }
}
Remove-RecursivelyAzManagementGroup -GroupName $ResourcePrefix -WhatIf -Verbose
#endregion

$Jobs | Wait-Job
