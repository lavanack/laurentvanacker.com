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
#requires -Version 5 -Modules Az.Accounts, Az.Compute, Az.ImageBuilder, Az.ManagedServiceIdentity, Az.Resources

#region Function definitions
function Repair-AzImageBuilderTemplate {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName
    )

    $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore
    if ($ResourceGroup) {
        $ImageBuilderTemplate = Get-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName
        $Location = $ResourceGroup.Location

        #Going through each template in the ResourceGroup
        foreach ($CurrentImageBuilderTemplate in $ImageBuilderTemplate) {
            $CurrentGalleryImageId = $CurrentImageBuilderTemplate.Distribute.GalleryImageId
            Write-Verbose -Message "Processing the Azure Compute Gallery Image '$CurrentGalleryImageId' ..."

            foreach ($CurrentUserAssignedIdentityId in $CurrentImageBuilderTemplate.IdentityUserAssignedIdentity.Keys) {
                Write-Verbose -Message "Processing The '$CurrentUserAssignedIdentityId' User Assigned Identity ..."
                #From https://learn.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-troubleshoot#solution-1
                #Remove the managed identity from the target VM Image Builder template:
                $CmdLine = "az image builder identity remove -g $ResourceGroupName -n $($CurrentImageBuilderTemplate.Name) --user-assigned $CurrentUserAssignedIdentityId --yes"
                $CmdLine | Set-Clipboard
                Start-Process -FilePath "$env:comspec" -ArgumentList "/c", $CmdLine -Wait
    
                if ($CurrentGalleryImageId -match "^.*/galleries/(?<gallery>.*)/images/(?<image>.*)/versions/(?<version>.*)$") {
                    $CurrentImageName = $Matches['image']
                    $CurrentImageVersion = $Matches['version']
                    $CurrentAzureComputeGalleryName = $Matches['gallery']

                    #Creating (if needed) or Getting the Azure Compute Gallery
                    $CurrentAzureComputeGallery = New-AzGallery -GalleryName $CurrentAzureComputeGalleryName -ResourceGroupName $ResourceGroupName -Location $location

                    #Getting the Azure Image Definition
                    $GalleryImageDefinition = Get-AzGalleryImageDefinition -ResourceGroupName $ResourceGroupName -GalleryName $CurrentAzureComputeGalleryName -Name $CurrentImageName -ErrorAction Ignore
                    if (-not($GalleryImageDefinition)) {
                        $GalleryParams = @{
                            GalleryName       = $CurrentAzureComputeGalleryName
                            ResourceGroupName = $ResourceGroupName
                            Location          = $location
                            Name              = $CurrentImageName
                            OsState           = 'generalized'
                            OsType            = 'Windows'
                            Publisher         = "{0}-json" -f $SrcObjParams.Publisher
                            Offer             = "{0}-json" -f $SrcObjParams.Offer
                            Sku               = "{0}-json" -f $SrcObjParams.Sku
                            HyperVGeneration  = 'V2'
                        }
                        #Creating the Azure Image Definition
                        Write-Verbose -Message "Creating Azure Compute Gallery Image Definition '$CurrentImageName' (From Powershell) ..."
                        $GalleryImageDefinition = New-AzGalleryImageDefinition @GalleryParams
                    }
                    else {
                        Write-Verbose -Message "The Azure Compute Gallery Image Definition '$CurrentImageName' already exists ..."
                    }
                    $GalleryImageDefinition

                    $TargetRegion = @(@{Name = $Location; ReplicaCount = 1 })
                    $Parameters = @{
                        ResourceGroupName          = $ResourceGroupName
                        GalleryName                = $CurrentAzureComputeGalleryName
                        GalleryImageDefinitionName = $CurrentImageName
                        Name                       = $CurrentImageVersion
                        Location                   = $Location
                        TargetRegion               = $TargetRegion
                        sourceImageId              = $CurrentGalleryImageId
                    }
                    #Creating (if needed) or Getting the new image version
                    New-AzGalleryImageVersion @Parameters -ErrorAction Ignore


                    $UserAssignedManagedIdentityName = $CurrentUserAssignedIdentityId -replace ".*/"
                    $UserAssignedIdentity = New-AzUserAssignedIdentity -Name $UserAssignedManagedIdentityName -ResourceGroupName $ResourceGroupName -Location $Location

                    #region RBAC Contributor Role for the User Assigned Identity on Resource Group
                    $RoleDefinition = Get-AzRoleDefinition -Name "Contributor"
                    $Parameters = @{
                        ObjectId           = $UserAssignedIdentity.PrincipalId
                        RoleDefinitionName = $RoleDefinition.Name
                        Scope              = $ResourceGroup.ResourceId
                    }
                    while (-not(Get-AzRoleAssignment @Parameters)) {
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.PrincipalId)' Identity on the '$($Parameters.Scope)' scope"
                        try {
                            $RoleAssignment = New-AzRoleAssignment @Parameters -ErrorAction Stop
                        } 
                        catch {
                            $RoleAssignment = $null
                        }
                        Write-Verbose -Message "`$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
                        Start-Sleep -Seconds 30
                    }
                    #endregion

                    #From https://learn.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-troubleshoot#solution-1
                    #Assign a new identity to the target VM Image Builder template:
                    $CmdLine = "az image builder identity assign -g $ResourceGroupName -n $($CurrentImageBuilderTemplate.Name) --user-assigned $CurrentUserAssignedIdentityId"
                    $CmdLine | Set-Clipboard
                    Start-Process -FilePath "$env:comspec" -ArgumentList "/c", $CmdLine -Wait
                }
            }
        }
    }
    else {
        Write-Warning -Message "The '$ResourceGroupName' ResourceGroup doesn't exist"
    }
}
#endregion 

#region Main code
Clear-Host
$Error.Clear()
$StartTime = Get-Date

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

#region Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount
}
#endregion

$TimeStamp = 1758173928
$ResourceGroupName = "rg-avd-aib-use2-$TimeStamp"

Repair-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Verbose
#endregion 

