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
		[Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [string[]]$ResourceGroupName
    )
    begin {
        $SubscriptionId = (Get-AzContext).Subscription.Id
        $SubscriptionScope = "/subscriptions/{0}" -f $SubscriptionId
    }
    process {
        foreach ($CurrentResourceGroupName in $ResourceGroupName)  {
            Write-Verbose -Message "Processing the '$CurrentResourceGroupName' ResourceGroup ..."
            $ResourceGroup = Get-AzResourceGroup -Name $CurrentResourceGroupName -ErrorAction Ignore
            if (($ResourceGroup) -and ($ResourceGroup.ProvisioningState -notmatch "ing$")) {
                $ImageBuilderTemplate = Get-AzImageBuilderTemplate -ResourceGroupName $CurrentResourceGroupName
                $Location = $ResourceGroup.Location

                #region Creating a new User Assigned Identity
                $UserAssignedManagedIdentityName = "aib_{0}" -f $CurrentResourceGroupName
                Write-Verbose -Message "Creating the new the '$UserAssignedManagedIdentityName' User Assigned Identity ..."
                $UserAssignedIdentity = New-AzUserAssignedIdentity -Name $UserAssignedManagedIdentityName -ResourceGroupName $CurrentResourceGroupName -Location $Location

                #region RBAC Owner Role for the User Assigned Identity on the Subscription
                $RoleDefinition = Get-AzRoleDefinition -Name "Owner"
                $Parameters = @{
                    ObjectId           = $UserAssignedIdentity.PrincipalId
                    RoleDefinitionName = $RoleDefinition.Name
                    #Scope              = $ResourceGroup.ResourceId
                    Scope              = $SubscriptionScope
                }
                while (-not(Get-AzRoleAssignment @Parameters)) {
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.ObjectId)' Identity on the '$($Parameters.Scope)' scope"
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
                #endregion


                #Going through each template in the ResourceGroup
                foreach ($CurrentImageBuilderTemplate in $ImageBuilderTemplate) {
                    $CurrentGalleryImageId = $CurrentImageBuilderTemplate.Distribute.GalleryImageId
                    Write-Verbose -Message "Processing the '$CurrentGalleryImageId' Azure Compute Gallery Image ..."
            
                    #region Removing the managed identity from the target VM Image Builder template:
                    foreach ($CurrentUserAssignedIdentityId in $CurrentImageBuilderTemplate.IdentityUserAssignedIdentity.Keys) {
                        Write-Verbose -Message "Processing The '$CurrentUserAssignedIdentityId' User Assigned Identity ..."
                        #From https://learn.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-troubleshoot#solution-1
                        $CmdLine = "az image builder identity remove -g $CurrentResourceGroupName -n $($CurrentImageBuilderTemplate.Name) --user-assigned $CurrentUserAssignedIdentityId --yes"
                        #$CmdLine | Set-Clipboard
                        Write-Verbose -Message "Removing the '$CurrentUserAssignedIdentityId' User Assigned Identity from the '$($CurrentImageBuilderTemplate.Name)' Template ..."
                        Start-Process -FilePath "$env:comspec" -ArgumentList "/c", $CmdLine  -Wait #-WindowStyle Hidden

                        <#
                        # Remove the user-assigned identity
                        $null = $CurrentImageBuilderTemplate.IdentityUserAssignedIdentity.Remove($CurrentUserAssignedIdentityId)

                        # Update the template
                        $CurrentImageBuilderTemplate | Update-AzImageBuilderTemplate
                        #>

                    }
                    #endregion

                    if ($CurrentGalleryImageId -match "^.*/galleries/(?<gallery>.*)/images/(?<image>.*)/versions/(?<version>.*)$") {
                        $CurrentImageName = $Matches['image']
                        $CurrentImageVersion = $Matches['version']
                        $CurrentAzureComputeGalleryName = $Matches['gallery']

                        #Creating (if needed) or Getting the Azure Compute Gallery
                        $CurrentAzureComputeGallery = New-AzGallery -GalleryName $CurrentAzureComputeGalleryName -ResourceGroupName $CurrentResourceGroupName -Location $location

	                    $SrcObjParams = @{
		                    Publisher = 'MicrosoftWindowsDesktop'
		                    Offer     = 'Windows-11'    
		                    Sku       = 'win11-24h2-avd'  
		                    Version   = 'latest'
	                    }

                        #Getting the Azure Image Definition
                        $GalleryImageDefinition = Get-AzGalleryImageDefinition -ResourceGroupName $CurrentResourceGroupName -GalleryName $CurrentAzureComputeGalleryName -Name $CurrentImageName -ErrorAction Ignore
                        if (-not($GalleryImageDefinition)) {
                            $GalleryParams = @{
                                GalleryName       = $CurrentAzureComputeGalleryName
                                ResourceGroupName = $CurrentResourceGroupName
                                Location          = $location
                                Name              = $CurrentImageName
                                OsState           = 'generalized'
                                OsType            = 'Windows'
                                Publisher         = "{0}-repair" -f $SrcObjParams.Publisher
                                Offer             = "{0}-repair" -f $SrcObjParams.Offer
                                Sku               = "{0}-repair" -f $SrcObjParams.Sku
                                HyperVGeneration  = 'V2'
                            }
                            #Creating the Azure Image Definition
                            Write-Verbose -Message "Creating Azure Compute Gallery Image Definition '$CurrentImageName' (From Powershell) ..."
                            $GalleryImageDefinition = New-AzGalleryImageDefinition @GalleryParams
                        }
                        else {
                            Write-Verbose -Message "The Azure Compute Gallery Image Definition '$CurrentImageName' already exists ..."
                        }

                        $TargetRegion = @(@{Name = $Location; ReplicaCount = 1 })
                        $Parameters = @{
                            ResourceGroupName          = $CurrentResourceGroupName
                            GalleryName                = $CurrentAzureComputeGalleryName
                            GalleryImageDefinitionName = $CurrentImageName
                            Name                       = $CurrentImageVersion
                            Location                   = $Location
                            TargetRegion               = $TargetRegion
                            sourceImageId              = $CurrentGalleryImageId
                        }
                        #Creating (if needed) or Getting the new image version
                        $GalleryImageVersion = New-AzGalleryImageVersion @Parameters -ErrorAction Ignore

                        #region Assigning a new identity to the target VM Image Builder template
                        #From https://learn.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-troubleshoot#solution-1
                        
                        $CmdLine = "az image builder identity assign -g $CurrentResourceGroupName -n $($CurrentImageBuilderTemplate.Name) --user-assigned $($UserAssignedIdentity.Id)"
                        #$CmdLine | Set-Clipboard
                        Write-Verbose -Message "Assigning the '$($UserAssignedIdentity.Name)' User Assigned Identity to the '$($CurrentImageBuilderTemplate.Name)' Template ..."
                        Start-Process -FilePath "$env:comspec" -ArgumentList "/c", $CmdLine  -Wait #-WindowStyle Hidden
                        #endregion

                        <#
                        # Assign the user-assigned identity
                        $CurrentImageBuilderTemplate.IdentityUserAssignedIdentity[$UserAssignedIdentity.Id] = @{}

                        # Update the template
                        $CurrentImageBuilderTemplate | Set-AzImageBuilderTemplate-Identity $template.Identity
                        #>
                    }
                }
            }
            else {
                if (-not($ResourceGroup)) {
                    Write-Warning -Message "The '$CurrentResourceGroupName' ResourceGroup doesn't exist"
                } 
                else {
					Write-Warning -Message "The '$CurrentResourceGroupName' is '$($ResourceGroup.ProvisioningState)'"
                }
            }

        }
    }
    end {}
}

function Get-RunspaceState {
    [CmdletBinding()]
    param
    (
        [Parameter(ValueFromPipelineByPropertyName = $true, Mandatory = $true)]
        [Alias('PowerShell')]
        [PowerShell]$PS,

        [Parameter(ValueFromPipelineByPropertyName = $true, Mandatory = $true)]
        [Alias('Handle')]
        # Should be of type [System.Management.Automation.PowerShellAsyncResult]. value returned from BeginInvoke
        [PSObject]$AsyncResult
    )

    Begin {
        # Set the Binding Flags for Reflection to get Non-Public Fields from PowerShell Instance
        $BindingFlags = [System.Reflection.BindingFlags]'static', 'nonpublic', 'instance'
    }
    process {
        # Get Value Runspace Worker Field
        $Worker = $PS.GetType().GetField('worker', $BindingFlags).GetValue($PS)

        # Get the 'CurrentlyRunningPipline' Property for the runspaces worker
        $CurrentlyRunningPipeline = $worker.GetType().GetProperty('CurrentlyRunningPipeline', $BindingFlags).GetValue($Worker)

        # Check Com
        if ($AsyncResult.IsCompleted -and $null -eq $CurrentlyRunningPipeline) {
            $State = 'Completed'
        }
        elseif (-not $AsyncResult.IsCompleted -and $null -ne $CurrentlyRunningPipeline ) {       

            $State = 'Running'
        }
        elseif (-not $AsyncResult.IsCompleted -and $null -eq $CurrentlyRunningPipeline) {
            # The logic here is that pipeline will be cleared when Completed.
            # So if it is Not Completed and there nothing in the Pipeline it has not started yet
            $State = 'NotStarted'
        }
        
        [PSCustomObject]@{
            PipelineRunning = [bool]$CurrentlyRunningPipeline
            State           = $State
            IsCompleted     = $AsyncResult.IsCompleted
            Synchronous     = $AsyncResult.CompletedSynchronously
        }
    }
}

function Repair-AzImageBuilderTemplateWithRunSpace {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        [int] $RunspacePoolSize = $([math]::Max(1, (Get-CimInstance -ClassName Win32_Processor).NumberOfLogicalProcessors / 2)),
		[Parameter(Mandatory = $True)]
        [string[]]$ResourceGroupName
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$RunspacePoolSize: $RunspacePoolSize"

    #[scriptblock] $scriptblock = Get-Content -Path Function:\Repair-AzImageBuilderTemplate
    [scriptblock] $scriptblock = [Scriptblock]::Create(((Get-Content -Path Function:\Repair-AzImageBuilderTemplate) -replace "Write-Verbose\s+(-Message)?\s*", "Write-Output -InputObject "))

    #region RunSpace Management
    $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $RunspacePoolSize)
    $RunspacePool.Open()
    [System.Collections.ArrayList]$RunspaceList = @()

    $OverallStartTime = Get-Date

    Foreach ($CurrentResourceGroupName in $ResourceGroupName) {
        Write-Host -Object "Processing '$CurrentResourceGroupName' VM"
        $PowerShell = [powershell]::Create()
        $PowerShell.RunspacePool = $RunspacePool

        $null = $PowerShell.AddScript($ScriptBlock)
        $null = $PowerShell.AddParameter("ResourceGroupName", $CurrentResourceGroupName)

        Write-Host -Object "Invoking RunSpace for '$CurrentResourceGroupName' ..."
        $null = $RunspaceList.Add([PSCustomObject]@{
                VMName      = $CurrentResourceGroupName.Name
                PowerShell  = $PowerShell
                AsyncResult = $PowerShell.BeginInvoke()
                Result      = $null
            })
    }

    # View available runspaces
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Available Runspaces: $($RunspacePool.GetAvailableRunspaces())"

    # View the list object runspace status
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Runspace Status:`r`n$($RunspaceList.AsyncResult | Out-String)"

    # View the list using the function declared at the top of this file !!!
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Runspace State:`r`n$($RunspaceList | Get-RunspaceState | Out-String)"

    Write-Host -Object "Waiting the overall processing completes ..."

    Foreach ($Instance in $RunspaceList) {
        $Instance.Result = $Instance.PowerShell.Endinvoke($Instance.AsyncResult)
        $Instance.PowerShell.Dispose()
    }
    $RunspacePool.Dispose() 

    $OverallEndTime = Get-Date

    Write-Host -Object "Runspace Results:`r`n$($RunspaceList.Result | Out-String)"

    $TimeSpan = New-TimeSpan -Start $OverallStartTime -End $OverallEndTime
    Write-Host -Object "Overall - Processing Time: $($TimeSpan.ToString())" -ForegroundColor Green
    #endregion
}

function Repair-AzImageBuilderTemplateWithThreadJob {
    [CmdletBinding(PositionalBinding = $false)]    
    param
    (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $false)]
		[Parameter(Mandatory = $True)]
        [string[]]$ResourceGroupName
    )

    begin {
        $OverallStartTime = Get-Date
        $ConvertedVMs = @()
        $Jobs = @()
        $ExportedFunctions = [scriptblock]::Create(@"
            Function Repair-AzImageBuilderTemplate { ${Function:Repair-AzImageBuilderTemplate} }
"@)
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ExportedFunctions:`r`n$($ExportedFunctions | Out-String)"
    }
    process {
        foreach ($CurrentResourceGroupName in $ResourceGroupName) {
            $Job = Start-ThreadJob -ScriptBlock {Repair-AzImageBuilderTemplate -ResourceGroupName $using:CurrentResourceGroupName} -InitializationScript $ExportedFunctions #-StreamingHost $Host
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `Running Job #$($Job.Id) for '$CurrentResourceGroupName' ResourceGroup"
			$Jobs += $Job
        }
    }
    end {
		$ConvertedVMs = $Jobs | Receive-Job -Wait -AutoRemoveJob
        $OverallEndTime = Get-Date
        $TimeSpan = New-TimeSpan -Start $OverallStartTime -End $OverallEndTime
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Overall - Processing Time: $TimeSpan"
        return $ConvertedVMs 
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

<#
$TimeStamp = 1758283049
$ResourceGroupNames = "rg-avd-aib-use2-$TimeStamp"
#>

$ImageBuilderTemplate = Get-AzImageBuilderTemplate | Where-Object -FilterScript {$_.LastRunStatusRunState -notmatch "ing$"}
$ResourceGroupNames = $ImageBuilderTemplate.ResourceGroupName | Select-Object -Unique
$ResourceGroupNames | Repair-AzImageBuilderTemplate -Verbose

#Cleanup
<#
$ImageBuilderTemplate | Remove-AzImageBuilderTemplate -Verbose
$ResourceGroupNames | ForEach-Object -Process { Remove-AzResourceGroup -Name $_ -AsJob -Force -Verbose }
#>

#endregion 
