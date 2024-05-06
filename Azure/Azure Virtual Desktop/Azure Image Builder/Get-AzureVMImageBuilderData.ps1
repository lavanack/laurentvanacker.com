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
#requires -Version 5 -Modules Az.Accounts, Az.Compute, Az.ImageBuilder, Az.Resources 

#From https://learn.microsoft.com/en-us/azure/virtual-machines/windows/image-builder-vnet#query-the-distribution-properties
#region Function definitions
function Get-AzureImageBuilderStatus {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true)]
		[string]$imageTemplateName,
		[Parameter(Mandatory = $true)]
		[string]$imageResourceGroup
	)

    Write-Verbose "`$imageTemplateName: $imageTemplateName"
    Write-Verbose "`$imageResourceGroup: $imageResourceGroup"
    $azContext = Get-AzContext
    $SubcriptionID = $azContext.Subscription.Id
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
    $token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'  = 'application/json'
        'Authorization' = 'Bearer ' + $token.AccessToken
    }

    $managementEp = $azContext.Environment.ResourceManagerUrl
    $urlBuildStatus = [System.String]::Format("{0}subscriptions/{1}/resourceGroups/$imageResourceGroup/providers/Microsoft.VirtualMachineImages/imageTemplates/{2}?api-version=2020-02-14", $managementEp, $SubcriptionID,$imageTemplateName)
    Write-Verbose "`$urlBuildStatus: $urlBuildStatus"
    try {
        $buildStatusResult  = Invoke-WebRequest -Method GET  -Uri $urlBuildStatus -UseBasicParsing -Headers $authHeader
        $buildJsonStatus = $buildStatusResult.Content
    }
    catch [System.Net.WebException] {   
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        $respStream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($respStream)
        $Response = $reader.ReadToEnd() | ConvertFrom-Json
        if (-not([string]::IsNullOrEmpty($Response.message))) {
            Write-Warning -Message $Response.message
        }
    }
    finally {
        $buildJsonStatus
    }
}

function Get-AzureImageBuilderRunOutput {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true)]
		[string]$imageTemplateName,
		[Parameter(Mandatory = $true)]
		[string]$imageResourceGroup,
		[Parameter(Mandatory = $true)]
		[string]$runOutputName
	)

    Write-Verbose "`$imageTemplateName: $imageTemplateName"
    Write-Verbose "`$imageResourceGroup: $imageResourceGroup"
    Write-Verbose "`$runOutputName: $runOutputName"
    $azContext = Get-AzContext
    $SubcriptionID = $azContext.Subscription.Id
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
    $token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'  = 'application/json'
        'Authorization' = 'Bearer ' + $token.AccessToken
    }

    $managementEp = $azContext.Environment.ResourceManagerUrl
    $urlRunOutputStatus = [System.String]::Format("{0}subscriptions/{1}/resourceGroups/$imageResourceGroup/providers/Microsoft.VirtualMachineImages/imageTemplates/$imageTemplateName/runOutputs/{2}?api-version=2023-07-01", $managementEp, $SubcriptionID, $runOutputName)
    Write-Verbose "`$urlRunOutputStatus: $urlRunOutputStatus"
    try {
        $runOutStatusResult = Invoke-WebRequest -Method GET  -Uri $urlRunOutputStatus -UseBasicParsing -Headers $authHeader
        $runOutJsonStatus =$runOutStatusResult.Content
    }
    catch [System.Net.WebException] {   
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        $respStream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($respStream)
        $Response = $reader.ReadToEnd() | ConvertFrom-Json
        if (-not([string]::IsNullOrEmpty($Response.message))) {
            Write-Warning -Message $Response.message
        }
    }
    finally {
        $runOutJsonStatus
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

#region Defining variables 
$SubscriptionName = "Cloud Solution Architect"
#endregion

#region Login to your Azure subscription.
While (-not((Get-AzContext).Subscription.Name -eq $SubscriptionName)) {
	Connect-AzAccount
	Get-AzSubscription | Out-GridView -OutputMode Single -Title "Select your Azure Subscription" | Select-AzSubscription
	#$Subscription = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction Ignore
	#Select-AzSubscription -SubscriptionName $SubscriptionName | Select-Object -Property *
}
#endregion

foreach ($CurrentAzImageBuilderTemplate in Get-AzImageBuilderTemplate)
{
    Write-Host "Processing '$($CurrentAzImageBuilderTemplate.Name)' ..."
    $AzureImageBuilderStatusJSON = Get-AzureImageBuilderStatus -imageTemplateName $CurrentAzImageBuilderTemplate.Name -imageResourceGroup $CurrentAzImageBuilderTemplate.ResourceGroupName -Verbose
    $AzureImageBuilderStatusJSON
    $AzureImageBuilderStatus = $AzureImageBuilderStatusJSON | ConvertFrom-Json
    if ($AzureImageBuilderStatus.properties.lastRunStatus.runState -ne "running")
    {
        foreach ($CurrentDistribute in $CurrentAzImageBuilderTemplate.Distribute)
        {
            Write-Host "`tProcessing '$($CurrentDistribute.RunOutputName)' ..."
            Get-AzureImageBuilderRunOutput -imageTemplateName $CurrentAzImageBuilderTemplate.Name -imageResourceGroup $CurrentAzImageBuilderTemplate.ResourceGroupName -runOutputName $CurrentDistribute.RunOutputName -Verbose
        }
    }
    else
    {
        Write-Warning -Message "'$($AzureImageBuilderStatus.name)' is running. So no output available ..."
    }
}
#endregion