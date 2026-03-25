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
#FROM https://github.com/Azure/azvmimagebuilder/tree/main/solutions/14_Building_Images_WVD
function New-AzureComputeGallery {
	[CmdletBinding(PositionalBinding = $false)]
	Param(
		[Parameter(Mandatory = $false)]
		[string]$Location = "EastUS2",
		[Parameter(Mandatory = $false)]
		[string[]]$TargetRegions = @($Location),
		[Parameter(Mandatory = $false)]
		[int]$ReplicaCount = 1,
		[Parameter(Mandatory = $false)]
		[bool] $excludeFromLatest = $true
	)

	#region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
	$AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
	$ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
	$shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
	#endregion

	#region Building an Hashtable to get the shortname of every Azure resource based on a JSON file on the Github repository of the Azure Naming Tool
	$Result = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/refs/heads/main/src/repository/resourcetypes.json 
	$ResourceTypeShortNameHT = $Result | Where-Object -FilterScript { $_.property -in @('', 'Windows') } | Select-Object -Property resource, shortName, lengthMax | Group-Object -Property resource -AsHashTable -AsString
	#endregion

	#region Set up the environment and variables
	# get existing context
	$AzContext = Get-AzContext
	# Your subscription. This command gets your current subscription
	$subscriptionID = $AzContext.Subscription.Id

	#Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
	#$AzureComputeGalleryPrefix = "acg"
	#$ResourceGroupPrefix = "rg"
	$ResourceGroupPrefix = $ResourceTypeShortNameHT["Resources/resourcegroups"].ShortName
	$AzureComputeGalleryPrefix = $ResourceTypeShortNameHT["Compute/galleries"].ShortName

	# Location (see possible locations in the main docs)
	Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Location: $Location"
	$LocationShortName = $shortNameHT[$Location].shortName
	Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$LocationShortName: $LocationShortName"
	if ($Location -notin $TargetRegions) {
		$TargetRegions += $Location
	}
	Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$TargetRegions: $($TargetRegions -join ', ')"
	[array] $TargetRegionSettings = foreach ($CurrentTargetRegion in $TargetRegions) {
		@{"name" = $CurrentTargetRegion; "replicaCount" = $ReplicaCount; "storageAccountType" = "Premium_LRS" }
	}

	$Project = "avd"
	$Role = "aib"
	#Timestamp
	$timeInt = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $ResourceGroupName = "{0}-{1}-{2}-{3}-{4}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $TimeInt 
	$ResourceGroupName = $ResourceGroupName.ToLower()
	Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ResourceGroupName: $ResourceGroupName"


	#region Tags
	if ($MyInvocation.MyCommand.ModuleName) {
		$Module = (Get-Module -Name $MyInvocation.MyCommand.ModuleName).Name
		$Tags = @{
			"SecurityControl" = "Ignore"
			"Module"          = $Module
		}
	} 
	else {
		$Script = $(Split-Path -Path $MyInvocation.ScriptName -Leaf)
		$Tags = @{
			"SecurityControl" = "Ignore"
			"Script"          = $Script
		}
	}
	$Jobs = @()
	#endregion

	#region Create resource group
	$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -Location $location -ErrorAction Ignore
	if ($ResourceGroup) {
		Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$ResourceGroupName' already exists ..."
	}
	else {
		Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$ResourceGroupName' Resource Group Name ..."
		$ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $location -Tag $Tags -Force
	}
	#endregion

	#region RBAC Assignment(s)
	#region User Assigned Identity
	$Scope = $ResourceGroup.ResourceId
	$RoleAssignment = Get-AzRoleAssignment -Scope $Scope | Where-Object -FilterScript { $_.RoleDefinitionName -match "^Azure Image Builder Image Def" }
    
	if ($RoleAssignment) {
		Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$($RoleAssignment.RoleDefinitionName)' Role Definition is already set to '$($RoleAssignment.DisplayName)' on the '$($RoleAssignment.Scope)' scope ..."
		$AssignedIdentity = Get-AzUserAssignedIdentity -ResourceGroupName $($RoleAssignment.Scope -replace ".+/") -Name $($RoleAssignment.DisplayName)
	}
	else {
		#region setup role def names, these need to be unique
		$imageRoleDefName = "Azure Image Builder Image Def - $timeInt"
		$identityName = "aibIdentity-$timeInt"
		Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$imageRoleDefName: $imageRoleDefName"
		Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$identityName: $identityName"
		#endregion

		#region Create the identity
		Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating User Assigned Identity '$identityName' ..."
		$AssignedIdentity = New-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $identityName -Location $location
		#endregion

		#region RBAC Assignment(s)
		#region aibRoleImageCreation.json creation and RBAC Assignment
		#$aibRoleImageCreationUrl="https://raw.githubusercontent.com/PeterR-msft/M365AVDWS/master/Azure%20Image%20Builder/aibRoleImageCreation.json"
		#$aibRoleImageCreationUrl="https://raw.githubusercontent.com/azure/azvmimagebuilder/main/solutions/12_Creating_AIB_Security_Roles/aibRoleImageCreation.json"
		#$aibRoleImageCreationUrl="https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20VM%20Image%20Builder/aibRoleImageCreation.json"
		$aibRoleImageCreationUrl = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20VM%20Image%20Builder/aibRoleImageCreation.json"
		#$aibRoleImageCreationPath = "aibRoleImageCreation.json"
		$aibRoleImageCreationPath = Join-Path -Path $env:TEMP -ChildPath $(Split-Path $aibRoleImageCreationUrl -Leaf)
		#Generate a unique file name 
		$aibRoleImageCreationPath = $aibRoleImageCreationPath -replace ".json$", "_$timeInt.json"
		Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$aibRoleImageCreationPath: $aibRoleImageCreationPath"

		# Download the config
		Invoke-WebRequest -Uri $aibRoleImageCreationUrl -OutFile $aibRoleImageCreationPath -UseBasicParsing

		((Get-Content -Path $aibRoleImageCreationPath -Raw) -replace '<subscriptionID>', $subscriptionID) | Set-Content -Path $aibRoleImageCreationPath
		((Get-Content -Path $aibRoleImageCreationPath -Raw) -replace '<rgName>', $ResourceGroupName) | Set-Content -Path $aibRoleImageCreationPath
		((Get-Content -Path $aibRoleImageCreationPath -Raw) -replace 'Azure Image Builder Service Image Creation Role', $imageRoleDefName) | Set-Content -Path $aibRoleImageCreationPath

		#region Create a role definition
		$RoleDefinition = Get-AzRoleDefinition -Name $imageRoleDefName
		if ($RoleDefinition) {
			Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The '$imageRoleDefName' Role Definition already exists ..."
		}
		else {
			Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$imageRoleDefName' Role Definition ..."
			$RoleDefinition = New-AzRoleDefinition -InputFile $aibRoleImageCreationPath
		}
		#endregion

		# Grant the role definition to the VM Image Builder service principal
		<#
        if (-not(Get-AzRoleAssignment -ObjectId $AssignedIdentity.PrincipalId -RoleDefinitionName $RoleDefinition.Name -Scope $Scope)) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($RoleDefinition.Name)' RBAC role to the '$($AssignedIdentity.PrincipalId)' User Assigned Managed Identity"
            $RoleAssignment = New-AzRoleAssignment -ObjectId $AssignedIdentity.PrincipalId -RoleDefinitionName $RoleDefinition.Name -Scope $Scope
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
        } else {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The '$($RoleDefinition.Name)' RBAC role is already assigned to the '$($AssignedIdentity.PrincipalId)' User Assigned Managed Identity"
        } 
        #> 
		$Parameters = @{
			ObjectId           = $AssignedIdentity.PrincipalId
			RoleDefinitionName = $RoleDefinition.Name
			Scope              = $Scope
		}

		While (-not(Get-AzRoleAssignment @Parameters)) {
			Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.ObjectId)' User Assigned Managed Identity on the '$($Parameters.Scope)' scope"
			try {
				$RoleAssignment = New-AzRoleAssignment @Parameters -ErrorAction Stop
			} 
			catch {
				$RoleAssignment = $null
			}
			Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
			if ($null -eq $RoleAssignment) {
				Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
				Start-Sleep -Seconds 30
			}
		}
		#endregion
		#endregion
        
	}
	#endregion

	#endregion

	#region Azure Compute Gallery
	#region Create an Azure Compute Gallery
	$GalleryName = "{0}_{1}_{2}_{3}" -f $AzureComputeGalleryPrefix, $Project, $LocationShortName, $timeInt
	Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$GalleryName: $GalleryName"

	# Create the gallery
	$Parameters = @{
		GalleryName       = $GalleryName 
		ResourceGroupName = $ResourceGroupName 
	}
	$Gallery = Get-AzGallery @Parameters -ErrorAction Ignore
	if ($Gallery) {
		Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The '$GalleryName' Azure Compute Gallery already exists (ResourceGroup: '$($Parameters.ResourceGroupName)'..."
	}
	else {
		Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating Azure Compute Gallery '$GalleryName' (ResourceGroup: '$($Parameters.ResourceGroupName)' ..."
		$Gallery = New-AzGallery @Parameters -Location $location
	}
	#endregion
	#endregion

	return $Gallery
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


#region To use Azure Image Builder, you have to register for the providers and to ensure that RegistrationState will be set to Registered.
$RequiredResourceProviders = 'Microsoft.VirtualMachineImages', 'Microsoft.Storage', 'Microsoft.Compute', 'Microsoft.KeyVault', 'Microsoft.ManagedIdentity', 'Microsoft.Network', 'Microsoft.ContainerInstance'
$Jobs = foreach ($CurrentRequiredResourceProvider in $RequiredResourceProviders) {
	Register-AzResourceProvider -ProviderNamespace $CurrentRequiredResourceProvider -AsJob
}
#Important: Wait until RegistrationState is set to Registered. 
While (Get-AzResourceProvider -ProviderNamespace $RequiredResourceProviders | Where-Object -FilterScript { $_.RegistrationState -ne 'Registered' }) {
	Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 10 seconds ..."
	Start-Sleep -Seconds 10
}
$Jobs | Remove-Job -Force
#endregion
$AzureComputeGallery = New-AzureComputeGallery -Location EastUS2 -TargetRegions EastUS2, CentralUS -Verbose
$AzureComputeGallery

$EndTime = Get-Date
$TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
Write-Host -Object "Total Processing Time: $($TimeSpan.ToString())"

#Remove-AzResourceGroup -Name $AzureComputeGallery.ResourceGroupName -Force -AsJob
#endregion