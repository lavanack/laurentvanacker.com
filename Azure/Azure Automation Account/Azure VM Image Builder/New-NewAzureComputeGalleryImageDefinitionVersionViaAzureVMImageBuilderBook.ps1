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
#requires -Version 5 -Modules Az.Automation, Az.Resources

#From https://luke.geek.nz/azure/turn-on-a-azure-virtual-machine-using-azure-automation/
[CmdletBinding()]
param
(
)


#region function definitions 
#From https://learn.microsoft.com/en-us/rest/api/automation/runbook/get-content?view=rest-automation-2023-11-01&tabs=HTTP
function Get-AzAPIAutomationRunbookDefinition {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$AutomationAccountName,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$RunbookName
    )
    #region Azure Context
    # Log in first with Connect-AzAccount if not using Cloud Shell

    $azContext = Get-AzContext
    $SubcriptionID = $azContext.Subscription.Id
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
    $token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'  = 'application/json'
        'Authorization' = 'Bearer ' + $token.AccessToken
    }
    #endregion

    $URI = "https://management.azure.com/subscriptions/$SubcriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/runbooks/$RunbookName/content?api-version=2023-11-01"
    try {
        # Invoke the REST API
        $Response = Invoke-RestMethod -Method GET -Headers $authHeader -ContentType "application/json" -Uri $URI -ErrorVariable ResponseError
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
    }
    return $Response
}

#From https://learn.microsoft.com/en-us/rest/api/automation/runbook/get?view=rest-automation-2023-11-01&tabs=HTTP
function Get-AzAPIAutomationRunbook {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$AutomationAccountName,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$RunbookName
    )
    #region Azure Context
    # Log in first with Connect-AzAccount if not using Cloud Shell

    $azContext = Get-AzContext
    $SubcriptionID = $azContext.Subscription.Id
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
    $token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'  = 'application/json'
        'Authorization' = 'Bearer ' + $token.AccessToken
    }
    #endregion

    $URI = "https://management.azure.com/subscriptions/$SubcriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/runbooks/$($RunbookName)?api-version=2023-11-01"
    try {
        # Invoke the REST API
        $Response = Invoke-RestMethod -Method GET -Headers $authHeader -ContentType "application/json" -Uri $URI -ErrorVariable ResponseError
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
    }
    return $Response
}

#From https://learn.microsoft.com/en-us/rest/api/automation/runbook/create-or-update?view=rest-automation-2023-11-01&tabs=HTTP#create-or-update-runbook-and-publish-it
function New-AzAPIAutomationPowerShellRunbook {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$AutomationAccountName,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$RunbookName,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$Location,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$RunBookPowerShellScriptURI,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$Description
    )
    #region Azure Context
    # Log in first with Connect-AzAccount if not using Cloud Shell

    $azContext = Get-AzContext
    $SubcriptionID = $azContext.Subscription.Id
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
    $token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'  = 'application/json'
        'Authorization' = 'Bearer ' + $token.AccessToken
    }
    #endregion

    $wc = [System.Net.WebClient]::new()
    $ContentHash = Get-FileHash -InputStream ($wc.OpenRead($RunBookPowerShellScriptURI)) -Algorithm SHA256

    $Body = [ordered]@{ 
        properties = [ordered]@{
            description        = $Description
            logVerbose         = $false
            logProgress        = $false
            logActivityTrace   = 0
            runbookType        = "PowerShell"
            publishContentLink = @{
                uri         = $RunBookPowerShellScriptURI
                contentHash = [ordered]@{
                    "algorithm" = $ContentHash.Algorithm
                    "value"     = $ContentHash.Hash
                }
            }
        }
        name       = $RunbookName
        location   = $Location
    }

    $URI = "https://management.azure.com/subscriptions/$SubcriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/runbooks/$($RunbookName)?api-version=2023-11-01"
    try {
        # Invoke the REST API
        $Response = Invoke-RestMethod -Method PUT -Headers $authHeader -Body $($Body | ConvertTo-Json -Depth 100) -ContentType "application/json" -Uri $URI -ErrorVariable ResponseError
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
    }
    return $Response
}
#endregion

Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

#region Defining variables 
#region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
$AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
$ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
$shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
#endregion

#region Building an Hashtable to get the shortname of every Azure resource based on a JSON file on the Github repository of the Azure Naming Tool
$Result = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/refs/heads/main/src/repository/resourcetypes.json 
$ResourceTypeShortNameHT = $Result | Where-Object -FilterScript { $_.property -notin @('Linux') } | Select-Object -Property resource, shortName, property, lengthMax | Group-Object -Property resource -AsHashTable -AsString
#endregion


# Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount
    Get-AzSubscription | Out-GridView -OutputMode Single -Title "Select your Azure Subscription" | Select-AzSubscription
    #$Subscription = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction Ignore
    #Select-AzSubscription -SubscriptionName $SubscriptionName | Select-Object -Property *
}


$Location = "EastUS2"
$LocationShortName = $shortNameHT[$Location].shortName
#Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
$AzureVMNameMaxLength = $ResourceTypeShortNameHT["Compute/virtualMachines"].lengthMax
$LocationShortName = $shortNameHT[$Location].shortName
#Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
$ResourceGroupPrefix = $ResourceTypeShortNameHT["Resources/resourcegroups"].ShortName
$VirtualMachinePrefix = $ResourceTypeShortNameHT["Compute/virtualMachines"].lengthMax
$RunBookPrefix = $ResourceTypeShortNameHT["Automation/automationAccounts/runbooks"].ShortName
$AutomationAccountPrefix = $ResourceTypeShortNameHT["Automation/automationAccounts"].ShortName

$Project = "auto"
$Role = "acg"
$DigitNumber = $AzureVMNameMaxLength - ($VirtualMachinePrefix + $Project + $Role + $LocationShortName).Length
#$DigitNumber = 3
$Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))


$ResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
$AutomationAccountName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $AutomationAccountPrefix, $Project, $Role, $LocationShortName, $Instance                       
$SubscriptionId = $((Get-AzContext).Subscription.Id)
$TimeStamp = Get-Date -Format 'yyyyMMddHHmmss'
#endregion

#region Resource Group and AutomationAccount Setup
$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
if ($ResourceGroup) {
    #Remove previously existing Azure Resource Group with the same name
    $ResourceGroup | Remove-AzResourceGroup -Force
}
Write-Verbose "`$ResourceGroupName: $ResourceGroupName"
Write-Verbose "`$AutomationAccountName: $AutomationAccountName"

#Create Azure Resource Group
# Create Resource Groups
$ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
$AutomationAccount = New-AzAutomationAccount -Name $AutomationAccountName -Location $Location -ResourceGroupName $ResourceGroupName -AssignSystemIdentity
#endregion

#region New-StartAzureVirtualMachineRunBook
#region Schedule Setup
#region Azure Virtual Machine - Daily Start
$TimeZone = ([System.TimeZoneInfo]::Local).Id
$StartTime = Get-Date "00:00:00"
if ($(Get-Date) -gt $StartTime) {
    $StartTime = $StartTime.AddDays(1)
}
$Schedule = New-AzAutomationSchedule -AutomationAccountName $AutomationAccount.AutomationAccountName -Name "Azure Virtual Machine - Montly Start - 2nd Wednesday of the Month" -StartTime $StartTime -MonthInterval 1 -DayOfWeek "Wednesday" -DayOfWeekOccurrence "Second" -ResourceGroupName $ResourceGroupName  -TimeZone $TimeZone
#endregion 
#endregion

#region RunBook Setup
$RunBookName = "{0}-NewAzureComputeGalleryImageDefinitionVersionViaAzureVMImageBuilder" -f $RunBookPrefix
#$Runbook = New-AzAutomationRunbook -AutomationAccountName $AutomationAccount.AutomationAccountName -Name $RunBookName -ResourceGroupName $ResourceGroupName -Type PowerShell
# Publish the runbook
#Publish-AzAutomationRunbook -AutomationAccountName $AutomationAccount.AutomationAccountName -Name $RunBookName -ResourceGroupName $ResourceGroupName
#endregion 

$Runbook = New-AzAPIAutomationPowerShellRunbook -AutomationAccountName $AutomationAccount.AutomationAccountName -runbookName $RunBookName -ResourceGroupName $ResourceGroupName -Location $Location -RunBookPowerShellScriptURI "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/refs/heads/master/Azure/Azure%20Automation%20Account/Azure%20VM%20Image%20Builder/NewAzureComputeGalleryImageDefinitionVersionViaAzureVMImageBuilder.ps1" -Description "PowerShell Azure Automation Runbook for Generating an Azure Compute Gallery Image Definition Version Via Azure VM Image Builder" 
#endregion 

#region Parameters

#region Azurecompute Gallery Resource Group Setup
$timeInt = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$GalleryResourceGroupName = "{0}-avd-aib-{1}-{2}" -f $ResourceGroupPrefix, $LocationShortName, $TimeInt 
$GalleryResourceGroup = Get-AzResourceGroup -Name $GalleryResourceGroupName -ErrorAction Ignore 
if (-not($GalleryResourceGroup)) {
    # Create Resource Group
    $GalleryResourceGroup = New-AzResourceGroup -Name $GalleryResourceGroupName -Location $Location -Force
}
Write-Verbose "`$GalleryResourceGroup: $GalleryResourceGroup"
#endregion

$GalleryName = "gal_avd_use2_{0}" -f $timeInt
$Tags =  @{
    "SecurityControl" = "Ignore"
    #"Script" = $(Split-Path -Path $MyInvocation.ScriptName -Leaf)
} 
$Parameters = @{
    ResourceGroupName = $GalleryResourceGroupName 
    GalleryName = $GalleryName 
}
#endregion

#region Azure Compute Gallery
$Gallery = Get-AzGallery @Parameters -ErrorAction Ignore
if (-not($Gallery)) {
    $GalleryResourceGroup = New-AzResourceGroup -Name $GalleryResourceGroupName -Location $Location -Tag $Tags -force
    $Gallery = New-AzGallery @Parameters -Location $Location
}
#endregion

#region Staging ResourceGroup
$Image = @{
	Publisher = 'MicrosoftWindowsDesktop'
	Offer     = 'Windows-11'    
	Sku       = 'win11-25h2-avd'  
	Version   = 'latest'
}
$imageDefinitionNameARM = "{0}-arm-vscode" -f $Image.Sku
$imageTemplateNameARM = "{0}-template-{1}" -f $imageDefinitionNameARM, $timeInt
$StagingResourceGroupNameARM = "IT_{0}_{1}_{2}" -f $GalleryResourceGroupName, $imageTemplateNameARM.Substring(0, 13), (New-Guid).Guid
$StagingResourceGroupARM = New-AzResourceGroup -Name $StagingResourceGroupNameARM -Location $Location -Tag $Tags -force
#endregion

#region Link the schedule to the runbook
$Parameters = @{ 
    GalleryResourceId = $Gallery.Id
    Image = $($Image | ConvertTo-Json -Compress)
    StagingResourceGroupNameARM = $StagingResourceGroupARM.ResourceGroupName
    AssignedIdentityId = $AssignedIdentity.Id
}
$Params = @{
    AutomationAccountName = $AutomationAccount.AutomationAccountName
    ResourceGroupName = $ResourceGroupName
    Name = $RunBookName 
}

Register-AzAutomationScheduledRunbook @Params -ScheduleName $Schedule.Name -Parameters $Parameters
#endregion

#region RBAC Assignments
#region 'Compute Gallery Artifacts Publisher' RBAC Assignment
$RoleDefinition = Get-AzRoleDefinition -Name "Compute Gallery Artifacts Publisher"
$Parameters = @{
    ObjectId           = $AutomationAccount.Identity.PrincipalId
    RoleDefinitionName = $RoleDefinition.Name
    Scope              = $GalleryResourceGroup.ResourceId
}
while (-not(Get-AzRoleAssignment @Parameters)) {
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.SignInName)' Identity on the '$($Parameters.Scope)' scope"
    $RoleAssignment = New-AzRoleAssignment @Parameters
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)]`$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
    Start-Sleep -Seconds 30
}
#endregion 

#region 'Resource Group Contributor' RBAC Assignments
foreach ($CurrentResourceGroup in $GalleryResourceGroup, $StagingResourceGroupARM)  {
    $RoleDefinition = Get-AzRoleDefinition -Name "Contributor"
    $Parameters = @{
        ObjectId           = $AutomationAccount.Identity.PrincipalId
        RoleDefinitionName = $RoleDefinition.Name
        Scope              = $CurrentResourceGroup.ResourceId
    }
    while (-not(Get-AzRoleAssignment @Parameters)) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.SignInName)' Identity on the '$($Parameters.Scope)' scope"
        $RoleAssignment = New-AzRoleAssignment @Parameters
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)]`$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
        Start-Sleep -Seconds 30
    }
}
#endregion 

#region User Assigned Identity
$Scope = $GalleryResourceGroup.ResourceId
$RoleAssignment = Get-AzRoleAssignment -Scope $Scope | Where-Object -FilterScript { $_.RoleDefinitionName -match "^Azure Image Builder Image Def"}
    
if ($RoleAssignment) {
    Write-Output -InputObject "'$($RoleAssignment.RoleDefinitionName)' Role Definition is already set to '$($RoleAssignment.DisplayName)' on the '$($RoleAssignment.Scope)' scope ..."
    $AssignedIdentity = Get-AzUserAssignedIdentity -ResourceGroupName $($RoleAssignment.Scope -replace ".+/") -Name $($RoleAssignment.DisplayName)
    $imageRoleDefName = $RoleAssignment.RoleDefinitionName
}
else {
	#region setup role def names, these need to be unique
	$imageRoleDefName = "Azure Image Builder Image Def - $timeInt"
	$identityName = "aibIdentity-$timeInt"
	Write-Output -InputObject "`$imageRoleDefName: $imageRoleDefName"
	Write-Output -InputObject "`$identityName: $identityName"
	#endregion

	#region Create the identity
	Write-Output -InputObject "Creating User Assigned Identity '$identityName' ..."
	$AssignedIdentity = New-AzUserAssignedIdentity -ResourceGroupName $Gallery.ResourceGroupName -Name $identityName -Location $location
	#endregion
        
}
#endregion

#region aibRoleImageCreation.json creation and RBAC Assignment
#$aibRoleImageCreationUrl="https://raw.githubusercontent.com/PeterR-msft/M365AVDWS/master/Azure%20Image%20Builder/aibRoleImageCreation.json"
#$aibRoleImageCreationUrl="https://raw.githubusercontent.com/azure/azvmimagebuilder/main/solutions/12_Creating_AIB_Security_Roles/aibRoleImageCreation.json"
#$aibRoleImageCreationUrl="https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20VM%20Image%20Builder/aibRoleImageCreation.json"
$aibRoleImageCreationUrl = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20VM%20Image%20Builder/aibRoleImageCreation.json"
#$aibRoleImageCreationPath = "aibRoleImageCreation.json"
$aibRoleImageCreationPath = Join-Path -Path $env:TEMP -ChildPath $(Split-Path $aibRoleImageCreationUrl -Leaf)
#Generate a unique file name 
$aibRoleImageCreationPath = $aibRoleImageCreationPath -replace ".json$", "_$timeInt.json"
Write-Output -InputObject "`$aibRoleImageCreationPath: $aibRoleImageCreationPath"

# Download the config
Invoke-WebRequest -Uri $aibRoleImageCreationUrl -OutFile $aibRoleImageCreationPath -UseBasicParsing

((Get-Content -Path $aibRoleImageCreationPath -Raw) -replace '<subscriptionID>', $subscriptionID) | Set-Content -Path $aibRoleImageCreationPath
((Get-Content -Path $aibRoleImageCreationPath -Raw) -replace '<rgName>', $Gallery.ResourceGroupName) | Set-Content -Path $aibRoleImageCreationPath
((Get-Content -Path $aibRoleImageCreationPath -Raw) -replace 'Azure Image Builder Service Image Creation Role', $imageRoleDefName) | Set-Content -Path $aibRoleImageCreationPath

#region Create a role definition
$RoleDefinition = Get-AzRoleDefinition -Name $imageRoleDefName
if ($RoleDefinition) {
	Write-Output -InputObject "The '$imageRoleDefName' Role Definition already exists ..."
}
else {
	Write-Output -InputObject "Creating '$imageRoleDefName' Role Definition ..."
	$RoleDefinition = New-AzRoleDefinition -InputFile $aibRoleImageCreationPath
}
#endregion

# Grant the role definition to the VM Image Builder service principal
<#
if (-not(Get-AzRoleAssignment -ObjectId $AssignedIdentity.PrincipalId -RoleDefinitionName $RoleDefinition.Name -Scope $Scope)) {
    Write-Output -InputObject "Assigning the '$($RoleDefinition.Name)' RBAC role to the '$($AssignedIdentity.PrincipalId)' System Assigned Managed Identity"
    $RoleAssignment = New-AzRoleAssignment -ObjectId $AssignedIdentity.PrincipalId -RoleDefinitionName $RoleDefinition.Name -Scope $Scope
    Write-Output -InputObject "`$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
} else {
    Write-Output -InputObject "The '$($RoleDefinition.Name)' RBAC role is already assigned to the '$($AssignedIdentity.PrincipalId)' System Assigned Managed Identity"
} 
#> 
$Parameters = @{
	ObjectId           = $AssignedIdentity.PrincipalId
	RoleDefinitionName = $RoleDefinition.Name
	Scope              = $Scope
}

While (-not(Get-AzRoleAssignment @Parameters)) {
	Write-Output -InputObject "Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.ObjectId)' System Assigned Managed Identity on the '$($Parameters.Scope)' scope"
	try {
		$RoleAssignment = New-AzRoleAssignment @Parameters -ErrorAction Stop
	} 
	catch {
		$RoleAssignment = $null
	}
	Write-Output -InputObject "`$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
	if ($null -eq $RoleAssignment) {
		Write-Output -InputObject "Sleeping 30 seconds"
		Start-Sleep -Seconds 30
	}
}
#endregion

#endregion

#region Disabling/Enabling Log Verbose Records 
$Params = @{
    AutomationAccountName = $AutomationAccount.AutomationAccountName
    ResourceGroupName = $ResourceGroupName
    Name = $RunBookName 
}
$null = Set-AzAutomationRunbook @Params -LogVerbose $false # <-- Verbose stream
#endregion

#region Test
#Start-Sleep -Seconds 30
#region PowerShell
$Parameters = @{ 
    GalleryResourceId = $Gallery.Id
    Image = $($Image | ConvertTo-Json -Compress)
    StagingResourceGroupNameARM = $StagingResourceGroupARM.ResourceGroupName
    AssignedIdentityId = $AssignedIdentity.Id
}
$Params = @{
    AutomationAccountName = $AutomationAccount.AutomationAccountName
    ResourceGroupName = $ResourceGroupName
    Name = $RunBookName 
}
$Result = Start-AzAutomationRunbook @Params -Parameters $Parameters

$Params = @{
    AutomationAccountName = $AutomationAccount.AutomationAccountName
    ResourceGroupName = $ResourceGroupName
    Id = $Result.JobId
}

While ((Get-AzAutomationJob @Params).Status -notin @("Completed", "Failed")) {
    Start-Sleep -Seconds 30
}

#All outputs except Verbose
(Get-AzAutomationJobOutput @Params | Where-Object -FilterScript { $_.Type -ne "Verbose"}).Summary
#All useful Verbose outputs
#(Get-AzAutomationJobOutput @Params | Where-Object -FilterScript { ($_.Type -eq "Verbose") -and ($_.Summary -notmatch "^Importing|^Exporting|^Loading module")}).Summary
#endregion
#endregion
