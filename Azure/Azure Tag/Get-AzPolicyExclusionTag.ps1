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
#requires -Version 5 -Modules Az.Accounts, Az.Resources

[CmdletBinding(PositionalBinding = $false)]
Param (
)

#region Function Definitions
function Get-AzPolicyLastModifiedAt {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
    )

    #Hastable for storing already processed policies (A policiy can be assigned to multiple scopes so we avoid duplicated processings). The Key is the PolicyDefinitionId
    $PolicyHT = @{}
    #Processing all assigned initiatives or policies only
    $PolicyLastModifiedAt = (Get-AzPolicyAssignment) | ForEach-Object -Process {
        #Initiatives
        if ($_.PolicyDefinitionId -match "policySetDefinitions") {
            $Initiative = (Get-AzPolicySetDefinition -Id $_.PolicyDefinitionId)
            Write-Verbose -Message "Processing Initiative '$($Initiative.DisplayName)'"
            [PSCustomObject]@{Initiative = $Initiative.DisplayName; Policy = $null; lastModifiedAt = $Initiative.SystemDataLastModifiedAt }

            $Initiative.PolicyDefinition | ForEach-Object {
                #Nested Policies
                $Policy = (Get-AzPolicyDefinition -Id $_.PolicyDefinitionId)
                Write-Verbose -Message "- Processing Initiative Policy: '$($Initiative.DisplayName)' > '$($Policy.DisplayName)'"
                if ($null -eq $PolicyHT[$_.PolicyDefinitionId]) {
                    [PSCustomObject]@{Initiative = $Initiative.DisplayName; Policy = $Policy.DisplayName; lastModifiedAt = $Policy.SystemDataLastModifiedAt }
                }
                else {
                    Write-Verbose -Message "- Initiative Policy: '$($Initiative.DisplayName)' > '$($Policy.DisplayName)' already processed"
                }

            }
        }
        #Standalone Policies (Not inside an Initiative)
        else {
            Write-Verbose -Message "Processing Standalone Policy: '$($Policy.DisplayName)'"
            if ($null -eq $PolicyHT[$_.PolicyDefinitionId]) {
                [PSCustomObject]@{Initiative = $null; Policy = $Policy.DisplayName; lastModifiedAt = $Policy.SystemDataLastModifiedAt }
            }
            else {
                Write-Verbose -Message "- Standalone Policy: '$($Policy.DisplayName)' already processed"
            }
        }
    }
    $PolicyLastModifiedAt | Select-Object -Property * -Unique | Sort-Object -Property lastModifiedAt -Descending
}

function Get-AzPolicyExclusionTag {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
    )

    #Hastable for storing already processed policies (A policiy can be assigned to multiple scopes so we avoid duplicated processings). The Key is the PolicyDefinitionId
    $PolicyHT = @{}
    #Processing all assigned initiatives or policies only
    (Get-AzPolicyAssignment) | ForEach-Object -Process {
        #Initiatives
        if ($_.PolicyDefinitionId -match "policySetDefinitions") {
            $Initiative = (Get-AzPolicySetDefinition -Id $_.PolicyDefinitionId)
            Write-Verbose -Message "Processing Initiative '$($Initiative.DisplayName)'"
            $Initiative.PolicyDefinition | ForEach-Object {
                #Nested Policies
                $Policy = (Get-AzPolicyDefinition -Id $_.PolicyDefinitionId)
                Write-Verbose -Message "- Processing Initiative Policy: '$($Initiative.DisplayName)' > '$($Policy.DisplayName)'"
                if ($null -eq $PolicyHT[$_.PolicyDefinitionId]) {
                    $PolicyHT[$_.PolicyDefinitionId] = [PSCustomObject]@{Initiative = $Initiative.DisplayName; Policy = $Policy }
                }
                else {
                    Write-Verbose -Message "- Initiative Policy: '$($Initiative.DisplayName)' > '$($Policy.DisplayName)' already processed"
                }

            }
        }
        #Standalone Policies (Not inside an Initiative)
        else {
            Write-Verbose -Message "Processing Standalone Policy: '$($Policy.DisplayName)'"
            if ($null -eq $PolicyHT[$_.PolicyDefinitionId]) {
                $PolicyHT[$_.PolicyDefinitionId] = [PSCustomObject]@{Initiative = $null; Policy = $Policy }
            }
            else {
                Write-Verbose -Message "- Standalone Policy: '$($Policy.DisplayName)' already processed"
            }
        }
    }
    #Keeping only the policies
    $Policies = $PolicyHT.Values
    $PolicyExclusionTags = foreach ($CurrentPolicy in $Policies) {
        if ($CurrentPolicy.Policy.Parameter.AllowedTagName) {
            #Creating a custom object with the Policy DisplayName and the Tag data (Name and associated Value)
            [PSCustomObject]@{Policy = $CurrentPolicy.Policy.DisplayName; TagName = $CurrentPolicy.Policy.Parameter.AllowedTagName.defaultValue; TagValue = $CurrentPolicy.Policy.Parameter.AllowedTagValue.defaultValue }
        }
    }
    $PolicyExclusionTags
}

Function Update-AzSubscriptionTag {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        [Object] $Subscription = (Get-AzContext).Subscription,
        [Parameter(Mandatory = $true)]
        #[ValidateScript({('TagName' -in $(($SubscriptionTags | Get-Member -MemberType NoteProperty).Name)) -and ('TagValue' -in $(($SubscriptionTags | Get-Member -MemberType NoteProperty).Name))})]
        [ValidateScript({ ($null -eq (Compare-Object -ReferenceObject ($_ | Get-Member -MemberType NoteProperty).Name -DifferenceObject @('TagName', 'TagValue'))) })]
        [Object[]] $Tags,
        [switch] $Force,
        [switch] $PassThru
    )
    #Getting all Tags at the subscription level
    $SubscriptionTags = (Get-AzTag -ResourceId "/subscriptions/$($Subscription.Id)").Properties.TagsProperty
    Write-Verbose -Message "Working on Subscription '$($Subscription.Name)/$($Subscription.Id)'"
    #Processing all Subscription tags
    foreach ($CurrentTag in $Tags) {
        Write-Verbose -Message "Processing '$($CurrentTag.TagName)=$($CurrentTag.TagValue)' Tag ..."
        #If Tag is already present at the subscription level
        if ($CurrentTag.TagName -in $SubscriptionTags.Keys) {
            $SubscriptionTagValue = $SubscriptionTags[$CurrentTag.TagName]
            #If -Force is specified we update the existing Tag
            if ($Force) {
                if ($CurrentTag.TagValue -eq $SubscriptionTagValue) {
                    Write-Verbose -Message "-Force was specified but the values are the same: We DON'T update the tag"
                }
                else {
                    Write-Verbose -Message "-Force was specified but the values are not the same: We update the tag from '$SubscriptionTagValue' to '$($CurrentTag.TagValue)'"
                    $null = Update-AzTag -ResourceId "/subscriptions/$($Subscription.Id)" -Tag @{$CurrentTag.TagName = $CurrentTag.TagValue } -Operation Merge
                }
            }
            else {
                Write-Verbose -Message "-Force was NOT specified: '$($CurrentTag.TagName)' already set with the value '$SubscriptionTagValue' at the Subscription level ('$($Subscription.Name)')"
            }
        }
        #If Tag is NOT already present at the subscription level: Updating Tag list
        else {
            Write-Verbose -Message "Setting '$($CurrentTag.TagName)=$($CurrentTag.Value)' Tag at the Subscription level ('$($Subscription.Name)')"
            $null = Update-AzTag -ResourceId "/subscriptions/$($Subscription.Id)" -Tag @{$CurrentTag.TagName = $CurrentTag.TagValue } -Operation Merge
        }
    }
    #Returning the Tags at the subscription level if -PassThru is specified
    if ($PassThru) {
        (Get-AzTag -ResourceId "/subscriptions/$($Subscription.Id)")
    }
}

Function New-AzInheritanceSubscriptionTagPolicyAssignment {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        [Object] $Subscription = (Get-AzContext).Subscription,
        [Parameter(Mandatory = $true)]
        #[ValidateScript({('TagName' -in $(($SubscriptionTags | Get-Member -MemberType NoteProperty).Name)) -and ('TagValue' -in $(($SubscriptionTags | Get-Member -MemberType NoteProperty).Name))})]
        [ValidateScript({ ($null -eq (Compare-Object -ReferenceObject ($_ | Get-Member -MemberType NoteProperty).Name -DifferenceObject @('TagName', 'TagValue'))) })]
        [Object[]] $Tags,
        [ValidateScript({ $_ -in (Get-AzLocation).Location })]
        [string]$Location = "EastUs2",
        [switch] $PassThru
    )

    #For 'Inherit a tag from the subscription if missing' Policy Definition
    $InheritanceSubscriptionTagPolicyDefinitionName = '40df99da-1232-49b1-a39a-6da8d878f469'
    $InheritanceSubscriptionTagPolicyDefinition = Get-AzPolicyDefinition -Name $InheritanceSubscriptionTagPolicyDefinitionName
    $InheritanceSubscriptionAzPolicyAssignment = Get-AzPolicyAssignment -PolicyDefinitionId $InheritanceSubscriptionTagPolicyDefinition.Id


    Write-Verbose -Message "Working on Subscription '$($Subscription.Name)/$($Subscription.Id)'"
    $InheritanceSubscriptionTagPolicyAssignment = foreach ($CurrentTag in $Tags) {
        Write-Verbose -Message "Processing '$($CurrentTag.TagName)' Tag ..."
        #If the Tag is already assigned to a 'Inherit a tag from the subscription if missing' Policy Definition
        if ($CurrentTag.TagName -in $InheritanceSubscriptionAzPolicyAssignment.Parameter.TagName.Value) {
            $ExistingInheritanceSubscriptionAzPolicyAssignment = ($InheritanceSubscriptionAzPolicyAssignment | Where-Object -FilterScript { $_.Parameter.TagName.Value -eq "$($CurrentTag.TagName)" })
            Write-Verbose -Message "The '$($ExistingInheritanceSubscriptionAzPolicyAssignment.DisplayName)' policy already exists for the '$($CurrentTag.TagName)' Tag"
        }
        else {
            #Generating a Policy Display Name under the form 'Inherit a tag from the subscription if missing: <TagName>'
            $InheritanceSubscriptionAzPolicyAssignmentDisplayName = "{0}: {1}" -f $InheritanceSubscriptionTagPolicyDefinition.DisplayName, $($CurrentTag.TagName)
            Write-Verbose -Message "Creating the '$($InheritanceSubscriptionAzPolicyAssignmentDisplayName)' policy for the '$($CurrentTag.TagName)' Tag"
            #Generating a 24-characters GUID as Policy Name
            $Name = ((New-Guid).Guid -replace "-").substring(0, 24)
            Write-Verbose -Message "`$Name: $Name"
            #Creating a Policy Assignment for 'Inherit a tag from the subscription if missing' Policy Definition for the current Tag 
            $PolicyParameterObject = @{'tagName' = $($CurrentTag.TagName) }
            New-AzPolicyAssignment -Name $Name -DisplayName $InheritanceSubscriptionAzPolicyAssignmentDisplayName -PolicyDefinition $InheritanceSubscriptionTagPolicyDefinition -Scope "/subscriptions/$($Subscription.Id)" -PolicyParameterObject $PolicyParameterObject  -IdentityType 'SystemAssigned' -Location $Location
        }
    }
    #Returning the Policy Assignments if -PassThru is specified
    if ($PassThru) {
        $InheritanceSubscriptionTagPolicyAssignment
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

#region Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount
}
#endregion

#Getting Azure Policy Last Modification Times 
$PolicyLastModifiedAt = Get-AzPolicyLastModifiedAt -Verbose
$ThreeMonthsAgo = (Get-Date).AddMonths(-3)
$PolicyModifiedintheLastMonth = $PolicyLastModifiedAt | Where-Object -FilterScript { $_.lastModifiedAt -ge $ThreeMonthsAgo }
$PolicyModifiedintheLastMonth | Sort-Object -Property lastModifiedAt -Descending | Out-GridView

#Getting Exclusion Tags From Azure Policies 
$PolicyExclusionTags = Get-AzPolicyExclusionTag -Verbose
$PolicyExclusionTags

#Removing duplicates 
$Tags = $PolicyExclusionTags | Select-Object -Property TagName, TagValue -Unique
$Tags

#Updating Subscription Tags with Exclusion Tags
$SubscriptionTag = Update-AzSubscriptionTag -Tag $Tags -PassThru -Force -Verbose
$SubscriptionTag

#Creating Policy Assignments for the added Exclusion Tags at Subscription level for inheritance at the resource level
$InheritanceSubscriptionTagPolicyAssignment = New-AzInheritanceSubscriptionTagPolicyAssignment -Tags $Tags -PassThru -Verbose
$InheritanceSubscriptionTagPolicyAssignment 
#endregion