#To run from the Azure VM
#requires -Version 7 -RunAsAdministrator 

<#
More info on 
- https://docs.microsoft.com/en-us/azure/governance/policy/how-to/guest-configuration-create-setup
- https://techcommunity.microsoft.com/t5/microsoft-defender-for-cloud/7-steps-to-author-develop-and-deploy-custom-recommendations-for/ba-p/3166026
- https://cloudbrothers.info/en/azure-persistence-azure-policy-guest-configuration/
#>
<#
#Cleaning up previous tests
$ResourceGroupName = "rg-dsc-amc*"
Get-AzResourceGroup -Name $ResourceGroupName | Select-Object -Property @{Name="Scope"; Expression={$_.ResourceID}} | Get-AzPolicyRemediation | Remove-AzPolicyRemediation -AllowStop -AsJob -Verbose | Wait-Job
Get-AzResourceGroup -Name $ResourceGroupName | Select-Object -Property @{Name="Scope"; Expression={$_.ResourceID}} | Get-AzPolicyAssignment  | Where-Object -FilterScript { $_.Scope -match 'rg-dsc-amc' } | Remove-AzPolicyAssignment -Verbose #-Whatif
Get-AzPolicyDefinition | Where-Object -filterScript {$_.metadata.category -eq "Guest Configuration" -and $_.DisplayName -like "*$ResourceGroupName"} | Remove-AzPolicyDefinition -Verbose -Force #-WhatIf
Get-AzResourceGroup -Name $ResourceGroupName | Remove-AzResourceGroup -AsJob -Force -Verbose 
#>

[CmdletBinding(PositionalBinding = $false)]
Param(
    [ValidateScript({ $_ -in $((Get-ChildItem -Path $PSSCriptRoot -Filter *DSCConfiguration.ps1 -File).BaseName) })]
    [string[]] $ConfigurationName
)

#region Function defintions
#Get The Azure VM Compute Object for the VM executing this function
function Get-AzVMCompute {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"

    $uri = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

    try {
        $response = Invoke-RestMethod -Uri $uri -Headers @{"Metadata" = "true" } -Method GET -TimeoutSec 5
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] VM Compute Object:`r`n$($response.compute | Out-String)"
        return $response.compute
    }
    catch {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        return $null
    }
}
#endregion

Clear-Host
#$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
#$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $PSScriptRoot

$AzVM = Get-AzVMCompute
#From https://learn.microsoft.com/en-us/azure/governance/machine-configuration/how-to/create-policy-definition#create-an-azure-policy-definition
$Location = $AzVM.Location
$ResourceGroupName = $AzVM.ResourceGroupName
$StorageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName
$StorageAccountName = $StorageAccount.StorageAccountName
$StorageGuestConfigurationContainerName = "guestconfiguration"
$StorageCertificateContainerName = "certificates"
#Adding a 7-day expiration time from now for the SAS Token
$StartTime = Get-Date
$ExpiryTime = $StartTime.AddDays(7)

#$GuestConfigurationPackageName = "$ConfigurationName.zip"
#$GuestConfigurationPackageFullName  = "$PSScriptRoot\$ConfigurationName\$GuestConfigurationPackageName"

#region From PowerShell
#region Deploy prerequisites to enable Guest Configuration policies on virtual machines

$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName
$PolicySetDefinition = Get-AzPolicySetDefinition | Where-Object -FilterScript { $_.DisplayName -eq "Deploy prerequisites to enable Guest Configuration policies on virtual machines" }
$PolicyAssignment = Get-AzPolicyAssignment -Name "$($ResourceGroupName)-deployPrereqForGuestConfigurationPolicies" -Scope $ResourceGroup.ResourceId -ErrorAction Ignore
if (-not($PolicyAssignment)) {
    $PolicyAssignment = New-AzPolicyAssignment -Name "$($ResourceGroupName)-deployPrereqForGuestConfigurationPolicies" -DisplayName "[$ResourceGroupName] Deploy prerequisites to enable Guest Configuration policies on virtual machines" -Scope $ResourceGroup.ResourceId -PolicySetDefinition $PolicySetDefinition -EnforcementMode Default -IdentityType SystemAssigned -Location $Location
    $PolicyState = $null
} 
else {
    Write-Host -Object  "'$($PolicyAssignment.DisplayName)' Policy is already assigned to the '$ResourceGroupName' Resource Group"
    $PolicyState = Get-AzPolicyState -ResourceGroupName $ResourceGroupName -PolicyAssignmentName $PolicyAssignment.Name #-Filter 'IsCompliant eq false'
}

# Grant permissions to the managed identity through defined roles
# From https://learn.microsoft.com/en-us/azure/governance/policy/how-to/remediate-resources?tabs=azure-powershell#grant-permissions-to-the-managed-identity-through-defined-roles
#######################################################
# Grant roles to managed identity at initiative scope #
#######################################################
if (($null -eq $PolicyState) -or (($PolicyState.ComplianceState | Select-Object -Unique) -ne "Compliant")) {
    $roleDefinitionIds = $PolicySetDefinition.PolicyDefinition | ForEach-Object -Process { Get-AzPolicyDefinition -Id $_.policyDefinitionId | Select-Object @{Name = "roleDefinitionIds"; Expression = { $_.policyRule.then.details.roleDefinitionIds } } } | Select-Object -ExpandProperty roleDefinitionIds -Unique
    Start-Sleep -Seconds 30
    if ($roleDefinitionIds.Count -gt 0) {
        $roleDefinitionIds | ForEach-Object {
            $roleDefId = $_.Split("/") | Select-Object -Last 1
            if (-not(Get-AzRoleAssignment -Scope $ResourceGroup.ResourceId -ObjectId $PolicyAssignment.IdentityPrincipalId -RoleDefinitionId $roleDefId)) {
                New-AzRoleAssignment -Scope $ResourceGroup.ResourceId -ObjectId $PolicyAssignment.IdentityPrincipalId -RoleDefinitionId $roleDefId
            }
        }
    }

    # Start remediation for every policy definition
    $PolicyRemediationJobs = $PolicySetDefinition.PolicyDefinition | ForEach-Object -Process {
        Write-Host -Object "Creating remediation for '$($_.policyDefinitionReferenceId)' Policy ..."
        Start-AzPolicyRemediation -PolicyAssignmentId $PolicyAssignment.Id -PolicyDefinitionReferenceId $_.policyDefinitionReferenceId -Name $_.policyDefinitionReferenceId -ResourceGroupName $ResourceGroup.ResourceGroupName -ResourceDiscoveryMode ReEvaluateCompliance -AsJob
    }
    $remediation = $PolicyRemediationJobs | Receive-Job -Wait -AutoRemoveJob
    $remediation
}
else {
    Write-Host -Object  "All resources in '$ResourceGroupName' Resource Group are already compliant with '$($PolicyAssignment.DisplayName)' Policy"
}
#endregion

#region Public Network Access and Shared Key Access Enabled on the Storage Account
$storageAccount | Set-AzStorageAccount -PublicNetworkAccess Enabled -AllowBlobPublicAccess $false -AllowSharedKeyAccess $false
Start-Sleep -Seconds 30
$Context = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount
#endregion

#region Removing existing blob
$storageAccount | Get-AzStorageContainer | Get-AzStorageBlob | Remove-AzStorageBlob
#endregion

#region Self-signed Certificate Management
# Creates a new certificate container
if (-not($storageAccount | Get-AzStorageContainer -Name $StorageCertificateContainerName -ErrorAction Ignore)) {
    New-AzStorageContainer -Name $StorageCertificateContainerName -Context $Context #-Permission Blob
}

#region Generating Self-signed Certificates, exporting them as .cer files and delete them from certificate store
$DnsName = 'www.fabrikam.com', 'www.contoso.com'
$CertificateFiles = $DnsName | ForEach-Object -Process { $cert = New-SelfSignedCertificate -DnsName $_ -CertStoreLocation 'Cert:\LocalMachine\My'; $FilePath = Join-Path -Path $PSScriptRoot -ChildPath "$_.cer" ; $cert | Export-Certificate -FilePath $FilePath; $cert | Remove-Item -Force }
#endregion

#region Adding Self-signed Certificates to the container
#$CertificateStorageBlobSASToken = Get-ChildItem -Path $PSScriptRoot -Filter *.cer -File | Set-AzStorageBlobContent -Container $StorageCertificateContainerName -Context $Context -Force | New-AzStorageBlobSASToken -Permission r -StartTime $StartTime -ExpiryTime $ExpiryTime -FullUri
$CertificateFiles | Set-AzStorageBlobContent -Container $StorageCertificateContainerName -Context $Context -Force
#endregion
#endregion

#region Assigning the 'Storage Blob Data Reader' RBAC Role to the Azure VM System Assigned Identity to the Storage Account 
#From https://learn.microsoft.com/en-us/azure/governance/machine-configuration/how-to/create-policy-definition#create-an-azure-policy-definition
$AZVMSystemAssignedIdentity = ($AzVM | Get-AzVM).Identity   
$RoleDefinition = Get-AzRoleDefinition -Name "Storage Blob Data Reader"
$Parameters = @{
    ObjectId           = $AZVMSystemAssignedIdentity.PrincipalId
    RoleDefinitionName = $RoleDefinition.Name
    Scope              = $StorageAccount.Id
}

While (-not(Get-AzRoleAssignment @Parameters)) {
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.ObjectId)' Identity on the '$($Parameters.Scope)' scope"
    $RoleAssignment = New-AzRoleAssignment @Parameters -ErrorAction Ignore
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
    Start-Sleep -Seconds 30
}
#endregion


#region Our Guest Policies
if ($ConfigurationName) {
    $DSCConfigurations = Get-ChildItem -Path $PSScriptRoot -Filter *DSCConfiguration.ps1 -File | Where-Object -FilterScript { $_.BaseName -in $ConfigurationName }
    #$DSCConfigurations = Get-ChildItem -Path $PSScriptRoot  -Filter *.ps1 -Include $ConfigurationName -Recurse
}
else {
    $DSCConfigurations = Get-ChildItem -Path $PSScriptRoot -Filter *DSCConfiguration.ps1 -File
}

$PolicyRemediationJobs = @()
foreach ($CurrentDSCConfiguration in $DSCConfigurations) {
    $CurrentConfigurationName = $CurrentDSCConfiguration.BaseName
    #Note : The name of the filename has to match the DSC configuration Name for an easier code maintenance: CreateAdminUserDSCConfiguration ==> CreateAdminUserDSCConfiguration.ps1, IISSetupDSCConfiguration ==> IISSetupDSCConfiguration.ps1. Else use the RegEx below
    <#
    $Result = Select-String -Path $CurrentDSCConfiguration.FullName -Pattern "^\s?Configuration\s(?<DSConfigurationName>[^{]*)"
    $CurrentConfigurationName = ($Result.Matches.Groups.Captures | Where-Object -FilterScript {$_.Name -eq "DSCConfigurationName"}).Value
    #>
    Write-Host -Object "Processing '$CurrentConfigurationName' DSCConfiguration"
    & $CurrentDSCConfiguration

    # Create a guest configuration package for Azure Policy GCS
    $GuestConfigurationPackage = New-GuestConfigurationPackage -Name $CurrentConfigurationName -Configuration "./$CurrentConfigurationName/localhost.mof" -Type AuditAndSet -Force
    # Validating the configuration package meets requirements: https://learn.microsoft.com/en-us/azure/governance/machine-configuration/how-to/develop-custom-package/3-test-package#validate-the-configuration-package-meets-requirements
    Get-GuestConfigurationPackageComplianceStatus -Path $GuestConfigurationPackage.Path -Verbose
    #Set-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -AllowBlobPublicAccess $true
    # Applying the Machine Configuration Package locally
    #Start-GuestConfigurationPackageRemediation -Path $GuestConfigurationPackage.Path -Verbose
    $GuestConfigurationPackageName = Split-Path -Path $GuestConfigurationPackage.Path -Leaf

    # Creates a new guest configuration container
    if (-not($storageAccount | Get-AzStorageContainer -Name $StorageGuestConfigurationContainerName -ErrorAction Ignore)) {
        New-AzStorageContainer -Name $StorageGuestConfigurationContainerName -Context $Context #-Permission Blob
    }


    $GuestConfigurationStorageBlob = Set-AzStorageBlobContent -Container $StorageGuestConfigurationContainerName -File $GuestConfigurationPackage.Path -Blob $GuestConfigurationPackageName -Context $Context -Force
    #$GuestConfigurationStorageBlobSASToken = New-AzStorageBlobSASToken -Context $Context -FullUri -Container $StorageGuestConfigurationContainerName -Blob $GuestConfigurationPackageName -Permission rwd -StartTime $StartTime -ExpiryTime $ExpiryTime      
    
    # Create a Policy Id
    $PolicyId = (New-Guid).Guid  
    # Define the parameters to create and publish the guest configuration policy
    $Params = @{
        "PolicyId"                  = $PolicyId
        "ContentUri"                = $GuestConfigurationStorageBlob.ICloudBlob.Uri.AbsoluteUri
        "DisplayName"               = "[Windows] $ResourceGroupName - Make sure all Windows servers comply with $CurrentConfigurationName DSC Config."
        "Description"               = "[Windows] $ResourceGroupName - Make sure all Windows servers comply with $CurrentConfigurationName DSC Config."
        "Path"                      = './policies'
        "Platform"                  = 'Windows'
        "PolicyVersion"             = '1.0.0'
        "Mode"                      = 'ApplyAndAutoCorrect'
        #From https://github.com/Azure/GuestConfiguration/blob/main/source/Public/New-GuestConfigurationPolicy.ps1#L55-L59
        "LocalContentPath"          = $GuestConfigurationPackage.Path
        "UseSystemAssignedIdentity" = $true
        "Verbose"                   = $true
    }
    # Create the guest configuration policy
    #From https://learn.microsoft.com/en-us/azure/governance/machine-configuration/how-to/create-policy-definition#create-an-azure-policy-definition
    $Policy = New-GuestConfigurationPolicy @Params

    $PolicyDefinition = New-AzPolicyDefinition -Name "[Win]$ResourceGroupName-$CurrentConfigurationName" -Policy $Policy.Path

    $NonComplianceMessage = [Microsoft.Azure.Commands.ResourceManager.Cmdlets.Entities.Policy.NonComplianceMessage]::new()
    $NonComplianceMessage.message = "Non Compliance Message"
    $IncludeArcConnectedServers = @{'IncludeArcMachines' = 'true' }# <- IncludeArcMachines is important - given you want to target Arc as well as Azure VMs

    $PolicyAssignment = New-AzPolicyAssignment -Name "$($ResourceGroupName)-$($CurrentConfigurationName)" -DisplayName "[Windows] $ResourceGroupName - Make sure all Windows servers comply with $CurrentConfigurationName DSC Config." -Scope $ResourceGroup.ResourceId -PolicyDefinition $PolicyDefinition -EnforcementMode Default -IdentityType SystemAssigned -Location $Location -PolicyParameterObject $IncludeArcConnectedServers -NonComplianceMessage $NonComplianceMessage  

    # Grant permissions to the managed identity through defined roles
    # https://learn.microsoft.com/en-us/azure/governance/policy/how-to/remediate-resources?tabs=azure-powershell#grant-permissions-to-the-managed-identity-through-defined-roles
    ###################################################
    # Grant roles to managed identity at policy scope #
    ###################################################
    $roleDefinitionIds = $PolicyDefinition.policyRule.then.details.roleDefinitionIds
    Start-Sleep -Seconds 30
    if ($roleDefinitionIds.Count -gt 0) {
        $roleDefinitionIds | ForEach-Object {
            $roleDefId = $_.Split("/") | Select-Object -Last 1
            if (-not(Get-AzRoleAssignment -Scope $ResourceGroup.ResourceId -ObjectId $PolicyAssignment.IdentityPrincipalId -RoleDefinitionId $roleDefId)) {
                New-AzRoleAssignment -Scope $ResourceGroup.ResourceId -ObjectId $PolicyAssignment.IdentityPrincipalId -RoleDefinitionId $roleDefId
            }
        }
    }

    Write-Host -Object "Creating remediation for '$($PolicyDefinition.DisplayName)' Policy (As Job) ..."
    $PolicyRemediationJobs += Start-AzPolicyRemediation -Name $PolicyAssignment.Name -PolicyAssignmentId $PolicyAssignment.Id -ResourceGroupName $ResourceGroup.ResourceGroupName -ResourceDiscoveryMode ReEvaluateCompliance -AsJob

}
Write-Host -Object "Waiting Policy Remediations complete ..."
$PolicyRemediations = $PolicyRemediationJobs | Receive-Job -Wait -AutoRemoveJob
$PolicyRemediations

#endregion

#region Resource Group Status
# Get the resources in your resource group that are non-compliant to the policy assignments
$PolicyAssignments = Get-AzPolicyAssignment -Scope $ResourceGroup.ResourceId | Where-Object -FilterScript { $_.Name -match $(($DSCConfigurations).BaseName -join "|") }
$PolicyAssignments | ForEach-Object -Process {
    Get-AzPolicyState -ResourceGroupName $ResourceGroupName -PolicyAssignmentName $_.Name | Select-Object -Property PolicyDefinitionName, ComplianceState
}

#If you want to force an update on the compliance result you can use the following cmdlet instead of waiting for the next trigger : https://docs.microsoft.com/en-us/azure/governance/policy/how-to/get-compliance-data#evaluation-triggers.
Write-Host -Object "Starting Compliance Scan for '$ResourceGroupName' Resource Group ..."
$PolicyComplianceScanJob = Start-AzPolicyComplianceScan -ResourceGroupName $ResourceGroupName -Verbose -AsJob

#Get latest non-compliant policy states summary in resource group scope
Get-AzPolicyStateSummary -ResourceGroupName $ResourceGroupName | Select-Object -ExpandProperty PolicyAssignments

$PolicyComplianceScanJob | Receive-Job -Wait -AutoRemoveJob
#endregion
#endregion