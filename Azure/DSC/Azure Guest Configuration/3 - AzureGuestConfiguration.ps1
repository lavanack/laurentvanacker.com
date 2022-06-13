#requires -Version 7 -RunAsAdministrator 

<#More info on 
- https://docs.microsoft.com/en-us/azure/governance/policy/how-to/guest-configuration-create-setup
- https://techcommunity.microsoft.com/t5/microsoft-defender-for-cloud/7-steps-to-author-develop-and-deploy-custom-recommendations-for/ba-p/3166026
#>

Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent


$Location                       = "EastUs"
$ResourcePrefix                 = "dscazgcfg"
#$resourceGroupName            = (Get-AzVM -Name $env:COMPUTERNAME).ResourceGroupName
$ResourceGroupName              = "$ResourcePrefix-rg-$Location"
$StorageAccountName             = "{0}sa" -f $ResourcePrefix # Name must be unique. Name availability can be check using PowerShell command Get-AzStorageAccountNameAvailability -Name ""
$ConfigurationName              = "FileServerBaseline"
$GuestConfigurationPackage      = "$CurrentDir\$ConfigurationName\$ConfigurationName.zip"

$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
$storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
# Creates a new resource group, storage account, and container
$storageAccount | New-AzStorageContainer -Name guestconfiguration -Permission Blob

& "$CurrentDir\AzureGuestDSCConfiguration.ps1"
New-GuestConfigurationPackage -Name $ConfigurationName  -Path $CurrentDir -Configuration $CurrentDir\LocalRegistry\localhost.mof -Type AuditAndSet -Force
Get-GuestConfigurationPackageComplianceStatus -Path $GuestConfigurationPackage
Start-GuestConfigurationPackageRemediation -Path $GuestConfigurationPackage -Verbose
Get-GuestConfigurationPackageComplianceStatus -Path $GuestConfigurationPackage

$SASURLSignature = (Publish-GuestConfigurationPackage -Path $GuestConfigurationPackage -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -Force).ContentUri

Remove-AzPolicyAssignment -Name "$($ConfigurationName)Assignment" -Scope $ResourceGroup.ResourceId
Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq $ConfigurationName } | Remove-AzPolicyDefinition -Force

$Guid = (New-Guid).Guid

New-GuestConfigurationPolicy -PolicyId $Guid -ContentUri $SASURLSignature -DisplayName $ConfigurationName -Description 'Compliance check for File Server Baseline' -Path './policies' -Platform 'Windows' -Version 1.0.0 -Mode 'ApplyAndAutoCorrect' -Verbose
Publish-GuestConfigurationPolicy -Path '.\policies' -Verbose

#From https://docs.microsoft.com/en-us/azure/governance/policy/assign-policy-powershell
# Register the resource provider if it's not already registered
Register-AzResourceProvider -ProviderNamespace 'Microsoft.PolicyInsights'

# Get a reference to the built-in policy definition to assign
#s$definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq $ConfigurationName }
$definition = Get-AzPolicyDefinition | Where-Object { $_.Name -eq $Guid }

# Create the policy assignment with the built-in definition against your resource group
$NonComplianceMessage = [Microsoft.Azure.Commands.ResourceManager.Cmdlets.Entities.Policy.NonComplianceMessage]::new()
$NonComplianceMessage.message = "Non Compliance Message"
$IncludeArcConnectedServers = @{'IncludeArcMachines'='True'}
#$PolicyAssignment = New-AzPolicyAssignment -Name 'auditandset-fileserverbaseline' -DisplayName $ConfigurationName -Scope $ResourceGroup.ResourceId -PolicyDefinition $definition -Location $Location -PolicyParameterObject $IncludeArcConnectedServers -IdentityType "SystemAssigned" -NonComplianceMessage $NonComplianceMessage  
$PolicyAssignment = New-AzPolicyAssignment -Name "$($ConfigurationName)Assignment" -DisplayName $ConfigurationName -Scope $ResourceGroup.ResourceId -PolicyDefinition $definition -Location $Location -PolicyParameterObject $IncludeArcConnectedServers -IdentityType "SystemAssigned" -NonComplianceMessage $NonComplianceMessage  

# Get the resources in your resource group that are non-compliant to the policy assignment
Get-AzPolicyState -ResourceGroupName $ResourceGroupName -PolicyAssignmentName "$($ConfigurationName)Assignment" #-Filter 'IsCompliant eq false'