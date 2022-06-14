#requires -Version 7 -RunAsAdministrator 

<#More info on 
- https://docs.microsoft.com/en-us/azure/governance/policy/how-to/guest-configuration-create-setup
- https://techcommunity.microsoft.com/t5/microsoft-defender-for-cloud/7-steps-to-author-develop-and-deploy-custom-recommendations-for/ba-p/3166026
- https://cloudbrothers.info/en/azure-persistence-azure-policy-guest-configuration/
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
$VMName 	                    = "{0}ws2019" -f $ResourcePrefix
$ConfigurationName              = "FileServerBaseline"
$GuestConfigurationPackage      = "$CurrentDir\$ConfigurationName.zip"


#region Adding the GuestConfiguration extension
$VM = Get-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName
Set-AzVMExtension -Publisher 'Microsoft.GuestConfiguration' -Type 'ConfigurationforWindows' -Name 'AzurePolicyforWindows' -TypeHandlerVersion 1.0 -ResourceGroupName $ResourceGroupName -Location $Location -VMName $VMName -EnableAutomaticUpgrade $true
$VM | Update-AzVM -Verbose
#endregion


$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
$storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
# Creates a new resource group, storage account, and container
$storageAccount | New-AzStorageContainer -Name guestconfiguration -Permission Blob
$StorageAccountKey = (($storageAccount | Get-AzStorageAccountKey) | Where-Object -FilterScript {$_.KeyName -eq "key1"}).Value
$Context = New-AzStorageContext -ConnectionString "DefaultEndpointsProtocol=https;AccountName=$StorageAccountName;AccountKey=$StorageAccountKey"

Install-Module -Name PSDesiredStateConfiguration -AllowClobber -Force
& "$CurrentDir\AzureGuestDSCConfiguration.ps1"
New-GuestConfigurationPackage -Name $ConfigurationName  -Path $CurrentDir -Configuration $CurrentDir\LocalRegistry\localhost.mof -Type AuditAndSet -Force
Get-GuestConfigurationPackageComplianceStatus -Path $GuestConfigurationPackage
#Start-GuestConfigurationPackageRemediation -Path $GuestConfigurationPackage -Verbose
Get-GuestConfigurationPackageComplianceStatus -Path $GuestConfigurationPackage

#$ContentURI = (Publish-GuestConfigurationPackage -Path $GuestConfigurationPackage -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -Force).ContentUri
Set-AzStorageBlobContent -Container "guestconfiguration" -File $GuestConfigurationPackage -Blob "guestconfiguration" -Context $Context
$ContentURI = New-AzStorageBlobSASToken -Context $Context -FullUri -Container guestconfiguration -Blob "guestconfiguration" -Permission rwd

Remove-AzPolicyAssignment -Name "$($ConfigurationName)Assignment" -Scope $ResourceGroup.ResourceId -Verbose
Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq $ConfigurationName } | Remove-AzPolicyDefinition -Force

$Guid = (New-Guid).Guid

Remove-Item -Path '.\policies' -Recurse -Force -ErrorAction Ignore
New-GuestConfigurationPolicy -PolicyId $Guid -ContentUri $ContentURI -DisplayName $ConfigurationName -Description 'Compliance check for File Server Baseline' -Path './policies' -Platform 'Windows' -PolicyVersion $([System.Version]::Parse("1.0.0")) -Mode 'ApplyAndAutoCorrect' -Verbose
$Policy = Get-ChildItem -Path '.\policies' -Filter "$($ConfigurationName)*.json" -File
New-AzPolicyDefinition -Name $ConfigurationName -Policy $Policy
#Publish-GuestConfigurationPolicy -Path '.\policies' -Verbose

#From https://docs.microsoft.com/en-us/azure/governance/policy/assign-policy-powershell
# Register the resource provider if it's not already registered
Register-AzResourceProvider -ProviderNamespace 'Microsoft.PolicyInsights'

# Get a reference to the built-in policy definition to assign
#s$definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq $ConfigurationName }
$definition = Get-AzPolicyDefinition | Where-Object { $_.Name -eq $ConfigurationName }

# Create the policy assignment with the built-in definition against your resource group
$NonComplianceMessage = [Microsoft.Azure.Commands.ResourceManager.Cmdlets.Entities.Policy.NonComplianceMessage]::new()
$NonComplianceMessage.message = "Non Compliance Message"
$IncludeArcConnectedServers = @{'IncludeArcMachines'='true'}
#$PolicyAssignment = New-AzPolicyAssignment -Name 'auditandset-fileserverbaseline' -DisplayName $ConfigurationName -Scope $ResourceGroup.ResourceId -PolicyDefinition $definition -Location $Location -PolicyParameterObject $IncludeArcConnectedServers -IdentityType "SystemAssigned" -NonComplianceMessage $NonComplianceMessage  
$PolicyAssignment = New-AzPolicyAssignment -Name "$($ConfigurationName)Assignment" -DisplayName $ConfigurationName -Scope $ResourceGroup.ResourceId -PolicyDefinition $definition -Location $Location -PolicyParameterObject $IncludeArcConnectedServers -IdentityType "SystemAssigned" -NonComplianceMessage $NonComplianceMessage  

# Get the resources in your resource group that are non-compliant to the policy assignment
Get-AzPolicyState -ResourceGroupName $ResourceGroupName -PolicyAssignmentName "$($ConfigurationName)Assignment" #-Filter 'IsCompliant eq false'