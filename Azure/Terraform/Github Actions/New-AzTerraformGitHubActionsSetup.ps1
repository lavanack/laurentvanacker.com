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
#requires -Version 5 -Modules Az.Accounts, Az.ManagedServiceIdentity, Az.Network, Az.Resources, Az.Storage

#From https://learn.microsoft.com/en-us/azure/developer/terraform/store-state-in-azure-storage?tabs=powershell
#From https://www.linkedin.com/pulse/d%C3%A9ployer-sur-azure-avec-terraform-et-github-actions-philippe-paven-enwxe/

#region function definitions
function New-AzTerraformGitHubActionsSetup {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [ValidateScript({ $_ -in (Get-AzLocation).Location })]
        [string] $Location = "eastus2",
        [switch] $Destroy
    )

    #region Defining variables 
    #region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
    $AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
    $ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
    $ResourceLocationShortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
    #endregion

    #region Building an Hashtable to get the shortname of every Azure resource based on a JSON file on the Github repository of the Azure Naming Tool
    $Result = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/refs/heads/main/src/repository/resourcetypes.json 
    $ResourceTypeShortNameHT = $Result | Where-Object -FilterScript { $_.property -in @('', 'Windows') } | Select-Object -Property resource, shortName, lengthMax | Group-Object -Property resource -AsHashTable -AsString
    #endregion

    #region Variables
    $LocationShortName = $ResourceLocationShortNameHT[$Location].shortName
    #Naming convention based on https://github.com/mspnp/AzureNamingTool/blob/main/src/repository/resourcetypes.json
    $AzureVMNameMaxLength = $ResourceTypeShortNameHT["Compute/virtualMachines"].lengthMax
    $ResourceGroupPrefix = $ResourceTypeShortNameHT["Resources/resourcegroups"].ShortName
    $StorageAccountPrefix = $ResourceTypeShortNameHT["Storage/storageAccounts"].ShortName
    $UserAssignedIdentityPrefix = $ResourceTypeShortNameHT["ManagedIdentity/userAssignedIdentities"].ShortName
    $Project = "tf"
    $Role = "ghact"
    $TFRole = "sample"
    #$DigitNumber = 4
    $DigitNumber = $AzureVMNameMaxLength - ($VirtualMachinePrefix + $Project + $Role + $LocationShortName).Length
    $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
    $ResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
    $TFResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $TFRole, $LocationShortName, $Instance                       
    $StorageAccountName = "{0}{1}{2}{3}{4:D$DigitNumber}" -f $StorageAccountPrefix, $Project, $Role, $LocationShortName, $Instance                       
    $UserAssignedIdentityName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $UserAssignedIdentityPrefix, $Project, $Role, $LocationShortName, $Instance                       
    $ResourceGroupName = $ResourceGroupName.ToLower()
    $TFResourceGroupName = $TFResourceGroupName.ToLower()
    $StorageAccountName = $StorageAccountName.ToLower()
    $UserAssignedIdentityName = $UserAssignedIdentityName.ToLower()
    #endregion
    #endregion

    #region Configure ResourceGroup
    if (Get-AzResourceGroup -Name $ResourceGroupName -Location $Location -ErrorAction Ignore) {
        Write-Verbose -Message "Removing '$ResourceGroupName' Resource Group Name ..."
        Remove-AzResourceGroup -Name $ResourceGroupName -Force
    }
    Write-Verbose -Message "Creating '$ResourceGroupName' Resource Group Name ..."
    $StorageResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
    #endregion

    #region Configure remote state storage account
    $StorageAccountSkuName = "Standard_LRS"
    $ContainerName = 'tfstate'
    # Create storage account
    $StorageAccount = New-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -Location $Location -SkuName $StorageAccountSkuName -MinimumTlsVersion TLS1_2 -EnableHttpsTrafficOnly $true  -AllowBlobPublicAccess $true
    # Create blob container
    $StorageContext = $StorageAccount.Context
    $StorageContainer = New-AzStorageContainer -Name $ContainerName -Context $StorageContext
    $StorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName | Select-Object -First 1).value
    #$env:ARM_ACCESS_KEY = $StorageAccountKey
    #endregion

    #region Maint.tf Management
    $MainTerraformTemplatePath = Join-Path -Path $PSScriptRoot -ChildPath "template_main.tf"
    $WorkingDir = New-Item -Path $(Join-Path -Path $PSScriptRoot -ChildPath $ResourceGroupName) -ItemType Directory -Force
    Write-Verbose -Message "`$WorkingDir: $WorkingDir"
    $MainTerraformPath = Join-Path -Path $WorkingDir -ChildPath "main.tf"
    Write-Verbose -Message "`$MainTerraformTemplatePath: $MainTerraformTemplatePath"
    Copy-Item -Path $MainTerraformTemplatePath -Destination $MainTerraformPath -Force

    ((Get-Content -Path $MainTerraformPath -Raw) -replace '<location>', $Location) | Set-Content -Path $MainTerraformPath
    ((Get-Content -Path $MainTerraformPath -Raw) -replace '<backend_storage_account_name>', $StorageAccountName) | Set-Content -Path $MainTerraformPath
    ((Get-Content -Path $MainTerraformPath -Raw) -replace '<backend_resource_group_name>', $ResourceGroupName) | Set-Content -Path $MainTerraformPath
    ((Get-Content -Path $MainTerraformPath -Raw) -replace '<resource_group_name>', $TFResourceGroupName) | Set-Content -Path $MainTerraformPath
    ((Get-Content -Path $MainTerraformPath -Raw) -replace '<backend_container_name>', $ContainerName) | Set-Content -Path $MainTerraformPath
    #endregion

    #region User Assigned Managed Identity
    $UserAssignedIdentity = New-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $UserAssignedIdentityName -Location $Location

    #region 'Owner' RBAC Assignment
    $SubscriptionId = $((Get-AzContext).Subscription.Id)
    $RoleDefinition = Get-AzRoleDefinition -Name "Owner"
    $Scope = "/subscriptions/$SubscriptionId"

    $Parameters = @{
        ObjectId           = $UserAssignedIdentity.PrincipalId
        RoleDefinitionName = $RoleDefinition.Name
        Scope              = $Scope
    }

    While (-not(Get-AzRoleAssignment @Parameters)) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.ObjectId)' Identity on the '$($Parameters.Scope)' scope"
        $RoleAssignment = New-AzRoleAssignment @Parameters
        Write-Verbose -Message "`$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
        Start-Sleep -Seconds 30
    }
    #endregion

    #endregion

    #region Federated identity credential
    #$GitHubRepoURI = "https://github.com/lavanack/laurentvanacker.com"
    $GitHubRepoURI = (git remote get-url origin) -replace ".git$"
    $Tokens = $GitHubRepoURI -split "/"
    $GitHubUserName = $Tokens[-2]
    $GitHubRepoName = $Tokens[-1]
    $FederatedIdentityCredential = New-AzFederatedIdentityCredential -ResourceGroupName $ResourceGroupName -IdentityName $UserAssignedIdentity.Name -Name "terraform-github-env-poc" -Issuer "https://token.actions.githubusercontent.com" -Subject "repo:${gitHubUser}/${gitHubRepo}:environment:poc" -Audience @('api://AzureADTokenExchange')
    #endregion

    #region Github CLI Setup
    if (-not(gh)) {
        $GithubCLIURI = $(((Invoke-RestMethod -Uri "https://api.github.com/repos/cli/cli/releases/latest").assets | Where-Object -FilterScript { $_.name.EndsWith("windows_amd64.msi") }).browser_download_url)
        Start-BitsTransfer -Source $GithubCLIURI -Destination $Env:TEMP
        $LocatGithubCLIURI = Join-Path -Path $Env:TEMP -ChildPath $(Split-Path -Path $GithubCLIURI -Leaf)
        Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "msiexec /i $LocatGithubCLIURI /passive /norestart" -Wait
    }
    #endregion

    #region Github Secret Management
    $AzContext = Get-AzContext
    $SubscriptionId = $AzContext.Subscription.Id
    $TenantId = $AzContext.Tenant.Id
    gh secret set AZURE_CLIENT_ID --body $UserAssignedIdentity.ClientId
    gh secret set AZURE_SUBSCRIPTION_ID  --body $SubscriptionId
    gh secret set AZURE_TENANT_ID  --body $TenantId
    gh secret set BACKEND_AZURE_RESOURCE_GROUP_NAME --body $ResourceGroupName
    gh secret set BACKEND_AZURE_STORAGE_ACCOUNT_CONTAINER_NAME  --body $ContainerName
    gh secret set BACKEND_AZURE_STORAGE_ACCOUNT_NAME  --body $StorageAccountName
    gh secret set AZURE_OBJECT_ID --body $UserAssignedIdentity.PrincipalId

    #endregion

    #region Github Environement Management
    $null = gh api --method PUT -H "Accept: application/vnd.github+json" repos/$GitHubUserName/$GitHubRepoName/environments/dev
    #endregion
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
#region Demo for a Terraform State on a StorageAccount
New-AzTerraformGitHubActionsSetup -Destroy -Verbose
#endregion

<#
#region Cleaning
#Cleaning Up the Resource Groups
Get-AzResourceGroup rg-tf-state-* | Remove-AzResourceGroup -AsJob -Force
Get-AzResourceGroup rg-tf-sample-* | Remove-AzResourceGroup -AsJob -Force
#endregion
#>
#endregion
