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
#requires -Version 5 -Modules Az.Accounts, Az.Network, Az.Resources, Az.Storage

#From https://learn.microsoft.com/en-us/azure/developer/terraform/store-state-in-azure-storage?tabs=powershell

#region function definitions
function Install-Terraform {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
    )

    #region Terraform Setup
    #region Downloading Terraform 
    if (terraform -v) {
        Write-Host -Object "Terraform is already installed"
    }
    else {
        if (winget) {
            Write-Host -Object "Installing Terraform with winget"
            winget install --exact --id=Hashicorp.Terraform --silent --accept-package-agreements --accept-source-agreements
        }
        else {
            Write-Host -Object "Installing Terraform from GitHub"
            $LatestTerraformBuild = (((Invoke-RestMethod  -Uri "https://api.releases.hashicorp.com/v1/releases/terraform")) | Where-Object -FilterScript { -not($_.is_prerelease) }) | Select-Object -Property version -ExpandProperty builds | Where-Object -FilterScript { ($_.arch -eq "amd64") -and ($_.os -eq "windows") } | Sort-Object -Property version -Descending | Select-Object -First 1
            $LatestTerraformZipURI = $LatestTerraformBuild.url
            $OutFile = Join-Path -Path $env:TEMP -ChildPath $(Split-Path -Path $LatestTerraformBuild.url -Leaf)
            Invoke-WebRequest -Uri $LatestTerraformBuild.url -OutFile $OutFile

            $DestinationPath = Join-Path -Path "C:\terraform" -ChildPath "terraform_$($LatestTerraformBuild.version)"
            Expand-Archive -Path $OutFile -DestinationPath $DestinationPath

            Write-Host -Object "Setting Terraform Path Environment Variable..."
            $env:PATH = "$($DestinationPath);$env:PATH"
            [System.Environment]::SetEnvironmentVariable('PATH', $env:PATH, 'Machine')    
            $null = Remove-Item $OutFile, $DestinationPath -Recurse -Force
        }
        Write-Host -Object "Finished Installing Terraform..."
    }
    #endregion
}

function New-AzTerraformStateStorageAccountDemo {
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
    $Project = "tf"
    $Role = "state"
    $TFRole = "sample"
    #$DigitNumber = 4
    $DigitNumber = $AzureVMNameMaxLength - ($VirtualMachinePrefix + $Project + $Role + $LocationShortName).Length
    $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
    $ResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
    $TFResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $TFRole, $LocationShortName, $Instance                       
    $StorageAccountName = "{0}{1}{2}{3}{4:D$DigitNumber}" -f $StorageAccountPrefix, $Project, $Role, $LocationShortName, $Instance                       
    $ResourceGroupName = $ResourceGroupName.ToLower()
    $StorageAccountName = $StorageAccountName.ToLower()
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
    #endregion

    #region Maint.tf Management
    $MainTerraformTemplatePath = Join-Path -Path $PSScriptRoot -ChildPath "template_main.tf"
    $WorkingDir = New-Item -Path $(Join-Path -Path $PSScriptRoot -ChildPath $ResourceGroupName) -ItemType Directory -Force
    Write-Verbose -Message "`$WorkingDir: $WorkingDir"
    $MainTerraformPath = Join-Path -Path $WorkingDir -ChildPath "main.tf"
    Write-Verbose -Message "`$MainTerraformTemplatePath: $MainTerraformTemplatePath"
    Copy-Item -Path $MainTerraformTemplatePath -Destination $MainTerraformPath -Force

    ((Get-Content -Path $MainTerraformPath -Raw) -replace '<location>', $Location) | Set-Content -Path $MainTerraformPath
    ((Get-Content -Path $MainTerraformPath -Raw) -replace '<storage_account_name>', $StorageAccountName) | Set-Content -Path $MainTerraformPath
    ((Get-Content -Path $MainTerraformPath -Raw) -replace '<resource_group_name>', $ResourceGroupName) | Set-Content -Path $MainTerraformPath
    ((Get-Content -Path $MainTerraformPath -Raw) -replace '<tf_resource_group_name>', $TFResourceGroupName) | Set-Content -Path $MainTerraformPath
    ((Get-Content -Path $MainTerraformPath -Raw) -replace '<container_name>', $ContainerName) | Set-Content -Path $MainTerraformPath
    #endregion

    #region Terraform Setup
    Install-Terraform
    #endregion

    #region Terraform
    terraform -chdir="$($WorkingDir.FullName)" init
    terraform -chdir="$($WorkingDir.FullName)" apply -auto-approve
    #endregion

    if ($Destroy) {
        Write-Verbose -Message "`Destroying resources"
        $null = Remove-Item $WorkingDir -Recurse -Force
        terraform -chdir="$($WorkingDir.FullName)" destroy -auto-approve
    }
}

#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

#region Demo for a Terraform State on a StorageAccount
New-AzTerraformStateStorageAccountDemo -Verbose
#endregion

<#
#region Cleaning
#Cleaning Up the Resource Groups
Get-AzResourceGroup rg-tf-state-* | Remove-AzResourceGroup -AsJob -Force
Get-AzResourceGroup rg-tf-sample-* | Remove-AzResourceGroup -AsJob -Force
#endregion
#>
#endregion
