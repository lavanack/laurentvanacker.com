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
#requires -Version 5 -Modules Az.Accounts, Az.Compute, Az.KeyVault, Az.Network, Az.Resources, Az.Storage, Az.Security, ThreadJob

[CmdletBinding()]
param
(
    [int] $VMNumber = 25,
    [switch] $JIT
)

#region function definitions 
#Based from https://adamtheautomator.com/powershell-random-password/
function New-RandomPassword {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [int] $minLength = 12, ## characters
        [int] $maxLength = 15, ## characters
        [int] $nonAlphaChars = 3,
        [switch] $AsSecureString,
        [switch] $ClipBoard
    )

    Add-Type -AssemblyName 'System.Web'
    $length = Get-Random -Minimum $minLength -Maximum $maxLength
    $RandomPassword = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
    Write-Host "The password is : $RandomPassword"
    if ($ClipBoard) {
        Write-Verbose "The password has beeen copied into the clipboard (Use Win+V) ..."
        $RandomPassword | Set-Clipboard
    }
    if ($AsSecureString) {
        ConvertTo-SecureString -String $RandomPassword -AsPlainText -Force
    }
    else {
        $RandomPassword
    }
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

# Login to your Azure subscription.
While (-not(Get-AzContext)) {
    Connect-AzAccount
}

$AzureVMNameMaxLength = 15
$RDPPort = 3389
$JitPolicyTimeInHours = 3
$JitPolicyName = "Default"
$Location = "eastus2"
$VMSize = "Standard_D8as_v5"
$LocationShortName = $shortNameHT[$Location].shortName
#Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
$KeyVaultPrefix = "kv"
$ResourceGroupPrefix = "rg"
$StorageAccountPrefix = "sa"
$VirtualMachinePrefix = "vm"
$NetworkSecurityGroupPrefix = "nsg"
$VirtualNetworkPrefix = "vnet"
$SubnetPrefix = "snet"
$DiskEncryptionSetPrefix = "des"
$DiskEncryptionKeyPrefix = "dek"

$Project = "kv"
$Role = "de"
#$DigitNumber = 4
$DigitNumber = $AzureVMNameMaxLength - ($VirtualMachinePrefix + $Project + $Role + $LocationShortName).Length
$Maximum = [long]([Math]::Pow(10, $DigitNumber))

Do {
    $Instance = Get-Random -Minimum 0 -Maximum $Maximum
    $StorageAccountName = "{0}{1}{2}{3}{4:D$DigitNumber}" -f $StorageAccountPrefix, $Project, $Role, $LocationShortName, $Instance                       
    $VMName = "{0}{1}{2}{3}{4:D$DigitNumber}" -f $VirtualMachinePrefix, $Project, $Role, $LocationShortName, $Instance                       
    $KeyVaultName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $KeyVaultPrefix, $Project, $Role, $LocationShortName, $Instance                       
    $KeyVaultName = $KeyVaultName.ToLower()
} While ((-not(Test-AzDnsAvailability -DomainNameLabel $VMName -Location $Location)) -or (-not(Get-AzStorageAccountNameAvailability -Name $StorageAccountName).NameAvailable) -or (-not(Test-AzKeyVaultNameAvailability -Name $KeyVaultName).NameAvailable))

$Index = 1
$CurrentInstance = $Instance + 1
$VMNames = @($VMName)
While ($Index -lt $VMNumber) {
    $CurrentVMName = "{0}{1}{2}{3}{4:D$DigitNumber}" -f $VirtualMachinePrefix, $Project, $Role, $LocationShortName, $CurrentInstance                       
    if (Test-AzDnsAvailability -DomainNameLabel $CurrentVMName -Location $Location) {
        $VMNames += $CurrentVMName 
        $Index++
    }
    $CurrentInstance = ($CurrentInstance + 1) % $Maximum
}

                         
$NetworkSecurityGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $NetworkSecurityGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
$VirtualNetworkName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $VirtualNetworkPrefix, $Project, $Role, $LocationShortName, $Instance                       
$SubnetName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $SubnetPrefix, $Project, $Role, $LocationShortName, $Instance                       
$ResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
$TargetResourceGroupName = "{0}-dest" -f $ResourceGroupName                    
$DiskEncryptionSetName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $DiskEncryptionSetPrefix, $Project, $Role, $LocationShortName, $Instance                       
$DiskEncryptionKeyName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $DiskEncryptionKeyPrefix, $Project, $Role, $LocationShortName, $Instance

$StorageAccountName = $StorageAccountName.ToLower()
$VMName = $VMName.ToLower()
$NetworkSecurityGroupName = $NetworkSecurityGroupName.ToLower()
$VirtualNetworkName = $VirtualNetworkName.ToLower()
$SubnetName = $SubnetName.ToLower()
$ResourceGroupName = $ResourceGroupName.ToLower()
$VirtualNetworkAddressSpace = "10.10.0.0/16" # Format 10.10.0.0/16
$SubnetIPRange = "10.10.1.0/24" # Format 10.10.1.0/24                         
$DiskEncryptionKeyDestination = "Software"


#region Defining credential(s)
$Username = $env:USERNAME
#$ClearTextPassword = 'I@m@JediLikeMyF@therB4Me'
#$ClearTextPassword = New-RandomPassword -ClipBoard -Verbose
#$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$SecurePassword = New-RandomPassword -ClipBoard -AsSecureString -Verbose
$Credential = New-Object System.Management.Automation.PSCredential -ArgumentList ($Username, $SecurePassword)
#endregion

#region Azure Provider Registration
#To use Azure Virtual Desktop, you have to register for the providers and to ensure that RegistrationState will be set to Registered.
#$RequiredResourceProviders = "Microsoft.ContainerInstance", "Microsoft.DesktopVirtualization", "Microsoft.Insights", "Microsoft.VirtualMachineImages", "Microsoft.Storage", "Microsoft.Compute", "Microsoft.KeyVault", "Microsoft.ManagedIdentity"
$RequiredResourceProviders = "Microsoft.Compute/EncryptionAtHost"
$RequiredPreviewResourceProviders = $RequiredResourceProviders | Where-Object -FilterScript { $_ -match "preview|/" }
$RequiredNonPreviewResourceProviders = $RequiredResourceProviders | Where-Object -FilterScript { $_ -notin $RequiredPreviewResourceProviders }

#region Non-preview Resource Providers
$Jobs = foreach ($CurrentRequiredNonPreviewResourceProviders in $RequiredNonPreviewResourceProviders) {
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Registering '$CurrentRequiredNonPreviewResourceProviders' Resource Provider"
    try {
        Register-AzResourceProvider -ProviderNamespace $CurrentRequiredNonPreviewResourceProviders -ErrorAction Stop -AsJob
    }
    catch {
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "Unable to register '$CurrentRequiredNonPreviewResourceProviders' Resource Provider"
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
        Write-Warning -Message "Message: $($_.Exception.Message)"
    }
}
Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Waiting for the 'Register-AzResourceProvider' job to finish"
$Result = $Jobs | Receive-Job -Wait -AutoRemoveJob -ErrorAction Ignore
Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The Waiting is over for the 'Register-AzResourceProvider' job"
$NonRegisteredProviders = ($Result | Where-Object -FilterScript { $_.RegistrationState -ne "Registered" }).ProviderNamespace
if ($NonRegisteredProviders) {
    Write-Warning -Message "The following resource providers were NOT registered: $($NonRegisteredProviders -join ', ')"
}
#endregion

#region Preview Resource Providers
foreach ($CurrentRequiredPreviewResourceProvider in $RequiredPreviewResourceProviders) {
    $ProviderNamespace, $FeatureName = $CurrentRequiredPreviewResourceProvider -split "/"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] ProviderNamespace: `$ProviderNamespace: $ProviderNamespace"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] ProviderNamespace: `$FeatureName: $FeatureName"
    $FeatureStatus = (Get-AzProviderFeature -ProviderNamespace $ProviderNamespace -FeatureName $FeatureName).RegistrationState
    if ($FeatureStatus -ne "Registered") {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Registering '$RequiredPreviewResourceProviders' Resource Provider"
        Register-AzProviderFeature -ProviderNamespace $ProviderNamespace -FeatureName $FeatureName
        Do {
            $FeatureStatus = (Get-AzProviderFeature -ProviderNamespace $ProviderNamespace -FeatureName $FeatureName).RegistrationState
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Waiting for '$CurrentRequiredPreviewResourceProvider' Resource Providers to be registered ... Waiting 10 seconds"
            Start-Sleep -Seconds 10
        } until ($FeatureStatus -eq "Registered")
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The Wait is over for registration of the '$CurrentRequiredPreviewResourceProvider' Resource Provider"
    }
    else {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$CurrentRequiredPreviewResourceProvider' Resource Provider is already registered"
    }

}
#endregion
#endregion

$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
if ($ResourceGroup) {
    #Step 0: Remove previously existing Azure Resource Group with the same name
    $ResourceGroup | Remove-AzResourceGroup -Force -Verbose
}
$TargetResourceGroup = Get-AzResourceGroup -Name $TargetResourceGroupName -ErrorAction Ignore 
if ($ResourceGroup) {
    #Step 0: Remove previously existing Azure Resource Group with the same name
    $TargetResourceGroup | Remove-AzResourceGroup -Force -Verbose
}

$MyPublicIp = (Invoke-WebRequest -Uri "https://ipv4.seeip.org").Content

#region Define Variables needed for Virtual Machine
$ImagePublisherName = "MicrosoftWindowsServer"
$ImageOffer = "WindowsServer"
$ImageSku = "2022-datacenter-g2"
$OSDiskSize = "127"
$StorageAccountSkuName = "Standard_LRS"
$OSDiskType = "StandardSSD_LRS"

Write-Verbose "`$VMNumber: $VMNumber"         
Write-Verbose "`$NetworkSecurityGroupName: $NetworkSecurityGroupName"         
Write-Verbose "`$VirtualNetworkName: $VirtualNetworkName"         
Write-Verbose "`$SubnetName: $SubnetName"       
Write-Verbose "`$ResourceGroupName: $ResourceGroupName"
#endregion
#endregion


if ($VMName.Length -gt $AzureVMNameMaxLength) {
    Write-Error "'$VMName' exceeds $AzureVMNameMaxLength characters" -ErrorAction Stop
}
elseif (-not($LocationShortName)) {
    Write-Error "No location short name found for '$Location'" -ErrorAction Stop
}
elseif ($null -eq (Get-AzVMSize -Location $Location | Where-Object -FilterScript { $_.Name -eq $VMSize })) {
    Write-Error "The '$VMSize' is not available in the '$Location' location ..." -ErrorAction Stop
}

#Step 1: Create Azure Resource Group
# Create Resource Groups
$ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
$TargetResourceGroup = New-AzResourceGroup -Name $TargetResourceGroupName -Location $Location -Force

#Step 2: Create Azure Storage Account
$StorageAccount = New-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -Location $Location -SkuName $StorageAccountSkuName -MinimumTlsVersion TLS1_2 -EnableHttpsTrafficOnly $true

#Step 3: Create Azure Network Security Group
#RDP only for my public IP address
$SecurityRules = @(
    #region Inbound
    #RDP only for my public IP address
    New-AzNetworkSecurityRuleConfig -Name RDPRule -Description "Allow RDP" -Access Allow -Protocol Tcp -Direction Inbound -Priority 300 -SourceAddressPrefix $MyPublicIp -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange $RDPPort
    #HTTP only for my public IP address
    New-AzNetworkSecurityRuleConfig -Name HTTPRule -Description "Allow HTTP" -Access Allow -Protocol Tcp -Direction Inbound -Priority 301 -SourceAddressPrefix $MyPublicIp -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 80
    #HTTPS only for my public IP address
    New-AzNetworkSecurityRuleConfig -Name HTTPSRule -Description "Allow HTTPS" -Access Allow -Protocol Tcp -Direction Inbound -Priority 302 -SourceAddressPrefix $MyPublicIp -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 443
    #endregion
)

$NetworkSecurityGroup = New-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Location $Location -Name $NetworkSecurityGroupName -SecurityRules $SecurityRules -Force

#Steps 4 + 5: Create Azure Virtual network using the virtual network subnet configuration
$VirtualNetwork = New-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VirtualNetworkName  -AddressPrefix $VirtualNetworkAddressSpace -Location $Location
Add-AzVirtualNetworkSubnetConfig -Name $SubnetName -VirtualNetwork $VirtualNetwork -AddressPrefix $SubnetIPRange -NetworkSecurityGroupId $NetworkSecurityGroup.Id

$VirtualNetwork = Set-AzVirtualNetwork -VirtualNetwork $VirtualNetwork
$Subnet = Get-AzVirtualNetworkSubnetConfig -Name $SubnetName -VirtualNetwork $VirtualNetwork

#region Setting up the Key Vault for Disk Encryption
#Create an Azure Key Vault
$KeyVault = New-AzKeyVault -VaultName $KeyVaultName -ResourceGroup $ResourceGroupName -Location $Location -EnabledForDiskEncryption -EnablePurgeProtection
#region 'Key Vault Administrator' RBAC Assignment
$KeyVaultAdministratorRole = Get-AzRoleDefinition "Key Vault Administrator"
While (-not(Get-AzRoleAssignment -SignInName $((Get-AzContext).Account.Id) -RoleDefinitionName $KeyVaultAdministratorRole.Name -Scope $KeyVault.ResourceId)) {
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($KeyVaultAdministratorRole.Name)' RBAC role to the '$((Get-AzContext).Account.Id)' user on the '$($HostPoolKeyVault.ResourceId)' KeyVault"
    $null = New-AzRoleAssignment -SignInName $((Get-AzContext).Account.Id) -RoleDefinitionName $KeyVaultAdministratorRole.Name -Scope $KeyVault.ResourceId
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
    Start-Sleep -Seconds 30
}
#endregion 
#FROM https://learn.microsoft.com/en-us/azure/virtual-machines/windows/disks-enable-customer-managed-keys-powershell#set-up-an-azure-key-vault-and-diskencryptionset-optionally-with-automatic-key-rotation
$key = Add-AzKeyVaultKey -VaultName $keyVaultName -Name $DiskEncryptionKeyName -Destination $DiskEncryptionKeyDestination
$DiskEncryptionSetConfig = New-AzDiskEncryptionSetConfig -Location $Location -SourceVaultId $keyVault.ResourceId -KeyUrl $key.Key.Kid -IdentityType SystemAssigned -RotationToLatestKeyVersionEnabled $true
$DiskEncryptionSet = New-AzDiskEncryptionSet -Name $DiskEncryptionSetName -ResourceGroupName $ResourceGroupName -InputObject $DiskEncryptionSetConfig
#region 'Key Vault Administrator' RBAC Assignment
$KeyVaultAdministratorRole = Get-AzRoleDefinition "Key Vault Administrator"
While (-not(Get-AzRoleAssignment -ObjectId $DiskEncryptionSet.Identity.PrincipalId -RoleDefinitionName $KeyVaultAdministratorRole.Name -Scope $KeyVault.ResourceId)) {
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($KeyVaultAdministratorRole.Name)' RBAC role to the '$((Get-AzContext).Account.Id)' user on the '$($HostPoolKeyVault.ResourceId)' KeyVault"
    $null = New-AzRoleAssignment -ObjectId $DiskEncryptionSet.Identity.PrincipalId -RoleDefinitionName $KeyVaultAdministratorRole.Name -Scope $KeyVault.ResourceId
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
    Start-Sleep -Seconds 30
}
#endregion 
#$AccessPolicy = Set-AzKeyVaultAccessPolicy -VaultName $keyVaultName -ObjectId $DiskEncryptionSet.Identity.PrincipalId -PermissionsToKeys wrapKey, unwrapKey, get -PassThru

#As the owner of the key vault, you automatically have access to create secrets. If you need to let another user create secrets, use:
#$UserPrincipalName = (Get-AzContext).Account.Id
#$AccessPolicy = Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -UserPrincipalName $UserPrincipalName -PermissionsToSecrets Get,Delete,List,Set -PassThru
#$AccessPolicy = Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -UserPrincipalName $UserPrincipalName -PermissionsToKeys wrapKey, unwrapKey, get -PassThru
#endregion 

$Index=0
$Jobs = foreach ($CurrentVMName in $VMNames) {
    $Index++
    $PercentComplete = $Index/$VMNames.Count*100
    Write-Progress -Activity "[$($Index)/$($VMNames.Count)] Creating VMs ..." -CurrentOperation "Processing '$CurrentVMName' VM ..." -Status $('{0:N0}%' -f $PercentComplete) -PercentComplete $PercentComplete
    $NICName = "nic-$CurrentVMName"
    $OSDiskName = '{0}_OSDisk' -f $CurrentVMName
    $DataDiskName = '{0}_DataDisk' -f $CurrentVMName
    $PublicIPName = "pip-$CurrentVMName" 
    Write-Verbose "`$CurrentVMName: $CurrentVMName"
    Write-Verbose "`$NICName: $NICName"
    Write-Verbose "`$OSDiskName: $OSDiskName"
    Write-Verbose "`$DataDiskName: $DataDiskName"
    Write-Verbose "`$PublicIPName: $PublicIPName"
    #Step 6: Create Azure Public Address
    $PublicIP = New-AzPublicIpAddress -Name $PublicIPName -ResourceGroupName $ResourceGroupName -Location $Location -AllocationMethod Static -DomainNameLabel $CurrentVMName.ToLower()

    #Step 7: Create Network Interface Card 
    $NIC = New-AzNetworkInterface -Name $NICName -ResourceGroupName $ResourceGroupName -Location $Location -SubnetId $Subnet.Id -PublicIpAddressId $PublicIP.Id #-NetworkSecurityGroupId $NetworkSecurityGroup.Id

    <# Optional : Step 8: Get Virtual Machine publisher, Image Offer, Sku and Image
    $ImagePublisherName = Get-AzVMImagePublisher -Location $Location | Where-Object -FilterScript { $_.PublisherName -eq "MicrosoftWindowsDesktop"}
    $ImageOffer = Get-AzVMImageOffer -Location $Location -publisher $ImagePublisherName.PublisherName | Where-Object -FilterScript { $_.Offer  -eq "Windows-11"}
    $ImageSku = Get-AzVMImageSku -Location  $Location -publisher $ImagePublisherName.PublisherName -offer $ImageOffer.Offer | Where-Object -FilterScript { $_.Skus  -eq "win11-21h2-pro"}
    $image = Get-AzVMImage -Location  $Location -publisher $ImagePublisherName.PublisherName -offer $ImageOffer.Offer -sku $ImageSku.Skus | Sort-Object -Property Version -Descending | Select-Object -First 1
    #>

    # Step 9: Create a virtual machine configuration file #(As a Spot Intance)
    $VMConfig = New-AzVMConfig -VMName $CurrentVMName -VMSize $VMSize -IdentityType SystemAssigned -EncryptionAtHost -Priority "Spot" -MaxPrice -1

    $null = Add-AzVMNetworkInterface -VM $VMConfig -Id $NIC.Id

    # Set VM operating system parameters
    $null = Set-AzVMOperatingSystem -VM $VMConfig -Windows -ComputerName $CurrentVMName -Credential $Credential -ProvisionVMAgent -EnableAutoUpdate -PatchMode "AutomaticByPlatform"

    # Set boot diagnostic storage account
    #Set-AzVMBootDiagnostic -Enable -ResourceGroupName $ResourceGroupName -VM $VMConfig -StorageAccountName $StorageAccountName    
    # Set boot diagnostic to managed storage account
    $null = Set-AzVMBootDiagnostic -VM $VMConfig -Enable 

    # The uncommented lines below replace Step #8 : Set virtual machine source image
    $null = Set-AzVMSourceImage -VM $VMConfig -PublisherName $ImagePublisherName -Offer $ImageOffer -Skus $ImageSku -Version 'latest'

    # Set OsDisk configuration
    $null = Set-AzVMOSDisk -VM $VMConfig -Name $OSDiskName -DiskSizeInGB $OSDiskSize -StorageAccountType $OSDiskType -DiskEncryptionSetId $DiskEncryptionSet.Id -CreateOption fromImage


    #region Adding Data Disk
    $VMDataDisk01Config = New-AzDiskConfig -SkuName $OSDiskType -Location $Location -CreateOption Empty -DiskSizeGB 512
    $VMDataDisk01 = New-AzDisk -DiskName $DataDiskName -Disk $VMDataDisk01Config -ResourceGroupName $ResourceGroupName
    $VM = Add-AzVMDataDisk -VM $VMConfig -Name $DataDiskName -Caching 'ReadWrite' -CreateOption Attach -ManagedDiskId $VMDataDisk01.Id -Lun 0 -DiskEncryptionSetId $DiskEncryptionSet.Id
    #endregion

    #Step 10: Create Azure Virtual Machine
    New-AzVM -ResourceGroupName $ResourceGroupName -Location $Location -VM $VMConfig -AsJob
    #-DisableBginfoExtension
}

$Jobs | Receive-Job -Wait | Out-Null
$Jobs | Remove-Job -Force
# Complete the progress bar
Write-Progress -Completed -Activity "Completed"

#Read more: https://www.sharepointdiary.com/2021/11/progress-bar-in-powershell.html#ixzz8ZSpM7IHS

$Index=0
foreach ($CurrentVMName in $VMNames) {
    $FQDN = "$CurrentVMName.$Location.cloudapp.azure.com".ToLower()
    $Index++
    $PercentComplete = $Index/$VMNames.Count*100
    Write-Progress -Activity "[$($Index)/$($VMNames.Count)] Post-Creation activities ..." -CurrentOperation "Processing '$CurrentVMName' VM ..." -Status $('{0:N0}%' -f $PercentComplete) -PercentComplete $PercentComplete

    Write-Verbose "`$FQDN: $FQDN"
    $VM = Get-AzVM -ResourceGroup $ResourceGroupName -Name $CurrentVMName
    #Assign privilege to VM so it can access Azure key Vault. We do that by using VM’s System managed identity.
    #From https://ystatit.medium.com/azure-key-vault-with-azure-service-endpoints-and-private-link-part-1-bcc84b4c5fbc
    $AccessPolicy = Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -ObjectId $VM.Identity.PrincipalId -PermissionsToSecrets all -PermissionsToKeys all -PermissionsToCertificates all -PassThru

    #region JIT Access Management
    if ($JIT) {
        #region Enabling JIT Access
        $NewJitPolicy = (@{
                id    = $VM.Id
                ports = (@{
                        number                     = $RDPPort;
                        protocol                   = "*";
                        allowedSourceAddressPrefix = "*";
                        maxRequestAccessDuration   = "PT$($JitPolicyTimeInHours)H"
                    })   
            })

        Write-Host "Get Existing JIT Policy. You can Ignore the error if not found."
        $ExistingJITPolicy = (Get-AzJitNetworkAccessPolicy -ResourceGroupName $ResourceGroupName -Location $Location -Name $JitPolicyName -ErrorAction Ignore).VirtualMachines
        $UpdatedJITPolicy = $ExistingJITPolicy.Where{ $_.id -ne "$($VM.Id)" } # Exclude existing policy for $CurrentVMName
        $UpdatedJITPolicy.Add($NewJitPolicy)
	
        # Enable Access to the VM including management Port, and Time Range in Hours
        Write-Host "Enabling Just in Time VM Access Policy for ($CurrentVMName) on port number $RDPPort for maximum $JitPolicyTimeInHours hours..."
        $JitNetworkAccessPolicy = Set-AzJitNetworkAccessPolicy -VirtualMachine $UpdatedJITPolicy -ResourceGroupName $ResourceGroupName -Location $Location -Name $JitPolicyName -Kind "Basic"
        Start-Sleep -Seconds 5
        #endregion

        #region Requesting Temporary Access : 3 hours
        $JitPolicy = (@{
                id    = $VM.Id
                ports = (@{
                        number                     = $RDPPort;
                        endTimeUtc                 = (Get-Date).AddHours(3).ToUniversalTime()
                        allowedSourceAddressPrefix = @($MyPublicIP) 
                    })
            })
        $ActivationVM = @($JitPolicy)
        Write-Host "Requesting Temporary Acces via Just in Time for $($VM.Name) on port number $RDPPort for maximum $JitPolicyTimeInHours hours..."
        $null = Start-AzJitNetworkAccessPolicy -ResourceGroupName $($VM.ResourceGroupName) -Location $VM.Location -Name $JitPolicyName -VirtualMachine $ActivationVM
        #endregion
    }
    #endregion

    #region Enabling auto-shutdown at 11:00 PM in the user time zome
    $SubscriptionId = ($VM.Id).Split('/')[2]
    $ScheduledShutdownResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/microsoft.devtestlab/schedules/shutdown-computevm-$CurrentVMName"
    $Properties = @{}
    $Properties.Add('status', 'Enabled')
    $Properties.Add('taskType', 'ComputeVmShutdownTask')
    $Properties.Add('dailyRecurrence', @{'time' = "2300" })
    $Properties.Add('timeZoneId', (Get-TimeZone).Id)
    $Properties.Add('targetResourceId', $VM.Id)
    $null = New-AzResource -Location $Location -ResourceId $ScheduledShutdownResourceId -Properties $Properties -Force
    #endregion

    #Step 11: Start Azure Virtual Machine
    #Start-AzVM -Name $CurrentVMName -ResourceGroupName $ResourceGroupName

    # Adding Credentials to the Credential Manager (and escaping the password)
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /generic:$FQDN /user:$($Credential.UserName) /pass:$($Credential.GetNetworkCredential().Password -replace "(\W)", '^$1')" -Wait

    #Start-Sleep -Seconds 15

    #Step 13: Start RDP Session
    #mstsc /v $PublicIP.IpAddress
    #mstsc /v $FQDN
}

Write-Host -Object "Your RDP credentials (login/password) are $($Credential.UserName)/$($Credential.GetNetworkCredential().Password)" -ForegroundColor Green
$null = $Jobs | Receive-Job -Wait
# Complete the progress bar
Write-Progress -Completed -Activity "Completed"

#Waiting 2 arbitrary minutes to be sure no operations are in progress ...
Start-Sleep -Second 120

$MoveAzResourceToAnotherResourceGroupScriptFilePath = Join-Path -Path $CurrentDir -ChildPath "Move-AzResourceScript.ps1"
#Moving the VM to a destination resource group and restarting them after.
& "$MoveAzResourceToAnotherResourceGroupScriptFilePath" -SourceResourceGroupName $ResourceGroupName -DestinationResourceGroupName $TargetResourceGroupName -Start
