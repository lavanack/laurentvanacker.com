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
#requires -Version 5 -Modules Az.Compute, Az.Network, Az.Storage, Az.Resources, ComputerManagementDsc, HyperVDsc, PSDscResources, StorageDsc, xPSDesiredStateConfiguration

[CmdletBinding()]
param
(
    [string] $SourceResourceGroupName = "rg-automatedlab-storage-use-001",
    [string] $SourceStorageAccountName = "automatedlablabsources",
    [string] $SourceShareName = "isos",
    [switch] $Spot
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

#region Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount
}
#endregion

$AzureVMNameMaxLength = 15
$RDPPort = 3389
$JitPolicyTimeInHours = 3
$JitPolicyName = "Default"
$Location = "eastus2"
#$VMSize = "Standard_D16s_v6"
#Always get the latest generation available in the Azure region
$VMSize = (Get-AzComputeResourceSku -Location $Location | Where-Object -FilterScript { $_.Name -match "^Standard_D16s_v" } | Sort-Object -Property Name -Descending | Select-Object -First 1).Name
$LocationShortName = $shortNameHT[$Location].shortName
#Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
$ResourceGroupPrefix = "rg"
$StorageAccountPrefix = "sa"
$VirtualMachinePrefix = "vm"
$NetworkSecurityGroupPrefix = "nsg"
$VirtualNetworkPrefix = "vnet"
$SubnetPrefix = "snet"
$Project = "al"
$Role = "hypv"
#$DigitNumber = 4
$DigitNumber = $AzureVMNameMaxLength - ($VirtualMachinePrefix + $Project + $Role + $LocationShortName).Length

Do {
    $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
    $StorageAccountName = "{0}{1}{2}{3}{4:D$DigitNumber}" -f $StorageAccountPrefix, $Project, $Role, $LocationShortName, $Instance                       
    $VMName = "{0}{1}{2}{3}{4:D$DigitNumber}" -f $VirtualMachinePrefix, $Project, $Role, $LocationShortName, $Instance                       
} While ((-not(Test-AzDnsAvailability -DomainNameLabel $VMName -Location $Location)) -or ((-not(Get-AzStorageAccountNameAvailability -Name $StorageAccountName).NameAvailable)))

$NetworkSecurityGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $NetworkSecurityGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
$VirtualNetworkName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $VirtualNetworkPrefix, $Project, $Role, $LocationShortName, $Instance                       
$SubnetName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $SubnetPrefix, $Project, $Role, $LocationShortName, $Instance                       
$ResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       

$StorageAccountName = $StorageAccountName.ToLower()
$VMName = $VMName.ToLower()
$NetworkSecurityGroupName = $NetworkSecurityGroupName.ToLower()
$VirtualNetworkName = $VirtualNetworkName.ToLower()
$SubnetName = $SubnetName.ToLower()
$ResourceGroupName = $ResourceGroupName.ToLower()
$VirtualNetworkAddressSpace = "10.10.0.0/16" # Format 10.10.0.0/16
$SubnetIPRange = "10.10.1.0/24" # Format 10.10.1.0/24                         
$FQDN = "$VMName.$Location.cloudapp.azure.com".ToLower()


#region Defining credential(s)
$Username = $env:USERNAME
#$ClearTextPassword = 'I@m@JediLikeMyF@therB4Me'
#$ClearTextPassword = New-RandomPassword -ClipBoard -Verbose
#$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$SecurePassword = New-RandomPassword -ClipBoard -AsSecureString -Verbose
$Credential = New-Object System.Management.Automation.PSCredential -ArgumentList ($Username, $SecurePassword)
#endregion

$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
if ($ResourceGroup) {
    #Step 0: Remove previously existing Azure Resource Group with the same name
    $ResourceGroup | Remove-AzResourceGroup -Force -Verbose
}
$MyPublicIp = (Invoke-WebRequest -uri "https://ipv4.seeip.org").Content
$ConfigurationDataFileName = "ConfigurationData.psd1"
$ConfigurationDataFilePath = Join-Path -Path $CurrentDir -ChildPath $ConfigurationDataFileName

$ConfigurationFileName = "AutomatedLabSetupDSC.ps1"
$ConfigurationFilePath = Join-Path -Path $CurrentDir -ChildPath $ConfigurationFileName
$ConfigurationName = "AutomatedLabSetupDSC"

#region Define Variables needed for Virtual Machine
$ImagePublisherName = "MicrosoftWindowsDesktop"
$ImageOffer = "Windows-11"
$ImageSku = "win11-24h2-ent"
$PublicIPName = "pip-$VMName" 
$NICName = "nic-$VMName"
$OSDiskName = '{0}_OSDisk' -f $VMName
$DataDiskName = "$VMName-DataDisk01"
$OSDiskSize = "127"
$StorageAccountSkuName = "Standard_LRS"
$OSDiskType = "StandardSSD_LRS"

Write-Verbose "`$VMName: $VMName"
Write-Verbose "`$NetworkSecurityGroupName: $NetworkSecurityGroupName"         
Write-Verbose "`$VirtualNetworkName: $VirtualNetworkName"         
Write-Verbose "`$SubnetName: $SubnetName"       
Write-Verbose "`$ResourceGroupName: $ResourceGroupName"
Write-Verbose "`$PublicIPName: $PublicIPName"
Write-Verbose "`$NICName: $NICName"
Write-Verbose "`$OSDiskName: $OSDiskName"
Write-Verbose "`$FQDN: $FQDN"
#endregion
#endregion


if ($VMName.Length -gt $AzureVMNameMaxLength) {
    Write-Error "'$VMName' exceeds $AzureVMNameMaxLength characters" -ErrorAction Stop
}
elseif (-not($LocationShortName)) {
    Write-Error "No location short name found for '$Location'" -ErrorAction Stop
}
elseif ($null -eq (Get-AZVMSize -Location $Location | Where-Object -FilterScript { $_.Name -eq $VMSize })) {
    Write-Error "The '$VMSize' is not available in the '$Location' location ..." -ErrorAction Stop
}

#Step 1: Create Azure Resource Group
# Create Resource Groups
$ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force

#Step 2: Create Azure Storage Account
New-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -Location $Location -SkuName $StorageAccountSkuName -MinimumTlsVersion TLS1_2 -EnableHttpsTrafficOnly $true

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


#Step 6: Create Azure Public Address
$PublicIP = New-AzPublicIpAddress -Name $PublicIPName -ResourceGroupName $ResourceGroupName -Location $Location -AlLocationMethod Static -DomainNameLabel $VMName.ToLower()
#Setting up the DNS Name
#$PublicIP.DnsSettings.Fqdn = $FQDN

#Step 7: Create Network Interface Card 
$NIC = New-AzNetworkInterface -Name $NICName -ResourceGroupName $ResourceGroupName -Location $Location -SubnetId $Subnet.Id -PublicIpAddressId $PublicIP.Id #-NetworkSecurityGroupId $NetworkSecurityGroup.Id

<# Optional : Step 8: Get Virtual Machine publisher, Image Offer, Sku and Image
$ImagePublisherName = Get-AzVMImagePublisher -Location $Location | Where-Object -FilterScript { $_.PublisherName -eq "MicrosoftWindowsDesktop"}
$ImageOffer = Get-AzVMImageOffer -Location $Location -publisher $ImagePublisherName.PublisherName | Where-Object -FilterScript { $_.Offer  -eq "Windows-11"}
$ImageSku = Get-AzVMImageSku -Location  $Location -publisher $ImagePublisherName.PublisherName -offer $ImageOffer.Offer | Where-Object -FilterScript { $_.Skus  -eq "win11-21h2-pro"}
$image = Get-AzVMImage -Location  $Location -publisher $ImagePublisherName.PublisherName -offer $ImageOffer.Offer -sku $ImageSku.Skus | Sort-Object -Property Version -Descending | Select-Object -First 1
#>

# Step 9: Create a virtual machine configuration file (As a Spot Intance)

if ($Spot) {
    #Create a virtual machine configuration file (As a Spot Intance for saving costs . DON'T DO THAT IN A PRODUCTION ENVIRONMENT !!!)
    $VMConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize -SecurityType TrustedLaunch -IdentityType SystemAssigned -Priority "Spot" -MaxPrice -1
}
else {
    $VMConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize -SecurityType TrustedLaunch -IdentityType SystemAssigned -HibernationEnabled
}

Add-AzVMNetworkInterface -VM $VMConfig -Id $NIC.Id

# Set VM operating system parameters
Set-AzVMOperatingSystem -VM $VMConfig -Windows -ComputerName $VMName -Credential $Credential -ProvisionVMAgent -EnableAutoUpdate #-PatchMode "AutomaticByPlatform"

# Set boot diagnostic storage account
#Set-AzVMBootDiagnostic -Enable -ResourceGroupName $ResourceGroupName -VM $VMConfig -StorageAccountName $StorageAccountName    
# Set boot diagnostic to managed storage account
Set-AzVMBootDiagnostic -VM $VMConfig -Enable 

# The uncommented lines below replace Step #8 : Set virtual machine source image
Set-AzVMSourceImage -VM $VMConfig -PublisherName $ImagePublisherName -Offer $ImageOffer -Skus $ImageSku -Version 'latest'

# Set OsDisk configuration
Set-AzVMOSDisk -VM $VMConfig -Name $OSDiskName -DiskSizeInGB $OSDiskSize -StorageAccountType $OSDiskType -CreateOption fromImage

#region Adding Data Disk
$VMDataDisk01Config = New-AzDiskConfig -SkuName $OSDiskType -Location $Location -CreateOption Empty -DiskSizeGB 512
$VMDataDisk01 = New-AzDisk -DiskName $DataDiskName -Disk $VMDataDisk01Config -ResourceGroupName $ResourceGroupName
$VM = Add-AzVMDataDisk -VM $VMConfig -Name $DataDiskName -Caching 'ReadWrite' -CreateOption Attach -ManagedDiskId $VMDataDisk01.Id -Lun 0
#endregion

#Step 10: Create Azure Virtual Machine
try {
    New-AzVM -ResourceGroupName $ResourceGroupName -Location $Location -VM $VMConfig -ErrorAction Stop #-DisableBginfoExtension
}
catch [Microsoft.Rest.Azure.CloudException] {
    Write-Warning -Message $_.Exception.Message
    Write-Warning -Message "Disabling Hibernation ..."
    $VMConfig.AdditionalCapabilities.HibernationEnabled = $false
    New-AzVM -ResourceGroupName $ResourceGroupName -Location $Location -VM $VMConfig -ErrorAction Stop #-DisableBginfoExtension
}
$VM = Get-AzVM -ResourceGroup $ResourceGroupName -Name $VMName
#region JIT Access Management
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
$UpdatedJITPolicy = $ExistingJITPolicy.Where{ $_.id -ne "$($VM.Id)" } # Exclude existing policy for $VMName
$UpdatedJITPolicy.Add($NewJitPolicy)
	
# Enable Access to the VM including management Port, and Time Range in Hours
Write-Host "Enabling Just in Time VM Access Policy for ($VMName) on port number $RDPPort for maximum $JitPolicyTimeInHours hours..."
$null = Set-AzJitNetworkAccessPolicy -VirtualMachine $UpdatedJITPolicy -ResourceGroupName $ResourceGroupName -Location $Location -Name $JitPolicyName -Kind "Basic"
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
Write-Host "Requesting Temporary Acces via Just in Time for ($VMName) on port number $RDPPort for maximum $JitPolicyTimeInHours hours..."
Start-AzJitNetworkAccessPolicy -ResourceGroupName $($VM.ResourceGroupName) -Location $VM.Location -Name $JitPolicyName -VirtualMachine $ActivationVM
#endregion

#endregion

#region Enabling auto-shutdown at 11:00 PM in the user time zome
$SubscriptionId = ($VM.Id).Split('/')[2]
$ScheduledShutdownResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/microsoft.devtestlab/schedules/shutdown-computevm-$VMName"
$Properties = @{}
$Properties.Add('status', 'Enabled')
$Properties.Add('taskType', 'ComputeVmShutdownTask')
$Properties.Add('dailyRecurrence', @{'time' = "2300" })
$Properties.Add('timeZoneId', (Get-TimeZone).Id)
$Properties.Add('targetResourceId', $VM.Id)
New-AzResource -Location $location -ResourceId $ScheduledShutdownResourceId -Properties $Properties -Force
#endregion

#Step 11: Start Azure Virtual Machine
Start-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName

#region Setting up the DSC extension

# Publishing DSC Configuration for AutomatedLab via Hyper-V (Nested Virtualization)
Publish-AzVMDscConfiguration -ConfigurationPath $ConfigurationFilePath -ConfigurationDataPath $ConfigurationDataFilePath -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -Force -Verbose

Do {
    try {
        #region Getting the Azure Storage Explorer Version via an online request
        <#
        $Response = (Invoke-WebRequest -Uri https://github.com/microsoft/AzureStorageExplorer/releases/latest)
        if ($Response.ParsedHtml.title -match "v(?<Version>\d+\.\d+.\d+)") {
        #>

        $Response = (Invoke-RestMethod  -Uri "https://api.github.com/repos/microsoft/AzureStorageExplorer/releases/latest").name
        if ($Response -match "v(?<Version>\d+\.\d+.\d+)") {
            $AzureStorageExplorerVersion = $Matches['Version']
        }
        else {
            #Latest version in July 2025
            $AzureStorageExplorerVersion = '1.39.0'
        }
        #endregion
        $ConfigurationArgument = @{
            Credential                  = $Credential
            AzureStorageExplorerVersion = $AzureStorageExplorerVersion
        }
        Set-AzVMDscExtension -ResourceGroupName $ResourceGroupName -VMName $VMName -ArchiveBlobName "$ConfigurationFileName.zip" -ArchiveStorageAccountName $StorageAccountName -ConfigurationName $ConfigurationName -ConfigurationData $ConfigurationDataFileName -ConfigurationArgument $ConfigurationArgument  -Version "2.80" -Location $Location -AutoUpdate -Verbose #-ErrorAction Ignore
    }
    catch {
        $_
    }
    Do {
        Write-Verbose -Message "Sleeping 30 seconds"
        Start-Sleep -Seconds 30
        $ProvisioningState = (Get-AzVMExtension -ResourceGroupName $ResourceGroupName -VMName $VMName -Name Microsoft.Powershell.DSC).ProvisioningState
        Write-Verbose -Message "`$ProvisioningState: $ProvisioningState"
    } While ($ProvisioningState -match "ing$")
} While ($ProvisioningState -eq "Failed")
$VM | Update-AzVM -Verbose


#endregion

<#
#region Setting up AutomatedLab via a PowerShell Script
#Getting storage account
$ContainerName = "scripts"
$PowershellScriptName = "AutomatedLabSetupNonDSC.ps1"
$PowershellScriptFullName = $(Join-Path -Path $CurrentDir -ChildPath $PowershellScriptName)

$StorageAccountKey = ((Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName)[0].Value)

$StorageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName 

#Getting context for blob upload
$StorageContext = $StorageAccount.Context

#Performing blob upload
if(-not(Get-AzStorageContainer -Name $ContainerName -Context $StorageContext -ErrorAction SilentlyContinue)) {
    New-AzStorageContainer -Name $ContainerName -Context $StorageContext
}

#Uploading script
Set-AzStorageBlobContent -Context $StorageContext -File $PowershellScriptFullName -Container $ContainerName -Blob $PowershellScriptName -BlobType Block -Force

Set-AzVMCustomScriptExtension -StorageAccountName $StorageAccountName -ContainerName $ContainerName -FileName $PowershellScriptName -Run $PowershellScriptName -StorageAccountKey $StorageAccountKey -Name $PowershellScriptName -VMName $VMName -ResourceGroupName $ResourceGroupName -Location $Location
#endregion
#>

#region Post Setup 
#Getting storage account
$ContainerName = "scripts"
$PowershellScriptName = "PostSetup.ps1"
$PowershellScriptFullName = $(Join-Path -Path $CurrentDir -ChildPath $PowershellScriptName)

$StorageAccountKey = ((Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName)[0].Value)

$StorageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName 

#Getting context for blob upload
$StorageContext = $StorageAccount.Context

#Performing blob upload
if (-not(Get-AzStorageContainer -Name $ContainerName -Context $StorageContext -ErrorAction SilentlyContinue)) {
    New-AzStorageContainer -Name $ContainerName -Context $StorageContext
}

#Uploading script
Set-AzStorageBlobContent -Context $StorageContext -File $PowershellScriptFullName -Container $ContainerName -Blob $PowershellScriptName -BlobType Block -Force

#region Script Parameters
$SourceResourceGroupName = "rg-automatedlab-storage-use-001"
$SourceStorageAccountName = "automatedlablabsources"
$SourceShareName = "isos"
#endregion

#region RBAC Assignment and calling script
$SourceStorageAccount = Get-AzStorageAccount -ResourceGroupName $SourceResourceGroupName -Name $SourceStorageAccountName -ErrorAction Ignore
if ($SourceStorageAccount) {
    $StorageAccountContributorRole = Get-AzRoleDefinition "Storage Account Contributor"
    #region 'Storage Account Contributor' RBAC Assignment
    While (-not(Get-AzRoleAssignment -ObjectId $VM.Identity.PrincipalId -RoleDefinitionName $StorageAccountContributorRole.Name -Scope $SourceStorageAccount.Id)) {
        Write-Verbose -Message "Assigning the '$($StorageAccountContributorRole.Name)' RBAC role to the '$($VM.Identity.PrincipalId)' identity on the '$($SourceStorageAccount.Id)' StorageAccount"
        $null = New-AzRoleAssignment -ObjectId $VM.Identity.PrincipalId -RoleDefinitionName $StorageAccountContributorRole.Name -Scope $SourceStorageAccount.Id
        Write-Verbose -Message "Sleeping 30 seconds"
        Start-Sleep -Seconds 30
    }
    #endregion 

    $Argument = "-ResourceGroupName {0} -StorageAccountName {1} -ShareName {2}" -f $SourceResourceGroupName, $SourceStorageAccountName, $SourceShareName
    Set-AzVMCustomScriptExtension -StorageAccountName $StorageAccountName -ContainerName $ContainerName -FileName $PowershellScriptName -Run $PowershellScriptName -Argument $Argument -StorageAccountKey $StorageAccountKey -Name $PowershellScriptName -VMName $VMName -ResourceGroupName $ResourceGroupName -Location $Location

    <#
    #Alternative
    $Parameter = @{
        ResourceGroupName  = $SourceResourceGroupName
        StorageAccountName = $SourceStorageAccountName
        ShareName          = $SourceShareName
    }
    Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VMName -CommandId 'RunPowerShellScript' -ScriptPath $PowershellScriptFullName -Parameter $Parameter
    #>

    #region RBAC Assignment Removal
    Get-AzRoleAssignment -ObjectId $VM.Identity.PrincipalId -Scope $SourceStorageAccount.Id | Remove-AzRoleAssignment
    #endregion
}
else {
    Write-Warning -Message "The '$SourceStorageAccountName' StorageAccountName (into the '$SourceResourceGroupName' ResourceGroupName) doesn't exist ..."
}
#endregion
#endregion

# Adding Credentials to the Credential Manager (and escaping the password)
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /generic:$FQDN /user:$($Credential.UserName) /pass:$($Credential.GetNetworkCredential().Password -replace "(\W)", '^$1')" -Wait

Start-Sleep -Seconds 15

#Step 12: Start RDP Session
#mstsc /v $PublicIP.IpAddress
mstsc /v $FQDN
Write-Host -Object "Your RDP credentials (login/password) are $($Credential.UserName)/$($Credential.GetNetworkCredential().Password)" -ForegroundColor Green
