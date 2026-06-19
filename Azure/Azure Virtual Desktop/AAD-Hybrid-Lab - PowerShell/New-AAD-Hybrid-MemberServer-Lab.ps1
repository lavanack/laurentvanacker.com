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
#requires -Version 5 -Modules Az.Accounts, Az.Compute, Az.Network, Az.Resources, Az.Security, Az.Storage

#region Function definition
function New-AAD-Hybrid-MemberServer-Lab {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [parameter(Mandatory = $true, HelpMessage = 'Please specify the administrator credential. The Username cannot be "Administrator", "root" and possibly other such common account names.')]
        [PSCredential] $AdminCredential,
        [parameter(Mandatory = $false, HelpMessage = 'Select a VM SKU (please ensure the SKU is available in your selected region).')]
        [string] $VMSize = "Standard_D2s_v5",
        [parameter(Mandatory = $false, HelpMessage = 'Select an OS Disk Type')]
        [ValidateSet("StandardSSD_LRS", "Premium_LRS")] 
        [string] $OSDiskType = "StandardSSD_LRS",
        [parameter(Mandatory = $false, HelpMessage = 'Please specify the project')]
        [ValidateLength(2, 4)] 
        [string] $Project = "avd",
        [parameter(Mandatory = $false, HelpMessage = 'Please specify the role')]
        [ValidateLength(2, 4)] 
        [string] $Role = "ad",
        [parameter(Mandatory = $false, HelpMessage = 'IMPORTANT: Two-part internal AD name - short/NB name will be first part ("contoso"). The short name will be reused and should be unique when deploying this template in your selected region. If a name is reused, DNS name collisions may occur.')]
        [ValidatePattern("\w+\.\w+")] 
        [string] $ADDomainName = "contoso.local",
        
        [parameter(Mandatory = $true, HelpMessage = 'The ResourceGroupName used to store the deployed Server Member')]
        [string] $ResourceGroupName,
        [parameter(Mandatory = $true, HelpMessage = 'The Subnet used to connect the deployed DC')]
        [Microsoft.Azure.Commands.Network.Models.PSSubnet] $Subnet,
        
        [parameter(Mandatory = $false, HelpMessage = 'The IP Addresses assigned to the domain controllers (a, b). Remember the first IP in a subnet is .4 e.g. 10.0.0.0/16 reserves 10.0.0.0-3. Specify one IP per server - must match numberofVMInstances or deployment will fail.')]
        [ValidatePattern("\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3}")] 
        [string] $DCIP = '10.0.1.4',
        [parameter(Mandatory = $false, HelpMessage = 'The IP Addresses assigned to the domain controllers (a, b). Remember the first IP in a subnet is .4 e.g. 10.0.0.0/16 reserves 10.0.0.0-3. Specify one IP per server - must match numberofVMInstances or deployment will fail.')]
        [ValidatePattern("\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3}")] 
        [string] $MemberServerIP = '10.0.1.101',
        [parameter(Mandatory = $false, HelpMessage = 'The instance number for your deployment.')]
        [ValidateScript({ $_ -in 0..999 })] 
        [int] $Instance = $(Get-Random -Minimum 0 -Maximum 1000),
        [switch] $Spot
    )

    $vNetworkId = $SubNet.Id -replace "/subnets/.*"
    $vNetwork = Get-AzResource -ResourceId $vNetworkId | Get-AzVirtualNetwork
    $Location = $vNetwork.Location

    Write-Verbose "`$VMSize: $VMSize"
    Write-Verbose "`$Project: $Project"         
    Write-Verbose "`$Role: $Role"         
    Write-Verbose "`$ADDomainName: $ADDomainName"       
    Write-Verbose "`$Subnet: $($Subnet.Id)"
    Write-Verbose "`$DCIP: $DCIP"
    Write-Verbose "`$MemberServerIP: $MemberServerIP"
    Write-Verbose "`$Instance: $Instance"
    Write-Verbose "`$Location: $Location"
    Write-Verbose "`$Spot: $Spot"

    #region Defining variables 
    #region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
    $AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
    $ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
    $shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
    #endregion

    $AzureVMNameMaxLength = 15
    $RDPPort = 3389
    $JitPolicyTimeInHours = 3
    $JitPolicyName = "Default"
    $LocationShortName = $shortNameHT[$Location].shortName
    #Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
    $ResourceGroupPrefix = "rg"
    $StorageAccountPrefix = "sa"
    $VirtualMachinePrefix = "vm"
    $NetworkSecurityGroupPrefix = "nsg"
    $VirtualNetworkPrefix = "vnet"

    $StorageAccountName = '{0}{1}{2}{3}{4:D3}' -f $StorageAccountPrefix, $Project, $Role, $LocationShortName, $Instance                       
    $VMName = '{0}{1}{2}{3}{4:D3}' -f $VirtualMachinePrefix, $Project, $Role, $LocationShortName, $Instance                       
    $VirtualNetworkName = '{0}-{1}-{2}-{3}-{4:D3}' -f $VirtualNetworkPrefix, $Project, $Role, $LocationShortName, $Instance                       


    $StorageAccountName = $StorageAccountName.ToLower()
    $VMName = $VMName.ToLower()
    $VirtualNetworkName = $VirtualNetworkName.ToLower()
    $ResourceGroupName = $ResourceGroupName.ToLower()
    
    $FQDN = "$VMName.$Location.cloudapp.azure.com".ToLower()

    $MyPublicIp = Invoke-RestMethod -Uri "https://ipv4.seeip.org"

    #region Define Variables needed for Virtual Machine
    $ImagePublisherName = "MicrosoftWindowsServer"
    $ImageOffer = "WindowsServer"
    $ImageSku = "2025-datacenter-azure-edition"
    $PublicIPName = "pip-$VMName" 
    $NICName = "nic-$VMName"
    $OSDiskName = '{0}_OSDisk' -f $VMName
    #$DataDiskName          = "$VMName-DataDisk01"
    $OSDiskSize = "127"
    $StorageAccountSkuName = "Standard_LRS"
    #$OSDiskType = "StandardSSD_LRS"
    $DSCZipFileUri = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/AAD-Hybrid-Lab%20-%20PowerShell/DSC/adMemberServerDSC.zip"
    $DSCConfigurationName = "AdditionalMemberServer"

    $DSCConfigurationArguments = @{ 
        ADDomainName = $ADDomainName
        ComputerName = $VMName
        AdminCreds   = $AdminCredential
        DCIP         = $DCIP
    }

    Write-Verbose "`$VMName: $VMName"
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
    elseif (-not(Get-AzStorageAccountNameAvailability -Name $StorageAccountName).NameAvailable) {
        Write-Error "The storage account name '$StorageAccountName' is NOT available" -ErrorAction Stop
    }
    elseif (-not(Test-AzDnsAvailability -DomainNameLabel $VMName -Location $Location)) {
        Write-Error "$FQDN is NOT available" -ErrorAction Stop
    }
    elseif ($null -eq (Get-AzComputeResourceSku -Location $Location | Where-Object -FilterScript { $_.Name -eq $VMSize })) {
        Write-Error "The '$VMSize' is not available in the '$Location' location ..." -ErrorAction Stop
    }

    $NetworkSecurityGroup = Get-AzResource -ResourceId $Subnet.NetworkSecurityGroup.Id | Get-AzNetworkSecurityGroup
    $VirtualNetworkName = $vNetwork.Name
    Write-Verbose "`$VirtualNetworkName: $VirtualNetworkName"         

    $StorageAccount = foreach ($CurrentStorageAccount in $(Get-AzStorageAccount -ResourceGroupName $ResourceGroupName)) {
        $null = $CurrentStorageAccount | Set-AzStorageAccount -PublicNetworkAccess Enabled -AllowBlobPublicAccess $true -AllowSharedKeyAccess $true -Tag @{ SecurityControl = "Ignore" }
        $StorageContainer = Get-AzStorageContainer -Name windows-powershell-dsc -Context $CurrentStorageAccount.Context -ErrorAction Ignore
        if ($StorageContainer) {
            $CurrentStorageAccount
            Write-Verbose "`$CurrentStorageAccount: $($CurrentStorageAccount | Out-String)"
            break
        }
    }
    $StorageAccountName = $StorageAccount.StorageAccountName
    Write-Verbose "`$StorageAccountName: $StorageAccountName"

    #Step 6: Create Azure Public Address
    $PublicIP = New-AzPublicIpAddress -Name $PublicIPName -ResourceGroupName $ResourceGroupName -Location $Location -AllocationMethod Static -DomainNameLabel $VMName.ToLower()
    #Setting up the DNS Name
    #$PublicIP.DnsSettings.Fqdn = $FQDN

    #Step 7: Create Network Interface Card 
    $NIC = New-AzNetworkInterface -Name $NICName -ResourceGroupName $ResourceGroupName -Location $Location -SubnetId $Subnet.Id -PublicIpAddressId $PublicIP.Id -PrivateIpAddress $MemberServerIP

    <# Optional : Step 8: Get Virtual Machine publisher, Image Offer, Sku and Image
    $ImagePublisherName = Get-AzVMImagePublisher -Location $Location | Where-Object -FilterScript { $_.PublisherName -eq "MicrosoftWindowsDesktop"}
    $ImageOffer = Get-AzVMImageOffer -Location $Location -publisher $ImagePublisherName.PublisherName | Where-Object -FilterScript { $_.Offer  -eq "Windows-11"}
    $ImageSku = Get-AzVMImageSku -Location  $Location -publisher $ImagePublisherName.PublisherName -offer $ImageOffer.Offer | Where-Object -FilterScript { $_.Skus  -eq "win11-21h2-pro"}
    $image = Get-AzVMImage -Location  $Location -publisher $ImagePublisherName.PublisherName -offer $ImageOffer.Offer -sku $ImageSku.Skus | Sort-Object -Property Version -Descending | Select-Object -First 1
    #>

    # Step 9: Create a virtual machine configuration file (As a Spot Intance)
    if ($Spot) {
        $VMConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize -Priority "Spot" -MaxPrice -1
    }
    else {
        $VMConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize
    }

    Add-AzVMNetworkInterface -VM $VMConfig -Id $NIC.Id

    # Set VM operating system parameters
    Set-AzVMOperatingSystem -VM $VMConfig -Windows -ComputerName $VMName -Credential $AdminCredential -ProvisionVMAgent -EnableAutoUpdate -PatchMode "AutomaticByPlatform"

    # Set boot diagnostic storage account
    #Set-AzVMBootDiagnostic -Enable -ResourceGroupName $ResourceGroupName -VM $VMConfig -StorageAccountName $StorageAccountName    
    # Set boot diagnostic to managed storage account
    Set-AzVMBootDiagnostic -VM $VMConfig -Enable 

    # The line below replaces Step #8 : Set virtual machine source image
    Set-AzVMSourceImage -VM $VMConfig -PublisherName $ImagePublisherName -Offer $ImageOffer -Skus $ImageSku -Version 'latest'

    # Set OsDisk configuration
    Set-AzVMOSDisk -VM $VMConfig -Name $OSDiskName -DiskSizeInGB $OSDiskSize -StorageAccountType $OSDiskType -CreateOption fromImage

    #region Adding Data Disk
    <#
    $VMDataDisk01Config = New-AzDiskConfig -SkuName $OSDiskType -Location $Location -CreateOption Empty -DiskSizeGB 512
    $VMDataDisk01       = New-AzDisk -DiskName $DataDiskName -Disk $VMDataDisk01Config -ResourceGroupName $ResourceGroupName
    $VM                 = Add-AzVMDataDisk -VM $VMConfig -Name $DataDiskName -Caching 'ReadWrite' -CreateOption Attach -ManagedDiskId $VMDataDisk01.Id -Lun 0
    #>
    #endregion

    #Step 10: Create Azure Virtual Machine
    New-AzVM -ResourceGroupName $ResourceGroupName -Location $Location -VM $VMConfig #-DisableBginfoExtension

    #Step 11: Updating the DNS Servers of the VNet to point to the DC.
    $vNetwork.DhcpOptions = [PSCustomObject]@{"DnsServers" = @($MemberServerIP, $DCIP) }
    $vNetwork | Set-AzVirtualNetwork

    #region vNet Peering
    #endregion

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
	
    #! Enable Access to the VM including management Port, and Time Range in Hours
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
    $SubscriptionId = (Get-AzContext).Subscription.Id
    $ScheduledShutdownResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/microsoft.devtestlab/schedules/shutdown-computevm-$VMName"
    $Properties = @{}
    $Properties.Add('status', 'Enabled')
    $Properties.Add('taskType', 'ComputeVmShutdownTask')
    $Properties.Add('dailyRecurrence', @{'time' = "2300" })
    $Properties.Add('timeZoneId', (Get-TimeZone).Id)
    $Properties.Add('targetResourceId', $VM.Id)
    New-AzResource -Location $location -ResourceId $ScheduledShutdownResourceId -Properties $Properties -Force -ErrorAction Ignore
    #endregion
    #Step 12: Start Azure Virtual Machine
    Start-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName

    #region Setting up the DSC extension
    # Publishing DSC Configuration 
    $DSCZipFileName = Split-Path -Path $DSCZipFileUri -Leaf
    $DSCZipLocalFilePath = Join-Path -Path $env:TEMP -ChildPath $DSCZipFileName
    #Downloading the zip file from the Gitbub repository (We use the same Zip file that the one use for the ARM template deployment to avoid content duplication)
    Invoke-RestMethod -Uri $DSCZipFileUri -OutFile $DSCZipLocalFilePath -Verbose
    if (Test-Path -Path $DSCZipLocalFilePath) {
        $DestinationFolder = Join-Path -Path $env:TEMP -ChildPath $((Get-Item -Path $DSCZipLocalFilePath).BaseName)
        #Extracting the files from the downoaded zip file
        Expand-Archive -Path $DSCZipLocalFilePath -DestinationPath $DestinationFolder -Verbose -Force 
        #Getting only the .ps1 file
        $DSCConfigurationFile = (Get-ChildItem -Path $DestinationFolder -Filter *.ps1 -File | Select-Object -First 1).Fullname
        #Getting only the module folders
        #$ModuleFolders = (Get-ChildItem -Path $DestinationFolder -Directory).FullName
        #Copying the module folders locally to avoid an error when using the Publish-AzVMDscConfiguration cmdlet
        #Copy-Item -Path $ModuleFolders -Destination $env:ProgramFiles\WindowsPowerShell\Modules -Recurse -Force -Verbose
        #Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -PublicNetworkAccess Enabled -AllowBlobPublicAccess $true -AllowSharedKeyAccess $true -Tag @{ SecurityControl="Ignore" }
        $StorageAccount | Set-AzStorageAccount -PublicNetworkAccess Enabled -AllowBlobPublicAccess $true -AllowSharedKeyAccess $true -Tag @{ SecurityControl = "Ignore" }
        $DSCConfigurationZipFileURI = Publish-AzVMDscConfiguration $DSCConfigurationFile -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -Force -Verbose
        try {
            Set-AzVMDscExtension -ResourceGroupName $ResourceGroupName -VMName $VMName -ArchiveBlobName "$(Split-Path -Path $DSCConfigurationZipFileURI -Leaf)" -ArchiveStorageAccountName $StorageAccountName -ConfigurationName $DSCConfigurationName -ConfigurationArgument $DSCConfigurationArguments -Version "2.80" -Location $Location -AutoUpdate -Verbose #-ErrorAction Ignore
        }
        catch {
        }
        $VM | Update-AzVM -Verbose
        Remove-Item -Path $DSCZipLocalFilePath -Force
        Remove-Item -Path $DestinationFolder -Recurse -Force
    }
    else {
        Write-Error -Exception "Unable to download $DSCZipFileUri ..." -ErrorAction Continue
    }
    #endregion

    # Adding Credentials to the Credential Manager (and escaping the password)
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /generic:$FQDN /user:$($AdminCredential.UserName) /pass:$($AdminCredential.GetNetworkCredential().Password -replace "(\W)", '^$1')" -Wait

    Start-Sleep -Seconds 15

    #Step 13: Start RDP Session
    #mstsc /v $PublicIP.IpAddress
    mstsc /v $FQDN
    Write-Host -Object "Your RDP credentials (login/password) are $($AdminCredential.UserName)/$($AdminCredential.GetNetworkCredential().Password)" -ForegroundColor Green
}
#endregion


Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

#region Azure Connection
if (-not(Get-AzContext)) {
    Connect-AzAccount
    Get-AzSubscription | Out-GridView -OutputMode Single | Select-AzSubscription
    Write-Verbose -Message "Account : $((Get-AzContext).Account)"
    Write-Verbose -Message "Subscription : $((Get-AzContext).Subscription.Name)"
}
#endregion

#region Examples
#Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Verbose
$null = Get-PackageProvider -Name NuGet -Force -Verbose
$RequiredModules = 'ActiveDirectoryDSC', 'NetworkingDSC', 'ComputerManagementDSC'
$InstalledModule = Get-InstalledModule -Name $RequiredModules -ErrorAction Ignore
if (-not([String]::IsNullOrEmpty($InstalledModule))) {
    $MissingModules = (Compare-Object -ReferenceObject $RequiredModules -DifferenceObject (Get-InstalledModule -Name $RequiredModules -ErrorAction Ignore).Name).InputObject
}
else {
    $MissingModules = $RequiredModules
}
if (-not([String]::IsNullOrEmpty($MissingModules))) {
    Install-Module -Name $MissingModules -Force -Verbose
}

$AdminCredential = Get-Credential -Credential $env:USERNAME

#$Instance = Get-Random -Minimum 1 -Maximum 1000
$Instance = 2

#region for Adding an additional Server Member in a region
$Parameters = @{
    "AdminCredential"    = $AdminCredential
    "VMSize"             = "Standard_D4s_v5"
    "OSDiskType"         = "StandardSSD_LRS"
    "Project"            = "avd"
    "Role"               = "mbr"
    "ADDomainName"       = "csa.fr"

    "ResourceGroupName"  = "rg-avd-ad-usc-002"
    "Subnet"             = Get-AzVirtualNetwork -Name "vnet-avd-ad-usc-002" -ResourceGroupName "rg-avd-ad-usc-002" | Get-AzVirtualNetworkSubnetConfig -Name "snet-avd-ad-usc-002"

    "DCIP"               = '10.1.1.4'
    "MemberServerIP"     = '10.1.1.101'
    "Instance"           = $Instance
    "Spot"               = $false
    "Verbose"            = $true
}
New-AAD-Hybrid-MemberServer-Lab @Parameters
#endregion
#endregion