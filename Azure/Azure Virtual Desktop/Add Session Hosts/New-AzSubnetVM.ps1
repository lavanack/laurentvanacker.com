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
#requires -Version 5 -Modules Az.Accounts, Az.Compute, Az.Network, Az.Resources, Az.Security, Az.Storage, Microsoft.PowerShell.ThreadJob

[CmdletBinding(PositionalBinding = $false)]
param
(
    [Alias("Number")]
    [uint16] $VMNumber = 10,

    [ValidateScript({ $_ -in (Get-AzLocation).Location })]
    [string] $Location = "centralus",

    [switch] $PublicIP
)

#region Function definitions
# Adapted from https://adamtheautomator.com/powershell-random-password/

<#
.SYNOPSIS
Generates and checks a virtual machine administrator password.

.DESCRIPTION
Creates a random password locally or retrieves one from DinoPass. Retries until
the candidate passes the configured character-pattern and prohibited-password
checks and is not found by the Have I Been Pwned range API. The result can be
returned as plain text or as a SecureString and optionally copied to the clipboard.

.PARAMETER minLength
Specifies the inclusive minimum length used when selecting a random password length.
Defaults to 12 characters.

.PARAMETER maxLength
Specifies the exclusive maximum length used when selecting a random password length.
Must exceed minLength. Defaults to 15 characters.

.PARAMETER AsSecureString
Returns the generated password as a SecureString instead of plain text.

.PARAMETER ClipBoard
Copies the generated password to the clipboard.

.PARAMETER nonAlphaChars
Specifies the minimum number of non-alphanumeric characters for the local
generator. Defaults to 3. Cannot be combined with Online.

.PARAMETER Online
Retrieves the password from DinoPass over HTTPS instead of generating it locally.
The service receives the requested length and character options.

.EXAMPLE
New-RandomPassword -Online -AsSecureString

Retrieves and checks a password, then returns it as a SecureString.

.EXAMPLE
New-RandomPassword -minLength 16 -maxLength 21 -nonAlphaChars 4 -AsSecureString

Generates and checks a local password of 16 through 20 characters.

.INPUTS
None. This function does not accept pipeline input.

.OUTPUTS
System.String
System.Security.SecureString
Returns plain text by default, or a SecureString when AsSecureString is specified.

.NOTES
Local generation uses System.Web.Security.Membership and requires .NET Framework.
Both generation modes call the Pwned Passwords service to check candidates.
The letter-pattern checks use PowerShell's case-insensitive -match operator;
they do not independently enforce uppercase and lowercase characters.

.LINK
https://adamtheautomator.com/powershell-random-password/
#>
function New-RandomPassword {
    [CmdletBinding(PositionalBinding = $false, DefaultParameterSetName = 'GeneratePassword')]
    param
    (
        [ValidateRange(12, 122)]
        [int] $minLength = 12,
        [ValidateRange(13, 123)]
        [ValidateScript({ $_ -gt $minLength })]
        [int] $maxLength = 15,
        [switch] $AsSecureString,
        [switch] $ClipBoard,
        [Parameter(ParameterSetName = 'GeneratePassword')]
        [int] $nonAlphaChars = 3,
        [Parameter(ParameterSetName = 'DinoPass')]
        [switch] $Online
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    <#
    .SYNOPSIS
    Checks a password against the Have I Been Pwned Pwned Passwords service.

    .DESCRIPTION
    Uses the Pwned Passwords range API: sends only the first five hexadecimal
    characters of the password's SHA-1 hash, then compares the returned hash
    suffixes locally. Neither the password nor its complete hash is sent. A match
    reports the number of known breach occurrences; API failures raise an error.

    .PARAMETER Password
    Specifies the plain-text password to check.

    .EXAMPLE
    Test-PwnedPassword -Password $RandomPassword

    Checks a candidate password before New-RandomPassword returns it.

    .OUTPUTS
    System.Management.Automation.PSCustomObject
    Returns a PSCustomObject with PasswordCompromised (Boolean) and Occurrences
    (integer count) properties. Occurrences is zero when the password was not found.

    .INPUTS
    None. This function does not accept pipeline input.

    .LINK
    https://haveibeenpwned.com/API/v3#PwnedPasswords
    #>
    function Test-PwnedPassword {
        [CmdletBinding(PositionalBinding = $false)]
        param(
            [Parameter(Mandatory = $true)]
            [string]$Password
        )

        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
        # Calculate the SHA-1 hash required by the Pwned Passwords range API.
        $sha1 = [System.BitConverter]::ToString([System.Security.Cryptography.SHA1]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Password))).Replace('-', '').ToUpper()

        # Split the hash so the API can return possible suffix matches for the prefix.
        $prefix = $sha1.Substring(0, 5)
        $suffix = $sha1.Substring(5)

        try {
            $response = Invoke-RestMethod -Uri "https://api.pwnedpasswords.com/range/$prefix" -Method Get -Headers @{ "User-Agent" = "PowerShell" }

            # A matching suffix indicates the password has appeared in a known breach.
            foreach ($line in $response -split "`n") {
                $parts = $line.Trim() -split ':'

                if ($parts[0] -eq $suffix) {
                    return [PSCustomObject]@{
                        PasswordCompromised = $true
                        Occurrences         = [int64]$parts[1]
                    }
                }
            }

            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
            return [PSCustomObject]@{
                PasswordCompromised = $false
                Occurrences         = 0
            }
        }
        catch {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
            throw "Error when calling the API : $_"
        }
    }

    # Azure password requirements:
    # https://learn.microsoft.com/azure/virtual-machines/windows/faq#what-are-the-password-requirements-when-creating-a-vm-
    # Azure rejects these commonly used passwords even when they satisfy complexity rules.
    $ProhibitedPasswords = @('abc@123', 'iloveyou!', 'P@$$w0rd', 'P@ssw0rd', 'P@ssword123', 'Pa$$word', 'pass@word1', 'Password!', 'Password1', 'Password22')
    $length = Get-Random -Minimum $minLength -Maximum $maxLength
    # Keep the chosen length for every retry; check breach status only after complexity passes.
    Do {
        if ($Online) {
            $URI = "https://www.dinopass.com/password/custom?length={0}&useSymbols=true&useNumbers=true&useCapitals=true" -f $length
            $RandomPassword = Invoke-RestMethod -Uri $URI
        }
        else {
            Add-Type -AssemblyName 'System.Web'
            $RandomPassword = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
        }
        # Check either source identically; -match is case-insensitive for the letter patterns.
    } Until (($RandomPassword -notin $ProhibitedPasswords) -and (($RandomPassword -match '[A-Z]') -and ($RandomPassword -match '[a-z]') -and ($RandomPassword -match '\d') -and ($RandomPassword -match '\W') -and (-not((Test-PwnedPassword -Password $RandomPassword).PasswordCompromised))))

    #Write-Host -Object "The password is : $RandomPassword"
    if ($ClipBoard) {
        #Write-Verbose -Message "The password has beeen copied into the clipboard (Use Win+V) ..."
        $RandomPassword | Set-Clipboard
    }
    if ($AsSecureString) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        ConvertTo-SecureString -String $RandomPassword -AsPlainText -Force
    }
    else {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        $RandomPassword
    }
}

<#
.SYNOPSIS
Creates a Windows 11 virtual machine on an existing subnet.

.DESCRIPTION
Creates a NIC and a Windows 11 Enterprise Trusted Launch VM with a system-assigned
managed identity, using the supplied administrator credentials. Stores those
credentials in the local Windows Credential Manager and configures daily shutdown
at 23:00 in the local computer's time zone. Starts the VM after deployment.

.PARAMETER ResourceGroupName
Specifies the existing resource group in which to create the VM and its resources.

.PARAMETER VMName
Specifies the VM and Windows computer name. Converted to lowercase.

.PARAMETER Subnet
Specifies the existing subnet to which the VM's NIC will be attached.

.PARAMETER VMSize
Specifies the Azure VM size.

.PARAMETER Credential
Specifies the local Windows administrator credentials used to provision the VM
and saved with cmdkey on the computer running this function.

.PARAMETER Location
Specifies the Azure region. Defaults to centralus.

.PARAMETER Spot
Creates a Spot VM without a price-based eviction limit. Capacity eviction can
still occur. Without this switch, requests hibernation for a regular-priority VM.

.PARAMETER PublicIP
Creates a static public IP with a DNS label, configures a JIT RDP policy, and
requests three hours of access from the caller's public IP.

.EXAMPLE
New-AzSubnetVM -ResourceGroupName 'rg-demo' -VMName 'vm-demo-01' -Subnet $Subnet -VMSize 'Standard_D2s_v5' -Credential $Credential

Creates a private-only VM on an existing subnet using supplied credentials.

.INPUTS
None. This function does not accept pipeline input.

.OUTPUTS
System.Object
Emits results from the Azure configuration, deployment, shutdown-schedule, and
start operations, and from the JIT access request when PublicIP is specified.
Does not return a single consolidated VM object.

.NOTES
Requires an authenticated Azure context and Windows tools including cmdkey.
PublicIP uses $MyPublicIP from the calling scope for the JIT access request;
that variable must also be available when running the function in a thread job.
If deployment raises an Azure CloudException, retries once with hibernation disabled.
#>
function New-AzSubnetVM {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $true)]
        [string] $ResourceGroupName,
        [Parameter(Mandatory = $true)]
        [string] $VMName,
        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.Network.Models.PSSubnet] $Subnet,
        [Parameter(Mandatory = $true)]
        [string] $VMSize,
        [Parameter(Mandatory = $true)]
        [PSCredential] $Credential,
        [Parameter(Mandatory = $false)]
        [ValidateScript({ $_ -in (Get-AzLocation).Location })]
        [string] $Location = "centralus",
        [switch] $Spot,
        [switch] $PublicIP
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    #region VM image, disk, and access settings
    $ImagePublisherName = "MicrosoftWindowsDesktop"
    $ImageOffer = "Windows-11"
    $ImageSku = "win11-25h2-ent"

    $VMName = $VMName.ToLower()
    $NICName = "nic-$VMName"
    $OSDiskName = '{0}_OSDisk' -f $VMName
    $OSDiskSize = "127"
    $OSDiskType = "StandardSSD_LRS"
    $RDPPort = 3389
    $JitPolicyTimeInHours = 3
    $JitPolicyName = "Default"

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$VMName: $VMName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$NICName: $NICName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$OSDiskName: $OSDiskName"
    #endregion

    if ($PublicIP) {
        # Retry DNS labels while the candidate name resolves; this does not reserve the label.
        Do {
            $RandomString = [Guid]::NewGuid().ToString('N').Substring(0, 8)
            $DomainNameLabel = $("{0}-{1}" -f $VMName, $RandomString).ToLower()
            $FQDN = $("{0}.{1}.cloudapp.azure.com" -f $DomainNameLabel, $Location).ToLower()
        } While ($null -ne $(Resolve-DnsName $FQDN -ErrorAction Ignore))

        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$FQDN: $FQDN"
        $PublicIPAddressName = "pip-$VMName" 
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$PublicIPAddressName: $PublicIPAddressName"
    
        # Create a static public IP with the selected DNS label.
        $PublicIPAddress = New-AzPublicIpAddress -Name $PublicIPAddressName -ResourceGroupName $ResourceGroupName -Location $Location -AlLocationMethod Static -DomainNameLabel $DomainNameLabel

        # Attach the public IP to a NIC on the supplied subnet.
        $NIC = New-AzNetworkInterface -Name $NICName -ResourceGroupName $ResourceGroupName -Location $Location -SubnetId $Subnet.Id -PublicIpAddressId $PublicIPAddress.Id #-NetworkSecurityGroupId $NetworkSecurityGroup.Id
    }
    else {
        # Create a private-only NIC on the supplied subnet.
        $NIC = New-AzNetworkInterface -Name $NICName -ResourceGroupName $ResourceGroupName -Location $Location -SubnetId $Subnet.Id #-NetworkSecurityGroupId $NetworkSecurityGroup.Id
    }

    # Build the in-memory VM configuration with Spot or regular-priority settings.
    if ($Spot) {
        # Spot capacity can be evicted; -MaxPrice -1 disables price-based eviction only.
        $VMConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize -SecurityType TrustedLaunch -IdentityType SystemAssigned -Priority "Spot" -MaxPrice -1
    }
    else {
        $VMConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize -SecurityType TrustedLaunch -IdentityType SystemAssigned -HibernationEnabled
    }

    Add-AzVMNetworkInterface -VM $VMConfig -Id $NIC.Id

    # Configure Windows provisioning, administrator credentials, and automatic updates.
    Set-AzVMOperatingSystem -VM $VMConfig -Windows -ComputerName $VMName -Credential $Credential -ProvisionVMAgent -EnableAutoUpdate #-PatchMode "AutomaticByPlatform"

    # Enable boot diagnostics using managed storage.
    Set-AzVMBootDiagnostic -VM $VMConfig -Enable 

    # Use the latest version of the configured marketplace image.
    Set-AzVMSourceImage -VM $VMConfig -PublisherName $ImagePublisherName -Offer $ImageOffer -Skus $ImageSku -Version 'latest'

    # Create the OS disk from the image with the configured capacity and storage tier.
    Set-AzVMOSDisk -VM $VMConfig -Name $OSDiskName -DiskSizeInGB $OSDiskSize -StorageAccountType $OSDiskType -CreateOption fromImage

    # Deploy the VM; retry once with hibernation disabled after an Azure CloudException.
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
    if ($PublicIP) {
        #region JIT Access Management

        #region Enabling JIT Access
        $NewJitPolicy = (
            @{
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
        $UpdatedJITPolicy = $ExistingJITPolicy.Where{ $_.id -ne "$($VM.Id)" } # Replace this VM's entry while retaining entries for other VMs.
        $UpdatedJITPolicy.Add($NewJitPolicy)
	
        # Save the RDP policy and maximum request duration; access is requested below.
        Write-Host "Enabling Just in Time VM Access Policy for ($VMName) on port number $RDPPort for maximum $JitPolicyTimeInHours hours..."
        $null = Set-AzJitNetworkAccessPolicy -VirtualMachine $UpdatedJITPolicy -ResourceGroupName $ResourceGroupName -Location $Location -Name $JitPolicyName -Kind "Basic"
        #endregion

        #region Request three hours of RDP access from the caller's public IP
        $JitPolicy = (
            @{
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
    }

    #region Schedule daily shutdown at 23:00 in the local computer's time zone
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

    # Ensure the deployed VM is running.
    Start-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName

    # Store credentials for the DNS name or VM name, escaping password characters for cmd.exe.
    if ($PublicIP) {
        Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /generic:$FQDN /user:$($Credential.UserName) /pass:$($Credential.GetNetworkCredential().Password -replace "(\W)", '^$1')" -Wait
    }
    else {
        Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /generic:$VMName /user:$($Credential.UserName) /pass:$($Credential.GetNetworkCredential().Password -replace "(\W)", '^$1')" -Wait
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

<#
.SYNOPSIS
Creates a NAT gateway and associates it with an existing or new subnet.

.DESCRIPTION
Creates a Standard static public IP and a Standard NAT gateway with a ten-minute
idle timeout in the virtual network's resource group and region. With SubnetConfig,
associates the gateway with that existing subnet. With VirtualNetwork, creates a
subnet and a dedicated network security group, then associates the gateway.
Persists the subnet changes by updating the virtual network.

Downloads region and resource abbreviations from the Azure Naming Tool repository
to derive resource names from the virtual network name.

.PARAMETER VirtualNetwork
Specifies the existing virtual network in which to create a dedicated NAT-enabled
subnet and network security group. Accepts a PSVirtualNetwork from the pipeline.
Cannot be combined with SubnetConfig.

.PARAMETER SubnetConfig
Specifies an existing subnet to associate with the new NAT gateway. Accepts a
PSSubnet from the pipeline and supports the alias Subnet. Resolves the parent
virtual network from the subnet resource ID. Does not create a subnet or NSG.
Cannot be combined with VirtualNetwork.

.PARAMETER Force
Passes Force to public IP and NAT gateway creation to suppress confirmation
prompts for those operations.

.EXAMPLE
$Subnet | New-PsAvdNatGatewaySetup -Force

Creates a public IP and NAT gateway and associates the gateway with $Subnet.

.EXAMPLE
New-PsAvdNatGatewaySetup -VirtualNetwork $VirtualNetwork -Verbose

Creates a dedicated subnet, NSG, public IP, and NAT gateway in the virtual network.

.INPUTS
Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork
Microsoft.Azure.Commands.Network.Models.PSSubnet

.OUTPUTS
None. Updates Azure resources without returning an object.

.NOTES
Requires an authenticated Azure context and access to raw.githubusercontent.com.
Names assume Azure Naming Tool prefixes and a hyphen-separated virtual network
naming convention. Existing resources are not checked before creation.

For a new subnet, sorts existing address-prefix strings in descending order,
increments the third octet of the first prefix, and uses a /24 mask. This is not
an address-space allocator: verify that the proposed range is valid, lies within
the virtual network, and does not overlap another subnet before using this mode.

.LINK
https://learn.microsoft.com/azure/nat-gateway/quickstart-create-nat-gateway?tabs=powershell
#>
function New-PsAvdNatGatewaySetup {
    [CmdletBinding(PositionalBinding = $false)]
    Param( 
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName= 'VirtualNetwork')]
        [Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork] $VirtualNetwork,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName= 'Subnet')]
        [Alias('Subnet')]
        [Microsoft.Azure.Commands.Network.Models.PSSubnet] $SubnetConfig,

        [Switch] $Force
    )

    begin {
        #region Defining variables 
        #region Map available Azure regions to Azure Naming Tool abbreviations
        $AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
        $ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
        $shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
        #endregion

        #region Load resource abbreviations and name-length limits from Azure Naming Tool
        $Result = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/refs/heads/main/src/repository/resourcetypes.json 
        $ResourceTypeShortNameHT = $Result | Where-Object -FilterScript { $_.property -in @('', 'Windows') } | Select-Object -Property resource, shortName, lengthMax | Group-Object -Property resource -AsHashTable -AsString
        #endregion

        $PublicIPAddressPrefix = $ResourceTypeShortNameHT["Network/publicIPAddresses"].ShortName
        $VirtualNetworkPrefix = $ResourceTypeShortNameHT["Network/virtualNetworks"].ShortName
        $NetworkSecurityGroupPrefix = $ResourceTypeShortNameHT["Network/networkSecurityGroups"].ShortName
        $SubnetPrefix = $ResourceTypeShortNameHT["Network/virtualnetworks/subnets"].ShortName
        #endregion
    }
    process {
        #region Defining variables 
        if ($SubnetConfig) {
            # Retrieve the parent network so its subnet association can be persisted.
            $VirtualNetworkId = $SubnetConfig.Id -replace "/subnets/.*"
            $VirtualNetwork = Get-AzResource -ResourceId $VirtualNetworkId | Get-AzVirtualNetwork

            $ResourceGroupName = $VirtualNetwork.ResourceGroupName
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ResourceGroupName: $ResourceGroupName"
            $Location = $VirtualNetwork.Location
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Location: $Location"
            $LocationShortName = $shortNameHT[$Location].shortName
        }
        else {
            $ResourceGroupName = $VirtualNetwork.ResourceGroupName
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ResourceGroupName: $ResourceGroupName"
            $Location = $VirtualNetwork.Location
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Location: $Location"
            $LocationShortName = $shortNameHT[$Location].shortName

            # A new dedicated subnet gets its own NSG; existing subnets retain theirs.
            $NetworkSecurityGroupName = $VirtualNetwork.Name -replace $VirtualNetworkPrefix, $NetworkSecurityGroupPrefix -replace "(\w+)-(\w+)-(\w+)-(\w+)-(\d+)", '$1-$2-natgw-$4-$5'
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$NetworkSecurityGroupName: $NetworkSecurityGroupName"
            $NetworkSecurityGroup = New-AzNetworkSecurityGroup -Name $NetworkSecurityGroupName -ResourceGroupName $ResourceGroupName -Location $Location
        }
        $NatGatewayPrefix = "natgw"
        $NatGatewayName = $VirtualNetwork.Name -replace $VirtualNetworkPrefix, $NatGatewayPrefix
        $SubnetName = $VirtualNetwork.Name -replace $VirtualNetworkPrefix, $SubnetPrefix -replace "(\w+)-(\w+)-(\w+)-(\w+)-(\d+)", '$1-$2-natgw-$4-$5'
        $NatGatewayPublicIpName = "{0}-{1}" -f $PublicIPAddressPrefix, $NatGatewayName

        #region Derive a candidate /24 by incrementing the third octet of the lexically last prefix
        # This calculation does not validate network bounds or check for overlapping subnets.
        $RegExpPattern = "(\d+)\.(\d+).(\d+).(\d+)/(\d{1,2})"
        $HighestAddressPrefix = ((Get-AzVirtualNetwork -Name $VirtualNetwork.Name).Subnets.AddressPrefix) | Sort-Object -Descending | Select-Object -First 1
        [int]$Octet3 = ([regex]::match($HighestAddressPrefix, $RegExpPattern).Groups[3].Value)
        $Octet3++
        $NatGatewaySubnetAddressPrefix = $HighestAddressPrefix -replace $RegExpPattern, "`$1.`$2.$Octet3.`$4/24"

        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$NatGatewayName: $NatGatewayName"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$SubnetName: $SubnetName"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$NatGatewayPublicIpName: $NatGatewayPublicIpName"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$NatGatewaySubnetAddressPrefix: $NatGatewaySubnetAddressPrefix"
        #endregion

        #endregion
 
        #region Create the NAT gateway
        # Based on https://learn.microsoft.com/azure/nat-gateway/quickstart-create-nat-gateway?tabs=powershell
        #region Create public IP address for NAT gateway 
        $IP = @{
            Name              = $NatGatewayPublicIpName
            ResourceGroupName = $ResourceGroupName
            Location          = $Location
            Sku               = 'Standard'
            AllocationMethod  = 'Static'
            Force             = $Force.IsPresent
            #Zone = 1,2,3
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating Public IP: $NatGatewayPublicIpName"
        $PublicIp = New-AzPublicIpAddress @IP
        #endregion 

        #region Create NAT gateway resource 
        $Nat = @{
            ResourceGroupName    = $ResourceGroupName
            Name                 = $NatGatewayName
            IdleTimeoutInMinutes = '10'
            Sku                  = 'Standard'
            Location             = $Location
            PublicIpAddress      = $PublicIp
            Force                = $Force.IsPresent
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating NatGateway: $NatGatewayName"
        $NatGateway = New-AzNatGateway @Nat
        #endregion 

        if ($SubnetConfig) {
            # Replace the subnet's NAT association without changing its other settings.
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Updating SubNet: $($SubnetConfig.Name)"
            ($VirtualNetwork.Subnets | Where-Object -FilterScript {$_.Id -eq $SubnetConfig.Id}).NatGateway = $NatGateway
        }
        else
        {
            #region Build the new subnet configuration with its NAT gateway and NSG
            $Parameters = @{
                Name                 = $SubnetName
                AddressPrefix        = $NatGatewaySubnetAddressPrefix
                NatGateway           = $NatGateway
                NetworkSecurityGroup = $NetworkSecurityGroup
            }
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating SubNet: $SubnetName"
            $SubnetConfig = New-AzVirtualNetworkSubnetConfig @Parameters 
            #endregion 
        
            #region Add the new subnet to the in-memory virtual network
            $VirtualNetwork.Subnets += $SubnetConfig
            #endregion
        }
        # Commit either the existing subnet association or the new subnet to Azure.
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Updating vNet: $($VirtualNetwork.Name)"
        $null = $VirtualNetwork | Set-AzVirtualNetwork
        #endregion
    }
    end {}
}
#endregion

#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
# Resolve relative paths from the script's directory.
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

# Suppress Azure PowerShell breaking-change warnings for this process only.
# See https://aka.ms/azps-changewarnings.
$null = Update-AzConfig -DisplayBreakingChangeWarning $false -Scope Process
$PSDefaultParameterValues['Import-Module:DisableNameChecking'] = $true

#region Sign in when no Azure access token is available
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount
}
#endregion

#region Defining variables 
#region Map available Azure regions to Azure Naming Tool abbreviations
$AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
$ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
$shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
#endregion

#region Load resource abbreviations and name-length limits from Azure Naming Tool
$Result = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/refs/heads/main/src/repository/resourcetypes.json 
$ResourceTypeShortNameHT = $Result | Where-Object -FilterScript { $_.property -in @('', 'Windows') } | Select-Object -Property resource, shortName, lengthMax | Group-Object -Property resource -AsHashTable -AsString
#endregion

$StorageAccountSkuName = "Standard_LRS"
$AzureVMNameMaxLength = 15
#$VMSize = "Standard_D16s_v6"
# Select the first matching D2s SKU after sorting names in descending lexical order.
$VMSize = (Get-AzComputeResourceSku -Location $Location | Where-Object -FilterScript { $_.Name -match "^Standard_D2s_v" } | Sort-Object -Property Name -Descending | Select-Object -First 1).Name
if ([string]::IsNullOrEmpty($VMSize)) {
    Write-Error "The '$VMSize' is not available in the '$Location' location ..." -ErrorAction Stop
}

$LocationShortName = $shortNameHT[$Location].shortName
if ([string]::IsNullOrEmpty($LocationShortName)) {
    Write-Error "No location short name found for '$Location'" -ErrorAction Stop
}

# Use Azure Naming Tool abbreviations for resource-name prefixes.
$ResourceGroupPrefix = $ResourceTypeShortNameHT["Resources/resourcegroups"].ShortName
$StorageAccountPrefix = $StorageAccountPrefix = $ResourceTypeShortNameHT["Storage/storageAccounts"].ShortName
$VirtualMachinePrefix = $VirtualMachinePrefix = $ResourceTypeShortNameHT["Compute/virtualMachines"].ShortName
$NetworkSecurityGroupPrefix = $ResourceTypeShortNameHT["Network/networkSecurityGroups"].ShortName
$VirtualNetworkPrefix = $ResourceTypeShortNameHT["Network/virtualNetworks"].ShortName
$SubnetPrefix = $ResourceTypeShortNameHT["Network/virtualnetworks/subnets"].ShortName
$PublicIPAddressPrefix = $ResourceTypeShortNameHT["Network/publicIPAddresses"].ShortName
$Project = "vm"
$Role = "rnd"
#$DigitNumber = 4
$DigitNumber = $AzureVMNameMaxLength - ($VirtualMachinePrefix + $Project + $Role + $LocationShortName).Length

# Choose a shared resource suffix whose storage account name is available.
Do {
    $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
    $StorageAccountName = "{0}{1}{2}{3}{4:D$DigitNumber}" -f $StorageAccountPrefix, $Project, $Role, $LocationShortName, $Instance                       
} While ((-not(Get-AzStorageAccountNameAvailability -Name $StorageAccountName).NameAvailable))

$NetworkSecurityGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $NetworkSecurityGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
$VirtualNetworkName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $VirtualNetworkPrefix, $Project, $Role, $LocationShortName, $Instance                       
$SubnetName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $SubnetPrefix, $Project, $Role, $LocationShortName, $Instance                       
$ResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       

$StorageAccountName = $StorageAccountName.ToLower()
$NetworkSecurityGroupName = $NetworkSecurityGroupName.ToLower()
$VirtualNetworkName = $VirtualNetworkName.ToLower()
$SubnetName = $SubnetName.ToLower()
$ResourceGroupName = $ResourceGroupName.ToLower()

$VirtualNetworkAddressSpace = "10.10.0.0/16" # Virtual network address space in CIDR notation.
$SubnetIPRange = "10.10.1.0/24" # Subnet address range within the virtual network.
Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$StorageAccountName: $StorageAccountName"         
Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$NetworkSecurityGroupName: $NetworkSecurityGroupName"         
Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$VirtualNetworkName: $VirtualNetworkName"         
Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$SubnetName: $SubnetName"       
Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ResourceGroupName: $ResourceGroupName"
Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$VirtualNetworkAddressSpace: $VirtualNetworkAddressSpace"
Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$SubnetIPRange: $SubnetIPRange"

$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
if ($ResourceGroup) {
    # Destructive: delete the matching resource group and all resources it contains.
    $ResourceGroup | Remove-AzResourceGroup -Force -Verbose
}
$MyPublicIp = Invoke-RestMethod -Uri "https://ipv4.seeip.org"
#endregion

#region  Create the resource group shared by the VMs and supporting resources.
$ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
#endregion

#region Create the sample storage account with public blob access and shared-key access allowed.
$StorageAccount = New-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -Location $Location -SkuName $StorageAccountSkuName -MinimumTlsVersion TLS1_2 -EnableHttpsTrafficOnly $true -PublicNetworkAccess Enabled -AllowBlobPublicAccess $true -AllowSharedKeyAccess $true -Tag @{ SecurityControl = "Ignore" }
#endregion

#region Network Configuration
$RDPPort = 3389
$SecurityRules = @(
    #region Inbound
    # Allow inbound RDP from the caller's public IP.
    New-AzNetworkSecurityRuleConfig -Name RDPRule -Description "Allow RDP" -Access Allow -Protocol Tcp -Direction Inbound -Priority 300 -SourceAddressPrefix $MyPublicIp -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange $RDPPort
    # Allow inbound HTTP from the caller's public IP.
    New-AzNetworkSecurityRuleConfig -Name HTTPRule -Description "Allow HTTP" -Access Allow -Protocol Tcp -Direction Inbound -Priority 301 -SourceAddressPrefix $MyPublicIp -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 80
    # Allow inbound HTTPS from the caller's public IP.
    New-AzNetworkSecurityRuleConfig -Name HTTPSRule -Description "Allow HTTPS" -Access Allow -Protocol Tcp -Direction Inbound -Priority 302 -SourceAddressPrefix $MyPublicIp -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 443
    #endregion
)
$NetworkSecurityGroup = New-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Location $Location -Name $NetworkSecurityGroupName -SecurityRules $SecurityRules -Force

$VirtualNetwork = New-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VirtualNetworkName  -AddressPrefix $VirtualNetworkAddressSpace -Location $Location
$null = Add-AzVirtualNetworkSubnetConfig -Name $SubnetName -VirtualNetwork $VirtualNetwork -AddressPrefix $SubnetIPRange -NetworkSecurityGroupId $NetworkSecurityGroup.Id

$VirtualNetwork = Set-AzVirtualNetwork -VirtualNetwork $VirtualNetwork
$Subnet = Get-AzVirtualNetworkSubnetConfig -Name $SubnetName -VirtualNetwork $VirtualNetwork
if (-not($PublicIP)) {
    # Provide explicit outbound connectivity for VMs that do not have public IPs.
    $Subnet | New-PsAvdNatGatewaySetup -Force -Verbose
}
#endregion

#region Generate administrator credentials and copy the password to the clipboard
$Username = $env:USERNAME
#$ClearTextPassword = 'I@m@JediLikeMyF@therB4Me'
#$ClearTextPassword = New-RandomPassword -ClipBoard -Verbose
#$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$SecurePassword = New-RandomPassword -ClipBoard -AsSecureString -Online -Verbose
$Credential = New-Object System.Management.Automation.PSCredential -ArgumentList ($Username, $SecurePassword)
#endregion

#region VM Provisioning
# Provision VMs in thread jobs, importing the required functions into each job.
$Jobs = 1..$VMNumber | ForEach-Object -Process {
    $VMName = "{0}{1}{2}{3}{4:D$DigitNumber}" -f $VirtualMachinePrefix, $Project, $Role, $LocationShortName, $_                       
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$VMName: $VMName"         
    $PercentComplete = 1/$VMNumber
    Write-Progress -Id 0 -Activity "[$($_)/$($VMNumber)] Creating VMs ..." -CurrentOperation "Creating '$VMName' VM ..." -Status $('{0:N0}%' -f $PercentComplete) -PercentComplete $PercentComplete
    if ($VMName.Length -gt $AzureVMNameMaxLength) {
        Write-Error "'$VMName' exceeds $AzureVMNameMaxLength characters" -ErrorAction Stop
    }

    $Params = @{
        ResourceGroupName = $ResourceGroupName 
        VMName            = $VMName 
        Subnet            = $Subnet 
        VMSize            = $VMSize 
        Location          = $Location 
        Spot              = $true
        Verbose           = $true
        PublicIP          = $PublicIP.IsPresent
        Credential        = $Credential
    }
    #New-AzSubnetVM @Params

    $ExportedFunctions = [scriptblock]::Create(@"
        Function New-AzSubnetVM { ${Function:New-AzSubnetVM} }
"@)

    Start-ThreadJob -ScriptBlock { param() New-AzSubnetVM @using:Params } -InitializationScript $ExportedFunctions -StreamingHost $Host
}
Write-Progress -Id 0 -Activity "Completed !" -Completed

# Wait for every job, receive its output, and remove completed jobs.
Write-Host -Object "Waiting for the creation of the virtual machines to complete ..." 
$null = $Jobs | Receive-Job -Wait -AutoRemoveJob
Write-Host -Object "Virtual machine creation complete !" -ForegroundColor Green
#endregion
#endregion