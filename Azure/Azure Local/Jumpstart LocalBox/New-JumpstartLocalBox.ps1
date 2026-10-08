<#
This Sample Code is provided for the purpose of illustration only
and is not intended to be used in a production environment.  THIS
SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
# WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
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

#Prerequisite: https://jumpstart.azure.com/azure_jumpstart_localbox/deployment_az

#requires -Version 5 #-Modules Az.Accounts, Az.Compute, Az.Quota, Az.Resources, Az.StackHCI, Az.StackHCIVM

[CmdletBinding(PositionalBinding = $false)]
param
(
    #LAW Supported Regions : ((Get-AzResourceProvider -ProviderNamespace 'Microsoft.OperationalInsights').ResourceTypes | Where-Object -FilterScript { $_.ResourceTypeName -eq 'workspaces' }).Locations
    [ValidateSet('australiacentral', 'australiacentral2', 'australiaeast', 'australiasoutheast', 'austriaeast', 'brazilsouth', 'brazilsoutheast', 'canadacentral', 'canadaeast', 'centralindia', 'centralus', 'chilecentral', 'eastasia', 'eastus', 'eastus2', 'francecentral', 'francesouth', 'germanynorth', 'germanywestcentral', 'indonesiacentral', 'israelcentral', 'italynorth', 'japaneast', 'japanwest', 'jioindiacentral', 'jioindiawest', 'koreacentral', 'koreasouth', 'malaysiawest', 'mexicocentral', 'newzealandnorth', 'northcentralus', 'northeurope', 'norwayeast', 'norwaywest', 'polandcentral', 'qatarcentral', 'southafricanorth', 'southafricawest', 'southcentralus', 'southeastasia', 'southindia', 'spaincentral', 'swedencentral', 'switzerlandnorth', 'switzerlandwest', 'uaecentral', 'uaenorth', 'uksouth', 'ukwest', 'westcentralus', 'westeurope', 'westus', 'westus2', 'westus3')]
    [string[]] $location,
    [ValidateSet('australiaeast', 'southcentralus', 'eastus', 'westeurope', 'southeastasia', 'canadacentral', 'japaneast', 'centralindia')]
    [string[]] $azureLocalInstanceLocation
)

trap {
    Write-Host "Stopping Transcript ..."
    Stop-Transcript
    break
}


#region function definitions 
#Based from https://adamtheautomator.com/powershell-random-password/
<#
.SYNOPSIS
Generates a password that meets Azure virtual machine complexity requirements.

.DESCRIPTION
Creates a random password locally or retrieves one from DinoPass, rejects known
prohibited values, and checks the password against the Have I Been Pwned range API.
The password can be returned as plain text or as a secure string and optionally
copied to the clipboard.

.PARAMETER minLength
Specifies the inclusive minimum length used when selecting a random password length.

.PARAMETER maxLength
Specifies the exclusive maximum length used when selecting a random password length.

.PARAMETER AsSecureString
Returns the generated password as a SecureString instead of plain text.

.PARAMETER ClipBoard
Copies the generated password to the clipboard.

.PARAMETER nonAlphaChars
Specifies how many non-alphanumeric characters the local generator should include.

.PARAMETER Online
Uses the DinoPass service instead of the local System.Web password generator.
#>
function New-RandomPassword {
    [CmdletBinding(PositionalBinding = $false, DefaultParameterSetName = 'GeneratePassword')]
    param
    (
        [ValidateRange(12, 122)]
        [int] $minLength = 12, ## characters
        [ValidateRange(13, 123)]
        [ValidateScript({ $_ -gt $minLength })]
        [int] $maxLength = 15, ## characters
        [switch] $AsSecureString,
        [switch] $ClipBoard,
        [Parameter(ParameterSetName = 'GeneratePassword')]
        [int] $nonAlphaChars = 3,
        [Parameter(ParameterSetName = 'DinoPass')]
        [switch] $Online
    )

    # Uses the k-anonymity API: only the first five SHA-1 characters leave this computer.
    function Test-PwnedPassword {
        [CmdletBinding(PositionalBinding = $false)]
        param(
            [Parameter(Mandatory)]
            [string]$Password
        )

        #SHA1 Calculation
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

            return [PSCustomObject]@{
                PasswordCompromised = $false
                Occurrences         = 0
            }
        }
        catch {
            throw "Error when calling the API : $_"
        }
    }

    #From https://learn.microsoft.com/en-us/azure/virtual-machines/windows/faq#what-are-the-password-requirements-when-creating-a-vm-
    # Azure rejects these commonly used passwords even when they satisfy complexity rules.
    $ProhibitedPasswords = @('abc@123', 'iloveyou!', 'P@$$w0rd', 'P@ssw0rd', 'P@ssword123', 'Pa$$word', 'pass@word1', 'Password!', 'Password1', 'Password22')
    $length = Get-Random -Minimum $minLength -Maximum $maxLength
    # Regenerate until all character classes are present and no compromised value is found.
    Do {
        if ($Online) {
            $URI = "https://www.dinopass.com/password/custom?length={0}&useSymbols=true&useNumbers=true&useCapitals=true" -f $length
            $RandomPassword = Invoke-RestMethod -Uri $URI
        }
        else {
            Add-Type -AssemblyName 'System.Web'
            $RandomPassword = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
        }
    } Until (($RandomPassword -notin $ProhibitedPasswords) -and (($RandomPassword -match '[A-Z]') -and ($RandomPassword -match '[a-z]') -and ($RandomPassword -match '\d') -and ($RandomPassword -match '\W') -and (-not((Test-PwnedPassword -Password $RandomPassword).PasswordCompromised))))

    #Write-Host -Object "The password is : $RandomPassword"
    if ($ClipBoard) {
        #Write-Verbose -Message "The password has beeen copied into the clipboard (Use Win+V) ..."
        $RandomPassword | Set-Clipboard
    }
    if ($AsSecureString) {
        ConvertTo-SecureString -String $RandomPassword -AsPlainText -Force
    }
    else {
        $RandomPassword
    }
}

function Add-RDPCredential {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string] $ComputerName,
        [Parameter(Mandatory = $true)]
        [PSCredential] $Credential,
        [switch] $Connect
    )
    # Adding Credentials to the Credential Manager (and escaping the password)
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /generic:$ComputerName /user:$($Credential.UserName) /pass:$($Credential.GetNetworkCredential().Password -replace "(\W)", '^$1')" -Wait
    Write-Host -Object "Your RDP credentials (login/password) are $($Credential.UserName)/$($Credential.GetNetworkCredential().Password)" -ForegroundColor Green
    if ($Connect) {
        $MSTSCProcess = Start-Process -FilePath "mstsc" -ArgumentList "/v:$ComputerName /f" -PassThru -WindowStyle Normal
        Do {
            Start-Sleep -Seconds 1
            $MSTSCProcess = Get-Process -Id $MSTSCProcess.Id -ErrorAction Stop
        } While ([string]::IsNullOrEmpty($MSTSCProcess.MainWindowtitle)) 
        #Start-Sleep -Seconds 3
        #region Bringing Process windows in the foreground
        $signature = '
        [DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
        [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        [DllImport("user32.dll")] public static extern int SetForegroundWindow(IntPtr hwnd);
        '
        $type = Add-Type -MemberDefinition $signature -Name xShowWindow -PassThru
        $hwnd = $MSTSCProcess.MainWindowHandle
        $null = $type::ShowWindow($hwnd, 5)
        $null = $type::SetForegroundWindow($hwnd) 
        Start-Sleep -Seconds 3
        #endregion
        #region Sending Keystrokes for 'Don't ...' and 'yes'
        $wshell = New-Object -ComObject wscript.shell;
        #$null = $wshell.AppActivate((Get-Process -Id $MSTSCProcess.Id -ErrorAction Stop).MainWindowtitle, $true)
        Start-Sleep -Milliseconds 100
        $wshell.SendKeys('d')
        Start-Sleep -Milliseconds 100
        $wshell.SendKeys('y')
        #endregion
    }
}

#region Azure Quota Function
#From https://github.com/lavanack/laurentvanacker.com/blob/master/Azure/Azure%20Virtual%20Machine/Get-AzQuotaData.ps1
<#
.SYNOPSIS
Returns regional Azure Compute quota for one or more resource families.

.DESCRIPTION
Queries the quota limit and current usage for each subscription, location, and
resource name combination, then calculates remaining capacity and percentage free.

.PARAMETER Location
Specifies the Azure regions to query.

.PARAMETER ResourceName
Specifies Compute quota resource names, such as virtualMachines or a VM family.

.PARAMETER SubscriptionId
Specifies the Azure subscriptions to query.
#>
function Get-AzVMQuota {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        [ValidateScript({ $_ -in $((Get-AzLocation).Location) })]
        [string[]] $Location = $((Get-AzLocation).Location),
        #[ValidateScript({$_ -in $((Get-AzComputeResourceSku | Where-Object { $_.ResourceType -eq "virtualMachines" }).Family)})]
        [string[]] $ResourceName = @("virtualMachines"),
        [ValidateScript({ $_ -in $((Get-AzSubscription).Id) })]
        [string[]] $SubscriptionId = (Get-AzSubscription).Id
    )

    $Quota = foreach ($CurrentSubscriptionId in $SubscriptionId) {
        Write-Verbose -Message "Processing '$CurrentSubscriptionId' Subscription"
        foreach ($CurrentLocation in $Location) {
            Write-Verbose -Message "Processing '$CurrentLocation' Azure Location"
            foreach ($CurrentResourceName in $ResourceName) {
                Write-Verbose -Message "Processing '$CurrentResourceName' Azure Resource"
                # Azure quota APIs use a regional Microsoft.Compute provider scope.
                $Scope = "/subscriptions/$CurrentSubscriptionId/providers/Microsoft.Compute/locations/$CurrentLocation"
                Write-Verbose -Message "`$Scope: $Scope"
                try {
                    $Limit = (Get-AzQuota -Scope $Scope -ResourceName $CurrentResourceName -ErrorAction Stop).Limit.Value
                    $Usage = (Get-AzQuotaUsage -Scope $Scope -Name $CurrentResourceName -ErrorAction Stop).UsageValue
                }
                catch {
                    Write-Warning "$($_.Exception.Message)"
                    $Limit = $null
                }
                if ([string]::IsNullOrEmpty($Limit)) {
                    $Limit = "N/A"
                    Write-Warning "No data for '$CurrentLocation'"
                }
                # Emit one object per subscription, region, and quota resource combination.
                [PSCustomObject]@{"SubscriptionId" = $CurrentSubscriptionId; "Location" = $CurrentLocation; ResourceName = $CurrentResourceName; Limit = $Limit; Usage = $Usage; Available = $Limit - $Usage; PercentFree = $("{0:p2}" -f $(($Limit - $Usage) / $Limit)) } 
            }
        }
    }
    $Quota
}

<#
.SYNOPSIS
Returns total regional vCPU quota for one or more Azure subscriptions.

.DESCRIPTION
Queries the Microsoft.Compute cores quota and usage in each requested region and
returns the remaining core capacity as structured objects.

.PARAMETER Location
Specifies the Azure regions to query.

.PARAMETER SubscriptionId
Specifies the Azure subscriptions to query.
#>
function Get-AzCoreQuota {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        [ValidateScript({ $_ -in $((Get-AzLocation).Location) })]
        [string[]] $Location = $((Get-AzLocation).Location),
        [ValidateScript({ $_ -in $((Get-AzSubscription).Id) })]
        [string[]] $SubscriptionId = (Get-AzSubscription).Id
    )

    [string] $ResourceName = "cores"
    $Quota = foreach ($CurrentSubscriptionId in $SubscriptionId) {
        Write-Verbose -Message "Processing '$CurrentSubscriptionId' Subscription"
        foreach ($CurrentLocation in $Location) {
            Write-Verbose -Message "Processing '$CurrentLocation' Azure Location"
            foreach ($CurrentResourceName in $ResourceName) {
                Write-Verbose -Message "Processing '$CurrentResourceName' Azure Resource"
                $Scope = "/subscriptions/$CurrentSubscriptionId/providers/Microsoft.Compute/locations/$CurrentLocation"
                Write-Verbose -Message "`$Scope: $Scope"
                try {
                    $Limit = (Get-AzQuota -Scope $Scope -ResourceName $CurrentResourceName -ErrorAction Stop).Limit.Value
                    $Usage = (Get-AzQuotaUsage -Scope $Scope -Name $CurrentResourceName -ErrorAction Stop).UsageValue
                }
                catch {
                    Write-Warning "$($_.Exception.Message)"
                    $Limit = $null
                }
                if ([string]::IsNullOrEmpty($Limit)) {
                    $Limit = "N/A"
                    Write-Warning "No data for '$CurrentLocation'"
                }
                [PSCustomObject]@{"SubscriptionId" = $CurrentSubscriptionId; "Location" = $CurrentLocation; ResourceName = $CurrentResourceName; Limit = $Limit; Usage = $Usage; Available = $Limit - $Usage; PercentFree = $("{0:p2}" -f $(($Limit - $Usage) / $Limit)) } 
            }
        }
    }
    $Quota
}

<#
.SYNOPSIS
Calculates how many virtual machines of a requested SKU can be deployed.

.DESCRIPTION
Combines the VM-family quota with the total regional core quota. The lower of those
two capacities is returned because both quota constraints must permit a deployment.

.PARAMETER Location
Specifies the Azure regions to evaluate.

.PARAMETER SubscriptionId
Specifies the Azure subscriptions to evaluate.

.PARAMETER ComputeResourceSku
Specifies one or more Azure virtual machine SKU names.
#>
function Get-AzAvailableComputeResourceSku {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        [ValidateScript({ $_ -in $((Get-AzLocation).Location) })]
        [string[]] $Location = $((Get-AzLocation).Location),
        [ValidateScript({ $_ -in $((Get-AzSubscription).Id) })]
        [string[]] $SubscriptionId = (Get-AzSubscription).Id,
        [Parameter(Mandatory = $True)]
        #[ValidateScript({$_ -in $((Get-AzComputeResourceSku -Location $Location).Name)})]
        [Alias("Sku")]
        [string[]] $ComputeResourceSku
    )

    
    $AvailableComputeResourceSku = foreach ($CurrentSubscriptionId in $SubscriptionId) {
        Write-Verbose -Message "Processing '$CurrentSubscriptionId' Subscription"
        foreach ($CurrentLocation in $Location) {
            Write-Verbose -Message "Processing '$CurrentLocation' Azure Location"
            foreach ($CurrentComputeResourceSku in $ComputeResourceSku) {
                Write-Verbose -Message "`$CurrentComputeResourceSku :$CurrentComputeResourceSku"
                # Resolve the SKU family and vCPU count needed for both quota calculations.
                $Family = (Get-AzComputeResourceSku -Location $CurrentLocation | Where-Object -FilterScript { $_.Name -eq $ComputeResourceSku }).Family
                Write-Verbose -Message "`$Family :$Family"
                $vCPUs = ((Get-AzComputeResourceSku -Location $CurrentLocation | Where-Object -FilterScript { $_.Name -eq $ComputeResourceSku }).Capabilities | Where-Object -FilterScript { $_.Name -eq "vCPUs" }).Value
                Write-Verbose -Message "`$vCPUs :$vCPUs"

                $VMQuota = Get-AzVMQuota -Location $CurrentLocation -ResourceName $Family -SubscriptionId $CurrentSubscriptionId
                Write-Verbose -Message "`$VMQuota:`r`n$($VMQuota | Out-String)"
                $CoreQuota = Get-AzCoreQuota -Location $CurrentLocation -SubscriptionId $CurrentSubscriptionId
                Write-Verbose -Message "`$CoreQuota:`r`n$($CoreQuota | Out-String)"
                $AvailablePerVMQuota = $VMQuota.Available
                Write-Verbose -Message "`$AvailablePerVMQuota: $AvailablePerVMQuota"
                $AvailablePerCoreQuota = [math]::Floor($CoreQuota.Available / $vCPUs)
                Write-Verbose -Message "`$AvailablePerCoreQuota: $AvailablePerCoreQuota"
                # Deployable capacity is constrained by whichever quota is exhausted first.
                $Available = [math]::min($AvailablePerVMQuota, $AvailablePerCoreQuota)
                Write-Verbose -Message "`$Available: $Available"
                [PSCustomObject]@{"SubscriptionId" = $CurrentSubscriptionId; "Location" = $CurrentLocation; ComputeResourceSku = $CurrentComputeResourceSku; AvailablePerVMQuota = $AvailablePerVMQuota; AvailablePerCoreQuota = $AvailablePerCoreQuota; Available = $Available } 
            }
        }
    }
    $AvailableComputeResourceSku
}
#endregion

<#
.SYNOPSIS
Deploys an Azure Arc Jumpstart LocalBox environment from Bicep.

.DESCRIPTION
Builds Azure Naming Tool-based resource names, creates a resource group, generates
a Bicep parameter file, launches the Azure portal deployment view, and submits the
resource-group deployment. A failed deployment schedules the resource group for
removal and returns false; a successful deployment returns true.

.PARAMETER tenantId
Specifies the Microsoft Entra tenant ID used by the deployment.

.PARAMETER spnProviderId
Specifies the object ID of the Azure Stack HCI resource provider service principal.

.PARAMETER windowsAdminUsername
Specifies the administrator username for the deployed Windows virtual machine.

.PARAMETER windowsAdminPassword
Specifies the administrator password passed to the Bicep deployment.

.PARAMETER logAnalyticsWorkspaceName
Specifies the Log Analytics workspace name.

.PARAMETER natDNS
Specifies the DNS server used by the nested environment.

.PARAMETER githubAccount
Specifies the GitHub account containing the Jumpstart source repository.

.PARAMETER githubBranch
Specifies the source repository branch used by the deployment.

.PARAMETER deployBastion
Controls whether Azure Bastion is deployed.

.PARAMETER location
Specifies the Azure region for the resource group and supporting resources.

.PARAMETER azureLocalInstanceLocation
Specifies the Azure region represented by the Azure Local instance.

.PARAMETER rdpPort
Specifies the RDP port exposed by the deployment.

.PARAMETER autoDeployClusterResource
Controls automatic deployment of the Azure Local cluster resource.

.PARAMETER autoUpgradeClusterResource
Controls automatic upgrade of the Azure Local cluster resource.

.PARAMETER vmAutologon
Controls automatic Windows sign-in on the deployed virtual machine.

.PARAMETER vmSize
Specifies the Azure virtual machine SKU used to host LocalBox.

.PARAMETER enableAzureSpotPricing
Controls whether the virtual machine uses Azure Spot pricing.

.PARAMETER governResourceTags
Controls whether resource tagging governance is enabled.

.PARAMETER tags
Specifies tags assigned to deployed Azure resources.

.PARAMETER BicepFileDir
Specifies the directory containing main.bicep.

.OUTPUTS
System.Boolean. Returns true for a successful deployment and false after a failure.
#>
function New-JumpstartLocalBox {
    [CmdletBinding(PositionalBinding = $false, DefaultParameterSetName = 'WindowsAdmin')]
    param
    (
        [string] $tenantId = $((Get-AzTenant).Id),
        [string] $spnProviderId = $(Get-AzADServicePrincipal -DisplayName "Microsoft.AzureStackHCI Resource Provider").Id,
        [Parameter(ParameterSetName = 'WindowsAdmin')]
        [string] $windowsAdminUsername = $env:USERNAME,
        [Parameter(ParameterSetName = 'WindowsAdmin')]
        [string] $windowsAdminPassword = $(New-RandomPassword -Online -ClipBoard),
        [Parameter(Mandatory=$True, ParameterSetName = 'Credential')]
        [PSCredential] $Credential,
        [string] $logAnalyticsWorkspaceName = 'LocalBox-Workspace',
        [string] $natDNS = '8.8.8.8',
        [string] $githubAccount = 'microsoft',
        [string] $githubBranch = 'main',
        [string] $deployBastion = $false,
        #LAW Supported Regions : ((Get-AzResourceProvider -ProviderNamespace 'Microsoft.OperationalInsights').ResourceTypes | Where-Object -FilterScript { $_.ResourceTypeName -eq 'workspaces' }).Locations
        [ValidateSet('australiacentral', 'australiacentral2', 'australiaeast', 'australiasoutheast', 'austriaeast', 'brazilsouth', 'brazilsoutheast', 'canadacentral', 'canadaeast', 'centralindia', 'centralus', 'chilecentral', 'eastasia', 'eastus', 'eastus2', 'francecentral', 'francesouth', 'germanynorth', 'germanywestcentral', 'indonesiacentral', 'israelcentral', 'italynorth', 'japaneast', 'japanwest', 'jioindiacentral', 'jioindiawest', 'koreacentral', 'koreasouth', 'malaysiawest', 'mexicocentral', 'newzealandnorth', 'northcentralus', 'northeurope', 'norwayeast', 'norwaywest', 'polandcentral', 'qatarcentral', 'southafricanorth', 'southafricawest', 'southcentralus', 'southeastasia', 'southindia', 'spaincentral', 'swedencentral', 'switzerlandnorth', 'switzerlandwest', 'uaecentral', 'uaenorth', 'uksouth', 'ukwest', 'westcentralus', 'westeurope', 'westus', 'westus2', 'westus3')]
        [string] $location = 'australiasoutheast',
        [ValidateSet('australiaeast', 'southcentralus', 'eastus', 'westeurope', 'southeastasia', 'canadacentral', 'japaneast', 'centralindia')]
        [string] $azureLocalInstanceLocation = 'australiaeast',
        [string] $rdpPort = '3389',
        [string] $autoDeployClusterResource = $true,
        [string] $autoUpgradeClusterResource = $false,
        [string] $vmAutologon = $true,
        [ValidateSet('Standard_E32s_v5', 'Standard_E32s_v6')]
        [string] $vmSize = 'Standard_E32s_v6',
        [string] $enableAzureSpotPricing = $false,
        [string] $governResourceTags = $true,
        [hashtable] $tags = @{ 'Project' = 'jumpstart_LocalBox' },
        [ValidateScript({ Test-Path -Path $_  -PathType Container })]
        [Parameter(Mandatory = $True)]
        [string] $BicepFileDir
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$azureLocalInstanceLocation: $azureLocalInstanceLocation"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$location: $location"

    #region Credential Management
    if ($Credential) {
        $windowsAdminUsername = $Credential.UserName
        $windowsAdminPassword = $Credential.GetNetworkCredential().Password
    }
    #endregion

    #region Defining variables 
    #region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
    $AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
    $ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
    $ANTResourceLocationShortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
    #endregion

    #region Building an Hashtable to get the shortname of every Azure resource based on a JSON file on the Github repository of the Azure Naming Tool
    $Result = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/refs/heads/main/src/repository/resourcetypes.json 
    $ResourceTypeShortNameHT = $Result | Where-Object -FilterScript { $_.property -in @('', 'Windows') } | Select-Object -Property resource, shortName, lengthMax | Group-Object -Property resource -AsHashTable -AsString
    #endregion

    # Add a zero-padded random suffix to reduce resource-group naming collisions.
    Do {
        $DigitNumber = 3
        $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
        $LocationShortName = $ANTResourceLocationShortNameHT[$Location].shortName
        $ResourceGroupPrefix = $ResourceTypeShortNameHT["Resources/resourcegroups"].ShortName
        $ResourceGroupName = "{0}-az-local-{1}-{2:D$DigitNumber}" -f $ResourceGroupPrefix, $LocationShortName, $Instance                       
        $ResourceGroupName = $ResourceGroupName.ToLower()
    } While (Get-AzResourceGroup -ResourceGroupName $ResourceGroupName -Location $Location -ErrorAction Ignore)
    #endregion
    
    #region ResourceGroup Management
    #region ResourceGroup Setup
    <#    
    $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
    if ($ResourceGroup) {
        #Step 0: Remove previously existing Azure Resource Group with the same name
        $ResourceGroup | Remove-AzResourceGroup -Force -Verbose
    }
    #>
    $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
    #endregion

    #region ResourceGroup Deployment
    Push-Location -Path $BicepFileDir
    $TemplateFile = "main.bicep"
    $TemplateParameterFile = "main.bicepparam"
    # Materialize runtime values as a Bicep parameter file beside the template.
    $TemplateParameterFileContent = @"
using './main.bicep'

param tenantId = '$tenantId'
param spnProviderId = '$spnProviderId'
param windowsAdminUsername = '$windowsAdminUsername'
param windowsAdminPassword = '$windowsAdminPassword'
param logAnalyticsWorkspaceName = '$logAnalyticsWorkspaceName'
param natDNS = '$natDNS'
param githubAccount = '$githubAccount'
param githubBranch = '$githubBranch'
param deployBastion = $(($deployBastion).ToString().ToLower())
param location = '$location'
param azureLocalInstanceLocation = '$azureLocalInstanceLocation'
param rdpPort = '$rdpPort'
param autoDeployClusterResource = $(($autoDeployClusterResource).ToString().ToLower())
param autoUpgradeClusterResource = $(($autoUpgradeClusterResource).ToString().ToLower())
param vmAutologon = $(($vmAutologon).ToString().ToLower())
param vmSize = '$vmSize'
param enableAzureSpotPricing = $(($enableAzureSpotPricing).ToString().ToLower())
param governResourceTags = $(($governResourceTags).ToString().ToLower())
param tags = $(($tags | ConvertTo-Json).Replace('"', "'"))
"@

    $null = New-Item -Path $TemplateParameterFile -ItemType File -Value $TemplateParameterFileContent -Force
    $SubscriptionId = (Get-AzContext).Subscription.Id
    # Open and copy the deployment blade URL so progress can be monitored interactively.
    $ResourceGroupDeploymentURI = "https://portal.azure.com/#@{0}/resource/subscriptions/{1}/resourceGroups/{2}/deployments" -f $((Get-AzTenant).Domains[-1]), $SubscriptionId, $ResourceGroupName
    Start-Process $ResourceGroupDeploymentURI 
    $ResourceGroupDeploymentURI | Set-ClipBoard
    $ResourceGroupDeployment = New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateFile $TemplateFile -TemplateParameterFile $TemplateParameterFile
    Pop-Location
    #endregion
    #endregion

    # Clean up a failed attempt so the caller can retry with another location.
    if ($ResourceGroupDeployment.ProvisioningState -ne 'Succeeded') {
        Write-Warning -Message "The deployment failed :`r`n$($ResourceGroupDeploymentURI | Out-string)`r`n`r`nRemoving the '$ResourceGroupName' dedicated created ResourceGroup ..."
        $ResourceGroup | Remove-AzResourceGroup -Force -AsJob
        return [PSCustomObject]@{Succeeded = $false; ResourceGroupName = $null; Location = $location}
    }
    else {
        #region DNS Name Setup
        $VMName = "LocalBox-Client"
        $VM = Get-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName
        $NIC = Get-AzNetworkInterface -ResourceId $VM.NetworkProfile.NetworkInterfaces[0].Id
        $PublicIpId = $NIC.IpConfigurations[0].PublicIpAddress.Id
        $PublicIp = Get-AzPublicIpAddress -ResourceGroupName ($PublicIpId -split '/')[4] -Name ($PublicIpId -split '/')[-1]
        Do {
            $RandomString = ((New-Guid).Guid -replace "\W").Substring(0,8)
            $DomainNameLabel = $("{0}-{1}-{2}" -f $VMName, $Instance, $RandomString).ToLower()
            $FQDN = $("{0}.{1}.cloudapp.azure.com" -f $DomainNameLabel, $Location).ToLower()
        } While ($null -ne $(Resolve-DnsName $FQDN -ErrorAction Ignore))
        $PublicIP.DnsSettings = @{
            #Fqdn = $FQDN
            DomainNameLabel = $DomainNameLabel
        }
        $null = $PublicIP | Set-AzPublicIpAddress
        #endregion

        #region Adding Credentials to the Credential Manager (and escaping the password)
        Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /generic:$FQDN /user:$windowsAdminUsername /pass:$($windowsAdminPassword -replace "(\W)", '^$1')" -Wait
        #endregion

        #region JIT Access Management
        $JitPolicyTimeInHours = 3
        $JitPolicyName = "Default"
        #region Enabling JIT Access
        $NewJitPolicy = (@{
                id    = $VM.Id
                ports = (@{
                        number                     = $rdpPort;
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
        $MyPublicIp = Invoke-RestMethod -Uri "https://ipv4.seeip.org"
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
        $null = Start-AzJitNetworkAccessPolicy -ResourceGroupName $($VM.ResourceGroupName) -Location $VM.Location -Name $JitPolicyName -VirtualMachine $ActivationVM
        #endregion
        #endregion

        <#
        mstsc /v $FQDN
        Write-Host -Object "Your RDP credentials (login/password) are $windowsAdminUsername/$windowsAdminPassword" -ForegroundColor Green
        #>

        $SecurePassword = ConvertTo-SecureString -String $windowsAdminPassword -AsPlainText -Force
        $Credential = New-Object System.Management.Automation.PSCredential -ArgumentList ($windowsAdminUsername, $SecurePassword)
        Add-RDPCredential -ComputerName $FQDN -Credential $Credential -Connect

        return [PSCustomObject]@{Succeeded = $true; ResourceGroupName = $ResourceGroupName; Location = $location}
    }
}

function Wait-AzConnectedMachine {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $True)]
        [ValidateNotNull()]
        [string] $ResourceGroupName
    )

    $ResourceGroup = Get-AzResourceGroup -ResourceGroupName $ResourceGroupName -ErrorAction Ignore
    if (-not($ResourceGroup)) {
        Write-Error -Message "the '$ResourceGroupName' ResourceGroup doesn't exist !!!" -ErrorAction Stop
    }

    #region From https://jumpstart.azure.com/azure_jumpstart_localbox/cloud_deployment#azure-local-instance-validation-and-deployment-from-the-azure-portal
    #region Waiting AzLHOST1 and AzLHOST2 have been created as Arc-enabled servers.
    $ReferenceObject = "AzLHOST1", "AzLHOST2"
    Do {
        $Seconds = 300
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping $Seconds seconds ..."
        Start-Sleep -Seconds $Seconds
        $AzureArcMachines = Get-AzConnectedMachine -ResourceGroupName $ResourceGroupName
        #If not the same one(s)
        if ($AzureArcMachines) {
            $Compare = Compare-Object -ReferenceObject $ReferenceObject -DifferenceObject $AzureArcMachines
        }
        else {
            $Compare = $null
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Compare: $($Compare | Out-String)"
    } While (-not($Compare))
    Write-Host -Object "$($ReferenceObject -join ',') Azure Arc Machines Created ..." -ForegroundColor Green
    #endregion 

    <#
    #region Waiting localcluster deployments end - v1
    Do {
        $Seconds = 600
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping $Seconds seconds ..."
        Start-Sleep -Seconds $Seconds
        $RunningDeployments = Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName | Where-Object -FilterScript {$_.ProvisioningState -match "ing$"}
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Compare: $($RunningDeployments | Out-String)"
    } While ($RunningDeployments)
    Write-Host -Object "No more running Azure ResourceGroup Deployment(s) ..." -ForegroundColor Green
    #endregion 
    #>

    #region Waiting localcluster deployments end - v2
    $ClusterName = "localboxcluster"
    $ResourceGroup = Get-AzResourceGroup -ResourceGroupName $Result.ResourceGroupName -Location  $Result.Location
    Do {
        $Seconds = 300
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping $Seconds seconds ..."
        Start-Sleep -Seconds $Seconds
        #region Azure Local resource
        <#
        $ClusterResourceId = @(
            $ResourceGroup.ResourceId
            "providers/Microsoft.AzureStackHCI/clusters/$ClusterName"
        ) -join "/"

        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ClusterResourceId: $ClusterResourceId)"
        $Cluster = Get-AzResource -ResourceId $ClusterResourceId -ExpandProperties -ErrorAction Ignore
        #>
        $Cluster = Get-AzStackHciCluster -ResourceGroupName $ResourceGroup.ResourceGroupName -ClusterName $ClusterName -ErrorAction Ignore
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Cluster: $($Cluster | Out-String)"
        #endregion
    } While (($null -eq $Cluster) -or ($Cluster.Properties.provisioningState -ne "Succeeded") -or ($Cluster.Properties.connectivityStatus -ne "Connected"))
    Write-Host -Object "'$ClusterResourceId' Connectivity Status: $($Cluster.Properties.connectivityStatus) ..."
    #endregion 
    #endregion
}

function Set-LocalClusterInsightSetup {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceGroupName,

        [ValidateNotNullOrEmpty()]
        [string] $ClusterName = "localboxcluster",

        [ValidateNotNullOrEmpty()]
        [string] $LogAnalyticsWorkSpaceName = "LocalBox-Workspace",

        [ValidateNotNullOrEmpty()]
        [string[]] $NodeName = @("AzLHOST1", "AzLHOST2")
    )

    $ResourceGroup = Get-AzResourceGroup -ResourceGroupName $ResourceGroupName -ErrorAction Ignore
    if (-not($ResourceGroup)) {
        Write-Error -Message "The '$ResourceGroupName' ResourceGroup doesn't exist !!!" -ErrorAction Stop
    }

    #region Building an Hashtable to get the shortname of every Azure resource based on a JSON file on the Github repository of the Azure Naming Tool
    $Result = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/refs/heads/main/src/repository/resourcetypes.json 
    $ResourceTypeShortNameHT = $Result | Where-Object -FilterScript { $_.property -in @('', 'Windows') } | Select-Object -Property resource, shortName, lengthMax | Group-Object -Property resource -AsHashTable -AsString
    #endregion

    #region Variables
    $SubscriptionId = (Get-AzContext).Subscription.Id
    $ClusterName = "localboxcluster"
    $LogAnalyticsWorkSpaceName = "LocalBox-Workspace"
    $LADestinationDestinationName = "LogAnalyticsWorkspace"
    $Location = $ResourceGroup.Location
    $ResourceGroupNamePrefix = $ResourceTypeShortNameHT["Resources/resourcegroups"].ShortName

    $DataCollectionRuleName = $ResourceGroup.ResourceGroupName -replace $ResourceGroupNamePrefix, "AzureStackHCI-dcr"
    $DataCollectionEndpointName = $ResourceGroup.ResourceGroupName -replace $ResourceGroupNamePrefix, "dce"

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$SubscriptionId: $SubscriptionId"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Location: $Location"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$DataCollectionRuleName: $DataCollectionRuleName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$DataCollectionEndpointName: $DataCollectionEndpointName"
    #endregion

    #region Azure Local resource
    $Cluster = Get-AzStackHciCluster -ResourceGroupName $ResourceGroup.ResourceGroupName -ClusterName $ClusterName -ErrorAction Ignore
    if (-not($Cluster)) {
        Write-Error -Message "The '$ClusterName' Azure Local cluster doesn't exist in the '$($ResourceGroup.ResourceGroupName)' ResourceGroup !!!" -ErrorAction Stop
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Cluster: $($Cluster | Out-String)"
    #endregion

    #region Log Analytics Workspace
    $Parameters = @{
        ResourceGroupName = $ResourceGroup.ResourceGroupName
        Name              = $LogAnalyticsWorkSpaceName
    }
    $LogAnalyticsWorkSpace = Get-AzOperationalInsightsWorkspace @Parameters -ErrorAction Ignore
    if (-not($LogAnalyticsWorkSpace)) {
        Write-Error -Message "The '$LogAnalyticsWorkSpaceName' Log Analytics Workspace doesn't exist in the '$($ResourceGroup.ResourceGroupName)' ResourceGroup !!!" -ErrorAction Stop
    }
    $LADestinationName = $LogAnalyticsWorkSpace.Name
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$LogAnalyticsWorkSpace: $($LogAnalyticsWorkSpace | Out-String)"
    #endregion

    #region Azure Local nodes (Azure Arc machines)
    # Only the Azure Local nodes are targeted: the Resource Group can also contain Azure Local VMs (also Microsoft.HybridCompute/machines).
    $AzureArcMachines = @(Get-AzConnectedMachine -ResourceGroupName $ResourceGroup.ResourceGroupName | Where-Object -FilterScript { $_.Name -in $NodeName })
    $MissingNodes = @($NodeName | Where-Object -FilterScript { $_ -notin $AzureArcMachines.Name })
    if ($MissingNodes.Count -gt 0) {
        Write-Error -Message "The following Azure Arc machine(s) were not found in the '$($ResourceGroup.ResourceGroupName)' ResourceGroup: $($MissingNodes -join ', ') !!!" -ErrorAction Stop
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Azure Local nodes: $($AzureArcMachines.Name -join ', ')"
    #endregion

    #region Installing Azure Monitor Windows Agent on the Azure Local nodes
    $Jobs = foreach ($AzureArcMachine in $AzureArcMachines) {
        $InstalledExtension = Get-AzConnectedMachineExtension -ResourceGroupName $ResourceGroup.ResourceGroupName -MachineName $AzureArcMachine.Name | Where-Object -FilterScript { $_.Name -match "AzureMonitorWindowsAgent" } | Select-Object -First 1
        if (-not($InstalledExtension)) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Installing 'AzureMonitorWindowsAgent' extension on the '$($AzureArcMachine.Name)' Azure Arc Machine (in the '$($ResourceGroup.ResourceGroupName)' Resource Group) (As A Job)"
            $ExtensionName = "AzureMonitorWindowsAgent_{0:yyyyMMddHHmmss}" -f (Get-Date)
            $Parameters = @{
                Name                   = $ExtensionName
                ExtensionType          = 'AzureMonitorWindowsAgent'
                Publisher              = 'Microsoft.Azure.Monitor'
                MachineName            = $AzureArcMachine.Name
                ResourceGroupName      = $ResourceGroup.ResourceGroupName
                Location               = $AzureArcMachine.Location
                TypeHandlerVersion     = '1.0'
                EnableAutomaticUpgrade = $true
                AsJob                  = $true
            }
            Set-AzConnectedMachineExtension @Parameters
        }
        else {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The '$($InstalledExtension.Name)' extension is already installed on the '$($AzureArcMachine.Name)' Azure Arc Machine (in the '$($ResourceGroup.ResourceGroupName)' Resource Group)"
        }
    }

    if ($Jobs) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Waiting all jobs completes"
        $null = $Jobs | Wait-Job
        $FailedJobs = @($Jobs | Where-Object -FilterScript { $_.State -ne "Completed" })
        $null = $Jobs | Receive-Job -Wait -AutoRemoveJob
        if ($FailedJobs.Count -gt 0) {
            Write-Error -Message "$($FailedJobs.Count) 'AzureMonitorWindowsAgent' installation job(s) failed !!!" -ErrorAction Stop
        }
    }
    #endregion

    #region Data Collection Endpoint
    $Parameters = @{
        ResourceGroupName = $ResourceGroup.ResourceGroupName
        Name              = $DataCollectionEndpointName
    }
    $DataCollectionEndpoint = Get-AzDataCollectionEndpoint @Parameters -ErrorAction Ignore

    if (-not($DataCollectionEndpoint)) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the '$DataCollectionEndpointName' Data Collection Endpoint"
        $Parameters['Location'] = $Location
        $Parameters['NetworkAclsPublicNetworkAccess'] = "Enabled"
        $DataCollectionEndpoint = New-AzDataCollectionEndpoint @Parameters
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$DataCollectionEndpoint: $($DataCollectionEndpoint | Out-String)"
    #endregion

    #region Data Collection Rule
    #region Performance Counters
    $Parameters = @{
        Name                      = "perfCounterDataSource"
        Stream                    = @("Microsoft-Perf")
        SamplingFrequencyInSecond = 10
        CounterSpecifier          = @(
            "\Memory\Available Bytes"
            "\Network Interface(*)\Bytes Total/sec"
            "\Processor(_Total)\% Processor Time"
            "\RDMA Activity(*)\RDMA Inbound Bytes/sec"
            "\RDMA Activity(*)\RDMA Outbound Bytes/sec"
        )
    }
    $PerformanceCounter = New-AzPerfCounterDataSourceObject @Parameters
    #endregion

    #region Windows Event Logs
    $Parameters = @{
        Name       = "eventLogsDataSource"
        Stream     = @("Microsoft-Event")
        XPathQuery = @(
            "Microsoft-Windows-SDDC-Management/Operational!*[System[(EventID=3000 or EventID=3001 or EventID=3002 or EventID=3003 or EventID=3004)]]"
            "Microsoft-Windows-Health/Operational!*"
        )
    }
    $WindowsEventLog = New-AzWindowsEventLogDataSourceObject @Parameters
    #endregion

    #region LogAnalyticsWorkSpace destination
    $Parameters = @{
        Name                = $LADestinationName
        WorkspaceResourceId = $LogAnalyticsWorkSpace.ResourceId
    }
    $DestinationLogAnalytic = New-AzLogAnalyticsDestinationObject @Parameters
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$DestinationLogAnalytic: $($DestinationLogAnalytic | Out-String)"
    #endregion

    #region DataFlows (the destination name MUST match the destination object name)
    $Parameters = @{
        Stream      = @("Microsoft-Perf")
        Destination = @($LADestinationName)
    }
    $PerfDataFlow = New-AzDataFlowObject @Parameters

    $Parameters = @{
        Stream      = @("Microsoft-Event")
        Destination = @($LADestinationName)
    }
    $EventDataFlow = New-AzDataFlowObject @Parameters
    #endregion

    #region Data Collection Rule creation (only if missing)
    $Parameters = @{
        ResourceGroupName = $ResourceGroup.ResourceGroupName
        Name              = $DataCollectionRuleName
    }
    $DataCollectionRule = Get-AzDataCollectionRule @Parameters -ErrorAction Ignore

    if (-not($DataCollectionRule)) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the '$DataCollectionRuleName' Data Collection Rule"
        $DataCollectionRuleParameters = @{
            Name                         = $DataCollectionRuleName
            ResourceGroupName            = $ResourceGroup.ResourceGroupName
            Location                     = $Location
            SubscriptionId               = $SubscriptionId
            DataCollectionEndpointId     = $DataCollectionEndpoint.Id
            DataSourcePerformanceCounter = @($PerformanceCounter)
            DataSourceWindowsEventLog    = @($WindowsEventLog)
            DestinationLogAnalytic       = @($DestinationLogAnalytic)
            DataFlow                     = @(
                $PerfDataFlow
                $EventDataFlow
            )
        }
        $DataCollectionRule = New-AzDataCollectionRule @DataCollectionRuleParameters
    }
    elseif ($DataCollectionRule.DataCollectionEndpointId -ne $DataCollectionEndpoint.Id) {
        Write-Warning -Message "The existing '$DataCollectionRuleName' Data Collection Rule is not linked to the '$DataCollectionEndpointName' Data Collection Endpoint (current: '$($DataCollectionRule.DataCollectionEndpointId)')."
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$DataCollectionRule: $($DataCollectionRule | Out-String)"
    #endregion
    #endregion

    #region Associate DCR with every Azure Local node
    foreach ($AzureArcMachine in $AzureArcMachines) {
        # Associations are listed per node (works even when no association exists yet)
        # PowerShell -eq is case-insensitive on strings, which is what we need for Azure Resource IDs
        $ExistingAssociation = Get-AzDataCollectionRuleAssociation -ResourceUri $AzureArcMachine.Id -ErrorAction Ignore | Where-Object -FilterScript { $_.DataCollectionRuleId -eq $DataCollectionRule.Id } | Select-Object -First 1

        if ($ExistingAssociation) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The '$($AzureArcMachine.Name)' Azure Arc Machine is already associated with the '$($DataCollectionRule.Name)' DCR ('$($ExistingAssociation.Name)')"
            continue
        }

        $AssociationName = "dra_{0}" -f $((New-Guid).Guid)
        $Parameters = @{
            ResourceUri          = $AzureArcMachine.Id
            AssociationName      = $AssociationName
            DataCollectionRuleId = $DataCollectionRule.Id
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Associating the '$($DataCollectionRule.Name)' DCR with the '$($AzureArcMachine.Name)' Azure Arc Machine"
        $DataCollectionRuleAssociation = New-AzDataCollectionRuleAssociation @Parameters
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$DataCollectionRuleAssociation: $($DataCollectionRuleAssociation | Out-String)"
    }
    #endregion

    #region Final verification
    $NonAssociatedMachines = @(
        foreach ($AzureArcMachine in $AzureArcMachines) {
            $Association = Get-AzDataCollectionRuleAssociation -ResourceUri $AzureArcMachine.Id -ErrorAction Ignore | Where-Object -FilterScript { $_.DataCollectionRuleId -eq $DataCollectionRule.Id }
            if (-not($Association)) {
                $AzureArcMachine.Name
            }
        }
    )
    if ($NonAssociatedMachines.Count -gt 0) {
        Write-Error -Message "The '$($DataCollectionRule.Name)' DCR is not associated with: $($NonAssociatedMachines -join ', ') !!!" -ErrorAction Stop
    }

    [PSCustomObject]@{
        Cluster                = $Cluster.Name
        LogAnalyticsWorkSpace  = $LogAnalyticsWorkSpace.ResourceId
        DataCollectionEndpoint = $DataCollectionEndpoint.Id
        DataCollectionRule     = $DataCollectionRule.Id
        Nodes                  = $AzureArcMachines.Name
    }
    #endregion
}

function New-VMLogicalNetwork {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceGroupName
    )

    $ScriptPath = "C:\LocalBox\Configure-VMLogicalNetwork.ps1"
    $AzVMRunCommand = Invoke-AzVMRunCommand  -CommandId 'RunPowerShellScript' -ResourceGroupName $ResourceGroupName -VMName LocalBox-Client -ScriptString "pwsh -File '$ScriptPath'"
    $LogicalNetworkName = "localbox-vm-lnet-vlan200"
    $LogicalNetwork = Get-AzStackHCIVMLogicalNetwork -ResourceGroupName $ResourceGroupName -Name $LogicalNetworkName
    if (-not($LogicalNetwork)) {
        Write-Error -Message "The '$LogicalNetworkName' Azure Local Logical Network doesn't exist ..." -ErrorAction Stop
    }
    return $LogicalNetwork
}

function New-AzLocalAVDVMImage {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceGroupName
    )
    #From https://jumpstart.azure.com/azure_jumpstart_localbox/RB#create-virtual-machine-images-from-azure-marketplace
    #$URN = "MicrosoftWindowsDesktop:office-365:win11-25h2-avd-m365:latest"
    #$ImageName ="{0}-{1}" -f ($URN -split ":")[-2], $Instance
    $CustomLocation = Get-AzResource -ResourceType "Microsoft.ExtendedLocation/customLocations" -ResourceGroupName $ResourceGroupName
    $Location = $CustomLocation.Location
    $PublisherName = "MicrosoftWindowsDesktop" 
    $Offer = "office-365" 
    $Sku = "win11-25h2-avd-m365" 
    #Getting the latest version because 'latest' is not accepted
    $Version = (Get-AzVMImage -Location  $Location -PublisherName $PublisherName -Offer $Offer -sku $Sku | Sort-Object -Property Version -Descending | Select-Object -First 1).Version
    $Instance = [regex]::Match($ResourceGroupName, "\d+$").Value
    $ImageName ="{0}-{1}-{2}" -f $Sku, $Instance, $(Get-Date -Format 'yyyyMMddHHmmss')
    $Parameters = @{
        Name = $ImageName
        ResourceGroupName = $ResourceGroupName
        Location = $Location
        CustomLocationId = $CustomLocation.Id
        #URN  = $URN
        Publisher = $PublisherName
        Offer = $Offer
        Sku = $Sku
        Version = $Version
        OSType = "Windows"
    }
    $null = New-AzStackHCIVMImage @Parameters
    $Parameters = @{
        Name = $ImageName
        ResourceGroupName = $ResourceGroupName
    }
    $Image = Get-AzStackHCIVMImage @Parameters
    return $Image
}

function New-AzLocalAVDVM {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [PSCredential] $Credential,
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Azure.PowerShell.Cmdlets.StackHCIVM.Models.MarketplaceGalleryImages] $Image,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Azure.PowerShell.Cmdlets.StackHCIVM.Models.LogicalNetworks] $LogicalNetwork
    )

    #region Building an Hashtable to get the shortname of every Azure resource based on a JSON file on the Github repository of the Azure Naming Tool
    $Result = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/refs/heads/main/src/repository/resourcetypes.json 
    $ResourceTypeShortNameHT = $Result | Where-Object -FilterScript { $_.property -in @('', 'Windows') } | Select-Object -Property resource, shortName, lengthMax | Group-Object -Property resource -AsHashTable -AsString
    #endregion

    #region Creating NIC
    $NICNamePrefix = $ResourceTypeShortNameHT["Network/networkInterfaces"].ShortName
    $VMNamePrefix = $ResourceTypeShortNameHT["Compute/virtualMachines"].ShortName
    $Instance = [regex]::Match($LogicalNetwork.ResourceGroupName, "\d+$").Value
    $VMName = "{0}win11avd{1}" -f $VMNamePrefix, $Instance
    $NICName = "{0}-{1}" -f $NICNamePrefix, $VMName

    $Parameters = @{
        Name = $NICName
        ResourceGroupName = $LogicalNetwork.ResourceGroupName
        Location = $LogicalNetwork.Location
        CustomLocationId = $LogicalNetwork.ExtendedLocationName
        SubnetName = $LogicalNetwork.Subnet.Name
    }
    $NIC = New-AzStackHCIVMNetworkInterface @Parameters
    #endregion

    #region Creating VM
    $Parameters = @{
        Name = $VMName
        ResourceGroupName = $LogicalNetwork.ResourceGroupName
        Location = $Image.Location
        CustomLocationId = $Image.ExtendedLocationName
        ImageName = $Image.Name
        NicId = $NIC.Id
        VMSize = "Standard_D2s_v5"
        AdminUsername = $Credential.UserName
        AdminPassword = $Credential.Password
        OSType = "Windows"
    }
    $VM = New-AzStackHCIVMVirtualMachine @Parameters
    #endregion
}
#endregion

#region Main Code
try { while (Stop-Transcript) {} } catch {}
Clear-Host
$VerbosePreference = "continue"
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

#region Transcript
$Now = Get-Date
$TranscriptFile = $CurrentScript -replace ".ps1$", "_$("{0:yyyyMMddHHmmss}.txt" -f $Now)"
Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader
#endregion
#region Login to your Azure subscription.
# Keep prompting until the Az context can issue an access token.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount
}
#endregion

#region Prerequisites
#region Registering required Providers
$null = Register-AzResourceProvider -ProviderNamespace "Microsoft.Attestation"
$null = Register-AzResourceProvider -ProviderNamespace "Microsoft.AzureStackHCI"
$null = Register-AzResourceProvider -ProviderNamespace "Microsoft.EdgeMarketPlace"
$null = Register-AzResourceProvider -ProviderNamespace "Microsoft.ExtendedLocation"
$null = Register-AzResourceProvider -ProviderNamespace "Microsoft.GuestConfiguration"
$null = Register-AzResourceProvider -ProviderNamespace "Microsoft.HybridCompute"
$null = Register-AzResourceProvider -ProviderNamespace "Microsoft.HybridConnectivity"
$null = Register-AzResourceProvider -ProviderNamespace "Microsoft.HybridContainerService"
$null = Register-AzResourceProvider -ProviderNamespace "Microsoft.Insights"
$null = Register-AzResourceProvider -ProviderNamespace "Microsoft.KeyVault"
$null = Register-AzResourceProvider -ProviderNamespace "Microsoft.Kubernetes"
$null = Register-AzResourceProvider -ProviderNamespace "Microsoft.KubernetesConfiguration"
$null = Register-AzResourceProvider -ProviderNamespace "Microsoft.ResourceConnector"
$null = Register-AzResourceProvider -ProviderNamespace "Microsoft.Storage"
$null = Register-AzResourceProvider -ProviderNamespace "Microsoft.Quota"
#endregion

#region Bicep
try {
    start-process bicep -ArgumentList "--version" -PassThru -NoNewWindow -ErrorAction Stop
} catch {
    Write-Error -Message "Bicep is mandatory. Please install it (winget install -e --id Microsoft.Bicep) ..." -ErrorAction Stop
}
#endregion
#endregion

<#
$LAWSupportedRegions = ((Get-AzResourceProvider -ProviderNamespace Microsoft.OperationalInsights).ResourceTypes | Where-Object ResourceTypeName -eq 'workspaces' | Select-Object -ExpandProperty Locations | Sort-Object)
$azureLocalInstanceLocations = "australiaeast", "southcentralus", "eastus", "westeurope", "southeastasia", "canadacentral", "japaneast", "centralindia"
#>

$SubscriptionId = (Get-AzContext).Subscription.Id

$VMSize = "Standard_E32s_v6"
#Customize with your own path
$GitDir = "C:\Source Control\GitHub\Cloned repositories"
$BicepFileDir = Join-Path -Path $GitDir -ChildPath "azure_arc\azure_jumpstart_localbox\bicep"
if (-not(Test-Path -Path $BicepFileDir -PathType Container)) {
    $null = New-Item -Path $GitDir -ItemType Directory -Force
    Push-Location -Path $GitDir
    git clone https://github.com/microsoft/azure_arc.git
    Pop-Location
}

if ($null -ne $azureLocalInstanceLocation) {
    $AzureLocalInstanceLocations = $AzureLocalInstanceLocation
}
else {
    #From https://jumpstart.azure.com/azure_jumpstart_localbox/deployment_az
    $AzureLocalInstanceLocations = 'australiaeast', 'southcentralus', 'eastus', 'westeurope', 'southeastasia', 'canadacentral', 'japaneast', 'centralindia'
}
Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AzureLocalInstanceLocations: $($AzureLocalInstanceLocations | Out-String)"

if ($null -ne $location) {
    $LAWSupportedRegions = $location
}
else {
    #LAW Supported Regions
    # Intersect provider-supported display names with canoNICal Azure location identifiers.
    $LAWSupportedDisplayNameRegions = ((Get-AzResourceProvider -ProviderNamespace Microsoft.OperationalInsights).ResourceTypes | Where-Object -FilterScript { $_.ResourceTypeName -eq 'workspaces' }).Locations
    $LAWSupportedRegions = (Get-AzLocation | Where-Object { $_.Providers -contains "Microsoft.OperationalInsights" -and ($_.DisplayName -in $LAWSupportedDisplayNameRegions) }).Location | Sort-Object
}
Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$LAWSupportedRegions: $($LAWSupportedRegions | Out-String)"
<#
#Simple Deployment by passing the parameters
$LAWSupportedRegions = "centralus"
$AzureLocalInstanceLocations = "southcentralus"
#>
$LAWSupportedRegions = "centralindia"
$AzureLocalInstanceLocations = "centralindia"


$Credential = Get-Credential -Message "Enter the required credentials" -UserName $env:USERNAME
# Try each Log Analytics-compatible region that has enough capacity for the requested VM SKU.
foreach ($Location in $LAWSupportedRegions) {
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Location: $Location"
    #Checking Azure Quota
    $AvailableComputeResourceSku = Get-AzAvailableComputeResourceSku -Location $Location -ComputeResourceSku $VMSize -SubscriptionId $SubscriptionId
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AvailableComputeResourceSku: $($AvailableComputeResourceSku | Out-String)"
    if ($AvailableComputeResourceSku.Available -gt 0) {
        # Retry the deployment across supported Azure Local instance regions until one succeeds.
        foreach ($AzureLocalInstanceLocation in $AzureLocalInstanceLocations) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AzureLocalInstanceLocation: $AzureLocalInstanceLocation)"
            $Result = New-JumpstartLocalBox -Credential $Credential -azureLocalInstanceLocation $AzureLocalInstanceLocation -Location $Location -BicepFileDir $BicepFileDir -enableAzureSpotPricing $true -autoUpgradeClusterResource $true -Verbose
            if ($Result.Succeeded) {
                Write-Host -Object "The Jumpstart LocalBox Deployment Succeeded !!!" -ForegroundColor Green
                break
            }
            else {
                Write-Host -Object "The Jumpstart LocalBox Deployment Failed !!!. We will automatically try other locations ..." -ForegroundColor Red
            }
        }

        if ($Result.Succeeded) {
            #From https://jumpstart.azure.com/azure_jumpstart_localbox/cloud_deployment
            Wait-AzConnectedMachine -ResourceGroupName $Result.ResourceGroupName
            
            #From https://jumpstart.azure.com/azure_jumpstart_localbox/using_localbox
            Set-LocalClusterInsightSetup -ResourceGroupName $Result.ResourceGroupName
            
            #From https://jumpstart.azure.com/azure_jumpstart_localbox/RB
            $Image = New-AzLocalAVDVMImage -ResourceGroupName $Result.ResourceGroupName
            $LogicalNetwork = New-VMLogicalNetwork -ResourceGroupName $Result.ResourceGroupName
            $VM = New-AzLocalAVDVM -Credential $Credential -Image $Image -LogicalNetwork $LogicalNetwork 

            #region Azure Lock on the ResourceGroup to prevent from accidental deletion
            $null = New-AzResourceLock -LockName CanNotDelete -LockLevel CanNotDelete -ResourceGroupName $Result.ResourceGroupName -Force
            #endregion
            break

        }
        else {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing: $($Result.ResourceGroupName) ResourceGroup (As Job)..."
            $null = Remove-AzResourceGroup -ResourceGroupName $Result.ResourceGroupName -AsJob -Force
        }
    }
    else {
        Write-Warning -Message "No available Quota for '$VMSize' in the '$Location' Azure location. We will automatically try other locations ..."
    }
}

Write-Host -Object "Done ..." -ForegroundColor Green
#winget install --exact --id=Microsoft.Sysinternals.Suite --location "C:\Tools" --accept-package-agreements --accept-source-agreements
#endregion