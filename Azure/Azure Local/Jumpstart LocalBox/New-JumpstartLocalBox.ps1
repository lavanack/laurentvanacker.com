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

# Prerequisites: https://jumpstart.azure.com/azure_jumpstart_localbox/deployment_az

#requires -Version 5 #-Modules Az.Accounts, Az.Compute, Az.Quota, Az.Resources, Az.StackHCI, Az.StackHCIVM

[CmdletBinding(PositionalBinding = $false)]
param
(
    # Log Analytics workspace regions:
    [ValidateScript({ $_ -in $($OperationalInsightLocations = ((Get-AzResourceProvider -ProviderNamespace 'Microsoft.OperationalInsights').ResourceTypes | Where-Object -FilterScript { $_.ResourceTypeName -eq 'workspaces' }).Locations; (Get-AzLocation | Where-Object -FilterScript { $_.DisplayName -in $OperationalInsightLocations }).Location) })]
    [string[]] $Location,
    [ValidateSet('australiaeast', 'southcentralus', 'eastus', 'westeurope', 'southeastasia', 'canadacentral', 'japaneast', 'centralindia')]
    [string[]] $azureLocalInstanceLocation,
    [switch] $AVD
)
<#
trap {
    Write-Host "Stopping Transcript ..."
    Stop-Transcript
    break
}
#>

#region Function definitions
# Adapted from https://adamtheautomator.com/powershell-random-password/

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

.EXAMPLE
New-RandomPassword -Online -AsSecureString

Retrieves and checks a password, then returns it as a SecureString.

.OUTPUTS
System.String
System.Security.SecureString
Returns plain text by default, or a SecureString when AsSecureString is specified.
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

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    # Uses the k-anonymity API: only the first five SHA-1 characters leave this computer.

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
    (Int64) properties. Occurrences is zero when the password was not found.
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
        # Apply the same complexity, prohibited-value, and breach checks to either password source.
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
Stores credentials for a target and optionally opens a Remote Desktop session.

.DESCRIPTION
Runs cmdkey to save the supplied credentials for the target and copies the target
name to the clipboard. With Connect, launches mstsc in full-screen mode, brings
its window to the foreground, and sends keystrokes to respond to connection
prompts. The user name and plain-text password are also written to host output;
use caution when running this function where console output may be retained or
visible to others.

.PARAMETER ComputerName
Specifies the target computer name or fully qualified domain name.

.PARAMETER Credential
Specifies the credentials to store for the target computer.

.PARAMETER Connect
Starts mstsc in full-screen mode after storing the credentials and attempts to
respond to its connection prompts.

.EXAMPLE
Add-RDPCredential -ComputerName 'localbox.example.com' -Credential (Get-Credential) -Connect

Prompts for credentials, saves them for the target, copies the target name to the
clipboard, displays the credentials, and opens a full-screen Remote Desktop
connection.

.OUTPUTS
None.
#>
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
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    # Escape the password for cmd.exe before storing the RDP credentials.
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /generic:$ComputerName /user:$($Credential.UserName) /pass:$($Credential.GetNetworkCredential().Password -replace "(\W)", '^$1')" -Wait
    # Copy the destination name so it is ready to paste into other connection workflows.
    $ComputerName | Set-Clipboard 
    Write-Host -Object "Your RDP credentials (login/password) are $($Credential.UserName)/$($Credential.GetNetworkCredential().Password) for '$ComputerName'" -ForegroundColor Green
    if ($Connect) {
        $MSTSCProcess = Start-Process -FilePath "mstsc" -ArgumentList "/v:$ComputerName /f" -PassThru -WindowStyle Normal
        try {
            Do {
                Start-Sleep -Seconds 1
                $MSTSCProcess = Get-Process -Id $MSTSCProcess.Id -ErrorAction Ignore
            } While ([string]::IsNullOrEmpty($MSTSCProcess.MainWindowtitle)) 
            #region Bring the RDP window to the foreground
            $signature = '
            [DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
            [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
            [DllImport("user32.dll")] public static extern int SetForegroundWindow(IntPtr hwnd);
            '
            $type = Add-Type -MemberDefinition $signature -Name xShowWindow -PassThru
            $hwnd = $MSTSCProcess.MainWindowHandle
            $null = $type::ShowWindow($hwnd, 5)
            $null = $type::SetForegroundWindow($hwnd) 
            Start-Sleep -Seconds 1
            #endregion
            #region Confirm the RDP connection prompts
            $wshell = New-Object -ComObject wscript.shell;
            # $null = $wshell.AppActivate((Get-Process -Id $MSTSCProcess.Id -ErrorAction Stop).MainWindowtitle, $true)
            Start-Sleep -Milliseconds 100
            $wshell.SendKeys('d')
            Start-Sleep -Milliseconds 100
            $wshell.SendKeys('y')
            #endregion
        }
        catch {
            Write-Warning "$($_.Exception.Message)"
        }
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

#region Azure Quota Function
# Adapted from:
# https://github.com/lavanack/laurentvanacker.com/blob/master/Azure/Azure%20Virtual%20Machine/Get-AzQuotaData.ps1

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

.EXAMPLE
Get-AzVMQuota -Location 'australiaeast' -ResourceName 'virtualMachines'

Retrieves virtual machine quota and usage for Australia East in the available subscriptions.

.OUTPUTS
System.Management.Automation.PSCustomObject
Returns subscription, location, resource name, limit, usage, available capacity, and percentage free.
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

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
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
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
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

.EXAMPLE
Get-AzCoreQuota -Location 'australiaeast'

Retrieves regional vCPU quota and usage in the available subscriptions.

.OUTPUTS
System.Management.Automation.PSCustomObject
Returns subscription, location, resource name, limit, usage, available capacity, and percentage free.
#>
function Get-AzCoreQuota {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        [ValidateScript({ $_ -in $((Get-AzLocation).Location) })]
        [string[]] $Location = $((Get-AzLocation).Location),
        [ValidateScript({ $_ -in $((Get-AzSubscription).Id) })]
        [string[]] $SubscriptionId = (Get-AzSubscription).Id
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
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
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
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

.EXAMPLE
Get-AzAvailableComputeResourceSku -Location 'australiaeast' -ComputeResourceSku 'Standard_E32s_v6'

Calculates deployment capacity for the specified VM size in Australia East.
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

    
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
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
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
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

.PARAMETER Credential
Specifies the administrator credentials instead of windowsAdminUsername and windowsAdminPassword.

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

.EXAMPLE
New-JumpstartLocalBox -Credential (Get-Credential) -BicepFileDir 'C:\Jumpstart\LocalBox'

Deploys LocalBox using the supplied administrator credentials and Bicep directory.

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
        [Parameter(Mandatory = $True, ParameterSetName = 'Credential')]
        [PSCredential] $Credential,
        [string] $logAnalyticsWorkspaceName = 'LocalBox-Workspace',
        [string] $natDNS = '8.8.8.8',
        [string] $githubAccount = 'microsoft',
        [string] $githubBranch = 'main',
        [string] $deployBastion = $false,
        # Log Analytics workspace regions:
        # ((Get-AzResourceProvider -ProviderNamespace 'Microsoft.OperationalInsights').ResourceTypes | Where-Object -FilterScript { $_.ResourceTypeName -eq 'workspaces' }).Locations
        [ValidateSet('australiacentral', 'australiacentral2', 'australiaeast', 'australiasoutheast', 'austriaeast', 'brazilsouth', 'brazilsoutheast', 'canadacentral', 'canadaeast', 'centralindia', 'centralus', 'chilecentral', 'eastasia', 'eastus', 'eastus2', 'francecentral', 'francesouth', 'germanynorth', 'germanywestcentral', 'indonesiacentral', 'israelcentral', 'italynorth', 'japaneast', 'japanwest', 'jioindiacentral', 'jioindiawest', 'koreacentral', 'koreasouth', 'malaysiawest', 'mexicocentral', 'newzealandnorth', 'northcentralus', 'northeurope', 'norwayeast', 'norwaywest', 'polandcentral', 'qatarcentral', 'southafricanorth', 'southafricawest', 'southcentralus', 'southeastasia', 'southindia', 'spaincentral', 'swedencentral', 'switzerlandnorth', 'switzerlandwest', 'uaecentral', 'uaenorth', 'uksouth', 'ukwest', 'westcentralus', 'westeurope', 'westus', 'westus2', 'westus3')]
        [string] $Location = 'australiasoutheast',
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

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$azureLocalInstanceLocation: $azureLocalInstanceLocation"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Location: $Location"

    #region Credential Management
    if ($Credential) {
        $windowsAdminUsername = $Credential.UserName
        $windowsAdminPassword = $Credential.GetNetworkCredential().Password
    }
    #endregion

    #region Define variables
    #region Build the Azure location abbreviation lookup from Azure Naming Tool data
    $AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
    $ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
    $ANTResourceLocationShortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
    #endregion

    #region Build the Azure resource abbreviation lookup from Azure Naming Tool data
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
    
    #region Resource group management
    #region Resource group setup
    <#    
    $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
    if ($ResourceGroup) {
        # Remove an existing resource group with the generated name before redeploying.
        $ResourceGroup | Remove-AzResourceGroup -Force
    }
    #>
    $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
    #endregion

    #region Resource group deployment
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
param location = '$Location'
param azureLocalInstanceLocation = '$azureLocalInstanceLocation'
param rdpPort = '$rdpPort'
param autoDeployClusterResource = $(($autoDeployClusterResource).ToString().ToLower())
param autoUpgradeClusterResource = $(($autoUpgradeClusterResource).ToString().ToLower())
param vmAutologon = $(($vmAutologon).ToString().ToLower())
param vmSize = '$vmSize'
param enableAzureSpotPricing = $(($enableAzureSpotPricing).ToString().ToLower())
param governResourceTags = $(($governResourceTags).ToString().ToLower())
param tags = $(($tags | ConvertTo-Json).Replace('"', "'") -replace '''(.*)'':', '$1:')
"@

    $null = New-Item -Path $TemplateParameterFile -ItemType File -Value $TemplateParameterFileContent -Force
    $SubscriptionId = (Get-AzContext).Subscription.Id
    # Open and copy the deployment blade URL so progress can be monitored interactively.
    $ResourceGroupDeploymentURI = "https://portal.azure.com/#@{0}/resource/subscriptions/{1}/resourceGroups/{2}/deployments" -f $((Get-AzTenant).Domains[-1]), $SubscriptionId, $ResourceGroupName
    Start-Process $ResourceGroupDeploymentURI 
    $ResourceGroupDeploymentURI | Set-ClipBoard
    $ResourceGroupDeployment = New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateFile $TemplateFile -TemplateParameterFile $TemplateParameterFile
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$ResourceGroupName' ResourceGroup Deployment:`r`n$(Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName | Select-Object  -Property DeploymentName, ProvisioningState | Out-String)"
    Pop-Location
    #endregion
    #endregion

    # Clean up a failed attempt so the caller can retry with another location.
    if ($ResourceGroupDeployment.ProvisioningState -ne 'Succeeded') {
        Write-Warning -Message "The deployment failed :`r`n$($ResourceGroupDeploymentURI | Out-string)`r`n`r`nRemoving the '$ResourceGroupName' dedicated created ResourceGroup ..."
        $ResourceGroup | Remove-AzResourceGroup -Force -AsJob
        return [PSCustomObject]@{Succeeded = $false; ResourceGroupName = $null; Location = $Location }
    }
    else {
        #region DNS Name Setup
        $VMName = "LocalBox-Client"
        $VM = Get-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName
        $NIC = Get-AzNetworkInterface -ResourceId $VM.NetworkProfile.NetworkInterfaces[0].Id
        $PublicIpId = $NIC.IpConfigurations[0].PublicIpAddress.Id
        $PublicIp = Get-AzPublicIpAddress -ResourceGroupName ($PublicIpId -split '/')[4] -Name ($PublicIpId -split '/')[-1]
        Do {
            $RandomString = [Guid]::NewGuid().ToString('N').Substring(0, 8)
            $DomainNameLabel = $("{0}-{1}-{2}" -f $VMName, $Instance, $RandomString).ToLower()
            $FQDN = $("{0}.{1}.cloudapp.azure.com" -f $DomainNameLabel, $Location).ToLower()
        } While ($null -ne $(Resolve-DnsName $FQDN -ErrorAction Ignore))
        $PublicIP.DnsSettings = @{
            #Fqdn = $FQDN
            DomainNameLabel = $DomainNameLabel
        }
        $null = $PublicIP | Set-AzPublicIpAddress
        #endregion

        #region Store credentials in Windows Credential Manager
        Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /generic:$FQDN /user:$windowsAdminUsername /pass:$($windowsAdminPassword -replace "(\W)", '^$1')" -Wait
        #endregion

        #region Just-in-time access management
        $JitPolicyTimeInHours = 3
        $JitPolicyName = "Default"
        #region Enable just-in-time access
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
        $UpdatedJITPolicy = $ExistingJITPolicy.Where{ $_.id -ne "$($VM.Id)" } # Replace any existing policy entry for this VM.
        $UpdatedJITPolicy.Add($NewJitPolicy)
	
        # Apply the management port and maximum access duration to the VM policy.
        Write-Host "Enabling Just in Time VM Access Policy for ($VMName) on port number $RDPPort for maximum $JitPolicyTimeInHours hours..."
        $null = Set-AzJitNetworkAccessPolicy -VirtualMachine $UpdatedJITPolicy -ResourceGroupName $ResourceGroupName -Location $Location -Name $JitPolicyName -Kind "Basic"
        #endregion

        #region Request temporary access for three hours
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

        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        return [PSCustomObject]@{Succeeded = $true; ResourceGroupName = $ResourceGroupName; Location = $Location }
    }
}

<#
.SYNOPSIS
Waits for the LocalBox Azure Arc nodes and cluster to become ready.

.DESCRIPTION
Validates the resource group and checks reachability of the VHDX URLs extracted
from the upstream LocalBox cluster script. It then checks every five minutes for
the AzLHOST1 and AzLHOST2 Azure Arc machines and for the localboxcluster resource
to report Succeeded provisioning and Connected connectivity. During polling, it
reads the deployment log on LocalBox-Client through Azure VM Run Command. There is
no timeout; the function continues waiting until the expected resources are ready
or a command fails.

.PARAMETER ResourceGroupName
Specifies the resource group containing the LocalBox deployment.

.EXAMPLE
Wait-AzConnectedMachine -ResourceGroupName 'rg-localbox-001' -Verbose

Checks VHDX URL reachability and waits for the two Azure Arc nodes and the Azure
Local cluster, writing progress details to the verbose stream.

.OUTPUTS
None.
#>
function Wait-AzConnectedMachine {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $True)]
        [ValidateNotNull()]
        [string] $ResourceGroupName
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    $ResourceGroup = Get-AzResourceGroup -ResourceGroupName $ResourceGroupName -ErrorAction Ignore
    if (-not($ResourceGroup)) {
        Write-Error -Message "the '$ResourceGroupName' ResourceGroup doesn't exist !!!" -ErrorAction Stop
    }

    #region Testing if VHDX URIs are reachable
    $URI = "https://raw.githubusercontent.com/microsoft/azure_arc/refs/heads/main/azure_jumpstart_localbox/artifacts/PowerShell/New-LocalBoxCluster.ps1"
    $FileContent = Invoke-RestMethod -Uri $URI -Method Get -UseBasicParsing
    # Extract active VHDX references from the upstream script before waiting on deployment.
    $VHXURIs = ([regex]::Matches($FileContent, "(?m)^\s(?<Comment>[^#]).*(?<URI>https?[^$]*vhdx)").Groups | Where-Object -FilterScript { $_.Name -eq "URI" }).Value
    foreach ($CurrentVHXURI in $VHXURIs) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CurrentVHXURI: $CurrentVHXURI"
        try {
            # A HEAD request checks reachability without downloading the disk image.
            $Result = Invoke-WebRequest -Uri $CurrentVHXURI -Method HEAD -UseBasicParsing
        }
        catch {
            Write-Error -Message "The '$CurrentVHXURI' is not reachable ($_.Exception.message)" #-ErrorAction Stop
            throw
        }
    }
    #endregion 

    #region From https://jumpstart.azure.com/azure_jumpstart_localbox/cloud_deployment#azure-local-instance-validation-and-deployment-from-the-azure-portal
    #region Wait for AzLHOST1 and AzLHOST2 to become Arc-enabled servers
    $ReferenceObject = "AzLHOST1", "AzLHOST2"
    Write-Host -Object "Creating the $($ReferenceObject -join ',') Azure Arc Machines ..."
    Do {
        $ScriptString = "Get-Content -Path 'C:\LocalBox\Logs\New-LocalBoxCluster.log' | Select-String -Pattern 'Step\s+(\d+)/(\d+)'"
        $AzVMRunCommand = Invoke-AzVMRunCommand  -CommandId 'RunPowerShellScript' -ResourceGroupName $ResourceGroupName -VMName LocalBox-Client -ScriptString $ScriptString
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Steps:`r`n$($AzVMRunCommand.Value.Message | Out-String)"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$ResourceGroupName' ResourceGroup Deployment:`r`n$(Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName | Select-Object  -Property DeploymentName, ProvisioningState | Out-String)"

        $Seconds = 300
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping $Seconds seconds ..."
        Start-Sleep -Seconds $Seconds
        $AzureArcMachines = Get-AzConnectedMachine -ResourceGroupName $ResourceGroupName
        # Compare the expected node names with the connected machines returned by Azure.
        # Compare-Object returns no difference only when both expected names are present and no extras remain.
        if ($AzureArcMachines) {
            $Compare = Compare-Object -ReferenceObject $ReferenceObject -DifferenceObject $AzureArcMachines
        }
        else {
            $Compare = $null
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Compare:`r`n$($Compare | Out-String)"
    } While (-not($Compare))
    Write-Host -Object "$($ReferenceObject -join ',') Azure Arc Machines Created ..." -ForegroundColor Green
    #endregion 

    <#
    #region Wait for localcluster deployments (legacy approach)
    Do {
        $Seconds = 600
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping $Seconds seconds ..."
        Start-Sleep -Seconds $Seconds
        $RunningDeployments = Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName | Where-Object -FilterScript {$_.ProvisioningState -match "ing$"}
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Compare:`r`n$($RunningDeployments | Out-String)"
    } While ($RunningDeployments)
    Write-Host -Object "No more running Azure ResourceGroup Deployment(s) ..." -ForegroundColor Green
    #endregion 
    #>

    #region Wait for the localcluster resource to become connected
    $ClusterName = "localboxcluster"
    Write-Host -Object "Creating the 'localboxcluster' Azure Local Cluster ..." 
    Do {
        $ScriptString = "Get-Content -Path 'C:\LocalBox\Logs\New-LocalBoxCluster.log' | Select-String -Pattern 'Step\s+(\d+)/(\d+)'"
        $AzVMRunCommand = Invoke-AzVMRunCommand  -CommandId 'RunPowerShellScript' -ResourceGroupName $ResourceGroupName -VMName LocalBox-Client -ScriptString $ScriptString
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Steps:`r`n$($AzVMRunCommand.Value.Message | Out-String)"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$ResourceGroupName' ResourceGroup Deployment:`r`n$(Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName | Select-Object  -Property DeploymentName, ProvisioningState | Out-String)"

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
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Cluster:`r`n$($Cluster | Out-String)"
        #endregion
    } While (($null -eq $Cluster) -or ($Cluster.provisioningState -ne "Succeeded") -or ($Cluster.connectivityStatus -ne "Connected"))
    Write-Host -Object "'$($Cluster.Name)' Connectivity Status: $($Cluster.connectivityStatus) ..."
    #endregion 
    #endregion
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

<#
.SYNOPSIS
Sets up Azure Monitor data collection for the LocalBox cluster and nodes.

.DESCRIPTION
Verifies the cluster and Log Analytics workspace exist, installs missing Azure
Monitor Agent extensions, and creates the data collection endpoint and rule when
they do not already exist. The rule collects performance counters and selected
Windows event logs in the workspace, then is associated with each requested Azure
Arc node. The function verifies those associations and returns a summary. An
existing rule is reused, not updated; if it references a different endpoint, the
function warns and continues with the existing rule.

.PARAMETER ResourceGroupName
Specifies the resource group containing the cluster, nodes, and workspace.

.PARAMETER ClusterName
Documents the cluster name, which defaults to localboxcluster. The function
currently uses that fixed name internally and does not honor a different value.

.PARAMETER LogAnalyticsWorkSpaceName
Documents the Log Analytics workspace name, which defaults to LocalBox-Workspace.
The function currently uses that fixed name internally and does not honor a
different value.

.PARAMETER NodeName
Specifies the Azure Arc machine names to monitor. Defaults to AzLHOST1 and
AzLHOST2. Every specified machine must already exist in the resource group.

.EXAMPLE
Set-LocalClusterInsightSetup -ResourceGroupName 'rg-localbox-001'

Sets up monitoring for the default LocalBox cluster, workspace, and two Azure Arc
nodes, then returns the resource IDs and node names.

.OUTPUTS
System.Management.Automation.PSCustomObject
Returns Cluster, LogAnalyticsWorkSpace, DataCollectionEndpoint,
DataCollectionRule, and Nodes properties describing the monitoring configuration.
#>
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

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    $ResourceGroup = Get-AzResourceGroup -ResourceGroupName $ResourceGroupName -ErrorAction Ignore
    if (-not($ResourceGroup)) {
        Write-Error -Message "The '$ResourceGroupName' ResourceGroup doesn't exist !!!" -ErrorAction Stop
    }

    #region Build the Azure resource abbreviation lookup from Azure Naming Tool data
    $Result = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/refs/heads/main/src/repository/resourcetypes.json 
    $ResourceTypeShortNameHT = $Result | Where-Object -FilterScript { $_.property -in @('', 'Windows') } | Select-Object -Property resource, shortName, lengthMax | Group-Object -Property resource -AsHashTable -AsString
    #endregion

    #region Variables
    $SubscriptionId = (Get-AzContext).Subscription.Id
    $ClusterName = "localboxcluster"
    $LogAnalyticsWorkSpaceName = "LocalBox-Workspace"
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
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Cluster:`r`n$($Cluster | Out-String)"
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
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$LogAnalyticsWorkSpace:`r`n$($LogAnalyticsWorkSpace | Out-String)"
    #endregion

    #region Install Azure Monitor Agent on the Azure Local cluster
    $ExtensionName = "AzureMonitorWindowsAgent"
    $ArcSettingName = "default"
    $Parameters = @{
        ResourceGroupName = $ResourceGroup.ResourceGroupName
        ClusterName       = $ClusterName
        ArcSettingName    = $ArcSettingName
    }
    $Extension = Get-AzStackHciExtension @Parameters | Where-Object -FilterScript { $_.Name -eq $ExtensionName }

    # Install the cluster extension only when it is not already present.
    if (-not($Extension)) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Installing '$ExtensionName' extension on the '$($ClusterName)' Azure Local ClusterMachine (in the '$($ResourceGroup.ResourceGroupName)' Resource Group)"
        $Parameters = @{
            ResourceGroupName                         = $ResourceGroup.ResourceGroupName
            ClusterName                               = $ClusterName
            ArcSettingName                            = $ArcSettingName
            ExtensionName                             = $ExtensionName
            ExtensionParameterPublisher               = "Microsoft.Azure.Monitor"
            ExtensionParameterType                    = "AzureMonitorWindowsAgent"
            ExtensionParameterAutoUpgradeMinorVersion = $false
            ExtensionParameterEnableAutomaticUpgrade  = $true
        }
        $Extension = New-AzStackHciExtension @Parameters

    }
    else {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The '$ExtensionName' extension is already installed on the '$($ClusterName)' Azure Local ClusterMachine (in the '$($ResourceGroup.ResourceGroupName)' Resource Group)"
    }
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

    #region Install Azure Monitor Agent on the Azure Local nodes
    $Jobs = foreach ($AzureArcMachine in $AzureArcMachines) {
        $InstalledExtension = Get-AzConnectedMachineExtension -ResourceGroupName $ResourceGroup.ResourceGroupName -MachineName $AzureArcMachine.Name | Where-Object -FilterScript { $_.Name -match "AzureMonitorWindowsAgent" } | Select-Object -First 1
        if (-not($InstalledExtension)) {
            $ExtensionName = "AzureMonitorWindowsAgent"
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Installing '$ExtensionName' extension on the '$($AzureArcMachine.Name)' Azure Arc Machine (in the '$($ResourceGroup.ResourceGroupName)' Resource Group) (As A Job)"
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
        # Wait for all node extension installations and surface any unsuccessful job.
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

    # Reuse the endpoint if present; otherwise create one in the resource group's location.
    if (-not($DataCollectionEndpoint)) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the '$DataCollectionEndpointName' Data Collection Endpoint"
        $Parameters['Location'] = $Location
        $Parameters['NetworkAclsPublicNetworkAccess'] = "Enabled"
        $DataCollectionEndpoint = New-AzDataCollectionEndpoint @Parameters
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$DataCollectionEndpoint:`r`n$($DataCollectionEndpoint | Out-String)"
    #endregion

    #region Data Collection Rule
    #region Performance Counters
    # Collect host memory, network throughput, CPU utilization, and RDMA traffic every 10 seconds.
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
    # Forward Azure Local health and SDDC management events to the workspace.
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

    #region Log Analytics workspace destinations
    $LADestinationName = $LogAnalyticsWorkSpace.Name
    $Parameters = @{
        Name                = $LADestinationName
        WorkspaceResourceId = $LogAnalyticsWorkSpace.ResourceId
    }
    $DestinationLogAnalytic = New-AzLogAnalyticsDestinationObject @Parameters
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$DestinationLogAnalytic:`r`n$($DestinationLogAnalytic | Out-String)"

    $LADestinationName2 = [Guid]::NewGuid().Guid
    $Parameters = @{
        Name                = $LADestinationName2
        WorkspaceResourceId = $LogAnalyticsWorkSpace.ResourceId
    }
    $DestinationLogAnalytic2 = New-AzLogAnalyticsDestinationObject @Parameters
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$DestinationLogAnalytic2:`r`n$($DestinationLogAnalytic2 | Out-String)"
    #endregion

    #region Data flows (each destination name must match its destination object)
    $Parameters = @{
        Stream      = @("Microsoft-Perf")
        Destination = @($LADestinationName)
    }
    $PerfDataFlow = New-AzDataFlowObject @Parameters

    $Parameters = @{
        Stream      = @("Microsoft-Event")
        Destination = @($LADestinationName2)
    }
    $EventDataFlow = New-AzDataFlowObject @Parameters
    #endregion

    #region Create the data collection rule when absent
    $Parameters = @{
        ResourceGroupName = $ResourceGroup.ResourceGroupName
        Name              = $DataCollectionRuleName
    }
    $DataCollectionRule = Get-AzDataCollectionRule @Parameters -ErrorAction Ignore

    # Create the rule only when absent; existing rules are intentionally left unchanged.
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
            DestinationLogAnalytic       = @($DestinationLogAnalytic, $DestinationLogAnalytic2)
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
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$DataCollectionRule:`r`n$($DataCollectionRule | Out-String)"
    #endregion
    #endregion

    #region Associate DCR with every Azure Local node
    foreach ($AzureArcMachine in $AzureArcMachines) {
        # Query each node because an unassociated node has no association resource to retrieve directly.
        # String comparison with -eq is case-insensitive, matching Azure resource ID semantics.
        $ExistingAssociation = Get-AzDataCollectionRuleAssociation -ResourceUri $AzureArcMachine.Id -ErrorAction Ignore | Where-Object -FilterScript { $_.DataCollectionRuleId -eq $DataCollectionRule.Id } | Select-Object -First 1

        if ($ExistingAssociation) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The '$($AzureArcMachine.Name)' Azure Arc Machine is already associated with the '$($DataCollectionRule.Name)' DCR ('$($ExistingAssociation.Name)')"
            continue
        }

        # Association names are unique per node/DCR link.
        $AssociationName = "dra_{0}" -f $((New-Guid).Guid)
        $Parameters = @{
            ResourceUri          = $AzureArcMachine.Id
            AssociationName      = $AssociationName
            DataCollectionRuleId = $DataCollectionRule.Id
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Associating the '$($DataCollectionRule.Name)' DCR with the '$($AzureArcMachine.Name)' Azure Arc Machine"
        $DataCollectionRuleAssociation = New-AzDataCollectionRuleAssociation @Parameters
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$DataCollectionRuleAssociation:`r`n$($DataCollectionRuleAssociation | Out-String)"
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
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

<#
.SYNOPSIS
Builds Azure Local images and virtual machines for Azure Virtual Desktop.

.DESCRIPTION
Builds Marketplace and Azure Compute Gallery images, waits for image jobs, removes
temporary Azure managed disks tagged ToBeCleaned, and starts VM creation jobs for
successfully provisioned images. Opens the cluster image status page in the Azure portal.
Uses Credential, LogicalNetwork, and SubscriptionId from the calling scope.

.PARAMETER ResourceGroupName
Specifies the resource group containing the LocalBox cluster and image resources.

.PARAMETER AsAJob
Requests background jobs from the image-building functions. This function still
waits for image and VM jobs before completing.

.EXAMPLE
New-AzLocalAVD -ResourceGroupName 'rg-localbox' -AsAJob

Builds images and VMs after Credential, LogicalNetwork, and SubscriptionId are set in the calling scope.

.OUTPUTS
None
Stores VM job results internally without returning them.
#>
function New-AzLocalAVD {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceGroupName,
        [switch] $AsAJob
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ResourceGroupName: $ResourceGroupName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AsAJob: $AsAJob"
    Write-Host -Object "The image and VM builds can take some hours ..." -ForegroundColor Yellow
    #region AVD MarketPlace + ACG Images
    #Building Windows 11 AVD images (with and without M365)
    $Jobs = New-AzLocalAVDVMImage -ResourceGroupName $ResourceGroupName -AsAJob:$AsAJob.IsPresent
    #Building one image per Azure Compute Image Version
    $Jobs += New-AzureLocalVMImageFromAzureComputeGalleryImage -ResourceGroupName $ResourceGroupName -All -AsAJob:$AsAJob.IsPresent
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Jobs:`r`n$($Jobs | Out-String)"
    $ClusterName = "localboxcluster"
    $ImageStatusURI = "https://portal.azure.com/#@{0}/resource/subscriptions/{1}/resourceGroups/{2}/providers/microsoft.azurestackhci/clusters/{3}/vmimages" -f $((Get-AzTenant).Domains[-1]), $SubscriptionId, $ResourceGroupName, $ClusterName
    Start-Process $ImageStatusURI 

    $Images = $Jobs | Receive-Job -Wait -AutoRemoveJob

    #region Disk cleanup
    $DiskToRemove = Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType Microsoft.Compute/disks -Tag @{"ToBeCleaned" = $true } | Get-AzDisk
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$DiskToRemove:`r`n$($DiskToRemove | Out-String)"
    $RevokedDiskAccess = $DiskToRemove | Revoke-AzDiskAccess -AsJob | Receive-Job -Wait -AutoRemoveJob
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$RevokedDiskAccess:`r`n$($RevokedDiskAccess | Out-String)"
    $RemovedDisk = $DiskToRemove | Remove-AzDisk -AsJob -Force | Receive-Job -Wait -AutoRemoveJob
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$RemovedDisk:`r`n$($RemovedDisk | Out-String)"
    #endregion

    if ($Images.ProvisioningState -contains "Failed") {
        $Parameters = @{
            ResourceGroupName = $ResourceGroupName
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Parameters:`r`n$($Parameters | Out-String)"
        $FailedImages = Get-AzStackHCIVMImage @Parameters | Where-Object -FilterScript { $_.ProvisioningState -ne "Succeeded" }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$FailedImages:`r`n$($FailedImages | Out-String)"
        Write-Error -Message "One or more image(s) failed during the build : $($FailedImages.Name -join ', ')"
    }

    $Parameters = @{
        ResourceGroupName = $ResourceGroupName
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Parameters:`r`n$($Parameters | Out-String)"
    $SuccessfulImages = Get-AzStackHCIVMImage @Parameters | Where-Object -FilterScript { $_.ProvisioningState -eq "Succeeded" }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$SuccessfulImages:`r`n$($SuccessfulImages | Out-String)"
    #endregion 

    #region VMs/AVD Session Hosts
    $ExportedFunctions = [scriptblock]::Create(@"
        Import-Module -Name Az.StackHCIVM
        Function New-AzLocalAVDVM { ${Function:New-AzLocalAVDVM} }
"@)
    $Jobs = foreach ($Image in $SuccessfulImages) {
        Start-Job -ScriptBlock { $null = Update-AzConfig -DisplayBreakingChangeWarning $false -Scope Process; New-AzLocalAVDVM -Credential $using:Credential -Image $using:Image -LogicalNetwork $using:LogicalNetwork } -InitializationScript $ExportedFunctions
        #New-AzLocalAVDVM -Credential $Credential -Image $Image -LogicalNetwork $LogicalNetwork
    }
    $VMs = $Jobs | Receive-Job -Wait -AutoRemoveJob
    #endregion
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

<#
.SYNOPSIS
Lists Marketplace image versions available to Azure Local clusters.

.DESCRIPTION
Queries Microsoft.EdgeMarketplace offers through the Azure Resource Manager batch
API using the current Azure context. Lists all image versions or filters by URN.
Resolves latest to the newest listed version and warns before substituting the
newest version when a requested version is unavailable.

.PARAMETER ResourceGroupName
Specifies the resource group containing the cluster in the current subscription.

.PARAMETER ClusterName
Specifies the cluster name when using ResourceGroupName. Defaults to localboxcluster.

.PARAMETER Cluster
Specifies one or more Azure Stack HCI cluster objects, including objects received through the pipeline.

.PARAMETER URN
Filters images by publisher:offer:sku:version. Use latest for the newest listed version.

.PARAMETER AsObject
Returns objects containing ClusterId, PublisherName, Offer, Sku, and Version instead of URN strings.

.EXAMPLE
Get-MicrosoftEdgeMarketPlaceImage -ResourceGroupName 'rg-localbox'

Lists all available image URNs for the default cluster.

.EXAMPLE
Get-AzStackHCICluster -ResourceGroupName 'rg-localbox' | Get-MicrosoftEdgeMarketPlaceImage -AsObject

Lists available image versions as objects for clusters received through the pipeline.

.OUTPUTS
System.String
System.Management.Automation.PSCustomObject
System.Boolean
Returns URN strings by default or image objects with AsObject. Returns false when a handled web request fails.
#>
function Get-MicrosoftEdgeMarketPlaceImage {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceGroupName')]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceGroupName')]
        [ValidateNotNullOrEmpty()]
        [string] $ClusterName = "localboxcluster",

        [Parameter(Mandatory = $true, ParameterSetName = 'Cluster', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $false)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Azure.PowerShell.Cmdlets.StackHCI.Models.Cluster[]] $Cluster,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^.+:.+:.+:.+$")]
        [string[]] $URN,

        [switch] $AsObject
    )

    begin {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ResourceGroupName: $ResourceGroupName"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ClusterName: $ClusterName"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$URN:`r`n$($URN | Out-String)"
        #region Azure Context
        # Log in first with Connect-AzAccount if not using Cloud Shell
        $azContext = Get-AzContext
        $SubcriptionID = $azContext.Subscription.Id
        $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
        $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
        $token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)
        $authHeader = @{
            'Content-Type'  = 'application/json'
            'Authorization' = 'Bearer ' + $token.AccessToken
        }
        #endregion
        $MicrosoftEdgeMarketPlaceImage = @()
    }

    process {
        if ($Cluster) {
            $ClusterId = foreach ($CurrentCluster in $Cluster) {
                $CurrentClusterId = $($CurrentCluster.Id)
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CurrentClusterId: $CurrentClusterId"
                $ClusterSubcriptionID = ([regex]::Match($CurrentClusterId, "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")).Value
                if ($ClusterSubcriptionID -ne $SubcriptionID) {
                    Write-Warning -Message "'$CurrentClusterId' is not in the '$SubcriptionID' Subcription. Skipping it ..."
                }
                else {
                    $CurrentClusterId
                }
            }
        }
        else {
            $ClusterId = @("/subscriptions/$SubcriptionID/resourcegroups/$ResourceGroupName/providers/microsoft.azurestackhci/clusters/$ClusterName")
        }

        foreach ($CurrentClusterId in $ClusterId) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CurrentClusterId: $CurrentClusterId"
            $URL = "https://management.azure.com$($CurrentClusterId)/providers/Microsoft.EdgeMarketplace/offers?api-version=2023-08-01-preview"        
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$URL: $URL"

            $Body = [ordered]@{ 
                "requests" = @(
                    [ordered]@{
                        "httpMethod"           = "GET"
                        "name"                 = $([Guid]::NewGuid().Guid)
                        "requestHeaderDetails" = @{
                            "commandName" = "Microsoft_AzureStackHCI_PortalExtension.GetMarketPlaceOffers"
                        }
                        "url"                  = $URL
                    }
                )
            }

            $URI = "https://management.azure.com/batch?api-version=2020-06-01"
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$URI: $URI"
            try {
                # Invoke the REST API
                $Payload = $($Body | ConvertTo-Json -Depth 100)
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Payload:`r`n$($Payload | Out-String)"
                $Response = Invoke-AzRestMethod -Method POST -Payload $Payload -Uri $URI -ErrorVariable ResponseError
            }
            catch [System.Net.WebException] {   
                # Dig into the exception to get the Response details.
                # Note that value__ is not a typo.
                Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
                Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
                $respStream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($respStream)
                $Response = $reader.ReadToEnd() | ConvertFrom-Json
                if (-not([string]::IsNullOrEmpty($Response.message))) {
                    Write-Warning -Message $Response.message
                }
                return $false
            }
            finally {
            }
            #endregion

            #region Getting URN
            if ($null -ne $URN) {
                $MicrosoftEdgeMarketPlaceImage += foreach ($CurrentURN in $URN) {
                    $PublisherName, $Offer, $Sku, $Version = $CurrentURN -split ":"
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$PublisherName: $PublisherName"
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Offer: $Offer"
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Sku: $Sku"
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Version: $Version"

                    $MicrosoftEdgeMarketPlaceOffer = ($Response.Content | ConvertFrom-Json).responses.content.value | Where-Object -FilterScript { $_.name -eq $("{0}:{1}" -f $PublisherName, $Offer) }
                    $MicrosoftEdgeMarketPlaceSku = $MicrosoftEdgeMarketPlaceOffer.properties.marketplaceSkus | Where-Object -FilterScript { $_.marketplaceSkuId -eq $Sku }
                    $MicrosoftEdgeMarketPlaceSkuVersions = $MicrosoftEdgeMarketPlaceSku.marketplaceSkuVersions
                    $MicrosoftEdgeMarketPlaceSkuLatestVersion = ($MicrosoftEdgeMarketPlaceSkuVersions | Sort-Object -Property Name -Descending | Select-Object -First 1).Name
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$MicrosoftEdgeMarketPlaceOffer: $MicrosoftEdgeMarketPlaceOffer"
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$MicrosoftEdgeMarketPlaceSku: $MicrosoftEdgeMarketPlaceSku"
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$MicrosoftEdgeMarketPlaceSkuVersions:`r`n$($MicrosoftEdgeMarketPlaceSkuVersions | Out-String)"
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$MicrosoftEdgeMarketPlaceSkuLatestVersion: $MicrosoftEdgeMarketPlaceSkuLatestVersion"

                    if ($version -eq "latest") {
                        $Version = $MicrosoftEdgeMarketPlaceSkuLatestVersion
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Version: $Version"
                    }
                    else {
                        if ($Version -notin $MicrosoftEdgeMarketPlaceSkuVersions.Name) {
                            Write-Warning -Message "Specified '$Version' Version is not part of the avalaible versions : '$($MicrosoftEdgeMarketPlaceSkuVersions.Name -join ',')'. We take the latest one : 'MicrosoftEdgeMarketPlaceSkuLatestVersion'"
                            $Version = ($MicrosoftEdgeMarketPlaceSkuVersions | Sort-Object -Property Name -Descending | Select-Object -First 1).Name
                            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Version: $Version"
                        }
                    }
                    if (-not([string]::IsNullOrEmpty($MicrosoftEdgeMarketPlaceOffer.Name)) -and -not([string]::IsNullOrEmpty($MicrosoftEdgeMarketPlaceSku.marketplaceSkuId)) -and -not([string]::IsNullOrEmpty($Version))) {
                        if ($AsObject) {
                            $PublisherName, $Offer = $MicrosoftEdgeMarketPlaceOffer.Name -split ":"
                            $CurrentMicrosoftEdgeMarketPlaceImage = [PScustomObject]@{ClusterId = $CurrentClusterId; PublisherName = $PublisherName; Offer = $Offer; Sku = $MicrosoftEdgeMarketPlaceSku.marketplaceSkuId; Version = $Version }
                            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CurrentMicrosoftEdgeMarketPlaceImage: $($CurrentMicrosoftEdgeMarketPlaceImage | Out-String)"
                            $CurrentMicrosoftEdgeMarketPlaceImage
                        }
                        else {
                            $CurrentMicrosoftEdgeMarketPlaceImage = "{0}:{1}:{2}" -f $MicrosoftEdgeMarketPlaceOffer.Name, $MicrosoftEdgeMarketPlaceSku.marketplaceSkuId, $Version
                            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CurrentMicrosoftEdgeMarketPlaceImage: $CurrentMicrosoftEdgeMarketPlaceImage"
                            $CurrentMicrosoftEdgeMarketPlaceImage
                        }

                    }
                }
            }
            else {
                $MicrosoftEdgeMarketPlaceOffers = ($Response.Content | ConvertFrom-Json).responses.content.value
                $MicrosoftEdgeMarketPlaceImage += foreach ($MicrosoftEdgeMarketPlaceOffer in $MicrosoftEdgeMarketPlaceOffers) {
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$MicrosoftEdgeMarketPlaceOffer: $MicrosoftEdgeMarketPlaceOffer"
                    $MicrosoftEdgeMarketPlaceSkus = $MicrosoftEdgeMarketPlaceOffer.properties.marketplaceSkus
                    foreach ($MicrosoftEdgeMarketPlaceSku in $MicrosoftEdgeMarketPlaceSkus) {
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$MicrosoftEdgeMarketPlaceSku: $MicrosoftEdgeMarketPlaceSku"
                        $MicrosoftEdgeMarketPlaceSkuVersions = $MicrosoftEdgeMarketPlaceSku.marketplaceSkuVersions.Name
                        foreach ($MicrosoftEdgeMarketPlaceSkuVersion in $MicrosoftEdgeMarketPlaceSkuVersions) {
                            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$MicrosoftEdgeMarketPlaceSkuVersion: $MicrosoftEdgeMarketPlaceSkuVersion"
                            if ($AsObject) {
                                $PublisherName, $Offer = $MicrosoftEdgeMarketPlaceOffer.Name -split ":"
                                $CurrentMicrosoftEdgeMarketPlaceImage = [PScustomObject]@{ClusterId = $CurrentClusterId; PublisherName = $PublisherName; Offer = $Offer; Sku = $MicrosoftEdgeMarketPlaceSku.marketplaceSkuId; Version = $MicrosoftEdgeMarketPlaceSkuVersion }
                                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CurrentMicrosoftEdgeMarketPlaceImage: $($CurrentMicrosoftEdgeMarketPlaceImage | Out-String)"
                                $CurrentMicrosoftEdgeMarketPlaceImage
                            }
                            else {
                                $CurrentMicrosoftEdgeMarketPlaceImage = "{0}:{1}:{2}" -f $MicrosoftEdgeMarketPlaceOffer.Name, $MicrosoftEdgeMarketPlaceSku.marketplaceSkuId, $MicrosoftEdgeMarketPlaceSkuVersion
                                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CurrentMicrosoftEdgeMarketPlaceImage: $CurrentMicrosoftEdgeMarketPlaceImage"
                                $CurrentMicrosoftEdgeMarketPlaceImage
                            }
                        }
                    }
                }
            }
        }
        #endregion
    }

    end {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        $MicrosoftEdgeMarketPlaceImage
    }
}

<#
.SYNOPSIS
Imports Azure Marketplace Windows images into Azure Local.

.DESCRIPTION
Finds the custom location in the resource group and starts one background import
job for each Marketplace URN. The function currently resolves every URN to the
second entry in the descending version list, regardless of the version supplied,
to avoid a known SAS token generation error. Without AsAJob, it waits for the
imports and returns the successfully provisioned images found in the resource
group.

.PARAMETER ResourceGroupName
Specifies the resource group containing the Azure Local custom location and
receiving the imported images.

.PARAMETER URN
Specifies one or more Marketplace image identifiers in Publisher:Offer:Sku:Version
format. Defaults to the Windows 11 25H2 Azure Virtual Desktop images with and
without Microsoft 365 Apps. The function currently resolves each identifier to
the second entry in the available versions sorted in descending order; the
version component supplied here does not select the imported version.

.PARAMETER AsAJob
Returns the image import jobs immediately instead of waiting for their results.

.EXAMPLE
New-AzLocalAVDVMImage -ResourceGroupName 'rg-localbox-001'

Starts imports for the default Windows 11 25H2 Azure Virtual Desktop images and
waits for the background jobs to complete.

.EXAMPLE
$Jobs = New-AzLocalAVDVMImage -ResourceGroupName 'rg-localbox-001' -AsAJob
$Jobs | Receive-Job -Wait -AutoRemoveJob

Starts both image imports asynchronously, then waits for and displays their job
results.

.OUTPUTS
Azure Local image objects, or System.Management.Automation.Job objects when
AsAJob is specified.
#>
function New-AzLocalAVDVMImage {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceGroupName,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^.+:.+:.+:.+$")]
        [string[]] $URN = @("MicrosoftWindowsDesktop:office-365:win11-25h2-avd-m365:latest", "MicrosoftWindowsDesktop:windows-11:win11-25h2-avd:latest"),
        [switch] $AsAJob
    )
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    # Marketplace image guidance:
    # https://jumpstart.azure.com/azure_jumpstart_localbox/RB#create-virtual-machine-images-from-azure-marketplace
    $CustomLocation = Get-AzResource -ResourceType "Microsoft.ExtendedLocation/customLocations" -ResourceGroupName $ResourceGroupName
    $Location = $CustomLocation.Location
    $Instance = [regex]::Match($ResourceGroupName, "\d+$").Value
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CustomLocation: $CustomLocation"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Location: $Location"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Instance: $Instance"

    #$MicrosoftEdgeMarketPlaceURNs = Get-MicrosoftEdgeMarketPlaceImage -ResourceGroupName $ResourceGroupName -URN $URN
    #To list all available images : Get-MicrosoftEdgeMarketPlaceImage -ResourceGroupName $ResourceGroupName -AsObject
    $MicrosoftEdgeMarketPlaceURNs = Get-MicrosoftEdgeMarketPlaceImage -ResourceGroupName $ResourceGroupName -URN $URN -AsObject

    $Jobs = foreach ($CurrentMicrosoftEdgeMarketPlaceURN in $MicrosoftEdgeMarketPlaceURNs) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CurrentMicrosoftEdgeMarketPlaceURN: $CurrentMicrosoftEdgeMarketPlaceURN"
        #$PublisherName, $Offer, $Sku, $Version = $CurrentMicrosoftEdgeMarketPlaceURN -split ":"
        $PublisherName = $CurrentMicrosoftEdgeMarketPlaceURN.PublisherName
        $Offer = $CurrentMicrosoftEdgeMarketPlaceURN.Offer
        $Sku = $CurrentMicrosoftEdgeMarketPlaceURN.Sku
        $Version = $CurrentMicrosoftEdgeMarketPlaceURN.Version
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$PublisherName: $PublisherName"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Offer: $Offer"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Sku: $Sku"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Version: $Version"
        $ImageName = "{0}-{1}-{2}" -f $Sku, $Instance, $(Get-Date -Format 'yyyyMMddHHmmss')
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ImageName: $ImageName"
        $Parameters = @{
            Name              = $ImageName
            ResourceGroupName = $ResourceGroupName
            Location          = $Location
            CustomLocationId  = $CustomLocation.Id
            Publisher         = $PublisherName
            Offer             = $Offer
            Sku               = $Sku
            Version           = $Version
            OSType            = "Windows"
            # New-AzStackHCIVMImage has no AsJob parameter; run it in a job to import multiple images concurrently.
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Parameters:`r`n$($Parameters | Out-String)"
        # Pass the image settings into the job and suppress per-process breaking-change warnings.
        Start-Job -ScriptBlock { $null = Update-AzConfig -DisplayBreakingChangeWarning $false -Scope Process; $Parameters = $Using:Parameters; New-AzStackHCIVMImage @Parameters }

    }
    if ($AsAJob) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        return $Jobs
    }
    else {
        $Images = $Jobs | Receive-Job -Wait -AutoRemoveJob
        if ($Images.ProvisioningState -contains "Failed") {
            $Parameters = @{
                ResourceGroupName = $ResourceGroupName
            }
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Parameters:`r`n$($Parameters | Out-String)"
            $FailedImages = Get-AzStackHCIVMImage @Parameters | Where-Object -FilterScript { $_.ProvisioningState -ne "Succeeded" }
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$FailedImages:`r`n$($FailedImages | Out-String)"
            Write-Error -Message "One or more image(s) failed during the build : $($FailedImages.Name -join ', ')"
        }

        $Parameters = @{
            ResourceGroupName = $ResourceGroupName
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Parameters:`r`n$($Parameters | Out-String)"
        $SuccessfulImages = Get-AzStackHCIVMImage @Parameters | Where-Object -FilterScript { $_.ProvisioningState -eq "Succeeded" }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$SuccessfulImages:`r`n$($SuccessfulImages | Out-String)"
    
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        return $SuccessfulImages
    }
}

<#
.SYNOPSIS
Creates a Windows VM on an Azure Local logical network.

.DESCRIPTION
Looks up resource abbreviations from Azure Naming Tool data, creates a network
interface on the supplied logical network, then creates a Windows VM using the
image, administrator credentials, and fixed Standard_D2s_v5 size. Names are
derived from the image, naming abbreviations, and trailing digits in the resource
group name. Supply an image object: although the Image parameter is not marked
mandatory, the function uses it to build the VM. This function does not register
the VM with Azure Virtual Desktop.

.PARAMETER Credential
Specifies the local administrator credentials for the new virtual machine.

.PARAMETER Image
Specifies the Azure Local image to use for the VM. Supply an image object returned
by Get-AzStackHCIVMImage or New-AzLocalAVDVMImage; the function uses its name,
location, and extended location.

.PARAMETER LogicalNetwork
Specifies the Azure Local logical network for the VM's network interface and
resource group.

.EXAMPLE
New-AzLocalAVDVM -Credential (Get-Credential) -Image $Image -LogicalNetwork $LogicalNetwork

Creates a Standard_D2s_v5 Windows VM using the supplied image, credentials, and
logical network, then returns the VM object.

.OUTPUTS
Returns the Azure Local virtual machine object created by
New-AzStackHCIVMVirtualMachine.
#>
function New-AzLocalAVDVM {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [PSCredential] $Credential,
        [ValidateNotNullOrEmpty()]
        [Microsoft.Azure.PowerShell.Cmdlets.StackHCIVM.Models.MarketplaceGalleryImages] $Image,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Azure.PowerShell.Cmdlets.StackHCIVM.Models.LogicalNetworks] $LogicalNetwork
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$LogicalNetwork:`r`n$($LogicalNetwork | Out-String)"
    #region Build the Azure resource abbreviation lookup from Azure Naming Tool data
    $Result = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/refs/heads/main/src/repository/resourcetypes.json 
    $ResourceTypeShortNameHT = $Result | Where-Object -FilterScript { $_.property -in @('', 'Windows') } | Select-Object -Property resource, shortName, lengthMax | Group-Object -Property resource -AsHashTable -AsString
    #endregion

    $NICNamePrefix = $ResourceTypeShortNameHT["Network/networkInterfaces"].ShortName
    $VMNamePrefix = $ResourceTypeShortNameHT["Compute/virtualMachines"].ShortName
    # Use the resource group's trailing instance number to keep related VM names aligned.
    $Instance = [regex]::Match($LogicalNetwork.ResourceGroupName, "\d+$").Value
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$NICNamePrefix: $NICNamePrefix"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$VMNamePrefix: $VMNamePrefix"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Instance: $Instance"

    #region Create the network interface
    # Shorten the image identifier so it can be incorporated into the generated VM name.
    $FormattedSku = $Image.Name -replace "(-\d{3})?-\d{14}$" -replace "win\d*", "w" -replace "acg", "a" -replace "avd" -replace "\W"
    $FormattedSku = $FormattedSku.SubString(0, [math]::Min(10, $FormattedSku.Length))
    $VMName = "{0}{1}{2}" -f $VMNamePrefix, $FormattedSku, $Instance
    if (Get-AzStackHCIVMVirtualMachine -Name $VMName -ResourceGroupName $LogicalNetwork.ResourceGroupName -ErrorAction Ignore) {
        $NewVMName = "{0}{1}" -f $VMNamePrefix, $(Get-Date -Format "yyMMddHHmmss")
        Write-Warning -Message "The '$VMName' is already taken. We will use a timestamped name: $NewVMName"
        $VMName = $NewVMName
    }

    $NICName = "{0}-{1}" -f $NICNamePrefix, $VMName
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$FormattedSku: $FormattedSku"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$VMName: $VMName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$NICName: $NICName"

    $Parameters = @{
        Name              = $NICName
        ResourceGroupName = $LogicalNetwork.ResourceGroupName
        Location          = $LogicalNetwork.Location
        CustomLocationId  = $LogicalNetwork.ExtendedLocationName
        #SubnetName        = $LogicalNetwork.Subnet.Name
        SubnetName        = $LogicalNetwork.Name
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Parameters:`r`n$($Parameters | Out-String)"
    $NIC = New-AzStackHCIVMNetworkInterface @Parameters
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$NIC:`r`n$($NIC | Out-String)"
    #endregion

    #region Create the virtual machine
    $Parameters = @{
        Name              = $VMName
        ResourceGroupName = $LogicalNetwork.ResourceGroupName
        Location          = $Image.Location
        CustomLocationId  = $Image.ExtendedLocationName
        ImageName         = $Image.Name
        NicId             = $NIC.Id
        VMSize            = "Standard_D2s_v5"
        AdminUsername     = $Credential.UserName
        AdminPassword     = $Credential.Password
        OSType            = "Windows"
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Parameters:`r`n$($Parameters | Out-String)"
    $VM = New-AzStackHCIVMVirtualMachine @Parameters        
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$VM:`r`n$($VM | Out-String)"

    #We have to put the tag on the Azure Arc machine not on the AzureStackHCI reource itself
    $ResourceId = $VM.Id -replace "/providers/Microsoft.AzureStackHCI/.*"
    $Parameters = @{
        ResourceId = $ResourceId
        Tag        = @{ "Image" = $Image.Name }
        Operation  = "Merge"
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Parameters:`r`n$($Parameters | Out-String)"
    $null = Update-AzTag @Parameters

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $VM

    #endregion
}

<#
.SYNOPSIS
Runs the LocalBox network configuration script and returns its logical network.

.DESCRIPTION
Uses Azure VM Run Command to run
C:\LocalBox\Configure-VMLogicalNetwork.ps1 on LocalBox-Client with the Azure CLI
directory added to PATH. It then looks up localbox-vm-lnet-vlan200 in the supplied
resource group. Raises a terminating error if the logical network is not found.

.PARAMETER ResourceGroupName
Specifies the resource group containing LocalBox-Client and the
localbox-vm-lnet-vlan200 logical network.

.EXAMPLE
$LogicalNetwork = New-VMLogicalNetwork -ResourceGroupName 'rg-localbox-001'

Runs the remote configuration script and stores the resulting logical network
object in $LogicalNetwork.

.OUTPUTS
Returns the Azure Local logical network object named localbox-vm-lnet-vlan200.
#>
function New-VMLogicalNetwork {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceGroupName
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    $ScriptPath = "C:\LocalBox\Configure-VMLogicalNetwork.ps1"

    # Run the guest-side network setup through Azure VM Run Command, where az must be on PATH.
    $ScriptString = @"
`$env:PATH = "C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin;`$env:PATH"

Write-Host "Identity:"
whoami

Write-Host "Azure CLI:"
Get-Command az
az version

Write-Host "Starting '$ScriptPath' ..."
pwsh -File '$ScriptPath'
"@
    $AzVMRunCommand = Invoke-AzVMRunCommand  -CommandId 'RunPowerShellScript' -ResourceGroupName $ResourceGroupName -VMName LocalBox-Client -ScriptString $ScriptString
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AzVMRunCommand:`r`n$($AzVMRunCommand | Out-String)"
    $LogicalNetworkName = "localbox-vm-lnet-vlan200"
    $LogicalNetwork = Get-AzStackHCIVMLogicalNetwork -ResourceGroupName $ResourceGroupName -Name $LogicalNetworkName -ErrorAction Ignore
    if (-not($LogicalNetwork)) {
        Write-Error -Message "The '$LogicalNetworkName' Azure Local Logical Network doesn't exist ..." -ErrorAction Stop
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $LogicalNetwork
}

<#
.SYNOPSIS
Imports Azure Compute Gallery images as Azure Local Windows VM images.

.DESCRIPTION
Lists gallery image versions in the current subscription. By default, Out-GridView
prompts for versions to import; with All, the function selects the latest version
of each image definition. For each selection, it creates a temporary managed disk
in the target resource group, grants read access through a time-limited SAS URL,
and starts an Azure Local image import job. Without AsAJob, it starts cleanup jobs
for the temporary disks, waits for the imports, and returns successfully
provisioned images found in the resource group.

.PARAMETER ResourceGroupName
Specifies the target resource group for temporary managed disks and Azure Local
images. It must also contain the specified Azure Local cluster and its custom
location.

.PARAMETER ClusterName
Specifies the Azure Local cluster name. Defaults to localboxcluster.

.PARAMETER SASExpiryDuration
Specifies how long, in seconds, the managed disk SAS URL remains valid. Defaults
to 100000 seconds.

.PARAMETER All
Selects the latest version of each gallery image definition instead of displaying
the interactive Out-GridView picker.

.PARAMETER AsAJob
Returns the import jobs without waiting. In this mode, the function does not start
temporary-disk cleanup; remove the managed disks tagged ToBeCleaned after the
imports complete.

.EXAMPLE
New-AzureLocalVMImageFromAzureComputeGalleryImage -ResourceGroupName 'rg-localbox-001'

Displays the Out-GridView picker, imports the selected gallery image versions, and
waits for the imports to finish.

.EXAMPLE
New-AzureLocalVMImageFromAzureComputeGalleryImage -ResourceGroupName 'rg-localbox-001' -All

Imports the latest version of each gallery image definition in the current
subscription and waits for the imports to finish.

.OUTPUTS
Returns successfully provisioned Azure Local image objects when waiting for
completion, or System.Management.Automation.Job objects when AsAJob is specified.
#>
function New-AzureLocalVMImageFromAzureComputeGalleryImage {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceGroupName,
        [Parameter(Mandatory = $false)]
        [string] $ClusterName = "localboxcluster",
        [Parameter(Mandatory = $false)]
        # Duration in seconds for SAS URL validity
        [uint32] $SASExpiryDuration = 100000,
        [switch] $All,
        [switch] $AsAJob
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ResourceGroupName: $ResourceGroupName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ClusterName: $ClusterName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$SASExpiryDuration: $SASExpiryDuration"
    if ($All) {
        # Sort versions numerically within each image definition, then keep its newest version.
        $Resources = Get-AzResource -ResourceType Microsoft.Compute/galleries/images/versions | Select-Object Name, ResourceId, ResourceGroupName, Location, ParentResource | Sort-Object ParentResource, @{Expression = { $v = $null; $null = [version]::TryParse(($_.Name -split '/')[-1], [ref]$v); $v }; Descending = $true } | Group-Object ParentResource | ForEach-Object { $_.Group[0] }
    }
    else {
        $Resources = Get-AzResource -ResourceType Microsoft.Compute/galleries/images/versions | Select-Object Name, ResourceId, ResourceGroupName, Location, ParentResource | Sort-Object Name | Out-GridView -OutputMode Multiple
    }
    $DiskToRemove = @() 

    $Jobs = foreach ($Resource in $Resources) {
        $GalleryName, $ImageDefinition, $ImageVersion = $Resource.Name -split "/"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$GalleryName: $GalleryName"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ImageDefinition: $ImageDefinition"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ImageVersion: $ImageVersion"

        #From https://learn.microsoft.com/en-us/azure/virtual-machines/managed-disk-from-image-version#powershell
        $Parameters = @{
            GalleryImageDefinitionName = $ImageDefinition 
            GalleryName                = $GalleryName 
            ResourceGroupName          = $Resource.ResourceGroupName 
            Name                       = $ImageVersion
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Parameters:`r`n$($Parameters | Out-String)"
        $SourceImageVersion = Get-AzGalleryImageVersion @Parameters
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$SourceImageVersion:`r`n$($SourceImageVersion | Out-String)"

        #Create a disk configuration.
        $Parameters = @{
            Location              = $Resource.Location 
            CreateOption          = 'FromImage' 
            GalleryImageReference = @{Id = $SourceImageVersion.Id }
            # Mark the temporary export disk so it can be identified for cleanup.
            Tag                   = @{"ToBeCleaned" = "true" }
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Parameters:`r`n$($Parameters | Out-String)"
        $DiskConfig = New-AzDiskConfig @Parameters
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$DiskConfig:`r`n$($DiskConfig | Out-String)"
        
        #Create the disk.
        $Parameters = @{
            Disk              = $DiskConfig 
            ResourceGroupName = $ResourceGroupName 
            DiskName          = $ImageDefinition
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Parameters:`r`n$($Parameters | Out-String)"
        $Disk = New-AzDisk @Parameters
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Disk:`r`n$($Disk | Out-String)"
        $DiskToRemove += $Disk

        #From https://learn.microsoft.com/en-us/azure/azure-local/manage/virtual-machine-image-azure-compute-gallery#export-image-to-managed-disk
        # Grant temporary read access so the Azure Local image import can read the managed disk.
        $Parameters = @{
            ResourceGroupName = $Disk.ResourceGroupName
            DiskName          = $Disk.Name 
            DurationInSecond  = $SASExpiryDuration
            Access            = 'Read'
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Parameters:`r`n$($Parameters | Out-String)"
        $SAS = Grant-AzDiskAccess @Parameters
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$SAS:`r`n$($SAS | Out-String)"

        $Cluster = Get-AzStackHciCluster -ResourceGroupName $ResourceGroupName -ClusterName $ClusterName -ErrorAction Ignore
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Cluster:`r`n$($Cluster | Out-String)"
        $SubscriptionId = (Get-AzContext).Subscription.Id
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Subscription: $Subscription"
        $CustomLocation = Get-AzResource -ResourceType "Microsoft.ExtendedLocation/customLocations" -ResourceGroupName $ResourceGroupName
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CustomLocation: $CustomLocation"

        #Create an Azure Local VM image
        #From https://learn.microsoft.com/en-us/azure/azure-local/manage/virtual-machine-image-azure-compute-gallery#create-an-azure-local-vm-image
        $Parameters = @{
            SubscriptionId    = $SubscriptionId
            ResourceGroupName = $ResourceGroupName
            CustomLocationId  = $CustomLocation.Id
            Location          = $Cluster.Location
            Name              = "acg-{0}-{1}" -f $ImageDefinition, $(Get-Date -Format 'yyyyMMddHHmmss')
            OSType            = "Windows"
            ImagePath         = ConvertTo-SecureString -String $SAS.AccessSAS -AsPlainText -Force
            #Version           = $ImageVersion
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Parameters:`r`n$($Parameters | Out-String)"
        Start-Job -ScriptBlock { $null = Update-AzConfig -DisplayBreakingChangeWarning $false -Scope Process; $Parameters = $Using:Parameters; New-AzStackHCIVMImage @Parameters }
    }
    
    if ($AsAJob) {
        # The early return skips the managed-disk cleanup below; retain the disks until the imports finish.
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        return $Jobs
    }
    else {
        #region Disk cleanup
        # Start disk deletion asynchronously to avoid ongoing storage charges after export.
        $null = $DiskToRemove | Remove-AzDisk -AsJob
        #endregion

        $Images = $Jobs | Receive-Job -Wait -AutoRemoveJob
        if ($Images.ProvisioningState -contains "Failed") {
            $Parameters = @{
                ResourceGroupName = $ResourceGroupName
            }
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Parameters:`r`n$($Parameters | Out-String)"
            $FailedImages = Get-AzStackHCIVMImage @Parameters | Where-Object -FilterScript { $_.ProvisioningState -ne "Succeeded" }
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$FailedImages:`r`n$($FailedImages | Out-String)"
            Write-Error -Message "One or more image(s) failed during the build : $($FailedImages.Name -join ', ')"
        }

        $Parameters = @{
            ResourceGroupName = $ResourceGroupName
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Parameters:`r`n$($Parameters | Out-String)"
        $SuccessfulImages = Get-AzStackHCIVMImage @Parameters | Where-Object -FilterScript { $_.ProvisioningState -eq "Succeeded" }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$SuccessfulImages:`r`n$($SuccessfulImages | Out-String)"
    
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        return $SuccessfulImages
    }

}
#endregion

#region Main
try { while (Stop-Transcript) {} } catch {}
Clear-Host
#$VerbosePreference = "continue"
$null = Update-AzConfig -DisplayBreakingChangeWarning $false -Scope Process
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
# Resolve paths relative to this script rather than the caller's working directory.
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

#region Transcript
$Now = Get-Date
$TranscriptFile = $CurrentScript -replace ".ps1$", "_$("{0:yyyyMMddHHmmss}.txt" -f $Now)"
Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader
#endregion

#region Sign in to Azure
# Keep prompting until the Az context can issue an access token.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount
}
#endregion

#region Prerequisites
#region Register required resource providers
$AzResourceProviders = "Microsoft.Attestation", "Microsoft.AzureStackHCI", "Microsoft.EdgeMarketPlace", "Microsoft.ExtendedLocation", "Microsoft.GuestConfiguration", "Microsoft.HybridCompute", "Microsoft.HybridConnectivity", "Microsoft.HybridContainerService", "Microsoft.Insights", "Microsoft.KeyVault", "Microsoft.Kubernetes", "Microsoft.KubernetesConfiguration", "Microsoft.ResourceConnector", "Microsoft.Storage", "Microsoft.Quota"
$Jobs = foreach ($AzResourceProvider in $AzResourceProviders) {
    Register-AzResourceProvider -ProviderNamespace $AzResourceProvider -AsJob
}
#Important: Wait until RegistrationState is set to Registered. 
While (Get-AzResourceProvider -ProviderNamespace $AzResourceProviders | Where-Object -FilterScript { $_.RegistrationState -ne 'Registered' }) {
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 10 seconds ..."
    Start-Sleep -Seconds 10
}
$Jobs | Receive-Job -Wait -AutoRemoveJob | Select-Object -Property ProviderNamespace, RegistrationState
#endregion

#region Bicep
if (-not(Get-Command -Name bicep)) {
    Write-Error -Message "Bicep is mandatory. Please install it (winget install -e --id Microsoft.Bicep) ..." -ErrorAction Stop
}
else {
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Bicep is installed:`r`n$(Get-Command -Name bicep | Out-String)..."
}
#endregion

#region Git
if (-not(Get-Command -Name git)) {
    Write-Error -Message "Git is mandatory. Please install it (winget install -e --id Git.Git) ..." -ErrorAction Stop
}
else {
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Git is installed:`r`n$(Get-Command -Name git | Out-String)..."
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
else {
    Push-Location -Path $(Join-Path -Path $GitDir -ChildPath "azure_arc")
    git pull
    Pop-Location
}

if ($null -ne $azureLocalInstanceLocation) {
    $AzureLocalInstanceLocations = $AzureLocalInstanceLocation
}
else {
    # Deployment source:
    # https://jumpstart.azure.com/azure_jumpstart_localbox/deployment_az
    $AzureLocalInstanceLocations = 'australiaeast', 'southcentralus', 'eastus', 'westeurope', 'southeastasia', 'canadacentral', 'japaneast', 'centralindia'
}
Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AzureLocalInstanceLocations:`r`n$($AzureLocalInstanceLocations | Out-String)"

if ($null -ne $Location) {
    $LAWSupportedRegions = $Location
}
else {
    # Query regions that support Log Analytics workspaces.
    # Intersect provider-supported display names with canoNICal Azure location identifiers.
    $LAWSupportedDisplayNameRegions = ((Get-AzResourceProvider -ProviderNamespace Microsoft.OperationalInsights).ResourceTypes | Where-Object -FilterScript { $_.ResourceTypeName -eq 'workspaces' }).Locations
    $LAWSupportedRegions = (Get-AzLocation | Where-Object { $_.Providers -contains "Microsoft.OperationalInsights" -and ($_.DisplayName -in $LAWSupportedDisplayNameRegions) }).Location | Sort-Object
}
Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$LAWSupportedRegions:`r`n$($LAWSupportedRegions | Out-String)"
<#
# Example deployment with explicit region parameters.
#Sample 1
$LAWSupportedRegions = "centralus"
$AzureLocalInstanceLocations = "southcentralus"

#Sample 2
$LAWSupportedRegions = @("centralindia")
$AzureLocalInstanceLocations = @("centralindia")
#>

$Credential = Get-Credential -Message "Enter the required credentials" -UserName $env:USERNAME
# Try each Log Analytics-compatible region that has enough capacity for the requested VM SKU.
foreach ($CurrentLAWSupportedRegion in $LAWSupportedRegions) {
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CurrentLAWSupportedRegion: $CurrentLAWSupportedRegion"
    # Check whether the region has capacity for at least one VM of the requested SKU.
    $AvailableComputeResourceSku = Get-AzAvailableComputeResourceSku -Location $CurrentLAWSupportedRegion -ComputeResourceSku $VMSize -SubscriptionId $SubscriptionId
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AvailableComputeResourceSku:`r`n$($AvailableComputeResourceSku | Out-String)"
    if ($AvailableComputeResourceSku.Available -gt 0) {
        # Retry the deployment across supported Azure Local instance regions until one succeeds.
        foreach ($CurrentAzureLocalInstanceLocation in $AzureLocalInstanceLocations) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AzureLocalInstanceLocation: $CurrentAzureLocalInstanceLocation"
            #Enabling enableAzureSpotPricing for cost optimization
            $Result = New-JumpstartLocalBox -Credential $Credential -azureLocalInstanceLocation $CurrentAzureLocalInstanceLocation -Location $CurrentLAWSupportedRegion -BicepFileDir $BicepFileDir -enableAzureSpotPricing $true -autoUpgradeClusterResource $true -vmSize $VMSize
            if ($Result.Succeeded) {
                Write-Host -Object "The Jumpstart LocalBox Deployment Succeeded !!!" -ForegroundColor Green
                break
            }
            else {
                Write-Host -Object "The Jumpstart LocalBox Deployment Failed !!!. We will automatically try other locations ..." -ForegroundColor Red
            }
        }
        
        #$Result = Get-AzResourceGroup -ResourceGroupName "rg-az-local-inc-*" | Out-GridView -OutputMode Single | Select-Object -Property ResourceGroupName, Location, @{Name="Succeeded"; Expression = {$true}}

        if ($Result.Succeeded) {
            Start-Sleep -Seconds 300
            $ScriptString = "Get-ChildItem -Path 'C:\LocalBox\Logs' -Filter *.log -File"
            $AzVMRunCommand = Invoke-AzVMRunCommand  -CommandId 'RunPowerShellScript' -ResourceGroupName $Result.ResourceGroupName -VMName LocalBox-Client -ScriptString $ScriptString
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AzVMRunCommand:`r`n$($AzVMRunCommand | Out-String)" #-Verbose
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$ResourceGroupName' ResourceGroup Deployment:`r`n$(Get-AzResourceGroupDeployment -ResourceGroupName $Result.ResourceGroupName | Select-Object  -Property DeploymentName, ProvisioningState | Out-String)"

            # Complete the cloud deployment:
            # https://jumpstart.azure.com/azure_jumpstart_localbox/cloud_deployment
            Wait-AzConnectedMachine -ResourceGroupName $Result.ResourceGroupName
            
            # Configure the LocalBox environment:
            # https://jumpstart.azure.com/azure_jumpstart_localbox/using_localbox
            Set-LocalClusterInsightSetup -ResourceGroupName $Result.ResourceGroupName

            $LogicalNetwork = New-VMLogicalNetwork -ResourceGroupName $Result.ResourceGroupName

            #region AVD
            if ($AVD) {
                New-AzLocalAVD -ResourceGroupName $Result.ResourceGroupName -AsAJob
            }
            #endregion

            #region Protect the resource group from accidental deletion
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
        Write-Warning -Message "No available Quota for '$VMSize' in the '$LAWSupportedRegion' Azure location. We will automatically try other locations ..."
    }
}

Write-Host -Object "Done ..." -ForegroundColor Green
#winget install --exact --id=Microsoft.Sysinternals.Suite --location "C:\Tools" --accept-package-agreements --accept-source-agreements
Stop-Transcript
#endregion