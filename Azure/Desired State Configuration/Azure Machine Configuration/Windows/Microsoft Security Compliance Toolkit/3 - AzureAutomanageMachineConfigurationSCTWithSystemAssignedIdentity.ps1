#To run from the Azure VM
#requires -Version 7 -RunAsAdministrator 

<#
More info on 
- https://docs.microsoft.com/en-us/azure/governance/policy/how-to/guest-configuration-create-setup
- https://techcommunity.microsoft.com/t5/microsoft-defender-for-cloud/7-steps-to-author-develop-and-deploy-custom-recommendations-for/ba-p/3166026
- https://cloudbrothers.info/en/azure-persistence-azure-policy-guest-configuration/
#>
<#
#Cleaning up previous tests
$ResourceGroupName = "rg-dsc-amc*"
Get-AzResourceGroup -Name $ResourceGroupName | Select-Object -Property @{Name="Scope"; Expression={$_.ResourceID}} | Get-AzPolicyRemediation | Remove-AzPolicyRemediation -AllowStop -AsJob -Verbose | Wait-Job
Get-AzResourceGroup -Name $ResourceGroupName | Select-Object -Property @{Name="Scope"; Expression={$_.ResourceID}} | Get-AzPolicyAssignment  | Where-Object -FilterScript { $_.Scope -match 'rg-dsc-amc' } | Remove-AzPolicyAssignment -Verbose #-Whatif
Get-AzPolicyDefinition | Where-Object -filterScript {$_.metadata.category -eq "Guest Configuration" -and $_.DisplayName -like "*$ResourceGroupName"} | Remove-AzPolicyDefinition -Verbose -Force #-WhatIf
Get-AzResourceGroup -Name $ResourceGroupName | Remove-AzResourceGroup -AsJob -Force -Verbose 
#>

[CmdletBinding(PositionalBinding = $false)]
Param(
)

#region Function defintions
#Get The Azure VM Compute Object for the VM executing this function
function Get-AzVMCompute {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"

    $uri = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

    try {
        $response = Invoke-RestMethod -Uri $uri -Headers @{"Metadata" = "true" } -Method GET -TimeoutSec 5
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] VM Compute Object:`r`n$($response.compute | Out-String)"
        return $response.compute
    }
    catch {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        return $null
    }
}


#From https://github.com/sdoubleday/GetCallerPreference/blob/master/GetCallerPreference.psm1
#From https://www.powershellgallery.com/packages/AsgGroup/2.0.6/Content/Private%5CGet-CallerPreference.ps1
function Get-CallerPreference {
    <#
        .SYNOPSIS
        Fetches "Preference" variable values from the caller's scope.
        .DESCRIPTION
        Script module functions do not automatically inherit their caller's variables, but they can be obtained
        through the $PSCmdlet variable in Advanced Functions. This function is a helper function for any script
        module Advanced Function; by passing in the values of $ExecutionContext.SessionState and $PSCmdlet,
        Get-CallerPreference will set the caller's preference variables locally.
        .PARAMETER Cmdlet
        The $PSCmdlet object from a script module Advanced Function.
        .PARAMETER SessionState
        The $ExecutionContext.SessionState object from a script module Advanced Function. This is how the
        Get-CallerPreference function sets variables in its callers' scope, even if that caller is in a different
        script module.
        .PARAMETER Name
        Optional array of parameter names to retrieve from the caller's scope. Default is to retrieve all preference
        variables as defined in the about_Preference_Variables help file (as of PowerShell 4.0). This parameter may
        also specify names of variables that are not in the about_Preference_Variables help file, and the function
        will retrieve and set those as well.
       .EXAMPLE
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        Imports the default PowerShell preference variables from the caller into the local scope.
        .EXAMPLE
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name 'ErrorActionPreference', 'SomeOtherVariable'
        Imports only the ErrorActionPreference and SomeOtherVariable variables into the local scope.
        .EXAMPLE
        'ErrorActionPreference','SomeOtherVariable' | Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        Same as Example 2, but sends variable names to the Name parameter via pipeline input.
       .INPUTS
        System.String
        .OUTPUTS
        None.
        This function does not produce pipeline output.
        .LINK
        about_Preference_Variables
    #>
    [CmdletBinding(DefaultParameterSetName = 'AllVariables')]
    param (
        [Parameter(Mandatory)]
        [ValidateScript( { $PSItem.GetType().FullName -eq 'System.Management.Automation.PSScriptCmdlet' })]
        $Cmdlet,
        [Parameter(Mandatory)][System.Management.Automation.SessionState]$SessionState,
        [Parameter(ParameterSetName = 'Filtered', ValueFromPipeline)][string[]]$Name
    )
    begin {
        $FilterHash = @{ }
    }
    
    process {
        if ($null -ne $Name) {
            foreach ($String in $Name) {
                $FilterHash[$String] = $true
            }
        }
    }
    end {
        # List of preference variables taken from the about_Preference_Variables help file in PowerShell version 4.0
        $Vars = @{
            'ErrorView'                     = $null
            'FormatEnumerationLimit'        = $null
            'LogCommandHealthEvent'         = $null
            'LogCommandLifecycleEvent'      = $null
            'LogEngineHealthEvent'          = $null
            'LogEngineLifecycleEvent'       = $null
            'LogProviderHealthEvent'        = $null
            'LogProviderLifecycleEvent'     = $null
            'MaximumAliasCount'             = $null
            'MaximumDriveCount'             = $null
            'MaximumErrorCount'             = $null
            'MaximumFunctionCount'          = $null
            'MaximumHistoryCount'           = $null
            'MaximumVariableCount'          = $null
            'OFS'                           = $null
            'OutputEncoding'                = $null
            'ProgressPreference'            = $null
            'PSDefaultParameterValues'      = $null
            'PSEmailServer'                 = $null
            'PSModuleAutoLoadingPreference' = $null
            'PSSessionApplicationName'      = $null
            'PSSessionConfigurationName'    = $null
            'PSSessionOption'               = $null
            'ErrorActionPreference'         = 'ErrorAction'
            'DebugPreference'               = 'Debug'
            'ConfirmPreference'             = 'Confirm'
            'WhatIfPreference'              = 'WhatIf'
            'VerbosePreference'             = 'Verbose'
            'WarningPreference'             = 'WarningAction'
        }
        foreach ($Entry in $Vars.GetEnumerator()) {
            if (([string]::IsNullOrEmpty($Entry.Value) -or -not $Cmdlet.MyInvocation.BoundParameters.ContainsKey($Entry.Value)) -and
                ($PSCmdlet.ParameterSetName -eq 'AllVariables' -or $FilterHash.ContainsKey($Entry.Name))) {
                $Variable = $Cmdlet.SessionState.PSVariable.Get($Entry.Key)
                
                if ($null -ne $Variable) {
                    if ($SessionState -eq $ExecutionContext.SessionState) {
                        Set-Variable -Scope 1 -Name $Variable.Name -Value $Variable.Value -Force -Confirm:$false -WhatIf:$false
                    }
                    else {
                        $SessionState.PSVariable.Set($Variable.Name, $Variable.Value)
                    }
                }
            }
        }
        if ($PSCmdlet.ParameterSetName -eq 'Filtered') {
            foreach ($VarName in $FilterHash.Keys) {
                if (-not $Vars.ContainsKey($VarName)) {
                    $Variable = $Cmdlet.SessionState.PSVariable.Get($VarName)
                
                    if ($null -ne $Variable) {
                        if ($SessionState -eq $ExecutionContext.SessionState) {
                            Set-Variable -Scope 1 -Name $Variable.Name -Value $Variable.Value -Force -Confirm:$false -WhatIf:$false
                        }
                        else {
                            $SessionState.PSVariable.Set($Variable.Name, $Variable.Value)
                        }
                    }
                }
            }
        }
    }
}

function Get-GitFile {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidatePattern("^https://api.github.com/repos/.*|^https://(www\.)?github.com/")] 
        [string]$URI,
        [Parameter(Mandatory = $false)]
        [string]$FileRegExPattern = ".*",
        [Parameter(Mandatory = $true)]
        [string]$Destination,
        [switch]$Recurse
    )   

    #Be aware of the API rate limit when unauthenticated: https://docs.github.com/en/rest/using-the-rest-api/getting-started-with-the-rest-api?apiVersion=2022-11-28#2-authenticate
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$URI: $URI"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$FileRegExPattern: $FileRegExPattern"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Destination: $Destination"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Recurse: $Recurse"

    $null = New-Item -Path $Destination -ItemType Directory -Force -ErrorAction Ignore

    #region URI transformation (in case of the end-user doesn't give an https://api.github.com/repos/... URI
    if ($URI -match "^https://(www\.)?github.com/(?<organisation>[^/]+)/(?<repository>[^/]+)/tree/master/(?<contents>.*)") {
        #https://github.com/lavanack/laurentvanacker.com/tree/master/Azure/Azure%20Virtual%20Desktop/MSIX
        #https://api.github.com/repos/lavanack/laurentvanacker.com/contents/Azure/Azure%20Virtual%20Desktop/MSIX/MSIX
        $Organisation = $Matches["organisation"]
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Organisation: $Organisation"
        $Repository = $Matches["repository"]
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Repository: $Repository"
        $Contents = $Matches["contents"]
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Contents: $Contents"
        $GitHubURI = "https://api.github.com/repos/$Organisation/$Repository/contents/$Contents"
    }
    else {
        $GitHubURI = $URI
    }
    #endregion
    #region Getting all request files
    $Response = Invoke-WebRequest -Uri $GitHubURI -UseBasicParsing
    $Objects = $Response.Content | ConvertFrom-Json
    [array] $Files = ($Objects | Where-Object -FilterScript { $_.type -eq "file" } | Select-Object -ExpandProperty html_url) -replace "/blob/", "/raw/"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Files:`r`n$($Files | Format-List -Property * | Out-String)"
    if ($Recurse) {
        $Directories = $Objects | Where-Object -FilterScript { $_.type -eq "dir" } | Select-Object -Property url, name
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Directories:`r`n$($Directories | Format-List -Property * | Out-String)"
        foreach ($CurrentDirectory in $Directories) {
            $CurrentDestination = Join-Path -Path $Destination -ChildPath $CurrentDirectory.name
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CurrentDestination: $CurrentDestination"
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `URI: $($CurrentDirectory.url)"
            Get-GitFile -URI $CurrentDirectory.url -FileRegExPattern $FileRegExPattern -Destination $CurrentDestination -Recurse
        }
    }
    $FileURIs = $Files -match $FileRegExPattern
    $GitFile = $null
    if ($FileURIs) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$FileURIs: $($FileURIs -join ', ')"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Destination: $($(@($Destination) * $($FileURIs.Count)) -join ', ')"
        Start-BitsTransfer -Source $FileURIs -Destination $(@($Destination) * $($FileURIs.Count))
        #Getting the url-decoded local file path 
        $GitFile = $FileURIs | ForEach-Object -Process { 
            $FileName = $_ -replace ".*/"
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$FileName: $FileName"
            $DecodedFileName = [System.Web.HttpUtility]::UrlDecode($FileName)
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$DecodedFileName: $DecodedFileName"
            if ($FileName -ne $DecodedFileName) {
                Remove-Item -Path $(Join-Path -Path $Destination -ChildPath $DecodedFileName) -ErrorAction Ignore
                Rename-Item -Path $(Join-Path -Path $Destination -ChildPath $FileName) -NewName $DecodedFileName -PassThru -Force 
            }
            else {
                Get-Item -Path $(Join-Path -Path $Destination -ChildPath $FileName)
            }
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$GitFile: $($GitFile -join ', ')"
    }
    else {
        Write-Warning -Message "No files to copy from '$GitHubURI'..."
    }
    #endregion

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $GitFile
}

function Get-SCTDSCConfiguration {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
    )   

    $Destination = Join-Path -Path $env:TEMP -ChildPath $([System.IO.Path]::GetRandomFileName())
    $URI = "https://api.github.com/repos/lavanack/laurentvanacker.com/contents/Windows%20Powershell/Windows/Security/Convert-FromSecurityComplianceToolkit"
    $ZipFiles = Get-GitFile -URI $URI -FileRegExPattern "\.zip?$" -Destination $Destination -Verbose
    $ZipFile = $ZipFiles | Sort-Object -Property Name -Descending | Select-Object -First 1

    $DSCConfigurations = (tar -C $Destination -zxvf $ZipFile  *.ps1 *>&1 | Where-Object -FilterScript { $_ -match "DSCConfigurations.*\.ps1$" }) -replace "^\S*\s*(.*)$", "$Destination\`$1" -replace "/", "\"
    $DSCConfigurationCategories = $DSCConfigurations -replace "(.*)\\(.*)\\(.*)\\(.*)\.*$", '$2' | Select-Object -Unique
    Do {
        $DSCConfigurationCategory = $DSCConfigurationCategories | Sort-Object | Out-GridView -Title "Microsoft Security Compliance Toolkit baselines" -OutputMode Single
    } While (-not($DSCConfigurationCategory))

    Do {
        $DSCConfigurationScriptFileNames = ($DSCConfigurations -match $DSCConfigurationCategory) -replace "(.*)\\(.*)\\(.*)$", '$3' | Sort-Object | Out-GridView -Title "GPOs" -OutputMode Multiple
    } While (-not($DSCConfigurationScriptFileNames))

    $SelectedDSCConfigurationScripts = foreach($CurrentDSCConfigurationScriptFileName in $DSCConfigurationScriptFileNames) {
        $DSCConfigurations -match "$DSCConfigurationCategory.*$CurrentDSCConfigurationScriptFileName"
    }

    $SelectedDSCConfigurationScripts
    #Remove-Item -Path $Destination -Force -Recurse -ErrorAction Ignore 
}
#endregion

Clear-Host
#$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
#$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $PSScriptRoot

$AzVM = Get-AzVMCompute
#From https://learn.microsoft.com/en-us/azure/governance/machine-configuration/how-to/create-policy-definition#create-an-azure-policy-definition
$Location = $AzVM.Location
$ResourceGroupName = $AzVM.ResourceGroupName
$StorageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName
$StorageAccountName = $StorageAccount.StorageAccountName
$StorageGuestConfigurationContainerName = "guestconfiguration"
#Adding a 7-day expiration time from now for the SAS Token
$StartTime = Get-Date
$ExpiryTime = $StartTime.AddDays(7)

#$GuestConfigurationPackageName = "$ConfigurationName.zip"
#$GuestConfigurationPackageFullName  = "$PSScriptRoot\$ConfigurationName\$GuestConfigurationPackageName"

#region From PowerShell
#region Deploy prerequisites to enable Guest Configuration policies on virtual machines

$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName
$PolicySetDefinition = Get-AzPolicySetDefinition | Where-Object -FilterScript { $_.DisplayName -eq "Deploy prerequisites to enable Guest Configuration policies on virtual machines" }
$PolicyAssignment = Get-AzPolicyAssignment -Name "$($ResourceGroupName)-deployPrereqForGuestConfigurationPolicies" -Scope $ResourceGroup.ResourceId -ErrorAction Ignore
if (-not($PolicyAssignment)) {
    $PolicyAssignment = New-AzPolicyAssignment -Name "$($ResourceGroupName)-deployPrereqForGuestConfigurationPolicies" -DisplayName "[$ResourceGroupName] Deploy prerequisites to enable Guest Configuration policies on virtual machines" -Scope $ResourceGroup.ResourceId -PolicySetDefinition $PolicySetDefinition -EnforcementMode Default -IdentityType SystemAssigned -Location $Location
    $PolicyState = $null
} 
else {
    Write-Host -Object  "'$($PolicyAssignment.DisplayName)' Policy is already assigned to the '$ResourceGroupName' Resource Group"
    $PolicyState = Get-AzPolicyState -ResourceGroupName $ResourceGroupName -PolicyAssignmentName $PolicyAssignment.Name #-Filter 'IsCompliant eq false'
}

# Grant permissions to the managed identity through defined roles
# From https://learn.microsoft.com/en-us/azure/governance/policy/how-to/remediate-resources?tabs=azure-powershell#grant-permissions-to-the-managed-identity-through-defined-roles
#######################################################
# Grant roles to managed identity at initiative scope #
#######################################################
if (($null -eq $PolicyState) -or (($PolicyState.ComplianceState | Select-Object -Unique) -ne "Compliant")) {
    $roleDefinitionIds = $PolicySetDefinition.PolicyDefinition | ForEach-Object -Process { Get-AzPolicyDefinition -Id $_.policyDefinitionId | Select-Object @{Name = "roleDefinitionIds"; Expression = { $_.policyRule.then.details.roleDefinitionIds } } } | Select-Object -ExpandProperty roleDefinitionIds -Unique
    Start-Sleep -Seconds 30
    if ($roleDefinitionIds.Count -gt 0) {
        $roleDefinitionIds | ForEach-Object {
            $roleDefId = $_.Split("/") | Select-Object -Last 1
            if (-not(Get-AzRoleAssignment -Scope $ResourceGroup.ResourceId -ObjectId $PolicyAssignment.IdentityPrincipalId -RoleDefinitionId $roleDefId)) {
                New-AzRoleAssignment -Scope $ResourceGroup.ResourceId -ObjectId $PolicyAssignment.IdentityPrincipalId -RoleDefinitionId $roleDefId
            }
        }
    }

    # Start remediation for every policy definition
    $PolicyRemediationJobs = $PolicySetDefinition.PolicyDefinition | ForEach-Object -Process {
        Write-Host -Object "Creating remediation for '$($_.policyDefinitionReferenceId)' Policy ..."
        Start-AzPolicyRemediation -PolicyAssignmentId $PolicyAssignment.Id -PolicyDefinitionReferenceId $_.policyDefinitionReferenceId -Name $_.policyDefinitionReferenceId -ResourceGroupName $ResourceGroup.ResourceGroupName -ResourceDiscoveryMode ReEvaluateCompliance -AsJob
    }
    $remediation = $PolicyRemediationJobs | Receive-Job -Wait -AutoRemoveJob
    $remediation
}
else {
    Write-Host -Object  "All resources in '$ResourceGroupName' Resource Group are already compliant with '$($PolicyAssignment.DisplayName)' Policy"
}
#endregion

#region Public Network Access and Shared Key Access Enabled on the Storage Account
$storageAccount | Set-AzStorageAccount -PublicNetworkAccess Enabled -AllowBlobPublicAccess $false -AllowSharedKeyAccess $false
Start-Sleep -Seconds 30
$Context = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount
#endregion

#region Removing existing blob
$storageAccount | Get-AzStorageContainer | Get-AzStorageBlob | Remove-AzStorageBlob
#endregion

#region Assigning the 'Storage Blob Data Reader' RBAC Role to the Azure VM System Assigned Identity to the Storage Account 
#From https://learn.microsoft.com/en-us/azure/governance/machine-configuration/how-to/create-policy-definition#create-an-azure-policy-definition
$AZVMSystemAssignedIdentity = ($AzVM | Get-AzVM).Identity   
$RoleDefinition = Get-AzRoleDefinition -Name "Storage Blob Data Reader"
$Parameters = @{
    ObjectId           = $AZVMSystemAssignedIdentity.PrincipalId
    RoleDefinitionName = $RoleDefinition.Name
    Scope              = $StorageAccount.Id
}

While (-not(Get-AzRoleAssignment @Parameters)) {
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.ObjectId)' Identity on the '$($Parameters.Scope)' scope"
    $RoleAssignment = New-AzRoleAssignment @Parameters -ErrorAction Ignore
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
    Start-Sleep -Seconds 30
}
#endregion


#region Our Guest Policies
$SCTDSCConfiguration = Get-SCTDSCConfiguration -Verbose
$DSCConfigurations = Get-ChildItem -Path $SCTDSCConfiguration -File

$PolicyRemediationJobs = @()
foreach ($CurrentDSCConfiguration in $DSCConfigurations) {
    $CurrentConfigurationName = $CurrentDSCConfiguration.BaseName
    #Note : The name of the filename has to match the DSC configuration Name for an easier code maintenance: CreateAdminUserDSCConfiguration ==> CreateAdminUserDSCConfiguration.ps1, IISSetupDSCConfiguration ==> IISSetupDSCConfiguration.ps1. Else use the RegEx below
    <#
    $Result = Select-String -Path $CurrentDSCConfiguration.FullName -Pattern "^\s?Configuration\s(?<DSConfigurationName>[^{]*)"
    $CurrentConfigurationName = ($Result.Matches.Groups.Captures | Where-Object -FilterScript {$_.Name -eq "DSCConfigurationName"}).Value
    #>
    Write-Host -Object "Processing '$CurrentConfigurationName' DSCConfiguration"
    (Get-Content -Path  $CurrentDSCConfiguration -Raw) -replace "(-OutputPath)", '#$1' | Set-Content -Path $CurrentDSCConfiguration
    & $CurrentDSCConfiguration

    # Create a guest configuration package for Azure Policy GCS
    $GuestConfigurationPackage = New-GuestConfigurationPackage -Name $CurrentConfigurationName -Configuration "./$CurrentConfigurationName/localhost.mof" -Type AuditAndSet -Force
    # Validating the configuration package meets requirements: https://learn.microsoft.com/en-us/azure/governance/machine-configuration/how-to/develop-custom-package/3-test-package#validate-the-configuration-package-meets-requirements
    Get-GuestConfigurationPackageComplianceStatus -Path $GuestConfigurationPackage.Path -Verbose
    #Set-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -AllowBlobPublicAccess $true
    # Applying the Machine Configuration Package locally
    #Start-GuestConfigurationPackageRemediation -Path $GuestConfigurationPackage.Path -Verbose
    $GuestConfigurationPackageName = Split-Path -Path $GuestConfigurationPackage.Path -Leaf

    # Creates a new guest configuration container
    if (-not($storageAccount | Get-AzStorageContainer -Name $StorageGuestConfigurationContainerName -ErrorAction Ignore)) {
        New-AzStorageContainer -Name $StorageGuestConfigurationContainerName -Context $Context #-Permission Blob
    }


    $GuestConfigurationStorageBlob = Set-AzStorageBlobContent -Container $StorageGuestConfigurationContainerName -File $GuestConfigurationPackage.Path -Blob $GuestConfigurationPackageName -Context $Context -Force
    #$GuestConfigurationStorageBlobSASToken = New-AzStorageBlobSASToken -Context $Context -FullUri -Container $StorageGuestConfigurationContainerName -Blob $GuestConfigurationPackageName -Permission rwd -StartTime $StartTime -ExpiryTime $ExpiryTime      
    
    # Create a Policy Id
    $PolicyId = (New-Guid).Guid  
    # Define the parameters to create and publish the guest configuration policy
    $DisplayName = "[Windows] $ResourceGroupName - Make sure all Windows servers comply with $CurrentConfigurationName DSC Config."
    #Display Name is limited to 128 characters 
    $DisplayName = $DisplayName.Substring(0, [math]::min(128, $DisplayName.Length))
    $Params = @{
        "PolicyId"                  = $PolicyId
        "ContentUri"                = $GuestConfigurationStorageBlob.ICloudBlob.Uri.AbsoluteUri
        "DisplayName"               = $DisplayName
        "Description"               = $DisplayName
        "Path"                      = './policies'
        "Platform"                  = 'Windows'
        "PolicyVersion"             = '1.0.0'
        "Mode"                      = 'ApplyAndAutoCorrect'
        #From https://github.com/Azure/GuestConfiguration/blob/main/source/Public/New-GuestConfigurationPolicy.ps1#L55-L59
        "LocalContentPath"          = $GuestConfigurationPackage.Path
        "UseSystemAssignedIdentity" = $true
        "Verbose"                   = $true
    }
    # Create the guest configuration policy
    #From https://learn.microsoft.com/en-us/azure/governance/machine-configuration/how-to/create-policy-definition#create-an-azure-policy-definition
    $Policy = New-GuestConfigurationPolicy @Params
    $PolicyDefinitionName = "[Win]$ResourceGroupName-$CurrentConfigurationName"
    $PolicyDefinitionName = $PolicyDefinitionName.Substring(0,  [math]::min(64,$PolicyDefinitionName.length))
    $PolicyDefinition = New-AzPolicyDefinition -Name $PolicyDefinitionName -Policy $Policy.Path

    $NonComplianceMessage = [Microsoft.Azure.Commands.ResourceManager.Cmdlets.Entities.Policy.NonComplianceMessage]::new()
    $NonComplianceMessage.message = "Non Compliance Message"
    $IncludeArcConnectedServers = @{'IncludeArcMachines' = 'true' }# <- IncludeArcMachines is important - given you want to target Arc as well as Azure VMs

    $PolicyAssignment = New-AzPolicyAssignment -Name "$($ResourceGroupName)-$($CurrentConfigurationName)" -DisplayName $DisplayName  -Scope $ResourceGroup.ResourceId -PolicyDefinition $PolicyDefinition -EnforcementMode Default -IdentityType SystemAssigned -Location $Location -PolicyParameterObject $IncludeArcConnectedServers -NonComplianceMessage $NonComplianceMessage  

    # Grant permissions to the managed identity through defined roles
    # https://learn.microsoft.com/en-us/azure/governance/policy/how-to/remediate-resources?tabs=azure-powershell#grant-permissions-to-the-managed-identity-through-defined-roles
    ###################################################
    # Grant roles to managed identity at policy scope #
    ###################################################
    $roleDefinitionIds = $PolicyDefinition.policyRule.then.details.roleDefinitionIds
    Start-Sleep -Seconds 30
    if ($roleDefinitionIds.Count -gt 0) {
        $roleDefinitionIds | ForEach-Object {
            $roleDefId = $_.Split("/") | Select-Object -Last 1
            if (-not(Get-AzRoleAssignment -Scope $ResourceGroup.ResourceId -ObjectId $PolicyAssignment.IdentityPrincipalId -RoleDefinitionId $roleDefId)) {
                New-AzRoleAssignment -Scope $ResourceGroup.ResourceId -ObjectId $PolicyAssignment.IdentityPrincipalId -RoleDefinitionId $roleDefId
            }
        }
    }

    Write-Host -Object "Creating remediation for '$($PolicyDefinition.DisplayName)' Policy (As Job) ..."
    $PolicyRemediationJobs += Start-AzPolicyRemediation -Name $PolicyAssignment.Name -PolicyAssignmentId $PolicyAssignment.Id -ResourceGroupName $ResourceGroup.ResourceGroupName -ResourceDiscoveryMode ReEvaluateCompliance -AsJob

}
Write-Host -Object "Waiting Policy Remediations complete ..."
$PolicyRemediations = $PolicyRemediationJobs | Receive-Job -Wait -AutoRemoveJob
$PolicyRemediations

#endregion

#region Resource Group Status
# Get the resources in your resource group that are non-compliant to the policy assignments
$PolicyAssignments = Get-AzPolicyAssignment -Scope $ResourceGroup.ResourceId | Where-Object -FilterScript { $_.Name -match $(($DSCConfigurations).BaseName -join "|") }
$PolicyAssignments | ForEach-Object -Process {
    Get-AzPolicyState -ResourceGroupName $ResourceGroupName -PolicyAssignmentName $_.Name | Select-Object -Property PolicyDefinitionName, ComplianceState
}

#If you want to force an update on the compliance result you can use the following cmdlet instead of waiting for the next trigger : https://docs.microsoft.com/en-us/azure/governance/policy/how-to/get-compliance-data#evaluation-triggers.
Write-Host -Object "Starting Compliance Scan for '$ResourceGroupName' Resource Group ..."
$PolicyComplianceScanJob = Start-AzPolicyComplianceScan -ResourceGroupName $ResourceGroupName -Verbose -AsJob

#Get latest non-compliant policy states summary in resource group scope
Get-AzPolicyStateSummary -ResourceGroupName $ResourceGroupName | Select-Object -ExpandProperty PolicyAssignments

$PolicyComplianceScanJob | Receive-Job -Wait -AutoRemoveJob
#endregion
#endregion