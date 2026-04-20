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
#requires -Version 5 -Modules Az.Accounts, Az.Functions, Az.Resources, Az.Storage -RunAsAdministrator 

#region function definitions 
function Test-FunctionAppNameAvailability {
    [CmdletBinding(PositionalBinding = $false)]
    [OutputType([Boolean])]
    Param(
        [Parameter(Mandatory = $true)]
        [Alias('Name')]
        [string]$FunctionAppName
    )

    #region Azure Context
    # Log in first with Connect-AzAccount if not using Cloud Shell
    $AzContext = Get-AzContext
    $SubcriptionID = $AzContext.Subscription.Id
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
    $token = $profileClient.AcquireAccessToken($AzContext.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'  = 'application/json'
        'Authorization' = 'Bearer ' + $token.AccessToken
    }
    #endregion
    $Body = [ordered]@{ 
        "name" = $FunctionAppName
        "type" = "Microsoft.Web/sites"
    }

    $URI = "https://management.azure.com/subscriptions/$SubcriptionID/providers/Microsoft.Web/checknameavailability?api-version=2024-04-01"
    try {
        # Invoke the REST API
        #$Response = Invoke-RestMethod -Method POST -Headers $authHeader -Body $($Body | ConvertTo-Json -Depth 100) -ContentType "application/json" -Uri $URI -ErrorVariable ResponseError
        $Response = Invoke-AzRestMethod -Method POST -Payload $($Body | ConvertTo-Json -Depth 100) -Uri $URI -ErrorVariable ResponseError
        return ($Response.Content | ConvertFrom-Json).NameAvailable

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
}

function New-PsAvdStopInactiveSessionHostAzFunction {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $false)]
        [uint16] $FrequencyInMinutes = 15,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Personal', 'Pooled')]
        [string[]] $HostPoolType = @('Personal', 'Pooled'),
        [Parameter(Mandatory = $false)]
        [string[]] $HostPoolName,
        [Parameter(Mandatory = $false)]
        [string] $Location = "eastus2",
        [switch] $PassThru,
        [switch] $Force
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"

    $RuntimeVersion = "7.4"
    $StorageAccountSkuName = "Standard_LRS"
    $DigitNumber = 3
    Set-Location -Path $env:TEMP
    $SubscriptionId = $((Get-AzContext).Subscription.Id)
	$Tags = @{
		"SecurityControl" = "Ignore"
	}

    #region Prerequisites
    #region Azure Functions Core Tools
    if ($null -eq $(Get-WmiObject -Class Win32Reg_AddRemovePrograms -Filter "DisplayName LIKE 'Azure Functions Core Tools%'")) {
        $AzureFunctionsCoreToolsURI = "https://go.microsoft.com/fwlink/?linkid=2174087"
        $OutFile = Join-Path -Path $env:TEMP -ChildPath "func-cli-x64.msi"
        Start-BitsTransfer -Source $AzureFunctionsCoreToolsURI -Destination $OutFile -DisplayName $AzureFunctionsCoreToolsURI
        Start-Process -FilePath "$env:comspec" -ArgumentList "/c", """$OutFile"" /qn"
    }
    else {
        Write-Warning "Azure Functions Core Tools is already installed"
    }
    #endregion

    #region Installing/Updating Powershell 7+ : Silent Install
    $PowerShellVersion = [version]::Parse($(pwsh -v) -replace "[^\d|\.]")
    if ($PowerShellVersion -lt [version]::Parse($RuntimeVersion)) {
        Invoke-Expression -Command "& { $(Invoke-RestMethod https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"
        $PowerShellVersion = [version]::Parse($(pwsh -v) -replace "[^\d|\.]")
    }
    #endregion 

    #region Latest DotNet SDK
    $LatestDotNetCoreSDKURIPath = (Invoke-WebRequest https://dotnet.microsoft.com/en-us/download -UseBasicParsing).links.href | Where-Object -FilterScript { $_ -match "sdk.*windows.*-x64" } | Sort-Object -Descending | Select-Object -First 1
    $Version = [regex]::Match($LatestDotNetCoreSDKURIPath, "sdk-(?<Version>\d+\.\d+)").Groups["Version"].Value
    if ($null -eq $(Get-WmiObject -Class Win32Reg_AddRemovePrograms -Filter "DisplayName LIKE '%sdk%$Version%'")) {
        #region Downloading
        $LatestDotNetCoreSDKURI = "https://dotnet.microsoft.com$($LatestDotNetCoreSDKURIPath)"
        $LatestDotNetCoreSDKSetupURI = (Invoke-WebRequest $LatestDotNetCoreSDKURI -UseBasicParsing).links.href | Where-Object -FilterScript { $_ -match "sdk.*win.*-x64" } | Select-Object -Unique
        $LatestDotNetCoreSDKSetupFileName = Split-Path -Path $LatestDotNetCoreSDKSetupURI -Leaf
        $LatestDotNetCoreSDKSetupFilePath = Join-Path -Path $env:TEMP -ChildPath $LatestDotNetCoreSDKSetupFileName 
        Start-BitsTransfer -Source $LatestDotNetCoreSDKSetupURI -Destination $LatestDotNetCoreSDKSetupFilePath
        Write-Host -Object "Latest DotNet Core SDK is available at '$LatestDotNetCoreSDKSetupFilePath'"
        #endregion

        #region Installing
        Start-Process -FilePath "$env:comspec" -ArgumentList "/c", """$LatestDotNetCoreSDKSetupFilePath"" /install /passive /norestart" -Wait
        #endregion
    }
    else {
        Write-Warning ".Net SDK $Version is already installed"
    }
    #endregion

    #endregion

    #region Azure Resource Creation if needed
    #region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
    $AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
    $ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
    $AzureLocationShortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
    #endregion

    $ResourceGroupNamePattern = "rg-avd-func-poc-{0}" -f $AzureLocationShortNameHT[$Location].shortName
    $AzureFunctionNamePattern = "func-avd-func-poc-{0}" -f $AzureLocationShortNameHT[$Location].shortName                
    $StorageAccountNamePattern = "saavdfuncpoc{0}" -f $AzureLocationShortNameHT[$Location].shortName

    Do {
        $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
        $StorageAccountName = "$StorageAccountNamePattern{0:D$DigitNumber}" -f $Instance
        $AzureFunctionName = "$AzureFunctionNamePattern-{0:D$DigitNumber}" -f $Instance
    } While ((-not(Get-AzStorageAccountNameAvailability -Name $StorageAccountName).NameAvailable) -or (-not(Test-FunctionAppNameAvailability -FunctionAppName $AzureFunctionName)))
    $ResourceGroupName = "$ResourceGroupNamePattern-{0:D$DigitNumber}" -f $Instance

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Instance: $Instance"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$StorageAccountName: $StorageAccountName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AzureFunctionName: $AzureFunctionName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ResourceGroupName: $ResourceGroupName"

    $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
    if ($null -eq $ResourceGroup) {
        $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Tag $Tags -Force
    }
    #Create Azure Storage Account
    $StorageAccount = New-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -Location $Location -SkuName $StorageAccountSkuName -MinimumTlsVersion TLS1_2 -EnableHttpsTrafficOnly $true

    #region Create Azure Function
    #$RuntimeVersion = "{0}.{1}" -f $PowerShellVersion.Major, $PowerShellVersion.Minor
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the '$AzureFunctionName' Azure Function"
    #Buggy command
    #$FunctionApp = New-AzFunctionApp -Name $AzureFunctionName -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -Runtime 'PowerShell' -RuntimeVersion $RuntimeVersion -OSType 'Linux' -Location $Location -IdentityType SystemAssigned -ErrorAction Ignore

    #region az cli alternative to the bug
    # Create the Function App (Consumption on Linux)
    az functionapp create --name "$AzureFunctionName" --resource-group "$ResourceGroupName" --storage-account "$StorageAccountName" --consumption-plan-location "$Location" --runtime powershell --runtime-version "$RuntimeVersion" --functions-version 4 --os-type Linux  --only-show-errors

    # Assign System-Assigned Managed Identity (equivalent of -IdentityType SystemAssigned)
    az functionapp identity assign --name "$AzureFunctionName" --resource-group "$ResourceGroupName"
    $PSDefaultParameterValues = @{
        'Invoke-WebRequest:UseBasicParsing' = $true
    }
    $FunctionApp = Get-AzFunctionApp | Where-Object -FilterScript { $_.Name -match "^$AzureFunctionNamePattern"} | Select-Object -First 1
    $PSDefaultParameterValues = @{
        'Invoke-WebRequest:UseBasicParsing' = $false
    }
    #endregion

    #region Creating the Function Locally
    $AzureFunctionsCoreToolsDirectory = "$env:ProgramFiles\Microsoft\Azure Functions Core Tools\"
    $Func = Join-Path -Path $AzureFunctionsCoreToolsDirectory -ChildPath "func"
    #$FunctionName = (Get-Item -Path $CurrentScript).BaseName
    $FunctionName = $MyInvocation.MyCommand
    $null = Remove-Item -Path $FunctionName -Recurse -ErrorAction Ignore -Force
    #Start-Process -FilePath "$env:comspec" -ArgumentList "/c", """$env:ProgramFiles\Microsoft\Azure Functions Core Tools\func"" init $FunctionName --powershell" -WorkingDirectory $env:TEMP
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c", """$Func"" init $FunctionName --powershell"

    #region Local code
    $Directory = New-Item -Path $FunctionName\$FunctionName -ItemType Directory -Force
    #From https://faultbucket.ca/2019/08/use-azure-function-to-start-vms/
    if ([string]::IsNullOrEmpty($HostPoolName)) {
        $ScriptContent = @'
# Input bindings are passed in via param block.
param($Timer)

# The 'IsPastDue' property is 'true' when the current function invocation is later than scheduled.
if ($Timer.IsPastDue) {
    Write-Host "PowerShell timer is running late!"
}

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Write-Host -Object "PowerShell timer trigger function executed at: $timestamp"

$AzInactiveRunningVMs = Get-AzWvdHostPool | Where-Object -FilterScript { $_.HostPoolType -in <HostPoolType> } | ForEach-Object -Process {
    (Get-AzWvdSessionHost -HostPoolName $_.Name -ResourceGroupName $_.ResourceGroupName) | Where-Object -FilterScript { $_.Session -le 0 } | Select-Object -Property ResourceId | Get-AzVM -Status | Where-Object -FilterScript { ($_.Statuses.code -eq "PowerState/running") -and ($_.Statuses.DisplayStatus -eq "VM running") }
}


if ($null -ne $AzInactiveRunningVMs) {
    Write-Host -Object "The following VMs will be hibernated :`r`n$($AzInactiveRunningVMs | Select-Object -Property ResourceGroupName, Name | Out-String)"
    $Jobs = $AzInactiveRunningVMs | Stop-AzVM -Hibernate -Force -AsJob -Verbose
    Write-Host -Object "Waiting the hibernation jobs complete ..."
    $null = $Jobs | Receive-Job -Wait -AutoRemoveJob -ErrorAction SilentlyContinue

    $AzInactiveRunningVMs = Get-AzWvdHostPool | Where-Object -FilterScript { $_.HostPoolType -in <HostPoolType> } | ForEach-Object -Process {
        (Get-AzWvdSessionHost -HostPoolName $_.Name -ResourceGroupName $_.ResourceGroupName) | Where-Object -FilterScript { $_.Session -le 0 } | Select-Object -Property ResourceId | Get-AzVM -Status | Where-Object -FilterScript { ($_.Statuses.code -eq "PowerState/running") -and ($_.Statuses.DisplayStatus -eq "VM running") }
    }
    if (-not([string]::IsNullOrEmpty($AzInactiveRunningVMs))) {
        Write-Warning -Message "The following VMs will be shutdown (hibernation failed) :`r`n$($AzInactiveRunningVMs | Select-Object -Property ResourceGroupName, Name | Out-String)"
        $Jobs = $AzInactiveRunningVMs | Stop-AzVM -Force -AsJob -Verbose
        Write-Host -Object "Waiting the shutdown jobs complete ..."
        $null = $Jobs | Receive-Job -Wait -AutoRemoveJob #-ErrorAction SilentlyContinue
    }
}
'@ -replace "<HostPoolType>", $("'{0}'" -f $($HostPoolType -join "', '"))
    }
    else {
        #Adding an AppSetting for filtering on some HostPool names
        $AppSetting = @{
            HostPoolName = $HostPoolName -join ','
        }

        Update-AzFunctionAppSetting -Name $AzureFunctionName -ResourceGroupName $ResourceGroupName -AppSetting $AppSetting

        $ScriptContent = @'
# Input bindings are passed in via param block.
param($Timer)

# The 'IsPastDue' property is 'true' when the current function invocation is later than scheduled.
if ($Timer.IsPastDue) {
    Write-Host "PowerShell timer is running late!"
}

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Write-Host -Object "PowerShell timer trigger function executed at: $timestamp"

Write-Host -Object "`$env:HostPoolName: $($env:HostPoolName)"
$HostPoolName = $env:HostPoolName -split ','
$AzInactiveRunningVMs = Get-AzWvdHostPool | Where-Object -FilterScript { ($_.HostPoolType -in <HostPoolType>) -and ($_.Name -in $HostPoolName) } | ForEach-Object -Process {
    (Get-AzWvdSessionHost -HostPoolName $_.Name -ResourceGroupName $_.ResourceGroupName) | Where-Object -FilterScript { $_.Session -le 0 } | Select-Object -Property ResourceId | Get-AzVM -Status | Where-Object -FilterScript { ($_.Statuses.code -eq "PowerState/running") -and ($_.Statuses.DisplayStatus -eq "VM running") }
}


if ($null -ne $AzInactiveRunningVMs) {
    Write-Host -Object "The following VMs will be hibernated :`r`n$($AzInactiveRunningVMs | Select-Object -Property ResourceGroupName, Name | Out-String)"
    $Jobs = $AzInactiveRunningVMs | Stop-AzVM -Hibernate -Force -AsJob -Verbose
    Write-Host -Object "Waiting the hibernation jobs complete ..."
    $null = $Jobs | Receive-Job -Wait -AutoRemoveJob -ErrorAction SilentlyContinue

    $AzInactiveRunningVMs = Get-AzWvdHostPool | Where-Object -FilterScript { ($_.HostPoolType -in <HostPoolType>) -and ($_.Name -in $HostPoolName) } | ForEach-Object -Process {
        (Get-AzWvdSessionHost -HostPoolName $_.Name -ResourceGroupName $_.ResourceGroupName) | Where-Object -FilterScript { $_.Session -le 0 } | Select-Object -Property ResourceId | Get-AzVM -Status | Where-Object -FilterScript { ($_.Statuses.code -eq "PowerState/running") -and ($_.Statuses.DisplayStatus -eq "VM running") }
    }
    if (-not([string]::IsNullOrEmpty($AzInactiveRunningVMs))) {
        Write-Warning -Message "The following VMs will be shutdown (hibernation failed) :`r`n$($AzInactiveRunningVMs | Select-Object -Property ResourceGroupName, Name | Out-String)"
        $Jobs = $AzInactiveRunningVMs | Stop-AzVM -Force -AsJob -Verbose
        Write-Host -Object "Waiting the shutdown jobs complete ..."
        $null = $Jobs | Receive-Job -Wait -AutoRemoveJob #-ErrorAction SilentlyContinue
    }
}
'@ -replace "<HostPoolType>", $("'{0}'" -f $($HostPoolType -join "', '"))
    }

    $FunctionJSONContent = @"
    {
        "bindings": [
        {
            "name": "Timer",
            "type": "timerTrigger",
            "direction": "in",
            "schedule": "0 */$FrequencyInMinutes * * * *"
        }
        ],
        "scriptFile": "run.ps1"
    }
"@

    $null = New-Item -Path $(Join-Path -Path $Directory -ChildPath "run.ps1") -Value $ScriptContent -Force
    $null = New-Item -Path $(Join-Path -Path $Directory -ChildPath "function.json") -Value $FunctionJSONContent -Force
    $Modules = New-Item -Path $(Join-Path -Path $Directory -ChildPath "..\Modules") -ItemType Directory -Force
    Find-Module -Name Az.Accounts, Az.Compute, Az.DesktopVirtualization | Save-Module -Path $Modules

    #region Requiring Az PowerShell modules
    Set-Location -Path $FunctionName
    While (-not(Test-Path -Path requirements.psd1)) {
        Start-Sleep -Seconds 10
    }

    #(Get-Content -Path requirements.psd1) -replace "# 'Az'", "'Az'" | Set-Content -Path requirements.psd1 
    #Increasing Timeout from 5 to 10 minutes
    Get-Content -Path host.json | ConvertFrom-Json | Add-Member -Name "functionTimeout" -Value "00:10:00" -MemberType NoteProperty -PassThru -Force | ConvertTo-Json | Set-Content -Path host.json
    #endregion


    <#
    $FuncProcess = Start-Process -FilePath """$Func""" -ArgumentList "start", "--verbose" -PassThru

    #Waiting some seconds the process be available
    Do {
        Start-Sleep -Second 30
    } While (-not(Get-NetTCPConnection -LocalPort 7071 -ErrorAction Ignore))
    #>

    #endregion
    #endregion

    #region Publishing the Azure Function
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c", """$Func"" azure functionapp publish $($FunctionApp.Name) --powershell" -Wait
    # Enable Logs
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c", """$Func"" azure functionapp logstream $($FunctionApp.Name) --browser" -Wait
    #endregion

    #endregion
    #endregion

    #region RBAC Assignment
    # Log in first with Connect-AzAccount if not using Cloud Shell
    $AzContext = Get-AzContext
    $SubcriptionID = $AzContext.Subscription.Id

    #region 'Virtual Machine Contributor' RBAC Assignment
    $RoleDefinition = Get-AzRoleDefinition "Virtual Machine Contributor"
    $objId = $FunctionApp.IdentityPrincipalId
    $SubscriptionId = $AzContext.Subscription.Id
    $Scope = "/subscriptions/$SubscriptionId"

    $Parameters = @{
        ObjectId           = $objId
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

    #region 'Desktop Virtualization Reader' RBAC Assignment
    $RoleDefinition = Get-AzRoleDefinition "Desktop Virtualization Reader"
    $objId = $FunctionApp.IdentityPrincipalId
    $SubscriptionId = $AzContext.Subscription.Id
    $Scope = "/subscriptions/$SubscriptionId"

    $Parameters = @{
        ObjectId           = $objId
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

    <#
    #region Adding CORS for testing from the Azure Portal (Not directly possible via PowerShell)
    #region Powershell Way
    az functionapp cors add -g $FunctionApp.ResourceGroupName -n $FunctionApp.Name --allowed-origins https://portal.azure.com
    #endregion
    #>
    if ($PassThru) {
        return $FunctionApp
    }
}
#endregion

#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

#New-PsAvdStopInactiveSessionHostAzFunction -Location eastus2 -Verbose
New-PsAvdStopInactiveSessionHostAzFunction -Location eastus2 -FrequencyInMinutes 5 -HostPoolName $((Get-AzWvdHostPool).Name) -Verbose
#endregion

