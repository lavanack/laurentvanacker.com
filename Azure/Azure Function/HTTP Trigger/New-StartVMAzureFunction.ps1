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


#From https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-http-webhook-trigger?tabs=python-v2%2Cisolated-process%2Cnodejs-v4%2Cfunctionsv2&pivots=programming-language-powershell#usage
#From https://learn.microsoft.com/en-us/azure/azure-functions/create-first-function-cli-powershell?tabs=windows%2Cazure-powershell%2Cbrowser
#From https://adamtheautomator.com/azure-function-powershell-cloud/
#From https://dev.to/pwd9000/power-virtual-machines-on-or-off-using-azure-functions-4k8o

[CmdletBinding()]
param
(
)


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
#endregion

#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 
$RuntimeVersion = "7.4"

#region Defining variables 
#region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
$AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
$ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
$shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
#endregion


#region Building an Hashtable to get the prefix of every Azure resource type based on a JSON file on the Github repository of the Azure Naming Tool
$Result = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/refs/heads/main/src/repository/resourcetypes.json 
$ResourceTypeShortNameHT = $Result | Where-Object -FilterScript { $_.property -notin @('Linux') } | Select-Object -Property resource, shortName, property, lengthMax | Group-Object -Property resource -AsHashTable -AsString
#endregion

# Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount
    #Get-AzSubscription | Out-GridView -OutputMode Single -Title "Select your Azure Subscription" | Select-AzSubscription
    #$Subscription = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction Ignore
    #Select-AzSubscription -SubscriptionName $SubscriptionName | Select-Object -Property *
}

$AzureVMNameMaxLength = $ResourceTypeShortNameHT["Compute/virtualMachines"].lengthMax
$StorageAccountSkuName = "Standard_LRS"
$Location = "eastus2"
$LocationShortName = $shortNameHT[$Location].shortName
#Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
$ResourceGroupNamePrefix = $ResourceTypeShortNameHT["Resources/resourcegroups"].ShortName
$StorageAccountPrefix = $ResourceTypeShortNameHT["Storage/storageAccounts"].Where({$_.Property -eq  [string]::Empty}).ShortName
$AzureFunctionPrefix = $ResourceTypeShortNameHT["Web/sites"].Where({$_.Property -eq "Function App"}).ShortName
$Project = "vm"
$Role = "start"
$DigitNumber = $AzureVMNameMaxLength - ($VirtualMachinePrefix + $Project + $Role + $LocationShortName).Length

Do {
    $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
    $StorageAccountName = "{0}{1}{2}{3}{4:D$DigitNumber}" -f $StorageAccountPrefix, $Project, $Role, $LocationShortName, $Instance                       
    $AzureFunctionName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $AzureFunctionPrefix, $Project, $Role, $LocationShortName, $Instance                       
} While ((-not(Get-AzStorageAccountNameAvailability -Name $StorageAccountName).NameAvailable) -or (-not(Test-FunctionAppNameAvailability -FunctionAppName $AzureFunctionName)))

$ResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupNamePrefix, $Project, $Role, $LocationShortName, $Instance                       
#endregion

#region Resource Group Setup
$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
if ($ResourceGroup) {
    #Step 0: Remove previously existing Azure Resource Group with the same name
    $ResourceGroup | Remove-AzResourceGroup -Force -Verbose
}

# Create Resource Groups
$ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
#endregion

#region Create Azure Storage Account
$StorageAccount = New-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -Location $Location -SkuName $StorageAccountSkuName -MinimumTlsVersion TLS1_2 -EnableHttpsTrafficOnly $true -AllowBlobPublicAccess $true
#endregion

#region Prerequisites
#region Azure Functions Core Tools
if ($null -eq $(Get-WmiObject -Class Win32Reg_AddRemovePrograms -Filter "DisplayName LIKE 'Azure Functions Core Tools%'")) {
    $AzureFunctionsCoreToolsURI = "https://go.microsoft.com/fwlink/?linkid=2174087"
    $OutFile = Join-Path -Path $CurrentDir -ChildPath "func-cli-x64.msi"
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
    $LatestDotNetCoreSDKSetupURI = (Invoke-WebRequest $LatestDotNetCoreSDKURI).links.href | Where-Object -FilterScript { $_ -match "sdk.*win.*-x64" } | Select-Object -Unique
    $LatestDotNetCoreSDKSetupFileName = Split-Path -Path $LatestDotNetCoreSDKSetupURI -Leaf
    $LatestDotNetCoreSDKSetupFilePath = Join-Path -Path $CurrentDir -ChildPath $LatestDotNetCoreSDKSetupFileName 
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

#region Create Azure Function
#$RuntimeVersion = "{0}.{1}" -f $PowerShellVersion.Major, $PowerShellVersion.Minor
$StorageAccount | Set-AzStorageAccount -AllowSharedKeyAccess $true
$FunctionApp = New-AzFunctionApp -Name $AzureFunctionName -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -Runtime "PowerShell" -RuntimeVersion $RuntimeVersion -OSType "Linux" -Location $Location -IdentityType SystemAssigned
#endregion

#region Creating the Function Locally
$AzureFunctionsCoreToolsDirectory = "$env:ProgramFiles\Microsoft\Azure Functions Core Tools\"
$Func = Join-Path -Path $AzureFunctionsCoreToolsDirectory -ChildPath "func"
$FunctionName = (Get-Item -Path $CurrentScript).BaseName
$null = Remove-Item -Path $FunctionName -Recurse -ErrorAction Ignore -Force
#Start-Process -FilePath "$env:comspec" -ArgumentList "/c", """$env:ProgramFiles\Microsoft\Azure Functions Core Tools\func"" init $FunctionName --powershell" -WorkingDirectory $CurrentDir
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", """$Func"" init $FunctionName --powershell"

#region Local code
$Directory = New-Item -Path $FunctionName\$FunctionName -ItemType Directory -Force
#From https://faultbucket.ca/2019/08/use-azure-function-to-start-vms/
$ScriptContent = @'
using namespace System.Net
 
# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)
 
# Interact with query parameters or the body of the request.
$rgname = $Request.Query.resourcegroup
if (-not $rgname) {
    $rgname = $Request.Body.resourcegroup
}
$action = $Request.Query.action
if (-not $action) {
    $action = $Request.Body.action
}
 
#Proceed if all request body parameters are found
if ($rgname -and $action) {
    $status = [HttpStatusCode]::OK
    if ($action -ceq "get"){
        $body = Get-AzVM -ResourceGroupName $rgname -Status | Select-Object -Property Name,PowerState
    }
    if ($action -ceq "start"){
        $Job = Get-AzVM -ResourceGroupName $rgname | Start-AzVM -AsJob
        $body = $Job | Receive-Job -Wait -AutoRemoveJob
    }
}
else {
    $status = [HttpStatusCode]::BadRequest
    $body = "Please pass a resource group name and an action on the query string or in the request body."
}
 
# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = $status
    Body = $body
})
'@

$FunctionJSONContent = @'
{
  "bindings": [
    {
      "name": "Request",
      "methods": [
        "get",
        "post"
      ],
      "authLevel": "anonymous",
      "type": "httpTrigger",
      "direction": "in"
    },
    {
      "type": "http",
      "name": "Response",
      "direction": "out"
    }
  ]
}
'@

New-Item -Path $(Join-Path -Path $Directory -ChildPath "run.ps1") -Value $ScriptContent -Force
New-Item -Path $(Join-Path -Path $Directory -ChildPath "function.json") -Value $FunctionJSONContent -Force

#region Requiring Az PowerShell modules
Set-Location -Path $FunctionName
While (-not(Test-Path -Path requirements.psd1)) {
    Start-Sleep -Seconds 10
}

(Get-Content -Path requirements.psd1) -replace "# 'Az'", "'Az'" | Set-Content -Path requirements.psd1 
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

$SubscriptionId = $((Get-AzContext).Subscription.Id)
#Getting randomly a Resource Group with at least one VM
$ResourcegroupName = (Get-AzVM).ResourceGroupName | Get-Random
$Body  = @{
    resourcegroup  = $ResourcegroupName
    action         = "start"
}
$Body
#Invoke-RestMethod -Uri "http://localhost:7071/api/$FunctionName" -Body $Body
#endregion
#endregion

#region Publishing the Azure Function
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", """$Func"" azure functionapp publish $($FunctionApp.Name) --powershell" -Wait
# Enable Logs
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", """$Func"" azure functionapp logstream $($FunctionApp.Name) --browser" -Wait
#endregion

#region RBAC Assignment(s)
#region 'Desktop Virtualization Power On Off Contributor' RBAC Assignment
$RoleDefinition = Get-AzRoleDefinition -Name "Virtual Machine Contributor"
$Parameters = @{
    ObjectId           = $FunctionApp.IdentityPrincipalId
    RoleDefinitionName = $RoleDefinition.Name
    Scope              = $ResourceGroupId 
}
while (-not(Get-AzRoleAssignment @Parameters)) {
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.ObjectId)' Identity on the '$($Parameters.Scope)' scope"
    $RoleAssignment = New-AzRoleAssignment @Parameters
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
    Start-Sleep -Seconds 30
}
#endregion
#endregion

#region Testing the Azure Function
#You have to wait some minutes before invoking this Azure function because some Az modules are downloading in the background ...
Invoke-RestMethod -Uri "https://$AzureFunctionName.azurewebsites.net/api/$FunctionName" -Body $Body
<#
#region Adding CORS for testing from the Azure Portal (Not directly possible via PowerShell)
#region Powershell Way
az functionapp cors add -g $FunctionApp.ResourceGroupName -n $FunctionApp.Name --allowed-origins https://portal.azure.com
#endregion

#region Powershell Way
$API = "2022-03-01"
$Parameters = @{
    ResourceGroupName = $FunctionApp.ResourceGroupName
    ResourceType      = "Microsoft.Web/sites/config"
    ResourceName      = "{0}/web" -f $FunctionApp.Name
    ApiVersion        = $API
}
$AZResource = Get-AzResource @Parameters

$AZResource.Properties.cors = @{
    allowedOrigins     = @("https://portal.azure.com")
    supportCredentials = $false
}

$Parameters = @{
    ResourceId = $AZResource.ResourceId
    Properties = $AZResource.Properties
    ApiVersion = $API
    Force      = $true
}
Set-AzResource @Parameters
#endregion
#endregion
#>
#endregion

#region Cleanup
Set-Location -Path $CurrentDir
#Stop-Process -InputObject $FuncProcess -Force

Remove-Item -Path $FunctionName -Recurse -Force

<#
Stop-AzFunctionApp -Name $AzureFunctionName -ResourceGroupName $ResourceGroupName -Force
Remove-AzResourceGroup -Name $ResourceGroupName -Force -AsJob
Get-AzResourceGroup -Name rg-func-poc* | Remove-AzResourceGroup -Force -AsJob
#>
#endregion

#endregion