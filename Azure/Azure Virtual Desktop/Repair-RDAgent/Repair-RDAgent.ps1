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
#requires -Version 5 -Modules Az.DesktopVirtualization 

[CmdletBinding(PositionalBinding = $false)]
Param(
)

#region Function Definitions 
#Coded as an alternative to Remove-AzWvdSessionHost (but useless)
function Remove-AzAvdSessionHost {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$HostPoolName,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SessionHostName,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$")] 
        [string]$SubscriptionId,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ApiVersion="2024-04-03",
        [switch] $Force
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"

    #region Azure Context
    # Log in first with Connect-AzAccount if not using Cloud Shell

    $azContext = Get-AzContext
    $SubscriptionId = $azContext.Subscription.Id
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
    $token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'  = 'application/json'
        'Authorization' = 'Bearer ' + $token.AccessToken
    }
    #endregion

    $URI = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.DesktopVirtualization/hostPools/$HostPoolName/sessionHosts/${sessionHostName}?api-version=2024-04-03&force=$($Force.IsPresent)"
    try {
        # Invoke the REST API
        $Response = Invoke-AzRestMethod -Method DELETE -Uri $URI -ErrorVariable ResponseError
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
    }
    finally {
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $Response
}
#endregion

#region Main Code
Clear-Host
$Error.Clear()

# Set working directory to script location for relative path operations
$CurrentScript = $MyInvocation.MyCommand.Path
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir
$SubscriptionId = (Get-AzContext).Subscription.Id

$SessionHosts = Get-AzWvdHostPool | ForEach-Object { 
    $HostPoolId=$_.Id
    (Get-AzWvdSessionHost -HostPoolName $_.Name -ResourceGroupName $_.ResourceGroupName) | ForEach-Object { 
        [PSCustomObject]@{SessionHostName = $_.Name -replace "^.*/"; SessionHostId = $_.ResourceId; HostPoolId=$HostPoolId} }
}
$FilteredSessionHosts = $SessionHosts | Where-Object -FilterScript { $_.SessionHostId } | Out-GridView -PassThru
$InstallScriptUri = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/refs/heads/master/Azure/Azure%20Virtual%20Desktop/Repair-RDAgent/Install-RDAgent.ps1"
$InstallScriptFileName = Split-Path -Path $InstallScriptUri -Leaf
$UninstallScriptUri = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/refs/heads/master/Azure/Azure%20Virtual%20Desktop/Repair-RDAgent/Uninstall-RDAgent.ps1"
$UninstallScriptFileName = Split-Path -Path $UninstallScriptUri -Leaf


foreach ($FilteredSessionHost in $FilteredSessionHosts) {
    $HostPool = $FilteredSessionHost.HostPoolId | Get-AzWvdHostPool
    $SessionHost = $FilteredSessionHost.SessionHostId | Get-AzVM
    Write-Host -Object "Starting '$($FilteredSessionHost.SessionHostId)' VM (if needed) ..."
    $null = $SessionHost | Start-AzVM
    $Parameters = @{
        HostPoolName = $HostPool.Name 
        ResourceGroupName = $HostPool.ResourceGroupName 
    }
    #Step 1 : Removing the Session Host/VM of the HostPool
    Write-Host -Object "Removing '$($FilteredSessionHost.SessionHostId)' of the HostPool ..."
    $IsRemoved = Remove-AzWvdSessionHost @Parameters -Name $FilteredSessionHost.SessionHostName -Force -PassThru 

    #Step 2: Uninstalling RDS Applications
    Write-Host -Object "Uninstalling RDS Applications from '$($FilteredSessionHost.SessionHostId)' Session Host ..."
    $null = Set-AzVMCustomScriptExtension -VMName $SessionHost.Name -ResourceGroupName $SessionHost.ResourceGroupName -Location $SessionHost.Location -FileUri $UninstallScriptUri -Run $UninstallScriptFileName -Name $UninstallScriptFileName
    Write-Host -Object "Sleeping 30 seconds  ..."
    Start-Sleep -Seconds 30

    #Waiting the VM be up and rnning to continue
    Write-Host -Object "Starting '$($FilteredSessionHost.SessionHostId)' VM (if needed) ..."
    $null = $SessionHost | Start-AzVM

    #Removing the CustomScriptExtension used to uninstall the RDS applications  (else will cause conflicts later)
    $null = Get-AzVMCustomScriptExtension -ResourceGroupName $SessionHost.ResourceGroupName -VMName $SessionHost.Name -Name $UninstallScriptFileName | Remove-AzVMCustomScriptExtension -Force


    #Step 3: Installing RDS Applications (the Session Host/VM will be part of the HostPool)
    $ExpirationTime = (Get-Date).AddDays(1)
    $RegistrationInfoToken = New-AzWvdRegistrationInfo @Parameters -ExpirationTime $ExpirationTime
    $Argument = "-RegistrationInfoToken $($RegistrationInfoToken.Token) -Restart"
    Write-Host -Object "Installing RDS Applications on '$($FilteredSessionHost.SessionHostId)' VM and set it as a SessionHost in the HostPool ..."
    $null = Set-AzVMCustomScriptExtension -VMName $SessionHost.Name -ResourceGroupName $SessionHost.ResourceGroupName -Location $SessionHost.Location -FileUri $InstallScriptUri -Run $InstallScriptFileName -Name $InstallScriptFileName -Argument $Argument

    #Removing the CustomScriptExtension used to install the RDS applications 
    $null = Get-AzVMCustomScriptExtension -ResourceGroupName $SessionHost.ResourceGroupName -VMName $SessionHost.Name -Name $InstallScriptFileName | Remove-AzVMCustomScriptExtension -Force
}
#endregion
