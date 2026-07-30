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
#requires -Version 5 -Modules AutomatedLab, Az.DesktopVirtualization, Az.ConnectedMachine -RunAsAdministrator 
#Requires -Modules @{ ModuleName='Microsoft.Graph.Beta.Identity.DirectoryManagement'; MaximumVersion="2.25.0" }

trap {
    Write-Host "Stopping Transcript ..."
    Stop-Transcript
    $VerbosePreference = $PreviousVerbosePreference
    $ErrorActionPreference = $PreviousErrorActionPreference
    [console]::beep(3000, 750)
    Send-ALNotification -Activity 'Lab started' -Message ('Lab deployment failed !') -Provider (Get-LabConfigurationItem -Name Notifications.SubscribedProviders)
    break
}

Import-Module -Name AutomatedLab -Verbose
try { while (Stop-Transcript) {} } catch {}
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

$PreviousVerbosePreference = $VerbosePreference
$VerbosePreference = 'SilentlyContinue'
$PreviousErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = 'SilentlyContinue'
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$TranscriptFile = $CurrentScript -replace ".ps1$", "_$("{0:yyyyMMddHHmmss}" -f (Get-Date)).txt"
Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader

#region Global variables definition
$Logon = 'Administrator'
$ClearTextPassword = 'P@ssw0rd'
$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force

$NetworkID = '10.0.0.0/16' 
$AVDHybrid01IPv4Address = '10.0.0.101'
$AVDHybrid02IPv4Address = '10.0.0.102'

$LabName = 'AVDHybrid'
#endregion

#Cleaning previously existing lab
if ($LabName -in (Get-Lab -List)) {
    Remove-Lab -Name $LabName -Confirm:$false -ErrorAction SilentlyContinue
}

#create an empty lab template and define where the lab XML files and the VMs will be stored
New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV

#make the network definition
Add-LabVirtualNetworkDefinition -Name $LabName -HyperVProperties @{ SwitchType = 'Internal' } -AddressSpace $NetworkID
Add-LabVirtualNetworkDefinition -Name 'Default Switch' -HyperVProperties @{ SwitchType = 'External'; AdapterName = 'Wi-Fi' }


#these credentials are used for connecting to the Machines. As this is a lab we use clear-text passwords
Set-LabInstallationCredential -Username $Logon -Password $ClearTextPassword

#defining default parameter values, as these ones are the same for all the Machines
$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:Network'         = $LabName
    'Add-LabMachineDefinition:MinMemory'       = 4GB
    'Add-LabMachineDefinition:MaxMemory'       = 8GB
    'Add-LabMachineDefinition:Memory'          = 4GB
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows 11 Enterprise'
    'Add-LabMachineDefinition:Processors'      = 2
}

$AVDHybrid01NetAdapter = @()
$AVDHybrid01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $AVDHybrid01IPv4Address -InterfaceName Corp
#Adding an Internet Connection on the DC (Required for PowerShell Gallery)
$AVDHybrid01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp -InterfaceName Internet

$AVDHybrid02NetAdapter = @()
$AVDHybrid02NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $AVDHybrid02IPv4Address -InterfaceName Corp
#Adding an Internet Connection on the DC (Required for PowerShell Gallery)
$AVDHybrid02NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp -InterfaceName Internet


#region server definitions
#AvdHybrid-01 
Add-LabMachineDefinition -Name AvdHybrid-01 -NetworkAdapter $AVDHybrid01NetAdapter
#AvdHybrid-02
Add-LabMachineDefinition -Name AvdHybrid-02 -NetworkAdapter $AVDHybrid02NetAdapter
#endregion

#Installing servers
Install-Lab -Verbose
Checkpoint-LabVM -SnapshotName FreshInstall -All -Verbose

#region Installing Required Windows Features
$Machines = Get-LabVM

Install-LabWindowsFeature -FeatureName Telnet-Client -ComputerName $Machines -IncludeManagementTools -AsJob
#endregion

Invoke-LabCommand -ActivityName 'Windows Virtual Desktop Optimization Tool (VDOT)' -ComputerName $Machines -ScriptBlock {
    winget install --id Git.Git -e --source winget
    $GitHubRootDir = Join-Path -Path $env:SystemDrive -ChildPath "Source Control\GitHub"
    $GitHubRepoURI = "https://github.com/The-Virtual-Desktop-Team/Virtual-Desktop-Optimization-Tool"
    $GitHubRepoName = Split-Path -Path $GitHubRepoURI -Leaf
    $GitHubRepoDir = Join-Path -Path $GitHubRootDir -ChildPath $GitHubRepoName

    $null = New-Item -Path $GitHubRootDir -ItemType Directory -Force
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "git clone $GitHubRepoURI ""$GitHubRepoDir""" -Wait -WorkingDirectory "$env:ProgramFiles\Git\cmd"
    <#
    Set-Location -Path $GitHubRepoDir
    .\Windows_VDOT.ps1 -Optimizations All -AdvancedOptimizations All -AcceptEULA -Verbose
    #>
    $ScriptFile = Join-Path -Path $GitHubRepoDir -ChildPath "Windows_VDOT.ps1"
    & $ScriptFile -Optimizations All -AdvancedOptimizations All -AcceptEULA -Verbose -ErrorAction Ignore
    #Restart-Computer -Force
}

Restart-LabVM -ComputerName $Machines -Wait

Get-Job -Name 'Installation of*' | Wait-Job | Out-Null

Checkpoint-LabVM -SnapshotName 'FullInstall' -All

Show-LabDeploymentSummary

$VerbosePreference = $PreviousVerbosePreference
$ErrorActionPreference = $PreviousErrorActionPreference
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose

Stop-Transcript

#region RDCMan Setup
$Servers = foreach ($Machine in $Machines) {
@"
        <server>
            <properties>
            <name>{0}</name>
            </properties>
        </server>
"@ -f $Machine
}


$PasswordBytes = [System.Text.Encoding]::Unicode.GetBytes($ClearTextPassword)
$SecurePassword = [Security.Cryptography.ProtectedData]::Protect($PasswordBytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
$SecurePasswordStr = [System.Convert]::ToBase64String($SecurePassword)
$RDCManFileContent = @"
<?xml version="1.0" encoding="utf-8"?>
<RDCMan programVersion="3.12" schemaVersion="3">
  <file>
    <credentialsProfiles />
    <properties>
      <expanded>True</expanded>
      <name>AVDHybrid</name>
    </properties>
    <logonCredentials inherit="None">
    </logonCredentials>
    <remoteDesktop inherit="None">
      <sameSizeAsClientArea>True</sameSizeAsClientArea>
      <fullScreen>False</fullScreen>
      <colorDepth>24</colorDepth>
    </remoteDesktop>
    <group>
      <properties>
        <expanded>True</expanded>
        <name>AVD</name>
      </properties>
      <group>
        <properties>
          <expanded>True</expanded>
          <name>Hybrid</name>
        </properties>
        <logonCredentials inherit="None">
          <profileName scope="Local">Custom</profileName>
          <userName>{0}</userName>
          <password>{1}</password>
          <domain />
        </logonCredentials>
{2}
      </group>
    </group>
  </file>
  <favorites />
  <recentlyUsed />
</RDCMan>
"@ -f $Logon, $SecurePasswordStr, $($Servers | Out-String)
$RDCManFilePath = Join-Path -Path $([Environment]::GetFolderPath("MyDocuments")) -ChildPath "AVDHybrid.rdg"
$RDCManFileContent | Out-File -FilePath $RDCManFilePath -Encoding utf8
#endregion

#region Azure
#Install-Module -Name 'Az.DesktopVirtualization', 'Az.ConnectedMachine' -Scope AllUsers -AllowClobber -Force -Verbose 
#Install-Module -Name 'Microsoft.Graph.Beta.Identity.DirectoryManagement' -MaximumVersion 2.25.0 -Scope AllUsers -AllowClobber -Force -Verbose 

#region Microsoft Graph
#region Microsoft Graph Connection
try {
    $null = Get-MgBetaDevice -All -ErrorAction Stop
}
catch {
    Connect-MgGraph -Scopes "Device.ReadWrite.All" -NoWelcome -UseDeviceCode
}
#endregion

#region Cleaning up the previously existing VMs (if any)
foreach($Machine in $Machines) {
    $Device = Get-MgBetaDevice -Filter "displayName eq '$($Machine.Name)'" -ErrorAction Ignore
    if ($Device) {
        Remove-MgBetaDevice -DeviceId $Device.Id
    }
}
#endregion
#Disconnect-MgGraph
#Get-Module Microsoft.Graph.* | Remove-Module -Force
#endregion


#region Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount -UseDeviceAuthentication
}
#endregion

#region Storing VM Credentials
foreach ($Machine in $Machines) {
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /generic:$Machine /user:$Logon /pass:$($ClearTextPassword -replace "(\W)", '^$1')" -Wait
}
#endregion

#region Host Pool Management
$ResourceGroup = Get-AzResourceGroup -Name rg-hp-pd-ei-hyb-mp-*
if ($ResourceGroup) {
    if ($ResourceGroup.count -gt 1) {
        $ResourceGroup = $ResourceGroup | Out-GridView -OutputMode Single
    }
    $PersonalHostPool = Get-AzWvdHostPool -ResourceGroupName $ResourceGroup.ResourceGroupName
    if ($PersonalHostPool -and $PersonalHostPool.HostPoolType -eq 'Personal') {
        if ($PersonalHostPool.count -gt 1) {
            $PersonalHostPool = $PersonalHostPool | Out-GridView -OutputMode Single
        }
        #$PersonalHostPool = Get-AzWvdHostPool -ResourceGroupName $ResourceGroup.ResourceGroupName | Select-Object -First 1
        $Location = $ResourceGroup.Location
        $Context = Get-AzContext
        $SubscriptionId = $Context.Subscription.Id
        $TenantId = $Context.Tenant.Id

        #region Azure Arc Onboarding
        $ScriptBlockContent = @"
`$null = Get-PackageProvider -Name Nuget -ForceBootstrap -Force
`$RequiredModules = 'Az.DesktopVirtualization', 'Az.ConnectedMachine'
`$InstalledModule = Get-InstalledModule -Name `$RequiredModules -ErrorAction Ignore
if (-not([String]::IsNullOrEmpty(`$InstalledModule))) {
    `$MissingModules = (Compare-Object -ReferenceObject `$RequiredModules -DifferenceObject (Get-InstalledModule -Name `$RequiredModules -ErrorAction Ignore).Name).InputObject
}
else {
    `$MissingModules = `$RequiredModules
}
if (-not([String]::IsNullOrEmpty(`$MissingModules))) {
    Install-Module -Name `$MissingModules -AllowClobber -Force -Verbose 
}

#region Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount -UseDeviceAuthentication
}
#Copying the Azure Logged Account into the clipboard for EntraID join 
(Get-AzContext).Account.Id | Set-Clipboard
#Set-WinUserLanguageList -LanguageList fr-fr -Force
While (-not(`$(dsregcmd /status | Out-String) -match  "AzureAdJoined\s+:\s+YES"))
{
    Write-Host -Object "Click on 'Connect' on the newly opened Windows and then on the 'Join this device to Microsoft Entra ID' link at the bottom to proceed .." -ForeGroundColor Green
    start ms-settings:workplace
}
#removing any existing Azure Arc Hybrid Machine with the same name
`$Parameters = @{
    ResourceGroupName = "$($ResourceGroup.ResourceGroupName)"
    Name = `$env:COMPUTERNAME
}
if (Get-AzConnectedMachine @Parameters -ErrorAction Ignore) {
    Remove-AzConnectedMachine @Parameters -ErrorAction Ignore
    start-Sleep -Seconds 30
}
Connect-AzConnectedMachine @Parameters -Location $Location
Write-Host -Object "Done ..." -ForegroundColor Green
"@

        $FilePath = Join-Path -Path $env:SystemDrive -ChildPath "AzureArcOnboarding.ps1"
        Invoke-LabCommand -ActivityName 'Copying Azure Arc Onboarding Script Locally' -ComputerName $Machines -ScriptBlock {
            $using:ScriptBlockContent | Out-File -FilePath $using:FilePath
        } #-AsJob

        <#
        foreach ($Machine in $Machines) {
            Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "mstsc /v:$Machine" #-Wait
        }
        #>
        $FilePath | Set-ClipBoard
		& $RDCManFilePath

		#Write-Host -Object "Run the '$FilePath' PowerShell script from $($Machines -join ', ') ..."
        Do {
            $Continue = Read-Host -Prompt "Connect via RDP to $($Machines.Name -join ', ') and run the '$FilePath' script before continuing ...`r`nPress Y to continue"
        } While ($Continue -ne 'Y')

        #region Check
        Start-Process "https://portal.azure.com/#servicemenu/Microsoft_Azure_ArcCenterUX/AzureArcCenterHub/servers"
        Get-AzConnectedMachine -ResourceGroupName $($ResourceGroup.ResourceGroupName)
        #endregion 
        #endregion 

        <#
        #region EntraID join
        $settings = @{
            # IMPORTANT: must be present even empty
            mdmId = ""   
        }
        foreach($Machine in $Machines) {
            New-AzConnectedMachineExtension -Name "aadlogin" -ResourceGroupName $ResourceGroup.ResourceGroupName -MachineName $Machine.Name -Location $Location -Publisher "Microsoft.Azure.ActiveDirectory" -ExtensionType "AADLoginForWindows" -Settings $settings
        }
        #endregion
        #>

        #region Generate a host pool registration key
        $ExpiresUtc = (Get-Date).ToUniversalTime().AddDays(1).ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ")
        $RegistrationInfo = New-AzWvdRegistrationInfo -ResourceGroupName $PersonalHostPool.ResourceGroupName -HostPoolName $PersonalHostPool.Name -ExpirationTime $ExpiresUtc
        $RegistrationToken = $RegistrationInfo.Token
        #endregion

        #region Installing the Arc Extension
        # Settings
        $settings          = @{ isCloudDevice = $false }
        $protectedSettings = @{ registrationToken = $RegistrationToken }

        #Installing the Arc Extension
        foreach($Machine in $Machines) {
            Write-Host "Install the Arc Extension on '$($Machine.Name)' ..."
            New-AzConnectedMachineExtension -Name 'Microsoft.AzureVirtualDesktop.CloudDeviceExtension' -ResourceGroupName $ResourceGroup.ResourceGroupName -MachineName $Machine.Name -Location $Location -Publisher 'Microsoft.AzureVirtualDesktop' -ExtensionType 'CloudDeviceExtension' -Setting $settings -ProtectedSetting $protectedSettings -verbose
            Get-AzConnectedMachineExtension -ResourceGroupName $ResourceGroup.ResourceGroupName -MachineName $Machine.Name -Name 'Microsoft.AzureVirtualDesktop.CloudDeviceExtension'
        }
        #endregion

        #region RBAC Assignments
        #region "Virtual Machine User Login"
        $ConnectedMachines = Get-AzConnectedMachine -ResourceGroupName $ResourceGroup.ResourceGroupName | Where-Object -FilterScript { $_.Name -in $Machines.Name}
        $RoleDefinition = Get-AzRoleDefinition -Name "Virtual Machine User Login"
        $AzADGroup = Get-AzADGroup -DisplayName "AVD Users"

        foreach($ConnectedMachine in $ConnectedMachines) {
            $Parameters = @{
                ObjectId           = $AzADGroup.Id
                RoleDefinitionName = $RoleDefinition.Name
                Scope              = $ConnectedMachine.Id
                #Verbose            = $true
            }
            if (-not(Get-AzRoleAssignment @Parameters)) {
                New-AzRoleAssignment @Parameters
            }
            else {
                Write-Warning -Message "The RBAC Assignment '$($Parameters.RoleDefinitionName)' for '$($Parameters.ObjectId)' on '$($Parameters.Scope)' already exists"
            }
        }
        #endregion

        #region "Desktop Virtualization User" to Desktop Application Group
        $ConnectedMachines = Get-AzConnectedMachine -ResourceGroupName $ResourceGroup.ResourceGroupName | Where-Object -FilterScript { $_.Name -in $Machines.Name}
        $RoleDefinition = Get-AzRoleDefinition -Name "Desktop Virtualization User"
        $AzADGroup = Get-AzADGroup -DisplayName "AVD Users"
        $ApplicationGroup = Get-AzWvdApplicationGroup -ResourceGroupName $ResourceGroup.ResourceGroupName
        $Parameters = @{
            ObjectId           = $AzADGroup.Id
            ResourceName       = $ApplicationGroup.Name
            ResourceGroupName  = $ResourceGroup.ResourceGroupName
            RoleDefinitionName = $RoleDefinition.Name
            ResourceType       = 'Microsoft.DesktopVirtualization/applicationGroups'
            #Verbose            = $true
        }
        if (-not(Get-AzRoleAssignment @Parameters)) {
            New-AzRoleAssignment @Parameters
        }
        else {
            Write-Warning -Message "The RBAC Assignment '$($Parameters.RoleDefinitionName)' for '$($Parameters.ObjectId)' on '$($Parameters.ResourceName)' already exists"
        }
        #endregion
        #endregion
    }
}

#endregion

#region removing VM Credentials
foreach ($Machine in $Machines) {
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /delete:$Machine" -Wait
}
#endregion
#endregion