Clear-Host

$Global:MaximumFunctionCount = 32768
$null = Remove-Module -Name PSAzureVirtualDesktop -Force -ErrorAction Ignore
Import-Module -Name PSAzureVirtualDesktop -Force
Connect-MgGraph -NoWelcome

#region Creating Host Pools
#region ADJoin User
$AdJoinUserName = 'adjoin'
$ClearTextPassword = 'I@m@JediLikeMyF@therB4Me'
$AdJoinPassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$AdJoinCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ($AdJoinUserName, $AdJoinPassword)
#region Azure Key Vault for stroing ADJoin Credentials
$HostPoolSessionCredentialKeyVault = New-PsAvdHostPoolSessionHostCredentialKeyVault -ADJoinCredential $ADJoinCredential
#endregion

[int] $RandomNumber = ((Get-AzWvdHostPool).Name -replace ".*-(\d+)", '$1' | Sort-Object | Select-Object -First 1)-1
[PooledHostPool]::Index = $RandomNumber
[PersonalHostPool]::Index = $RandomNumber

$HostPools = @(
    # Use case 1: Deploy a Pooled HostPool with 3 (default value) Session Hosts (AD Domain joined) with FSLogix
    [PooledHostPool]::new($HostPoolSessionCredentialKeyVault)#.EnableSpotInstance()
    # Use case 2: Deploy a Pooled HostPool with 3 (default value) Session Hosts (AD Domain joined) with FSLogix, Ephemeral OS Disk (ResourceDisk mode) and a Standard_DS3_v2 size (compatible with Ephemeral OS Disk)
    [PooledHostPool]::new($HostPoolSessionCredentialKeyVault).SetVMSize('Standard_D8ds_v5').EnableEphemeralOSDisk([DiffDiskPlacement]::ResourceDisk)
    # Use case 3: Deploy a Pooled HostPool with 3 (default value) Session Hosts (Azure AD/Microsoft Entra ID joined) with FSLogix and Spot Instance VMs and setting the LoadBalancer Type to DepthFirst
    [PooledHostPool]::new($HostPoolSessionCredentialKeyVault).SetIdentityProvider([IdentityProvider]::MicrosoftEntraID).EnableSpotInstance().SetLoadBalancerType([Microsoft.Azure.PowerShell.Cmdlets.DesktopVirtualization.Support.LoadBalancerType]::DepthFirst)
    # Use case 4: Deploy a Pooled HostPool with 3 (default value) Session Hosts (Azure AD/Microsoft Entra ID joined, enrolled with Intune) with FSLogix and a Scaling Plan
    [PooledHostPool]::new($HostPoolSessionCredentialKeyVault).EnableIntune()#.EnableScalingPlan()#.SetVMNumberOfInstances(1).EnableSpotInstance()
    # Use case 5: Deploy a Personal HostPool with 2 Session Hosts (AD Domain joined and without FSLogix and MSIX - Not necessary for Personal Desktops) 
    [PersonalHostPool]::new($HostPoolSessionCredentialKeyVault).SetVMNumberOfInstances(2)
    # Use case 6: Deploy a Personal HostPool with 3 (default value) Session Hosts (Azure AD/Microsoft Entra ID joined and without FSLogix and MSIX - Not necessary for Personal Desktops), Hibernation enabled and a Scaling Plan 
    [PersonalHostPool]::new($HostPoolSessionCredentialKeyVault).SetIdentityProvider([IdentityProvider]::MicrosoftEntraID).EnableHibernation().EnableScalingPlan()
)
#endregion

$HostPool = $HostPools
$ModuleBase = (Get-Module -Name PSAzureVirtualDesktop -ListAvailable).ModuleBase
$PesterDirectory = Join-Path -Path $ModuleBase -ChildPath 'Pester'

#region Pester Tests
$HostPoolClassPesterTests    = Join-Path -Path $PesterDirectory -ChildPath 'HostPool.Class.Tests.ps1'
$Container = New-PesterContainer -Path $HostPoolClassPesterTests -Data @{ HostPool = $HostPool }
Invoke-Pester -Container $Container -Output Detailed #-Verbose

$HostPoolAzurePesterTests    = Join-Path -Path $PesterDirectory -ChildPath 'HostPool.Azure.Tests.ps1'
$Container = New-PesterContainer -Path $HostPoolAzurePesterTests -Data @{ HostPool = $HostPool }
Invoke-Pester -Container $Container -Output Detailed #-Verbose

$ScalingPlanAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'ScalingPlan.Azure.Tests.ps1'
$Container = New-PesterContainer -Path $ScalingPlanAzurePesterTests -Data @{ HostPool = $HostPool }
Invoke-Pester -Container $Container -Output Detailed #-Verbose

$FSLogixAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'FSLogix.Azure.Tests.ps1'
$Container = New-PesterContainer -Path $FSLogixAzurePesterTests -Data @{ HostPool = $HostPool }
Invoke-Pester -Container $Container -Output Detailed #-Verbose

$MSIXAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'MSIX.Azure.Tests.ps1'
$Container = New-PesterContainer -Path $MSIXAzurePesterTests -Data @{ HostPool = $HostPool }
Invoke-Pester -Container $Container -Output Detailed #-Verbose

$MFAAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'MFA.Azure.Tests.ps1'
$Container = New-PesterContainer -Path $MFAAzurePesterTests -Data @{ HostPool = $HostPool }
Invoke-Pester -Container $Container -Output Detailed #-Verbose

$ConditionalAccessPolicyAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'ConditionalAccessPolicy.Azure.Tests.ps1'
$Container = New-PesterContainer -Path $ConditionalAccessPolicyAzurePesterTests
Invoke-Pester -Container $Container -Output Detailed #-Verbose

$CurrentLogDir = Get-ChildItem -Path ~\Documents\ -Filter HostPool_* -Directory | Sort-Object -Property Name -Descending | Select-Object -First 1
$ErrorLogFilePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'Error.LogFile.Tests.ps1'
$Container = New-PesterContainer -Path $ErrorLogFilePesterTests -Data @{ LogDir = $CurrentLogDir.FullName }
Invoke-Pester -Container $Container -Output Detailed #-Verbose

$WorkBooks = @{
    #Feom https://github.com/Azure/avdaccelerator/tree/main/workload/workbooks/deepInsightsWorkbook
    "Deep Insights Workbook - AVD Accelerator" = "https://raw.githubusercontent.com/Azure/avdaccelerator/main/workload/workbooks/deepInsightsWorkbook/deepInsights.workbook"
    #From https://github.com/scautomation/Azure-Inventory-Workbook/tree/master/galleryTemplate
    "Windows Virtual Desktop Workbook - Billy York" = "https://raw.githubusercontent.com/scautomation/WVD-Workbook/master/galleryTemplate/template.json"
    #From https://blog.itprocloud.de/AVD-Azure-Virtual-Desktop-Error-Drill-Down-Workbook/
    "AVD - Deep-Insights - ITProCloud" = "https://blog.itprocloud.de/assets/files/AzureDeployments/Workbook-AVD-Error-Logging.json"
    #From https://github.com/microsoft/Application-Insights-Workbooks/tree/master/Workbooks/Windows%20Virtual%20Desktop/AVD%20Insights
    "AVD Insights - Application-Insights-Workbooks" = "https://raw.githubusercontent.com/microsoft/Application-Insights-Workbooks/master/Workbooks/Windows%20Virtual%20Desktop/AVD%20Insights/AVDWorkbookV2.workbook"
}

$WorkbookAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'WorkBook.Azure.Tests.ps1'
$Container = New-PesterContainer -Path $WorkbookAzurePesterTests -Data @{ WorkBook = $WorkBooks }
Invoke-Pester -Container $Container -Output Detailed -Verbose

$OSEphemeralDiskAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'OSEphemeralDisk.Azure.Tests.ps1'
$Container = New-PesterContainer -Path $OSEphemeralDiskAzurePesterTests -Data @{ HostPool = $HostPool }
Invoke-Pester -Container $Container -Output Detailed -Verbose

$OperationalInsightsQueryAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'OperationalInsightsQuery.Azure.Tests.ps1'
$Container = New-PesterContainer -Path $OperationalInsightsQueryAzurePesterTests -Data @{ HostPool = $HostPool }
Invoke-Pester -Container $Container -Output Detailed -Verbose


$HostPoolSessionHostAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'HostPool.SessionHost.Azure.Tests.ps1'
foreach ($CurrentHostPool in $HostPools) {
    $SessionHostName = (Get-AzWvdSessionHost -HostpoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPool.GetResourceGroupName()).ResourceId -replace ".*/"
    $Container = New-PesterContainer -Path $HostPoolSessionHostAzurePesterTests -Data @{ HostPool = $CurrentHostPool; SessionHostName = $SessionHostName }
    Invoke-Pester -Container $Container -Output Detailed #-Verbose
}
#endregion