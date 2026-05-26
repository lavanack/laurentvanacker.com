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
#requires -Version 5 -Modules Az.Accounts, Az.Aks, Az.Compute, Az.Network, Az.Resources, Az.Security

#From https://learn.microsoft.com/en-us/azure/aks/learn/quick-windows-container-deploy-powershell

[CmdletBinding()]
param
(
)

#region function definitions 
function New-RandomPassword {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [ValidateScript({$_ -ge 14 -and $_ -le 123})]
        [int]$Length = 14,
        [switch] $AsSecureString,
        [switch] $ClipBoard
    )

    # Character sets
    $lower   = 'abcdefghijklmnopqrstuvwxyz'.ToCharArray()
    $upper   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.ToCharArray()
    $digits  = '0123456789'.ToCharArray()
    $special = '!@#$%^&*()'.ToCharArray()

    $all = $lower + $upper + $digits + $special

    # Ensure at least one of each required category
    $RandomPassword = @($(Get-Random -InputObject $lower), $(Get-Random -InputObject $upper), $(Get-Random -InputObject $special))

    # Fill the rest randomly
    for ($i = $RandomPassword.Count; $i -lt $Length; $i++) {
        $RandomPassword += Get-Random -InputObject $all
    }

    # Shuffle the result
    $RandomPassword = -join $($RandomPassword | Sort-Object { Get-Random })

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
#endregion

#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

$FeatureName="AksWindows2025Preview" 
$ProviderNamespace="Microsoft.ContainerService"
Register-AzProviderFeature -ProviderNamespace $ProviderNamespace -FeatureName $FeatureName
do {
    $FeatureStatus = (Get-AzProviderFeature -ProviderNamespace $ProviderNamespace -FeatureName $FeatureName).RegistrationState
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Waiting for '$ProviderNamespace' Resource Provider to be registered ... Waiting 10 seconds"
    Start-Sleep -Seconds 10
} until ($FeatureStatus -eq "Registered")


try {
    $null = kubectl
}
catch {
    Write-Warning -Message "kubectl not found. We will install it via winget"
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "winget install -e --id Kubernetes.kubectl" -Wait
    Write-Warning -Message "kubectl installed. Re-run this script from a NEW PowerShell host !"
    break
}

#From https://aka.ms/azps-changewarnings: Disabling breaking change warning messages in Azure PowerShell
$null = Update-AzConfig -DisplayBreakingChangeWarning $false

#region Defining variables 
#region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
$AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
$ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
$shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
#endregion

# Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount
}


$Location = "eastus2"
$LocationShortName = $shortNameHT[$Location].shortName

#Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
$AKSClusterPrefix = "aks"
$ResourceGroupPrefix = "rg"
$Project = "aks"
$Role = "cluster"
$DigitNumber = 4
$AKSStoreQuickstartURI = 'https://raw.githubusercontent.com/Azure-Samples/aks-store-demo/main/aks-store-quickstart.yaml'
$UserNP = "npwin"
$Username = $env:USERNAME
$SecurePassword = New-RandomPassword -ClipBoard -AsSecureString -Verbose
$AdminCreds = New-Object System.Management.Automation.PSCredential -ArgumentList ($Username, $SecurePassword)


$Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
$ResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
$AKSClusterName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $AKSClusterPrefix, $Project, $Role, $LocationShortName, $Instance

$ResourceGroupName = $ResourceGroupName.ToLower()
$AKSClusterName = $AKSClusterName.ToLower()

$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
if ($ResourceGroup) {
    #Remove previously existing Azure Resource Group with the same name
    $ResourceGroup | Remove-AzResourceGroup -Force
}
$ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
#endregion

#region AKS Cluster Setup
#region Create AKS cluster
$SshKeyValue = Join-Path -Path $HOME -ChildPath '.ssh\id_rsa.pub'
if (Test-Path -Path $SshKeyValue -PathType Leaf) {
    $AksCluster = New-AzAksCluster -ResourceGroupName $ResourceGroupName -Name $AKSClusterName -NodeCount 2 -EnableManagedIdentity -NetworkPlugin azure -NodeVmSetType VirtualMachineScaleSets -WindowsProfileAdminUserName $AdminCreds.UserName -WindowsProfileAdminUserPassword $AdminCreds.Password -SshKeyValue $SshKeyValue -Force
}
else {
    $AksCluster = New-AzAksCluster -ResourceGroupName $ResourceGroupName -Name $AKSClusterName -NodeCount 2 -EnableManagedIdentity -NetworkPlugin azure -NodeVmSetType VirtualMachineScaleSets -WindowsProfileAdminUserName $AdminCreds.UserName -WindowsProfileAdminUserPassword $AdminCreds.Password -Force
}

#endregion

#Adding a user mode node pool
$AksNodePool = New-AzAksNodePool -ResourceGroupName $ResourceGroupName -ClusterName $AKSClusterName -VmSetType VirtualMachineScaleSets -OsType Windows -OsSKU Windows2022 -Name $UserNP

#region Connect to the cluster
Import-AzAksCredential -ResourceGroupName $ResourceGroupName -Name $AKSCluster.Name -Force

#Verify the connection to the cluster
kubectl get nodes
#endregion

#region Deploy the application
$AKSClusterFile = Join-Path -Path $CurrentDir -ChildPath "sample.yaml"

kubectl apply -f $AKSClusterFile
Remove-Item -Path $AKSClusterFile -Force
#endregion

#region Test the application
#Check the status of the deployed pods 
kubectl get pods

#Check for a public IP address for the store-front applicatio
While (kubectl get service sample | Select-String -Pattern "pending") {
    Start-Sleep -Seconds 10
}
$ExternalIP = ((kubectl get service sample | Select-Object -Skip 1) -split "\s+")[3]
Start-Process $("http://{0}" -f $ExternalIP)
#endregion
#endregion

<#
#Cleanup
Get-AzResourceGroup "*$ResourceGroupName*" | Remove-AzResourceGroup -Force -AsJob
#>
#endregion
