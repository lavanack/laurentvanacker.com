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

#From https://learn.microsoft.com/en-us/azure/aks/learn/quick-kubernetes-deploy-powershell

[CmdletBinding()]
param
(
)


Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

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
$SubscriptionName = "Cloud Solution Architect"
#region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
$AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
$ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
$shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
#endregion

# Login to your Azure subscription.
While (-not((Get-AzContext).Subscription.Name -eq $SubscriptionName)) {
    Connect-AzAccount
    Get-AzSubscription | Out-GridView -OutputMode Single -Title "Select your Azure Subscription" | Select-AzSubscription
    #$Subscription = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction Ignore
    #Select-AzSubscription -SubscriptionName $SubscriptionName | Select-Object -Property *
}


$Location = "eastus"
$LocationShortName = $shortNameHT[$Location].shortName

#Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
$AKSClusterPrefix = "aks"
$ResourceGroupPrefix = "rg"
$Project = "aks"
$Role = "cluster"
$DigitNumber = 4
$AKSStoreQuickstartURI = 'https://raw.githubusercontent.com/Azure-Samples/aks-store-demo/main/aks-store-quickstart.yaml'

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
    $AksCluster = New-AzAksCluster -ResourceGroupName $ResourceGroupName -Name $AKSClusterName -NodeCount 1 -EnableManagedIdentity -SshKeyValue $SshKeyValue -Force
}
else {
    $AksCluster = New-AzAksCluster -ResourceGroupName $ResourceGroupName -Name $AKSClusterName -NodeCount 1 -EnableManagedIdentity -GenerateSshKey -Force
}

#endregion

#region Connect to the cluster
Import-AzAksCredential -ResourceGroupName $ResourceGroupName -Name $AKSCluster.Name -Force

#Verify the connection to the cluster
kubectl get nodes
#endregion

#region Deploy the application
$AKSClusterFile = Join-Path -Path $CurrentDir -ChildPath "aks-store-quickstart.yaml"
Invoke-RestMethod -Uri $AKSStoreQuickstartURI -OutFile $AKSClusterFile

kubectl apply -f $AKSClusterFile
Remove-Item -Path $AKSClusterFile -Force
#endregion

#region Test the application
#Check the status of the deployed pods 
kubectl get pods

#Check for a public IP address for the store-front applicatio
While (kubectl get service store-front | Select-String -Pattern "pending") {
    Start-Sleep -Seconds 10
}
$ExternalIP = ((kubectl get service store-front | Select-Object -Skip 1) -split "\s+")[3]
Start-Process $("http://{0}" -f $ExternalIP)
#endregion
#endregion

<#
#Cleanup
Get-AzResourceGroup "*$ResourceGroupName*" | Remove-AzResourceGroup -Force -AsJob
#>