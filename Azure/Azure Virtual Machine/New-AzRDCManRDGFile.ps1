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
#requires -Version 5 -Modules Az.Compute, Az.Network, Az.Resources


#region Dunction definitions
function New-AzureVMsWithPublicIPRDCManRDGFile {
    [CmdletBinding()]
    Param ()


    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    #region variables
    $RDGFileContentTemplate = @"
<?xml version="1.0" encoding="utf-8"?>
<RDCMan programVersion="2.83" schemaVersion="3">
    <file>
        <credentialsProfiles />
        <properties>
            <expanded>True</expanded>
            <name>RDCManager</name>
        </properties>
        <remoteDesktop inherit="None">
            <sameSizeAsClientArea>True</sameSizeAsClientArea>
            <fullScreen>False</fullScreen>
            <colorDepth>24</colorDepth>
        </remoteDesktop>
        <localResources inherit="None">
            <audioRedirection>Client</audioRedirection>
            <audioRedirectionQuality>Dynamic</audioRedirectionQuality>
            <audioCaptureRedirection>DoNotRecord</audioCaptureRedirection>
            <keyboardHook>FullScreenClient</keyboardHook>
            <redirectClipboard>True</redirectClipboard>
            <redirectDrives>True</redirectDrives>
            <redirectDrivesList>
            </redirectDrivesList>
            <redirectPrinters>False</redirectPrinters>
            <redirectPorts>False</redirectPorts>
            <redirectSmartCards>False</redirectSmartCards>
            <redirectPnpDevices>False</redirectPnpDevices>
        </localResources>
        <group>
            <properties>
                <expanded>True</expanded>
                <name>Azure</name>
            </properties>
        </group>
    </file>
    <connected />
    <favorites />
    <recentlyUsed />
</RDCMan>
"@
    $CurrentSubscription = (Get-AzContext).Subscription
    $RDGFilePath = $(Join-Path -Path $([Environment]::GetFolderPath("Desktop")) -ChildPath "AzureVMsWithPublicIP.rdg")
    #endregion

    #region Listing all Azure VM with a Public IP Address
    $VMsWithPublicIP = foreach ($Subscription in Get-AzSubscription) {
        Write-Host -Object "Switching to '$($Subscription.Name)' Subscription"
        $null = $Subscription | Select-AzSubscription

        foreach ($CurrentVM in Get-AzVM) {
            Write-Host -Object "Processing [$($Subscription.Name)] $($CurrentVM.Name)"
            # Get the network interface of the VM
            $nic = Get-AzNetworkInterface -ResourceGroupName $CurrentVM.ResourceGroupName -Name $CurrentVM.NetworkProfile.NetworkInterfaces[0].Id.Split('/')[-1]
    
            # Get the public IP address of the network interface
            foreach ($ipconfig in $nic.IpConfigurations) {
                if ($ipconfig.PublicIpAddress) {
                    $PublicIP = Get-AzPublicIpAddress -ResourceGroupName $CurrentVM.ResourceGroupName -Name $ipconfig.PublicIpAddress.Id.Split('/')[-1]
                    $DNSLabel = $publicIP.DnsSettings.DomainNameLabel
                    [PSCustomObject]@{
                        SubscriptionName = $Subscription.Name
                        VMName           = $CurrentVM.Name
                        PublicIP         = $PublicIP.IpAddress
                        DNSName          = $("{0}.{1}.cloudapp.azure.com" -f $DNSLabel, $CurrentVM.Location).ToLower()
                    }
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$($Subscription.Name)] '$($CurrentVM.Name)' has the '$($PublicIP.IpAddress)' Public IP Address"
                }
                else {
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$($Subscription.Name)] '$($CurrentVM.Name)' doesn't have a Public IP Address"
                }
            }
        }

    }
    #endregion

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$RDGFilePath' file"
    Set-Content -Value $RDGFileContentTemplate -Path $RDGFilePath

    $AzureVMsWithPublicIPRDCManRDGFileContent = [xml](Get-Content -Path $RDGFilePath)
    $AzureVMsWithPublicIPRDCManFileContent = $AzureVMsWithPublicIPRDCManRDGFileContent.RDCMan.file
    $AzureGroupElement = $AzureVMsWithPublicIPRDCManFileContent.group | Where-Object -FilterScript {
        $_.ChildNodes.Name -eq 'Azure'
    }

    foreach ($CurrentVMWithPublicIP in $VMsWithPublicIP) {

        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing [$($Subscription.Name)] $($CurrentVMWithPublicIP.VMName)"
        #region Dedicated SubscriptionName RDG Group creation
        $groupElement = $AzureVMsWithPublicIPRDCManRDGFileContent.SelectNodes("//properties[contains(name, '$($CurrentVMWithPublicIP.SubscriptionName)')]")

        #If the Subscription Group doesn't exist
        if ([string]::IsNullOrEmpty($groupElement)) {
            $groupElement = $AzureGroupElement.AppendChild($AzureVMsWithPublicIPRDCManRDGFileContent.CreateElement('group'))
            $propertiesElement = $groupElement.AppendChild($AzureVMsWithPublicIPRDCManRDGFileContent.CreateElement('properties'))
            $nameElement = $propertiesElement.AppendChild($AzureVMsWithPublicIPRDCManRDGFileContent.CreateElement('name'))
            $nameTextNode = $nameElement.AppendChild($AzureVMsWithPublicIPRDCManRDGFileContent.CreateTextNode($CurrentVMWithPublicIP.SubscriptionName))
            $expandedElement = $propertiesElement.AppendChild($AzureVMsWithPublicIPRDCManRDGFileContent.CreateElement('expanded'))
            $expandedTextNode = $expandedElement.AppendChild($AzureVMsWithPublicIPRDCManRDGFileContent.CreateTextNode('True'))
        }
        else {
            $groupElement = $groupElement.ParentNode
        }
        #endregion

        #region Server Nodes Management
        if ([string]::IsNullOrEmpty($CurrentVMWithPublicIP.DNSName)) {
            $DisplayName = $CurrentVMWithPublicIP.VMName
            $Name = $CurrentVMWithPublicIP.PublicIP
        }
        else {
            $DisplayName = $CurrentVMWithPublicIP.DNSName
            $Name = $CurrentVMWithPublicIP.DNSName
        }

        $serverElement = $groupElement.AppendChild($AzureVMsWithPublicIPRDCManRDGFileContent.CreateElement('server'))
        $propertiesElement = $serverElement.AppendChild($AzureVMsWithPublicIPRDCManRDGFileContent.CreateElement('properties'))
        $displayNameElement = $propertiesElement.AppendChild($AzureVMsWithPublicIPRDCManRDGFileContent.CreateElement('displayName'))
        $displayNameTextNode = $displayNameElement.AppendChild($AzureVMsWithPublicIPRDCManRDGFileContent.CreateTextNode($DisplayName))
        $nameElement = $propertiesElement.AppendChild($AzureVMsWithPublicIPRDCManRDGFileContent.CreateElement('name'))
        $nameTextNode = $nameElement.AppendChild($AzureVMsWithPublicIPRDCManRDGFileContent.CreateTextNode($Name))
        #endregion
    }
    $AzureVMsWithPublicIPRDCManRDGFileContent.Save($RDGFilePath)
    & $RDGFilePath

    Write-Host -Object "Switching back to '$($CurrentSubscription.Name)' Subscription"
    $null = $CurrentSubscription | Select-AzSubscription
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}
#endregion 

Clear-Host
New-AzureVMsWithPublicIPRDCManRDGFile -Verbose