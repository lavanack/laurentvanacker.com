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
#requires -Version 5 -RunAsAdministrator
Function Update-AutomatedLabRDCMan
{
    [CmdletBinding()]
    param
    (
		[Parameter(Mandatory = $false)]
		[string]$FullName = $(Join-Path -Path $([Environment]::GetFolderPath("MyDocuments")) -ChildPath "$env:USERNAME.rdg"),
        [switch] $Open
    )


    $null = Add-Type -AssemblyName System.Security
    #region variables
    $LabsPath = Join-Path -Path $(Get-LabConfigurationItem -Name LabAppDataRoot) -ChildPath 'Labs'
    $RDGFileContentTemplate = @'
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
                <name>AutomatedLab</name>
            </properties>
            <group>
                <properties>
                    <expanded>False</expanded>
                    <name>Azure</name>
                </properties>
            </group>
            <group>
                <properties>
                    <expanded>False</expanded>
                    <name>HyperV</name>
                </properties>
            </group>
        </group>
    </file>
    <connected />
    <favorites />
    <recentlyUsed />
</RDCMan>
'@
    #endregion

    #Remove-Item -Path $FullName -Force 
    If (-not(Test-Path -Path $FullName)) {
        Write-Verbose -Message "Creating '$FullName' file ..."
        Set-Content -Value $RDGFileContentTemplate -Path $FullName
    }

    $AutomatedLabRDGFileContent = [xml](Get-Content -Path $FullName)
    $AutomatedLabFileElement = $AutomatedLabRDGFileContent.RDCMan.file
    $AutomatedLabGroupElement = $AutomatedLabFileElement.group | Where-Object -FilterScript {
        $_.ChildNodes.Name -eq 'AutomatedLab'
    }

    $XMLLabFiles = Get-ChildItem -Path $LabsPath -Directory -ErrorAction SilentlyContinue | Get-ChildItem -Filter Lab.xml -File

    foreach ($CurrentXMLLabFile in $XMLLabFiles.FullName) {
        Write-Verbose -Message "Processing '$CurrentXMLLabFile' lab ..."
        $CurrentXMLLabFileContent = [xml](Get-Content -Path $CurrentXMLLabFile)
        $XMLMachinesFile = Join-Path -Path $(Split-Path -Path $CurrentXMLLabFile -Parent) -ChildPath 'Machines.xml'
        $CurrentXMLMachinesFileContent = [xml](Get-Content -Path $XMLMachinesFile)
        $Machines = ($CurrentXMLMachinesFileContent.SelectNodes('//Machine'))
        $DefaultVirtualizationEngine = $CurrentXMLLabFileContent.Lab.DefaultVirtualizationEngine
        $LabName = $CurrentXMLLabFileContent.Lab.Name
        Write-Host -Object "Processing Lab: $LabName"
        #region Remove all previously existing nodes with the same name
        #$PreviouslyExistingNodes = $AutomatedLabRDGFileContent.SelectNodes("//group/group/group/properties[contains(name, '$LabName')]")
        $PreviouslyExistingNodes = $AutomatedLabRDGFileContent.SelectNodes("//properties[contains(name, '$LabName')]")
        #$PreviouslyExistingNodes | ForEach-Object -Process {$_.ParentNode.RemoveAll()}
        $PreviouslyExistingNodes | ForEach-Object -Process {
            $ParentNode = $_.ParentNode
            $null = $ParentNode.ParentNode.RemoveChild($ParentNode)
        }
        #endregion 

        #region Dedicated RDG Group creation
        $ParentElement = $AutomatedLabGroupElement.group | Where-Object -FilterScript {
            $_.ChildNodes.Name -eq $DefaultVirtualizationEngine
        }
        $groupElement = $ParentElement.AppendChild($AutomatedLabRDGFileContent.CreateElement('group'))
        $propertiesElement = $groupElement.AppendChild($AutomatedLabRDGFileContent.CreateElement('properties'))
        $nameElement = $propertiesElement.AppendChild($AutomatedLabRDGFileContent.CreateElement('name'))
        $nameTextNode = $nameElement.AppendChild($AutomatedLabRDGFileContent.CreateTextNode($CurrentXMLLabFileContent.Lab.Name))
        $expandedElement = $propertiesElement.AppendChild($AutomatedLabRDGFileContent.CreateElement('expanded'))
        $expandedTextNode = $expandedElement.AppendChild($AutomatedLabRDGFileContent.CreateTextNode('False'))

        #region Credential Management
        $UserName = $CurrentXMLLabFileContent.Lab.Domains.Domain.Administrator.UserName
        $Password = $CurrentXMLLabFileContent.Lab.Domains.Domain.Administrator.Password
        $Domain = $CurrentXMLLabFileContent.Lab.Domains.Domain.Name
        $PasswordBytes = [System.Text.Encoding]::Unicode.GetBytes($Password)
        $SecurePassword = [Security.Cryptography.ProtectedData]::Protect($PasswordBytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
        $SecurePasswordStr = [System.Convert]::ToBase64String($SecurePassword)
        $logonCredentialsElement = $groupElement.AppendChild($AutomatedLabRDGFileContent.CreateElement('logonCredentials'))
        $logonCredentialsElement.SetAttribute('inherit', 'None')
        $profileNameElement = $logonCredentialsElement.AppendChild($AutomatedLabRDGFileContent.CreateElement('profileName'))
        $profileNameElement.SetAttribute('scope', 'Local')
        $profileNameTextNode = $profileNameElement.AppendChild($AutomatedLabRDGFileContent.CreateTextNode('Custom'))
        $UserNameElement = $logonCredentialsElement.AppendChild($AutomatedLabRDGFileContent.CreateElement('UserName'))
        $UserNameTextNode = $UserNameElement.AppendChild($AutomatedLabRDGFileContent.CreateTextNode($UserName))
        $PasswordElement = $logonCredentialsElement.AppendChild($AutomatedLabRDGFileContent.CreateElement('Password'))
        $PasswordTextNode = $PasswordElement.AppendChild($AutomatedLabRDGFileContent.CreateTextNode($SecurePasswordStr))
        $DomainElement = $logonCredentialsElement.AppendChild($AutomatedLabRDGFileContent.CreateElement('Domain'))
        $DomainTextNode = $DomainElement.AppendChild($AutomatedLabRDGFileContent.CreateTextNode($Domain))
        #endregion

        if ($DefaultVirtualizationEngine -eq 'Azure') {
            Import-Lab -Name $LabName
        }

        #region Server Nodes Management
        $ParentElement = $AutomatedLabGroupElement.group | Where-Object -FilterScript {
            $_.ChildNodes.Name -eq $DefaultVirtualizationEngine
        }
        foreach ($CurrentMachine in $Machines) {
            $serverElement = $groupElement.AppendChild($AutomatedLabRDGFileContent.CreateElement('server'))
            $propertiesElement = $serverElement.AppendChild($AutomatedLabRDGFileContent.CreateElement('properties'))
            $displayNameElement = $propertiesElement.AppendChild($AutomatedLabRDGFileContent.CreateElement('displayName'))
            $displayNameTextNode = $displayNameElement.AppendChild($AutomatedLabRDGFileContent.CreateTextNode($CurrentMachine.Name))
            $nameElement = $propertiesElement.AppendChild($AutomatedLabRDGFileContent.CreateElement('name'))
            if ($DefaultVirtualizationEngine -eq 'Azure') {
                $LWAzureVMConnectionInfo = Get-LWAzureVMConnectionInfo -ComputerName (Get-LabVM -ComputerName $CurrentMachine.Name)
                $nameTextNode = $nameElement.AppendChild($AutomatedLabRDGFileContent.CreateTextNode("$($LWAzureVMConnectionInfo.DnsName):$($LWAzureVMConnectionInfo.RdpPort)"))
            }
            else {
                $nameTextNode = $nameElement.AppendChild($AutomatedLabRDGFileContent.CreateTextNode("$($CurrentMachine.Name).$($Domain)"))
            }
        }
        #endregion
        #endregion 
    }
    $AutomatedLabRDGFileContent.Save($FullName)
    if ($Open)
    {
        & $FullName
    }

}

Update-AutomatedLabRDCMan -Open -Verbose