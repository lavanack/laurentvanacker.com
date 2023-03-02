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

#To run from a Domain Controller
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$ilesHybridZipName = 'AzFilesHybrid.zip'
Set-Location -Path $CurrentDir

#region Azure File Share Setup
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Verbose
Install-Module -Name Az.Accounts, Az.Network, Az.Resources, Az.Storage, PowerShellGet -Force -Verbose
#Update-Module PowerShellGet -Force -Verbose -ErrorAction SilentlyContinue

$OutFile = Join-Path -Path $CurrentDir -ChildPath $ilesHybridZipName
Start-BitsTransfer https://github.com/Azure-Samples/azure-files-samples/releases/latest/download/AzFilesHybrid.zip -destination $OutFile
Expand-Archive -Path $OutFile -DestinationPath $CurrentDir\AzFilesHybrid -Force
Set-Location -Path .\AzFilesHybrid
.\CopyToPSPath.ps1
Set-Location -Path $CurrentDir

#Creating an AD Groups
$AVDOUName = "AVD"
$UserOUName = "OrgUsers"
$AVDUsers="AVD Users"
#Replace with your own AVD resource group
$resourceGroupName = "AVD-ADDS-RG"

$FSLogixContributor="FSLogix Contributor"
$FSLogixElevatedContributor="FSLogix Elevated Contributor"
$FSLogixReader="FSLogix Reader"

$ADGroup = New-ADGroup -Name $AVDUsers -SamAccountName $AVDUsers -GroupCategory Security -GroupScope Global -DisplayName $AVDUsers -Path "OU=$AVDOUName,$((Get-ADDomain).DistinguishedName)" -PassThru
$ADGroup | Add-ADGroupMember -Members $(Get-ADUser -Filter * -SearchBase "OU=$UserOUName,$((Get-ADDomain).DistinguishedName)")

#region FSLogix groups
$ADGroup = New-ADGroup -Name $FSLogixContributor -SamAccountName $FSLogixContributor -GroupCategory Security -GroupScope Global -DisplayName $FSLogixContributor -Path "OU=$AVDOUName,$((Get-ADDomain).DistinguishedName)" -PassThru
$ADGroup | Add-ADGroupMember -Members $AVDUsers

$ADGroup = New-ADGroup -Name $FSLogixElevatedContributor -SamAccountName $FSLogixElevatedContributor -GroupCategory Security -GroupScope Global -DisplayName $FSLogixElevatedContributor -Path "OU=$AVDOUName,$((Get-ADDomain).DistinguishedName)" -PassThru

$ADGroup = New-ADGroup -Name $FSLogixReader -SamAccountName $FSLogixReader -GroupCategory Security -GroupScope Global -DisplayName $FSLogixReader -Path "OU=$AVDOUName,$((Get-ADDomain).DistinguishedName)" -PassThru
#endregion

#Run a sync with Azure AD
Start-Service -Name ADSync -Verbose
Import-Module -Name "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync";Start-ADSyncSyncCycle -PolicyType Delta

#    - It is recommended not locate FSLogix on same storage as MSIX packages in production environment, 
Connect-AzAccount
Get-AzSubscription | Out-GridView -OutputMode Single | Select-AzSubscription
$AzContext = Get-AzContext
$null=$AzContext.Account.Id -match "\w+@(\w+).onmicrosoft.com"
$SubscriptionId = $AzContext.Subscription.Id
#$storageAccountName = 'avd'+$Matches[1].ToLower()
$storageAccountName = 'fslogix'+$Matches[1].ToLower()
    
$region = "EastUS"
$shareName = "profiles", "odfc" 
$SkuName = "Standard_ZRS"

Get-ADComputer -Filter "Name -like '$storageAccountName*'" | Remove-ADComputer -Confirm:$false
    
#Creating a dedicated storage account for FSLogix
$storageaccount = New-AzStorageAccount -ResourceGroupName $resourceGroupName -AccountName $storageAccountName -Location $region -SkuName $SkuName

#Registering the target storage account with your active directory environment under the target
Import-Module AzFilesHybrid
Join-AzStorageAccountForAuth -ResourceGroupName $resourceGroupName -Name $storageAccountName -DomainAccountType "ComputerAccount" -OrganizationalUnitName $AVDOUName

# Get the target storage account
$storageaccount = Get-AzStorageAccount -ResourceGroupName $resourceGroupName -Name $storageAccountName

# List the directory service of the selected service account
$storageAccount.AzureFilesIdentityBasedAuth.DirectoryServiceOptions

# List the directory domain information if the storage account has enabled AD authentication for file shares
$storageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties

$AzStorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $resourceGroupName -AccountName $storageAccountName) | Where-Object -FilterScript {$_.KeyName -eq "key1"}

# Save the password so the drive 
Start-Process -FilePath $env:ComSpec -ArgumentList "/c","cmdkey /add:`"$storageAccountName.file.core.windows.net`" /user:`"localhost\$storageAccountName`" /pass:`"$($AzStorageAccountKey.Value)`""

$ShareName | ForEach-Object -Process { 
    $CurrentShareName = $_
    #Create a share for FSLogix
    $StorageShare = New-AzRmStorageShare -ResourceGroupName $resourceGroupName -StorageAccountName $storageAccountName -Name $CurrentShareName -AccessTier Hot -QuotaGiB 200

    # Mount the share
    New-PSDrive -Name Z -PSProvider FileSystem -Root "\\$storageAccountName.file.core.windows.net\$CurrentShareName"

    #region NTFS permissions for FSLogix
    #From https://blue42.net/windows/changing-ntfs-security-permissions-using-powershell/
    #region Sample NTFS permissions for FSLogix
    $existingAcl = Get-Acl Z:

    #Disabling inheritance
    $existingAcl.SetAccessRuleProtection($true,$false)

    #Remove all inherited permissions from this object.
    $existingAcl.Access | ForEach-Object -Process { $null = $existingAcl.RemoveAccessRule($_) }

    #Add Modify for CREATOR OWNER Group for Subfolders and files only
    $identity = "CREATOR OWNER"
    $colRights = [System.Security.AccessControl.FileSystemRights]::Modify
    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::InheritOnly           
    $objType = [System.Security.AccessControl.AccessControlType]::Allow
    # Create a new FileSystemAccessRule object
    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity,$colRights,$InheritanceFlag,$PropagationFlag, $objType)
    # Modify the existing ACL to include the new rule
    $existingAcl.SetAccessRule($AccessRule)

    #Add Full Control for "Administrators" Group for This folder, subfolders and files
    $identity = "Administrators"
    $colRights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
    $objType = [System.Security.AccessControl.AccessControlType]::Allow
    # Create a new FileSystemAccessRule object
    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity,$colRights,$InheritanceFlag,$PropagationFlag, $objType)
    # Modify the existing ACL to include the new rule
    $existingAcl.SetAccessRule($AccessRule)

    #Add Modify for "Users" Group for This folder only
    $identity = "Users"
    $colRights = [System.Security.AccessControl.FileSystemRights]::Modify
    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None
    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
    $objType = [System.Security.AccessControl.AccessControlType]::Allow
    # Create a new FileSystemAccessRule object
    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity,$colRights,$InheritanceFlag,$PropagationFlag, $objType)
    # Modify the existing ACL to include the new rule
    $existingAcl.SetAccessRule($AccessRule)

    #Enabling inheritance
    $existingAcl.SetAccessRuleProtection($false, $true)

    # Apply the modified access rule to the folder
    $existingAcl | Set-Acl -Path Z:
    #endregion

    # Unmount the share
    Remove-PSDrive -Name Z
    #endregion

    #region RBAC Management
    #Constrain the scope to the target file share
    $scope = "/subscriptions/$SubscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Storage/storageAccounts/$storageAccountName/fileServices/default/fileshares/$CurrentShareName"

    #region Setting up the file share with right RBAC: FSLogix Contributor = "Storage File Data SMB Share Elevated Contributor"
    #Get the name of the custom role
    $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Contributor"
    #Assign the custom role to the target identity with the specified scope.
    $AzADGroup = Get-AzADGroup -SearchString $FSLogixContributor
    New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $scope
    #endregion

    #region Setting up the file share with right RBAC: FSLogix Elevated Contributor = "Storage File Data SMB Share Contributor"
    #Get the name of the custom role
    $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Elevated Contributor"
    #Assign the custom role to the target identity with the specified scope.
    $AzADGroup = Get-AzADGroup -SearchString $FSLogixElevatedContributor
    New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $scope
    #endregion

    #region Setting up the file share with right RBAC: FSLogix Reader = "Storage File Data SMB Share Reader"
    #Get the name of the custom role
    $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Reader"
    #Assign the custom role to the target identity with the specified scope.
    $AzADGroup = Get-AzADGroup -SearchString $FSLogixReader
    New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $scope
    #endregion

    #endregion
}