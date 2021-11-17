#requires -Version 5 -RunAsAdministrator 
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent


#region Azure File Share Setup
#    - On CONTOSODC : We create an AD security group for hosting all host pool VMs
    $OUName = "AVD"
    $ADGroup = New-ADGroup -Name "MSIX Hosts" -SamAccountName MSIXHosts -GroupCategory Security -GroupScope Global -DisplayName "MSIX Hosts" -Path "OU=$OUName,$((Get-ADDomain).DistinguishedName)" -PassThru
    Add-ADGroupMember -Identity MSIXHosts -Members $(Get-ADComputer -Filter "Name -like 'HP*'" -SearchBase "OU=$OUName,$((Get-ADDomain).DistinguishedName)")
    Import-Module -Name "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync";Start-ADSyncSyncCycle -PolicyType Delta

#    - It is recommended not locate MSIX packages on same storage as FSLogix in production environment, 
#    - Create a storage account and new file share like explained in Lab 05 / Exercice 1 / Task 1,2 & 3 or run the following command lines from PowerShell Core
    Connect-AzAccount
    $AzContext = Get-AzContext
    $null=$AzContext.Account -match "\w+@(\w+).onmicrosoft.com"
    $SubscriptionId = $AzContext.Subscription.Id
    $resourceGroupName = "rg-ad-westeu-01"
    #$storageAccountName = 'avd'+$Matches[1].ToLower()
    $storageAccountName = 'msix'+$Matches[1].ToLower()
    $region = "westeurope"
    $shareName = "msix"  
    $SkuName = "Standard_ZRS"
    
    #Creating a dedicated storage account for MSIX
    New-AzStorageAccount -ResourceGroupName $resourceGroupName -AccountName $storageAccountName -Location $region -SkuName $SkuName

    #Registering the target storage account with your active directory environment under the target
    Import-Module AzFilesHybrid
    Join-AzStorageAccountForAuth -ResourceGroupName $resourceGroupName -Name $storageAccountName -DomainAccountType "ComputerAccount" -OrganizationalUnitName $OUName

    # Get the target storage account
    $storageaccount = Get-AzStorageAccount -ResourceGroupName $resourceGroupName -Name $storageAccountName

    # List the directory service of the selected service account
    $storageAccount.AzureFilesIdentityBasedAuth.DirectoryServiceOptions

    # List the directory domain information if the storage account has enabled AD authentication for file shares
    $storageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties

    #Create a share for MSIX
    $StorageShare = New-AzRmStorageShare -ResourceGroupName $resourceGroupName -StorageAccountName $storageAccountName -Name $shareName -AccessTier Hot -QuotaGiB 200
    $AzStorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $resourceGroupName -AccountName $storageAccountName) | Where-Object -FilterScript {$_.KeyName -eq "key1"}

    # Save the password so the drive will persist on reboot
    cmd.exe /C "cmdkey /add:`"$storageAccountName.file.core.windows.net`" /user:`"localhost\$storageAccountName`" /pass:`"$($AzStorageAccountKey.Value)`""
    # Mount the share
    New-PSDrive -Name Z -PSProvider FileSystem -Root "\\$storageAccountName.file.core.windows.net\$shareName" -Persist
    $existingAcl = Get-Acl Z:
    $existingAcl.Access | ForEach-Object -Process {$existingAcl.RemoveAccessRule($_)}
    #Disabling inheritance
    $existingAcl.SetAccessRuleProtection($true,$false)

    #Add Full Control for Administrators Group for This folder, subfolders and files
    $identity = "BUILTIN\Administrators"
    $colRights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
    $objType = [System.Security.AccessControl.AccessControlType]::Allow
    # Create a new FileSystemAccessRule object
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule ($identity,$colRights,$InheritanceFlag,$PropagationFlag, $objType)
    # Modify the existing ACL to include the new rule
    $existingAcl.SetAccessRule($AccessRule)

    #Add Modify for CREATOR OWNER Group for Subfolders and files
    $identity = "CREATOR OWNER"
    $colRights = [System.Security.AccessControl.FileSystemRights]::Modify
    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::InheritOnly           
    $objType = [System.Security.AccessControl.AccessControlType]::Allow
    # Create a new FileSystemAccessRule object
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule ($identity,$colRights,$InheritanceFlag,$PropagationFlag, $objType)
    # Modify the existing ACL to include the new rule
    $existingAcl.SetAccessRule($AccessRule)

    #Add Modify for Users Group for This folder only
    $identity = "BUILTIN\Users"
    $colRights = [System.Security.AccessControl.FileSystemRights]::Modify
    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None
    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
    $objType = [System.Security.AccessControl.AccessControlType]::Allow
    # Create a new FileSystemAccessRule object
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule ($identity,$colRights,$InheritanceFlag,$PropagationFlag, $objType)
    # Modify the existing ACL to include the new rule
    $existingAcl.SetAccessRule($AccessRule)

    #Enabling inheritance
    $existingAcl.SetAccessRuleProtection($false, $true)

    # Apply the modified access rule to the folder
    $existingAcl | Set-Acl -Path Z:

    # Unmount the share
    Remove-PSDrive -Name Z

    #Get the name of the custom role
    $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Reader"
    #Constrain the scope to the target file share
    $scope = "/subscriptions/$SubscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Storage/storageAccounts/$storageAccountName/fileServices/default/fileshares/$shareName"
    #Assign the custom role to the target identity with the specified scope.
    $AzADGroup = Get-AzADGroup -SearchString "MSIX Hosts"
    New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $scope
