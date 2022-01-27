#requires -Version 5 -RunAsAdministrator 
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$AzFilesHybridZipName = 'AzFilesHybrid.zip'
Set-Location -Path $CurrentDir

#region Azure File Share Setup
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Verbose
    Install-Module -Name Az.Accounts, Az.Network, Az.Resources, Az.Storage -Force -Verbose
    Update-Module PowerShellGet -Force -Verbose

    $response = Invoke-WebRequest -Uri https://github.com/Azure-Samples/azure-files-samples/releases
    $LatestRelease = "https://github.com" + $($response.Links | Where-Object { $_.innerText -match $AzFilesHybridZipName} | Select-Object -First 1).href
    $OutFile = Join-Path -Path $CurrentDir -ChildPath $AzFilesHybridZipName
    Invoke-WebRequest -Uri $LatestRelease -OutFile $OutFile
    Expand-Archive -Path $OutFile -DestinationPath $CurrentDir -Force
    Set-Location -Path .\AzFilesHybrid
    .\CopyToPSPath.ps1
    Set-Location -Path $CurrentDir

    #Creating an AD Group for all session hosts
    $OUName = "AVD"
    $ADGroup = New-ADGroup -Name "MSIX Hosts" -SamAccountName MSIXHosts -GroupCategory Security -GroupScope Global -DisplayName "MSIX Hosts" -Path "OU=$OUName,$((Get-ADDomain).DistinguishedName)" -PassThru
    Add-ADGroupMember -Identity MSIXHosts -Members $(Get-ADComputer -Filter "Name -like 'HP*'" -SearchBase "OU=$OUName,$((Get-ADDomain).DistinguishedName)")

    #Creating an AD Group for all share admins (inside the OrgUsers OU)
    $OUName = "OrgUsers"
    $ADGroup = New-ADGroup -Name "MSIX Share Admins" -SamAccountName MSIXShareAdmins -GroupCategory Security -GroupScope Global -DisplayName "MSIX Share Admins" -Path "OU=$OUName,$((Get-ADDomain).DistinguishedName)" -PassThru
    Add-ADGroupMember -Identity MSIXShareAdmins -Members $(Get-ADUser -Filter "Name -like 'ad*'")

    #Creating an AD Group for all test users (inside the OrgUsers OU)
    $OUName = "OrgUsers"
    $ADGroup = New-ADGroup -Name "MSIX Users" -SamAccountName MSIXUsers -GroupCategory Security -GroupScope Global -DisplayName "MSIX Users" -Path "OU=$OUName,$((Get-ADDomain).DistinguishedName)" -PassThru
    Add-ADGroupMember -Identity MSIXUsers -Members $(Get-ADUser -Filter "UserPrincipalName -like '*.onmicrosoft.com'" -SearchBase "OU=$OUName,$((Get-ADDomain).DistinguishedName)")

    #Run a sync with Azure AD
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
    
    $region = "WestEurope"
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

    #region NTFS permissions for MSIX
    #From https://docs.microsoft.com/en-us/azure/virtual-desktop/app-attach-file-share#next-steps
    #From https://blue42.net/windows/changing-ntfs-security-permissions-using-powershell/
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
    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity,$colRights,$InheritanceFlag,$PropagationFlag, $objType)
    # Modify the existing ACL to include the new rule
    $existingAcl.SetAccessRule($AccessRule)

    #Add Full Control for MSIXShareAdmins Group for This folder, subfolders and files
    $identity = "MSIXShareAdmins"
    $colRights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
    $objType = [System.Security.AccessControl.AccessControlType]::Allow
    # Create a new FileSystemAccessRule object
    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity,$colRights,$InheritanceFlag,$PropagationFlag, $objType)
    # Modify the existing ACL to include the new rule
    $existingAcl.SetAccessRule($AccessRule)

    #Add Modify for MSIXUsers Group for This folder, subfolders and files
    $identity = "MSIXUsers"
    $colRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None           
    $objType = [System.Security.AccessControl.AccessControlType]::Allow
    # Create a new FileSystemAccessRule object
    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity,$colRights,$InheritanceFlag,$PropagationFlag, $objType)
    # Modify the existing ACL to include the new rule
    $existingAcl.SetAccessRule($AccessRule)

    #Add Modify for MSIXHosts Group for This folder, subfolders and files
    $identity = "MSIXHosts"
    $colRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
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

    <#
    #region Sample NTFS permissions for FSLogix
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
    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity,$colRights,$InheritanceFlag,$PropagationFlag, $objType)
    # Modify the existing ACL to include the new rule
    $existingAcl.SetAccessRule($AccessRule)

    #Add Modify for CREATOR OWNER Group for Subfolders and files
    $identity = "CREATOR OWNER"
    $colRights = [System.Security.AccessControl.FileSystemRights]::Modify
    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::InheritOnly           
    $objType = [System.Security.AccessControl.AccessControlType]::Allow
    # Create a new FileSystemAccessRule object
    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity,$colRights,$InheritanceFlag,$PropagationFlag, $objType)
    # Modify the existing ACL to include the new rule
    $existingAcl.SetAccessRule($AccessRule)

    #Add Modify for Users Group for This folder only
    $identity = "BUILTIN\Users"
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
    #>
    # Unmount the share
    Remove-PSDrive -Name Z

    #From https://docs.microsoft.com/en-us/azure/virtual-desktop/app-attach-file-share#next-steps
    #Setting up the file share with right RBAC: MSIX Hosts & Users = "Storage File Data SMB Share Contributor" + MSIX Share Admins = Storage File Data SMB Share Elevated Contributor
    #Get the name of the custom role
    $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Contributor"
    #Constrain the scope to the target file share
    $scope = "/subscriptions/$SubscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Storage/storageAccounts/$storageAccountName/fileServices/default/fileshares/$shareName"
    #Assign the custom role to the target identity with the specified scope.
    $AzADGroup = Get-AzADGroup -SearchString "MSIX Hosts"
    New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $scope
    $AzADGroup = Get-AzADGroup -SearchString "MSIX Users" 
    New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $scope

    $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Elevated Contributor"
    #Constrain the scope to the target file share
    $scope = "/subscriptions/$SubscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Storage/storageAccounts/$storageAccountName/fileServices/default/fileshares/$shareName"
    #Assign the custom role to the target identity with the specified scope.
    $AzADGroup = Get-AzADGroup -SearchString "MSIX Share Admins"
    New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $scope


    #Copying the Self-Signed certificate to the MSIX file share
    Copy-Item -Path $CurrentDir\*.pfx -Destination "\\$storageAccountName.file.core.windows.net\$shareName"
    #Copyng the VHD package for MSIX to the MSIX file share
    Copy-Item -Path $CurrentDir\*.vhd -Destination "\\$storageAccountName.file.core.windows.net\$shareName"
#endregion