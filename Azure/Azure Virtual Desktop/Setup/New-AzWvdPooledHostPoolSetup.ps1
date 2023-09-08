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

##requires -Version 5 -Modules Az.Accounts, Az.Compute, Az.DesktopVirtualization, Az.ImageBuilder, Az.Insights, Az.ManagedServiceIdentity, Az.Monitor, Az.Network, Az.KeyVault, Az.OperationalInsights, Az.PrivateDns, Az.Resources, Az.Storage, PowerShellGet -RunAsAdministrator 
#requires -Version 5 -RunAsAdministrator 

#It is recommended not locate FSLogix on same storage as MSIX packages in production environment, 
#To run from a Domain Controller

#region Function definitions
#Based from https://adamtheautomator.com/powershell-random-password/
function New-RandomPassword {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [int] $minLength = 12, ## characters
        [int] $maxLength = 15, ## characters
        [int] $nonAlphaChars = 3,
        [switch] $AsSecureString,
        [switch] $ClipBoard
    )

    Add-Type -AssemblyName 'System.Web'
    $length = Get-Random -Minimum $minLength -Maximum $maxLength
    $RandomPassword = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
    Write-Host "The password is : $RandomPassword"
    if ($ClipBoard) {
        Write-Verbose "The password has beeen copied into the clipboard (Use Win+V) ..."
        $RandomPassword | Set-Clipboard
    }
    if ($AsSecureString) {
        ConvertTo-SecureString -String $RandomPassword -AsPlainText -Force
    }
    else {
        $RandomPassword
    }
}

function Get-AzKeyVaultNameAvailability {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [alias('Name')]
        [string]$VaultName
    )
    #region Azure Context
    # Log in first with Connect-AzAccount if not using Cloud Shell

    $azContext = Get-AzContext
    $SubcriptionID = $azContext.Subscription.Id
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
    $token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'='application/json'
        'Authorization'='Bearer ' + $token.AccessToken
    }
    #endregion
    $Body = [ordered]@{ 
        "name" = $VaultName
        "type" = "Microsoft.KeyVault/vaults"
    }

    $URI = "https://management.azure.com/subscriptions/$SubcriptionID/providers/Microsoft.KeyVault/checkNameAvailability?api-version=2022-07-01"
    try
    {
        # Invoke the REST API
        $Response = Invoke-RestMethod -Method POST -Headers $authHeader -Body $($Body | ConvertTo-Json) -ContentType "application/json" -Uri $URI -ErrorVariable ResponseError
    }
    catch [System.Net.WebException] {   
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        $respStream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($respStream)
        $Response = $reader.ReadToEnd() | ConvertFrom-Json
        if (-not([string]::IsNullOrEmpty($Response.message)))
        {
            Write-Warning -Message $Response.message
        }
    }
    finally 
    {
    }
    return $Response
}

function Grant-ADJoinPermission {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [PSCredential]$Credential,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [alias('OU')]
        [string]$OrganizationalUnit
    )
     # Import the Active Directory module
    Import-Module ActiveDirectory

    $ComputerGUID = "bf967a86-0de6-11d0-a285-00aa003049e2"
    $ObjectTypeGUIDs = @{
	    'Domain-Administer-Server' = 'ab721a52-1e2f-11d0-9819-00aa0040529b'
	    'User-Change-Password' = 'ab721a53-1e2f-11d0-9819-00aa0040529b'
	    'User-Force-Change-Password' = '00299570-246d-11d0-a768-00aa006e0529'
	    'Send-As' = 'ab721a54-1e2f-11d0-9819-00aa0040529b'
	    'Receive-As' = 'ab721a56-1e2f-11d0-9819-00aa0040529b'
	    'Send-To' = 'ab721a55-1e2f-11d0-9819-00aa0040529b'
	    'Domain-Password' = 'c7407360-20bf-11d0-a768-00aa006e0529'
	    'General-Information' = '59ba2f42-79a2-11d0-9020-00c04fc2d3cf'
	    'User-Account-Restrictions' = '4c164200-20c0-11d0-a768-00aa006e0529'
	    'User-Logon' = '5f202010-79a5-11d0-9020-00c04fc2d4cf'
	    'Membership' = 'bc0ac240-79a9-11d0-9020-00c04fc2d4cf'
	    'Open-Address-Book' = 'a1990816-4298-11d1-ade2-00c04fd8d5cd'
	    'Personal-Information' = '77B5B886-944A-11d1-AEBD-0000F80367C1'
	    'Email-Information' = 'E45795B2-9455-11d1-AEBD-0000F80367C1'
	    'Web-Information' = 'E45795B3-9455-11d1-AEBD-0000F80367C1'
	    'DS-Replication-Get-Changes' = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
	    'DS-Replication-Synchronize' = '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2'
	    'DS-Replication-Manage-Topology' = '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2'
	    'Change-Schema-Master' = 'e12b56b6-0a95-11d1-adbb-00c04fd8d5cd'
	    'Change-Rid-Master' = 'd58d5f36-0a98-11d1-adbb-00c04fd8d5cd'
	    'Do-Garbage-Collection' = 'fec364e0-0a98-11d1-adbb-00c04fd8d5cd'
	    'Recalculate-Hierarchy' = '0bc1554e-0a99-11d1-adbb-00c04fd8d5cd'
	    'Allocate-Rids' = '1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd'
	    'Change-PDC' = 'bae50096-4752-11d1-9052-00c04fc2d4cf'
	    'Add-GUID' = '440820ad-65b4-11d1-a3da-0000f875ae0d'
	    'Change-Domain-Master' = '014bf69c-7b3b-11d1-85f6-08002be74fab'
	    'Public-Information' = 'e48d0154-bcf8-11d1-8702-00c04fb96050'
	    'msmq-Receive-Dead-Letter' = '4b6e08c0-df3c-11d1-9c86-006008764d0e'
	    'msmq-Peek-Dead-Letter' = '4b6e08c1-df3c-11d1-9c86-006008764d0e'
	    'msmq-Receive-computer-Journal' = '4b6e08c2-df3c-11d1-9c86-006008764d0e'
	    'msmq-Peek-computer-Journal' = '4b6e08c3-df3c-11d1-9c86-006008764d0e'
	    'msmq-Receive' = '06bd3200-df3e-11d1-9c86-006008764d0e'
	    'msmq-Peek' = '06bd3201-df3e-11d1-9c86-006008764d0e'
	    'msmq-Send' = '06bd3202-df3e-11d1-9c86-006008764d0e'
	    'msmq-Receive-journal' = '06bd3203-df3e-11d1-9c86-006008764d0e'
	    'msmq-Open-Connector' = 'b4e60130-df3f-11d1-9c86-006008764d0e'
	    'Apply-Group-Policy' = 'edacfd8f-ffb3-11d1-b41d-00a0c968f939'
	    'RAS-Information' = '037088f8-0ae1-11d2-b422-00a0c968f939'
	    'DS-Install-Replica' = '9923a32a-3607-11d2-b9be-0000f87a36b2'
	    'Change-Infrastructure-Master' = 'cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd'
	    'Update-Schema-Cache' = 'be2bb760-7f46-11d2-b9ad-00c04f79f805'
	    'Recalculate-Security-Inheritance' = '62dd28a8-7f46-11d2-b9ad-00c04f79f805'
	    'DS-Check-Stale-Phantoms' = '69ae6200-7f46-11d2-b9ad-00c04f79f805'
	    'Certificate-Enrollment' = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
	    'Self-Membership' = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
	    'Validated-DNS-Host-Name' = '72e39547-7b18-11d1-adef-00c04fd8d5cd'
	    'Validated-SPN' = 'f3a64788-5306-11d1-a9c5-0000f80367c1'
	    'Generate-RSoP-Planning' = 'b7b1b3dd-ab09-4242-9e30-9980e5d322f7'
	    'Refresh-Group-Cache' = '9432c620-033c-4db7-8b58-14ef6d0bf477'
	    'SAM-Enumerate-Entire-Domain' = '91d67418-0135-4acc-8d79-c08e857cfbec'
	    'Generate-RSoP-Logging' = 'b7b1b3de-ab09-4242-9e30-9980e5d322f7'
	    'Domain-Other-Parameters' = 'b8119fd0-04f6-4762-ab7a-4986c76b3f9a'
	    'DNS-Host-Name-Attributes' = '72e39547-7b18-11d1-adef-00c04fd8d5cd'
	    'Create-Inbound-Forest-Trust' = 'e2a36dc9-ae17-47c3-b58b-be34c55ba633'
	    'DS-Replication-Get-Changes-All' = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
	    'Migrate-SID-History' = 'BA33815A-4F93-4c76-87F3-57574BFF8109'
	    'Reanimate-Tombstones' = '45EC5156-DB7E-47bb-B53F-DBEB2D03C40F'
	    'Allowed-To-Authenticate' = '68B1D179-0D15-4d4f-AB71-46152E79A7BC'
	    'DS-Execute-Intentions-Script' = '2f16c4a5-b98e-432c-952a-cb388ba33f2e'
	    'DS-Replication-Monitor-Topology' = 'f98340fb-7c5b-4cdb-a00b-2ebdfa115a96'
	    'Update-Password-Not-Required-Bit' = '280f369c-67c7-438e-ae98-1d46f3c6f541'
	    'Unexpire-Password' = 'ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501'
	    'Enable-Per-User-Reversibly-Encrypted-Password' = '05c74c5e-4deb-43b4-bd9f-86664c2a7fd5'
	    'DS-Query-Self-Quota' = '4ecc03fe-ffc0-4947-b630-eb672a8a9dbc'
	    'Private-Information' = '91e647de-d96f-4b70-9557-d63ff4f3ccd8'
	    'Read-Only-Replication-Secret-Synchronization' = '1131f6ae-9c07-11d1-f79f-00c04fc2dcd2'
	    'MS-TS-GatewayAccess' = 'ffa6f046-ca4b-4feb-b40d-04dfee722543'
	    'Terminal-Server-License-Server' = '5805bc62-bdc9-4428-a5e2-856a0f4c185e'
	    'Reload-SSL-Certificate' = '1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8'
	    'DS-Replication-Get-Changes-In-Filtered-Set' = '89e95b76-444d-4c62-991a-0facbeda640c'
	    'Run-Protect-Admin-Groups-Task' = '7726b9d5-a4b4-4288-a6b2-dce952e80a7f'
	    'Manage-Optional-Features' = '7c0e2a7c-a419-48e4-a995-10180aad54dd'
	    'DS-Clone-Domain-Controller' = '3e0f7e18-2c7a-4c10-ba82-4d926db99a3e'
	    'Validated-MS-DS-Behavior-Version' = 'd31a8757-2447-4545-8081-3bb610cacbf2'
	    'Validated-MS-DS-Additional-DNS-Host-Name' = '80863791-dbe9-4eb8-837e-7f0ab55d9ac7'
	    'Certificate-AutoEnrollment' = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
	    'DS-Set-Owner' = '4125c71f-7fac-4ff0-bcb7-f09a41325286'
	    'DS-Bypass-Quota' = '88a9933e-e5c8-4f2a-9dd7-2527416b8092'
	    'DS-Read-Partition-Secrets' = '084c93a2-620d-4879-a836-f0ae47de0e89'
	    'DS-Write-Partition-Secrets' = '94825A8D-B171-4116-8146-1E34D8F54401'
	    'DS-Validated-Write-Computer' = '9b026da6-0d3c-465c-8bee-5199d7165cba'
    }
    $ADRights = @(
        @{
            "ActiveDirectoryRights" = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
            "InheritanceType" = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
            "ObjectType" = "00000000-0000-0000-0000-000000000000"
            "InheritedObjectType" = "00000000-0000-0000-0000-000000000000"
            "AccessControlType" = [System.Security.AccessControl.AccessControlType]::Allow
        }
        @{
            "ActiveDirectoryRights" = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty -bor [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor [System.DirectoryServices.ActiveDirectoryRights]::ReadControl -bor [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl
            "InheritanceType" = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::[System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
            "ObjectType" = "00000000-0000-0000-0000-000000000000"
            "InheritedObjectType" = $ComputerGUID
            "AccessControlType" = [System.Security.AccessControl.AccessControlType]::Allow
        }
        @{
            "ActiveDirectoryRights" = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild -bor [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
            "InheritanceType" = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
            "ObjectType" = $ComputerGUID
            "InheritedObjectType" = "00000000-0000-0000-0000-000000000000"
            "AccessControlType" = [System.Security.AccessControl.AccessControlType]::Allow
        }
        @{
            "ActiveDirectoryRights" = [System.DirectoryServices.ActiveDirectoryRights]::Self
            "InheritanceType" = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::[System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
            "ObjectType" = $ObjectTypeGUIDs.'Validated-SPN'
            "InheritedObjectType" = $ComputerGUID
            "AccessControlType" = [System.Security.AccessControl.AccessControlType]::Allow
        }
        @{
            "ActiveDirectoryRights" = [System.DirectoryServices.ActiveDirectoryRights]::Self
            "InheritanceType" = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::[System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
            "ObjectType" = $ObjectTypeGUIDs.'DNS-Host-Name-Attributes'
            "InheritedObjectType" = $ComputerGUID
            "AccessControlType" = [System.Security.AccessControl.AccessControlType]::Allow
        }
        @{
            "ActiveDirectoryRights" = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
            "InheritanceType" = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
            "ObjectType" = $ObjectTypeGUIDs.'User-Force-Change-Password'
            "InheritedObjectType" = $ComputerGUID
            "AccessControlType" = [System.Security.AccessControl.AccessControlType]::Allow
        }
        @{
            "ActiveDirectoryRights" = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
            "InheritanceType" = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
            "ObjectType" = $ObjectTypeGUIDs.'User-Change-Password'
            "InheritedObjectType" = $ComputerGUID
            "AccessControlType" = [System.Security.AccessControl.AccessControlType]::Allow
        }
    )
    $ADUser = Get-ADUser -Filter "SamAccountName -eq '$($Credential.UserName)'"
    #If the user doesn't exist, we create it
    if (-not($ADUser))
    {
        $ADUser = New-ADUser -Name $Credential.UserName -AccountPassword $Credential.Password -PasswordNeverExpires $true -Enabled $true -Description "Created by PowerShell Script for AD-joined AVD Session Hosts"
        Write-Verbose -Message "Creating '$($ADUser.SamAccountName)' AD User (for adding Azure VM to ADDS)"
    }

    # Define the security SamAccountName (user or group) to which you want to grant the permission
    $IdentityReference = [System.Security.Principal.IdentityReference] $ADUser.SID
    $Permission = Get-Acl "AD:$OrganizationalUnit"

    Write-Verbose -Message "Applying required privileges to '$($Credential.UserName)' AD User (for adding Azure VM to ADDS)"
    foreach ($CurrentADRight in $ADRights) {
        $AccessRule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($IdentityReference, $CurrentADRight.ActiveDirectoryRights, $CurrentADRight.AccessControlType, $CurrentADRight.ObjectType, $CurrentADRight.InheritanceType, $CurrentADRight.InheritedObjectType)
        $Permission.AddAccessRule($AccessRule)
    }

    # Apply the permission recursively to the OU and its descendants
    Get-ADOrganizationalUnit -Filter "DistinguishedName -like '$OrganizationalUnit'" -SearchBase $OrganizationalUnit -SearchScope Subtree | ForEach-Object {
        Write-Verbose -Message "Applying those required privileges to '$_'"
        Set-Acl "AD:$_" $Permission
    }

    Write-Verbose -Message "Permissions granted successfully."
}

function New-AzureComputeGallery {
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $false)]
    [string]$Location = "eastus",
    [Parameter(Mandatory = $false)]
    [string[]]$ReplicationRegions = "eastus2"
  )

  #region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
  $AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
  $ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
  $shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
  #endregion

  #region Set up the environment and variables
  # get existing context
  $AzContext = Get-AzContext
  # Your subscription. This command gets your current subscription
  $subscriptionID = $AzContext.Subscription.Id

  #Timestamp
  $timeInt = (Get-Date -UFormat "%s").Split(".")[0]

  #Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
  $AzureComputeGalleryPrefix = "acg"
  $ResourceGroupPrefix = "rg"

  # Location (see possible locations in the main docs)
  #$Location = "eastus"
  Write-Verbose -Message "`$Location: $Location"
  $LocationShortName = $shortNameHT[$Location].shortName
  Write-Verbose -Message "`$LocationShortName: $LocationShortName"
  #$ReplicationRegions = "eastus2"
  Write-Verbose -Message "`$ReplicationRegions: $($ReplicationRegions -join ', ')"

  $Project = "avd"
  $Role = "aib"
  $TimeInt = (Get-Date -UFormat "%s").Split(".")[0]
  $ResourceGroupName = "{0}-{1}-{2}-{3}-{4}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $TimeInt 
  $ResourceGroupName = $ResourceGroupName.ToLower()
  Write-Verbose -Message "`$ResourceGroupName: $ResourceGroupName"

  # Image template and definition names
  #AVD MultiSession Session Image Market Place Image + customizations: VSCode
  $imageDefName01 = "win11-22h2-ent-avd-custom-vscode"
  $imageTemplateName01 = $imageDefName01 + "-template-" + $timeInt
  #AVD MultiSession + Microsoft 365 Market Place Image + customizations: VSCode
  $imageDefName02 = "win11-22h2-ent-avd-m365-vscode"
  $imageTemplateName02 = $imageDefName02 + "-template-" + $timeInt
  Write-Verbose -Message "`$imageDefName01: $imageDefName01"
  Write-Verbose -Message "`$imageTemplateName01: $imageTemplateName01"
  Write-Verbose -Message "`$imageDefName02: $imageDefName02"
  Write-Verbose -Message "`$imageTemplateName02: $imageTemplateName02"

  # Distribution properties object name (runOutput). Gives you the properties of the managed image on completion
  $runOutputName01 = "cgOutput01"
  $runOutputName02 = "cgOutput02"

  #$Version = "1.0.0"
  $Version = Get-Date -UFormat "%Y.%m.%d"
  $Jobs = @()
  #endregion
  #endregion

  # Create resource group
  if (Get-AzResourceGroup -Name $ResourceGroupName -Location $location -ErrorAction Ignore) {
    Write-Verbose -Message "Removing '$ResourceGroupName' Resource Group Name ..."
    Remove-AzResourceGroup -Name $ResourceGroupName -Force
  }
  Write-Verbose -Message "Creating '$ResourceGroupName' Resource Group Name ..."
  $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $location -Force

  #region Permissions, user identity, and role
  # setup role def names, these need to be unique
  $imageRoleDefName = "Azure Image Builder Image Def - $timeInt"
  $identityName = "aibIdentity-$timeInt"
  Write-Verbose -Message "`$imageRoleDefName: $imageRoleDefName"
  Write-Verbose -Message "`$identityName: $identityName"


  # Create the identity
  Write-Verbose -Message "Creating User Assigned Identity '$identityName' ..."
  $AssignedIdentity = New-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $identityName -Location $location

  #$aibRoleImageCreationUrl="https://raw.githubusercontent.com/PeterR-msft/M365AVDWS/master/Azure%20Image%20Builder/aibRoleImageCreation.json"
  #$aibRoleImageCreationUrl="https://raw.githubusercontent.com/azure/azvmimagebuilder/main/solutions/12_Creating_AIB_Security_Roles/aibRoleImageCreation.json"
  #$aibRoleImageCreationUrl="https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Azure%20Image%20Builder/aibRoleImageCreation.json"
  $aibRoleImageCreationUrl = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Azure%20Image%20Builder/aibRoleImageCreation.json"
  #$aibRoleImageCreationPath = "aibRoleImageCreation.json"
  $aibRoleImageCreationPath = Join-Path -Path $CurrentDir -ChildPath $(Split-Path $aibRoleImageCreationUrl -Leaf)
  #Generate a unique file name 
  $aibRoleImageCreationPath = $aibRoleImageCreationPath -replace ".json$", "_$timeInt.json"
  Write-Verbose -Message "`$aibRoleImageCreationPath: $aibRoleImageCreationPath"

  # Download the config
  Invoke-WebRequest -Uri $aibRoleImageCreationUrl -OutFile $aibRoleImageCreationPath -UseBasicParsing

  ((Get-Content -path $aibRoleImageCreationPath -Raw) -replace '<subscriptionID>', $subscriptionID) | Set-Content -Path $aibRoleImageCreationPath
  ((Get-Content -path $aibRoleImageCreationPath -Raw) -replace '<rgName>', $ResourceGroupName) | Set-Content -Path $aibRoleImageCreationPath
  ((Get-Content -path $aibRoleImageCreationPath -Raw) -replace 'Azure Image Builder Service Image Creation Role', $imageRoleDefName) | Set-Content -Path $aibRoleImageCreationPath

  # Create a role definition
  Write-Verbose -Message "Creating '$imageRoleDefName' Role Definition ..."
  $RoleDefinition = New-AzRoleDefinition -InputFile $aibRoleImageCreationPath

  # Grant the role definition to the VM Image Builder service principal
  Write-Verbose -Message "Assigning '$($RoleDefinition.Name)' Role to '$($AssignedIdentity.Name)' ..."
  Do
  {
    Write-Verbose -Message "Sleeping 10 seconds ..."
    Start-Sleep -Seconds 10
    $RoleAssignment = New-AzRoleAssignment -ObjectId $AssignedIdentity.PrincipalId -RoleDefinitionName $RoleDefinition.Name -Scope $ResourceGroup.ResourceId -ErrorAction Ignore #-Debug
  } While ($null -eq $RoleAssignment)
  
  <#
  While (-not(Get-AzRoleAssignment -ObjectId $AssignedIdentity.PrincipalId -RoleDefinitionName $RoleDefinition.Name -Scope $ResourceGroup.ResourceId))
  {
      Start-Sleep -Seconds 10
  }
  #>

  #To allow Azure VM Image Builder to distribute images to either the managed images or to a Azure Compute Gallery, you will need to provide Contributor permissions for the service "Azure Virtual Machine Image Builder" (ApplicationId: cf32a0cc-373c-47c9-9156-0db11f6a6dfc) on the resource group.
  # assign permissions for the resource group, so that AIB can distribute the image to it
  <#
  Install-Module -Name AzureAD -Force
  Connect-AzureAD
  $ApplicationId = (Get-AzureADServicePrincipal -SearchString "Azure Virtual Machine Image Builder").AppId
  #>
  #New-AzRoleAssignment -ApplicationId cf32a0cc-373c-47c9-9156-0db11f6a6dfc -Scope $ResourceGroup.ResourceId -RoleDefinitionName Contributor
  #endregion

  #region Create an Azure Compute Gallery
  $GalleryName = "{0}_{1}_{2}_{3}" -f $AzureComputeGalleryPrefix, $Project, $LocationShortName, $timeInt
  Write-Verbose -Message "`$GalleryName: $GalleryName"

  # Create the gallery
  Write-Verbose -Message "Creating Azure Compute Gallery '$GalleryName' ..."
  $Gallery = New-AzGallery -GalleryName $GalleryName -ResourceGroupName $ResourceGroupName -Location $location
  #endregion

  #region Template #1 via a customized JSON file
  #Based on https://github.com/Azure/azvmimagebuilder/tree/main/solutions/14_Building_Images_WVD
  # Create the gallery definition
  Write-Verbose -Message "Creating Azure Compute Gallery Image Definition '$imageDefName01' (From Customized JSON)..."
  $GalleryImageDefinition01 = New-AzGalleryImageDefinition -GalleryName $GalleryName -ResourceGroupName $ResourceGroupName -Location $location -Name $imageDefName01 -OsState generalized -OsType Windows -Publisher 'Contoso' -Offer 'Windows' -Sku 'avd-win11' -HyperVGeneration V2

  #region Download and configure the template
  #$templateUrl="https://raw.githubusercontent.com/azure/azvmimagebuilder/main/solutions/14_Building_Images_WVD/armTemplateWVD.json"
  #$templateFilePath = "armTemplateWVD.json"
  $templateUrl = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Azure%20Image%20Builder/armTemplateAVD.json"
  $templateFilePath = Join-Path -Path $CurrentDir -ChildPath $(Split-Path $templateUrl -Leaf)
  #Generate a unique file name 
  $templateFilePath = $templateFilePath -replace ".json$", "_$timeInt.json"
  Write-Verbose -Message "`$templateFilePath: $templateFilePath  ..."

  Invoke-WebRequest -Uri $templateUrl -OutFile $templateFilePath -UseBasicParsing

  ((Get-Content -path $templateFilePath -Raw) -replace '<subscriptionID>', $subscriptionID) | Set-Content -Path $templateFilePath
  ((Get-Content -path $templateFilePath -Raw) -replace '<rgName>', $ResourceGroupName) | Set-Content -Path $templateFilePath
  #((Get-Content -path $templateFilePath -Raw) -replace '<region>',$location) | Set-Content -Path $templateFilePath
  ((Get-Content -path $templateFilePath -Raw) -replace '<runOutputName>', $runOutputName01) | Set-Content -Path $templateFilePath

  ((Get-Content -path $templateFilePath -Raw) -replace '<imageDefName>', $imageDefName01) | Set-Content -Path $templateFilePath
  ((Get-Content -path $templateFilePath -Raw) -replace '<sharedImageGalName>', $GalleryName) | Set-Content -Path $templateFilePath
  ((Get-Content -path $templateFilePath -Raw) -replace '<region1>', $replicationRegions) | Set-Content -Path $templateFilePath
  ((Get-Content -path $templateFilePath -Raw) -replace '<imgBuilderId>', $AssignedIdentity.Id) | Set-Content -Path $templateFilePath
  ((Get-Content -path $templateFilePath -Raw) -replace '<version>', $version) | Set-Content -Path $templateFilePath
  #endregion

  #region Submit the template
  Write-Verbose -Message "Starting Resource Group Deployment from '$templateFilePath' ..."
  $ResourceGroupDeployment = New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateFile $templateFilePath -TemplateParameterObject @{"api-Version" = "2020-02-14" } -imageTemplateName $imageTemplateName01 -svclocation $location

  #region Build the image
  Write-Verbose -Message "Starting Image Builder Template from '$imageTemplateName01' (As Job) ..."
  $Jobs += Start-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateName01 -AsJob
  #endregion
  #endregion
  #endregion

  #region Template #2 via a image from the market place + customizations
  # create gallery definition
  $GalleryParams = @{
    GalleryName       = $GalleryName
    ResourceGroupName = $ResourceGroupName
    Location          = $location
    Name              = $imageDefName02
    OsState           = 'generalized'
    OsType            = 'Windows'
    Publisher         = 'Contoso'
    Offer             = 'Windows'
    Sku               = 'Win11WVD'
    HyperVGeneration  = 'V2'
  }
  Write-Verbose -Message "Creating Azure Compute Gallery Image Definition '$imageDefName02' (From A Market Place Image)..."
  $GalleryImageDefinition02 = New-AzGalleryImageDefinition @GalleryParams

  $SrcObjParams = @{
    PlatformImageSource = $true
    Publisher           = 'MicrosoftWindowsDesktop'
    Offer               = 'Office-365'    
    Sku                 = 'win11-22h2-avd-m365'  
    Version             = 'latest'
  }
  Write-Verbose -Message "Creating Azure Image Builder Template Source Object  ..."
  $srcPlatform = New-AzImageBuilderTemplateSourceObject @SrcObjParams

  $disObjParams = @{
    SharedImageDistributor = $true
    GalleryImageId         = "$($GalleryImageDefinition02.Id)/versions/$version"
    ArtifactTag            = @{source = 'avd-win11'; baseosimg = 'windows11' }

    # 1. Uncomment following line for a single region deployment.
    #ReplicationRegion = $location

    # 2. Uncomment following line if the custom image should be replicated to another region(s).
    ReplicationRegion      = @($location) + $replicationRegions

    RunOutputName          = $runOutputName02
    ExcludeFromLatest      = $false
  }
  Write-Verbose -Message "Creating Azure Image Builder Template Distributor Object  ..."
  $disSharedImg = New-AzImageBuilderTemplateDistributorObject @disObjParams

  $ImgCustomParams = @{  
    PowerShellCustomizer = $true  
    Name                 = 'InstallVSCode'  
    RunElevated          = $true  
    runAsSystem          = $true  
    ScriptUri            = 'https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Azure%20Image%20Builder/Install-VSCode.ps1'
  }

  Write-Verbose -Message "Creating Azure Image Builder Template Customizer Object  ..."
  $Customizer = New-AzImageBuilderTemplateCustomizerObject @ImgCustomParams 

  #Create an Azure Image Builder template and submit the image configuration to the Azure VM Image Builder service:
  $ImgTemplateParams = @{
    ImageTemplateName      = $imageTemplateName02
    ResourceGroupName      = $ResourceGroupName
    Source                 = $srcPlatform
    Distribute             = $disSharedImg
    Customize              = $Customizer
    Location               = $location
    UserAssignedIdentityId = $AssignedIdentity.Id
    VMProfileVmsize        = "Standard_D4s_v3"
    VMProfileOsdiskSizeGb  = 127
  }
  Write-Verbose -Message "Creating Azure Image Builder Template from '$imageTemplateName02' Image Template Name ..."
  $ImageBuilderTemplate = New-AzImageBuilderTemplate @ImgTemplateParams

  #region Build the image
  #Start the image building process using Start-AzImageBuilderTemplate cmdlet:
  Write-Verbose -Message "Starting Image Builder Template from '$imageTemplateName02' (As Job) ..."
  $Jobs += Start-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateName02 -AsJob
  #endregion

  Write-Verbose -Message "Waiting for jobs to complete ..."
  $Jobs | Wait-Job | Out-Null

  #region imageTemplateName01 status 
  #To determine whenever or not the template upload process was successful, run the following command.
  $getStatus01 = Get-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateName01
  # Optional - if you have any errors running the preceding command, run:
  Write-Verbose -Message "'$imageTemplateName01' ProvisioningErrorCode: $($getStatus01.ProvisioningErrorCode) "
  Write-Verbose -Message "'$imageTemplateName01' ProvisioningErrorMessage: $($getStatus01.ProvisioningErrorMessage) "
  # Shows the status of the build
  Write-Verbose -Message "'$imageTemplateName01' LastRunStatusRunState: $($getStatus01.LastRunStatusRunState) "
  Write-Verbose -Message "'$imageTemplateName01' LastRunStatusMessage: $($getStatus01.LastRunStatusMessage) "
  Write-Verbose -Message "'$imageTemplateName01' LastRunStatusRunSubState: $($getStatus01.LastRunStatusRunSubState) "
  Write-Verbose -Message "Removing Azure Image Builder Template for '$imageTemplateName01' ..."
  $null = $getStatus01 | Remove-AzImageBuilderTemplate -AsJob
  Write-Verbose -Message "Removing '$aibRoleImageCreationPath' ..."
  Write-Verbose -Message "Removing '$templateFilePath' ..."
  Remove-Item -Path $aibRoleImageCreationPath, $templateFilePath -Force
  #endregion

  #region imageTemplateName02 status
  #To determine whenever or not the template upload process was successful, run the following command.
  $getStatus02 = Get-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateName02
  # Optional - if you have any errors running the preceding command, run:
  Write-Verbose -Message "'$imageTemplateName02' ProvisioningErrorCode: $($getStatus02.ProvisioningErrorCode) "
  Write-Verbose -Message "'$imageTemplateName02' ProvisioningErrorMessage: $($getStatus02.ProvisioningErrorMessage) "
  # Shows the status of the build
  Write-Verbose -Message "'$imageTemplateName02' LastRunStatusRunState: $($getStatus02.LastRunStatusRunState) "
  Write-Verbose -Message "'$imageTemplateName02' LastRunStatusMessage: $($getStatus02.LastRunStatusMessage) "
  Write-Verbose -Message "'$imageTemplateName02' LastRunStatusRunSubState: $($getStatus02.LastRunStatusRunSubState) "
  #endregion

  Write-Verbose -Message "Removing Azure Image Builder Template for '$imageTemplateName02' ..."
  $null = $getStatus02 | Remove-AzImageBuilderTemplate -AsJob
  Write-Verbose -Message "Removing jobs ..."
  $Jobs | Remove-Job
  #endregion

  $EndTime = Get-Date
  $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
  Write-Verbose -Message "Total Processing Time: $($TimeSpan.ToString())"
  #Adding a delete lock (for preventing accidental deletion)
  #New-AzResourceLock -LockLevel CanNotDelete -LockNotes "$ResourceGroupName - CanNotDelete" -LockName "$ResourceGroupName - CanNotDelete" -ResourceGroupName $ResourceGroupName -Force
  #region Clean up your resources
  <#
  ## Remove the Resource Group
  Remove-AzResourceGroup $ResourceGroupName -Force -AsJob
  ## Remove the definitions
  Remove-AzRoleDefinition -Name $RoleDefinition.Name -Force
  #>
  #endregion
  
  return $Gallery
}

#Get The Azure VM Compute Object for the VM executing this function
function Get-AzVMCompute {
    [CmdletBinding()]
    Param(
    )
    $uri = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

    try {
        $response = Invoke-RestMethod -Uri $uri -Headers @{"Metadata"="true"} -Method GET -TimeoutSec 5
        return $response.compute
    }
    catch {
        return $null
    }
}

function New-AzAvdSessionHost {
    [CmdletBinding(DefaultParameterSetName = 'Image')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Id')]
        [String]$HostPoolId, 
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [ValidateLength(2,13)]
        [string]$NamePrefix,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [ValidateScript({$_ -gt 0})]
        [int]$VMNumberOfInstances,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [PSCredential]$LocalAdminCredential,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [PSCredential]$ADDomainJoinUPNCredential,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [String]$RegistrationInfoToken,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [String]$OUPath,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [String]$DomainName,
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [string]$VMSize = "Standard_D2s_v3",
        [Parameter(Mandatory = $false, ParameterSetName = 'Image', ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [string]$ImagePublisherName = "microsoftwindowsdesktop",
        [Parameter(Mandatory = $false, ParameterSetName = 'Image', ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [string]$ImageOffer = "office-365",
        [Parameter(Mandatory = $false, ParameterSetName = 'Image', ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [string]$ImageSku = "win11-22h2-avd-m365",
        [Parameter(Mandatory = $true, ParameterSetName = 'ACG', ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$VMSourceImageId
    )
    $OSDiskSize = "127"
    $OSDiskType = "Premium_LRS"
    $ThisDomainController = Get-AzVMCompute | Get-AzVM
    # Get the VM's network interface
    $ThisDomainControllerNetworkInterfaceId = $ThisDomainController.NetworkProfile.NetworkInterfaces[0].Id
    $ThisDomainControllerNetworkInterface = Get-AzNetworkInterface -ResourceId $ThisDomainControllerNetworkInterfaceId
    # Get the subnet ID
    $ThisDomainControllerSubnetId = $ThisDomainControllerNetworkInterface.IpConfigurations[0].Subnet.Id
    $ThisDomainControllerSubnet = Get-AzVirtualNetworkSubnetConfig -ResourceId $ThisDomainControllerSubnetId
    $split = $ThisDomainControllerSubnetId.split('/')
    # Get the vnet ID
    $ThisDomainControllerVirtualNetwork = $split[0..($split.Count - 3)] -join "/"
    $ThisDomainControllerVirtualNetwork = Get-AzResource -ResourceId $ThisDomainControllerVirtualNetworkId | Get-AzVirtualNetwork

    if ($null -eq (Get-AZVMSize -Location $ThisDomainControllerVirtualNetwork.Location | Where-Object -FilterScript { $_.Name -eq $VMSize })) {
        Write-Error "The '$VMSize' is not available in the '$Location' location ..." -ErrorAction Stop
    }
    $HostPool = Get-AzResource -ResourceId $HostPoolId
    $ExistingSessionHostNames = (Get-AzWvdSessionHost -ResourceGroupName $HostPool.ResourceGroupName -HostPoolName $HostPool.Name).ResourceId -replace ".*/"
    $ExistingSessionHostNamesWithSameNamePrefix = $ExistingSessionHostNames -match "$NamePrefix-"
    if (-not([string]::IsNullOrEmpty($ExistingSessionHostNamesWithSameNamePrefix)))
    {
        $VMIndexes =  $ExistingSessionHostNamesWithSameNamePrefix -replace "\D"
        if ([string]::IsNullOrEmpty($VMIndexes))
        {
            $Start = 0
        }
        else
        {
            #We take the highest existing VM index and restart just after
            $Start = ($VMIndexes | Measure-Object -Maximum).Maximum+1
        }
    }
    else
    {
        $Start = 0
    }
    $End = $Start+$VMNumberOfInstances-1
    foreach ($Index in $Start..$End)
    {
        $CurrentVMName = '{0}-{1}' -f $NamePrefix, $Index
        Write-Verbose -Message "Creating Session Host: '$CurrentVMName' ..."
        $NICName = "nic-$CurrentVMName"
        $OSDiskName = '{0}_OSDisk' -f $CurrentVMName
        #$DataDiskName = "$VMName-DataDisk01"

        #Create Network Interface Card 
        $NIC = New-AzNetworkInterface -Name $NICName -ResourceGroupName $HostPool.ResourceGroupName -Location $ThisDomainControllerVirtualNetwork.Location -SubnetId $ThisDomainControllerSubnet.Id -Force

        #Create a virtual machine configuration file (As a Spot Intance for sqving costs . DON'T DO THAT IN A PRODUCTION ENVIRONMENT !!!)
        $VMConfig = New-AzVMConfig -VMName $CurrentVMName -VMSize $VMSize -Priority "Spot" -MaxPrice -1
        $null = Add-AzVMNetworkInterface -VM $VMConfig -Id $NIC.Id

        #Set VM operating system parameters
        $null = Set-AzVMOperatingSystem -VM $VMConfig -Windows -ComputerName $CurrentVMName -Credential $LocalAdminCredential -ProvisionVMAgent

        #Set boot diagnostic to managed storage account
        $null = Set-AzVMBootDiagnostic -VM $VMConfig -Enable 

        #Set virtual machine source image
        if (-not([string]::IsNullOrEmpty($VMSourceImageId)))
        {
            Write-Verbose "Building Azure VM via `$VMSourceImageId:$VMSourceImageId"
            $null = Set-AzVMSourceImage -VM $VMConfig -Id $VMSourceImageId
        }
        else
        {
            Write-Verbose "Building Azure VM via `$ImagePublisherName:$ImagePublisherName/`$ImageOffer:$ImageOffer/`$ImageSku:$ImageSku"
            $null = Set-AzVMSourceImage -VM $VMConfig -PublisherName $ImagePublisherName -Offer $ImageOffer -Skus $ImageSku -Version 'latest'
        }

        #Set OsDisk configuration
        $null = Set-AzVMOSDisk -VM $VMConfig -Name $OSDiskName -DiskSizeInGB $OSDiskSize -StorageAccountType $OSDiskType -CreateOption fromImage

        #Create Azure Virtual Machine
        $null = New-AzVM -ResourceGroupName $HostPool.ResourceGroupName -Location $ThisDomainControllerVirtualNetwork.Location -VM $VMConfig #-DisableBginfoExtension

        $VM = Get-AzVM -ResourceGroup $HostPool.ResourceGroupName -Name $CurrentVMName
        $null = Start-AzVM -Name $CurrentVMName -ResourceGroupName $HostPool.ResourceGroupName
        $ExtensionName = "joindomain$("{0:yyyyMMddHHmmss}" -f (Get-Date))"

        Write-Verbose -Message "Adding '$CurrentVMName' to '$DomainName' AD domain ..."
        $null = Set-AzVMADDomainExtension -Name $ExtensionName -DomainName $DomainName -OUPath $OUPath -VMName $CurrentVMName -Credential $ADDomainJoinUPNCredential -ResourceGroupName $HostPool.ResourceGroupName -JoinOption 0x00000003 -Restart

        $DSCConfigurationName = "AddSessionHost"

        $DSCConfigurationArguments = @{ 
            hostPoolName                           = $HostPool.Name
            RegistrationInfoToken                  = $RegistrationInfoToken
            aadJoin                                = $false
        }

        #From https://www.rozemuller.com/avd-automation-cocktail-avd-automated-with-powershell/
        #Date : 08/17/2023
        $avdModuleLocation = "https://wvdportalstorageblob.blob.core.windows.net/galleryartifacts/Configuration_1.0.02411.177.zip"
        $avdDscSettings = @{
            Name               = "Microsoft.PowerShell.DSC"
            Type               = "DSC" 
            Publisher          = "Microsoft.Powershell"
            typeHandlerVersion = "2.73"
            SettingString      = "{
                ""modulesUrl"":'$avdModuleLocation',
                ""ConfigurationFunction"":""Configuration.ps1\\AddSessionHost"",
                ""Properties"": {
                    ""hostPoolName"": ""$($HostPool.Name)"",
                    ""RegistrationInfoToken"": ""$($RegistrationInfoToken)"",
                    ""aadJoin"": false
                }
            }"
            VMName             = $CurrentVMName
            ResourceGroupName  = $HostPool.ResourceGroupName
            location           = $ThisDomainControllerVirtualNetwork.Location
        }
        Write-Verbose -Message "Adding '$CurrentVMName' to '$($HostPool.Name)' Host Pool ..."
        $null = Set-AzVMExtension @avdDscSettings 
    }
}

function Copy-MSIXDemoPackage {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Destination
    )   
    $URI = "https://api.github.com/repos/lavanack/laurentvanacker.com/contents/Azure/Azure%20Virtual%20Desktop/MSIX/MSIX"
    $Response = Invoke-WebRequest -Uri $URI
    $Objects = $Response.Content | ConvertFrom-Json
    $Files = $Objects | Where-Object -FilterScript {$_.type -eq "file"} | Select-Object -ExpandProperty download_url
    $VHDFileURIs = $Files -match "\.vhd$"

    Write-Verbose -Message "VHD File Source URIs: $($VHDFileURIs -join ',')" 
    #Copying the VHD package for MSIX to the MSIX file share    
    Start-BitsTransfer -Source $VHDFileURIs -Destination $Destination
    $MSIXDemoPackage = $VHDFileURIs | ForEach-Object -Process { Join-Path -Path $Destination -ChildPath $($_ -replace ".*/") }
    return $MSIXDemoPackage
}

function Copy-MSIXDemoPFXFile {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()] 
        [string[]]$SessionHosts,
        [Parameter(Mandatory = $false)]
        [ValidateNotNull()] 
        [System.Security.SecureString]$SecurePassword = $(ConvertTo-SecureString -String "P@ssw0rd" -AsPlainText -Force)
    )   

    $URI = "https://api.github.com/repos/lavanack/laurentvanacker.com/contents/Azure/Azure%20Virtual%20Desktop/MSIX/MSIX"
    $Response = Invoke-WebRequest -Uri $URI
    $Objects = $Response.Content | ConvertFrom-Json
    $Files = $Objects | Where-Object -FilterScript {$_.type -eq "file"} | Select-Object -ExpandProperty download_url
    $PFXFileURIs = $Files -match "\.pfx$"

    #Copying the PFX files for MSIX to a temp local folder
    $TempFolder = New-Item -Path $(Join-Path -Path $env:TEMP -ChildPath $("{0:yyyyMMddHHmmss}" -f (Get-Date))) -ItemType Directory -Force
    #Copying the Self-Signed certificate to the MSIX file share
    Start-BitsTransfer -Source $PFXFileURIs -Destination $TempFolder
    $DownloadedPFXFiles = Get-ChildItem -Path $TempFolder -Filter *.pfx -File

    $Session = New-PSSession -ComputerName $SessionHosts
    #Copying the PFX to all session hosts
    $Session | ForEach-Object -Process { Copy-Item -Path $DownloadedPFXFiles.FullName -Destination C:\ -ToSession $_ -Force}

    Invoke-command -Session $Session -ScriptBlock {
        $using:DownloadedPFXFiles | ForEach-Object -Process { 
            $LocalFile = $(Join-Path -Path C: -ChildPath $_.Name)
            #Adding the self-signed certificate to the Trusted Root Certification Authorities (To validate this certificate)
            $ImportPfxCertificates = Import-PfxCertificate $LocalFile -CertStoreLocation Cert:\LocalMachine\TrustedPeople\ -Password $using:SecurePassword 
            Write-Verbose -Message $($ImportPfxCertificates | Out-String)
            #Removing the PFX file (useless now)
            Remove-Item -Path $LocalFile -Force
            gpupdate /force /wait:-1 /target:computer 
        }
    }
    #Removing the Temp folder (useless now)
    Remove-Item -Path $TempFolder -Recurse -Force
}

function Disable-WindowsUpdateScheduledStartScheduledTask {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()] 
        [string[]]$SessionHosts
    )   

    $Session = New-PSSession -ComputerName $SessionHosts
    Invoke-command -Session $Session -ScriptBlock {
        $null = Disable-ScheduledTask -TaskPath "\Microsoft\Windows\WindowsUpdate\" -TaskName "Scheduled Start" -ErrorAction Ignore
    }
}

function Remove-AzWvdPooledHostPoolSetup {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [alias('Name')]
        [object[]]$PooledHostPool
    )
    #region Cleanup of the previously existing resources
    #region DNS Cleanup
    $OUDistinguishedNames = (Get-ADOrganizationalUnit -Filter * | Where-Object -FilterScript {$_.Name -in $($PooledHostPools.Name)}).DistinguishedName 
    if (-not([string]::IsNullOrEmpty($OUDistinguishedNames)))
    {
        $OUDistinguishedNames | ForEach-Object -Process {
            Write-Verbose "Processing OU: $_ ..."
            (Get-ADComputer -Filter 'DNSHostName -like "*"' -SearchBase $_).Name } | ForEach-Object -Process { 
                    try {
                        Write-Verbose "Removing DNS Record: $_ ..."
                        Remove-DnsServerResourceRecord -ZoneName $((Get-ADDomain).DNSRoot) -RRType "A" -Name "$_" -Force -ErrorAction Ignore
                    } 
                    catch {} 
               }
    }
    #endregion
    #region AD OU/GPO Cleanup
    Write-Verbose "Removing OUs ..."
    Get-ADOrganizationalUnit -Filter * | Where-Object -FilterScript {$_.Name -in $($PooledHostPools.Name) -or $_.Name -in 'AVD', 'PooledDesktops', 'PersonalDesktops'} | Set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $false -PassThru -ErrorAction Ignore | Remove-ADOrganizationalUnit -Recursive -Confirm:$false #-WhatIf
    Write-Verbose "Removing GPOs ..."
    Get-GPO -All | Where-Object -FilterScript {($_.DisplayName -match $($PooledHostPools.Name -join "|")) -or ($_.DisplayName -in 'AVD - Global Settings', 'PooledDesktops - FSLogix Global Settings', 'Group Policy Reporting Firewall Ports', 'Group Policy Remote Update Firewall Ports')} | Remove-GPO #-WhatIf
    #endregion
    #region Azure Cleanup
    <#
    $HostPool = (Get-AzWvdHostPool | Where-Object -FilterScript {$_.Name -in $($PooledHostPools.Name)})
    Write-Verbose "Getting HostPool(s): $($HostPool.Name -join, ', ') ..."
    $ResourceGroup = $HostPool | ForEach-Object { Get-AzResourceGroup $_.Id.split('/')[4]}
    #Alternative to get the Resource Group(s)
    #$ResourceGroup = Get-AzResourceGroup  | Where-Object -FilterScript {($_.ResourceGroupName -match $($PooledHostPools.Name -join "|"))
    #>
    $ResourceGroupName = ($PooledHostPools.Name | ForEach-Object -Process { "rg-avd-$($_)"})
    Write-Verbose "ResourceGroup Name(s): $($ResourceGroupName -join, ', ') ..."
    $ResourceGroup = Get-AzResourceGroup  | Where-Object -FilterScript {($_.ResourceGroupName -in $ResourceGroupName)}

    Write-Verbose "Removing Azure Delete Lock (if any) on Resource Group(s): $($ResourceGroup.ResourceGroupName -join, ', ') ..."
    $ResourceGroup | Foreach-Object -Process {Get-AzResourceLock -ResourceGroupName $_.ResourceGroupName -AtScope | Where-Object -FilterScript {$_.Properties.level -eq 'CanNotDelete'}} | Remove-AzResourceLock -Force -ErrorAction Ignore

    Write-Verbose "Removing Resource Group(s): $($ResourceGroup.ResourceGroupName -join, ', ') ..."
    $Jobs = $ResourceGroup | Remove-AzResourceGroup -Force -AsJob
    $Jobs | Wait-Job
    $Jobs | Remove-Job

    #region
    #Removing Dedicated HostPool Key Vault in removed state
    Write-Verbose "Removing Dedicated HostPool Key Vault in removed state ..."
    $Jobs = Get-AzKeyVault -InRemovedState | Where-Object -FilterScript {($_.VaultName -match $($(($PooledHostPools.Name -replace "\W").ToLower()) -join "|"))} | Remove-AzKeyVault -InRemovedState -AsJob -Force 
    $Jobs | Wait-Job
    $Jobs | Remove-Job
    #endregion
    #endregion
    #region Run a sync with Azure AD
    if (Get-Service -Name ADSync -ErrorAction Ignore)
    {
        Start-Service -Name ADSync
        Import-Module -Name "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync"
        if (-not(Get-ADSyncConnectorRunStatus)) {
            Write-Verbose "Running a sync with Azure AD ..."
            $null = Start-ADSyncSyncCycle -PolicyType Delta
        }
    }
}

function New-AzWvdPooledHostPoolSetup {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [alias('Name')]
        [object[]]$PooledHostPool
    )

    begin {
        #region Get the vnet and subnet where this DC is connected to
        # Get the VM networking data
        $ThisDomainController = Get-AzVMCompute | Get-AzVM
        # Get the VM's network interface
        $ThisDomainControllerNetworkInterfaceId = $ThisDomainController.NetworkProfile.NetworkInterfaces[0].Id
        $ThisDomainControllerNetworkInterface = Get-AzNetworkInterface -ResourceId $ThisDomainControllerNetworkInterfaceId

        # Get the subnet ID
        $ThisDomainControllerSubnetId = $ThisDomainControllerNetworkInterface.IpConfigurations[0].Subnet.Id
        $split = $ThisDomainControllerSubnetId.split('/')
        # Get the vnet ID
        $ThisDomainControllerVirtualNetworkId = $split[0..($split.Count - 3)] -join "/"
        $ThisDomainControllerVirtualNetwork = Get-AzResource -ResourceId $ThisDomainControllerVirtualNetworkId | Get-AzVirtualNetwork

        # Get the subnet details
        $ThisDomainControllerSubnet = Get-AzVirtualNetworkSubnetConfig -ResourceId $ThisDomainControllerSubnetId
        #endregion

        #region AVD OU Management
        $DefaultNamingContext = (Get-ADRootDSE).defaultNamingContext
        $DomainName = (Get-ADDomain).DNSRoot

        $AVDRootOU = Get-ADOrganizationalUnit -Filter 'Name -eq "AVD"' -SearchBase $DefaultNamingContext
        if (-not($AVDRootOU)) {
            $AVDRootOU = New-ADOrganizationalUnit -Name "AVD" -Path $DefaultNamingContext -ProtectedFromAccidentalDeletion $true -PassThru
            Write-Verbose -Message "Creating '$($AVDRootOU.DistinguishedName)' OU (under '$DefaultNamingContext') ..."
        }
        #Blocking Inheritance
        $null = $AVDRootOU | Set-GPInheritance -IsBlocked Yes

        #region AVD GPO Management
        $AVDGPO = Get-GPO -Name "AVD - Global Settings" -ErrorAction Ignore
        if (-not($AVDGPO)) {
            $AVDGPO = New-GPO -Name "AVD - Global Settings" -ErrorAction Ignore
            Write-Verbose -Message "Creating '$($AVDGPO.DisplayName)' GPO (linked to '$($AVDRootOU.DistinguishedName)' OU) ..."
        }
        $null = $AVDGPO | New-GPLink -Target $AVDRootOU.DistinguishedName -LinkEnabled Yes -ErrorAction Ignore

        Write-Verbose -Message "Setting GPO Setting for $($AVDGPO.DisplayName)' GPO (linked to '$($AVDRootOU.DistinguishedName)' OU) ..."
        #region Network Settings
        #From https://learn.microsoft.com/en-us/training/modules/configure-user-experience-settings/4-configure-user-settings-through-group-policies
        Write-Verbose -Message "Setting some 'Network Settings' related registry values for '$($AVDGPO.DisplayName)' GPO (linked to '$($AVDRootOU.DistinguishedName)' OU) ..."
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\Windows\BITS' -ValueName "DisableBranchCache" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\PeerDist\Service' -ValueName "Enable" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\Windows\HotspotAuthentication' -ValueName "Enabled" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\Software\policies\Microsoft\Peernet' -ValueName "Disabled" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\Windows\NetCache' -ValueName "Enabled" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
        #endregion

        #region Session Time Settings
        #From https://learn.microsoft.com/en-us/training/modules/configure-user-experience-settings/6-configure-session-timeout-properties
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_SESSIONS_Idle_Limit_1
        Write-Verbose -Message "Setting some 'Session Time Settings' related registry values for '$($AVDGPO.DisplayName)' GPO (linked to '$($AVDRootOU.DistinguishedName)' OU) ..."
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "MaxIdleTime" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 900000
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_SESSIONS_Disconnected_Timeout_1
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "MaxDisconnectionTime" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 900000
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_SESSIONS_Limits_2
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "MaxConnectionTime" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_Session_End_On_Limit_2
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "fResetBroken" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
        #endregion

        #region Enable Screen Capture Protection
        #From https://learn.microsoft.com/en-us/training/modules/manage-access/5-configure-screen-capture-protection-for-azure-virtual-desktop
        #Value 2 is for blocking screen capture on client and server.
        Write-Verbose -Message "Setting some 'Enable Screen Capture Protection' related registry values for '$($AVDGPO.DisplayName)' GPO (linked to '$($AVDRootOU.DistinguishedName)' OU) ..."
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "fEnableScreenCaptureProtection" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 2
        #endregion

        #region Enabling and using the new performance counters
        #From https://learn.microsoft.com/en-us/training/modules/install-configure-apps-session-host/10-troubleshoot-application-issues-user-input-delay
        Write-Verbose -Message "Setting some 'Performance Counters' related registry values for '$($AVDGPO.DisplayName)' GPO (linked to '$($AVDRootOU.DistinguishedName)' OU) ..."
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\System\CurrentControlSet\Control\Terminal Server' -ValueName "EnableLagCounter" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
        #endregion 

        $PersonalDesktopsOU = Get-ADOrganizationalUnit -Filter 'Name -eq "PersonalDesktops"' -SearchBase $AVDRootOU.DistinguishedName
        if (-not($PersonalDesktopsOU)) {
            $PersonalDesktopsOU = New-ADOrganizationalUnit -Name "PersonalDesktops" -Path $AVDRootOU.DistinguishedName -ProtectedFromAccidentalDeletion $false -PassThru
            Write-Verbose -Message "Creating '$($PersonalDesktopsOU.DistinguishedName)' OU (under '$($AVDRootOU.DistinguishedName)') ..."
        }
        $PooledDesktopsOU = Get-ADOrganizationalUnit -Filter 'Name -eq "PooledDesktops"' -SearchBase $AVDRootOU.DistinguishedName
        if (-not($PooledDesktopsOU)) {
            $PooledDesktopsOU = New-ADOrganizationalUnit -Name "PooledDesktops" -Path $AVDRootOU.DistinguishedName -ProtectedFromAccidentalDeletion $false -PassThru
            Write-Verbose -Message "Creating '$($PooledDesktopsOU.DistinguishedName)' OU (under '$($AVDRootOU.DistinguishedName)') ..."
        }
        #region Starter GPOs Management
        Write-Verbose -Message "Starter GPOs Management ..."
        try
        {
            $null = Get-GPStarterGPO -Name "Group Policy Reporting Firewall Ports" -ErrorAction Stop
        }
        catch 
        {
            <#
            Write-Warning "The required starter GPOs are not installed. Please click on the 'Create Starter GPOs Folder' under Group Policy Management / Forest / Domains / $DomainName / Starter GPOs before continuing"
            Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "gpmc.msc" -Wait
            #>
            $OutFile = Join-Path -Path $env:Temp -ChildPath StarterGPOs.zip
            Invoke-WebRequest -Uri https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Setup/StarterGPOs.zip -OutFile $OutFile
            $DestinationPath = "\\{0}\SYSVOL\{0}" -f $((Get-ADDomain).DNSRoot)
            Expand-Archive -Path $OutFile -DestinationPath $DestinationPath
            Remove-Item -Path $OutFile -Force -ErrorAction Ignore
        }
        #region These Starter GPOs include policy settings to configure the firewall rules required for GPO operations
        if (-not(Get-GPO -Name "Group Policy Reporting Firewall Ports" -ErrorAction Ignore))
        {
            $GPO = Get-GPStarterGPO -Name "Group Policy Reporting Firewall Ports" | New-GPO -Name "Group Policy Reporting Firewall Ports"
            Write-Verbose -Message "Creating '$($GPO.DisplayName)' Starter GPO ..."
        }
        $GPLink = $GPO | New-GPLink -Target $AVDRootOU.DistinguishedName -LinkEnabled Yes -ErrorAction Ignore
        Write-Verbose -Message "Linking '$($GPO.DisplayName)' Starter GPO to '$($AVDRootOU.DistinguishedName)' OU ..."
        if (-not(Get-GPO -Name "Group Policy Remote Update Firewall Ports" -ErrorAction Ignore))
        {
            $GPO = Get-GPStarterGPO -Name "Group Policy Remote Update Firewall Ports" | New-GPO -Name "Group Policy Remote Update Firewall Ports"
            Write-Verbose -Message "Creating '$($GPO.DisplayName)' Starter GPO ..."
        }
        $GPLink = $GPO | New-GPLink -Target $AVDRootOU.DistinguishedName -LinkEnabled Yes -ErrorAction Ignore
        Write-Verbose -Message "Linking '$($GPO.DisplayName)' Starter GPO to '$($AVDRootOU.DistinguishedName)' OU ..."
        #endregion
        #endregion
        #endregion

        #region FSLogix GPO Management
        $FSLogixGPO = Get-GPO -Name "PooledDesktops - FSLogix Global Settings" -ErrorAction Ignore
        if (-not($FSLogixGPO)) {
            $FSLogixGPO = New-GPO -Name "PooledDesktops - FSLogix Global Settings" -ErrorAction Ignore
            Write-Verbose -Message "Creating '$($FSLogixGPO.DisplayName)' GPO (linked to '($($PooledDesktopsOU.DistinguishedName))' ..."
        }
        $null = $FSLogixGPO | New-GPLink -Target $PooledDesktopsOU.DistinguishedName -LinkEnabled Yes -ErrorAction Ignore
        #region Top GPO used for setting up all configuration settings for FSLogix profiles but the VHDLocations that will be set per HostPool (1 storage account per HostPool)
        #From https://learn.microsoft.com/en-us/fslogix/tutorial-configure-profile-containers#profile-container-configuration
        Write-Verbose -Message "Setting some 'FSLogix' related registry values for 'PooledDesktops - FSLogix Global Settings' GPO (linked to '$($PooledDesktopsOU.DistinguishedName)' OU) ..."
        $null = Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "Enabled" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
        $null = Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "DeleteLocalProfileWhenVHDShouldApply" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
        $null = Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "FlipFlopProfileDirectoryName" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
        $null = Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "LockedRetryCount" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 3
        $null = Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "LockedRetryInterval" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 15
        $null = Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "ProfileType" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 0
        $null = Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "ReAttachIntervalSeconds" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 15
        $null = Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "ReAttachRetryCount" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 3
        $null = Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "SizeInMBs" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 30000
        $null = Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "ProfileType" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 0

        $null = Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "PreventLoginWithFailure" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
        $null = Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "PreventLoginWithTempProfile" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
        $null = Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "VolumeType" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "VHDX"
        $null = Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "LogFileKeepingPeriod" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 10
        $null = Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "IsDynamic" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
        #From https://learn.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image#disable-automatic-updates
        $null = Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueName "NoAutoUpdate" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
        #From https://learn.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image#set-up-time-zone-redirection
        $null = Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "fEnableTimeZoneRedirection" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
        #From https://learn.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image#disable-storage-sense
        $null = Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -ValueName "01" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0

        #region GPO Debug log file
        #From https://blog.piservices.fr/post/2017/12/21/active-directory-debug-avance-de-l-application-des-gpos
        $null = Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics' -ValueName "GPSvcDebugLevel" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0x30002
        #endregion

        <#
        #region Microsoft Defender Endpoint A/V General Exclusions
        #From https://learn.microsoft.com/en-us/fslogix/overview-prerequisites#configure-antivirus-file-and-folder-exclusions
        $null = Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions' -ValueName "Exclusions_Paths" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
        $null = Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "TempFolderVHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%TEMP%\*\*.VHD"
        $null = Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "TempFolderVHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%TEMP%\*\*.VHDX"
        $null = Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "WindirTempFolderVHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%Windir%\TEMP\*\*.VHD"
        $null = Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "WindirTempFolderVHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%Windir%\TEMP\*\*.VHDX"
        $null = Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "FSLogixCache" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%ProgramData%\FSLogix\Cache\*"
        $null = Set-GPRegistryValue -Name $FSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "FSLogixProxy" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%ProgramData%\FSLogix\Proxy\*"
        #endregion
        #> 
        #endregion 
        #endregion 

        #region Variables
        $FSLogixContributor = "FSLogix Contributor"
        $FSLogixElevatedContributor = "FSLogix Elevated Contributor"
        $FSLogixReader = "FSLogix Reader"
        $FSLogixShareName = "profiles", "odfc" 

        $MSIXHosts = "MSIX Hosts"
        $MSIXShareAdmins = "MSIX Share Admins"
        $MSIXUsers = "MSIX Users"
        $MSIXShareName = "msix"  

        $SKUName = "Standard_ZRS"
        $CurrentPooledHostPoolStorageAccountNameMaxLength = 24
        $CurrentPooledHostPoolKeyVaultNameMaxLength = 24

        #From https://www.youtube.com/watch?v=lvBiLj7oAG4&t=2s
        $RedirectionsXMLFileContent = @'
<?xml version="1.0"  encoding="UTF-8"?>
<FrxProfileFolderRedirection ExcludeCommonFolders="49">
<Excludes>
<Exclude Copy="0">AppData\Roaming\Microsoft\Teams\media-stack</Exclude>
<Exclude Copy="0">AppData\Local\Microsoft\Teams\meeting-addin\Cache</Exclude>
<Exclude Copy="0">AppData\Local\Microsoft\Outlook</Exclude>
<Exclude Copy="0">AppData\Local\Microsoft\OneDrive</Exclude>
<Exclude Copy="0">AppData\Local\Microsoft\Edge</Exclude>
</Excludes>
<Includes>
<Include>AppData\Local\Microsoft\Edge\User Data</Include>
</Includes>
</FrxProfileFolderRedirection>
'@
        #endregion 

        #region Assigning the Desktop Virtualization Power On Contributor
        #From https://learn.microsoft.com/en-us/azure/virtual-desktop/start-virtual-machine-connect?tabs=azure-portal#assign-the-desktop-virtualization-power-on-contributor-role-with-the-azure-portal
        $objId = (Get-AzADServicePrincipal -AppId "9cdead84-a844-4324-93f2-b2e6bb768d07").Id
        $SubscriptionId = (Get-AzContext).Subscription.Id
        $Scope="/subscriptions/$SubscriptionId"
        if (-not(Get-AzRoleAssignment -RoleDefinitionName "Desktop Virtualization Power On Contributor" -Scope $Scope)) {
            Write-Verbose -Message "Assigning the 'Desktop Virtualization Power On Contributor' RBAC role to Service Principal '$objId' on the Subscription '$SubscriptionId' ..."
            $null = New-AzRoleAssignment -ObjectId $objId -RoleDefinitionName "Desktop Virtualization Power On Contributor" -Scope $Scope
        }
        #endregion
    }
    process {
        Foreach ($CurrentPooledHostPool in $PooledHostPool) {
            #region General AD Management
            #region Host Pool Management: Dedicated AD OU Setup (1 OU per HostPool)
            $CurrentPooledHostPoolOU = Get-ADOrganizationalUnit -Filter "Name -eq '$($CurrentPooledHostPool.Name)'" -SearchBase $PooledDesktopsOU.DistinguishedName
            if (-not($CurrentPooledHostPoolOU)) {
                $CurrentPooledHostPoolOU = New-ADOrganizationalUnit -Name "$($CurrentPooledHostPool.Name)" -Path $PooledDesktopsOU.DistinguishedName -ProtectedFromAccidentalDeletion $false -PassThru
                Write-Verbose -Message "Creating '$($CurrentPooledHostPoolOU.DistinguishedName)' OU (under '$($PooledDesktopsOU.DistinguishedName)') ..."
            }
            Grant-ADJoinPermission -Credential $CurrentPooledHostPool.ADDomainJoinCredential -OrganizationalUnit $CurrentPooledHostPoolOU.DistinguishedName
            #endregion

            #region Host Pool Management: Dedicated AD users group
            $CurrentPooledHostPoolUsersADGroupName = "$($CurrentPooledHostPool.Name) - Users"
            $CurrentPooledHostPoolADGroup = Get-ADGroup -Filter "Name -eq '$CurrentPooledHostPoolUsersADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentPooledHostPoolOU.DistinguishedName
            if (-not($CurrentPooledHostPoolADGroup)) {
                Write-Verbose -Message "Creating '$CurrentPooledHostPoolUsersADGroupName' AD Group (under '$($CurrentPooledHostPoolOU.DistinguishedName)') ..."
                $CurrentPooledHostPoolUsersADGroup = New-ADGroup -Name $CurrentPooledHostPoolUsersADGroupName -SamAccountName $CurrentPooledHostPoolUsersADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentPooledHostPoolUsersADGroupName -Path $CurrentPooledHostPoolOU.DistinguishedName -PassThru
            }
            #endregion
            #endregion

            #region FSLogix

            #region FSLogix AD Management

            #region Dedicated HostPool AD group
            #region Dedicated HostPool AD FSLogix groups
            $CurrentPooledHostPoolFSLogixContributorADGroupName = "$($CurrentPooledHostPool.Name) - $FSLogixContributor"
            $CurrentPooledHostPoolFSLogixContributorADGroup = Get-ADGroup -Filter "Name -eq '$CurrentPooledHostPoolFSLogixContributorADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentPooledHostPoolOU.DistinguishedName
            if (-not($CurrentPooledHostPoolFSLogixContributorADGroup)) {
                $CurrentPooledHostPoolFSLogixContributorADGroup = New-ADGroup -Name $CurrentPooledHostPoolFSLogixContributorADGroupName -SamAccountName $CurrentPooledHostPoolFSLogixContributorADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentPooledHostPoolFSLogixContributorADGroupName -Path $CurrentPooledHostPoolOU.DistinguishedName -PassThru
                Write-Verbose -Message "Creating '$($CurrentPooledHostPoolFSLogixContributorADGroup.Name)' AD Group (under '$($CurrentPooledHostPoolOU.DistinguishedName)') ..."
            }
            Write-Verbose -Message "Adding the '$CurrentPooledHostPoolUsersADGroupName' AD group to the '$CurrentPooledHostPoolFSLogixContributorADGroupName' AD Group (under '$($CurrentPooledHostPoolOU.DistinguishedName)') ..."
            $CurrentPooledHostPoolFSLogixContributorADGroup | Add-ADGroupMember -Members $CurrentPooledHostPoolUsersADGroupName

            $CurrentPooledHostPoolFSLogixElevatedContributorADGroupName = "$($CurrentPooledHostPool.Name) - $FSLogixElevatedContributor"
            $CurrentPooledHostPoolFSLogixElevatedContributorADGroup = Get-ADGroup -Filter "Name -eq '$CurrentPooledHostPoolFSLogixElevatedContributorADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentPooledHostPoolOU.DistinguishedName
            if (-not($CurrentPooledHostPoolFSLogixElevatedContributorADGroup)) {
                $CurrentPooledHostPoolFSLogixElevatedContributorADGroup = New-ADGroup -Name $CurrentPooledHostPoolFSLogixElevatedContributorADGroupName -SamAccountName $CurrentPooledHostPoolFSLogixElevatedContributorADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentPooledHostPoolFSLogixElevatedContributorADGroupName -Path $CurrentPooledHostPoolOU.DistinguishedName -PassThru
                Write-Verbose -Message "Creating '$($CurrentPooledHostPoolFSLogixElevatedContributorADGroup.Name)' AD Group (under '$($CurrentPooledHostPoolOU.DistinguishedName)') ..."
            }

            $CurrentPooledHostPoolFSLogixReaderADGroupName = "$($CurrentPooledHostPool.Name) - $FSLogixReader"
            $CurrentPooledHostPoolFSLogixReaderADGroup = Get-ADGroup -Filter "Name -eq '$CurrentPooledHostPoolFSLogixReaderADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentPooledHostPoolOU.DistinguishedName
            if (-not($CurrentPooledHostPoolFSLogixReaderADGroup)) {
                $CurrentPooledHostPoolFSLogixReaderADGroup = New-ADGroup -Name $CurrentPooledHostPoolFSLogixReaderADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentPooledHostPoolFSLogixReaderADGroupName -Path $CurrentPooledHostPoolOU.DistinguishedName -PassThru
                Write-Verbose -Message "Creating '$($CurrentPooledHostPoolFSLogixReaderADGroup.Name)' AD Group (under '$($CurrentPooledHostPoolOU.DistinguishedName)') ..."
            }
            #endregion
            #endregion

            #region Run a sync with Azure AD
            if (Get-Service -Name ADSync -ErrorAction Ignore)
            {
                Start-Service -Name ADSync
                Import-Module -Name "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync"
                if (-not(Get-ADSyncConnectorRunStatus)) {
                    Write-Verbose "Running a sync with Azure AD ..."
                    $null = Start-ADSyncSyncCycle -PolicyType Delta
                }
            }
            Write-Verbose -Message "Sleeping 30 seconds ..."
            Start-Sleep -Seconds 30
            #endregion 
            #endregion

            #region FSLogix Storage Account Management
            #region FSLogix Storage Account Name Setup
            $CurrentPooledHostPoolStorageAccountName = "fsl{0}" -f $($CurrentPooledHostPool.Name -replace "\W")
            $CurrentPooledHostPoolStorageAccountName = $CurrentPooledHostPoolStorageAccountName.Substring(0, [system.math]::min($CurrentPooledHostPoolStorageAccountNameMaxLength, $CurrentPooledHostPoolStorageAccountName.Length)).ToLower()
            #endregion 

            #region Dedicated Host Pool AD GPO Management (1 GPO per Host Pool for setting up the dedicated VHDLocations/CCDLocations value)
            $CurrentPooledHostPoolFSLogixGPO = Get-GPO -Name "$($CurrentPooledHostPool.Name) - FSLogix Settings" -ErrorAction Ignore
            if (-not($CurrentPooledHostPoolFSLogixGPO)) {
                $CurrentPooledHostPoolFSLogixGPO = New-GPO -Name "$($CurrentPooledHostPool.Name) - FSLogix Settings"
                Write-Verbose -Message "Creating '$($CurrentPooledHostPoolFSLogixGPO.DisplayName)' GPO (linked to '($($CurrentPooledHostPoolOU.DistinguishedName))' ..."
            }
            $null = $CurrentPooledHostPoolFSLogixGPO | New-GPLink -Target $CurrentPooledHostPoolOU.DistinguishedName -LinkEnabled Yes -ErrorAction Ignore

            #region Dedicated GPO settings for FSLogix profiles for this HostPool 
            Write-Verbose -Message "Setting some 'FSLogix' related registry values for '$($CurrentPooledHostPoolFSLogixGPO.DisplayName)' GPO (linked to '$($CurrentPooledHostPoolOU.DistinguishedName)' OU) ..."
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "VHDLocations" -Type ([Microsoft.Win32.RegistryValueKind]::MultiString) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles"
            #Use Redirections.xml. Be careful : https://twitter.com/JimMoyle/status/1247843511413755904w
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "RedirXMLSourceFolder" -Type ([Microsoft.Win32.RegistryValueKind]::MultiString) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles"
            #endregion

            #region Microsoft Defender Endpoint A/V General Exclusions
            #From https://learn.microsoft.com/en-us/fslogix/overview-prerequisites#configure-antivirus-file-and-folder-exclusions
            Write-Verbose -Message "Setting some 'Microsoft Defender Endpoint A/V General Exclusions' related registry values for '$($CurrentPooledHostPoolFSLogixGPO.DisplayName)' GPO (linked to '$($CurrentPooledHostPoolOU.DistinguishedName)' OU) ..."
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions' -ValueName "Exclusions_Paths" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "TempFolderVHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%TEMP%\*\*.VHD"
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "TempFolderVHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%TEMP%\*\*.VHDX"
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "WindirTempFolderVHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%Windir%\TEMP\*\*.VHD"
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "WindirTempFolderVHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%Windir%\TEMP\*\*.VHDX"
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "FSLogixCache" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%ProgramData%\FSLogix\Cache\*"
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "FSLogixProxy" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%ProgramData%\FSLogix\Proxy\*"
            #endregion 

            #region Microsoft Defender Endpoint A/V Exclusions for this HostPool 
            #From https://learn.microsoft.com/en-us/fslogix/overview-prerequisites#configure-antivirus-file-and-folder-exclusions
            Write-Verbose -Message "Setting some 'Microsoft Defender Endpoint A/V Exclusions for this HostPool' related registry values for '$($CurrentPooledHostPoolFSLogixGPO.DisplayName)' GPO (linked to '$($CurrentPooledHostPoolOU.DistinguishedName)' OU) ..."
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "FSLogixSharedFolderVHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHD"
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "FSLogixSharedFolderVHDLock" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHD.lock"
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "FSLogixSharedFolderVHDMeta" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHD.meta"
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "FSLogixSharedFolderVHDMetaData" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHD.metadata"
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "FSLogixSharedFolderVHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHDX"
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "FSLogixSharedFolderVHDXLock" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHDX.lock"
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "FSLogixSharedFolderVHDXMeta" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHDX.meta"
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "FSLogixSharedFolderVHDXMetaData" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHDX.metadata"
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "FSLogixSharedFolderCIM" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.CIM"
            #endregion

            #region GPO "Local Users and Groups" Management via groups.xml
            #From https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/37722b69-41dd-4813-8bcd-7a1b4d44a13d
            #From https://jans.cloud/2019/08/microsoft-fslogix-profile-container/
            $GroupXMLGPOFilePath = "\\{0}\SYSVOL\{0}\Policies\{{{1}}}\Machine\Preferences\Groups\Groups.xml" -f $DomainName, $($CurrentPooledHostPoolFSLogixGPO.Id)
            Write-Verbose -Message "Creating '$GroupXMLGPOFilePath' ..."
            #Generating an UTC time stamp
            $Changed = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
            #$ADGroupToExcludeFromFSLogix = @('Domain Admins', 'Enterprise Admins')
            $ADGroupToExcludeFromFSLogix = @('Domain Admins')
            $Members = foreach ($CurrentADGroupToExcludeFromFSLogix in $ADGroupToExcludeFromFSLogix)
            {
                $CurrentADGroupToExcludeFromFSLogixSID = (Get-ADGroup -Filter "Name -eq '$CurrentADGroupToExcludeFromFSLogix'").SID.Value
                if (-not([string]::IsNullOrEmpty($CurrentADGroupToExcludeFromFSLogixSID)))
                {
                    Write-Verbose -Message "Excluding '$CurrentADGroupToExcludeFromFSLogix' from '$GroupXMLGPOFilePath' ..."
                    "<Member name=""$((Get-ADDomain).NetBIOSName)\$CurrentADGroupToExcludeFromFSLogix"" action=""ADD"" sid=""$CurrentADGroupToExcludeFromFSLogixSID""/>"
                }
            }
            $Members = $Members -join ""

            $GroupXMLGPOFileContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
	<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="FSLogix ODFC Exclude List" image="2" changed="$Changed" uid="{$((New-Guid).Guid.ToUpper())}"><Properties action="U" newName="" description="Members of this group are on the exclude list for Outlook Data Folder Containers" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="" groupName="FSLogix ODFC Exclude List"><Members>$Members</Members></Properties></Group>
	<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="FSLogix ODFC Include List" image="2" changed="$Changed" uid="{$((New-Guid).Guid.ToUpper())}"><Properties action="U" newName="" description="Members of this group are on the include list for Outlook Data Folder Containers" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupName="FSLogix ODFC Include List"/></Group>
	<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="FSLogix Profile Exclude List" image="2" changed="$Changed" uid="{$((New-Guid).Guid.ToUpper())}" userContext="0" removePolicy="0"><Properties action="U" newName="" description="Members of this group are on the exclude list for dynamic profiles" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="" groupName="FSLogix Profile Exclude List"><Members>$Members</Members></Properties></Group>
	<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="FSLogix Profile Include List" image="2" changed="$Changed" uid="{$((New-Guid).Guid.ToUpper())}"><Properties action="U" newName="" description="Members of this group are on the include list for dynamic profiles" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupName="FSLogix Profile Include List"/></Group>
</Groups>

"@

            
            $null = New-Item -Path $GroupXMLGPOFilePath -ItemType File -Value $GroupXMLGPOFileContent -Force
            <#
            Set-Content -Path $GroupXMLGPOFilePath -Value $GroupXMLGPOFileContent -Encoding UTF8
            $GroupXMLGPOFileContent | Out-File $GroupXMLGPOFilePath -Encoding utf8
            #>
            #endregion
        
            #region GPT.INI Management
            $GPTINIGPOFilePath = "\\{0}\SYSVOL\{0}\Policies\{{{1}}}\GPT.INI" -f $DomainName, $($CurrentPooledHostPoolFSLogixGPO.Id)
            Write-Verbose -Message "Processing '$GPTINIGPOFilePath' ..."
            $result =  Select-string -Pattern "(Version)=(\d+)" -AllMatches -Path $GPTINIGPOFilePath
            #Getting current version
            [int]$VersionNumber = $result.Matches.Groups[-1].Value
            Write-Verbose -Message "Version Number: $VersionNumber"
            #Increasing current version
            $VersionNumber+=2
            Write-Verbose -Message "New Version Number: $VersionNumber"
            #Updating file
            (Get-Content $GPTINIGPOFilePath -Encoding UTF8) -replace "(Version)=(\d+)", "`$1=$VersionNumber" | Set-Content $GPTINIGPOFilePath -Encoding UTF8
            Write-Verbose -Message $(Get-Content $GPTINIGPOFilePath -Encoding UTF8 | Out-String)
            #endregion 

            #region gPCmachineExtensionNames Management
            #From https://www.infrastructureheroes.org/microsoft-infrastructure/microsoft-windows/guid-list-of-group-policy-client-extensions/
            #[{00000000-0000-0000-0000-000000000000}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}][{17D89FEC-5C44-4972-B12D-241CAEF74509}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}]
            #[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]
            Write-Verbose -Message "Processing gPCmachineExtensionNames Management ..."
            $gPCmachineExtensionNamesToAdd = "[{00000000-0000-0000-0000-000000000000}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}][{17D89FEC-5C44-4972-B12D-241CAEF74509}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}]"
            $RegExPattern = $gPCmachineExtensionNamesToAdd -replace "(\W)" , '\$1'
            $GPOADObject = Get-ADObject -LDAPFilter "CN={$($CurrentPooledHostPoolFSLogixGPO.Id.Guid)}" -Properties gPCmachineExtensionNames
            #if (-not($GPOADObject.gPCmachineExtensionNames.StartsWith($gPCmachineExtensionNamesToAdd)))
            if ($GPOADObject.gPCmachineExtensionNames -notmatch $RegExPattern)
            {
                $GPOADObject | Set-ADObject -Replace @{gPCmachineExtensionNames=$($gPCmachineExtensionNamesToAdd + $GPOADObject.gPCmachineExtensionNames)}
                #Get-ADObject -LDAPFilter "CN={$($CurrentPooledHostPoolFSLogixGPO.Id.Guid)}" -Properties gPCmachineExtensionNames
            }
            #endregion
            
            #endregion 

            #region Dedicated Resource Group Management (1 per HostPool)
            $CurrentPooledHostPoolResourceGroupName = "rg-avd-$($CurrentPooledHostPool.Name.ToLower())"

            $CurrentPooledHostPoolResourceGroup = Get-AzResourceGroup -Name $CurrentPooledHostPoolResourceGroupName -Location $CurrentPooledHostPool.Location -ErrorAction Ignore
            if (-not($CurrentPooledHostPoolResourceGroup)) {
                $CurrentPooledHostPoolResourceGroup = New-AzResourceGroup -Name $CurrentPooledHostPoolResourceGroupName -Location $CurrentPooledHostPool.Location -Force
                Write-Verbose -Message "Creating '$($CurrentPooledHostPoolResourceGroup.ResourceGroupName)' Resource Group ..."
            }
            #endregion

            #region Dedicated Storage Account Setup
            $CurrentPooledHostPoolStorageAccount = Get-AzStorageAccount -Name $CurrentPooledHostPoolStorageAccountName -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -ErrorAction Ignore
            if (-not($CurrentPooledHostPoolStorageAccount)) {
                if (-not(Get-AzStorageAccountNameAvailability -Name $CurrentPooledHostPoolStorageAccountName).NameAvailable) {
                    Write-Error "The storage account name '$CurrentPooledHostPoolStorageAccountName' is not available !" -ErrorAction Stop
                }
                $CurrentPooledHostPoolStorageAccount = New-AzStorageAccount -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -AccountName $CurrentPooledHostPoolStorageAccountName -Location $ThisDomainControllerVirtualNetwork.Location -SkuName $SKUName -MinimumTlsVersion TLS1_2 -EnableHttpsTrafficOnly $true
                Write-Verbose -Message "Creating '$($CurrentPooledHostPoolStorageAccount.StorageAccountName)' Storage Account (in the '$($CurrentPooledHostPoolStorageAccount.ResourceGroupName)' Resource Group) ..."
            }
            #Registering the Storage Account with your active directory environment under the target
            if (-not(Get-ADComputer -Filter "Name -eq '$CurrentPooledHostPoolStorageAccountName'" -SearchBase $CurrentPooledHostPoolOU.DistinguishedName)) {
                if (-not(Get-Module -Name AzFilesHybrid -ListAvailable)) {
                    $AzFilesHybridZipName = 'AzFilesHybrid.zip'
                    $OutFile = Join-Path -Path $env:TEMP -ChildPath $AzFilesHybridZipName
                    Start-BitsTransfer https://github.com/Azure-Samples/azure-files-samples/releases/latest/download/AzFilesHybrid.zip -destination $OutFile
                    Expand-Archive -Path $OutFile -DestinationPath $env:TEMP\AzFilesHybrid -Force
                    Push-Location -Path $env:TEMP\AzFilesHybrid
                    .\CopyToPSPath.ps1
                    Pop-Location
                }
                Write-Verbose -Message "Registering the Storage Account '$CurrentPooledHostPoolStorageAccountName' with your AD environment (under '$($CurrentPooledHostPoolOU.DistinguishedName)') OU ..."
                Import-Module AzFilesHybrid
                $null = Join-AzStorageAccountForAuth -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -Name $CurrentPooledHostPoolStorageAccountName -DomainAccountType "ComputerAccount" -OrganizationUnitDistinguishedName $CurrentPooledHostPoolOU.DistinguishedName -Confirm:$false
                #$KerbKeys = Get-AzStorageAccountKey -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -Name $CurrentPooledHostPoolStorageAccountName -ListKerbKey 
            }

            # Get the target storage account
            #$storageaccount = Get-AzStorageAccount -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -Name $CurrentPooledHostPoolStorageAccountName

            # List the directory service of the selected service account
            #$CurrentPooledHostPoolStorageAccount.AzureFilesIdentityBasedAuth.DirectoryServiceOptions

            # List the directory domain information if the storage account has enabled AD authentication for file shares
            #$CurrentPooledHostPoolStorageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties

            $CurrentPooledHostPoolStorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -AccountName $CurrentPooledHostPoolStorageAccountName) | Where-Object -FilterScript { $_.KeyName -eq "key1" }

            # Save the password so the drive 
            Write-Verbose -Message "Saving the credentials for accessing to the Storage Account '$CurrentPooledHostPoolStorageAccountName' in the Windows Credential Manager ..."
            Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "cmdkey /add:`"$CurrentPooledHostPoolStorageAccountName.file.core.windows.net`" /user:`"localhost\$CurrentPooledHostPoolStorageAccountName`" /pass:`"$($CurrentPooledHostPoolStorageAccountKey.Value)`""

            #region Private endpoint for Storage Setup
            #From https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-powershell?tabs=dynamic-ip#create-a-private-endpoint
            #From https://www.jorgebernhardt.com/private-endpoint-azure-key-vault-powershell/
            #From https://ystatit.medium.com/azure-key-vault-with-azure-service-endpoints-and-private-link-part-1-bcc84b4c5fbc
            ## Create the private endpoint connection. ## 

            Write-Verbose -Message "Creating the Private Endpoint for the Storage Account '$CurrentPooledHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group) ..."
            $PrivateEndpointName = "pep{0}" -f $($CurrentPooledHostPoolStorageAccountName -replace "\W")
            $GroupId = (Get-AzPrivateLinkResource -PrivateLinkResourceId $CurrentPooledHostPoolStorageAccount.Id).GroupId | Where-Object -FilterScript { $_ -match "file" }
            $PrivateLinkServiceConnection = New-AzPrivateLinkServiceConnection -Name $PrivateEndpointName -PrivateLinkServiceId $CurrentPooledHostPoolStorageAccount.Id -GroupId $GroupId
            $PrivateEndpoint = New-AzPrivateEndpoint -Name $PrivateEndpointName -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -Location $ThisDomainControllerVirtualNetwork.Location -Subnet $ThisDomainControllerSubnet -PrivateLinkServiceConnection $PrivateLinkServiceConnection -CustomNetworkInterfaceName $("{0}-nic" -f $PrivateEndpointName) -Force

            ## Create the private DNS zone. ##
            Write-Verbose -Message "Creating the Private DNS Zone for the Storage Account '$CurrentPooledHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group) ..."
            $PrivateDnsZoneName = 'privatelink.file.core.windows.net'
            $PrivateDnsZone = Get-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName -ErrorAction Ignore
            if ($PrivateDnsZone -eq $null)
            {
                Write-Verbose -Message "Creating the Private DNS Zone for the Storage Account '$CurrentPooledHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group) ..."
                $PrivateDnsZone = New-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName
            }

            $PrivateDnsVirtualNetworkLinkName = "pdvnl{0}" -f $($ThisDomainControllerVirtualNetwork.Name -replace "\W")
            $PrivateDnsVirtualNetworkLink = Get-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -ErrorAction Ignore
            if ($PrivateDnsVirtualNetworkLink -eq $null)
            {
                $ThisDomainControllerVirtualNetworkId = [string]::Join("/", $split[0..($split.Count - 3)])
                ## Create a DNS network link. ##
                Write-Verbose -Message "Creating the Private DNS VNet Link for the Storage Account '$CurrentPooledHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group) ..."
                $PrivateDnsVirtualNetworkLink = New-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -VirtualNetworkId $ThisDomainControllerVirtualNetworkId
            }


            ## Configure the DNS zone. ##
            Write-Verbose -Message "Creating the DNS Zone Configuration of the Private Dns Zone Group for the Storage Account '$CurrentPooledHostPoolStorageAccountName' ..."
            $PrivateDnsZoneConfig = New-AzPrivateDnsZoneConfig -Name $PrivateDnsZone.Name -PrivateDnsZoneId $PrivateDnsZone.ResourceId

            ## Create the DNS zone group. ##
            Write-Verbose -Message "Creating the Private DNS Zone Group in the Specified Private Endpoint '$PrivateEndpointName' (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
            $PrivateDnsZoneGroup = New-AzPrivateDnsZoneGroup -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -PrivateEndpointName $PrivateEndpointName -Name 'default' -PrivateDnsZoneConfig $PrivateDnsZoneConfig

            #Storage Account - Disabling Public Access
            #From https://www.jorgebernhardt.com/azure-storage-public-access/
            #From https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security?tabs=azure-powershell#change-the-default-network-access-rule
            #From https://github.com/adstuart/azure-privatelink-dns-microhack
            Write-Verbose -Message "Disabling the Public Access for the Storage Account '$CurrentPooledHostPoolStorageAccountName' (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
            $null = Set-AzStorageAccount -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -Name $CurrentPooledHostPoolStorageAccountName -PublicNetworkAccess Disabled
            #(Get-AzStorageAccount -Name $CurrentPooledHostPoolResourceGroupName -ResourceGroupName $CurrentPooledHostPoolStorageAccountName ).AllowBlobPublicAccess
            #endregion
            #endregion

            #region Dedicated Share Management
            $FSLogixShareName | ForEach-Object -Process { 
                $CurrentPooledHostPoolShareName = $_
                Write-Verbose -Message "Creating the Share '$CurrentPooledHostPoolShareName' in the Storage Account '$CurrentPooledHostPoolStorageAccountName' (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
                #Create a share for FSLogix
                $CurrentPooledHostPoolStorageAccountShare = New-AzRmStorageShare -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -StorageAccountName $CurrentPooledHostPoolStorageAccountName -Name $CurrentPooledHostPoolShareName -AccessTier Hot -QuotaGiB 200

                # Mount the share
                $null = New-PSDrive -Name Z -PSProvider FileSystem -Root "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\$CurrentPooledHostPoolShareName"

                #region NTFS permissions for FSLogix
                #From https://blue42.net/windows/changing-ntfs-security-permissions-using-powershell/
                #region Sample NTFS permissions for FSLogix
                Write-Verbose -Message "Setting the ACL for the Share '$CurrentPooledHostPoolShareName' in the Storage Account '$CurrentPooledHostPoolStorageAccountName' (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group)  ..."
                $existingAcl = Get-Acl Z:

                #Disabling inheritance
                $existingAcl.SetAccessRuleProtection($true, $false)

                #Remove all inherited permissions from this object.
                $existingAcl.Access | ForEach-Object -Process { $null = $existingAcl.RemoveAccessRule($_) }

                #Add Modify for CREATOR OWNER Group for Subfolders and files only
                $identity = "CREATOR OWNER"
                $colRights = [System.Security.AccessControl.FileSystemRights]::Modify
                $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::InheritOnly           
                $objType = [System.Security.AccessControl.AccessControlType]::Allow
                # Create a new FileSystemAccessRule object
                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                # Modify the existing ACL to include the new rule
                $existingAcl.SetAccessRule($AccessRule)

                #Add Full Control for "Administrators" Group for This folder, subfolders and files
                $identity = "Administrators"
                $colRights = [System.Security.AccessControl.FileSystemRights]::FullControl
                $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
                $objType = [System.Security.AccessControl.AccessControlType]::Allow
                # Create a new FileSystemAccessRule object
                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                # Modify the existing ACL to include the new rule
                $existingAcl.SetAccessRule($AccessRule)

                #Add Modify for "Users" Group for This folder only
                #$identity = "Users"
                $identity = $CurrentPooledHostPoolUsersADGroupName
                $colRights = [System.Security.AccessControl.FileSystemRights]::Modify
                $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None
                $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
                $objType = [System.Security.AccessControl.AccessControlType]::Allow
                # Create a new FileSystemAccessRule object
                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                # Modify the existing ACL to include the new rule
                $existingAcl.SetAccessRule($AccessRule)

                #Enabling inheritance
                $existingAcl.SetAccessRuleProtection($false, $true)

                # Apply the modified access rule to the folder
                $existingAcl | Set-Acl -Path Z:
                #endregion

                #region redirection.xml file management
                #Creating the redirection.xml file
                Write-Verbose -Message "Creating the 'redirections.xml' file for the Share '$CurrentPooledHostPoolShareName' in the Storage Account '$CurrentPooledHostPoolStorageAccountName' (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
                $null = New-Item -Path Z: -Name "redirections.xml" -ItemType "file" -Value $RedirectionsXMLFileContent -Force
                Write-Verbose -Message "Setting the ACL for the 'redirections.xml' file in the Share '$CurrentPooledHostPoolShareName' in the Storage Account '$CurrentPooledHostPoolStorageAccountName' (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
                $existingAcl = Get-Acl Z:\redirections.xml
                #Add Read for "Users" Group for This folder only
                #$identity = "Users"
                $identity = $CurrentPooledHostPoolUsersADGroupName
                $colRights = [System.Security.AccessControl.FileSystemRights]::Read
                $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None
                $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
                $objType = [System.Security.AccessControl.AccessControlType]::Allow
                # Create a new FileSystemAccessRule object
                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                # Modify the existing ACL to include the new rule
                $existingAcl.SetAccessRule($AccessRule)
                $existingAcl | Set-Acl -Path Z:\redirections.xml
                #endregion

                # Unmount the share
                Remove-PSDrive -Name Z
                #endregion

                #region Run a sync with Azure AD
                if (Get-Service -Name ADSync -ErrorAction Ignore)
                {
                    Start-Service -Name ADSync
                    Import-Module -Name "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync"
                    if (-not(Get-ADSyncConnectorRunStatus)) {
                        Write-Verbose "Running a sync with Azure AD ..."
                        $null = Start-ADSyncSyncCycle -PolicyType Delta
                    }
                }
                #endregion 

                #region RBAC Management
                #Constrain the scope to the target file share
                $AzContext = Get-AzContext
                $SubscriptionId = $AzContext.Subscription.Id
                $Scope = "/subscriptions/$SubscriptionId/resourceGroups/$CurrentPooledHostPoolResourceGroupName/providers/Microsoft.Storage/storageAccounts/$CurrentPooledHostPoolStorageAccountName/fileServices/default/fileshares/$CurrentPooledHostPoolShareName"

                #region Setting up the file share with right RBAC: FSLogix Contributor = "Storage File Data SMB Share Elevated Contributor"
                #Get the name of the custom role
                $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Contributor"
                #Assign the custom role to the target identity with the specified scope.
                Do 
                {
                    $AzADGroup = $null
                    $AzADGroup = Get-AzADGroup -SearchString $CurrentPooledHostPoolFSLogixContributorADGroupName
                    Write-Verbose -Message "Sleeping 10 seconds ..."
                    Start-Sleep -Seconds 10
                } While (-not($AzADGroup.Id))
                if (-not(Get-AzRoleAssignment -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                    Write-Verbose -Message "Assigning the '$($FileShareContributorRole.Name)' RBAC role to '$CurrentPooledHostPoolFSLogixContributorADGroupName' AD Group on the Share '$CurrentPooledHostPoolShareName' in the Storage Account '$CurrentPooledHostPoolStorageAccountName' (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group)  ..."
                    $null = New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                }
                #endregion

                #region Setting up the file share with right RBAC: FSLogix Elevated Contributor = "Storage File Data SMB Share Contributor"
                #Get the name of the custom role
                $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Elevated Contributor"
                #Assign the custom role to the target identity with the specified scope.
                Do 
                {
                    $AzADGroup = $null
                    $AzADGroup = Get-AzADGroup -SearchString $CurrentPooledHostPoolFSLogixElevatedContributorADGroupName
                    Write-Verbose -Message "Sleeping 10 seconds ..."
                    Start-Sleep -Seconds 10
                } While (-not($AzADGroup.Id))

                if (-not(Get-AzRoleAssignment -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                    Write-Verbose -Message "Assigning the '$($FileShareContributorRole.Name)' RBAC role to '$CurrentPooledHostPoolFSLogixElevatedContributorADGroupName' AD Group on the Share '$CurrentPooledHostPoolShareName' in the Storage Account '$CurrentPooledHostPoolStorageAccountName' (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group)  ..."
                    $null = New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                }
                #endregion

                #region Setting up the file share with right RBAC: FSLogix Reader = "Storage File Data SMB Share Reader"
                #Get the name of the custom role
                $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Reader"
                #Assign the custom role to the target identity with the specified scope.
                Do 
                {
                    $AzADGroup = $null
                    $AzADGroup = Get-AzADGroup -SearchString $CurrentPooledHostPoolFSLogixReaderADGroupName
                    Write-Verbose -Message "Sleeping 10 seconds ..."
                    Start-Sleep -Seconds 10
                } While (-not($AzADGroup.Id))
                if (-not(Get-AzRoleAssignment -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                    Write-Verbose -Message "Assigning the '$($FileShareContributorRole.Name)' RBAC role to '$CurrentPooledHostPoolFSLogixReaderADGroupName' AD Group on the Share '$CurrentPooledHostPoolShareName' in the Storage Account '$CurrentPooledHostPoolStorageAccountName' (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group)  ..."
                    $null = New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                }
                #endregion

                #endregion
            }
            #endregion
            #endregion
            #endregion

            #region MSIX

            #region MSIX AD Management
            #region Dedicated HostPool AD group

            #region Dedicated HostPool AD FSLogix groups
            $CurrentPooledHostPoolMSIXHostsADGroupName = "$($CurrentPooledHostPool.Name) - $MSIXHosts"
            $CurrentPooledHostPoolMSIXHostsADGroup = Get-ADGroup -Filter "Name -eq '$CurrentPooledHostPoolMSIXHostsADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentPooledHostPoolOU.DistinguishedName
            if (-not($CurrentPooledHostPoolMSIXHostsADGroup)) {
                Write-Verbose -Message "Creating '$CurrentPooledHostPoolMSIXHostsADGroupName' AD Group (under '$($CurrentPooledHostPoolOU.DistinguishedName)') ..."
                $CurrentPooledHostPoolMSIXHostsADGroup = New-ADGroup -Name $CurrentPooledHostPoolMSIXHostsADGroupName -SamAccountName $CurrentPooledHostPoolMSIXHostsADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentPooledHostPoolMSIXHostsADGroupName -Path $CurrentPooledHostPoolOU.DistinguishedName -PassThru
            }

            $CurrentPooledHostPoolMSIXShareAdminsADGroupName = "$($CurrentPooledHostPool.Name) - $MSIXShareAdmins"
            $CurrentPooledHostPoolMSIXShareAdminsADGroup = Get-ADGroup -Filter "Name -eq '$CurrentPooledHostPoolMSIXShareAdminsADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentPooledHostPoolOU.DistinguishedName
            if (-not($CurrentPooledHostPoolMSIXShareAdminsADGroup)) {
                Write-Verbose -Message "Creating '$CurrentPooledHostPoolMSIXShareAdminsADGroupName' AD Group (under '$($CurrentPooledHostPoolOU.DistinguishedName)') ..."
                $CurrentPooledHostPoolMSIXShareAdminsADGroup = New-ADGroup -Name $CurrentPooledHostPoolMSIXShareAdminsADGroupName -SamAccountName $CurrentPooledHostPoolMSIXShareAdminsADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentPooledHostPoolMSIXShareAdminsADGroupName -Path $CurrentPooledHostPoolOU.DistinguishedName -PassThru
            }

            $CurrentPooledHostPoolMSIXUsersADGroupName = "$($CurrentPooledHostPool.Name) - $MSIXUsers"
            $CurrentPooledHostPoolMSIXUsersADGroup = Get-ADGroup -Filter "Name -eq '$CurrentPooledHostPoolMSIXUsersADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentPooledHostPoolOU.DistinguishedName
            if (-not($CurrentPooledHostPoolMSIXUsersADGroup)) {
                Write-Verbose -Message "Creating '$CurrentPooledHostPoolMSIXUsersADGroup' AD Group (under '$($CurrentPooledHostPoolOU.DistinguishedName)') ..."
                $CurrentPooledHostPoolMSIXUsersADGroup = New-ADGroup -Name $CurrentPooledHostPoolMSIXUsersADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentPooledHostPoolMSIXUsersADGroupName -Path $CurrentPooledHostPoolOU.DistinguishedName -PassThru
            }
            Write-Verbose -Message "Adding the '$CurrentPooledHostPoolUsersADGroupName' AD group to the '$CurrentPooledHostPoolMSIXUsersADGroup' AD Group (under '$($CurrentPooledHostPoolOU.DistinguishedName)') ..."
            $CurrentPooledHostPoolMSIXUsersADGroup | Add-ADGroupMember -Members $CurrentPooledHostPoolUsersADGroupName
            #endregion
            #endregion

            #region Run a sync with Azure AD
            if (Get-Service -Name ADSync -ErrorAction Ignore)
            {
                Start-Service -Name ADSync
                Import-Module -Name "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync"
                if (-not(Get-ADSyncConnectorRunStatus)) {
                    Write-Verbose "Running a sync with Azure AD ..."
                    $null = Start-ADSyncSyncCycle -PolicyType Delta
                }
            }
            #endregion 
            #endregion 

            #region MSIX Storage Account Management
            #region MSIX Storage Account Name Setup
            $CurrentPooledHostPoolStorageAccountName = "msix{0}" -f $($CurrentPooledHostPool.Name -replace "\W")
            $CurrentPooledHostPoolStorageAccountName = $CurrentPooledHostPoolStorageAccountName.Substring(0, [system.math]::min($CurrentPooledHostPoolStorageAccountNameMaxLength, $CurrentPooledHostPoolStorageAccountName.Length)).ToLower()
            #endregion 

            #region Dedicated Host Pool AD GPO Management (1 GPO per Host Pool for setting up the dedicated VHDLocations/CCDLocations value)
            $CurrentPooledHostPoolMSIXGPO = Get-GPO -Name "$($CurrentPooledHostPool.Name) - MSIX Settings" -ErrorAction Ignore
            if (-not($CurrentPooledHostPoolMSIXGPO)) {
                $CurrentPooledHostPoolMSIXGPO = New-GPO -Name "$($CurrentPooledHostPool.Name) - MSIX Settings"
                Write-Verbose -Message "Creating '$($CurrentPooledHostPoolMSIXGPO.DisplayName)' GPO (linked to '($($CurrentPooledHostPoolOU.DistinguishedName))' ..."
            }
            $null = $CurrentPooledHostPoolMSIXGPO | New-GPLink -Target $CurrentPooledHostPoolOU.DistinguishedName -LinkEnabled Yes -ErrorAction Ignore

            #region Dedicated Host Pool AD GPO Management
            #region Turning off automatic updates for MSIX app attach applications
            #From https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-azure-portal#turn-off-automatic-updates-for-msix-app-attach-applications
            Write-Verbose -Message "Turning off automatic updates for MSIX app attach applications for '$($CurrentPooledHostPoolMSIXGPO.DisplayName)' GPO (linked to '$($CurrentPooledHostPoolOU.DistinguishedName)' OU) ..."
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolMSIXGPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\WindowsStore' -ValueName "AutoDownload" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 2
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolMSIXGPO.DisplayName -Key 'HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -ValueName "PreInstalledAppsEnabled" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Debug' -ValueName "ContentDeliveryAllowedOverride" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 2
            #Look for Disable-WindowsUpdateScheduledStartScheduledTask in the follwoing code for the next step(s)
            #endregion

            #region Microsoft Defender Endpoint A/V General Exclusions
            #From https://learn.microsoft.com/en-us/fslogix/overview-prerequisites#configure-antivirus-file-and-folder-exclusions
            Write-Verbose -Message "Setting some 'Microsoft Defender Endpoint A/V General Exclusions' related registry values for '$($CurrentPooledHostPoolMSIXGPO.DisplayName)' GPO (linked to '$($CurrentPooledHostPoolOU.DistinguishedName)' OU) ..."
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions' -ValueName "Exclusions_Paths" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "TempFolderVHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%TEMP%\*\*.VHD"
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "TempFolderVHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%TEMP%\*\*.VHDX"
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "WindirTempFolderVHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%Windir%\TEMP\*\*.VHD"
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "WindirTempFolderVHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "%Windir%\TEMP\*\*.VHDX"
            #endregion 

            #region Microsoft Defender Endpoint A/V Exclusions for this HostPool 
            #From https://learn.microsoft.com/en-us/fslogix/overview-prerequisites#configure-antivirus-file-and-folder-exclusions
            Write-Verbose -Message "Setting some 'Microsoft Defender Endpoint A/V Exclusions for this HostPool' related registry values for '$($CurrentPooledHostPoolMSIXGPO.DisplayName)' GPO (linked to '$($CurrentPooledHostPoolOU.DistinguishedName)' OU) ..."
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "MSixSharedFolderVHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHD"
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "MSixSharedFolderVHDLock" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHD.lock"
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "MSixSharedFolderVHDMeta" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHD.meta"
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "MSixSharedFolderVHDMetaData" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHD.metadata"
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "MSixSharedFolderVHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHDX"
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "MSixSharedFolderVHDXLock" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHDX.lock"
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "MSixSharedFolderVHDXMeta" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHDX.meta"
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "MSixSharedFolderVHDXMetaData" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.VHDX.metadata"
            $null = Set-GPRegistryValue -Name $CurrentPooledHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "MSixSharedFolderCIM" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\profiles\*.CIM"
            #endregion

            #endregion

            #region Dedicated Resource Group Management (1 per HostPool)
            $CurrentPooledHostPoolResourceGroupName = "rg-avd-$($CurrentPooledHostPool.Name.ToLower())"

            $CurrentPooledHostPoolResourceGroup = Get-AzResourceGroup -Name $CurrentPooledHostPoolResourceGroupName -Location $CurrentPooledHostPool.Location -ErrorAction Ignore
            if (-not($CurrentPooledHostPoolResourceGroup)) {
                Write-Verbose -Message "Creating '$CurrentPooledHostPoolResourceGroupName' Resource Group ..."
                $CurrentPooledHostPoolResourceGroup = New-AzResourceGroup -Name $CurrentPooledHostPoolResourceGroupName -Location $CurrentPooledHostPool.Location -Force
            }
            #endregion

            #region Dedicated Storage Account Setup
            $CurrentPooledHostPoolStorageAccount = Get-AzStorageAccount -Name $CurrentPooledHostPoolStorageAccountName -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -ErrorAction Ignore
            if (-not($CurrentPooledHostPoolStorageAccount)) {
                if (-not(Get-AzStorageAccountNameAvailability -Name $CurrentPooledHostPoolStorageAccountName).NameAvailable) {
                    Write-Error "The storage account name '$CurrentPooledHostPoolStorageAccountName' is not available !" -ErrorAction Stop
                }
                $CurrentPooledHostPoolStorageAccount = New-AzStorageAccount -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -AccountName $CurrentPooledHostPoolStorageAccountName -Location $ThisDomainControllerVirtualNetwork.Location -SkuName $SKUName -MinimumTlsVersion TLS1_2 -EnableHttpsTrafficOnly $true
                Write-Verbose -Message "Creating '$($CurrentPooledHostPoolStorageAccount.StorageAccountName)' Storage Account (in the '$($CurrentPooledHostPoolStorageAccount.ResourceGroupName)' Resource Group) ..."
            }
            #Registering the Storage Account with your active directory environment under the target
            if (-not(Get-ADComputer -Filter "Name -eq '$CurrentPooledHostPoolStorageAccountName'" -SearchBase $CurrentPooledHostPoolOU.DistinguishedName)) {
                Write-Verbose -Message "Registering the Storage Account '$CurrentPooledHostPoolStorageAccountName' with your AD environment (under '$($CurrentPooledHostPoolOU.DistinguishedName)') ..."
                Import-Module AzFilesHybrid
                $null = Join-AzStorageAccountForAuth -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -Name $CurrentPooledHostPoolStorageAccountName -DomainAccountType "ComputerAccount" -OrganizationUnitDistinguishedName $CurrentPooledHostPoolOU.DistinguishedName -Confirm:$false
                #$KerbKeys = Get-AzStorageAccountKey -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -Name $CurrentPooledHostPoolStorageAccountName -ListKerbKey 
            }

            # Get the target storage account
            #$storageaccount = Get-AzStorageAccount -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -Name $CurrentPooledHostPoolStorageAccountName

            # List the directory service of the selected service account
            #$CurrentPooledHostPoolStorageAccount.AzureFilesIdentityBasedAuth.DirectoryServiceOptions

            # List the directory domain information if the storage account has enabled AD authentication for file shares
            #$CurrentPooledHostPoolStorageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties

            $CurrentPooledHostPoolStorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -AccountName $CurrentPooledHostPoolStorageAccountName) | Where-Object -FilterScript { $_.KeyName -eq "key1" }

            # Save the password so the drive 
            Write-Verbose -Message "Saving the credentials for accessing to the Storage Account '$CurrentPooledHostPoolStorageAccountName' in the Windows Credential Manager ..."
            Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "cmdkey /add:`"$CurrentPooledHostPoolStorageAccountName.file.core.windows.net`" /user:`"localhost\$CurrentPooledHostPoolStorageAccountName`" /pass:`"$($CurrentPooledHostPoolStorageAccountKey.Value)`""

            #region Private endpoint for Storage Setup
            #From https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-powershell?tabs=dynamic-ip#create-a-private-endpoint
            #From https://www.jorgebernhardt.com/private-endpoint-azure-key-vault-powershell/
            #From https://ystatit.medium.com/azure-key-vault-with-azure-service-endpoints-and-private-link-part-1-bcc84b4c5fbc
            ## Create the private endpoint connection. ## 

            $PrivateEndpointName = "pep{0}" -f $($CurrentPooledHostPoolStorageAccountName -replace "\W")
            $GroupId = (Get-AzPrivateLinkResource -PrivateLinkResourceId $CurrentPooledHostPoolStorageAccount.Id).GroupId | Where-Object -FilterScript { $_ -match "file" }
            $PrivateLinkServiceConnection = New-AzPrivateLinkServiceConnection -Name $PrivateEndpointName -PrivateLinkServiceId $CurrentPooledHostPoolStorageAccount.Id -GroupId $GroupId
            Write-Verbose -Message "Creating the Private Endpoint for the Storage Account '$CurrentPooledHostPoolStorageAccountName'  (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group)..."
            $PrivateEndpoint = New-AzPrivateEndpoint -Name $PrivateEndpointName -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -Location $ThisDomainControllerVirtualNetwork.Location -Subnet $ThisDomainControllerSubnet -PrivateLinkServiceConnection $PrivateLinkServiceConnection -CustomNetworkInterfaceName $("{0}-nic" -f $PrivateEndpointName) -Force

            ## Create the private DNS zone. ##
            $PrivateDnsZoneName = 'privatelink.file.core.windows.net'
            $PrivateDnsZone = Get-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName -ErrorAction Ignore
            if ($PrivateDnsZone -eq $null)
            {
                Write-Verbose -Message "Creating the Private DNS Zone for the Storage Account '$CurrentPooledHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group) ..."
                $PrivateDnsZone = New-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName
            }

            $PrivateDnsVirtualNetworkLinkName = "pdvnl{0}" -f $($ThisDomainControllerVirtualNetwork.Name -replace "\W")
            $PrivateDnsVirtualNetworkLink = Get-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -ErrorAction Ignore
            if ($PrivateDnsVirtualNetworkLink -eq $null)
            {
                $ThisDomainControllerVirtualNetworkId = [string]::Join("/", $split[0..($split.Count - 3)])
                ## Create a DNS network link. ##
                Write-Verbose -Message "Creating the Private DNS VNet Link for the Storage Account '$CurrentPooledHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group) ..."
                $PrivateDnsVirtualNetworkLink = New-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -VirtualNetworkId $ThisDomainControllerVirtualNetworkId
            }


            ## Configure the DNS zone. ##
            Write-Verbose -Message "Creating the DNS Zone Configuration of the Private Dns Zone Group for the Storage Account '$CurrentPooledHostPoolStorageAccountName' ..."
            $PrivateDnsZoneConfig = New-AzPrivateDnsZoneConfig -Name $PrivateDnsZone.Name -PrivateDnsZoneId $PrivateDnsZone.ResourceId

            ## Create the DNS zone group. ##
            Write-Verbose -Message "Creating the Private DNS Zone Group in the Specified Private Endpoint '$PrivateEndpointName' (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
            $PrivateDnsZoneGroup = New-AzPrivateDnsZoneGroup -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -PrivateEndpointName $PrivateEndpointName -Name 'default' -PrivateDnsZoneConfig $PrivateDnsZoneConfig

            #Storage Account - Disabling Public Access
            #From https://www.jorgebernhardt.com/azure-storage-public-access/
            #From https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security?tabs=azure-powershell#change-the-default-network-access-rule
            #From https://github.com/adstuart/azure-privatelink-dns-microhack
            Write-Verbose -Message "Disabling the Public Access for the Storage Account '$CurrentPooledHostPoolStorageAccountName' (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
            $null = Set-AzStorageAccount -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -Name $CurrentPooledHostPoolStorageAccountName -PublicNetworkAccess Disabled
            #(Get-AzStorageAccount -Name $CurrentPooledHostPoolResourceGroupName -ResourceGroupName $CurrentPooledHostPoolStorageAccountName ).AllowBlobPublicAccess
            #endregion
            #endregion

            $MSIXDemoPackages = $null
            #region Dedicated Share Management
            $MSIXShareName | ForEach-Object -Process { 
                $CurrentPooledHostPoolShareName = $_
                #Create a share for FSLogix
                Write-Verbose -Message "Creating the Share '$CurrentPooledHostPoolShareName' in the Storage Account '$CurrentPooledHostPoolStorageAccountName' (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
                $CurrentPooledHostPoolStorageShare = New-AzRmStorageShare -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -StorageAccountName $CurrentPooledHostPoolStorageAccountName -Name $CurrentPooledHostPoolShareName -AccessTier Hot -QuotaGiB 200

                # Copying the  Demo MSIX Packages from my dedicated GitHub repository
                $MSIXDemoPackages = Copy-MSIXDemoPackage -Destination "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\$CurrentPooledHostPoolShareName"

                # Mount the share
                $null = New-PSDrive -Name Z -PSProvider FileSystem -Root "\\$CurrentPooledHostPoolStorageAccountName.file.core.windows.net\$CurrentPooledHostPoolShareName"

                #region NTFS permissions for MSIX
                #From https://docs.microsoft.com/en-us/azure/virtual-desktop/app-attach-file-share#how-to-set-up-the-file-share
                #From https://blue42.net/windows/changing-ntfs-security-permissions-using-powershell/
                Write-Verbose -Message "Setting the ACL on the Share '$CurrentPooledHostPoolShareName' in the Storage Account '$CurrentPooledHostPoolStorageAccountName' (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
                $existingAcl = Get-Acl Z:
                $existingAcl.Access | ForEach-Object -Process { $null = $existingAcl.RemoveAccessRule($_) }
                #Disabling inheritance
                $existingAcl.SetAccessRuleProtection($true, $false)

                #Add Full Control for Administrators Group for This folder, subfolders and files
                $identity = "BUILTIN\Administrators"
                $colRights = [System.Security.AccessControl.FileSystemRights]::FullControl
                $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
                $objType = [System.Security.AccessControl.AccessControlType]::Allow
                # Create a new FileSystemAccessRule object
                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                # Modify the existing ACL to include the new rule
                $existingAcl.SetAccessRule($AccessRule)

                #Add Full Control for MSIXShareAdmins Group for This folder, subfolders and files
                $identity = $CurrentPooledHostPoolMSIXShareAdminsADGroupName
                $colRights = [System.Security.AccessControl.FileSystemRights]::FullControl
                $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
                $objType = [System.Security.AccessControl.AccessControlType]::Allow
                # Create a new FileSystemAccessRule object
                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                # Modify the existing ACL to include the new rule
                $existingAcl.SetAccessRule($AccessRule)

                #Add "Read And Execute" for MSIXUsers Group for This folder, subfolders and files
                $identity = $CurrentPooledHostPoolMSIXUsersADGroupName
                $colRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
                $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None           
                $objType = [System.Security.AccessControl.AccessControlType]::Allow
                # Create a new FileSystemAccessRule object
                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                # Modify the existing ACL to include the new rule
                $existingAcl.SetAccessRule($AccessRule)

                #Add "Read And Execute" for MSIXHosts Group for This folder, subfolders and files
                $identity = $CurrentPooledHostPoolMSIXHostsADGroupName
                $colRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
                $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
                $objType = [System.Security.AccessControl.AccessControlType]::Allow
                # Create a new FileSystemAccessRule object
                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                # Modify the existing ACL to include the new rule
                $existingAcl.SetAccessRule($AccessRule)

                #Enabling inheritance
                $existingAcl.SetAccessRuleProtection($false, $true)

                # Apply the modified access rule to the folder
                $existingAcl | Set-Acl -Path Z:
                #endregion

                # Unmount the share
                Remove-PSDrive -Name Z

                #region RBAC Management
                #Constrain the scope to the target file share
                $AzContext = Get-AzContext
                $SubscriptionId = $AzContext.Subscription.Id
                $Scope = "/subscriptions/$SubscriptionId/resourceGroups/$CurrentPooledHostPoolResourceGroupName/providers/Microsoft.Storage/storageAccounts/$CurrentPooledHostPoolStorageAccountName/fileServices/default/fileshares/$CurrentPooledHostPoolShareName"

                #region Setting up the file share with right RBAC: MSIX Hosts & MSIX Users = "Storage File Data SMB Share Contributor" + MSIX Share Admins = Storage File Data SMB Share Elevated Contributor
                #https://docs.microsoft.com/en-us/azure/virtual-desktop/app-attach-file-share#how-to-set-up-the-file-share
                #Get the name of the custom role
                $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Contributor"
                #Assign the custom role to the target identity with the specified scope.
                Do 
                {
                    $AzADGroup = $null
                    $AzADGroup = Get-AzADGroup -SearchString $CurrentPooledHostPoolMSIXHostsADGroupName
                    Write-Verbose -Message "Sleeping 10 seconds ..."
                    Start-Sleep -Seconds 10
                } While (-not($AzADGroup.Id))
                if (-not(Get-AzRoleAssignment -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                    Write-Verbose -Message "Assigning the '$($FileShareContributorRole.Name)' RBAC role to '$CurrentPooledHostPoolMSIXHostsADGroupName' AD Group on the Share '$CurrentPooledHostPoolShareName' in the Storage Account '$CurrentPooledHostPoolStorageAccountName' (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
                    $null = New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                }

                #Assign the custom role to the target identity with the specified scope.
                Do 
                {
                    $AzADGroup = $null
                    $AzADGroup = Get-AzADGroup -SearchString $CurrentPooledHostPoolMSIXUsersADGroupName
                    Write-Verbose -Message "Sleeping 10 seconds ..."
                    Start-Sleep -Seconds 10
                } While (-not($AzADGroup.Id))
                if (-not(Get-AzRoleAssignment -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                    Write-Verbose -Message "Assigning the '$($FileShareContributorRole.Name)' RBAC role to 'CurrentPooledHostPoolMSIXUsersADGroupName' AD Group on the Share '$CurrentPooledHostPoolShareName' in the Storage Account '$CurrentPooledHostPoolStorageAccountName'  (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
                    $null = New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                }
                #endregion

                #region Setting up the file share with right RBAC: FSLogix Elevated Contributor = "Storage File Data SMB Share Contributor"
                #Get the name of the custom role
                $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Elevated Contributor"
                #Assign the custom role to the target identity with the specified scope.
                Do 
                {
                    $AzADGroup = $null
                    $AzADGroup = Get-AzADGroup -SearchString $CurrentPooledHostPoolMSIXShareAdminsADGroupName
                    Write-Verbose -Message "Sleeping 10 seconds ..."
                    Start-Sleep -Seconds 10
                } While (-not($AzADGroup.Id))
                if (-not(Get-AzRoleAssignment -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                    Write-Verbose -Message "Assigning the '$($FileShareContributorRole.Name)' RBAC role to '$CurrentPooledHostPoolMSIXShareAdminsADGroupName' AD Group on the Share '$CurrentPooledHostPoolShareName' in the Storage Account '$CurrentPooledHostPoolStorageAccountName' (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
                    $null = New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                }
                #endregion

                #endregion
            }
            #endregion
            #endregion
            
            #endregion

            #endregion

            #region Key Vault
            #region Key Vault Name Setup
            $CurrentPooledHostPoolKeyVaultName = "kv{0}" -f $($CurrentPooledHostPool.Name -replace "\W")
            $CurrentPooledHostPoolKeyVaultName = $CurrentPooledHostPoolKeyVaultName.Substring(0, [system.math]::min($CurrentPooledHostPoolKeyVaultNameMaxLength, $CurrentPooledHostPoolKeyVaultName.Length)).ToLower()
            #endregion 

            #region Dedicated Resource Group Management (1 per HostPool)
            $CurrentPooledHostPoolResourceGroupName = "rg-avd-$($CurrentPooledHostPool.Name.ToLower())"

            $CurrentPooledHostPoolResourceGroup = Get-AzResourceGroup -Name $CurrentPooledHostPoolResourceGroupName -Location $CurrentPooledHostPool.Location -ErrorAction Ignore
            if (-not($CurrentPooledHostPoolResourceGroup)) {
                Write-Verbose -Message "Creating '$CurrentPooledHostPoolResourceGroupName' Resource Group ..."
                $CurrentPooledHostPoolResourceGroup = New-AzResourceGroup -Name $CurrentPooledHostPoolResourceGroupName -Location $CurrentPooledHostPool.Location -Force
            }
            #endregion

            #region Dedicated Key Vault Setup
            $CurrentPooledHostPoolKeyVault = Get-AzKeyVault -VaultName $CurrentPooledHostPoolKeyVaultName -ErrorAction Ignore
            if (-not($CurrentPooledHostPoolKeyVault)) {
                if (-not(Get-AzKeyVaultNameAvailability -Name $CurrentPooledHostPoolKeyVaultName).NameAvailable) {
                    Write-Error "The key vault name '$CurrentPooledHostPoolKeyVaultName' is not available !" -ErrorAction Stop
                }
                Write-Verbose -Message "Creating '$CurrentPooledHostPoolKeyVaultName' Key Vault (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
                $CurrentPooledHostPoolKeyVault = New-AzKeyVault -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -VaultName $CurrentPooledHostPoolKeyVaultName -Location $ThisDomainControllerVirtualNetwork.Location -EnabledForDiskEncryption
            }
            #endregion

            #region Private endpoint for Key Vault Setup
            #From https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-powershell?tabs=dynamic-ip#create-a-private-endpoint
            #From https://www.jorgebernhardt.com/private-endpoint-azure-key-vault-powershell/
            ## Create the private endpoint connection. ## 

            $PrivateEndpointName = "pep{0}" -f $($CurrentPooledHostPoolKeyVaultName -replace "\W")
            $GroupId = (Get-AzPrivateLinkResource -PrivateLinkResourceId $CurrentPooledHostPoolKeyVault.ResourceId).GroupId
            $PrivateLinkServiceConnection = New-AzPrivateLinkServiceConnection -Name $PrivateEndpointName -PrivateLinkServiceId $CurrentPooledHostPoolKeyVault.ResourceId -GroupId $GroupId
            Write-Verbose -Message "Creating the Private Endpoint for the Key Vault '$CurrentPooledHostPoolKeyVaultName' (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
            $PrivateEndpoint = New-AzPrivateEndpoint -Name $PrivateEndpointName -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -Location $ThisDomainControllerVirtualNetwork.Location -Subnet $ThisDomainControllerSubnet -PrivateLinkServiceConnection $PrivateLinkServiceConnection -CustomNetworkInterfaceName $("{0}-nic" -f $PrivateEndpointName) -Force

            ## Create the private DNS zone. ##
            $PrivateDnsZoneName = 'privatelink.vaultcore.azure.net'
            $PrivateDnsZone = Get-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName -ErrorAction Ignore
            if ($PrivateDnsZone -eq $null)
            {
                Write-Verbose -Message "Creating the Private DNS Zone for the Key Vault '$CurrentPooledHostPoolKeyVaultName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group) ..."
                $PrivateDnsZone = New-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName
            }

            $PrivateDnsVirtualNetworkLinkName = "pdvnl{0}" -f $($ThisDomainControllerVirtualNetwork.Name -replace "\W")
            $PrivateDnsVirtualNetworkLink = Get-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -ErrorAction Ignore
            if ($PrivateDnsVirtualNetworkLink -eq $null)
            {
                $ThisDomainControllerVirtualNetworkId = [string]::Join("/", $split[0..($split.Count - 3)])
                ## Create a DNS network link. ##
                Write-Verbose -Message "Creating the Private DNS VNet Link for the Key Vault '$CurrentPooledHostPoolKeyVaultName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group) ..."
                $PrivateDnsVirtualNetworkLink = New-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -VirtualNetworkId $ThisDomainControllerVirtualNetworkId
            }


            ## Configure the DNS zone. ##
            Write-Verbose -Message "Creating the DNS Zone Configuration of the Private Dns Zone Group for Key Vault '$CurrentPooledHostPoolKeyVaultName' ..."
            $PrivateDnsZoneConfig = New-AzPrivateDnsZoneConfig -Name $PrivateDnsZone.Name -PrivateDnsZoneId $PrivateDnsZone.ResourceId

            ## Create the DNS zone group. ##
            Write-Verbose -Message "Creating the Private DNS Zone Group in the Specified Private Endpoint '$PrivateEndpointName' (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
            $PrivateDnsZoneGroup = New-AzPrivateDnsZoneGroup -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -PrivateEndpointName $PrivateEndpointName -Name 'default' -PrivateDnsZoneConfig $PrivateDnsZoneConfig

            #Key Vault - Disabling Public Access
            Write-Verbose -Message "Disabling the Public Access for the Key Vault'$CurrentPooledHostPoolKeyVaultName' (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
            $null = Update-AzKeyVault -VaultName $CurrentPooledHostPoolKeyVaultName -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -PublicNetworkAccess "Disabled" 
            #endregion

            #endregion

            #region Host Pool Setup
            $parameters = @{
                Name                  = $CurrentPooledHostPool.Name
                ResourceGroupName     = $CurrentPooledHostPoolResourceGroupName
                HostPoolType          = 'Pooled'
                LoadBalancerType      = 'BreadthFirst'
                PreferredAppGroupType = 'Desktop'
                MaxSessionLimit       = $CurrentPooledHostPool.MaxSessionLimit
                Location              = $CurrentPooledHostPool.Location
                StartVMOnConnect      = $true
                # From https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/rdp-files?context=%2Fazure%2Fvirtual-desktop%2Fcontext%2Fcontext#device-redirection
                # No RDP redirection for COM ports, Local Drives and printers.
                CustomRdpProperty     = "redirectcomports:i:0;redirectlocation:i:0;redirectprinters:i:0;drivestoredirect:s:;usbdevicestoredirect:s:"
                Verbose               = $true
            }

            Write-Verbose -Message "Creating the '$($CurrentPooledHostPool.Name)' Host Pool (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
            $CurrentAzWvdHostPool = New-AzWvdHostPool @parameters
            $RegistrationInfoExpirationTime = (Get-Date).AddDays(1)
            Write-Verbose -Message "Getting the Registration Token (Expiration: '$RegistrationInfoExpirationTime') for the '$($CurrentPooledHostPool.Name)' Host Pool (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
            $RegistrationInfoToken = New-AzWvdRegistrationInfo -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -HostPoolName $CurrentPooledHostPool.Name -ExpirationTime $RegistrationInfoExpirationTime -ErrorAction SilentlyContinue


            #region Scale session hosts using Azure Automation
            #TODO : https://learn.microsoft.com/en-us/training/modules/automate-azure-virtual-desktop-management-tasks/1-introduction
            #endregion

            #region Set up Private Link with Azure Virtual Desktop
            #TODO: https://learn.microsoft.com/en-us/azure/virtual-desktop/private-link-setup?tabs=powershell%2Cportal-2#enable-the-feature
            #endregion


            #region Use Azure Firewall to protect Azure Virtual Desktop deployments
            #TODO: https://learn.microsoft.com/en-us/training/modules/protect-virtual-desktop-deployment-azure-firewall/
            #endregion
            #endregion

            #region Desktop Application Group Setup
            $parameters = @{
                Name                 = "{0}-DAG" -f $CurrentPooledHostPool.Name
                ResourceGroupName    = $CurrentPooledHostPoolResourceGroupName
                Location             = $CurrentPooledHostPool.Location
                HostPoolArmPath      = $CurrentAzWvdHostPool.Id
                ApplicationGroupType = 'Desktop'
            }

            Write-Verbose -Message "Creating the Desktop Application Group for the '$($CurrentPooledHostPool.Name)' Host Pool (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
            $CurrentAzDesktopApplicationGroup = New-AzWvdApplicationGroup @parameters

            #region Assign groups to an application group
            # Get the object ID of the user group you want to assign to the application group
            Do 
            {
                $AzADGroup = $null
                $AzADGroup = Get-AzADGroup -DisplayName $CurrentPooledHostPoolUsersADGroupName
                Write-Verbose -Message "Sleeping 10 seconds ..."
                Start-Sleep -Seconds 10
            } While (-not($AzADGroup.Id))

            # Assign users to the application group
            $parameters = @{
                ObjectId           = $AzADGroup.Id
                ResourceName       = $CurrentAzDesktopApplicationGroup.Name
                ResourceGroupName  = $CurrentPooledHostPoolResourceGroupName
                RoleDefinitionName = 'Desktop Virtualization User'
                ResourceType       = 'Microsoft.DesktopVirtualization/applicationGroups'
            }

            Write-Verbose -Message "Assigning the 'Desktop Virtualization User' RBAC role to '$CurrentPooledHostPoolUsersADGroupName' AD Group on the Desktop Application Group (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
            $null = New-AzRoleAssignment @parameters
            #endregion 

            #endregion

            #region Remote Application Group Setup
            $parameters = @{
                Name                 = "{0}-RAG" -f $CurrentPooledHostPool.Name
                ResourceGroupName    = $CurrentPooledHostPoolResourceGroupName
                Location             = $CurrentPooledHostPool.Location
                HostPoolArmPath      = $CurrentAzWvdHostPool.Id
                ApplicationGroupType = 'RemoteApp'
            }

            Write-Verbose -Message "Creating the Remote Application Group for the '$($CurrentPooledHostPool.Name)' Host Pool (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
            $CurrentAzRemoteApplicationGroup = New-AzWvdApplicationGroup @parameters

            <#
            #region Adding Some Remote Apps
            $RemoteApps = "Edge","Excel"
            $FilteredAzWvdStartMenuItem = (Get-AzWvdStartMenuItem -ApplicationGroupName $CurrentAzRemoteApplicationGroup.Name -ResourceGroupName $CurrentPooledHostPoolResourceGroupName | Where-Object -FilterScript {$_.Name -match $($RemoteApps -join '|')} | Select-Object -Property *)

            foreach($CurrentFilteredAppAlias in $FilteredAzWvdStartMenuItem)
            {
                #$Name = $CurrentFilteredAppAlias.Name -replace "(.*)/"
                $Name = $CurrentFilteredAppAlias.Name -replace "$($CurrentAzRemoteApplicationGroup.Name)/"
                New-AzWvdApplication -AppAlias $CurrentFilteredAppAlias.appAlias -GroupName $CurrentAzRemoteApplicationGroup.Name -Name $Name -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -CommandLineSetting DoNotAllow
            }
            #endregion
            #>

            #region Assign groups to an application group
            # Get the object ID of the user group you want to assign to the application group
            Do 
            {
                $AzADGroup = $null
                $AzADGroup = Get-AzADGroup -DisplayName $CurrentPooledHostPoolUsersADGroupName
                Write-Verbose -Message "Sleeping 10 seconds ..."
                Start-Sleep -Seconds 10
            } While (-not($AzADGroup.Id))

            # Assign users to the application group
            $parameters = @{
                ObjectId           = $AzADGroup.Id
                ResourceName       = $CurrentAzRemoteApplicationGroup.Name
                ResourceGroupName  = $CurrentPooledHostPoolResourceGroupName
                RoleDefinitionName = 'Desktop Virtualization User'
                ResourceType       = 'Microsoft.DesktopVirtualization/applicationGroups'
            }

            Write-Verbose -Message "Assigning the 'Desktop Virtualization User' RBAC role to '$CurrentPooledHostPoolUsersADGroupName' AD Group on the Remote Application Group (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
            $null = New-AzRoleAssignment @parameters
            #endregion 

            #endregion

            #region Workspace Setup
            $parameters = @{
                Name                      = "ws-{0}" -f $CurrentPooledHostPool.Name
                ResourceGroupName         = $CurrentPooledHostPoolResourceGroupName
                ApplicationGroupReference = $CurrentAzRemoteApplicationGroup.Id, $CurrentAzDesktopApplicationGroup.Id
                Location                  = $CurrentPooledHostPool.Location
            }

            Write-Verbose -Message "Creating the WorkSpace for the '$($CurrentPooledHostPool.Name)' Host Pool (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
            $CurrentAzWvdWorkspace = New-AzWvdWorkspace @parameters
            #endregion

            #region Adding Session Hosts to the Host Pool
            $ADDomainJoinUPNCredential = New-Object System.Management.Automation.PSCredential -ArgumentList("$($CurrentPooledHostPool.ADDomainJoinCredential.UserName)@$DomainName", $CurrentPooledHostPool.ADDomainJoinCredential.Password)
            Write-Verbose -Message "Adding the Session Hosts to the '$($CurrentPooledHostPool.Name)' Host Pool (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
            if (-not([String]::IsNullOrEmpty($CurrentPooledHostPool.VMSourceImageId)))
            {
                New-AzAvdSessionHost -HostPoolId $CurrentAzWvdHostPool.Id -NamePrefix $CurrentPooledHostPool.NamePrefix -VMNumberOfInstances $CurrentPooledHostPool.VMNumberOfInstances -LocalAdminCredential $CurrentPooledHostPool.LocalAdminCredential -RegistrationInfoToken $RegistrationInfoToken.Token -DomainName $DomainName -ADDomainJoinUPNCredential $ADDomainJoinUPNCredential -OUPath $CurrentPooledHostPoolOU.DistinguishedName -VMSize $CurrentPooledHostPool.VMSize -VMSourceImageId $CurrentPooledHostPool.VMSourceImageId
            }
            else
            {
                New-AzAvdSessionHost -HostPoolId $CurrentAzWvdHostPool.Id -NamePrefix $CurrentPooledHostPool.NamePrefix -VMNumberOfInstances $CurrentPooledHostPool.VMNumberOfInstances -LocalAdminCredential $CurrentPooledHostPool.LocalAdminCredential -RegistrationInfoToken $RegistrationInfoToken.Token -DomainName $DomainName -ADDomainJoinUPNCredential $ADDomainJoinUPNCredential -OUPath $CurrentPooledHostPoolOU.DistinguishedName -VMSize $CurrentPooledHostPool.VMSize -ImagePublisherName $CurrentPooledHostPool.ImagePublisherName -ImageOffer $CurrentPooledHostPool.ImageOffer -ImageSku $CurrentPooledHostPool.ImageSku            
            }
            $SessionHostNames = (Get-AzWvdSessionHost -HostpoolName $CurrentPooledHostPool.Name -ResourceGroupName $CurrentPooledHostPoolResourceGroupName).ResourceId -replace ".*/"
            #Adding Session Hosts to the dedicated AD MSIX Host group
            Write-Verbose -Message "Adding the Session Hosts Session Hosts to the '$($CurrentPooledHostPoolMSIXHostsADGroup.Name)' AD Group ..."
            $CurrentPooledHostPoolMSIXHostsADGroup | Add-ADGroupMember -Members $($SessionHostNames | Get-ADComputer).DistinguishedName
            #endregion 

            #region Copying and Installing the MSIX Demo PFX File(s) (for signing MSIX Packages) on Session Host(s)
            Copy-MSIXDemoPFXFile -SessionHosts $SessionHostNames
            #endregion 

            #region Adding the MSIX package(s) to the Host Pool
            #From https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-powershell
            foreach ($CurrentMSIXDemoPackage in $MSIXDemoPackages)
            {
                $obj = $null
                While ($null -eq $obj)
                {
                    Write-Verbose -Message "Expanding MSIX Image '$CurrentMSIXDemoPackage' ..."
                    $MyError = $null
                    $obj = Expand-AzWvdMsixImage -HostPoolName $CurrentPooledHostPool.Name -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -Uri $CurrentMSIXDemoPackage -ErrorAction Ignore -ErrorVariable MyError
                    if (($null -eq $obj))
                    {
                        Write-Verbose -Message "Error Message: $($MyError.Exception.Message)"
                        Write-Verbose -Message "Sleeping 30 seconds ..."
                        Start-Sleep -Seconds 30
                    }
                }

                $DisplayName = "{0} v{1}" -f $obj.PackageApplication.FriendlyName, $obj.Version
                Write-Verbose -Message "Adding MSIX Image '$CurrentMSIXDemoPackage' as '$DisplayName'..."
                New-AzWvdMsixPackage -HostPoolName $CurrentPooledHostPool.Name -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -PackageAlias $obj.PackageAlias -DisplayName $DisplayName -ImagePath $CurrentMSIXDemoPackage -IsActive:$true
                #Get-AzWvdMsixPackage -HostPoolName $CurrentPooledHostPool.Name -ResourceGroupName $CurrentPooledHostPoolResourceGroupName | Where-Object {$_.PackageFamilyName -eq $obj.PackageFamilyName}
            }
            #endregion 

            #region Publishing MSIX apps to an application group
            #From https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-powershell#publish-msix-apps-to-an-application-group
            #Publishing MSIX application to a desktop application group
            $AzContext = Get-AzContext
            $SubscriptionId = $AzContext.Subscription.Id
            $null = New-AzWvdApplication -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -SubscriptionId $SubscriptionId -Name $obj.PackageName -ApplicationType MsixApplication  -ApplicationGroupName $CurrentAzDesktopApplicationGroup.Name -MsixPackageFamilyName $obj.PackageFamilyName -CommandLineSetting 0
            
            #Publishing MSIX application to a RemoteApp application group
            $null = New-AzWvdApplication -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -SubscriptionId $SubscriptionId -Name $obj.PackageName -ApplicationType MsixApplication  -ApplicationGroupName $CurrentAzRemoteApplicationGroup.Name -MsixPackageFamilyName $obj.PackageFamilyName -CommandLineSetting 0 -MsixPackageApplicationId $obj.PackageApplication.AppId
            #endregion 
            <#
            #>

            #region Disabling the "\Microsoft\Windows\WindowsUpdate\Scheduled Start" Scheduled Task on Session Host(s)
            #From https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-azure-portal#turn-off-automatic-updates-for-msix-app-attach-applications
            Disable-WindowsUpdateScheduledStartScheduledTask -SessionHosts $SessionHostNames
            #endregion 

            #region Log Analytics WorkSpace Setup : Monitor and manage performance and health
            #From https://learn.microsoft.com/en-us/training/modules/monitor-manage-performance-health/3-log-analytics-workspace-for-azure-monitor
            #From https://www.rozemuller.com/deploy-azure-monitor-for-windows-virtual-desktop-automated/#update-25-03-2021
            $LogAnalyticsWorkSpaceName = "opiw{0}" -f $($CurrentAzWvdHostPool.Name -replace "\W")
            Write-Verbose -Message "Creating the Log Analytics WorkSpace '$($LogAnalyticsWorkSpaceName)' (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
            $LogAnalyticsWorkSpace = New-AzOperationalInsightsWorkspace -Location $CurrentPooledHostPool.Location -Name $LogAnalyticsWorkSpaceName -Sku pergb2018 -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -Force
            #Enabling Diagnostics Setting for the HostPool
            $null = Set-AzDiagnosticSetting -Name $CurrentAzWvdHostPool.Name -ResourceId $CurrentAzWvdHostPool.Id -WorkspaceId $LogAnalyticsWorkSpace.ResourceId -Enabled $true -Category "Checkpoint", "Error", "Management", "Connection", "HostRegistration", "AgentHealthStatus"
            Write-Verbose -Message "Enabling Diagnostics Setting for the HostPool for the  '$($CurrentAzWvdHostPool.Name)' Host Pool (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
            #Enabling Diagnostics Setting for the WorkSpace
            Write-Verbose -Message "Enabling Diagnostics Setting for the HostPool for the  '$($CurrentAzWvdWorkspace.Name)' Work Space ..."
            $null = Set-AzDiagnosticSetting -Name $CurrentAzWvdWorkspace.Name -ResourceId $CurrentAzWvdWorkspace.Id -WorkspaceId $LogAnalyticsWorkSpace.ResourceId -Enabled $true #-Category "Checkpoint", "Error", "Management", "Feed"

            $EventLogs = @(
                @{EventLogName='Application' ; CollectInformation=$false; CollectWarnings=$true; CollectErrors=$true}
                @{EventLogName='Microsoft-FSLogix-Apps/Admin' ; CollectInformation=$true;  CollectWarnings=$true; CollectErrors=$true}
                @{EventLogName='Microsoft-FSLogix-Apps/Operational' ; CollectInformation=$true;  CollectWarnings=$true; CollectErrors=$true}
                @{EventLogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; CollectInformation=$true;  CollectWarnings=$true; CollectErrors=$true}
                @{EventLogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin' ; CollectInformation=$true; CollectWarnings=$true; CollectErrors=$true}
                @{EventLogName='System' ; CollectInformation=$false; CollectWarnings=$true; CollectErrors=$true}
            )
            foreach ($CurrentEventLog in $EventLogs)
            {
                $Name = $CurrentEventLog.EventLogName -replace "\W", "-"
                Write-Verbose -Message "Enabling the '$($CurrentEventLog.EventLogName)' EventLog in the '$LogAnalyticsWorkSpaceName' Log Analytics WorkSpace (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
                $null = New-AzOperationalInsightsWindowsEventDataSource -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -WorkspaceName $LogAnalyticsWorkSpaceName -Name $Name @CurrentEventLog -Force
            }
            
            $PerformanceCouters = @(
                @{ObjectName='LogicalDisk'; CounterName='% Free Space'; InstanceName= 'C:'; IntervalSeconds=60}
                @{ObjectName='LogicalDisk'; CounterName='Avg. Disk Queue Length'; InstanceName= 'C:'; IntervalSeconds=30}
                @{ObjectName='LogicalDisk'; CounterName='Avg. Disk sec/Transfer'; InstanceName= 'C:'; IntervalSeconds=60}
                @{ObjectName='LogicalDisk'; CounterName='Current Disk Queue Length'; InstanceName= 'C:'; IntervalSeconds=30}
                @{ObjectName='Memory'; CounterName='Available Mbytes'; InstanceName= '*'; IntervalSeconds=30}
                @{ObjectName='Memory'; CounterName='Page Faults/sec'; InstanceName= '*'; IntervalSeconds=30}
                @{ObjectName='Memory'; CounterName='Pages/sec'; InstanceName= '*'; IntervalSeconds=30}
                @{ObjectName='Memory'; CounterName='% Committed Bytes In Use'; InstanceName= '*'; IntervalSeconds=30}
                @{ObjectName='PhysicalDisk'; CounterName='Avg. Disk sec/Read'; InstanceName= '*'; IntervalSeconds=30}
                @{ObjectName='PhysicalDisk'; CounterName='Avg. Disk sec/Transfer'; InstanceName= '*'; IntervalSeconds=30}
                @{ObjectName='PhysicalDisk'; CounterName='Avg. Disk sec/Write'; InstanceName= '*'; IntervalSeconds=30}
                @{ObjectName='PhysicalDisk'; CounterName='Avg. Disk Queue Length'; InstanceName= '*'; IntervalSeconds=30}
                @{ObjectName='Processor Information'; CounterName='% Processor Time'; InstanceName= '_Total'; IntervalSeconds=30}
                @{ObjectName='RemoteFX Network'; CounterName='Current TCP RTT'; InstanceName= '*'; IntervalSeconds=30}
                @{ObjectName='RemoteFX Network'; CounterName='Current UDP Bandwidth'; InstanceName= '*'; IntervalSeconds=30}
                @{ObjectName='Terminal Services'; CounterName='Active Sessions'; InstanceName= '*'; IntervalSeconds=60}
                @{ObjectName='Terminal Services'; CounterName='Inactive Sessions'; InstanceName= '*'; IntervalSeconds=60}
                @{ObjectName='Terminal Services'; CounterName='Total Sessions'; InstanceName= '*'; IntervalSeconds=60}
                @{ObjectName='User Input Delay per Process'; CounterName='Max Input Delay'; InstanceName= '*'; IntervalSeconds=30}
                @{ObjectName='User Input Delay per Session'; CounterName='Max Input Delay'; InstanceName= '*'; IntervalSeconds=30}
            )
            foreach ($CurrentPerformanceCouter in $PerformanceCouters)
            {
                $Name = $('{0}-{1}-{2}' -f $CurrentPerformanceCouter.ObjectName, $CurrentPerformanceCouter.CounterName, $CurrentPerformanceCouter.InstanceName) -replace "\W", "-"
                Write-Verbose -Message "Enabling '$($CurrentPerformanceCouter.CounterName)' Performance Counter in the '$LogAnalyticsWorkSpaceName' Log Analytics WorkSpace (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
                $null = New-AzOperationalInsightsWindowsPerformanceCounterDataSource -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -WorkspaceName $LogAnalyticsWorkSpaceName -Name $Name @CurrentPerformanceCouter -Force
            }

            # region install Log Analytics Agent on Virtual Machine(s)
            $SessionHosts = Get-AzWvdSessionHost -HostpoolName $CurrentPooledHostPool.Name -ResourceGroupName $CurrentPooledHostPoolResourceGroupName
            if (-not([string]::IsNullOrEmpty($SessionHosts.ResourceId)))
            {
                $SessionHostVMs = $SessionHosts.ResourceId | Get-AzVM
                $LogAnalyticsWorkSpaceKey = ($LogAnalyticsWorkSpace | Get-AzOperationalInsightsWorkspaceSharedKey).PrimarySharedKey
                $PublicSettings = @{ "workspaceId" = $LogAnalyticsWorkSpace.CustomerId }
                $ProtectedSettings = @{ "workspaceKey" = $LogAnalyticsWorkSpaceKey }
                foreach ($CurrentSessionHostVM in $SessionHostVMs)
                {
                    Write-Verbose -Message "Install Log Analytics Agent on the '$($CurrentSessionHostVM.Name )' Virtual Machine (in the '$CurrentPooledHostPoolResourceGroupName' Resource Group) ..."
                    $null = Set-AzVMExtension -ExtensionName "MicrosoftMonitoringAgent" -ResourceGroupName $CurrentPooledHostPoolResourceGroupName -VMName $CurrentSessionHostVM.Name -Publisher "Microsoft.EnterpriseCloud.Monitoring" -ExtensionType "MicrosoftMonitoringAgent" -Settings $PublicSettings -TypeHandlerVersion "1.0" -ProtectedSettings $ProtectedSettings -Location $ThisDomainControllerVirtualNetwork.Location
                }
            }
            #endregion
        }    
    }
    end {}
}
#endregion

#region Main code
Clear-Host
$StartTime = Get-Date
$Error.Clear()
#From https://aka.ms/azps-changewarnings: Disabling breaking change warning messages in Azure PowerShell
$null = Update-AzConfig -DisplayBreakingChangeWarning $false
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

#For installing required modules if needed
#Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
$null = Get-PackageProvider -Name NuGet -Force
$RequiredModules = 'Az.Accounts', 'Az.Compute', 'Az.DesktopVirtualization', 'Az.ImageBuilder', 'Az.Insights', 'Az.ManagedServiceIdentity','Az.Monitor', 'Az.Network', 'Az.KeyVault', 'Az.OperationalInsights', 'Az.PrivateDns', 'Az.Resources', 'Az.Storage', 'PowerShellGet'
$InstalledModule = Get-InstalledModule -Name $RequiredModules -ErrorAction Ignore
if (-not([String]::IsNullOrEmpty($InstalledModule)))
{
    $MissingModules  = (Compare-Object -ReferenceObject $RequiredModules -DifferenceObject $InstalledModule.Name).InputObject
}
else
{
    $MissingModules  = $RequiredModules
}
if (-not([String]::IsNullOrEmpty($MissingModules)))
{
    Install-Module -Name $MissingModules -AllowClobber -Force
}

#region Azure Provider Registration
#To use Azure Virtual Desktop, you have to register for the providers and to ensure that RegistrationState will be set to Registered.
$null = Register-AzResourceProvider -ProviderNamespace Microsoft.DesktopVirtualization
$null = Register-AzResourceProvider -ProviderNamespace Microsoft.Insights
$null = Register-AzResourceProvider -ProviderNamespace Microsoft.VirtualMachineImages
$null = Register-AzResourceProvider -ProviderNamespace Microsoft.Storage
$null = Register-AzResourceProvider -ProviderNamespace Microsoft.Compute
$null = Register-AzResourceProvider -ProviderNamespace Microsoft.KeyVault
$null = Register-AzResourceProvider -ProviderNamespace Microsoft.ManagedIdentity
#Important: Wait until RegistrationState is set to Registered. 
While (Get-AzResourceProvider -ProviderNamespace Microsoft.DesktopVirtualization, Microsoft.Insights, Microsoft.VirtualMachineImages, Microsoft.Storage, Microsoft.Compute, Microsoft.KeyVault, Microsoft.ManagedIdentity | Where-Object -FilterScript {$_.RegistrationState -ne 'Registered'})
{
    Write-Verbose -Message "Sleeping 10 seconds ..."
    Start-Sleep -Seconds 10
}


#endregion

#region Azure Connection
if (-not(Get-AzContext))
{
    Connect-AzAccount
    Get-AzSubscription | Out-GridView -OutputMode Single | Select-AzSubscription
}
#endregion

#region Installling FSLogix GPO Setting
if (-not(Test-Path -Path $env:SystemRoot\policyDefinitions\en-US\fslogix.adml -PathType Leaf) -or -not(Test-Path -Path $env:SystemRoot\policyDefinitions\fslogix.admx -PathType Leaf)) {
    $FSLogixLatestZipName = 'FSLogix_Apps_Latest.zip'
    $OutFile = Join-Path -Path $env:Temp -ChildPath $FSLogixLatestZipName
    $FSLogixLatestURI = 'https://download.microsoft.com/download/c/4/4/c44313c5-f04a-4034-8a22-967481b23975/FSLogix_Apps_2.9.8440.42104.zip'
    Start-BitsTransfer $FSLogixLatestURI -destination $OutFile
    Expand-Archive -Path $OutFile -DestinationPath $env:Temp\FSLogixLatest -Force
    Copy-Item -Path $env:Temp\FSLogixLatest\fslogix.adml $env:SystemRoot\policyDefinitions\en-US
    Copy-Item -Path $env:Temp\FSLogixLatest\fslogix.admx $env:SystemRoot\policyDefinitions
}
#endregion 

#region Installling AVD GPO Setting
if (-not(Test-Path -Path $env:SystemRoot\policyDefinitions\en-US\terminalserver-avd.adml -PathType Leaf) -or -not(Test-Path -Path $env:SystemRoot\policyDefinitions\terminalserver-avd.admx -PathType Leaf)) {
    $AVDGPOLatestCabName = 'AVDGPTemplate.cab'
    $OutFile = Join-Path -Path $env:Temp -ChildPath $AVDGPOLatestCabName
    $AVDGPOLatestURI = 'https://aka.ms/avdgpo'
    Invoke-WebRequest -Uri  $AVDGPOLatestURI -OutFile $OutFile
    $AVDGPOLatestDir = New-Item -Path $env:Temp\AVDGPOLatest -ItemType Directory -Force
    Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "extrac32 $OutFile /Y" -WorkingDirectory $AVDGPOLatestDir -Wait 
    $ZipFiles = Get-ChildItem -Path $AVDGPOLatestDir -Filter *.zip -File 
    $ZipFiles | Expand-Archive -DestinationPath $AVDGPOLatestDir -Force
    Remove-Item -Path $ZipFiles.FullName -Force

    Copy-Item -Path $AVDGPOLatestDir\en-US\terminalserver-avd.adml $env:SystemRoot\policyDefinitions\en-US
    Copy-Item -Path $AVDGPOLatestDir\terminalserver-avd.admx $env:SystemRoot\policyDefinitions
    Remove-Item -Path $AVDGPOLatestDir -Recurse -Force
}
#endregion 

#region function calls
$ADDomainJoin = "adjoin"
$ADDomainJoinClearTextPassword = 'I@m@JediLikeMyF@therB4Me'
$ADDomainJoinSecurePassword = ConvertTo-SecureString -String $ADDomainJoinClearTextPassword -AsPlainText -Force
#If you prefer use auto-generated secure password, uncomment the line below
#$ADDomainJoinSecurePassword = New-RandomPassword -ClipBoard -AsSecureString -Verbose
$ADDomainJoinCredential = New-Object System.Management.Automation.PSCredential -ArgumentList($ADDomainJoin, $ADDomainJoinSecurePassword)
$ADDomainJoinCredential = New-Object System.Management.Automation.PSCredential -ArgumentList("$ADDomainJoin", $ADDomainJoinSecurePassword)

$LocalAdmin = "localadmin"
$LocalAdminClearTextPassword = 'I@m@JediLikeMyF@therB4Me'
$LocalAdminSecurePassword = ConvertTo-SecureString -String $LocalAdminClearTextPassword -AsPlainText -Force
#If you prefer use auto-generated secure password, uncomment the line below
#$LocalAdminSecurePassword = New-RandomPassword -ClipBoard -AsSecureString -Verbose
$LocalAdminCredential = New-Object System.Management.Automation.PSCredential -ArgumentList($LocalAdmin, $LocalAdminSecurePassword)

$AzureComputeGallery = New-AzureComputeGallery -Verbose
#Taking randomly and VM Image source (among the ones available) in the Azure compute Gallery
$VMSourceImageId = (Get-AzGalleryImageDefinition -GalleryName $AzureComputeGallery.Name -ResourceGroupName $AzureComputeGallery.ResourceGroupName).Id | Get-Random
Write-Verbose "Random VM Source Image Id for the ACG Host Pool: $VMSourceImageId"
$PooledHostPools = @(
    [PSCustomObject]@{Name = "hp-ad-demo-mp-001"; Location = "EastUS"; MaxSessionLimit = 5; NamePrefix = "MP"; VMNumberOfInstances = 2; LocalAdminCredential=$LocalAdminCredential; ADDomainJoinCredential=$ADDomainJoinCredential; VMSize="Standard_D2s_v3"; ImagePublisherName="microsoftwindowsdesktop"; ImageOffer="office-365";ImageSku = "win11-22h2-avd-m365" }
    [PSCustomObject]@{Name = "hp-ad-demo-acg-eu-001"; Location = "EastUS"; MaxSessionLimit = 5; NamePrefix = "ACG"; VMNumberOfInstances = 2; LocalAdminCredential=$LocalAdminCredential; ADDomainJoinCredential=$ADDomainJoinCredential; VMSize="Standard_D2s_v3"; VMSourceImageId=$VMSourceImageId }
)
#>

New-AzWvdPooledHostPoolSetup -PooledHostPool $PooledHostPools -Verbose
#Or pipeline processing call
#$PooledHostPools | New-AzWvdPooledHostPoolSetup 

#Remove-AzResourceGroup -Name $AzureComputeGallery.ResourceGroupName -Force -AsJob

#Uncomment the following block to remove all previously existing resources
#Remove-AzWvdPooledHostPoolSetup -PooledHostPool $PooledHostPools -Verbose
#Or pipeline processing call
#$PooledHostPools | Remove-AzWvdPooledHostPoolSetup -Verbose

#(Get-ADComputer -Filter 'DNSHostName -like "*"').Name | Invoke-GPUpdate -Force
Invoke-Command -ComputerName $((Get-ADComputer -Filter 'DNSHostName -like "*"').Name) -ScriptBlock { gpupdate /force /wait:-1 /target:computer} 
#To be sure the "Domain Admins" AD group is excluded from FSLogix profile
Invoke-Command -ComputerName $((Get-ADComputer -Filter 'DNSHostName -like "*"').Name) -ScriptBlock { Get-LocalGroupMember -Group "FSLogix Profile Exclude List" -ErrorAction Ignore}
#endregion
$EndTime = Get-Date
$TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
Write-Host -Object "Processing Time: $($TimeSpan.ToString())"
#endregion