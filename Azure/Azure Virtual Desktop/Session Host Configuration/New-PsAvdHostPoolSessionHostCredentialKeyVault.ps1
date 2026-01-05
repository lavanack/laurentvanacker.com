function New-PsAvdHostPoolSessionHostCredentialKeyVault {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential] $LocalAdminCredential,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential] $ADJoinCredential,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Azure.Commands.Network.Models.PSSubnet] $Subnet
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"

    $VirtualNetwork = Get-AzResource -ResourceId $($Subnet.Id -replace "/subnets/.*$") | Get-AzVirtualNetwork
    $Location = $VirtualNetwork.Location

    Write-Host -Object "Azure Key Vault Setup"
    $StartTime = Get-Date
    #region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
    [HostPool]::BuildAzureLocationShortNameHashtable()
    #endregion
    
    $Index = 0
    do {
        $Index++
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Index: $Index"
        $KeyVaultName = "kvavdhpcred{0}{1:D3}" -f [HostPool]::GetAzLocationShortName($Location), $Index
        $KeyVaultName = $KeyVaultName.ToLower()
        if ($Index -gt 999) {
            Write-Error "No name available for HostPool Credential Keyvault" -ErrorAction Stop
        }
    } while (-not(Test-AzKeyVaultNameAvailability -Name $KeyVaultName).NameAvailable)
    Write-Host -Object "Azure Key Vault Name for Credentials: $KeyVaultName"
    $ResourceGroupName = "rg-avd-kv-poc-{0}-{1:D3}" -f [HostPool]::GetAzLocationShortName($Location), $Index

    $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
    if ($null -eq $ResourceGroup) {
        $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
    }

    #region Create an Azure Key Vault
    #$KeyVault = New-AzKeyVault -VaultName $KeyVaultName -ResourceGroup $ResourceGroupName -Location $location -EnabledForDeployment -EnabledForTemplateDeployment -SoftDeleteRetentionInDays 7 -DisableRbacAuthorization #-EnablePurgeProtection
    #As the owner of the key vault, you automatically have access to create secrets. If you need to let another user create secrets, use:
    #$AccessPolicy = Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -UserPrincipalName $UserPrincipalName -PermissionsToSecrets Get,Delete,List,Set -PassThru
    $KeyVault = New-AzKeyVault -VaultName $KeyVaultName -ResourceGroup $ResourceGroupName -Location $location -EnabledForDeployment -EnabledForTemplateDeployment -SoftDeleteRetentionInDays 7 #-EnablePurgeProtection
    #region 'Key Vault Administrator' RBAC Assignment
    $RoleDefinition = Get-AzRoleDefinition -Name "Key Vault Administrator"
    $Parameters = @{
        SignInName         = (Get-AzContext).Account.Id
        RoleDefinitionName = $RoleDefinition.Name
        Scope              = $KeyVault.ResourceId
    }
    while (-not(Get-AzRoleAssignment @Parameters)) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.SignInName)' Identity on the '$($Parameters.Scope)' scope"
        $RoleAssignment = New-AzRoleAssignment @Parameters
        Write-Verbose -Message "`$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
        Start-Sleep -Seconds 30
    }
    #endregion 
    #endregion 

    #region Defining local admin credential(s)
    if ($LocalAdminCredential) {
        $SecureUserName = $(ConvertTo-SecureString -String $LocalAdminCredential.UserName -AsPlainText -Force) 
        $SecurePassword = $LocalAdminCredential.Password
    }
    else {
        $UserName = "localadmin"
        $SecureUserName = $(ConvertTo-SecureString -String $UserName -AsPlainText -Force) 
        Write-Host "UserName: $UserName"
        $SecurePassword = New-RandomPassword -AsSecureString
    }
    $SecretUserName = "LocalAdminUserName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating a secret in $KeyVaultName called '$SecretUserName'"
    $secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretUserName -SecretValue $SecureUserName

    $SecretPassword = "LocalAdminPassword"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating a secret in $KeyVaultName called '$SecretPassword'"
    $secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretPassword -SecretValue $SecurePassword
    #endregion

    #region Defining AD join credential(s)
    if ($ADJoinCredential) {
        $SecureUserName = $(ConvertTo-SecureString -String $ADJoinCredential.UserName -AsPlainText -Force) 
        $SecurePassword = $ADJoinCredential.Password
    }
    else {
        $UserName = "adjoin"
        $SecureUserName = $(ConvertTo-SecureString -String $UserName -AsPlainText -Force) 
        Write-Host "UserName: $UserName"
        $SecurePassword = New-RandomPassword -AsSecureString
    }

    $SecretUserName = "ADJoinUserName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating a secret in $KeyVaultName called '$SecretUserName'"
    $secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretUserName -SecretValue $SecureUserName

    $SecretPassword = "ADJoinPassword"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating a secret in $KeyVaultName called '$SecretPassword'"
    $secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretPassword -SecretValue $SecurePassword
    #endregion

    #region Private endpoint for Key Vault Setup
    #From https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-powershell?tabs=dynamic-ip#create-a-private-endpoint
    #From https://www.jorgebernhardt.com/private-endpoint-azure-key-vault-powershell/


    #Creating a Private EndPoint for this KeyVault on this Subnet
    New-PsAvdPrivateEndpointSetup -SubnetId $Subnet.Id -KeyVault $KeyVault

    #endregion

    $EndTime = Get-Date
    $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
    Write-Host -Object "Azure Key Vault Setup Processing Time: $($TimeSpan.ToString())"

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $KeyVault
}
