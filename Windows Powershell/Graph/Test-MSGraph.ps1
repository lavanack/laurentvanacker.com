#From https://tech.nicolonsky.ch/exploring-the-new-microsoft-graph-powershell-modules/
Install-Module Microsoft.Graph, Az.Accounts, AzureAD
Import-Module Az.Accounts, AzureAD
Get-Module Microsoft.Graph.* -ListAvailable

#Connect-AzAccount
$AzureADUser = Connect-AzureAD

#Connect to the graph API
#Connect-MgGraph -Scopes User.Read.All, Group.Read.All, Application.Read.All, Directory.ReadWrite.All, ChannelMessage.Send -ContextScope Process -ForceRefresh
Disconnect-MgGraph
Connect-MgGraph -Scopes "User.Read.All", "Group.ReadWrite.All", "ChannelSettings.ReadWrite.All" -ContextScope Process -ForceRefresh

#Get information based on the scope given at the connection step
Get-MgGroup
Get-MgUser
Get-MgApplication

#Check the scope(s)
Get-MgContext
(Get-MgContext).Scopes
[Microsoft.Graph.PowerShell.Authentication.GraphSession]::Instance.AuthContext

#region Creating a self-signed certificate 

#From https://adamtheautomator.com/microsoft-graph-api-powershell/#Prerequisites
# Your app  name (can something more descriptive as well)
$appName = "Microsoft Graph PowerShell Script"

# Your tenant name (can something more descriptive as well)
$TenantName = $AzureADUser.TenantDomain

# Where to export the certificate without the private key
$CerOutputPath = "C:\Temp\$TenantName.cer"

# What cert store you want it to be in
$StoreLocation = "Cert:\CurrentUser\My"

# Expiration date of the new certificate
$ExpirationDate = (Get-Date).AddYears(2)

# Splat for readability
$CreateCertificateSplat = @{
    FriendlyName      = $appName
    DnsName           = $TenantName
    CertStoreLocation = $StoreLocation
    NotAfter          = $ExpirationDate
    KeyExportPolicy   = "Exportable"
    KeySpec           = "Signature"
    Provider          = "Microsoft Enhanced RSA and AES Cryptographic Provider"
    HashAlgorithm     = "SHA256"
}

Get-ChildItem -Path $StoreLocation | Where-Object { $_.Subject -eq "CN=$TenantName" } | Remove-Item -Force -Verbose

# Create certificate
$Certificate = New-SelfSignedCertificate @CreateCertificateSplat

# Get certificate path
$CertPath = Join-Path -Path $StoreLocation -ChildPath $Certificate.Thumbprint

# Export certificate without private key
$export = Export-Certificate -Cert $CertPath -FilePath $CerOutputPath

$credValue = [System.Convert]::ToBase64String($Certificate.GetRawCertData())
Write-Output "Exported certificate '$($Certificate.Thumbprint)' to '$($export.FullName)'"
#endregion

#region Creating an Azure AD application and its Service Principal
#From https://rajanieshkaushikk.wordpress.com/2019/07/31/how-to-assign-permissions-to-azure-ad-app-by-using-powershell/
# Set required permissions via Microsoft Graph Service Principal
$svcprincipal = Get-AzureADServicePrincipal -All $true | Where-Object -FilterScript { $_.DisplayName -eq "Microsoft Graph" }
$AppRoles = $svcprincipal.AppRoles | Where-Object -FilterScript { $_.value -in @("User.Read.All", "Group.Read.All", "Application.Read.All", "Directory.ReadWrite.All") }
$Oauth2Permissions = $svcprincipal.Oauth2Permissions | Where-Object -FilterScript { $_.value -in @("ChatMessage.Send", "Chat.ReadWrite") }
$RoleResourceAccess = $AppRoles | ForEach-Object -Process { New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList $_.Id, "Role" } 
$ScopeResourceAccess = $Oauth2Permissions | ForEach-Object -Process { New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList $_.Id, "Scope" } 
$RequiredResourceAccess = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
$RequiredResourceAccess.ResourceAppId = $svcprincipal.AppId
$RequiredResourceAccess.ResourceAccess = $RoleResourceAccess + $ScopeResourceAccess

#Create an Azure AD application and upload the self-signed certificate
#Remove any previsouly exisiting Azure AD application with the same name 
Get-AzureADApplication -SearchString $appName | Remove-AzureADApplication -Verbose
#Or New-MgApplication
$myApp = New-AzureADApplication -DisplayName $appName -RequiredResourceAccess $RequiredResourceAccess
New-AzADAppCredential -ApplicationId $myApp.AppId  -CertValue $credValue -StartDate $Certificate.NotBefore -EndDate $Certificate.NotAfter
#Set the current AZure AD user as Azure AD application owner
Add-AzureADApplicationOwner -ObjectId $myApp.ObjectId -RefObjectId (Get-AzADUser -UserPrincipalName $AzureADUser.Account).Id
$AzureADServicePrincipal = New-AzureADServicePrincipal -AppId $myApp.AppId
#endregion

Start-Sleep -Seconds 10
#Go to the Service Principal to grant admin content and reconnect again
Connect-MgGraph -ClientId $myApp.AppId -TenantId $AzureADUser.TenantId -CertificateThumbprint $Certificate.Thumbprint  -ContextScope Process -ForceRefresh
Connect-MgGraph -Scopes User.Read.All, Group.Read.All, Application.Read.All, Directory.ReadWrite.All, ChannelMessage.Send -ContextScope Process -ForceRefresh

<#
For working with JWT Token please refer to :
- https://stackoverflow.com/questions/58375480/json-web-token-signature-not-matching-using-powershell-and-azure-ad-app
- https://samcogan.com/provide-admin-consent-fora-azure-ad-applications-programmatically/
- https://adamtheautomator.com/microsoft-graph-api-powershell 
#>

#region Acquiring an Access Token (Using a Certificate)
$AppId = (Get-AzureADApplication).AppId
$Scope = "https://graph.microsoft.com/.default"

# Create base64 hash of certificate
$CertificateBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash())

# Create JWT timestamp for expiration
$StartDate = (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime()
$JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds
$JWTExpiration = [math]::Round($JWTExpirationTimeSpan, 0)

# Create JWT validity start timestamp
$NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
$NotBefore = [math]::Round($NotBeforeExpirationTimeSpan, 0)

# Create JWT header
$JWTHeader = @{
    alg = "RS256"
    typ = "JWT"
    # Use the CertificateBase64Hash and replace/strip to match web encoding of base64
    x5t = $CertificateBase64Hash -replace '\+', '-' -replace '/', '_' -replace '='
}

# Create JWT payload
$JWTPayLoad = @{
    # What endpoint is allowed to use this JWT
    aud = "https://login.microsoftonline.com/$TenantName/oauth2/token"

    # Expiration timestamp
    exp = $JWTExpiration

    # Issuer = your application
    iss = $AppId

    # JWT ID: random guid
    jti = [guid]::NewGuid()

    # Not to be used before
    nbf = $NotBefore

    # JWT Subject
    sub = $AppId
}

# Convert header and payload to base64
$JWTHeaderToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json))
$EncodedHeader = [System.Convert]::ToBase64String($JWTHeaderToByte)

$JWTPayLoadToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json))
$EncodedPayload = [System.Convert]::ToBase64String($JWTPayLoadToByte)

# Join header and Payload with "." to create a valid (unsigned) JWT
$JWT = $EncodedHeader + "." + $EncodedPayload

# Get the private key object of your certificate
$PrivateKey = $Certificate.PrivateKey

# Define RSA signature and hashing algorithm
$RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
$HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256

# Create a signature of the JWT
$Signature = [Convert]::ToBase64String(
    $PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JWT), $HashAlgorithm, $RSAPadding)
) -replace '\+', '-' -replace '/', '_' -replace '='

# Join the signature to the JWT with "."
$JWT = $JWT + "." + $Signature

# Create a hash with body parameters
$Body = @{
    client_id             = $AppId
    client_assertion      = $JWT
    client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    scope                 = $Scope
    grant_type            = "client_credentials"

}

$Url = "https://login.microsoftonline.com/$TenantName/oauth2/v2.0/token"

# Use the self-generated JWT as Authorization
$Header = @{
    Authorization = "Bearer $JWT"
}

# Splat the parameters for Invoke-Restmethod for cleaner code
$PostSplat = @{
    ContentType = 'application/x-www-form-urlencoded'
    Method      = 'POST'
    Body        = $Body
    Uri         = $Url
    Headers     = $Header
}

$Request = Invoke-RestMethod @PostSplat
#endregion

#region Making Requests to the Microsoft Graph API
# Create header
$Header = @{
    Authorization = "$($Request.token_type) $($Request.access_token)"
}

#Grant Consent
#The clientId and resourceID are the object ID of the Service Principal related to the Azure application
$body = @{
    clientId    = $AzureADServicePrincipal.ObjectId 
    consentType = "AllPrincipals"
    principalId = $null
    resourceId  = $AzureADServicePrincipal.ObjectId
    scope       = "Directory.ReadWrite.All"
    startTime   = "2019-10-19T10:37:00Z"
    expiryTime  = "2019-10-19T10:37:00Z"
}

$apiUrl = "https://graph.microsoft.com/beta/oauth2PermissionGrants"
Invoke-RestMethod -Uri $apiUrl -Headers $Header  -Method POST -Body $($body | ConvertTo-Json) -ContentType "application/json"

# Fetch all oauth2 permissions
$oauth2PermissionGrants = Invoke-RestMethod -Uri $apiUrl -Headers $Header -Method Get -ContentType "application/json"
$oauth2PermissionGrants.value
#Get-AzureADOAuth2PermissionGrant
#endregion


#region playing with Teams
#From https://github.com/microsoftgraph/msgraph-sdk-powershell/blob/dev/samples/5-Teams.ps1
#Removing any existing Team with the same name
Get-MgGroup -Filter "DisplayName eq '$appName'" | ForEach-Object { Remove-MgGroup -GroupId  $_.Id }

#Creating a Team (and becoming the owner)
New-MgTeam -DisplayName $appName -Description $appName -AdditionalProperties @{ "template@odata.bind" = "https://graph.microsoft.com/beta/teamsTemplates('standard')" }

#Get the Team 
$MgGroup = Get-MgGroup -Filter "DisplayName eq '$appName'"
#Get the General Team Channel
$MgTeamChannel = Get-MgTeamChannel -TeamId $MgGroup.Id

$param = @{
    TeamId    = $MgGroup.Id
    ChannelId = $MgTeamChannel.Id
}

#Sample #1 : Won't work. Probably a bug. 
$body = [Microsoft.Graph.PowerShell.Models.MicrosoftGraphItemBody]::new()
$body.Content = '<attachment id="74d20c7f34aa4a7fb74e2b30004247c5"></attachment>'
$body.ContentType = 'html'
$attachment = [Microsoft.Graph.PowerShell.Models.MicrosoftGraphChatMessageAttachment]::new()
$attachment.Id = '74d20c7f34aa4a7fb74e2b30004247c5'
$attachment.Content = @'
{
	"title": "This is an example of posting a card",
	"subtitle": "<h3>This is the subtitle</h3>",
	"text": "Here is some body text. <br>\r\nAnd a <a href=\"http://microsoft.com/\">hyperlink</a>. <br>\r\nAnd below that is some buttons:",
	"buttons": [
		{
			"type": "messageBack",
			"title": "Login to FakeBot",
			"text": "login",
			"displayText": "login",
			"value": "login"
		}
	]
}
'@
$attachment.ContentType = 'application/vnd.microsoft.card.thumbnail'

New-MgTeamChannelMessage @param -Body $body -Attachments $attachment

#Sample 2 
$body = [Microsoft.Graph.PowerShell.Models.MicrosoftGraphItemBody]::new()
$body.Content = '<attachment id="74d20c7f34aa4a7fb74e2b30004247c5"></attachment>'
$body.ContentType = 'html'
New-MgTeamChannelMessage @param -Body $body

#Sample 3 
New-MgTeamChannelMessage @param  -Body @{ Content = "Hello World" }

#Sample #4
Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/teams/$($MgGroup.Id)/channels/$($MgTeamChannel.Id)/messages" -Body @'
{
    "subject": null,
    "body": {
        "contentType": "html",
        "content": "<attachment id=\"74d20c7f34aa4a7fb74e2b30004247c5\"></attachment>"
    },
    "attachments": [
        {
            "id": "74d20c7f34aa4a7fb74e2b30004247c5",
            "contentType": "application/vnd.microsoft.card.thumbnail",
            "contentUrl": null,
            "content": "{\r\n  \"title\": \"This is an example of posting a card\",\r\n  \"subtitle\": \"<h3>This is the subtitle</h3>\",\r\n  \"text\": \"Here is some body text. <br>\\r\\nAnd a <a href=\\\"http://microsoft.com/\\\">hyperlink</a>. <br>\\r\\nAnd below that is some buttons:\",\r\n  \"buttons\": [\r\n    {\r\n      \"type\": \"messageBack\",\r\n      \"title\": \"Login to FakeBot\",\r\n      \"text\": \"login\",\r\n      \"displayText\": \"login\",\r\n      \"value\": \"login\"\r\n    }\r\n  ]\r\n}",
            "name": null,
            "thumbnailUrl": null
        }
    ]
}
'@
#endregion