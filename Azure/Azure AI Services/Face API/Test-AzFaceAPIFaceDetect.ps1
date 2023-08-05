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
#requires -Version 5 -Modules Az.Accounts, Az.CognitiveServices
[CmdletBinding()]
param
(
)

#region Function definitions
function Get-AzCognitiveServicesNameAvailability {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [alias('Name')]
        [string]$CognitiveServicesName
    )
    #region Azure Context
    # Log in first with Connect-AzAccount if not using Cloud Shell

    $azContext = Get-AzContext
    $SubcriptionID = $azContext.Subscription.Id
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
    $token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'  = 'application/json'
        'Authorization' = 'Bearer ' + $token.AccessToken
    }
    #endregion
    $Body = [ordered]@{ 
        "subdomainName" = $CognitiveServicesName
        "type"          = "Microsoft.CognitiveServices/accounts"
    } | ConvertTo-Json

    $URI = "https://management.azure.com/subscriptions/$SubcriptionID/providers/Microsoft.CognitiveServices/checkDomainAvailability?api-version=2023-05-01"
    try {
        # Invoke the REST API
        $Response = Invoke-RestMethod -Method POST -Headers $authHeader -Body $Body -ContentType "application/json" -Uri $URI -ErrorVariable ResponseError
    }
    catch [System.Net.WebException] {   
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        $respStream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($respStream)
        $Response = $reader.ReadToEnd() | ConvertFrom-Json
        Write-Warning -Message $Response.message
    }
    return $Response
}
#endregion

Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

#region Defining variables 
$SubscriptionName = "Cloud Solution Architect"
#region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
$AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
$ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/microsoft/CloudAdoptionFramework/master/ready/AzNamingTool/repository/resourcelocations.json
$shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
#endregion

# Login to your Azure subscription.
While (-not((Get-AzContext).Subscription.Name -eq $SubscriptionName)) {
    Connect-AzAccount
    Get-AzSubscription | Out-GridView -OutputMode Single -Title "Select your Azure Subscription" | Select-AzSubscription
    #$Subscription = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction Ignore
    #Select-AzSubscription -SubscriptionName $SubscriptionName | Select-Object -Property *
}


$null = Register-AzResourceProvider -ProviderNamespace Microsoft.CognitiveServices
#Important: Wait until RegistrationState is set to Registered. 
While (Get-AzResourceProvider -ProviderNamespace Microsoft.CognitiveServices | Where-Object -FilterScript { $_.RegistrationState -ne 'Registered' }) {
    Start-Sleep -Seconds 10
}

# Set the Azure region for the Cognitive Services resource
$Location = "eastus"
$LocationShortName = $shortNameHT[$Location].shortName
$CognitiveServicesNameMaxLength = 15
$CognitiveServicesPrefix = "cg"
$ResourceGroupPrefix = "rg"
$Project = "cg"
$Role = "faceapi"
#$DigitNumber = 4
$DigitNumber = $CognitiveServicesNameMaxLength - ($CognitiveServicesPrefix + $Project + $Role + $LocationShortName).Length

Do {
    $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
    # Create a unique name for the Cognitive Services resource
    $CognitiveServicesName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $CognitiveServicesPrefix, $Project, $Role, $LocationShortName, $Instance                       
} While ((-not(Get-AzCognitiveServicesNameAvailability -Name $CognitiveServicesName).isSubdomainAvailable))

$ResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
$ResourceGroupName = $ResourceGroupName.ToLower()

$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
if ($ResourceGroup) {
    #Step 0: Remove previously existing Azure Resource Group with the same name
    $ResourceGroup | Remove-AzResourceGroup -Force -Verbose
}

# Create Resource Groups 
$ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force

# Create a Free ComputerVision (Only One Per Subscription)  Cognitive Services resource: https://azure.microsoft.com/en-us/pricing/details/cognitive-services/computer-vision/
try {
    $cognitiveServices = New-AzCognitiveServicesAccount -Name $cognitiveServicesName -ResourceGroupName $resourceGroupName -Location $Location -SkuName "F0" -Kind "Face" -ErrorAction Stop
}
catch [System.Management.Automation.PSInvalidOperationException] {   
    # Dig into the exception to get the Response details.
    # Note that value__ is not a typo.
    Write-Error -Message "$($_.Exception.Message)"
    exit
}

$cognitiveServices

#Sleeping some seconds to avoid a HTTP error 401".
Start-Sleep -Seconds 60

# Get the key and CognitiveServicesAccountEndPoint for the Cognitive Services resource
$CognitiveServicesAccountKey = (Get-AzCognitiveServicesAccountKey -ResourceGroupName $resourceGroupName -Name $cognitiveServicesName).Key2
$CognitiveServicesAccountEndPoint = (Get-AzCognitiveServicesAccount -ResourceGroupName $resourceGroupName -Name $cognitiveServicesName).Endpoint

#region Face - Detect
$Pictures = (Get-ChildItem -Path $CurrentDir -Filter "*.jpg" -File -Recurse).FullName
$detectUrl = "$CognitiveServicesAccountEndPoint/face/v1.0/detect?returnFaceId=true&returnFaceLandmarks=true&returnFaceAttributes=headPose,glasses,occlusion,accessories,blur,exposure,noise,qualityForRecognition&returnFaceLandmarks=true&recognitionModel=recognition_04&returnRecognitionModel=true&detectionModel=detection_01"

foreach ($CurrentPicture in $Pictures) {
    Write-Host -Object "`r`nProcessing '$CurrentPicture' ..." -ForegroundColor Cyan

    # Detect face in the photo using the Computer Vision API
    #FROM https://eastus.dev.cognitive.microsoft.com/docs/services/563879b61984550e40cbbe8d/operations/563879b61984550f30395236
    #$detectUrl = "$CognitiveServicesAccountEndPoint/face/v1.0/detect?returnFaceId=true&returnFaceLandmarks=true&returnFaceAttributes=headPose,glasses&recognitionModel=recognition_04&returnRecognitionModel=true"
    $CurrentPictureData = [System.IO.File]::ReadAllBytes($CurrentPicture)
    $CurrentPictureBase64 = [System.Convert]::ToBase64String($CurrentPictureData)

    $headers = @{
        "Ocp-Apim-Subscription-Key" = $CognitiveServicesAccountKey
        "Content-Type"              = "application/octet-stream"
    }

    try {
        # Invoke the REST API
        $Response = Invoke-RestMethod -Uri $detectUrl -Method POST -Headers $headers -InFile $CurrentPicture
    }
    catch [System.Net.WebException] {   
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        $respStream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($respStream)
        $Response = $reader.ReadToEnd() | ConvertFrom-Json
        if (-not([string]::IsNullOrEmpty($Response.message))) {
            Write-Error -Message $Response.message -ErrorAction Stop
        }
    }
    $Response | Format-List -Property * -Force
    $Response | ConvertTo-Json
}
#endregion