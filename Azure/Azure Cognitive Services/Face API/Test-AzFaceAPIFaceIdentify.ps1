﻿<#
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

#From https://eastus.dev.cognitive.microsoft.com/docs/services/563879b61984550e40cbbe8d/
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
        'Content-Type'='application/json'
        'Authorization'='Bearer ' + $token.AccessToken
    }
    #endregion
    $Body = [ordered]@{ 
        "subdomainName" = $CognitiveServicesName
        "type" = "Microsoft.CognitiveServices/accounts"
    } | ConvertTo-Json

    $URI = "https://management.azure.com/subscriptions/$SubcriptionID/providers/Microsoft.CognitiveServices/checkDomainAvailability?api-version=2023-05-01"
    try
    {
        # Invoke the REST API
        $Response = Invoke-RestMethod -Method Post -Headers $authHeader -Body $Body -ContentType "application/json" -Uri $URI -ErrorVariable ResponseError
    }
    catch [System.Net.WebException] {   
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        Write-Warning -Message "Code: $(($_.ErrorDetails.Message | ConvertFrom-Json).error.code)"
        Write-Warning -Message "Message: $(($_.ErrorDetails.Message | ConvertFrom-Json).error.message)"
        $respStream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($respStream)
        $Response = $reader.ReadToEnd() | ConvertFrom-Json
        Write-Error -Message $Response.message -ErrorAction Stop
    }
    finally 
    {
    }
    return $Response
}

function Split-ArrayIntoSegments {
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [array]$InputArray,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [int]$SegmentSize = 10
    )

    $start=0
    $end=[math]::Min($start+$SegmentSize-1, $InputArray.Count)

    $segments = while ($start -lt $InputArray.Count)
    {
        # Comma creates an array with one element (subarray)
        ,$InputArray[$start..$end]
        $start = $end+1
        $end=[math]::Min($start+$SegmentSize-1, $InputArray.Count-1)
    }
    return $segments
}
#endregion

Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir
$TimeStamp = Get-Date -Format 'yyyyMMddHHmmss'

#region Defining variables 
$SubscriptionName = "Cloud Solution Architect"
#region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
$AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
$ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/microsoft/CloudAdoptionFramework/master/ready/AzNamingTool/repository/resourcelocations.json
$shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
#endregion
#endregion

#region Login to your Azure subscription.
While (-not((Get-AzContext).Subscription.Name -eq $SubscriptionName)) {
    Connect-AzAccount
    Get-AzSubscription | Out-GridView -OutputMode Single -Title "Select your Azure Subscription" | Select-AzSubscription
    #$Subscription = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction Ignore
    #Select-AzSubscription -SubscriptionName $SubscriptionName | Select-Object -Property *
}
#endregion

#region Registering required providers
$null = Register-AzResourceProvider -ProviderNamespace Microsoft.CognitiveServices
#Important: Wait until RegistrationState is set to Registered. 
While (Get-AzResourceProvider -ProviderNamespace Microsoft.CognitiveServices | Where-Object -FilterScript { $_.RegistrationState -ne 'Registered' }) {
    Start-Sleep -Seconds 10
}
#endregion

#region Azure resources creation
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

#region Cognitive Services
# Create a Free FaceAPI (Only One Per Subscription)  Cognitive Services resource: https://azure.microsoft.com/en-us/pricing/details/cognitive-services/computer-vision/
try
{
    $cognitiveServices = New-AzCognitiveServicesAccount -Name $cognitiveServicesName -ResourceGroupName $resourceGroupName -Location $Location -SkuName "S0" -Kind "Face" -ErrorAction Stop
}
catch [System.Management.Automation.PSInvalidOperationException] {   
    # Dig into the exception to get the Response details.
    # Note that value__ is not a typo.
    Write-Error -Message "$($_.Exception.Message)"
    exit
}

$cognitiveServices
#endregion

# Get the key and CognitiveServicesAccountEndPoint for the Cognitive Services resource
$CognitiveServicesAccountKey = (Get-AzCognitiveServicesAccountKey -ResourceGroupName $resourceGroupName -Name $cognitiveServicesName).Key2
$CognitiveServicesAccountEndPoint = (Get-AzCognitiveServicesAccount -ResourceGroupName $resourceGroupName -Name $cognitiveServicesName).Endpoint

Write-Verbose -Message "`$CognitiveServicesAccountKey: $CognitiveServicesAccountKey"
Write-Verbose -Message "`$CognitiveServicesAccountEndPoint: $CognitiveServicesAccountEndPoint"
#endregion

#region Snapshot
#region Snapshot - List
$facelistsUrl = "$CognitiveServicesAccountEndPoint/face/v1.0/facelists"
$headers = @{
    "Ocp-Apim-Subscription-Key" = $CognitiveServicesAccountKey
    "Content-Type" = "application/octet-stream"
}

Do
{
    Start-Sleep -Seconds 10
    try
    {
        $StatusCode = 200
        # Invoke the REST API
        $Response = Invoke-RestMethod -Uri $facelistsUrl -Method Get -Headers $headers
    }
    catch [System.Net.WebException] {   
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        $StatusCode = $_.Exception.Response.StatusCode.value__
    }
    Write-Verbose -Message "Status Code: $StatusCode"

} While ($StatusCode -eq 401)

#endregion
#endregion

#region Face
#region Face - Detect
$IdentifyDir = Join-Path -Path $CurrentDir -ChildPath "Identify"
$Pictures = (Get-ChildItem -Path $IdentifyDir -Filter "*.jpg" -File -Recurse).FullName
$detectUrl = "$CognitiveServicesAccountEndPoint/face/v1.0/detect?returnFaceId=true&returnFaceLandmarks=true&returnFaceAttributes=headPose,glasses,occlusion,accessories,blur,exposure,noise,qualityForRecognition&returnFaceLandmarks=true&recognitionModel=recognition_04&returnRecognitionModel=true&detectionModel=detection_01"
$headers = @{
    "Ocp-Apim-Subscription-Key" = $CognitiveServicesAccountKey
    "Content-Type" = "application/octet-stream"
}


$IdentifyDetectedFaces = foreach($CurrentPicture in $Pictures) {
    Write-Host -Object "`r`nDetecting '$CurrentPicture' ..." -ForegroundColor Cyan

    # Detect face in the photo using the Face API
    #$detectUrl = "$CognitiveServicesAccountEndPoint/face/v1.0/detect?returnFaceId=true&returnFaceLandmarks=true&returnFaceAttributes=headPose,glasses&recognitionModel=recognition_04&returnRecognitionModel=true"
    #$CurrentPictureData = [System.IO.File]::ReadAllBytes($CurrentPicture)
    #$CurrentPictureBase64 = [System.Convert]::ToBase64String(#$CurrentPictureData)

    try
    {
        # Invoke the REST API
        $Response = Invoke-RestMethod -Uri $detectUrl -Method Post -Headers $headers -InFile $CurrentPicture
        $Response | Select-Object -Property *, @{Name='FilePath'; Expression={$CurrentPicture}}
        if (-not($Response))
        {
            Write-Warning -Message "No face identification for '$CurrentPicture'"
        }
    }
    catch [System.Net.WebException] {   
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        Write-Warning -Message "Code: $(($_.ErrorDetails.Message | ConvertFrom-Json).error.code)"
        Write-Warning -Message "Message: $(($_.ErrorDetails.Message | ConvertFrom-Json).error.message)"
        $respStream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($respStream)
        $Response = $reader.ReadToEnd() | ConvertFrom-Json
        if (-not([string]::IsNullOrEmpty($Response.message)))
        {
            Write-Error -Message $Response.message -ErrorAction Stop
        }
    }
}
$IdentifyDetectedFaces
$IdentifyDetectedFacesHT = $IdentifyDetectedFaces | Group-Object -Property faceId -AsHashTable -AsString
#endregion
#endregion

#region PersonGroup
#region PersonGroup - Delete (all)
$PersonGroupUrl = "$CognitiveServicesAccountEndPoint/face/v1.0/persongroups/"
$headers = @{
    "Ocp-Apim-Subscription-Key" = $CognitiveServicesAccountKey
    "Content-Type" = "application/octet-stream"
}

$PersonGroups = Invoke-RestMethod -Uri $PersonGroupUrl -Method Get -Headers $headers
foreach($CurrentPersonGroup in $PersonGroups) {
    Write-Host -Object "`r`nDeleting '$($CurrentPersonGroup.name)' PersonGroup ..." -ForegroundColor Cyan
    #region FaceList - Get
    try
    {
        # Invoke the REST API
        $DeletedFaceList = Invoke-RestMethod -Uri $($PersonGroupUrl+$CurrentPersonGroup.personGroupId) -Method Delete -Headers $headers
        $DeletedFaceList
    }
    catch [System.Net.WebException] {   
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        Write-Warning -Message "Code: $(($_.ErrorDetails.Message | ConvertFrom-Json).error.code)"
        Write-Warning -Message "Message: $(($_.ErrorDetails.Message | ConvertFrom-Json).error.message)"
        $respStream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($respStream)
        $Response = $reader.ReadToEnd() | ConvertFrom-Json
        if (-not([string]::IsNullOrEmpty($Response.message)))
        {
            Write-Error -Message $Response.message -ErrorAction Stop
        }
    }
    #endregion
}
#endregion

#region Creating a new PersonGroup
$MyPersonGroupName = "mypersongroup_$TimeStamp"
$CreatePersonGroupUrl = "$CognitiveServicesAccountEndPoint/face/v1.0/persongroups/$MyPersonGroupName"
$headers = @{
    "Ocp-Apim-Subscription-Key" = $CognitiveServicesAccountKey
    "Content-Type" = "application/json"
}

$Body = [ordered]@{
    "name" = $MyPersonGroupName
    "userData" = $MyPersonGroupName
    "recognitionModel" = "recognition_04"
} | ConvertTo-Json

try
{
    # Invoke the REST API
    Write-Host -Object "`r`nCreating '$MyPersonGroupName' PersonGroup ..." -ForegroundColor Cyan
    $CreatedPersonGroup = Invoke-RestMethod -Uri $CreatePersonGroupUrl -Method Put -Headers $headers -Body $Body
}
catch [System.Net.WebException] {   
    # Dig into the exception to get the Response details.
    # Note that value__ is not a typo.
    Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
    Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
    Write-Warning -Message "Code: $(($_.ErrorDetails.Message | ConvertFrom-Json).error.code)"
    Write-Warning -Message "Message: $(($_.ErrorDetails.Message | ConvertFrom-Json).error.message)"
    $respStream = $_.Exception.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($respStream)
    $Response = $reader.ReadToEnd() | ConvertFrom-Json
    if (-not([string]::IsNullOrEmpty($CreatedPersonGroup.message)))
    {
        Write-Error -Message $Response.message -ErrorAction Stop
    }
}
#endregion

#region PersonGroup - List
$PersonGroupsUrl = "$CognitiveServicesAccountEndPoint/face/v1.0/persongroups/"
$headers = @{
    "Ocp-Apim-Subscription-Key" = $CognitiveServicesAccountKey
    "Content-Type" = "application/octet-stream"
}

$PersonGroups = Invoke-RestMethod -Uri $PersonGroupsUrl -Method Get -Headers $headers
$PersonGroups
#endregion

#region PersonGroup - Person
#region Creating new PersonGroup - Persons
$TrainingDir = Join-Path -Path $CurrentDir -ChildPath "Training"
$Persons = (Get-ChildItem -Path $TrainingDir -Directory).Name
$MyPersonGroupName = "mypersongroup_$TimeStamp"
$CreatePersonGroupPersonUrl = "$CognitiveServicesAccountEndPoint/face/v1.0/persongroups/$MyPersonGroupName/persons"
$headers = @{
    "Ocp-Apim-Subscription-Key" = $CognitiveServicesAccountKey
    "Content-Type" = "application/json"
}

$AddedPersonToPersonGroup = foreach($CurrentPerson in $Persons) {
    $MyPersonGroupPersonName = (Get-Item (Split-Path $CurrentPicture)).Name
    $Body = [ordered]@{
        "name" = $CurrentPerson
        "userData" = $CurrentPerson
    } | ConvertTo-Json

    try
    {
        # Invoke the REST API
        Write-Host -Object "`r`nAdding '$CurrentPerson' to '$MyPersonGroupName' PersonGroup ..." -ForegroundColor Cyan
        $CreatedPersonGroupPerson = Invoke-RestMethod -Uri $CreatePersonGroupPersonUrl -Method Post -Headers $headers -Body $Body
    }
    catch [System.Net.WebException] {   
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        Write-Warning -Message "Code: $(($_.ErrorDetails.Message | ConvertFrom-Json).error.code)"
        Write-Warning -Message "Message: $(($_.ErrorDetails.Message | ConvertFrom-Json).error.message)"
        $respStream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($respStream)
        $Response = $reader.ReadToEnd() | ConvertFrom-Json
        if (-not([string]::IsNullOrEmpty($CreatedPersonGroupPerson.message)))
        {
            Write-Error -Message $Response.message -ErrorAction Stop
        }
    }
}
#endregion

#region PersonGroup - Person - Add Face
$TrainingDir = Join-Path -Path $CurrentDir -ChildPath "Training"

$PersonGroupsUrl = "$CognitiveServicesAccountEndPoint/face/v1.0/persongroups/"
$headers = @{
    "Ocp-Apim-Subscription-Key" = $CognitiveServicesAccountKey
    "Content-Type" = "application/octet-stream"
}

$PersonGroups = Invoke-RestMethod -Uri $PersonGroupsUrl -Method Get -Headers $headers
$AddedFacesToPersonGroupsPerson = foreach($CurrentPersonGroup in $PersonGroups) {
    try
    {
        # Invoke the REST API
        $CurrentPersonGroupsPersonUrl = $PersonGroupsUrl+$CurrentPersonGroup.personGroupId+'/persons'
        $Persons = Invoke-RestMethod -Uri $CurrentPersonGroupsPersonUrl -Method Get -Headers $headers
        foreach ($CurrentPerson in $Persons)
        {
            $TrainingPersonDir = Join-Path -Path $TrainingDir -ChildPath $($CurrentPerson.Name)
            $Pictures = (Get-ChildItem -Path $TrainingPersonDir -Filter "*.jpg" -File -Recurse).FullName
            $AddFaceToCurrentPersonGroupsPersonUrl = "$CurrentPersonGroupsPersonUrl/$($CurrentPerson.personId)/persistedFaces?userData=$($CurrentPerson.userData)&detectionModel=detection_01"
            foreach ($CurrentPicture in $Pictures)
            {
                Write-Host -Object "`r`nAdding '$CurrentPicture' to '$($CurrentPerson.Name)' in $($CurrentPersonGroup.name) PersonGroup ..." -ForegroundColor Cyan
                #$CurrentPictureData = [System.IO.File]::ReadAllBytes($CurrentPicture)
                #$CurrentPictureBase64 = [System.Convert]::ToBase64String($CurrentPictureData)
                $Person = Invoke-RestMethod -Uri $AddFaceToCurrentPersonGroupsPersonUrl -Method Post -Headers $headers -InFile $CurrentPicture
                $Person | Select-Object -Property *, @{Name='FilePath'; Expression={$CurrentPicture}}
            }
        }
    }
    catch [System.Net.WebException] {   
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        Write-Warning -Message "Code: $(($_.ErrorDetails.Message | ConvertFrom-Json).error.code)"
        Write-Warning -Message "Message: $(($_.ErrorDetails.Message | ConvertFrom-Json).error.message)"
        $respStream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($respStream)
        $Response = $reader.ReadToEnd() | ConvertFrom-Json
        if (-not([string]::IsNullOrEmpty($Response.message)))
        {
            Write-Error -Message $Response.message -ErrorAction Stop
        }
    }
}
$AddedFacesToPersonGroupsPerson
#endregion

#region PersonGroup - Person - List
$PersonGroupsUrl = "$CognitiveServicesAccountEndPoint/face/v1.0/persongroups/"
$headers = @{
    "Ocp-Apim-Subscription-Key" = $CognitiveServicesAccountKey
    "Content-Type" = "application/octet-stream"
}

$PersonGroups = Invoke-RestMethod -Uri $PersonGroupsUrl -Method Get -Headers $headers
$PersonGroupData = foreach($CurrentPersonGroup in $PersonGroups) {
    try
    {
        # Invoke the REST API
        Write-Host -Object "`r`nListing '$($CurrentPersonGroup.name)' PersonGroup ..." -ForegroundColor Cyan
        $CurrentPersonGroupsPersonUrl = $PersonGroupsUrl+$CurrentPersonGroup.personGroupId+'/persons'
        $Response = Invoke-RestMethod -Uri $CurrentPersonGroupsPersonUrl -Method Get -Headers $headers
        $Response
    }
    catch [System.Net.WebException] {   
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        Write-Warning -Message "Code: $(($_.ErrorDetails.Message | ConvertFrom-Json).error.code)"
        Write-Warning -Message "Message: $(($_.ErrorDetails.Message | ConvertFrom-Json).error.message)"
        $respStream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($respStream)
        $Response = $reader.ReadToEnd() | ConvertFrom-Json
        if (-not([string]::IsNullOrEmpty($Response.message)))
        {
            Write-Error -Message $Response.message -ErrorAction Stop
        }
    }
}
$PersonGroupData | Format-List -Property *
$PersonGroupDataHT = $PersonGroupData | Group-Object -Property personId -AsHashTable -AsString
#endregion
#endregion

#region PersonGroup - Train
$PersonGroupsUrl = "$CognitiveServicesAccountEndPoint/face/v1.0/persongroups/"
$headers = @{
    "Ocp-Apim-Subscription-Key" = $CognitiveServicesAccountKey
    "Content-Type" = "application/octet-stream"
}

$PersonGroups = Invoke-RestMethod -Uri $PersonGroupsUrl -Method Get -Headers $headers
foreach($CurrentPersonGroup in $PersonGroups) {
    try
    {
        # Invoke the REST API
        Write-Host -Object "`r`nTraining '$($CurrentPersonGroup.name)' PersonGroup ..." -ForegroundColor Cyan
        $CurrentPersonGroupsPersonUrl = $PersonGroupsUrl+$CurrentPersonGroup.personGroupId+'/train'
        $Response = Invoke-RestMethod -Uri $CurrentPersonGroupsPersonUrl -Method Post -Headers $headers
        $Response
    }
    catch [System.Net.WebException] {   
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        Write-Warning -Message "Code: $(($_.ErrorDetails.Message | ConvertFrom-Json).error.code)"
        Write-Warning -Message "Message: $(($_.ErrorDetails.Message | ConvertFrom-Json).error.message)"
        $respStream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($respStream)
        $Response = $reader.ReadToEnd() | ConvertFrom-Json
        if (-not([string]::IsNullOrEmpty($Response.message)))
        {
            Write-Error -Message $Response.message -ErrorAction Stop
        }
    }
}
#endregion

#region PersonGroup - Training Status
$PersonGroupsUrl = "$CognitiveServicesAccountEndPoint/face/v1.0/persongroups/"
$headers = @{
    "Ocp-Apim-Subscription-Key" = $CognitiveServicesAccountKey
    "Content-Type" = "application/octet-stream"
}

$PersonGroups = Invoke-RestMethod -Uri $PersonGroupsUrl -Method Get -Headers $headers
$PersonGroupTrainData = foreach($CurrentPersonGroup in $PersonGroups) {
    try
    {
        # Invoke the REST API
        Write-Host -Object "`r`nTraining '$($CurrentPersonGroup.name)' PersonGroup ..." -ForegroundColor Cyan
        $CurrentPersonGroupsPersonUrl = $PersonGroupsUrl+$CurrentPersonGroup.personGroupId+'/training'
        $Response = Invoke-RestMethod -Uri $CurrentPersonGroupsPersonUrl -Method Get -Headers $headers
        $Response
    }
    catch [System.Net.WebException] {   
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        Write-Warning -Message "Code: $(($_.ErrorDetails.Message | ConvertFrom-Json).error.code)"
        Write-Warning -Message "Message: $(($_.ErrorDetails.Message | ConvertFrom-Json).error.message)"
        $respStream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($respStream)
        $Response = $reader.ReadToEnd() | ConvertFrom-Json
        if (-not([string]::IsNullOrEmpty($Response.message)))
        {
            Write-Error -Message $Response.message -ErrorAction Stop
        }
    }
}
$PersonGroupTrainData | Format-List -Property * -Force
#endregion
#endregion

#region Face
#region Face - Identify
$IdentifyDir = Join-Path -Path $CurrentDir -ChildPath "Identify"
$Pictures = (Get-ChildItem -Path $IdentifyDir -Filter "*.jpg" -File -Recurse).FullName
$identifyUrl = "$CognitiveServicesAccountEndPoint/face/v1.0/identify"
$headers = @{
    "Ocp-Apim-Subscription-Key" = $CognitiveServicesAccountKey
    "Content-Type" = "application/octet-stream"
}

$PersonGroupsUrl = "$CognitiveServicesAccountEndPoint/face/v1.0/persongroups/"
$PersonGroups = Invoke-RestMethod -Uri $PersonGroupsUrl -Method Get -Headers $headers
#Have to split faceId into 10-items segments because we can only pass max 10 items per API call
$SegmentedIdentifyDetectedFacesFaceId = Split-ArrayIntoSegments -InputArray $IdentifyDetectedFaces.faceId -SegmentSize 10

$Index = 0
$FaceIdentifyData = foreach ($CurrentFaceIdsSegment in $SegmentedIdentifyDetectedFacesFaceId) {
    $Index++
    foreach ($CurrentPersonGroup in $PersonGroups) {
        $Body = [ordered]@{ 
            "personGroupId" = $CurrentPersonGroup.personGroupId
            "faceIds" = $CurrentFaceIdsSegment
            "maxNumOfCandidatesReturned" = 1
            "confidenceThreshold" = 0.8
        } | ConvertTo-Json
        try
        {
            # Invoke the REST API
            Write-Host -Object "`r`n[$Index/$($SegmentedIdentifyDetectedFacesFaceId.Count)] Identifying '$($CurrentPersonGroup.name)' PersonGroup ..." -ForegroundColor Cyan
            $Response = Invoke-RestMethod -Uri $identifyUrl -Method Post -Headers $headers -Body $Body -ContentType "application/json"
            $Response
        }
        catch [System.Net.WebException] {   
            # Dig into the exception to get the Response details.
            # Note that value__ is not a typo.
            Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
            Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
            Write-Warning -Message "Code: $(($_.ErrorDetails.Message | ConvertFrom-Json).error.code)"
            Write-Warning -Message "Message: $(($_.ErrorDetails.Message | ConvertFrom-Json).error.message)"
            $respStream = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($respStream)
            $Response = $reader.ReadToEnd() | ConvertFrom-Json
            if (-not([string]::IsNullOrEmpty($Response.message)))
            {
                Write-Error -Message $Response.message -ErrorAction Stop
            }
        }
    }
}

foreach ($FaceIdentifyDataItem in $FaceIdentifyData) {
    $CurrentIdentifyDetectedFace = $IdentifyDetectedFacesHT[$($FaceIdentifyDataItem.faceId)]
    if ($FaceIdentifyDataItem.candidates.Count -gt 0)
    {
        $Identification = $PersonGroupDataHT[$FaceIdentifyDataItem.candidates.personId].name
        $Confidence = '{0:p2}' -f $FaceIdentifyDataItem.candidates.confidence
        #$Confidence = $('{0:p2}' -f $FaceIdentifyDataItem.candidates.confidence).padLeft(7, '0')
        #Write-Host -Object "Matching '$Identification' (Confidence: $Confidence) for [$($FaceIdentifyDataItem.faceId)] '$($CurrentIdentifyDetectedFace.FilePath)' ..." -ForegroundColor Cyan    
        Write-Host -Object "Matching '$Identification' (Confidence: $Confidence) for '$($CurrentIdentifyDetectedFace.FilePath)' ..." -ForegroundColor Cyan    
    }
    else
    {
        Write-Warning -Message "Unable to identify [$($FaceIdentifyDataItem.faceId)] '$($CurrentIdentifyDetectedFace.FilePath)' ..." 
    }
}
#endregion
#endregion


#region Some Cleanup
Remove-AzResourceGroup -Name $ResourceGroupName -Force -Verbose -AsJob
$cognitiveServices | Remove-AzCognitiveServicesAccount -Force -Verbose
$null=Get-AzCognitiveServicesAccount -InRemovedState | Remove-AzResource -Force -Verbose
<#
<#
#>
#endregion
