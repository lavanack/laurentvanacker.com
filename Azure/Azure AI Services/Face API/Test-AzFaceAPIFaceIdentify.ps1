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
    return $Response
}

function Split-ArrayIntoSegments {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [array]$InputArray,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [int]$SegmentSize = 10
    )

    $start = 0
    $end = [math]::Min($start + $SegmentSize - 1, $InputArray.Count)

    $segments = while ($start -lt $InputArray.Count) {
        # Comma creates an array with one element (subarray)
        , $InputArray[$start..$end]
        $start = $end + 1
        $end = [math]::Min($start + $SegmentSize - 1, $InputArray.Count - 1)
    }
    return $segments
}

function Write-MyProgress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [int] $Index,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [int] $Count,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [string] $Item,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [datetime] $StartTime,
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [int] $Id = 1
    )
    Write-Verbose "`$Index: $Index"
    Write-Verbose "`$Count: $Count"
    Write-Verbose "`$Item: $Item"
    Write-Verbose "`$StartTime: $StartTime"
    Write-Verbose "`$Id: $Id"
    $Percent = ($Index / $Count * 100)
    Write-Verbose "`$Percent: $Percent"
    $ElapsedTime = New-TimeSpan -Start $StartTime -End $(Get-Date)
    $ElapsedTimeToString = $ElapsedTime.ToString('hh\:mm\:ss')
    Write-Verbose "`$ElapsedTime: $ElapsedTime"
    try {
        $RemainingTime = New-TimeSpan -Seconds $($ElapsedTime.TotalSeconds / ($Index - 1) * ($Count - $Index + 1))
        $RemainingTimeToString = $RemainingTime.ToString('hh\:mm\:ss')
    }
    catch {
        $RemainingTimeToString = '--:--:--'
    }
    Write-Verbose "`$RemainingTime: $RemainingTime"
    Write-Progress -Id $Id -Activity "[$Index/$Count] Processing '$Item'" -Status "Percent : $('{0:N0}' -f $Percent)% - Elapsed Time: $ElapsedTimeToString - Remaining Time: $RemainingTimeToString" -PercentComplete $Percent
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
#region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
$AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
$ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
$shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
#endregion
#endregion

#region Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount
}
#endregion

#region Registering required providers
$null = Register-AzResourceProvider -ProviderNamespace Microsoft.CognitiveServices
#Important: Wait until RegistrationState is set to Registered. 
While (Get-AzResourceProvider -ProviderNamespace Microsoft.CognitiveServices | Where-Object -FilterScript { $_.RegistrationState -ne 'Registered' }) {
    Write-Verbose -Message "Sleeping 10 seconds ..."
    Start-Sleep -Seconds 10
}
#endregion

#region Azure resources creation
# Set the Azure region for the Cognitive Services resource
$Location = "eastus"
$LocationShortName = $shortNameHT[$Location].shortName
$FaceAPINameMaxLength = 15
$FaceAPIPrefix = "face"
$ResourceGroupPrefix = "rg"
$Project = "ai"
$Role = "face"
$DigitNumber = $FaceAPINameMaxLength - ($FaceAPIPrefix + $Project + $Role + $LocationShortName).Length

Do {
    $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
    # Create a unique name for the Cognitive Services resource
    $FaceAPIName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $FaceAPIPrefix, $Project, $Role, $LocationShortName, $Instance                       
} While ((-not(Get-AzCognitiveServicesNameAvailability -Name $FaceAPIName).isSubdomainAvailable))

$ResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
$ResourceGroupName = $ResourceGroupName.ToLower()

$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
if ($ResourceGroup) {
    #Step 0: Remove previously existing Azure Resource Group with the same name
    $ResourceGroup | Remove-AzResourceGroup -Force
}

# Create Resource Groups 
$ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force

#region Cognitive Services
# Create a Free FaceAPI (Only One Per Subscription)  Cognitive Services resource: https://azure.microsoft.com/en-us/pricing/details/cognitive-services/computer-vision/
try {
    $CognitiveServicesAccount = New-AzCognitiveServicesAccount -Name $FaceAPIName -ResourceGroupName $resourceGroupName -Location $Location -SkuName "S0" -Kind "Face" -ErrorAction Stop
}
catch [System.Management.Automation.PSInvalidOperationException] {   
    # Dig into the exception to get the Response details.
    # Note that value__ is not a typo.
    Write-Error -Message "$($_.Exception.Message)"
    exit
}

#$FaceAPI
#endregion

# Get the key and CognitiveServicesAccountEndPoint for the Cognitive Services resource
$CognitiveServicesAccountKey = (Get-AzCognitiveServicesAccountKey -ResourceGroupName $resourceGroupName -Name $FaceAPIName).Key2
$CognitiveServicesAccountEndPoint = (Get-AzCognitiveServicesAccount -ResourceGroupName $resourceGroupName -Name $FaceAPIName).Endpoint

Write-Verbose -Message "`$CognitiveServicesAccountKey: $CognitiveServicesAccountKey"
Write-Verbose -Message "`$CognitiveServicesAccountEndPoint: $CognitiveServicesAccountEndPoint"
#endregion

#region FaceList - Just for Waiting and avoid useless HTTP/401 response
#region FaceList - List
$facelistsUrl = "$CognitiveServicesAccountEndPoint/face/v1.0/facelists"
$headers = @{
    "Ocp-Apim-Subscription-Key" = $CognitiveServicesAccountKey
    "Content-Type"              = "application/octet-stream"
}

Do {
    Write-Verbose -Message "Sleeping 10 seconds ..."
    Start-Sleep -Seconds 10
    try {
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
    "Content-Type"              = "application/octet-stream"
}

$Index = 0
$StartTime = Get-Date
$IdentifyDetectedFaces = foreach ($CurrentPicture in $Pictures) {
    Write-Host -Object "`r`nDetecting face in '$CurrentPicture' ..."
    $Index++
    Write-MyProgress -Index $Index -Count $Pictures.Count -Item $CurrentPicture -StartTime $StartTime #-Verbose

    try {
        # Invoke the REST API
        $Response = Invoke-RestMethod -Uri $detectUrl -Method Post -Headers $headers -InFile $CurrentPicture
        #Adding the FilePath property to keep track of the picture path
        $Response | Select-Object -Property *, @{Name = 'FilePath'; Expression = { $CurrentPicture } }
        if (-not($Response)) {
            Write-Warning -Message "No face identification for '$CurrentPicture'"
        }
        else {
            Write-Verbose -Message "Face detected in '$CurrentPicture'"
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
        if (-not([string]::IsNullOrEmpty($Response.message))) {
            Write-Error -Message $Response.message -ErrorAction Stop
        }
    }
}
Write-Progress -Activity "Completed !" -Completed
Write-Verbose $($IdentifyDetectedFaces | Out-String)
$IdentifyDetectedFacesHT = $IdentifyDetectedFaces | Group-Object -Property faceId -AsHashTable -AsString
#endregion
#endregion

#region PersonGroup
<#
#region PersonGroup - Delete (all)
$PersonGroupUrl = "$CognitiveServicesAccountEndPoint/face/v1.0/persongroups/"
$headers = @{
    "Ocp-Apim-Subscription-Key" = $CognitiveServicesAccountKey
    "Content-Type" = "application/octet-stream"
}

$Index=0
$StartTime = Get-Date
$PersonGroups = Invoke-RestMethod -Uri $PersonGroupUrl -Method Get -Headers $headers
foreach($CurrentPersonGroup in $PersonGroups) {
    Write-Host -Object "`r`nDeleting '$($CurrentPersonGroup.name)' PersonGroup ..."
    #region FaceList - Get
    $Index++
    Write-MyProgress -Index $Index -Count $PersonGroups.Count -Item $($CurrentPersonGroup.name) -StartTime $StartTime #-Verbose
    try
    {
        # Invoke the REST API
        $DeletedFaceList = Invoke-RestMethod -Uri $($PersonGroupUrl+$CurrentPersonGroup.personGroupId) -Method Delete -Headers $headers
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
        if (-not([string]::IsNullOrEmpty($Response.message))) {
            Write-Error -Message $Response.message -ErrorAction Stop
        }
    }
    #endregion
}
Write-Progress -Activity "Completed !" -Completed
#endregion
#>

#region Creating a new PersonGroup
$MyPersonGroupName = "mypersongroup_$TimeStamp"
$CreatePersonGroupUrl = "$CognitiveServicesAccountEndPoint/face/v1.0/persongroups/$MyPersonGroupName"
$headers = @{
    "Ocp-Apim-Subscription-Key" = $CognitiveServicesAccountKey
    "Content-Type"              = "application/json"
}

$Body = [ordered]@{
    "name"             = $MyPersonGroupName
    "userData"         = $MyPersonGroupName
    "recognitionModel" = "recognition_04"
} | ConvertTo-Json

try {
    # Invoke the REST API
    Write-Host -Object "`r`nCreating '$MyPersonGroupName' PersonGroup ..."
    $Response = Invoke-RestMethod -Uri $CreatePersonGroupUrl -Method Put -Headers $headers -Body $Body
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
    if (-not([string]::IsNullOrEmpty($Response.message))) {
        Write-Error -Message $Response.message -ErrorAction Stop
    }
}
#endregion

#region PersonGroup - List
$PersonGroupsUrl = "$CognitiveServicesAccountEndPoint/face/v1.0/persongroups/"
$headers = @{
    "Ocp-Apim-Subscription-Key" = $CognitiveServicesAccountKey
    "Content-Type"              = "application/octet-stream"
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
    "Content-Type"              = "application/json"
}

$Index = 0
$StartTime = Get-Date
foreach ($CurrentPerson in $Persons) {
    $Body = [ordered]@{
        "name"     = $CurrentPerson
        "userData" = $CurrentPerson
    } | ConvertTo-Json
    $Index++
    Write-MyProgress -Index $Index -Count $Persons.Count -Item $CurrentPerson -StartTime $StartTime #-Verbose

    try {
        # Invoke the REST API
        Write-Host -Object "`r`nAdding '$CurrentPerson' to '$MyPersonGroupName' PersonGroup ..."
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
        if (-not([string]::IsNullOrEmpty($CreatedPersonGroupPerson.message))) {
            Write-Error -Message $Response.message -ErrorAction Stop
        }
    }
}
Write-Progress -Activity "Completed !" -Completed
#endregion

#region PersonGroup - Person - Add Face
$TrainingDir = Join-Path -Path $CurrentDir -ChildPath "Training"

$PersonGroupsUrl = "$CognitiveServicesAccountEndPoint/face/v1.0/persongroups/"
$headers = @{
    "Ocp-Apim-Subscription-Key" = $CognitiveServicesAccountKey
    "Content-Type"              = "application/octet-stream"
}

$PersonGroups = Invoke-RestMethod -Uri $PersonGroupsUrl -Method Get -Headers $headers
$Index = 0
$StartTime = Get-Date
$AddedFacesToPersonGroupsPerson = foreach ($CurrentPersonGroup in $PersonGroups) {
    $Index++
    Write-MyProgress -Index $Index -Count $PersonGroups.Count -Item $CurrentPersonGroup.name -StartTime $StartTime #-Verbose
    try {
        # Invoke the REST API
        $CurrentPersonGroupsPersonUrl = $PersonGroupsUrl + $CurrentPersonGroup.personGroupId + '/persons'
        $Persons = Invoke-RestMethod -Uri $CurrentPersonGroupsPersonUrl -Method Get -Headers $headers
        $Index2 = 0
        $StartTime2 = Get-Date
        foreach ($CurrentPerson in $Persons) {
            $Index2++
            Write-MyProgress -Id 2 -Index $Index2 -Count $Persons.Count -Item $CurrentPerson.name -StartTime $StartTime2
            $TrainingPersonDir = Join-Path -Path $TrainingDir -ChildPath $($CurrentPerson.Name)
            $Pictures = (Get-ChildItem -Path $TrainingPersonDir -Filter "*.jpg" -File -Recurse).FullName
            $AddFaceToCurrentPersonGroupsPersonUrl = "$CurrentPersonGroupsPersonUrl/$($CurrentPerson.personId)/persistedFaces?userData=$($CurrentPerson.userData)&detectionModel=detection_01"
            $Index3 = 0
            $StartTime3 = Get-Date
            foreach ($CurrentPicture in $Pictures) {
                $Index3++
                Write-MyProgress -Id 3 -Index $Index3 -Count $Persons.Count -Item $CurrentPicture -StartTime $StartTime3
                Write-Host -Object "`r`nAdding '$CurrentPicture' to '$($CurrentPerson.Name)' in '$($CurrentPersonGroup.name)' PersonGroup ..."
                $Person = Invoke-RestMethod -Uri $AddFaceToCurrentPersonGroupsPersonUrl -Method Post -Headers $headers -InFile $CurrentPicture
                #Adding the FilePath property to keep track of the picture path
                $Person | Select-Object -Property *, @{Name = 'FilePath'; Expression = { $CurrentPicture } }
                Write-Verbose -Message $($Person | Out-String)
            }
            Write-Progress -Id 3 -Activity "Completed !" -Completed
        }
        Write-Progress -Id 2 -Activity "Completed !" -Completed
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
        if (-not([string]::IsNullOrEmpty($Response.message))) {
            Write-Error -Message $Response.message -ErrorAction Stop
        }
    }
}
Write-Progress -Activity "Completed !" -Completed
$AddedFacesToPersonGroupsPerson
#endregion

#region PersonGroup - Person - List
$PersonGroupsUrl = "$CognitiveServicesAccountEndPoint/face/v1.0/persongroups/"
$headers = @{
    "Ocp-Apim-Subscription-Key" = $CognitiveServicesAccountKey
    "Content-Type"              = "application/octet-stream"
}

$PersonGroups = Invoke-RestMethod -Uri $PersonGroupsUrl -Method Get -Headers $headers
$Index = 0
$StartTime = Get-Date
$PersonGroupData = foreach ($CurrentPersonGroup in $PersonGroups) {
    $Index++
    Write-MyProgress -Index $Index -Count $PersonGroups.Count -Item $CurrentPersonGroup.name -StartTime $StartTime #-Verbose
    try {
        # Invoke the REST API
        Write-Host -Object "`r`nListing '$($CurrentPersonGroup.name)' PersonGroup ..."
        $CurrentPersonGroupsPersonUrl = $PersonGroupsUrl + $CurrentPersonGroup.personGroupId + '/persons'
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
        if (-not([string]::IsNullOrEmpty($Response.message))) {
            Write-Error -Message $Response.message -ErrorAction Stop
        }
    }
}
Write-Progress -Activity "Completed !" -Completed
$PersonGroupData | Format-List -Property *
$PersonGroupDataHT = $PersonGroupData | Group-Object -Property personId -AsHashTable -AsString
#endregion
#endregion

#region PersonGroup - Train
$PersonGroupsUrl = "$CognitiveServicesAccountEndPoint/face/v1.0/persongroups/"
$headers = @{
    "Ocp-Apim-Subscription-Key" = $CognitiveServicesAccountKey
    "Content-Type"              = "application/octet-stream"
}

$PersonGroups = Invoke-RestMethod -Uri $PersonGroupsUrl -Method Get -Headers $headers
$Index = 0
$StartTime = Get-Date
foreach ($CurrentPersonGroup in $PersonGroups) {
    $Index++
    Write-MyProgress -Index $Index -Count $PersonGroups.Count -Item $CurrentPersonGroup.name -StartTime $StartTime #-Verbose
    try {
        # Invoke the REST API
        Write-Host -Object "`r`nTraining '$($CurrentPersonGroup.name)' PersonGroup ..."
        $CurrentPersonGroupsPersonUrl = $PersonGroupsUrl + $CurrentPersonGroup.personGroupId + '/train'
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
        if (-not([string]::IsNullOrEmpty($Response.message))) {
            Write-Error -Message $Response.message -ErrorAction Stop
        }
    }
}
Write-Progress -Activity "Completed !" -Completed
#endregion

#region PersonGroup - Training Status
$PersonGroupsUrl = "$CognitiveServicesAccountEndPoint/face/v1.0/persongroups/"
$headers = @{
    "Ocp-Apim-Subscription-Key" = $CognitiveServicesAccountKey
    "Content-Type"              = "application/octet-stream"
}

$PersonGroups = Invoke-RestMethod -Uri $PersonGroupsUrl -Method Get -Headers $headers
$Index = 0
$StartTime = Get-Date
$PersonGroupTrainData = foreach ($CurrentPersonGroup in $PersonGroups) {
    $Index++
    Write-MyProgress -Index $Index -Count $PersonGroups.Count -Item $CurrentPersonGroup.name -StartTime $StartTime #-Verbose
    try {
        # Invoke the REST API
        Write-Host -Object "`r`nTraining '$($CurrentPersonGroup.name)' PersonGroup ..."
        $CurrentPersonGroupsPersonUrl = $PersonGroupsUrl + $CurrentPersonGroup.personGroupId + '/training'
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
        if (-not([string]::IsNullOrEmpty($Response.message))) {
            Write-Error -Message $Response.message -ErrorAction Stop
        }
    }
}
Write-Progress -Activity "Completed !" -Completed
$PersonGroupTrainData | Format-List -Property * -Force
#endregion
#endregion

#region Face
#region Face - Identify
$identifyUrl = "$CognitiveServicesAccountEndPoint/face/v1.0/identify"
$headers = @{
    "Ocp-Apim-Subscription-Key" = $CognitiveServicesAccountKey
    "Content-Type"              = "application/octet-stream"
}

$PersonGroupsUrl = "$CognitiveServicesAccountEndPoint/face/v1.0/persongroups/"
$PersonGroups = Invoke-RestMethod -Uri $PersonGroupsUrl -Method Get -Headers $headers
#Have to split faceId into 10-items segments because we can only pass max 10 items per API call
$SegmentedIdentifyDetectedFacesFaceId = Split-ArrayIntoSegments -InputArray $IdentifyDetectedFaces.faceId -SegmentSize 10

$Index = 0
$StartTime = Get-Date
$FaceIdentifyData = foreach ($CurrentFaceIdsSegment in $SegmentedIdentifyDetectedFacesFaceId) {
    $Index++
    Write-MyProgress -Index $Index -Count $SegmentedIdentifyDetectedFacesFaceId.Count -Item $Index -StartTime $StartTime #-Verbose
    $Index2 = 0
    $StartTime2 = Get-Date
    foreach ($CurrentPersonGroup in $PersonGroups) {
        $Index2++
        Write-MyProgress -Id 2 -Index $Index2 -Count $PersonGroups.Count -Item $CurrentPersonGroup.name -StartTime $StartTime2
        $Body = [ordered]@{ 
            "personGroupId"              = $CurrentPersonGroup.personGroupId
            "faceIds"                    = $CurrentFaceIdsSegment
            "maxNumOfCandidatesReturned" = 1
            "confidenceThreshold"        = 0.8
        } | ConvertTo-Json
        try {
            # Invoke the REST API
            Write-Host -Object "`r`n[$Index/$($SegmentedIdentifyDetectedFacesFaceId.Count)] Identifying '$($CurrentPersonGroup.name)' PersonGroup ..."
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
            if (-not([string]::IsNullOrEmpty($Response.message))) {
                Write-Error -Message $Response.message -ErrorAction Stop
            }
        }
    }
    Write-Progress -Id 2 -Activity "Completed !" -Completed
}
Write-Progress -Activity "Completed !" -Completed

$Index = 0
$StartTime = Get-Date
$MyMatches = foreach ($FaceIdentifyDataItem in $FaceIdentifyData) {
    $CurrentIdentifyDetectedFace = $IdentifyDetectedFacesHT[$($FaceIdentifyDataItem.faceId)]
    $Index++
    Write-MyProgress -Index $Index -Count $FaceIdentifyData.Count -Item $CurrentIdentifyDetectedFace.FilePath -StartTime $StartTime #-Verbose
    if ($FaceIdentifyDataItem.candidates.Count -gt 0) {
        $Match = $PersonGroupDataHT[$FaceIdentifyDataItem.candidates.personId].name
        $Confidence = '{0:p2}' -f $FaceIdentifyDataItem.candidates.confidence
        Write-Verbose -Message "Matching '$Match' (Confidence: $Confidence) for '$($CurrentIdentifyDetectedFace.FilePath)' ..."
        [PSCustomObject] @{Match = $Match; Confidence = $Confidence; FilePath = $CurrentIdentifyDetectedFace.FilePath }  
    }
    else {
        Write-Warning -Message "Unable to identify [$($FaceIdentifyDataItem.faceId)] '$($CurrentIdentifyDetectedFace.FilePath)' ..." 
    }
}
Write-Progress -Activity "Completed !" -Completed
$MyMatches
#endregion
#endregion

#region Some Cleanup
#Get-AzResourceGroup -Name rg-cg-face* | Remove-AzResourceGroup -Force -Verbose -AsJob
$null = Remove-AzResourceGroup -Name $ResourceGroupName -Force -AsJob
$CognitiveServicesAccount | Remove-AzCognitiveServicesAccount -Force
$null = Get-AzCognitiveServicesAccount -InRemovedState | Remove-AzResource -Force
<#
<#
#>
#endregion