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
    }

    $URI = "https://management.azure.com/subscriptions/$SubcriptionID/providers/Microsoft.CognitiveServices/checkDomainAvailability?api-version=2023-05-01"
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
        Write-Warning -Message $Response.message
    }
    finally 
    {
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
#region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
$AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
$ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
$shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
#endregion

# Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount
}


$null = Register-AzResourceProvider -ProviderNamespace Microsoft.CognitiveServices
#Important: Wait until RegistrationState is set to Registered. 
While (Get-AzResourceProvider -ProviderNamespace Microsoft.CognitiveServices | Where-Object -FilterScript { $_.RegistrationState -ne 'Registered' }) {
    Start-Sleep -Seconds 10
}

# Set the Azure region for the Cognitive Services resource
$Location = "eastus"
$LocationShortName = $shortNameHT[$Location].shortName
$ComputerVisionNameMaxLength = 15
$ComputerVisionPrefix = "cpv"
$ResourceGroupPrefix = "rg"
$Project = "ai"
$Role = "cpv"
#$DigitNumber = 4
$DigitNumber = $ComputerVisionNameMaxLength - ($ComputerVisionPrefix + $Project + $Role + $LocationShortName).Length

Do {
    $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
    # Create a unique name for the Cognitive Services resource
    $ComputerVisionName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ComputerVisionPrefix, $Project, $Role, $LocationShortName, $Instance                       
} While ((-not(Get-AzCognitiveServicesNameAvailability -Name $ComputerVisionName).isSubdomainAvailable))

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
try
{
    $ComputerVision = New-AzCognitiveServicesAccount -Name $ComputerVisionName -ResourceGroupName $resourceGroupName -Location $Location -SkuName "F0" -Kind "ComputerVision" -ErrorAction Stop
}
catch [System.Management.Automation.PSInvalidOperationException] {   
    # Dig into the exception to get the Response details.
    # Note that value__ is not a typo.
    Write-Error -Message "$($_.Exception.Message)"
    exit
}

$ComputerVision

#Sleeping some seconds to avoid a HTTP error 401".
Start-Sleep -Seconds 60

# Get the key and CognitiveServicesAccountEndPoint for the Cognitive Services resource
$CognitiveServicesAccountKey = (Get-AzCognitiveServicesAccountKey -ResourceGroupName $resourceGroupName -Name $ComputerVisionName).Key2
$CognitiveServicesAccountEndPoint = (Get-AzCognitiveServicesAccount -ResourceGroupName $resourceGroupName -Name $ComputerVisionName).Endpoint

$visualFeatures = "Description", "Objects", "Tags", "Categories", "Faces"

# Will Get a new full HD photo at every request
$RandomFullHDPictureURI = "https://picsum.photos/1920/1080"
$TestNumber = 3

for($i=0; $i -lt $TestNumber;  $i++)
{
    $TimeStamp = Get-Date -Format "yyyyMMddHHmmss"
    $CurrentPicture = Join-Path -Path $CurrentDir -ChildPath $('{0}.jpg' -f $TimeStamp)
    $Response = Invoke-WebRequest -Uri $RandomFullHDPictureURI -OutFile $CurrentPicture -PassThru
    $OriginalFileName = $null
    if ($Response.Headers["Content-Disposition"] -match 'filename=\"(?<filename>.*)"')
    {
        $OriginalFileName = $Matches["filename"]
        $NewName = $CurrentPicture -replace ".jpg", $('_{0}' -f $OriginalFileName)
        Rename-Item -Path $CurrentPicture -NewName $NewName
        $CurrentPicture = $NewName
    }
    Write-Host -Object "`r`nProcessing '$CurrentPicture' ..." -ForegroundColor Cyan

    #Displaying the current picture by using the default registered application (depends of the user settings)"
    & $CurrentPicture
    foreach ($CurrentvisualFeature in $visualFeatures)
    {
    
        # Analyze the photo using the Computer Vision API
        #FROM https://eastus.dev.cognitive.microsoft.com/docs/services/computer-vision-v3-2/
        $analyzeUrl = "$CognitiveServicesAccountEndPoint/vision/v3.2/analyze?visualFeatures=$CurrentvisualFeature&language=en"
        #$CurrentPictureData = [System.IO.File]::ReadAllBytes($CurrentPicture)
        #$CurrentPictureBase64 = [System.Convert]::ToBase64String(#$CurrentPictureData)

        $headers = @{
            "Ocp-Apim-Subscription-Key" = $CognitiveServicesAccountKey
            "Content-Type" = "application/octet-stream"
        }

        try
        {
            # Invoke the REST API
            $Response = Invoke-RestMethod -Uri $analyzeUrl -Method POST -Headers $headers -InFile $CurrentPicture
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

        switch ($CurrentvisualFeature)
        {
            "Description" { Write-Host "Image Description: $($Response.Description.Captions.text)"}
            "Objects" { Write-Host "Image Objects: $(($Response.objects.object | Select-Object -Unique) -join ', ')" }
            "Tags"  { Write-Host "Image Tags: $(($Response.tags.name | Select-Object -Unique) -join ', ')" }
            "Categories"  { Write-Host "Image Categories: $(($Response.categories.name | Select-Object -Unique) -join ', ')" }
            "Faces" { Write-Host "Image Faces Number detected : $($Response.faces.Count)" }
        }
        #Remove-Item -Path $CurrentPicture
    }
    Start-Sleep -Seconds 5
}

#region Some Cleanup
#Get-AzResourceGroup -Name rg-cg-faceapi* | Remove-AzResourceGroup -Force -Verbose -AsJob
$null = Remove-AzResourceGroup -Name $ResourceGroupName -Force -AsJob
$ComputerVision | Remove-AzCognitiveServicesAccount -Force
$null = Get-AzCognitiveServicesAccount -InRemovedState | Remove-AzResource -Force
<#
<#
#>
#endregion