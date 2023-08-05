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
#requires -Version 5
[CmdletBinding()]
param
(
)

#region Function definitions
#From https://alexholmeset.blog/2023/02/09/getting-started-with-azure-openai-and-powershell/
function Get-AzureOpenAIToken {
    <#  .SYNOPSIS
       Get an azure token for user or managed identity thats required to authenticate to Azure OpenAI with Rest API.
       Also construct the header if you are using an Azure OpenAI API key instead of Azure AD authentication.
    .PARAMETER ManagedIdentity
        Use this parameter if you want to use a managed identity to authenticate to Azure OpenAI.
    .PARAMETER User
        Use this parameter if you want to use a user to authenticate to Azure OpenAI.
    .PARAMETER APIKey
        Use this parameter if you want to use an API key to authenticate to Azure OpenAI.

    .EXAMPLE
        # Manually specify username and password to acquire an authentication token:
        Get-AzureOpenAIToken -APIKey "ghgkfhgfgfgkhgh"
        Get-AzureOpenAIToken -ManagedIdentity $true
        Get-AzureOpenAIToken -User $true
    .NOTES
        Author: Alexander Holmeset
        Twitter: @AlexHolmeset
        Website: https://www.alexholmeset.blog
        Created: 09-02-2023
        Updated: 
        Version history:
        1.0.0 - (09-02-2023) Function created  
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$APIKey,
        [Parameter(Mandatory = $false)]
        [string]$ManagedIdentity,
        [Parameter(Mandatory = $false)]
        [string]$User
    )

    Process {
        $ErrorActionPreference = "Stop"

        if (Get-Module -ListAvailable -Name Az.Accounts) {
            # Write-Host "You have the Az.Accounts module installed"
        } 
        else {
            Write-Host "You need to install the Az.Accounts module";
            break
        }
        If (!$MyHeader) {


            If ($ManagedIdentity -eq $true) {
                "managed"
                try {
                    Connect-AzAccount -Identity

                    $MyTokenRequest = Get-AzAccessToken -ResourceUrl "https://cognitiveservices.azure.com"
                    $MyToken = $MyTokenRequest.token
                    If (!$MyToken) {
                        Write-Warning "Failed to get API access token!"
                        Exit 1
                    }
                    $Global:MyHeader = @{"Authorization" = "Bearer $MyToken" }
                }
                catch [System.Exception] {
                    Write-Warning "Failed to get Access Token, Error message: $($_.Exception.Message)"; break
                }
    
            }
            If ($User -eq $true) {
                "USER"
                try {
                    Connect-AzAccount
    
                    $MyTokenRequest = Get-AzAccessToken -ResourceUrl "https://cognitiveservices.azure.com"
                    $MyToken = $MyTokenRequest.token
                    If (!$MyToken) {
                        Write-Warning "Failed to get API access token!"
                        Exit 1
                    }
                    $Global:MyHeader = @{"Authorization" = "Bearer $MyToken" }
                }
                catch [System.Exception] {
                    Write-Warning "Failed to get Access Token, Error message: $($_.Exception.Message)"; break
                }
   
            }
            If ($APIkey) {
                "APIKEY"

                $Global:MyHeader = @{"api-key" = $apikey }

        

            }
        }
    }
}

function Get-Completion {
    <#  .SYNOPSIS
        Get a text completion from Azure OpenAI Completion endpoint.
    .PARAMETER DeploymentName
        A deployment name should be provided.
    .PARAMETER ResourceName
        A Resource  name should be provided.
    .PARAMETER Prompt
        A prompt name should be provided.
    .PARAMETER Token
        A token name should be provided.                
    .EXAMPLE
        Get-Completion -DeploymentName $DeploymentName -ResourceName $ResourceName -maxtokens 100 -prompt "What is the meaning of life?"
    .NOTES
        Author: Alexander Holmeset
        Twitter: @AlexHolmeset
        Website: https://www.alexholmeset.blog
        Created: 09-02-2023
        Updated: 
        Version history:
        1.0.0 - (09-02-2023) Function created      
    #>[CmdletBinding()]
    param (
        [parameter(Mandatory = $true, HelpMessage = "Your azure openai deployment name")]
        [ValidateNotNullOrEmpty()]
        [string]$DeploymentName,
        [parameter(Mandatory = $true, HelpMessage = "your azure openai resource name")]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceName,
        [parameter(Mandatory = $true, HelpMessage = "Your Azure OpenAI prompt")]
        [ValidateNotNullOrEmpty()]
        [string]$Prompt,
        [parameter(Mandatory = $true, HelpMessage = "Max number of tokens allowed to be used in this request")]
        [ValidateNotNullOrEmpty()]
        [int]$Maxtokens
        )

Process {
    $ErrorActionPreference = "Stop"
    $APIVersion = "2022-12-01"
    # Construct URI
    $uri = "https://$ResourceName.openai.azure.com/openai/deployments/$DeploymentName/completions?api-version=$ApiVersion"
    # Construct Body
    $Body = @"
    {
"prompt": "$Prompt",
"max_tokens": $maxtokens
    }
"@


    try {
        $Global:Request = invoke-restmethod -Method POST -Uri $uri -ContentType "application/json" -Body $body  -Headers $Global:MyHeader

       }
    catch [System.Exception] {
      Write-Warning "Failed to to POST request: $($_.Exception.Message)"; break
    }
    return $Request
    }
}
#endregion
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

#region Secrets
$APIKey = "replace-with-your-own-apikey"
$DeploymentName = "replace-with-your-own-deployement-name"
#cf. https://portal.azure.com/#view/Microsoft_Azure_ProjectOxford/CognitiveServicesHub/~/OpenAI
$ResourceName = "replace-with-your-own-resource-name"
$AZOpenAIURI = "https://$ResourceName.openai.azure.com/openai/deployments/$DeploymentName/completions?api-version=2022-12-01"
#endregion

$Prompt = "What is microsoft azure?"

#region Sample #1
#From https://learn.microsoft.com/en-us/azure/cognitive-services/openai/reference
$Headers = @{ 'api-Key' = $APIKey }
$Body = [ordered]@{ 
    "prompt"     = $Prompt
    "max_tokens" = 100
}

$Response = Invoke-RestMethod -Method POST -Headers $Headers -Body $($Body | ConvertTo-Json)  -ContentType "application/json" -Uri $AZOpenAIURI
$Response

"Generated text:"
$Response.choices.text

"Token cost"
$Response.usage
#endregion

Write-Host "Sleeping 1 minute due to rate limit of the free tier ..."
Start-Sleep -Seconds 60

#region Sample #2
#From https://alexholmeset.blog/2023/02/09/getting-started-with-azure-openai-and-powershell/
Get-AzureOpenAIToken -APIKey $APIKey
$Response = Get-Completion -DeploymentName $DeploymentName -ResourceName $ResourceName -Maxtokens 100 -Prompt $Prompt
$Response

"Generated text:"
$Response.choices.text

"Token cost"
$Response.usage
#endregion
