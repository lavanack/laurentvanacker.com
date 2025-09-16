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
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^https://api.github.com/repos/.*|^https://(www\.)?github.com/")] 
    [string]$URI,
    [Parameter(Mandatory = $false)]
    [string]$FileRegExPattern = ".*",
    [Parameter(Mandatory = $true)]
    [string]$Destination,
    [Parameter(Mandatory = $false)]
    [ValidateScript({$_ -in @([boolean]::TrueString, [boolean]::FalseString)})]
    [string]$Recurse = [boolean]::FalseString
) 

#region Function Definitions
function Get-CallerPreference {
    <#
        .SYNOPSIS
        Fetches "Preference" variable values from the caller's scope.
        .DESCRIPTION
        Script module functions do not automatically inherit their caller's variables, but they can be obtained
        through the $PSCmdlet variable in Advanced Functions. This function is a helper function for any script
        module Advanced Function; by passing in the values of $ExecutionContext.SessionState and $PSCmdlet,
        Get-CallerPreference will set the caller's preference variables locally.
        .PARAMETER Cmdlet
        The $PSCmdlet object from a script module Advanced Function.
        .PARAMETER SessionState
        The $ExecutionContext.SessionState object from a script module Advanced Function. This is how the
        Get-CallerPreference function sets variables in its callers' scope, even if that caller is in a different
        script module.
        .PARAMETER Name
        Optional array of parameter names to retrieve from the caller's scope. Default is to retrieve all preference
        variables as defined in the about_Preference_Variables help file (as of PowerShell 4.0). This parameter may
        also specify names of variables that are not in the about_Preference_Variables help file, and the function
        will retrieve and set those as well.
       .EXAMPLE
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        Imports the default PowerShell preference variables from the caller into the local scope.
        .EXAMPLE
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name 'ErrorActionPreference', 'SomeOtherVariable'
        Imports only the ErrorActionPreference and SomeOtherVariable variables into the local scope.
        .EXAMPLE
        'ErrorActionPreference','SomeOtherVariable' | Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        Same as Example 2, but sends variable names to the Name parameter via pipeline input.
       .INPUTS
        System.String
        .OUTPUTS
        None.
        This function does not produce pipeline output.
        .LINK
        about_Preference_Variables
    #>
    [CmdletBinding(DefaultParameterSetName = 'AllVariables')]
    param (
        [Parameter(Mandatory)]
        [ValidateScript( { $PSItem.GetType().FullName -eq 'System.Management.Automation.PSScriptCmdlet' })]
        $Cmdlet,
        [Parameter(Mandatory)][System.Management.Automation.SessionState]$SessionState,
        [Parameter(ParameterSetName = 'Filtered', ValueFromPipeline)][string[]]$Name
    )
    begin {
        $FilterHash = @{ }
    }
    
    process {
        if ($null -ne $Name) {
            foreach ($String in $Name) {
                $FilterHash[$String] = $true
            }
        }
    }
    end {
        # List of preference variables taken from the about_Preference_Variables help file in PowerShell version 4.0
        $Vars = @{
            'ErrorView'                     = $null
            'FormatEnumerationLimit'        = $null
            'LogCommandHealthEvent'         = $null
            'LogCommandLifecycleEvent'      = $null
            'LogEngineHealthEvent'          = $null
            'LogEngineLifecycleEvent'       = $null
            'LogProviderHealthEvent'        = $null
            'LogProviderLifecycleEvent'     = $null
            'MaximumAliasCount'             = $null
            'MaximumDriveCount'             = $null
            'MaximumErrorCount'             = $null
            'MaximumFunctionCount'          = $null
            'MaximumHistoryCount'           = $null
            'MaximumVariableCount'          = $null
            'OFS'                           = $null
            'OutputEncoding'                = $null
            'ProgressPreference'            = $null
            'PSDefaultParameterValues'      = $null
            'PSEmailServer'                 = $null
            'PSModuleAutoLoadingPreference' = $null
            'PSSessionApplicationName'      = $null
            'PSSessionConfigurationName'    = $null
            'PSSessionOption'               = $null
            'ErrorActionPreference'         = 'ErrorAction'
            'DebugPreference'               = 'Debug'
            'ConfirmPreference'             = 'Confirm'
            'WhatIfPreference'              = 'WhatIf'
            'VerbosePreference'             = 'Verbose'
            'WarningPreference'             = 'WarningAction'
        }
        foreach ($Entry in $Vars.GetEnumerator()) {
            if (([string]::IsNullOrEmpty($Entry.Value) -or -not $Cmdlet.MyInvocation.BoundParameters.ContainsKey($Entry.Value)) -and
                ($PSCmdlet.ParameterSetName -eq 'AllVariables' -or $FilterHash.ContainsKey($Entry.Name))) {
                $Variable = $Cmdlet.SessionState.PSVariable.Get($Entry.Key)
                
                if ($null -ne $Variable) {
                    if ($SessionState -eq $ExecutionContext.SessionState) {
                        Set-Variable -Scope 1 -Name $Variable.Name -Value $Variable.Value -Force -Confirm:$false -WhatIf:$false
                    }
                    else {
                        $SessionState.PSVariable.Set($Variable.Name, $Variable.Value)
                    }
                }
            }
        }
        if ($PSCmdlet.ParameterSetName -eq 'Filtered') {
            foreach ($VarName in $FilterHash.Keys) {
                if (-not $Vars.ContainsKey($VarName)) {
                    $Variable = $Cmdlet.SessionState.PSVariable.Get($VarName)
                
                    if ($null -ne $Variable) {
                        if ($SessionState -eq $ExecutionContext.SessionState) {
                            Set-Variable -Scope 1 -Name $Variable.Name -Value $Variable.Value -Force -Confirm:$false -WhatIf:$false
                        }
                        else {
                            $SessionState.PSVariable.Set($Variable.Name, $Variable.Value)
                        }
                    }
                }
            }
        }
    }
}

function Get-GitFile {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidatePattern("^https://api.github.com/repos/.*|^https://(www\.)?github.com/")] 
        [string]$URI,
        [Parameter(Mandatory = $false)]
        [string]$FileRegExPattern = ".*",
        [Parameter(Mandatory = $true)]
        [string]$Destination,
        [switch]$Recurse
    )   

    #Be aware of the API rate limit when unauthenticated: https://docs.github.com/en/rest/using-the-rest-api/getting-started-with-the-rest-api?apiVersion=2022-11-28#2-authenticate
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$URI: $URI"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$FileRegExPattern: $FileRegExPattern"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Destination: $Destination"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Recurse: $Recurse"

    $null = New-Item -Path $Destination -ItemType Directory -Force -ErrorAction Ignore

    #region URI transformation (in case of the end-user doesn't give an https://api.github.com/repos/... URI
    if ($URI -match "^https://(www\.)?github.com/(?<organisation>[^/]+)/(?<repository>[^/]+)/tree/master/(?<contents>.*)") {
        #https://github.com/lavanack/laurentvanacker.com/tree/master/Azure/Azure%20Virtual%20Desktop/MSIX
        #https://api.github.com/repos/lavanack/laurentvanacker.com/contents/Azure/Azure%20Virtual%20Desktop/MSIX/MSIX
        $Organisation = $Matches["organisation"]
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Organisation: $Organisation"
        $Repository = $Matches["repository"]
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Repository: $Repository"
        $Contents = $Matches["contents"]
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Contents: $Contents"
        $GitHubURI = "https://api.github.com/repos/$Organisation/$Repository/contents/$Contents"
    }
    else {
        $GitHubURI = $URI
    }
    #endregion
    #region Getting all request files
    $Response = Invoke-WebRequest -Uri $GitHubURI -UseBasicParsing
    $Objects = $Response.Content | ConvertFrom-Json
    [array] $Files = ($Objects | Where-Object -FilterScript { $_.type -eq "file" } | Select-Object -ExpandProperty html_url) -replace "/blob/", "/raw/"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Files:`r`n$($Files | Format-List -Property * | Out-String)"
    if ($Recurse) {
        $Directories = $Objects | Where-Object -FilterScript { $_.type -eq "dir" } | Select-Object -Property url, name
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Directories:`r`n$($Directories | Format-List -Property * | Out-String)"
        foreach ($CurrentDirectory in $Directories) {
            $CurrentDestination = Join-Path -Path $Destination -ChildPath $CurrentDirectory.name
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CurrentDestination: $CurrentDestination"
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `URI: $($CurrentDirectory.url)"
            Get-GitFile -URI $CurrentDirectory.url -FileRegExPattern $FileRegExPattern -Destination $CurrentDestination -Recurse
        }
    }
    $FileURIs = $Files -match $FileRegExPattern
    $GitFile = $null
    if ($FileURIs) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$FileURIs: $($FileURIs -join ', ')"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Destination: $($(@($Destination) * $($FileURIs.Count)) -join ', ')"
        Start-BitsTransfer -Source $FileURIs -Destination $(@($Destination) * $($FileURIs.Count))
        #Getting the url-decoded local file path 
        $GitFile = $FileURIs | ForEach-Object -Process { 
            $FileName = $_ -replace ".*/"
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$FileName: $FileName"
            $DecodedFileName = [System.Web.HttpUtility]::UrlDecode($FileName)
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$DecodedFileName: $DecodedFileName"
            if ($FileName -ne $DecodedFileName) {
                Remove-Item -Path $(Join-Path -Path $Destination -ChildPath $DecodedFileName) -ErrorAction Ignore
                Rename-Item -Path $(Join-Path -Path $Destination -ChildPath $FileName) -NewName $DecodedFileName -PassThru -Force 
            }
            else {
                Get-Item -Path $(Join-Path -Path $Destination -ChildPath $FileName)
            }
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$GitFile: $($GitFile -join ', ')"
    }
    else {
        Write-Warning -Message "No files to copy from '$GitHubURI'..."
    }
    #endregion

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $GitFile
}
#endregion

#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$CurrentScriptName = Split-Path -Path $CurrentScript -Leaf
$TranscriptFileName = $CurrentScriptName -replace ".ps1$", "$("_{0}.txt" -f (Get-Date -Format 'yyyyMMddHHmmss'))"
$TranscriptFile = Join-Path -Path "C:\Temp" -ChildPath $TranscriptFileName
Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader
Set-Location -Path $CurrentDir 

Write-Host "Transcript File : $TranscriptFile"
Get-GitFile -URI $URI -FileRegExPattern $FileRegExPattern -Destination $Destination -Recurse:$([boolean]::Parse($Recurse)) -Verbose
Stop-Transcript
#endregion