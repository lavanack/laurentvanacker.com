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

#requires -Version 5 -Modules Az.Accounts, Az.Resources, Microsoft.Graph.Authentication

#region Intune Management
Function Remove-IntuneItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $HostPoolName,
        [Parameter(Mandatory = $true)]
        [string[]] $SessionHostName
    )

    #region deviceManagementScripts and groupPolicyConfigurations
    $Topics = "deviceManagementScripts", "groupPolicyConfigurations"
    foreach($CurrentHostPoolName in $HostPoolName) {
        foreach($CurrentTopic in $Topics) {
            Write-Verbose "Processing '$($CurrentTopic)' ..."
            $URI = "https://graph.microsoft.com/beta/deviceManagement/$($CurrentTopic)?`$filter=startswith(displayName,+'[$CurrentHostPoolName]')&`$select=id,displayname"
            $deviceManagementScripts = Invoke-MgGraphRequest -Uri $URI -Method GET -OutputType PSObject
            foreach ($CurrentValue in $deviceManagementScripts.Value) {
                Write-Verbose -Message "Deleting the previously '$($CurrentValue.displayName)' $CurrentTopic (id: '$($CurrentValue.id)')..."
                Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/$CurrentTopic/$($CurrentValue.id)" -Method DELETE -OutputType PSObject
            }
        }
    }
    #endregion

    #region Devices
    Write-Verbose -Message "Removing Intune Enrolled Devices : $($SessionHostName -join ', ')"
    Get-MgDeviceManagementManagedDevice -All | Where-Object -FilterScript {$_.DeviceName -in $SessionHostName } | ForEach-Object -Process { 
        Write-Verbose -Message "Removing Intune Enrolled Device : $($_.DeviceName)"
        Remove-MgDeviceManagementManagedDevice -ManagedDeviceId $_.Id 
    }
    #endregion
}

#From https://learn.microsoft.com/en-us/graph/api/intune-shared-devicemanagementscript-create?view=graph-rest-beta
Function New-IntunePowerShellScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostPoolName,

        [Parameter(Mandatory = $true, ParameterSetName = 'ScriptURI')]
        [ValidateScript({ $_ -match '^https?://' })]
        [string]$ScriptURI,

        [Parameter(Mandatory = $true, ParameterSetName = 'ScriptPath')]
        [string]$ScriptPath
    )

    #region Uploading Powershell Script
    if ($ScriptURI) {
        $ScriptURIContent = Invoke-RestMethod -Uri $ScriptURI
        $ScriptContent = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($ScriptURIContent))
        $FileName = Split-Path $ScriptURI -Leaf
        Write-Verbose -Message "Adding the '$ScriptURI' script ..."
    }
    else {
        $ScriptPathContent = Get-Content -Path $ScriptPath -Encoding Byte -Raw
        $ScriptContent = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($ScriptPathContent))
        $FileName = Split-Path $ScriptPathContent -Leaf
        Write-Verbose -Message "Adding the '$ScriptPath' script ..."
    }

    $DisplayName = "[{0}] {1}" -f $HostPoolName, $FileName
    #Checking if the script is already present (with the same naming convention)
    $AddedScript = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts?`$filter=displayName+eq+'$DisplayName'" -Method GET -OutputType PSObject
    #If present
    if ($AddedScript.Value) {
        Write-Verbose -Message "Deleting the previously imported PowerShell Script file..."
        $AddedScript = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/$($AddedScript.value.id)" -Method DELETE
        if ($AddedScript.Value.status -eq 'removalFailed') {
            Write-Error -Message "Removal Failed ..."
            return $AddedScript
        }
    }

    $Body = @{
        #"description" = ""
        "displayName"           = $DisplayName
        "enforceSignatureCheck" = $false
        "fileName"              = $FileName
        "roleScopeTagIds"       = @("0")
        "runAs32Bit"            = $false
        "runAsAccount"          = "system"
        "scriptContent"         = $ScriptContent
    }

    $AddedScript = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts" -Method POST -Body $($Body | ConvertTo-Json -Depth 100) -OutputType PSObject
    #endregion

    #region Assign
    $DeviceAzADGroupName = "$HostPoolName - Devices"
    $DeviceAzADGroup = Get-AzADGroup -Filter "DisplayName eq '$DeviceAzADGroupName'"
    $Body = @{
        deviceManagementScriptAssignments = @(
            @{
                target = @{
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                    groupId       = $DeviceAzADGroup.Id
                }
            }
        )
    }
    Write-Verbose -Message "Assigning the '$FileName' PowerShell script to '$DeviceAzADGroupName' ..."
    $Assign = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/$($AddedScript.id)/assign" -Method POST -Body $($Body | ConvertTo-Json -Depth 100) -OutputType PSObject
    #endregion
}

function Get-GroupPolicyDefinitionPresentation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [array] $GroupPolicyDefinition
    )
    $GroupPolicyDefinitionPresentationHT = @{}
    foreach ($CurrentGroupPolicyDefinition in $GroupPolicyDefinition) {
        $GroupPolicyDefinitionPresentation = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/Beta/deviceManagement/groupPolicyDefinitions/$($CurrentGroupPolicyDefinition.id)/presentations" -Method GET -OutputType PSObject
        $Key = "{0} (version: {1})" -f $CurrentGroupPolicyDefinition.displayName, $CurrentGroupPolicyDefinition.version
        if ($CurrentGroupPolicyDefinition.supportedOn) {
            Write-Verbose -Message "Processing '$Key' (Supported On: $($CurrentGroupPolicyDefinition.supportedOn)) ..."
            $GroupPolicyDefinitionPresentationHT.Add($("{0} (Supported On: {1})" -f $Key, $CurrentGroupPolicyDefinition.supportedOn) , $GroupPolicyDefinitionPresentation.Value)
        }
        else {
            Write-Verbose -Message "Processing '$Key' ..."
            $GroupPolicyDefinitionPresentationHT.Add($Key, $GroupPolicyDefinitionPresentation.Value)
        }
    }
    $GroupPolicyDefinitionPresentationHT
}

function Import-FSLogixADMX {
    [CmdletBinding()]
    param (
    )

    #Checking if the ADMX is already present -
    $GroupPolicyUploadedDefinitionFile = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles?`$filter=fileName+eq+'fslogix.admx'" -Method GET -OutputType PSObject
    #If present
    if ($GroupPolicyUploadedDefinitionFile.Value) {
        if ($GroupPolicyUploadedDefinitionFile.Value.status -eq 'available') {
            Write-Verbose -Message "Returning the previously imported ADMX file..."
            return $GroupPolicyUploadedDefinitionFile
        }
        else {
            Write-Verbose -Message "Deleting the previously imported ADMX file..."
            $GroupPolicyUploadedDefinitionFile = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles/$($GroupPolicyUploadedDefinitionFile.value.id)" -Method DELETE
            if ($GroupPolicyUploadedDefinitionFile.Value.status -eq 'removalFailed') {
                Write-Error -Message "Removal Failed ..."
                return $GroupPolicyUploadedDefinitionFile
            }
        }
    }

    #Always get the latest version of FSLogix
    $FSLogixLatestURI = ((Invoke-WebRequest -Uri "https://aka.ms/fslogix-latest").Links | Where-Object -FilterScript { $_.innerText -eq "Download" }).href
    $OutFile = Join-Path -Path $env:Temp -ChildPath $(Split-Path -Path $FSLogixLatestURI -Leaf)
    Write-Verbose -Message "Downloading from '$FSLogixLatestURI' to '$OutFile' ..."
    Start-BitsTransfer $FSLogixLatestURI -destination $OutFile
    $DestinationPath = Join-Path -Path $env:Temp -ChildPath "FSLogixLatest"
    Write-Verbose -Message "Unzipping '$OutFile' into '$DestinationPath'..."
    Expand-Archive -Path $OutFile -DestinationPath $DestinationPath -Force
    $ADMLFilePath = Join-Path -Path $DestinationPath -ChildPath "fslogix.adml"
    $ADMXFilePath = Join-Path -Path $DestinationPath -ChildPath "fslogix.admx"

    #region ADML file
    $ADMLFileData = Get-Content -Path $ADMLFilePath -Encoding Byte -Raw
    #$ADMLFileContent = [System.Convert]::ToBase64String($ADMLFileData)
    $ADMLFileContent = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($ADMLFileData))

    #endregion

    #region ADMX file
    $ADMXFileData = Get-Content -Path $ADMXFilePath -Encoding Byte -Raw
    #$ADMXFileContent = [System.Convert]::ToBase64String($ADMXFileData)
    $ADMXFileContent = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($ADMXFileData))
    #endregion

    #From https://learn.microsoft.com/en-us/graph/api/intune-grouppolicy-grouppolicyuploadeddefinitionfile-create?view=graph-rest-beta
    $GUID = (New-Guid).Guid
    $Now = $(Get-Date -Format "yyyy-MM-ddTHH:mm:ssK")
    $Body = @{
        #"displayName" = $null
        #"description" = $null
        "languageCodes"                    = @("en-US")
        "targetPrefix"                     = "FSLogix{0}" -f $GUID
        "targetNamespace"                  = "FSLogix.Policies"
        "policyType"                       = "admxIngested"
        #"revision" = $null
        "fileName"                         = $ADMXFileName
        #"id" = $GUID
        #"lastModifiedDateTime" = $Now
        #"status" = "uploadInProgress"
        "content"                          = $ADMXFileContent
        #"uploadDateTime" = $Now
        "defaultLanguageCode"              = $null
        "groupPolicyUploadedLanguageFiles" = @(
            @{
                "fileName"     = $ADMLFileName
                "languageCode" = "en-US"
                "content"      = $ADMLFileContent
                #"id" = (New-Guid).Guid
                #"lastModifiedDateTime" = $Now
            }
        )
    }

    Write-Verbose -Message "Uploading the ADMX and ADML files ..."
    Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/Beta/deviceManagement/groupPolicyUploadedDefinitionFiles" -Method POST -Body $($Body | ConvertTo-Json -Depth 100) -OutputType PSObject
    Remove-Item -Path $OutFile, $DestinationPath -Recurse -Force
}

function Set-GroupPolicyDefinitionSetting {
    [CmdletBinding(DefaultParameterSetName = 'Enable', PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)]
        [object] $GroupPolicyDefinition,
        [Parameter(Mandatory = $true)]
        [object] $GroupPolicyConfiguration,
        [Parameter(ParameterSetName = 'Enable')]
        #Value can be an int, a string or an hashtable for multi-valued properties
        [object] $Value,
        [Parameter(ParameterSetName = 'Enable')]
        [alias('Enabled')]
        [switch] $Enable,
        [Parameter(ParameterSetName = 'Disable')]
        [alias('Disabled')]
        [switch] $Disable
    )

    Write-Verbose -Message "Parameter Set: $($psCmdlet.ParameterSetName) ..."
    Write-Verbose -Message "[$($GroupPolicyConfiguration.displayName)] Processing '$($GroupPolicyDefinition.categoryPath)\$($GroupPolicyDefinition.displayName)' ..."
    Write-Verbose -Message "`$Value: $Value"
    $GroupPolicyDefinitionPresentation = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/Beta/deviceManagement/groupPolicyDefinitions/$($GroupPolicyDefinition.id)/presentations" -Method GET -OutputType PSObject
    if ($GroupPolicyDefinitionPresentation.value.count -gt 1) {
        #When multiple Group Policy Definition Presentations are returned we keep only the one with a 'required' property
        $GroupPolicyDefinitionPresentationValues = $GroupPolicyDefinitionPresentation.value | Where-Object -FilterScript { "required" -in $_.psobject.Properties.Name }
    }
    else {
        $GroupPolicyDefinitionPresentationValues = $GroupPolicyDefinitionPresentation.value
    }
    Write-Verbose "`$GroupPolicyDefinitionPresentationValues:`r`n$($GroupPolicyDefinitionPresentationValues | Out-String)"
    if ($GroupPolicyDefinitionPresentationValues) {
        $PresentationValues = foreach ($CurrentGroupPolicyDefinitionPresentationValue in $GroupPolicyDefinitionPresentationValues) {
            Write-Verbose "Processing '$($CurrentGroupPolicyDefinitionPresentationValue.label)' ..."
            if ($Value -is [int]) {
                $DataType = "#microsoft.graph.groupPolicyPresentationValueDecimal"
                $CurrentValue = $Value
            }
            elseif ($Value -is [hashtable]) {
                $CurrentValue = $Value[$CurrentGroupPolicyDefinitionPresentationValue.label.Trim()]
                if ($null -eq $CurrentValue) {
                    Write-Warning -Message "The value for '$($CurrentGroupPolicyDefinitionPresentationValue.label.Trim())' is NULL ..."
                }
                elseif ($CurrentValue -is [int]) {
                    $DataType = "#microsoft.graph.groupPolicyPresentationValueDecimal"
                }
                else {
                    $DataType = "#microsoft.graph.groupPolicyPresentationValueText"
                }
            }
            else {
                $DataType = "#microsoft.graph.groupPolicyPresentationValueText"
                $CurrentValue = $Value
            }
            Write-Verbose "`$CurrentValue: $CurrentValue"
            @{
                "@odata.type"             = $DataType
                "presentation@odata.bind" = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($GroupPolicyDefinition.id)')/presentations('$($CurrentGroupPolicyDefinitionPresentationValue.id)')"
                "value"                   = $CurrentValue                
            }
        }
    }
    else {
        $PresentationValues = @()
    }
    
    $Body = @{
        added      = @(
            @{
                "definition@odata.bind" = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($GroupPolicyDefinition.id)')"
                "enabled"               = $($psCmdlet.ParameterSetName -eq 'Enable')
                "presentationValues"    = @($PresentationValues)
            }    
        )
        deletedIds = @()
        updated    = @()
    }
    Write-Verbose -Message "[$($GroupPolicyConfiguration.displayName)] Enabling '$($GroupPolicyDefinition.categoryPath)\$($GroupPolicyDefinition.displayName)' ..."
    #$updatedDefinitionValues = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/Beta/deviceManagement/groupPolicyConfigurations/$($GroupPolicyConfiguration.id)/updateDefinitionValues" -Method POST -Body $($Body | ConvertTo-Json -Depth 100| ForEach-Object -Process { [System.Text.RegularExpressions.Regex]::Unescape($_) }) -OutputType PSObject -Verbose
    $JSONBody = $($Body | ConvertTo-Json -Depth 100)
    $URI = "https://graph.microsoft.com/Beta/deviceManagement/groupPolicyConfigurations/$($GroupPolicyConfiguration.id)/updateDefinitionValues"
    Write-Verbose -Message "Body :`r`n$($JSONBody | ForEach-Object -Process { [System.Text.RegularExpressions.Regex]::Unescape($_) })"
    Write-Verbose -Message "Uri :`r`n$URI"
    $updatedDefinitionValues = Invoke-MgGraphRequest -Uri $URI -Method POST -Body $JSONBody -OutputType PSObject -Verbose
}

function New-FSLogixIntuneConfigurationProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [alias('StorageAccountName')]
        [string] $CurrentHostPoolStorageAccountName,

        [Parameter(Mandatory = $true)]
        [string]$HostPoolName,

        [Parameter(Mandatory = $false)]
        [string] $StorageEndpointSuffix = 'core.windows.net'
    )

    #region groupPolicyConfigurations
    $GroupPolicyConfigurationName = "[{0}] FSLogix Policy" -f $HostPoolName
    $Now = $(Get-Date -Format "yyyy-MM-ddTHH:mm:ssK")
    Write-Verbose -Message "Creating the '$GroupPolicyConfigurationName' Group Policy Configuration ..."
    $Body = @{
        #"createdDateTime" = $Now
        "displayName" = $GroupPolicyConfigurationName
        #"description" = ""
        #"roleScopeTagIds" = @("0")
        #"policyConfigurationIngestionType" = "custom"
        #"id" = (New-Guid).Guid
        #"lastModifiedDateTime" = $Now
    }

    #Checking if the groupPolicyConfigurations is already present
    $GroupPolicyConfiguration = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations?`$filter=displayName+eq+'$GroupPolicyConfigurationName'" -Method GET -OutputType PSObject
    if ($GroupPolicyConfiguration.Value) {
        foreach ($CurrentValue in $GroupPolicyConfiguration.Value) {
            Write-Verbose -Message "Deleting the previously '$($CurrentValue.displayName)' groupPolicyConfigurations (id: '$($CurrentValue.id)')..."
            Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$($CurrentValue.id)" -Method DELETE -OutputType PSObject
        }
    }
    $GroupPolicyConfiguration = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/Beta/deviceManagement/groupPolicyConfigurations" -Method POST -Body $($Body | ConvertTo-Json -Depth 100) -OutputType PSObject
    #endregion

    #region Assign
    $DeviceAzADGroupName = "$HostPoolName - Devices"
    $DeviceAzADGroup = Get-AzADGroup -Filter "DisplayName eq '$DeviceAzADGroupName'"
    $Body = @{
        assignments = @(
            @{
                target = @{
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                    groupId       = $DeviceAzADGroup.Id
                }
            }
        )
    }
    Write-Verbose -Message "Assigning the '$GroupPolicyConfigurationName' Group Policy Configuration to '$DeviceAzADGroupName' ..."
    $Assign = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/Beta/deviceManagement/groupPolicyConfigurations/$($GroupPolicyConfiguration.id)/assign" -Method POST -Body $($Body | ConvertTo-Json -Depth 100) -OutputType PSObject
    #endregion

    #region FSLogix Profile Containers Settings
    #$FSLogixSettings = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions?`$filter=contains(categoryPath,'FSLogix')" -Method GET -OutputType PSObject).Value
    $FSLogixProfileContainersAndLoggingGroupPolicyDefinitions = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions?`$filter=startsWith(categoryPath,'\FSLogix\Profile Containers')+or+startsWith(categoryPath,'\FSLogix\Logging')" -Method GET -OutputType PSObject).Value
    if (-not($FSLogixProfileContainersAndLoggingGroupPolicyDefinitions)) {
        $GroupPolicyUploadedDefinitionFile = Import-FSLogixADMX -Verbose
        $GroupPolicyUploadedDefinitionFileId = $GroupPolicyUploadedDefinitionFile.id
        While ($GroupPolicyUploadedDefinitionFile.value.status -eq 'uploadInProgress') {
            $GroupPolicyUploadedDefinitionFile = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles?`$filter=id+eq+'$GroupPolicyUploadedDefinitionFileId'" -Method GET -OutputType PSObject
            Write-Verbose -Message "Waiting the upload completes. Sleeping 10 seconds ..."
            Start-Sleep -Seconds 10
        } 
        Write-Host -Object "Final status: $($GroupPolicyUploadedDefinitionFile.value.status)"
        $FSLogixProfileContainersAndLoggingGroupPolicyDefinitions = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions?`$filter=startsWith(categoryPath,'\FSLogix\Profile Containers\')" -Method GET -OutputType PSObject).Value
    }
    #Adding a displayName Property
    $FSLogixProfileContainersAndLoggingGroupPolicyDefinitions = $FSLogixProfileContainersAndLoggingGroupPolicyDefinitions | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $_.categoryPath -ChildPath $_.displayName } }
    switch ($FSLogixProfileContainersAndLoggingGroupPolicyDefinitions) {
        { $_.FullPath -eq '\FSLogix\Profile Containers\Enabled' } { Set-GroupPolicyDefinitionSetting -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Verbose; continue }  
        { $_.FullPath -eq '\FSLogix\Profile Containers\Delete Local Profile When VHD Should Apply' } { Set-GroupPolicyDefinitionSetting -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Verbose; continue } 
        { $_.FullPath -eq '\FSLogix\Profile Containers\Container and Directory Naming\Flip Flop Profile Directory Name' } { Set-GroupPolicyDefinitionSetting -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Verbose; continue } 
        { $_.FullPath -eq '\FSLogix\Profile Containers\Locked Retry Count' } { Set-GroupPolicyDefinitionSetting -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 3 -Verbose; continue }  
        { $_.FullPath -eq '\FSLogix\Profile Containers\Locked Retry Interval' } { Set-GroupPolicyDefinitionSetting -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 15 -Verbose }
        { $_.FullPath -eq '\FSLogix\Profile Containers\Profile Type' } { Set-GroupPolicyDefinitionSetting -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value "0" -Verbose }
        { $_.FullPath -eq '\FSLogix\Profile Containers\ReAttach Interval' } { Set-GroupPolicyDefinitionSetting -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 15 -Verbose }
        { $_.FullPath -eq '\FSLogix\Profile Containers\ReAttach Count' } { Set-GroupPolicyDefinitionSetting -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 3 -Verbose }
        { $_.FullPath -eq '\FSLogix\Profile Containers\Size In MBs' } { Set-GroupPolicyDefinitionSetting -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 30000 -Verbose }
        { $_.FullPath -eq '\FSLogix\Profile Containers\Prevent Login With Failure' } { Set-GroupPolicyDefinitionSetting -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 1 -Verbose; continue } 
        { $_.FullPath -eq '\FSLogix\Profile Containers\Prevent Login With Temp Profile' } { Set-GroupPolicyDefinitionSetting -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 1 -Verbose; continue }   
        { $_.FullPath -eq '\FSLogix\Profile Containers\Container and Directory Naming\Volume Type (VHD or VHDX)' } { Set-GroupPolicyDefinitionSetting -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 'VHDX' -Verbose }
        { $_.FullPath -eq '\FSLogix\Profile Containers\Is Dynamic (VHD)' } { Set-GroupPolicyDefinitionSetting -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 1 -Verbose; continue } 
        { $_.FullPath -eq '\FSLogix\Logging\Log Keeping Period' } { Set-GroupPolicyDefinitionSetting -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 10 -Verbose }
        default { Write-Verbose -Message "'$($_.FullPath)' not modified ..." }  
    }
    #endregion
}

function New-AVDIntuneConfigurationProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostPoolName
    )

    #region groupPolicyConfigurations
    $GroupPolicyConfigurationName = "[{0}] AVD Policy" -f $HostPoolName
    $Now = $(Get-Date -Format "yyyy-MM-ddTHH:mm:ssK")
    Write-Verbose -Message "Creating the '$GroupPolicyConfigurationName' Group Policy Configuration ..."
    $Body = @{
        #"createdDateTime" = $Now
        "displayName" = $GroupPolicyConfigurationName
        #"description" = ""
        #"roleScopeTagIds" = @("0")
        #"policyConfigurationIngestionType" = "custom"
        #"id" = (New-Guid).Guid
        #"lastModifiedDateTime" = $Now
    }

    #Checking if the groupPolicyConfigurations is already present
    $GroupPolicyConfiguration = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations?`$filter=displayName+eq+'$GroupPolicyConfigurationName'" -Method GET -OutputType PSObject
    if ($GroupPolicyConfiguration.Value) {
        foreach ($CurrentValue in $GroupPolicyConfiguration.Value) {
            Write-Verbose -Message "Deleting the previously '$($CurrentValue.displayName)' groupPolicyConfigurations (id: '$($CurrentValue.id)')..."
            Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$($CurrentValue.id)" -Method DELETE -OutputType PSObject
        }
    }
    $GroupPolicyConfiguration = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/Beta/deviceManagement/groupPolicyConfigurations" -Method POST -Body $($Body | ConvertTo-Json -Depth 100) -OutputType PSObject
    #endregion

    #region Assign
    $DeviceAzADGroupName = "$HostPoolName - Devices"
    $DeviceAzADGroup = Get-AzADGroup -Filter "DisplayName eq '$DeviceAzADGroupName'"
    $Body = @{
        assignments = @(
            @{
                target = @{
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                    groupId       = $DeviceAzADGroup.Id
                }
            }
        )
    }
    Write-Verbose -Message "Assigning the '$GroupPolicyConfigurationName' Group Policy Configuration to '$DeviceAzADGroupName' ..."
    $Assign = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/Beta/deviceManagement/groupPolicyConfigurations/$($GroupPolicyConfiguration.id)/assign" -Method POST -Body $($Body | ConvertTo-Json -Depth 100) -OutputType PSObject
    #endregion

    #region Network\Background Intelligent Transfer Service (BITS) Settings
    $NetworkBITSGroupPolicyDefinitions = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions?`$filter=startsWith(categoryPath,'\Network\Background Intelligent Transfer Service (BITS)')" -Method GET -OutputType PSObject).Value
    $NetworkBITSGroupPolicyDefinitions = $NetworkBITSGroupPolicyDefinitions | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $_.categoryPath -ChildPath $_.displayName } }
    switch ($NetworkBITSGroupPolicyDefinitions) {
        { $_.FullPath -eq '\Network\Background Intelligent Transfer Service (BITS)\Do not allow the BITS client to use Windows Branch Cache' } { Set-GroupPolicyDefinitionSetting -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Verbose; continue }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified ..." }  
    }
    #endregion

    #region Network\BranchCache Settings
    $NetworkBranchCacheGroupPolicyDefinitions = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions?`$filter=startsWith(categoryPath,'\Network\BranchCache')" -Method GET -OutputType PSObject).Value
    $NetworkBranchCacheGroupPolicyDefinitions = $NetworkBranchCacheGroupPolicyDefinitions | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $_.categoryPath -ChildPath $_.displayName } }
    switch ($NetworkBranchCacheGroupPolicyDefinitions) {
        { $_.FullPath -eq '\Network\BranchCache\Enable Hotspot Authentication' } { Set-GroupPolicyDefinitionSetting -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Disable -Verbose; continue }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified ..." }  
    }
    #endregion

    #region Network\Hotspot Authentication Settings
    $NetworkHotspotAuthenticationGroupPolicyDefinitions = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions?`$filter=startsWith(categoryPath,'\Network\Hotspot Authentication')" -Method GET -OutputType PSObject).Value
    $NetworkHotspotAuthenticationGroupPolicyDefinitions = $NetworkHotspotAuthenticationGroupPolicyDefinitions | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $_.categoryPath -ChildPath $_.displayName } }
    switch ($NetworkHotspotAuthenticationGroupPolicyDefinitions) {
        { $_.FullPath -eq '\Network\Hotspot Authentication\Enable Hotspot Authentication' } { Set-GroupPolicyDefinitionSetting -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Disable -Verbose; continue }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified ..." }  
    }
    #endregion

    #region Network\Microsoft Peer-to-Peer Networking Services Settings
    $NetworkP2PGroupPolicyDefinitions = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions?`$filter=startsWith(categoryPath,'\Network\Microsoft Peer-to-Peer Networking Services')" -Method GET -OutputType PSObject).Value
    switch ($NetworkP2PGroupPolicyDefinitions) {
        { $_.FullPath -eq '\Network\Microsoft Peer-to-Peer Networking Services\Turn off Microsoft Peer-to-Peer Networking Services' } { Set-GroupPolicyDefinitionSetting -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Verbose; continue }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified ..." }  
    }
    #endregion

    #region Network\Offline Files Settings
    $NetworkOfflineFilesGroupPolicyDefinitions = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions?`$filter=startsWith(categoryPath,'\Network\Offline Files')" -Method GET -OutputType PSObject).Value
    $NetworkOfflineFilesGroupPolicyDefinitions = $NetworkOfflineFilesGroupPolicyDefinitions | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $_.categoryPath -ChildPath $_.displayName } }
    switch ($NetworkOfflineFilesGroupPolicyDefinitions) {
        { $_.FullPath -eq '\Network\Offline Files\Allow or Disallow use of the Offline Files feature' } { Set-GroupPolicyDefinitionSetting -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Disable -Verbose; continue }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified ..." }  
    }
    #endregion

    #region Remote Desktop Services Settings
    $RDSSessionTimeLimitsGroupPolicyDefinitions = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions?`$filter=startsWith(categoryPath,'\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits')" -Method GET -OutputType PSObject).Value
    $RDSSessionTimeLimitsGroupPolicyDefinitions = $RDSSessionTimeLimitsGroupPolicyDefinitions | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $_.categoryPath -ChildPath $_.displayName } }
    switch ($RDSSessionTimeLimitsGroupPolicyDefinitions) {
        { $_.FullPath -eq '\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits\Set time limit for active but idle Remote Desktop Services sessions' } { Set-GroupPolicyDefinitionSetting -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value "900000" -Verbose; continue }  
        { $_.FullPath -eq '\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits\Set time limit for disconnected sessions' } { Set-GroupPolicyDefinitionSetting -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value "900000" -Verbose; continue }  
        { $_.FullPath -eq '\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits\Set time limit for active Remote Desktop Services sessions' } { Set-GroupPolicyDefinitionSetting -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value "0" -Verbose; continue }  
        { $_.FullPath -eq '\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits\End session when time limits are reached' } { Set-GroupPolicyDefinitionSetting -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 0 -Verbose; continue }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified ..." }  
    }
    #endregion

    #region Remote Desktop Services Settings
    $RDSAVDGroupPolicyDefinitions = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions?`$filter=startsWith(categoryPath,'\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Azure Virtual Desktop')" -Method GET -OutputType PSObject).Value
    $RDSAVDGroupPolicyDefinitions = $RDSAVDGroupPolicyDefinitions | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $_.categoryPath -ChildPath $_.displayName } }
    $GroupPolicyDefinitionPresentation = Get-GroupPolicyDefinitionPresentation -GroupPolicyDefinition $RDSAVDGroupPolicyDefinitions -Verbose
    switch ($RDSAVDGroupPolicyDefinitions) {
        { $_.FullPath -eq '\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Azure Virtual Desktop\Enable screen capture protection' } { Set-GroupPolicyDefinitionSetting -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value "2" -Verbose; continue }  
        { ($_.FullPath -eq '\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Azure Virtual Desktop\Enable watermarking') -and ($_.version -eq '2.0') } { 
            $Value = @{
                "QR code bitmap scale factor"                                     = 4
                "QR code bitmap opacity"                                          = 2000
                "Width of grid box in percent relative to QR code bitmap width"   = 320
                "Height of grid box in percent relative to QR code bitmap height" = 180
                "QR code embedded content"                                        = "0"
            }
            Set-GroupPolicyDefinitionSetting -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value $Value -Verbose; continue 
        }
        default { Write-Verbose -Message "'$($_.FullPath)' not modified ..." }  
    }
    #endregion

}
#endregion

Clear-Host
$Error.Clear()
Connect-MgGraph -NoWelcome -Scopes Device.Read.All, Device.ReadWrite.All, DeviceManagementConfiguration.Read.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.Read.All, DeviceManagementManagedDevices.ReadWrite.All, Directory.AccessAsUser.All, Directory.Read.All, Directory.ReadWrite.All

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

#region Function calls
$HostPoolName = "hp-np-ei-poc-mp-use-73"
$SessionHostName = "nepcmuse73-0", "nepcmuse73-1", "nepcmuse73-2"

New-FSLogixIntuneConfigurationProfile -CurrentHostPoolStorageAccountName fslhpnpeipocmpuse73 -HostPoolName $HostPoolName -Verbose
New-AVDIntuneConfigurationProfile -HostPoolName $HostPoolName -Verbose
New-IntunePowerShellScript -ScriptURI 'https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Setup/Enable-NewPerformanceCounter.ps1' -HostPoolName $HostPoolName -Verbose

Remove-IntuneItem -HostPoolName $HostPoolName -SessionHostName $SessionHostName -Verbose
#endregion