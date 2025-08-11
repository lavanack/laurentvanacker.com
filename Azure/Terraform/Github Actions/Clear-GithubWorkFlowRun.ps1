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

#region function definitions
#From https://blog.oddbit.com/post/2022-09-22-delete-workflow-runs/
function Clear-GithubWorkFlowRun {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [ValidateScript({ Test-Path -Path $_ -PathType Container })]
        [alias('Fullname')]
        [string] $Directory,
        [switch] $AsJob
    )

    #region Github CLI Setup
    try { 
        $null = gh 
    }
    catch {
        $GithubCLIURI = $(((Invoke-RestMethod -Uri "https://api.github.com/repos/cli/cli/releases/latest").assets | Where-Object -FilterScript { $_.name.EndsWith("windows_amd64.msi") }).browser_download_url)
        Start-BitsTransfer -Source $GithubCLIURI -Destination $Env:TEMP
        $LocalGithubCLIURI = Join-Path -Path $Env:TEMP -ChildPath $(Split-Path -Path $GithubCLIURI -Leaf)
        Write-Verbose -Message "Installing $GithubCLIURI"
        Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "msiexec /i $LocalGithubCLIURI /passive /norestart" -Wait
        $env:Path = "$env:Path;$env:ProgramFiles\GitHub CLI\"
    }
    #endregion

    #region Git CLI Setup
    try { 
        $null = git 
    }
    catch {
        $GitCLIURI = $(((Invoke-RestMethod  -Uri "https://api.github.com/repos/git-for-windows/git/releases/latest").assets | Where-Object -FilterScript { $_.name.EndsWith("64-bit.exe") }).browser_download_url)
        Start-BitsTransfer -Source $GitCLIURI -Destination $Env:TEMP
        $LocalGitCLIURI = Join-Path -Path $Env:TEMP -ChildPath $(Split-Path -Path $GitCLIURI -Leaf)
        Write-Verbose -Message "Installing $GitCLIURI"
        Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "$LocalGitCLIURI /SILENT /CLOSEAPPLICATIONS" -Wait
        $env:Path = "$env:Path;$env:ProgramFiles\Git\cmd\"
    }
    #endregion

    if ($Directory) {
        Push-Location -Path $Directory
    }


    #region Git Login
    $null = gh auth status 
    if (-not($?)) {
        gh auth login
    }
    #endregion


    $null = gh run list 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Error -Message "The '$pwd' folder is not a git repository (or any of the parent directories)" #-ErrorAction Stop
    }
    else {
        Do {
            #Listing non "in-progress" actions
            $Jobs = gh run list --json databaseId,workflowName,createdAt,status -q '.[]' | ConvertFrom-Json | Where-Object -FilterScript { $_.status -eq "completed" } | ForEach-Object -Process {
                Write-Verbose -Message "Removing the '$($_.databaseId) - $($_.workflowName) - $([datetime]::Parse($_.createdAt))' run"
                if ($AsJob) {
                    $DatabaseId = $_.databaseId
                    Start-Job -ScriptBlock { Set-Location -Path $using:PSScriptRoot; gh api "repos/$(gh repo view --json nameWithOwner -q .nameWithOwner)/actions/runs/$($using:DatabaseId)" -X DELETE }
                }
                else {
                    gh api "repos/$(gh repo view --json nameWithOwner -q .nameWithOwner)/actions/runs/$($_.databaseId)" -X DELETE
                }
            }
            if ($AsJob) {
                $null = $Jobs | Receive-Job -Wait -AutoRemoveJob
            }
        } while (gh run list --json status -q '.[]' | ConvertFrom-Json | Where-Object -FilterScript { $_.status -ne "in_progress" })
    }
    if ($Directory) {
        Pop-Location
    }
}
#endregion

#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir
#$GitHubDirectories = (Get-ChildItem -Path (Get-PSDrive -PSProvider FileSystem | Where-Object -FilterScript { $_.Used }).Root -Directory -Filter ".github" -Recurse -ErrorAction Ignore).Parent

#If you put this script in any location inside a github repo
Clear-GithubWorkFlowRun -AsJob -Verbose

#If you put this script in any location outside a github repo you have to specify the path of the github repo
#Clear-GithubWorkFlowRun -Directory (Resolve-Path -Path ..\..\..).Path -AsJob -Verbose
#endregion