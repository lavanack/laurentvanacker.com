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
#Installing Python Tools

Clear-Host
$Error.Clear()

#region Installing Python Tools 
#$Python = (Get-Command -Name python).Source
$Python = "python"

#The key is just here for explanation of the software name (Use it as a comment)
$PythonTools = [ordered] @{
    'PyMuPDF / fitz' = '"pymupdf==2.1"'
    'pymupdf4llm'    = '"pymupdf4llm==2.1"'
    'MLflow'         = '"mlflow==3.18"'
    'vLLM'           = '"vllm==0.33"'
    'PEFT'           = '"peft==0.21.2"'
    'accelerate'     = '"accelerate==1.15"'
    'bitsandbytes'   = '"bitsandbytes==0.50.2"'
    'torch'          = '"torch==2.15"'
    'SGLang'         = '"sglang==0.5.23"'
    'unsloth'        = '"unsloth==2026.11.4"'
    'edsnlp'         = '"edsnlp==0.23"'
    'eds-scikit'     = '"eds-scikit==0.1.8"'
    'edspdf'         = '"edspdf==0.10"'
    'eds-pseudo'     = '"git+https://github.com/aphp/eds-pseudo.git@v0.4.0"'
    'glmocr'         = '"glmocr==0.1.5"'
    'transformers'   = '"transformers==5.22.2"'
}

$Index=0
foreach ($Key in $PythonTools.Keys){
    $Index++
    $PercentComplete = $Index/$PythonTools.Count*100
    $VersionedTool = $PythonTools[$Key]
    Write-Progress -Id 0 -Activity "[$($Index)/$($PythonTools.Count)] Installing Python Tool ..." -CurrentOperation "Installing '$VersionedTool' VM ..." -Status $('{0:N0}%' -f $PercentComplete) -PercentComplete $PercentComplete

    Write-Host "Installing '$VersionedTool' ..."
    & $Python -m pip install $VersionedTool --no-warn-script-location

    $Tool = $VersionedTool -replace "==.*"
    Write-Host "Checking '$Tool' ..." -ForegroundColor Green
    & $Python -m pip show $Tool
}
Write-Progress -Id 0 -Activity "Completed !" -Completed

#endregion 

