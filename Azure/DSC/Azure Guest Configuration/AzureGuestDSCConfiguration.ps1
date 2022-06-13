Clear-Host
Set-Location -Path $PSScriptRoot

configuration LocalRegistry
{
    Import-DscResource -ModuleName PSDSCResources

    Registry Test
    {
        Key = 'HKLM:\SOFTWARE\DscOnAzure'
        ValueName = 'DoesItStillWork'
        ValueData = 'YesItDoes'
    }
}

LocalRegistry
