configuration LocalRegistry
{
    Import-DscResource -ModuleName PSDSCResources

    node localhost
    {
        Registry Test
        {
            Key = 'HKLM:\SOFTWARE\DscOnAzure'
            ValueName = 'DoesItStillWork'
            ValueData = 'YesItDoes'
        }
    }
}

LocalRegistry
