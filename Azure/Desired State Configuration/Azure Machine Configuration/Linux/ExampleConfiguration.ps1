#From https://azurearcjumpstart.com/azure_arc_jumpstart/azure_arc_servers/day2/arc_automanage/arc_automanage_machine_configuration_custom_linux
Configuration ExampleConfiguration
{
    param(
        $FilePath = "/tmp/arc-nxscript-demo",
        $FileContent = "Hello Arc!"
    )

    Import-DscResource -ModuleName nxtools

    Node localhost
    {
        nxPackage nginx {
            Name   = "nginx"
            Ensure = "Present"
        }
        nxPackage hello {
            Name   = "hello"
            Ensure = "Present"
        }
        nxFile demofile1 {
            DestinationPath = "/tmp/arc-demo"
            Ensure          = "Present"
            Mode            = '0777'
            Contents        = "Hello Arc!"
            Owner           = 'root'
            Group           = 'root'
        }
        nxGroup arcusers {
            GroupName = "arcusers"
            Ensure    = "Present"
        }
        nxScript demofile2 {
            GetScript  = {
                $Reason = [Reason]::new()
                $Reason.Code = "Script:Script:FileMissing"
                $Reason.Phrase = "File does not exist"

                if (Test-Path -Path $using:FilePath) {
                    $text = $(Get-Content -Path $using:FilePath -Raw).Trim()
                    if ($text -eq $using:FileContent) {
                        $Reason.Code = "Script:Script:Success"
                        $Reason.Phrase = "File exists with correct content"
                    }
                    else {
                        $Reason.Code = "Script:Script:ContentMissing"
                        $Reason.Phrase = "File exists but has incorrect content"
                    }
                }

                return @{
                    Reasons = @($Reason)
                }
            }
            TestScript = {
                if (Test-Path -Path $using:FilePath) {
                    $text = $(Get-Content -Path $using:FilePath -Raw).Trim()
                    return $text -eq $using:FileContent
                }
                else {
                    return $false
                }
            }
            SetScript  = {
                $null = Set-Content -Path $using:FilePath -Value $using:FileContent
            }
        }
    }
}

ExampleConfiguration