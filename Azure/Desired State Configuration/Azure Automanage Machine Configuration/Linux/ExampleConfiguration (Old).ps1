Import-Module PSDesiredStateConfiguration -RequiredVersion 3.0.0

Configuration ExampleConfiguration
{
	Import-DSCResource -ModuleName nxtools

	Node  localhost
	{
		nxFile ExampleFile
		{
			DestinationPath = "/tmp/example"
			Contents        = "hello world `n"
			Ensure          = "Present"
			Type            = "File"
            Mode            = '0777'
		}
	}
}

ExampleConfiguration 