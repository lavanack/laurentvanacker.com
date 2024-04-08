# Enable-AllPIMRolesForAzResource.ps1

This PowerShell script is designed to activate all Privileged Identity Management (PIM) roles for a the connected Azure account. It was requeted by a customer or mine. 

## Prerequisites

- PowerShell 5.1 or higher
- The following PowerShell module: Az.Accounts and Az.Resources

## Usage

1. Open PowerShell.
2. Navigate to the directory containing `Enable-allPIMRolesForAzResource.ps1`.
3. Run the script using the command `.\Enable-allPIMRolesForAzResource.ps1`.
4. Follow the prompts to specify the Azure resource for which you want to enable PIM roles.

## Functionality

The script performs the following steps:

1. Authenticates to Azure using your credentials (it not already connected to Azure).
2. Retrieves a list of all eligible PIM roles to activate. If you specify the -filter switch you can filter the roles via a Grid View. By default the role are activated for 8 hours. You can control this time range (between 1 and 8 hours) via the -Hour (integer) parameter.
3. Activates each PIM role.

## Parameters

- Filter: If specified, the script will display a Grid View of all eligible PIM roles. You can select the roles you want to activate.
- Hour: If specified, the script will activate the roles for the specified number of hours. The default value is 8 hours.
  
## Contributing

Contributions are welcome. Please open an issue or submit a pull request.
