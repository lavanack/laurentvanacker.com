# Terraform configuration block
# Specifies the required Terraform version and provider dependencies
terraform {
  required_version = ">= 1.9, < 2.0.0"

  required_providers {
    # Random provider for generating passwords and random values
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5.1, < 4.0.0"
    }

    # Azure Resource Manager provider for managing Azure resources
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0"
    }

    # Azure Active Directory provider for managing Entra ID resources
    azuread = {
      source  = "hashicorp/azuread"
      version = ">= 2.0"
    }

    # Azure API provider for resources not yet supported by azurerm
    azapi = {
      source  = "Azure/azapi"
      version = ">= 2.0"
    }
  }

  # Store Terraform state locally
  backend "local" {}
}

# Azure AD / Entra ID provider configuration (uses default authentication)
provider "azuread" {}

# Azure API provider configuration (uses default authentication)
provider "azapi" {}

# Azure Resource Manager provider configuration
provider "azurerm" {
  features {
    resource_group {
      # Allow deletion of resource groups even if they still contain resources
      prevent_deletion_if_contains_resources = false
    }
  }
}

