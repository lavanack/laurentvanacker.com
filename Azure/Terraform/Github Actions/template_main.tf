terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~>3.0"
    }
  }
  backend "azurerm" {
    resource_group_name  = "<backend_resource_group_name>"
    storage_account_name = "<backend_storage_account_name>"
    container_name       = "<backend_container_name>"
    key                  = "terraform.tfstate"
  }

}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "<resource_group_name>" {
  name     = "<resource_group_name>"
  location = "<location>"
}
