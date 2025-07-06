terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~>3.0"
    }
  }
  backend "azurerm" {
      resource_group_name  = "<resource_group_name>"
      storage_account_name = "<storage_account_name>"
      container_name       = "<container_name>"
      key                  = "terraform.tfstate"
  }

}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "<resource_group_name>" {
  name     = "<tf_resource_group_name>"
  location = "<location>"
}