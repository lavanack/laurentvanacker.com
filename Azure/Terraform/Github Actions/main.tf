terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~>3.0"
    }
  }
  backend "azurerm" {
    resource_group_name  = "rg-tf-ghact-use2-4361"
    storage_account_name = "sttfghactuse24361"
    container_name       = "tfstate"
    key                  = "terraform.tfstate"
  }

}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "rg-tf-sample-use2-4361" {
  name     = "rg-tf-sample-use2-4361"
  location = "eastus2"
}

