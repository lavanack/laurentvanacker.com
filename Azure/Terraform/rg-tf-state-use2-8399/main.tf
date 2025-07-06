terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~>3.0"
    }
  }
  backend "azurerm" {
    resource_group_name  = "rg-tf-state-use2-8399"
    storage_account_name = "sttfstateuse28399"
    container_name       = "tfstate"
    key                  = "terraform.tfstate"
  }

}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "rg-tf-state-use2-8399" {
  name     = "rg-tf-sample-use2-8399"
  location = "eastus2"
}




