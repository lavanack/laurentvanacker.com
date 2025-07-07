terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~>3.0"
    }
  }
  backend "azurerm" {
    resource_group_name  = "rg-tf-state-use2-3577"
    storage_account_name = "sttfstateuse23577"
    container_name       = "tfstate"
    key                  = "terraform.tfstate"
  }

}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "rg-tf-state-use2-3577" {
  name     = "rg-tf-sample-use2-3577"
  location = "eastus2"
}




