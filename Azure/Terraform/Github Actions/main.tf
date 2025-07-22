terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~>3.0"
    }
  }
  backend "azurerm" {
    resource_group_name  = "rg-tf-ghact-use2-1716"
    storage_account_name = "sttfghactuse21716"
    container_name       = "tfstate"
    key                  = "terraform.tfstate"
    use_oidc             = true
  }

}

provider "azurerm" {
  features {}
  use_oidc = true
}

resource "azurerm_resource_group" "rg-tf-sample-use2-1716" {
  name     = "rg-tf-sample-use2-1716"
  location = "eastus2"
}





