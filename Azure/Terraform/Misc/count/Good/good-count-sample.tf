terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~>3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "count-sample" {
  count = 3
  name     = "rg-tf-sample-use2-${count.index}"
  location = "eastus2"
}
