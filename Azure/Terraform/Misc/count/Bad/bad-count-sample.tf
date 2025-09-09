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

variable "resource_group_names" {
  type = list(string)
  default = [
    "rg-tf-dev",
    "rg-tf-test", # What happens if we remove this item from the middle of the list?
    "rg-tf-prod"
  ]
}

variable "region" {
  type    = string
  default = "eastus2"
}

resource "azurerm_resource_group" "count_bad" {
  count    = length(var.resource_group_names)
  name     = var.resource_group_names[count.index]
  location = var.region
}
