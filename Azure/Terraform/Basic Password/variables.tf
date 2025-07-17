# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

variable "prefix" {
  description = "The prefix which should be used for all resources in this example"
  default     = "lavanack"
}

variable "location" {
  description = "The Azure Region in which all resources in this example should be created."
  default     = "eastus2"
}

variable "password" {
  description = "The Azure VM password."
  default     = "Pssw0rd1234!"
  sensitive   = true
}

