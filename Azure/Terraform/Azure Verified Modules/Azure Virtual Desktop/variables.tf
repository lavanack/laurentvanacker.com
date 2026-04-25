variable "virtual_desktop_host_pool_start_vm_on_connect" {
  type        = bool
  default     = true
  description = "Indicates whether to start the VM on connect."
}

variable "virtual_desktop_host_pool_load_balancer_type" {
  type        = string
  default     = "BreadthFirst"
  description = "The load balancer type for the host pool. Possible values are BreadthFirst and DepthFirst."
}

variable "virtual_desktop_host_pool_type" {
  type        = string
  default     = "Pooled"
  description = "The type of the host pool. Possible values are Personal and Pooled."
}

variable "virtual_desktop_host_pool_maximum_sessions_allowed" {
  type        = number
  default     = 16
  description = "The maximum number of sessions allowed per session host."
}

variable "enable_telemetry" {
  type        = bool
  default     = true
  description = "Enable or disable telemetry for the module."
}

variable "vm_count" {
  type        = number
  default     = 1
  description = "The number of AVD session host VMs to deploy."
}

variable "avd_vm_prefix" {
  type        = string
  default     = "nem"
  description = "The base name for the AVD session host VMs."
}

variable "avd_vm_size" {
  type        = string
  default     = "Standard_B2as_v2"
  description = "The size of the AVD session host VMs."
}

variable "tags" {
  type = map(string)
  default = {
    environment = "demo"
    owner       = "Laurent VAN ACKER"
  }
  description = "Azure resource tags to apply to some resources."
}

variable "vnet_address_space" {
  type        = list(string)
  default     = ["10.1.6.0/26"]
  description = "The address space for the virtual network."
}

variable "subnet_address_prefixes" {
  type        = list(string)
  default     = ["10.1.6.0/27"]
  description = "The address prefixes for the AVD subnet."
}
