locals {
  azure_regions = {
    # Europe
    "northeurope"        = "eun"
    "westeurope"         = "euw"
    "francecentral"      = "frc"
    "francesouth"        = "frs"
    "germanywestcentral" = "dewc"
    "germanynorth"       = "den"
    "swedencentral"      = "swc"
    "swedensouth"        = "sws"
    "switzerlandnorth"   = "szn"
    "switzerlandwest"    = "szw"
    "norwayeast"         = "noe"
    "norwaywest"         = "now"
    "uksouth"            = "uks"
    "ukwest"             = "ukw"
    "spaincentral"       = "spc"
    "polandcentral"      = "plc"
    "italynorth"         = "itn"
    "denmarkeast"        = "dke"
    "belgiumcentral"     = "bec"
    "austriaeast"        = "ate"

    # Americas
    "eastus"          = "use"
    "eastus2"         = "use2"
    "centralus"       = "usc"
    "northcentralus"  = "usnc"
    "southcentralus"  = "ussc"
    "westus"          = "usw"
    "westcentralus"   = "uscw"
    "westus2"         = "usw2"
    "westus3"         = "usw3"
    "canadacentral"   = "cac"
    "canadaeast"      = "cae"
    "brazilsouth"     = "brs"
    "brazilsoutheast" = "brse"
    "mexicocentral"   = "mxc"
    "chilecentral"    = "clc"

    # Asia Pacific
    "eastasia"           = "ase"
    "southeastasia"      = "sea"
    "japaneast"          = "jpe"
    "japanwest"          = "jpw"
    "koreacentral"       = "krc"
    "koreasouth"         = "krs"
    "centralindia"       = "inc"
    "southindia"         = "sin"
    "westindia"          = "win"
    "indonesiacentral"   = "idc"
    "malaysiawest"       = "myw"
    "australiaeast"      = "aue"
    "australiasoutheast" = "aus"
    "australiacentral"   = "auc"
    "australiacentral2"  = "auc2"
    "newzealandnorth"    = "nzn"

    # Middle East & Africa
    "uaenorth"         = "uan"
    "uaecentral"       = "uac"
    "qatarcentral"     = "qac"
    "israelcentral"    = "ilc"
    "southafricanorth" = "san"
    "southafricawest"  = "saw"
  }

  virtual_desktop_azure_regions = {
    # Europe
    "northeurope" = "eun"
    "westeurope"  = "euw"
    "uksouth"     = "uks"
    "ukwest"      = "ukw"

    # Americas
    "eastus"         = "use"
    "eastus2"        = "use2"
    "centralus"      = "usc"
    "northcentralus" = "usnc"
    "southcentralus" = "ussc"
    "westus"         = "usw"
    "westcentralus"  = "uscw"
    "westus2"        = "usw2"
    "westus3"        = "usw3"
    "canadacentral"  = "cac"
    "canadaeast"     = "cae"

    # Asia Pacific
    "eastasia"      = "ase"
    "southeastasia" = "sea"
    "japaneast"     = "jpe"
    "japanwest"     = "jpw"
    "koreacentral"  = "krc"
    "centralindia"  = "inc"
    "australiaeast" = "aue"

    # Middle East & Africa
    "southafricanorth" = "san"
  }

  virtual_desktop_hostpool_name                                  = "hp-np-ei-tf-mp-${local.azure_regions[random_shuffle.avd_region.result[0]]}-${random_integer.instance_index.result}"
  virtual_desktop_vm_prefix                                      = "${var.virtual_desktop_vm_prefix}${local.azure_regions[random_shuffle.avd_region.result[0]]}${random_integer.instance_index.result}"
  virtual_desktop_application_group_default_desktop_display_name = "${local.virtual_desktop_hostpool_name}-DAG"
  virtual_desktop_application_group_description                  = "Default desktop application group for host pool ${local.virtual_desktop_hostpool_name}"
  virtual_desktop_application_group_friendly_name                = local.virtual_desktop_application_group_default_desktop_display_name
  virtual_desktop_workspace_name                                 = "ws-${local.virtual_desktop_hostpool_name}"
  virtual_desktop_workspace_description                          = "Workspace for host pool ${local.virtual_desktop_hostpool_name}"
  virtual_desktop_workspace_friendly_name                        = local.virtual_desktop_workspace_description
  virtual_desktop_scalingplan_name                               = "sp-${local.virtual_desktop_hostpool_name}"
  virtual_desktop_dag_group_name                                 = "${local.virtual_desktop_hostpool_name} - Desktop Application Group Users"

  # According to versions/provider, output may already be an HCL object.
  # We secure with try() to support both:
  ra_value = try(
    data.azapi_resource_list.role_assignments_sub.output.value,
    jsondecode(data.azapi_resource_list.role_assignments_sub.output).value
  )

  matching_role_assignments = [
    for ra in local.ra_value : ra
    if ra.properties.principalId == data.azuread_service_principal.avd_spn.object_id
    && ra.properties.roleDefinitionId == data.azurerm_role_definition.power_role.id
  ]

  role_assignment_exists = length(local.matching_role_assignments) > 0

  # name must be a GUID : we make it deterministic
  role_assignment_guid = uuidv5(
    "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    "${data.azurerm_subscription.current.id}|${data.azuread_service_principal.avd_spn.object_id}|${data.azurerm_role_definition.power_role.id}"
  )
}
