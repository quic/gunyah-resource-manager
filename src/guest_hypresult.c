// Automatically generated. Do not modify.
//
// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

// Result Accessors

paddr_result_t
paddr_result_error(error_t err)
{
	return (paddr_result_t){ .e = err };
}

paddr_result_t
paddr_result_ok(paddr_t ret)
{
	return (paddr_result_t){ .r = ret, .e = OK };
}

paddr_ptr_result_t
paddr_ptr_result_error(error_t err)
{
	return (paddr_ptr_result_t){ .e = err };
}

paddr_ptr_result_t
paddr_ptr_result_ok(paddr_t *ret)
{
	return (paddr_ptr_result_t){ .r = ret, .e = OK };
}

error_result_t
error_result_error(error_t err)
{
	return (error_result_t){ .e = err };
}

error_result_t
error_result_ok(error_t ret)
{
	return (error_result_t){ .r = ret, .e = OK };
}

error_ptr_result_t
error_ptr_result_error(error_t err)
{
	return (error_ptr_result_t){ .e = err };
}

error_ptr_result_t
error_ptr_result_ok(error_t *ret)
{
	return (error_ptr_result_t){ .r = ret, .e = OK };
}

register_result_t
register_result_error(error_t err)
{
	return (register_result_t){ .e = err };
}

register_result_t
register_result_ok(register_t ret)
{
	return (register_result_t){ .r = ret, .e = OK };
}

register_ptr_result_t
register_ptr_result_error(error_t err)
{
	return (register_ptr_result_t){ .e = err };
}

register_ptr_result_t
register_ptr_result_ok(register_t *ret)
{
	return (register_ptr_result_t){ .r = ret, .e = OK };
}

sregister_result_t
sregister_result_error(error_t err)
{
	return (sregister_result_t){ .e = err };
}

sregister_result_t
sregister_result_ok(sregister_t ret)
{
	return (sregister_result_t){ .r = ret, .e = OK };
}

sregister_ptr_result_t
sregister_ptr_result_error(error_t err)
{
	return (sregister_ptr_result_t){ .e = err };
}

sregister_ptr_result_t
sregister_ptr_result_ok(sregister_t *ret)
{
	return (sregister_ptr_result_t){ .r = ret, .e = OK };
}

count_result_t
count_result_error(error_t err)
{
	return (count_result_t){ .e = err };
}

count_result_t
count_result_ok(count_t ret)
{
	return (count_result_t){ .r = ret, .e = OK };
}

count_ptr_result_t
count_ptr_result_error(error_t err)
{
	return (count_ptr_result_t){ .e = err };
}

count_ptr_result_t
count_ptr_result_ok(count_t *ret)
{
	return (count_ptr_result_t){ .r = ret, .e = OK };
}

index_result_t
index_result_error(error_t err)
{
	return (index_result_t){ .e = err };
}

index_result_t
index_result_ok(index_t ret)
{
	return (index_result_t){ .r = ret, .e = OK };
}

index_ptr_result_t
index_ptr_result_error(error_t err)
{
	return (index_ptr_result_t){ .e = err };
}

index_ptr_result_t
index_ptr_result_ok(index_t *ret)
{
	return (index_ptr_result_t){ .r = ret, .e = OK };
}

boot_env_phys_range_result_t
boot_env_phys_range_result_error(error_t err)
{
	return (boot_env_phys_range_result_t){ .e = err };
}

boot_env_phys_range_result_t
boot_env_phys_range_result_ok(boot_env_phys_range_t ret)
{
	return (boot_env_phys_range_result_t){ .r = ret, .e = OK };
}

boot_env_phys_range_ptr_result_t
boot_env_phys_range_ptr_result_error(error_t err)
{
	return (boot_env_phys_range_ptr_result_t){ .e = err };
}

boot_env_phys_range_ptr_result_t
boot_env_phys_range_ptr_result_ok(boot_env_phys_range_t *ret)
{
	return (boot_env_phys_range_ptr_result_t){ .r = ret, .e = OK };
}

boot_env_data_result_t
boot_env_data_result_error(error_t err)
{
	return (boot_env_data_result_t){ .e = err };
}

boot_env_data_result_t
boot_env_data_result_ok(boot_env_data_t ret)
{
	return (boot_env_data_result_t){ .r = ret, .e = OK };
}

boot_env_data_ptr_result_t
boot_env_data_ptr_result_error(error_t err)
{
	return (boot_env_data_ptr_result_t){ .e = err };
}

boot_env_data_ptr_result_t
boot_env_data_ptr_result_ok(boot_env_data_t *ret)
{
	return (boot_env_data_ptr_result_t){ .r = ret, .e = OK };
}

cpu_index_result_t
cpu_index_result_error(error_t err)
{
	return (cpu_index_result_t){ .e = err };
}

cpu_index_result_t
cpu_index_result_ok(cpu_index_t ret)
{
	return (cpu_index_result_t){ .r = ret, .e = OK };
}

cpu_index_ptr_result_t
cpu_index_ptr_result_error(error_t err)
{
	return (cpu_index_ptr_result_t){ .e = err };
}

cpu_index_ptr_result_t
cpu_index_ptr_result_ok(cpu_index_t *ret)
{
	return (cpu_index_ptr_result_t){ .r = ret, .e = OK };
}

hyp_variant_result_t
hyp_variant_result_error(error_t err)
{
	return (hyp_variant_result_t){ .e = err };
}

hyp_variant_result_t
hyp_variant_result_ok(hyp_variant_t ret)
{
	return (hyp_variant_result_t){ .r = ret, .e = OK };
}

hyp_variant_ptr_result_t
hyp_variant_ptr_result_error(error_t err)
{
	return (hyp_variant_ptr_result_t){ .e = err };
}

hyp_variant_ptr_result_t
hyp_variant_ptr_result_ok(hyp_variant_t *ret)
{
	return (hyp_variant_ptr_result_t){ .r = ret, .e = OK };
}

hyp_api_info_result_t
hyp_api_info_result_error(error_t err)
{
	return (hyp_api_info_result_t){ .e = err };
}

hyp_api_info_result_t
hyp_api_info_result_ok(hyp_api_info_t ret)
{
	return (hyp_api_info_result_t){ .r = ret, .e = OK };
}

hyp_api_info_ptr_result_t
hyp_api_info_ptr_result_error(error_t err)
{
	return (hyp_api_info_ptr_result_t){ .e = err };
}

hyp_api_info_ptr_result_t
hyp_api_info_ptr_result_ok(hyp_api_info_t *ret)
{
	return (hyp_api_info_ptr_result_t){ .r = ret, .e = OK };
}

hyp_api_flags0_result_t
hyp_api_flags0_result_error(error_t err)
{
	return (hyp_api_flags0_result_t){ .e = err };
}

hyp_api_flags0_result_t
hyp_api_flags0_result_ok(hyp_api_flags0_t ret)
{
	return (hyp_api_flags0_result_t){ .r = ret, .e = OK };
}

hyp_api_flags0_ptr_result_t
hyp_api_flags0_ptr_result_error(error_t err)
{
	return (hyp_api_flags0_ptr_result_t){ .e = err };
}

hyp_api_flags0_ptr_result_t
hyp_api_flags0_ptr_result_ok(hyp_api_flags0_t *ret)
{
	return (hyp_api_flags0_ptr_result_t){ .r = ret, .e = OK };
}

hyp_api_flags1_result_t
hyp_api_flags1_result_error(error_t err)
{
	return (hyp_api_flags1_result_t){ .e = err };
}

hyp_api_flags1_result_t
hyp_api_flags1_result_ok(hyp_api_flags1_t ret)
{
	return (hyp_api_flags1_result_t){ .r = ret, .e = OK };
}

hyp_api_flags1_ptr_result_t
hyp_api_flags1_ptr_result_error(error_t err)
{
	return (hyp_api_flags1_ptr_result_t){ .e = err };
}

hyp_api_flags1_ptr_result_t
hyp_api_flags1_ptr_result_ok(hyp_api_flags1_t *ret)
{
	return (hyp_api_flags1_ptr_result_t){ .r = ret, .e = OK };
}

hyp_api_flags2_result_t
hyp_api_flags2_result_error(error_t err)
{
	return (hyp_api_flags2_result_t){ .e = err };
}

hyp_api_flags2_result_t
hyp_api_flags2_result_ok(hyp_api_flags2_t ret)
{
	return (hyp_api_flags2_result_t){ .r = ret, .e = OK };
}

hyp_api_flags2_ptr_result_t
hyp_api_flags2_ptr_result_error(error_t err)
{
	return (hyp_api_flags2_ptr_result_t){ .e = err };
}

hyp_api_flags2_ptr_result_t
hyp_api_flags2_ptr_result_ok(hyp_api_flags2_t *ret)
{
	return (hyp_api_flags2_ptr_result_t){ .r = ret, .e = OK };
}

memextent_memtype_result_t
memextent_memtype_result_error(error_t err)
{
	return (memextent_memtype_result_t){ .e = err };
}

memextent_memtype_result_t
memextent_memtype_result_ok(memextent_memtype_t ret)
{
	return (memextent_memtype_result_t){ .r = ret, .e = OK };
}

memextent_memtype_ptr_result_t
memextent_memtype_ptr_result_error(error_t err)
{
	return (memextent_memtype_ptr_result_t){ .e = err };
}

memextent_memtype_ptr_result_t
memextent_memtype_ptr_result_ok(memextent_memtype_t *ret)
{
	return (memextent_memtype_ptr_result_t){ .r = ret, .e = OK };
}

memextent_attrs_result_t
memextent_attrs_result_error(error_t err)
{
	return (memextent_attrs_result_t){ .e = err };
}

memextent_attrs_result_t
memextent_attrs_result_ok(memextent_attrs_t ret)
{
	return (memextent_attrs_result_t){ .r = ret, .e = OK };
}

memextent_attrs_ptr_result_t
memextent_attrs_ptr_result_error(error_t err)
{
	return (memextent_attrs_ptr_result_t){ .e = err };
}

memextent_attrs_ptr_result_t
memextent_attrs_ptr_result_ok(memextent_attrs_t *ret)
{
	return (memextent_attrs_ptr_result_t){ .r = ret, .e = OK };
}

memextent_mapping_attrs_result_t
memextent_mapping_attrs_result_error(error_t err)
{
	return (memextent_mapping_attrs_result_t){ .e = err };
}

memextent_mapping_attrs_result_t
memextent_mapping_attrs_result_ok(memextent_mapping_attrs_t ret)
{
	return (memextent_mapping_attrs_result_t){ .r = ret, .e = OK };
}

memextent_mapping_attrs_ptr_result_t
memextent_mapping_attrs_ptr_result_error(error_t err)
{
	return (memextent_mapping_attrs_ptr_result_t){ .e = err };
}

memextent_mapping_attrs_ptr_result_t
memextent_mapping_attrs_ptr_result_ok(memextent_mapping_attrs_t *ret)
{
	return (memextent_mapping_attrs_ptr_result_t){ .r = ret, .e = OK };
}

memextent_access_attrs_result_t
memextent_access_attrs_result_error(error_t err)
{
	return (memextent_access_attrs_result_t){ .e = err };
}

memextent_access_attrs_result_t
memextent_access_attrs_result_ok(memextent_access_attrs_t ret)
{
	return (memextent_access_attrs_result_t){ .r = ret, .e = OK };
}

memextent_access_attrs_ptr_result_t
memextent_access_attrs_ptr_result_error(error_t err)
{
	return (memextent_access_attrs_ptr_result_t){ .e = err };
}

memextent_access_attrs_ptr_result_t
memextent_access_attrs_ptr_result_ok(memextent_access_attrs_t *ret)
{
	return (memextent_access_attrs_ptr_result_t){ .r = ret, .e = OK };
}

pgtable_vm_memtype_result_t
pgtable_vm_memtype_result_error(error_t err)
{
	return (pgtable_vm_memtype_result_t){ .e = err };
}

pgtable_vm_memtype_result_t
pgtable_vm_memtype_result_ok(pgtable_vm_memtype_t ret)
{
	return (pgtable_vm_memtype_result_t){ .r = ret, .e = OK };
}

pgtable_vm_memtype_ptr_result_t
pgtable_vm_memtype_ptr_result_error(error_t err)
{
	return (pgtable_vm_memtype_ptr_result_t){ .e = err };
}

pgtable_vm_memtype_ptr_result_t
pgtable_vm_memtype_ptr_result_ok(pgtable_vm_memtype_t *ret)
{
	return (pgtable_vm_memtype_ptr_result_t){ .r = ret, .e = OK };
}

pgtable_access_result_t
pgtable_access_result_error(error_t err)
{
	return (pgtable_access_result_t){ .e = err };
}

pgtable_access_result_t
pgtable_access_result_ok(pgtable_access_t ret)
{
	return (pgtable_access_result_t){ .r = ret, .e = OK };
}

pgtable_access_ptr_result_t
pgtable_access_ptr_result_error(error_t err)
{
	return (pgtable_access_ptr_result_t){ .e = err };
}

pgtable_access_ptr_result_t
pgtable_access_ptr_result_ok(pgtable_access_t *ret)
{
	return (pgtable_access_ptr_result_t){ .r = ret, .e = OK };
}

priority_result_t
priority_result_error(error_t err)
{
	return (priority_result_t){ .e = err };
}

priority_result_t
priority_result_ok(priority_t ret)
{
	return (priority_result_t){ .r = ret, .e = OK };
}

priority_ptr_result_t
priority_ptr_result_error(error_t err)
{
	return (priority_ptr_result_t){ .e = err };
}

priority_ptr_result_t
priority_ptr_result_ok(priority_t *ret)
{
	return (priority_ptr_result_t){ .r = ret, .e = OK };
}

scheduler_variant_result_t
scheduler_variant_result_error(error_t err)
{
	return (scheduler_variant_result_t){ .e = err };
}

scheduler_variant_result_t
scheduler_variant_result_ok(scheduler_variant_t ret)
{
	return (scheduler_variant_result_t){ .r = ret, .e = OK };
}

scheduler_variant_ptr_result_t
scheduler_variant_ptr_result_error(error_t err)
{
	return (scheduler_variant_ptr_result_t){ .e = err };
}

scheduler_variant_ptr_result_t
scheduler_variant_ptr_result_ok(scheduler_variant_t *ret)
{
	return (scheduler_variant_ptr_result_t){ .r = ret, .e = OK };
}

scheduler_yield_control_result_t
scheduler_yield_control_result_error(error_t err)
{
	return (scheduler_yield_control_result_t){ .e = err };
}

scheduler_yield_control_result_t
scheduler_yield_control_result_ok(scheduler_yield_control_t ret)
{
	return (scheduler_yield_control_result_t){ .r = ret, .e = OK };
}

scheduler_yield_control_ptr_result_t
scheduler_yield_control_ptr_result_error(error_t err)
{
	return (scheduler_yield_control_ptr_result_t){ .e = err };
}

scheduler_yield_control_ptr_result_t
scheduler_yield_control_ptr_result_ok(scheduler_yield_control_t *ret)
{
	return (scheduler_yield_control_ptr_result_t){ .r = ret, .e = OK };
}

scheduler_yield_hint_result_t
scheduler_yield_hint_result_error(error_t err)
{
	return (scheduler_yield_hint_result_t){ .e = err };
}

scheduler_yield_hint_result_t
scheduler_yield_hint_result_ok(scheduler_yield_hint_t ret)
{
	return (scheduler_yield_hint_result_t){ .r = ret, .e = OK };
}

scheduler_yield_hint_ptr_result_t
scheduler_yield_hint_ptr_result_error(error_t err)
{
	return (scheduler_yield_hint_ptr_result_t){ .e = err };
}

scheduler_yield_hint_ptr_result_t
scheduler_yield_hint_ptr_result_ok(scheduler_yield_hint_t *ret)
{
	return (scheduler_yield_hint_ptr_result_t){ .r = ret, .e = OK };
}

vmaddr_result_t
vmaddr_result_error(error_t err)
{
	return (vmaddr_result_t){ .e = err };
}

vmaddr_result_t
vmaddr_result_ok(vmaddr_t ret)
{
	return (vmaddr_result_t){ .r = ret, .e = OK };
}

vmaddr_ptr_result_t
vmaddr_ptr_result_error(error_t err)
{
	return (vmaddr_ptr_result_t){ .e = err };
}

vmaddr_ptr_result_t
vmaddr_ptr_result_ok(vmaddr_t *ret)
{
	return (vmaddr_ptr_result_t){ .r = ret, .e = OK };
}

nanoseconds_result_t
nanoseconds_result_error(error_t err)
{
	return (nanoseconds_result_t){ .e = err };
}

nanoseconds_result_t
nanoseconds_result_ok(nanoseconds_t ret)
{
	return (nanoseconds_result_t){ .r = ret, .e = OK };
}

nanoseconds_ptr_result_t
nanoseconds_ptr_result_error(error_t err)
{
	return (nanoseconds_ptr_result_t){ .e = err };
}

nanoseconds_ptr_result_t
nanoseconds_ptr_result_ok(nanoseconds_t *ret)
{
	return (nanoseconds_ptr_result_t){ .r = ret, .e = OK };
}

vic_option_flags_result_t
vic_option_flags_result_error(error_t err)
{
	return (vic_option_flags_result_t){ .e = err };
}

vic_option_flags_result_t
vic_option_flags_result_ok(vic_option_flags_t ret)
{
	return (vic_option_flags_result_t){ .r = ret, .e = OK };
}

vic_option_flags_ptr_result_t
vic_option_flags_ptr_result_error(error_t err)
{
	return (vic_option_flags_ptr_result_t){ .e = err };
}

vic_option_flags_ptr_result_t
vic_option_flags_ptr_result_ok(vic_option_flags_t *ret)
{
	return (vic_option_flags_ptr_result_t){ .r = ret, .e = OK };
}

virq_result_t
virq_result_error(error_t err)
{
	return (virq_result_t){ .e = err };
}

virq_result_t
virq_result_ok(virq_t ret)
{
	return (virq_result_t){ .r = ret, .e = OK };
}

virq_ptr_result_t
virq_ptr_result_error(error_t err)
{
	return (virq_ptr_result_t){ .e = err };
}

virq_ptr_result_t
virq_ptr_result_ok(virq_t *ret)
{
	return (virq_ptr_result_t){ .r = ret, .e = OK };
}

msgqueue_create_info_result_t
msgqueue_create_info_result_error(error_t err)
{
	return (msgqueue_create_info_result_t){ .e = err };
}

msgqueue_create_info_result_t
msgqueue_create_info_result_ok(msgqueue_create_info_t ret)
{
	return (msgqueue_create_info_result_t){ .r = ret, .e = OK };
}

msgqueue_create_info_ptr_result_t
msgqueue_create_info_ptr_result_error(error_t err)
{
	return (msgqueue_create_info_ptr_result_t){ .e = err };
}

msgqueue_create_info_ptr_result_t
msgqueue_create_info_ptr_result_ok(msgqueue_create_info_t *ret)
{
	return (msgqueue_create_info_ptr_result_t){ .r = ret, .e = OK };
}

msgqueue_send_flags_result_t
msgqueue_send_flags_result_error(error_t err)
{
	return (msgqueue_send_flags_result_t){ .e = err };
}

msgqueue_send_flags_result_t
msgqueue_send_flags_result_ok(msgqueue_send_flags_t ret)
{
	return (msgqueue_send_flags_result_t){ .r = ret, .e = OK };
}

msgqueue_send_flags_ptr_result_t
msgqueue_send_flags_ptr_result_error(error_t err)
{
	return (msgqueue_send_flags_ptr_result_t){ .e = err };
}

msgqueue_send_flags_ptr_result_t
msgqueue_send_flags_ptr_result_ok(msgqueue_send_flags_t *ret)
{
	return (msgqueue_send_flags_ptr_result_t){ .r = ret, .e = OK };
}

vmid_result_t
vmid_result_error(error_t err)
{
	return (vmid_result_t){ .e = err };
}

vmid_result_t
vmid_result_ok(vmid_t ret)
{
	return (vmid_result_t){ .r = ret, .e = OK };
}

vmid_ptr_result_t
vmid_ptr_result_error(error_t err)
{
	return (vmid_ptr_result_t){ .e = err };
}

vmid_ptr_result_t
vmid_ptr_result_ok(vmid_t *ret)
{
	return (vmid_ptr_result_t){ .r = ret, .e = OK };
}

vcpu_option_flags_result_t
vcpu_option_flags_result_error(error_t err)
{
	return (vcpu_option_flags_result_t){ .e = err };
}

vcpu_option_flags_result_t
vcpu_option_flags_result_ok(vcpu_option_flags_t ret)
{
	return (vcpu_option_flags_result_t){ .r = ret, .e = OK };
}

vcpu_option_flags_ptr_result_t
vcpu_option_flags_ptr_result_error(error_t err)
{
	return (vcpu_option_flags_ptr_result_t){ .e = err };
}

vcpu_option_flags_ptr_result_t
vcpu_option_flags_ptr_result_ok(vcpu_option_flags_t *ret)
{
	return (vcpu_option_flags_ptr_result_t){ .r = ret, .e = OK };
}

cap_id_result_t
cap_id_result_error(error_t err)
{
	return (cap_id_result_t){ .e = err };
}

cap_id_result_t
cap_id_result_ok(cap_id_t ret)
{
	return (cap_id_result_t){ .r = ret, .e = OK };
}

cap_id_ptr_result_t
cap_id_ptr_result_error(error_t err)
{
	return (cap_id_ptr_result_t){ .e = err };
}

cap_id_ptr_result_t
cap_id_ptr_result_ok(cap_id_t *ret)
{
	return (cap_id_ptr_result_t){ .r = ret, .e = OK };
}

cap_rights_result_t
cap_rights_result_error(error_t err)
{
	return (cap_rights_result_t){ .e = err };
}

cap_rights_result_t
cap_rights_result_ok(cap_rights_t ret)
{
	return (cap_rights_result_t){ .r = ret, .e = OK };
}

cap_rights_ptr_result_t
cap_rights_ptr_result_error(error_t err)
{
	return (cap_rights_ptr_result_t){ .e = err };
}

cap_rights_ptr_result_t
cap_rights_ptr_result_ok(cap_rights_t *ret)
{
	return (cap_rights_ptr_result_t){ .r = ret, .e = OK };
}

cap_rights_generic_result_t
cap_rights_generic_result_error(error_t err)
{
	return (cap_rights_generic_result_t){ .e = err };
}

cap_rights_generic_result_t
cap_rights_generic_result_ok(cap_rights_generic_t ret)
{
	return (cap_rights_generic_result_t){ .r = ret, .e = OK };
}

cap_rights_generic_ptr_result_t
cap_rights_generic_ptr_result_error(error_t err)
{
	return (cap_rights_generic_ptr_result_t){ .e = err };
}

cap_rights_generic_ptr_result_t
cap_rights_generic_ptr_result_ok(cap_rights_generic_t *ret)
{
	return (cap_rights_generic_ptr_result_t){ .r = ret, .e = OK };
}

cap_rights_addrspace_result_t
cap_rights_addrspace_result_error(error_t err)
{
	return (cap_rights_addrspace_result_t){ .e = err };
}

cap_rights_addrspace_result_t
cap_rights_addrspace_result_ok(cap_rights_addrspace_t ret)
{
	return (cap_rights_addrspace_result_t){ .r = ret, .e = OK };
}

cap_rights_addrspace_ptr_result_t
cap_rights_addrspace_ptr_result_error(error_t err)
{
	return (cap_rights_addrspace_ptr_result_t){ .e = err };
}

cap_rights_addrspace_ptr_result_t
cap_rights_addrspace_ptr_result_ok(cap_rights_addrspace_t *ret)
{
	return (cap_rights_addrspace_ptr_result_t){ .r = ret, .e = OK };
}

cap_rights_cspace_result_t
cap_rights_cspace_result_error(error_t err)
{
	return (cap_rights_cspace_result_t){ .e = err };
}

cap_rights_cspace_result_t
cap_rights_cspace_result_ok(cap_rights_cspace_t ret)
{
	return (cap_rights_cspace_result_t){ .r = ret, .e = OK };
}

cap_rights_cspace_ptr_result_t
cap_rights_cspace_ptr_result_error(error_t err)
{
	return (cap_rights_cspace_ptr_result_t){ .e = err };
}

cap_rights_cspace_ptr_result_t
cap_rights_cspace_ptr_result_ok(cap_rights_cspace_t *ret)
{
	return (cap_rights_cspace_ptr_result_t){ .r = ret, .e = OK };
}

cap_rights_doorbell_result_t
cap_rights_doorbell_result_error(error_t err)
{
	return (cap_rights_doorbell_result_t){ .e = err };
}

cap_rights_doorbell_result_t
cap_rights_doorbell_result_ok(cap_rights_doorbell_t ret)
{
	return (cap_rights_doorbell_result_t){ .r = ret, .e = OK };
}

cap_rights_doorbell_ptr_result_t
cap_rights_doorbell_ptr_result_error(error_t err)
{
	return (cap_rights_doorbell_ptr_result_t){ .e = err };
}

cap_rights_doorbell_ptr_result_t
cap_rights_doorbell_ptr_result_ok(cap_rights_doorbell_t *ret)
{
	return (cap_rights_doorbell_ptr_result_t){ .r = ret, .e = OK };
}

cap_rights_hwirq_result_t
cap_rights_hwirq_result_error(error_t err)
{
	return (cap_rights_hwirq_result_t){ .e = err };
}

cap_rights_hwirq_result_t
cap_rights_hwirq_result_ok(cap_rights_hwirq_t ret)
{
	return (cap_rights_hwirq_result_t){ .r = ret, .e = OK };
}

cap_rights_hwirq_ptr_result_t
cap_rights_hwirq_ptr_result_error(error_t err)
{
	return (cap_rights_hwirq_ptr_result_t){ .e = err };
}

cap_rights_hwirq_ptr_result_t
cap_rights_hwirq_ptr_result_ok(cap_rights_hwirq_t *ret)
{
	return (cap_rights_hwirq_ptr_result_t){ .r = ret, .e = OK };
}

cap_rights_memextent_result_t
cap_rights_memextent_result_error(error_t err)
{
	return (cap_rights_memextent_result_t){ .e = err };
}

cap_rights_memextent_result_t
cap_rights_memextent_result_ok(cap_rights_memextent_t ret)
{
	return (cap_rights_memextent_result_t){ .r = ret, .e = OK };
}

cap_rights_memextent_ptr_result_t
cap_rights_memextent_ptr_result_error(error_t err)
{
	return (cap_rights_memextent_ptr_result_t){ .e = err };
}

cap_rights_memextent_ptr_result_t
cap_rights_memextent_ptr_result_ok(cap_rights_memextent_t *ret)
{
	return (cap_rights_memextent_ptr_result_t){ .r = ret, .e = OK };
}

cap_rights_msgqueue_result_t
cap_rights_msgqueue_result_error(error_t err)
{
	return (cap_rights_msgqueue_result_t){ .e = err };
}

cap_rights_msgqueue_result_t
cap_rights_msgqueue_result_ok(cap_rights_msgqueue_t ret)
{
	return (cap_rights_msgqueue_result_t){ .r = ret, .e = OK };
}

cap_rights_msgqueue_ptr_result_t
cap_rights_msgqueue_ptr_result_error(error_t err)
{
	return (cap_rights_msgqueue_ptr_result_t){ .e = err };
}

cap_rights_msgqueue_ptr_result_t
cap_rights_msgqueue_ptr_result_ok(cap_rights_msgqueue_t *ret)
{
	return (cap_rights_msgqueue_ptr_result_t){ .r = ret, .e = OK };
}

cap_rights_partition_result_t
cap_rights_partition_result_error(error_t err)
{
	return (cap_rights_partition_result_t){ .e = err };
}

cap_rights_partition_result_t
cap_rights_partition_result_ok(cap_rights_partition_t ret)
{
	return (cap_rights_partition_result_t){ .r = ret, .e = OK };
}

cap_rights_partition_ptr_result_t
cap_rights_partition_ptr_result_error(error_t err)
{
	return (cap_rights_partition_ptr_result_t){ .e = err };
}

cap_rights_partition_ptr_result_t
cap_rights_partition_ptr_result_ok(cap_rights_partition_t *ret)
{
	return (cap_rights_partition_ptr_result_t){ .r = ret, .e = OK };
}

cap_rights_thread_result_t
cap_rights_thread_result_error(error_t err)
{
	return (cap_rights_thread_result_t){ .e = err };
}

cap_rights_thread_result_t
cap_rights_thread_result_ok(cap_rights_thread_t ret)
{
	return (cap_rights_thread_result_t){ .r = ret, .e = OK };
}

cap_rights_thread_ptr_result_t
cap_rights_thread_ptr_result_error(error_t err)
{
	return (cap_rights_thread_ptr_result_t){ .e = err };
}

cap_rights_thread_ptr_result_t
cap_rights_thread_ptr_result_ok(cap_rights_thread_t *ret)
{
	return (cap_rights_thread_ptr_result_t){ .r = ret, .e = OK };
}

cap_rights_vic_result_t
cap_rights_vic_result_error(error_t err)
{
	return (cap_rights_vic_result_t){ .e = err };
}

cap_rights_vic_result_t
cap_rights_vic_result_ok(cap_rights_vic_t ret)
{
	return (cap_rights_vic_result_t){ .r = ret, .e = OK };
}

cap_rights_vic_ptr_result_t
cap_rights_vic_ptr_result_error(error_t err)
{
	return (cap_rights_vic_ptr_result_t){ .e = err };
}

cap_rights_vic_ptr_result_t
cap_rights_vic_ptr_result_ok(cap_rights_vic_t *ret)
{
	return (cap_rights_vic_ptr_result_t){ .r = ret, .e = OK };
}

cap_rights_vpm_group_result_t
cap_rights_vpm_group_result_error(error_t err)
{
	return (cap_rights_vpm_group_result_t){ .e = err };
}

cap_rights_vpm_group_result_t
cap_rights_vpm_group_result_ok(cap_rights_vpm_group_t ret)
{
	return (cap_rights_vpm_group_result_t){ .r = ret, .e = OK };
}

cap_rights_vpm_group_ptr_result_t
cap_rights_vpm_group_ptr_result_error(error_t err)
{
	return (cap_rights_vpm_group_ptr_result_t){ .e = err };
}

cap_rights_vpm_group_ptr_result_t
cap_rights_vpm_group_ptr_result_ok(cap_rights_vpm_group_t *ret)
{
	return (cap_rights_vpm_group_ptr_result_t){ .r = ret, .e = OK };
}

bool_result_t
bool_result_error(error_t err)
{
	return (bool_result_t){ .e = err };
}

bool_result_t
bool_result_ok(bool ret)
{
	return (bool_result_t){ .r = ret, .e = OK };
}

uint8_result_t
uint8_result_error(error_t err)
{
	return (uint8_result_t){ .e = err };
}

uint8_result_t
uint8_result_ok(uint8_t ret)
{
	return (uint8_result_t){ .r = ret, .e = OK };
}

uint16_result_t
uint16_result_error(error_t err)
{
	return (uint16_result_t){ .e = err };
}

uint16_result_t
uint16_result_ok(uint16_t ret)
{
	return (uint16_result_t){ .r = ret, .e = OK };
}

uint32_result_t
uint32_result_error(error_t err)
{
	return (uint32_result_t){ .e = err };
}

uint32_result_t
uint32_result_ok(uint32_t ret)
{
	return (uint32_result_t){ .r = ret, .e = OK };
}

uint64_result_t
uint64_result_error(error_t err)
{
	return (uint64_result_t){ .e = err };
}

uint64_result_t
uint64_result_ok(uint64_t ret)
{
	return (uint64_result_t){ .r = ret, .e = OK };
}

uintptr_result_t
uintptr_result_error(error_t err)
{
	return (uintptr_result_t){ .e = err };
}

uintptr_result_t
uintptr_result_ok(uintptr_t ret)
{
	return (uintptr_result_t){ .r = ret, .e = OK };
}

sint8_result_t
sint8_result_error(error_t err)
{
	return (sint8_result_t){ .e = err };
}

sint8_result_t
sint8_result_ok(int8_t ret)
{
	return (sint8_result_t){ .r = ret, .e = OK };
}

sint16_result_t
sint16_result_error(error_t err)
{
	return (sint16_result_t){ .e = err };
}

sint16_result_t
sint16_result_ok(int16_t ret)
{
	return (sint16_result_t){ .r = ret, .e = OK };
}

sint32_result_t
sint32_result_error(error_t err)
{
	return (sint32_result_t){ .e = err };
}

sint32_result_t
sint32_result_ok(int32_t ret)
{
	return (sint32_result_t){ .r = ret, .e = OK };
}

sint64_result_t
sint64_result_error(error_t err)
{
	return (sint64_result_t){ .e = err };
}

sint64_result_t
sint64_result_ok(int64_t ret)
{
	return (sint64_result_t){ .r = ret, .e = OK };
}

sintptr_result_t
sintptr_result_error(error_t err)
{
	return (sintptr_result_t){ .e = err };
}

sintptr_result_t
sintptr_result_ok(intptr_t ret)
{
	return (sintptr_result_t){ .r = ret, .e = OK };
}

char_result_t
char_result_error(error_t err)
{
	return (char_result_t){ .e = err };
}

char_result_t
char_result_ok(char ret)
{
	return (char_result_t){ .r = ret, .e = OK };
}

size_result_t
size_result_error(error_t err)
{
	return (size_result_t){ .e = err };
}

size_result_t
size_result_ok(size_t ret)
{
	return (size_result_t){ .r = ret, .e = OK };
}

void_ptr_result_t
void_ptr_result_error(error_t err)
{
	return (void_ptr_result_t){ .e = err };
}

void_ptr_result_t
void_ptr_result_ok(void *ret)
{
	return (void_ptr_result_t){ .r = ret, .e = OK };
}
