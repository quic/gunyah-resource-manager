// Automatically generated. Do not modify.
//
// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// _result_t type definitions and accessors

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

typedef struct paddr_result {
	paddr_t r;
	error_t alignas(register_t) e;
} paddr_result_t;

paddr_result_t
paddr_result_error(error_t err);
paddr_result_t
paddr_result_ok(paddr_t ret);

typedef struct paddr_ptr_result {
	paddr_t *r;
	error_t alignas(register_t) e;
} paddr_ptr_result_t;

paddr_ptr_result_t
paddr_ptr_result_error(error_t err);
paddr_ptr_result_t
paddr_ptr_result_ok(paddr_t *ret);

typedef struct error_result {
	error_t r;
	error_t alignas(register_t) e;
} error_result_t;

error_result_t
error_result_error(error_t err);
error_result_t
error_result_ok(error_t ret);

typedef struct error_ptr_result {
	error_t *r;
	error_t alignas(register_t) e;
} error_ptr_result_t;

error_ptr_result_t
error_ptr_result_error(error_t err);
error_ptr_result_t
error_ptr_result_ok(error_t *ret);

typedef struct register_result {
	register_t r;
	error_t alignas(register_t) e;
} register_result_t;

register_result_t
register_result_error(error_t err);
register_result_t
register_result_ok(register_t ret);

typedef struct register_ptr_result {
	register_t *r;
	error_t alignas(register_t) e;
} register_ptr_result_t;

register_ptr_result_t
register_ptr_result_error(error_t err);
register_ptr_result_t
register_ptr_result_ok(register_t *ret);

typedef struct sregister_result {
	sregister_t r;
	error_t alignas(register_t) e;
} sregister_result_t;

sregister_result_t
sregister_result_error(error_t err);
sregister_result_t
sregister_result_ok(sregister_t ret);

typedef struct sregister_ptr_result {
	sregister_t *r;
	error_t alignas(register_t) e;
} sregister_ptr_result_t;

sregister_ptr_result_t
sregister_ptr_result_error(error_t err);
sregister_ptr_result_t
sregister_ptr_result_ok(sregister_t *ret);

typedef struct count_result {
	count_t r;
	error_t alignas(register_t) e;
} count_result_t;

count_result_t
count_result_error(error_t err);
count_result_t
count_result_ok(count_t ret);

typedef struct count_ptr_result {
	count_t *r;
	error_t alignas(register_t) e;
} count_ptr_result_t;

count_ptr_result_t
count_ptr_result_error(error_t err);
count_ptr_result_t
count_ptr_result_ok(count_t *ret);

typedef struct index_result {
	index_t r;
	error_t alignas(register_t) e;
} index_result_t;

index_result_t
index_result_error(error_t err);
index_result_t
index_result_ok(index_t ret);

typedef struct index_ptr_result {
	index_t *r;
	error_t alignas(register_t) e;
} index_ptr_result_t;

index_ptr_result_t
index_ptr_result_error(error_t err);
index_ptr_result_t
index_ptr_result_ok(index_t *ret);

typedef struct boot_env_phys_range_result {
	boot_env_phys_range_t r;
	error_t alignas(register_t) e;
} boot_env_phys_range_result_t;

boot_env_phys_range_result_t
boot_env_phys_range_result_error(error_t err);
boot_env_phys_range_result_t
boot_env_phys_range_result_ok(boot_env_phys_range_t ret);

typedef struct boot_env_phys_range_ptr_result {
	boot_env_phys_range_t *r;
	error_t alignas(register_t) e;
} boot_env_phys_range_ptr_result_t;

boot_env_phys_range_ptr_result_t
boot_env_phys_range_ptr_result_error(error_t err);
boot_env_phys_range_ptr_result_t
boot_env_phys_range_ptr_result_ok(boot_env_phys_range_t *ret);

typedef struct boot_env_data_result {
	boot_env_data_t r;
	error_t alignas(register_t) e;
} boot_env_data_result_t;

boot_env_data_result_t
boot_env_data_result_error(error_t err);
boot_env_data_result_t
boot_env_data_result_ok(boot_env_data_t ret);

typedef struct boot_env_data_ptr_result {
	boot_env_data_t *r;
	error_t alignas(register_t) e;
} boot_env_data_ptr_result_t;

boot_env_data_ptr_result_t
boot_env_data_ptr_result_error(error_t err);
boot_env_data_ptr_result_t
boot_env_data_ptr_result_ok(boot_env_data_t *ret);

typedef struct cpu_index_result {
	cpu_index_t r;
	error_t alignas(register_t) e;
} cpu_index_result_t;

cpu_index_result_t
cpu_index_result_error(error_t err);
cpu_index_result_t
cpu_index_result_ok(cpu_index_t ret);

typedef struct cpu_index_ptr_result {
	cpu_index_t *r;
	error_t alignas(register_t) e;
} cpu_index_ptr_result_t;

cpu_index_ptr_result_t
cpu_index_ptr_result_error(error_t err);
cpu_index_ptr_result_t
cpu_index_ptr_result_ok(cpu_index_t *ret);

typedef struct hyp_variant_result {
	hyp_variant_t r;
	error_t alignas(register_t) e;
} hyp_variant_result_t;

hyp_variant_result_t
hyp_variant_result_error(error_t err);
hyp_variant_result_t
hyp_variant_result_ok(hyp_variant_t ret);

typedef struct hyp_variant_ptr_result {
	hyp_variant_t *r;
	error_t alignas(register_t) e;
} hyp_variant_ptr_result_t;

hyp_variant_ptr_result_t
hyp_variant_ptr_result_error(error_t err);
hyp_variant_ptr_result_t
hyp_variant_ptr_result_ok(hyp_variant_t *ret);

typedef struct hyp_api_info_result {
	hyp_api_info_t r;
	error_t alignas(register_t) e;
} hyp_api_info_result_t;

hyp_api_info_result_t
hyp_api_info_result_error(error_t err);
hyp_api_info_result_t
hyp_api_info_result_ok(hyp_api_info_t ret);

typedef struct hyp_api_info_ptr_result {
	hyp_api_info_t *r;
	error_t alignas(register_t) e;
} hyp_api_info_ptr_result_t;

hyp_api_info_ptr_result_t
hyp_api_info_ptr_result_error(error_t err);
hyp_api_info_ptr_result_t
hyp_api_info_ptr_result_ok(hyp_api_info_t *ret);

typedef struct hyp_api_flags0_result {
	hyp_api_flags0_t r;
	error_t alignas(register_t) e;
} hyp_api_flags0_result_t;

hyp_api_flags0_result_t
hyp_api_flags0_result_error(error_t err);
hyp_api_flags0_result_t
hyp_api_flags0_result_ok(hyp_api_flags0_t ret);

typedef struct hyp_api_flags0_ptr_result {
	hyp_api_flags0_t *r;
	error_t alignas(register_t) e;
} hyp_api_flags0_ptr_result_t;

hyp_api_flags0_ptr_result_t
hyp_api_flags0_ptr_result_error(error_t err);
hyp_api_flags0_ptr_result_t
hyp_api_flags0_ptr_result_ok(hyp_api_flags0_t *ret);

typedef struct hyp_api_flags1_result {
	hyp_api_flags1_t r;
	error_t alignas(register_t) e;
} hyp_api_flags1_result_t;

hyp_api_flags1_result_t
hyp_api_flags1_result_error(error_t err);
hyp_api_flags1_result_t
hyp_api_flags1_result_ok(hyp_api_flags1_t ret);

typedef struct hyp_api_flags1_ptr_result {
	hyp_api_flags1_t *r;
	error_t alignas(register_t) e;
} hyp_api_flags1_ptr_result_t;

hyp_api_flags1_ptr_result_t
hyp_api_flags1_ptr_result_error(error_t err);
hyp_api_flags1_ptr_result_t
hyp_api_flags1_ptr_result_ok(hyp_api_flags1_t *ret);

typedef struct hyp_api_flags2_result {
	hyp_api_flags2_t r;
	error_t alignas(register_t) e;
} hyp_api_flags2_result_t;

hyp_api_flags2_result_t
hyp_api_flags2_result_error(error_t err);
hyp_api_flags2_result_t
hyp_api_flags2_result_ok(hyp_api_flags2_t ret);

typedef struct hyp_api_flags2_ptr_result {
	hyp_api_flags2_t *r;
	error_t alignas(register_t) e;
} hyp_api_flags2_ptr_result_t;

hyp_api_flags2_ptr_result_t
hyp_api_flags2_ptr_result_error(error_t err);
hyp_api_flags2_ptr_result_t
hyp_api_flags2_ptr_result_ok(hyp_api_flags2_t *ret);

typedef struct memextent_memtype_result {
	memextent_memtype_t r;
	error_t alignas(register_t) e;
} memextent_memtype_result_t;

memextent_memtype_result_t
memextent_memtype_result_error(error_t err);
memextent_memtype_result_t
memextent_memtype_result_ok(memextent_memtype_t ret);

typedef struct memextent_memtype_ptr_result {
	memextent_memtype_t *r;
	error_t alignas(register_t) e;
} memextent_memtype_ptr_result_t;

memextent_memtype_ptr_result_t
memextent_memtype_ptr_result_error(error_t err);
memextent_memtype_ptr_result_t
memextent_memtype_ptr_result_ok(memextent_memtype_t *ret);

typedef struct memextent_attrs_result {
	memextent_attrs_t r;
	error_t alignas(register_t) e;
} memextent_attrs_result_t;

memextent_attrs_result_t
memextent_attrs_result_error(error_t err);
memextent_attrs_result_t
memextent_attrs_result_ok(memextent_attrs_t ret);

typedef struct memextent_attrs_ptr_result {
	memextent_attrs_t *r;
	error_t alignas(register_t) e;
} memextent_attrs_ptr_result_t;

memextent_attrs_ptr_result_t
memextent_attrs_ptr_result_error(error_t err);
memextent_attrs_ptr_result_t
memextent_attrs_ptr_result_ok(memextent_attrs_t *ret);

typedef struct memextent_mapping_attrs_result {
	memextent_mapping_attrs_t r;
	error_t alignas(register_t) e;
} memextent_mapping_attrs_result_t;

memextent_mapping_attrs_result_t
memextent_mapping_attrs_result_error(error_t err);
memextent_mapping_attrs_result_t
memextent_mapping_attrs_result_ok(memextent_mapping_attrs_t ret);

typedef struct memextent_mapping_attrs_ptr_result {
	memextent_mapping_attrs_t *r;
	error_t alignas(register_t) e;
} memextent_mapping_attrs_ptr_result_t;

memextent_mapping_attrs_ptr_result_t
memextent_mapping_attrs_ptr_result_error(error_t err);
memextent_mapping_attrs_ptr_result_t
memextent_mapping_attrs_ptr_result_ok(memextent_mapping_attrs_t *ret);

typedef struct memextent_access_attrs_result {
	memextent_access_attrs_t r;
	error_t alignas(register_t) e;
} memextent_access_attrs_result_t;

memextent_access_attrs_result_t
memextent_access_attrs_result_error(error_t err);
memextent_access_attrs_result_t
memextent_access_attrs_result_ok(memextent_access_attrs_t ret);

typedef struct memextent_access_attrs_ptr_result {
	memextent_access_attrs_t *r;
	error_t alignas(register_t) e;
} memextent_access_attrs_ptr_result_t;

memextent_access_attrs_ptr_result_t
memextent_access_attrs_ptr_result_error(error_t err);
memextent_access_attrs_ptr_result_t
memextent_access_attrs_ptr_result_ok(memextent_access_attrs_t *ret);

typedef struct pgtable_vm_memtype_result {
	pgtable_vm_memtype_t r;
	error_t alignas(register_t) e;
} pgtable_vm_memtype_result_t;

pgtable_vm_memtype_result_t
pgtable_vm_memtype_result_error(error_t err);
pgtable_vm_memtype_result_t
pgtable_vm_memtype_result_ok(pgtable_vm_memtype_t ret);

typedef struct pgtable_vm_memtype_ptr_result {
	pgtable_vm_memtype_t *r;
	error_t alignas(register_t) e;
} pgtable_vm_memtype_ptr_result_t;

pgtable_vm_memtype_ptr_result_t
pgtable_vm_memtype_ptr_result_error(error_t err);
pgtable_vm_memtype_ptr_result_t
pgtable_vm_memtype_ptr_result_ok(pgtable_vm_memtype_t *ret);

typedef struct pgtable_access_result {
	pgtable_access_t r;
	error_t alignas(register_t) e;
} pgtable_access_result_t;

pgtable_access_result_t
pgtable_access_result_error(error_t err);
pgtable_access_result_t
pgtable_access_result_ok(pgtable_access_t ret);

typedef struct pgtable_access_ptr_result {
	pgtable_access_t *r;
	error_t alignas(register_t) e;
} pgtable_access_ptr_result_t;

pgtable_access_ptr_result_t
pgtable_access_ptr_result_error(error_t err);
pgtable_access_ptr_result_t
pgtable_access_ptr_result_ok(pgtable_access_t *ret);

typedef struct priority_result {
	priority_t r;
	error_t alignas(register_t) e;
} priority_result_t;

priority_result_t
priority_result_error(error_t err);
priority_result_t
priority_result_ok(priority_t ret);

typedef struct priority_ptr_result {
	priority_t *r;
	error_t alignas(register_t) e;
} priority_ptr_result_t;

priority_ptr_result_t
priority_ptr_result_error(error_t err);
priority_ptr_result_t
priority_ptr_result_ok(priority_t *ret);

typedef struct scheduler_variant_result {
	scheduler_variant_t r;
	error_t alignas(register_t) e;
} scheduler_variant_result_t;

scheduler_variant_result_t
scheduler_variant_result_error(error_t err);
scheduler_variant_result_t
scheduler_variant_result_ok(scheduler_variant_t ret);

typedef struct scheduler_variant_ptr_result {
	scheduler_variant_t *r;
	error_t alignas(register_t) e;
} scheduler_variant_ptr_result_t;

scheduler_variant_ptr_result_t
scheduler_variant_ptr_result_error(error_t err);
scheduler_variant_ptr_result_t
scheduler_variant_ptr_result_ok(scheduler_variant_t *ret);

typedef struct scheduler_yield_control_result {
	scheduler_yield_control_t r;
	error_t alignas(register_t) e;
} scheduler_yield_control_result_t;

scheduler_yield_control_result_t
scheduler_yield_control_result_error(error_t err);
scheduler_yield_control_result_t
scheduler_yield_control_result_ok(scheduler_yield_control_t ret);

typedef struct scheduler_yield_control_ptr_result {
	scheduler_yield_control_t *r;
	error_t alignas(register_t) e;
} scheduler_yield_control_ptr_result_t;

scheduler_yield_control_ptr_result_t
scheduler_yield_control_ptr_result_error(error_t err);
scheduler_yield_control_ptr_result_t
scheduler_yield_control_ptr_result_ok(scheduler_yield_control_t *ret);

typedef struct scheduler_yield_hint_result {
	scheduler_yield_hint_t r;
	error_t alignas(register_t) e;
} scheduler_yield_hint_result_t;

scheduler_yield_hint_result_t
scheduler_yield_hint_result_error(error_t err);
scheduler_yield_hint_result_t
scheduler_yield_hint_result_ok(scheduler_yield_hint_t ret);

typedef struct scheduler_yield_hint_ptr_result {
	scheduler_yield_hint_t *r;
	error_t alignas(register_t) e;
} scheduler_yield_hint_ptr_result_t;

scheduler_yield_hint_ptr_result_t
scheduler_yield_hint_ptr_result_error(error_t err);
scheduler_yield_hint_ptr_result_t
scheduler_yield_hint_ptr_result_ok(scheduler_yield_hint_t *ret);

typedef struct vmaddr_result {
	vmaddr_t r;
	error_t alignas(register_t) e;
} vmaddr_result_t;

vmaddr_result_t
vmaddr_result_error(error_t err);
vmaddr_result_t
vmaddr_result_ok(vmaddr_t ret);

typedef struct vmaddr_ptr_result {
	vmaddr_t *r;
	error_t alignas(register_t) e;
} vmaddr_ptr_result_t;

vmaddr_ptr_result_t
vmaddr_ptr_result_error(error_t err);
vmaddr_ptr_result_t
vmaddr_ptr_result_ok(vmaddr_t *ret);

typedef struct nanoseconds_result {
	nanoseconds_t r;
	error_t alignas(register_t) e;
} nanoseconds_result_t;

nanoseconds_result_t
nanoseconds_result_error(error_t err);
nanoseconds_result_t
nanoseconds_result_ok(nanoseconds_t ret);

typedef struct nanoseconds_ptr_result {
	nanoseconds_t *r;
	error_t alignas(register_t) e;
} nanoseconds_ptr_result_t;

nanoseconds_ptr_result_t
nanoseconds_ptr_result_error(error_t err);
nanoseconds_ptr_result_t
nanoseconds_ptr_result_ok(nanoseconds_t *ret);

typedef struct vic_option_flags_result {
	vic_option_flags_t r;
	error_t alignas(register_t) e;
} vic_option_flags_result_t;

vic_option_flags_result_t
vic_option_flags_result_error(error_t err);
vic_option_flags_result_t
vic_option_flags_result_ok(vic_option_flags_t ret);

typedef struct vic_option_flags_ptr_result {
	vic_option_flags_t *r;
	error_t alignas(register_t) e;
} vic_option_flags_ptr_result_t;

vic_option_flags_ptr_result_t
vic_option_flags_ptr_result_error(error_t err);
vic_option_flags_ptr_result_t
vic_option_flags_ptr_result_ok(vic_option_flags_t *ret);

typedef struct virq_result {
	virq_t r;
	error_t alignas(register_t) e;
} virq_result_t;

virq_result_t
virq_result_error(error_t err);
virq_result_t
virq_result_ok(virq_t ret);

typedef struct virq_ptr_result {
	virq_t *r;
	error_t alignas(register_t) e;
} virq_ptr_result_t;

virq_ptr_result_t
virq_ptr_result_error(error_t err);
virq_ptr_result_t
virq_ptr_result_ok(virq_t *ret);

typedef struct msgqueue_create_info_result {
	msgqueue_create_info_t r;
	error_t alignas(register_t) e;
} msgqueue_create_info_result_t;

msgqueue_create_info_result_t
msgqueue_create_info_result_error(error_t err);
msgqueue_create_info_result_t
msgqueue_create_info_result_ok(msgqueue_create_info_t ret);

typedef struct msgqueue_create_info_ptr_result {
	msgqueue_create_info_t *r;
	error_t alignas(register_t) e;
} msgqueue_create_info_ptr_result_t;

msgqueue_create_info_ptr_result_t
msgqueue_create_info_ptr_result_error(error_t err);
msgqueue_create_info_ptr_result_t
msgqueue_create_info_ptr_result_ok(msgqueue_create_info_t *ret);

typedef struct msgqueue_send_flags_result {
	msgqueue_send_flags_t r;
	error_t alignas(register_t) e;
} msgqueue_send_flags_result_t;

msgqueue_send_flags_result_t
msgqueue_send_flags_result_error(error_t err);
msgqueue_send_flags_result_t
msgqueue_send_flags_result_ok(msgqueue_send_flags_t ret);

typedef struct msgqueue_send_flags_ptr_result {
	msgqueue_send_flags_t *r;
	error_t alignas(register_t) e;
} msgqueue_send_flags_ptr_result_t;

msgqueue_send_flags_ptr_result_t
msgqueue_send_flags_ptr_result_error(error_t err);
msgqueue_send_flags_ptr_result_t
msgqueue_send_flags_ptr_result_ok(msgqueue_send_flags_t *ret);

typedef struct vmid_result {
	vmid_t r;
	error_t alignas(register_t) e;
} vmid_result_t;

vmid_result_t
vmid_result_error(error_t err);
vmid_result_t
vmid_result_ok(vmid_t ret);

typedef struct vmid_ptr_result {
	vmid_t *r;
	error_t alignas(register_t) e;
} vmid_ptr_result_t;

vmid_ptr_result_t
vmid_ptr_result_error(error_t err);
vmid_ptr_result_t
vmid_ptr_result_ok(vmid_t *ret);

typedef struct vcpu_option_flags_result {
	vcpu_option_flags_t r;
	error_t alignas(register_t) e;
} vcpu_option_flags_result_t;

vcpu_option_flags_result_t
vcpu_option_flags_result_error(error_t err);
vcpu_option_flags_result_t
vcpu_option_flags_result_ok(vcpu_option_flags_t ret);

typedef struct vcpu_option_flags_ptr_result {
	vcpu_option_flags_t *r;
	error_t alignas(register_t) e;
} vcpu_option_flags_ptr_result_t;

vcpu_option_flags_ptr_result_t
vcpu_option_flags_ptr_result_error(error_t err);
vcpu_option_flags_ptr_result_t
vcpu_option_flags_ptr_result_ok(vcpu_option_flags_t *ret);

typedef struct cap_id_result {
	cap_id_t r;
	error_t alignas(register_t) e;
} cap_id_result_t;

cap_id_result_t
cap_id_result_error(error_t err);
cap_id_result_t
cap_id_result_ok(cap_id_t ret);

typedef struct cap_id_ptr_result {
	cap_id_t *r;
	error_t alignas(register_t) e;
} cap_id_ptr_result_t;

cap_id_ptr_result_t
cap_id_ptr_result_error(error_t err);
cap_id_ptr_result_t
cap_id_ptr_result_ok(cap_id_t *ret);

typedef struct cap_rights_result {
	cap_rights_t r;
	error_t alignas(register_t) e;
} cap_rights_result_t;

cap_rights_result_t
cap_rights_result_error(error_t err);
cap_rights_result_t
cap_rights_result_ok(cap_rights_t ret);

typedef struct cap_rights_ptr_result {
	cap_rights_t *r;
	error_t alignas(register_t) e;
} cap_rights_ptr_result_t;

cap_rights_ptr_result_t
cap_rights_ptr_result_error(error_t err);
cap_rights_ptr_result_t
cap_rights_ptr_result_ok(cap_rights_t *ret);

typedef struct cap_rights_generic_result {
	cap_rights_generic_t r;
	error_t alignas(register_t) e;
} cap_rights_generic_result_t;

cap_rights_generic_result_t
cap_rights_generic_result_error(error_t err);
cap_rights_generic_result_t
cap_rights_generic_result_ok(cap_rights_generic_t ret);

typedef struct cap_rights_generic_ptr_result {
	cap_rights_generic_t *r;
	error_t alignas(register_t) e;
} cap_rights_generic_ptr_result_t;

cap_rights_generic_ptr_result_t
cap_rights_generic_ptr_result_error(error_t err);
cap_rights_generic_ptr_result_t
cap_rights_generic_ptr_result_ok(cap_rights_generic_t *ret);

typedef struct cap_rights_addrspace_result {
	cap_rights_addrspace_t r;
	error_t alignas(register_t) e;
} cap_rights_addrspace_result_t;

cap_rights_addrspace_result_t
cap_rights_addrspace_result_error(error_t err);
cap_rights_addrspace_result_t
cap_rights_addrspace_result_ok(cap_rights_addrspace_t ret);

typedef struct cap_rights_addrspace_ptr_result {
	cap_rights_addrspace_t *r;
	error_t alignas(register_t) e;
} cap_rights_addrspace_ptr_result_t;

cap_rights_addrspace_ptr_result_t
cap_rights_addrspace_ptr_result_error(error_t err);
cap_rights_addrspace_ptr_result_t
cap_rights_addrspace_ptr_result_ok(cap_rights_addrspace_t *ret);

typedef struct cap_rights_cspace_result {
	cap_rights_cspace_t r;
	error_t alignas(register_t) e;
} cap_rights_cspace_result_t;

cap_rights_cspace_result_t
cap_rights_cspace_result_error(error_t err);
cap_rights_cspace_result_t
cap_rights_cspace_result_ok(cap_rights_cspace_t ret);

typedef struct cap_rights_cspace_ptr_result {
	cap_rights_cspace_t *r;
	error_t alignas(register_t) e;
} cap_rights_cspace_ptr_result_t;

cap_rights_cspace_ptr_result_t
cap_rights_cspace_ptr_result_error(error_t err);
cap_rights_cspace_ptr_result_t
cap_rights_cspace_ptr_result_ok(cap_rights_cspace_t *ret);

typedef struct cap_rights_doorbell_result {
	cap_rights_doorbell_t r;
	error_t alignas(register_t) e;
} cap_rights_doorbell_result_t;

cap_rights_doorbell_result_t
cap_rights_doorbell_result_error(error_t err);
cap_rights_doorbell_result_t
cap_rights_doorbell_result_ok(cap_rights_doorbell_t ret);

typedef struct cap_rights_doorbell_ptr_result {
	cap_rights_doorbell_t *r;
	error_t alignas(register_t) e;
} cap_rights_doorbell_ptr_result_t;

cap_rights_doorbell_ptr_result_t
cap_rights_doorbell_ptr_result_error(error_t err);
cap_rights_doorbell_ptr_result_t
cap_rights_doorbell_ptr_result_ok(cap_rights_doorbell_t *ret);

typedef struct cap_rights_hwirq_result {
	cap_rights_hwirq_t r;
	error_t alignas(register_t) e;
} cap_rights_hwirq_result_t;

cap_rights_hwirq_result_t
cap_rights_hwirq_result_error(error_t err);
cap_rights_hwirq_result_t
cap_rights_hwirq_result_ok(cap_rights_hwirq_t ret);

typedef struct cap_rights_hwirq_ptr_result {
	cap_rights_hwirq_t *r;
	error_t alignas(register_t) e;
} cap_rights_hwirq_ptr_result_t;

cap_rights_hwirq_ptr_result_t
cap_rights_hwirq_ptr_result_error(error_t err);
cap_rights_hwirq_ptr_result_t
cap_rights_hwirq_ptr_result_ok(cap_rights_hwirq_t *ret);

typedef struct cap_rights_memextent_result {
	cap_rights_memextent_t r;
	error_t alignas(register_t) e;
} cap_rights_memextent_result_t;

cap_rights_memextent_result_t
cap_rights_memextent_result_error(error_t err);
cap_rights_memextent_result_t
cap_rights_memextent_result_ok(cap_rights_memextent_t ret);

typedef struct cap_rights_memextent_ptr_result {
	cap_rights_memextent_t *r;
	error_t alignas(register_t) e;
} cap_rights_memextent_ptr_result_t;

cap_rights_memextent_ptr_result_t
cap_rights_memextent_ptr_result_error(error_t err);
cap_rights_memextent_ptr_result_t
cap_rights_memextent_ptr_result_ok(cap_rights_memextent_t *ret);

typedef struct cap_rights_msgqueue_result {
	cap_rights_msgqueue_t r;
	error_t alignas(register_t) e;
} cap_rights_msgqueue_result_t;

cap_rights_msgqueue_result_t
cap_rights_msgqueue_result_error(error_t err);
cap_rights_msgqueue_result_t
cap_rights_msgqueue_result_ok(cap_rights_msgqueue_t ret);

typedef struct cap_rights_msgqueue_ptr_result {
	cap_rights_msgqueue_t *r;
	error_t alignas(register_t) e;
} cap_rights_msgqueue_ptr_result_t;

cap_rights_msgqueue_ptr_result_t
cap_rights_msgqueue_ptr_result_error(error_t err);
cap_rights_msgqueue_ptr_result_t
cap_rights_msgqueue_ptr_result_ok(cap_rights_msgqueue_t *ret);

typedef struct cap_rights_partition_result {
	cap_rights_partition_t r;
	error_t alignas(register_t) e;
} cap_rights_partition_result_t;

cap_rights_partition_result_t
cap_rights_partition_result_error(error_t err);
cap_rights_partition_result_t
cap_rights_partition_result_ok(cap_rights_partition_t ret);

typedef struct cap_rights_partition_ptr_result {
	cap_rights_partition_t *r;
	error_t alignas(register_t) e;
} cap_rights_partition_ptr_result_t;

cap_rights_partition_ptr_result_t
cap_rights_partition_ptr_result_error(error_t err);
cap_rights_partition_ptr_result_t
cap_rights_partition_ptr_result_ok(cap_rights_partition_t *ret);

typedef struct cap_rights_thread_result {
	cap_rights_thread_t r;
	error_t alignas(register_t) e;
} cap_rights_thread_result_t;

cap_rights_thread_result_t
cap_rights_thread_result_error(error_t err);
cap_rights_thread_result_t
cap_rights_thread_result_ok(cap_rights_thread_t ret);

typedef struct cap_rights_thread_ptr_result {
	cap_rights_thread_t *r;
	error_t alignas(register_t) e;
} cap_rights_thread_ptr_result_t;

cap_rights_thread_ptr_result_t
cap_rights_thread_ptr_result_error(error_t err);
cap_rights_thread_ptr_result_t
cap_rights_thread_ptr_result_ok(cap_rights_thread_t *ret);

typedef struct cap_rights_vic_result {
	cap_rights_vic_t r;
	error_t alignas(register_t) e;
} cap_rights_vic_result_t;

cap_rights_vic_result_t
cap_rights_vic_result_error(error_t err);
cap_rights_vic_result_t
cap_rights_vic_result_ok(cap_rights_vic_t ret);

typedef struct cap_rights_vic_ptr_result {
	cap_rights_vic_t *r;
	error_t alignas(register_t) e;
} cap_rights_vic_ptr_result_t;

cap_rights_vic_ptr_result_t
cap_rights_vic_ptr_result_error(error_t err);
cap_rights_vic_ptr_result_t
cap_rights_vic_ptr_result_ok(cap_rights_vic_t *ret);

typedef struct cap_rights_vpm_group_result {
	cap_rights_vpm_group_t r;
	error_t alignas(register_t) e;
} cap_rights_vpm_group_result_t;

cap_rights_vpm_group_result_t
cap_rights_vpm_group_result_error(error_t err);
cap_rights_vpm_group_result_t
cap_rights_vpm_group_result_ok(cap_rights_vpm_group_t ret);

typedef struct cap_rights_vpm_group_ptr_result {
	cap_rights_vpm_group_t *r;
	error_t alignas(register_t) e;
} cap_rights_vpm_group_ptr_result_t;

cap_rights_vpm_group_ptr_result_t
cap_rights_vpm_group_ptr_result_error(error_t err);
cap_rights_vpm_group_ptr_result_t
cap_rights_vpm_group_ptr_result_ok(cap_rights_vpm_group_t *ret);

typedef struct bool_result {
	bool r;
	error_t alignas(register_t) e;
} bool_result_t;

bool_result_t
bool_result_error(error_t err);
bool_result_t
bool_result_ok(bool ret);

typedef struct uint8_result {
	uint8_t r;
	error_t alignas(register_t) e;
} uint8_result_t;

uint8_result_t
uint8_result_error(error_t err);
uint8_result_t
uint8_result_ok(uint8_t ret);

typedef struct uint16_result {
	uint16_t r;
	error_t alignas(register_t) e;
} uint16_result_t;

uint16_result_t
uint16_result_error(error_t err);
uint16_result_t
uint16_result_ok(uint16_t ret);

typedef struct uint32_result {
	uint32_t r;
	error_t alignas(register_t) e;
} uint32_result_t;

uint32_result_t
uint32_result_error(error_t err);
uint32_result_t
uint32_result_ok(uint32_t ret);

typedef struct uint64_result {
	uint64_t r;
	error_t alignas(register_t) e;
} uint64_result_t;

uint64_result_t
uint64_result_error(error_t err);
uint64_result_t
uint64_result_ok(uint64_t ret);

typedef struct uintptr_result {
	uintptr_t r;
	error_t alignas(register_t) e;
} uintptr_result_t;

uintptr_result_t
uintptr_result_error(error_t err);
uintptr_result_t
uintptr_result_ok(uintptr_t ret);

typedef struct sint8_result {
	int8_t r;
	error_t alignas(register_t) e;
} sint8_result_t;

sint8_result_t
sint8_result_error(error_t err);
sint8_result_t
sint8_result_ok(int8_t ret);

typedef struct sint16_result {
	int16_t r;
	error_t alignas(register_t) e;
} sint16_result_t;

sint16_result_t
sint16_result_error(error_t err);
sint16_result_t
sint16_result_ok(int16_t ret);

typedef struct sint32_result {
	int32_t r;
	error_t alignas(register_t) e;
} sint32_result_t;

sint32_result_t
sint32_result_error(error_t err);
sint32_result_t
sint32_result_ok(int32_t ret);

typedef struct sint64_result {
	int64_t r;
	error_t alignas(register_t) e;
} sint64_result_t;

sint64_result_t
sint64_result_error(error_t err);
sint64_result_t
sint64_result_ok(int64_t ret);

typedef struct sintptr_result {
	intptr_t r;
	error_t alignas(register_t) e;
} sintptr_result_t;

sintptr_result_t
sintptr_result_error(error_t err);
sintptr_result_t
sintptr_result_ok(intptr_t ret);

typedef struct char_result {
	char r;
	error_t alignas(register_t) e;
} char_result_t;

char_result_t
char_result_error(error_t err);
char_result_t
char_result_ok(char ret);

typedef struct size_result {
	size_t r;
	error_t alignas(register_t) e;
} size_result_t;

size_result_t
size_result_error(error_t err);
size_result_t
size_result_ok(size_t ret);

typedef struct void_ptr_result {
	void *r;
	error_t alignas(register_t) e;
} void_ptr_result_t;

void_ptr_result_t
void_ptr_result_error(error_t err);
void_ptr_result_t
void_ptr_result_ok(void *ret);

#pragma clang diagnostic pop
