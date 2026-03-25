// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_RESOURCE_MANAGER_H_
#define INCLUDE_RESOURCE_MANAGER_H_

extern gunyah_hyp_hypervisor_identify_result_t hyp_id;

paddr_t
rm_ipa_to_pa(uintptr_t ipa);

cap_id_t
rm_get_rm_addrspace(void);

cap_id_t
rm_get_rm_cspace(void);

cap_id_t
rm_get_rm_partition(void);

cap_id_t
rm_get_rm_vic(void);

count_t
rm_get_vic_max_virqs(void);

cap_id_t
rm_get_device_me_cap(void);

count_t
rm_get_device_ranges_count(void);

void
rm_get_device_ranges(index_t i, paddr_t *base, size_t *size);

cap_id_t
rm_get_me(void);

vmaddr_t
rm_get_hlos_entry(void);

bool
rm_get_watchdog_supported(void);

paddr_t
rm_get_watchdog_address(void);

cap_id_t
rm_get_restricted_hwirq(virq_t irq, vmid_t vmid);

count_t
rm_get_platform_max_cores(void);

cpu_index_t
rm_get_platform_root_vcpu_index(void);

bool
rm_is_core_usable(cpu_index_t i);

const uint64_t *
rm_get_usable_cores(count_t *array_size);

vmaddr_t
rm_get_me_ipa_base(void);

size_t
rm_get_me_size(void);

vmaddr_t
rm_get_hlos_dt_base(void);

paddr_t
rm_get_uart_address(void);

cap_id_t
rm_get_uart_me(void);

platform_env_data_t *
rm_get_platform_env_data(void);

const vm_device_assignments_t *
rm_get_vm_device_assignments(void);

bool
rm_get_sve_supported(void);

bool
rm_get_sme_supported(void);

cap_id_t
rm_get_system_power(void);

bool
rm_get_has_system_suspend(void);

bool
rm_get_sdei_supported(void);

rm_smmu_env_data_t *
rm_get_smmuv2_env(void);

count_t
rm_get_num_v2_smmu(void);

cap_id_t
rm_get_smmuv3_cap(index_t i);

cap_id_t
rm_get_its_cap(index_t i);

#else

#error multiple include of resource-manager.h

#endif
