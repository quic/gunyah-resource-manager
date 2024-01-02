// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

typedef struct gunyah_hyp_hypervisor_identify_result
	gunyah_hyp_hypervisor_identify_result_t;

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

cap_id_t
rm_get_device_me_cap(void);

paddr_t
rm_get_device_me_base(void);

size_t
rm_get_device_me_size(void);

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

index_t
rm_get_platform_root_vcpu_index(void);

bool
rm_is_core_usable(cpu_index_t i);

vmaddr_t
rm_get_me_ipa_base(void);

vmaddr_t
rm_get_hlos_dt_base(void);

cap_id_t
rm_get_uart_me(void);

platform_env_data_t *
rm_get_platform_env_data(void);

const vm_device_assignments_t *
rm_get_vm_device_assignments(void);
