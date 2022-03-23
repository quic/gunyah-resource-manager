// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define VMID_HYP  0x0U
#define VMID_HLOS 0x3U
#define VMID_RM	  0xFFU

#define VMID_PEER_DEFAULT 0xFFFFU

typedef enum {
	VM_ID_TYPE_GUID	     = 0,
	VM_ID_TYPE_URI	     = 1,
	VM_ID_TYPE_NAME	     = 2,
	VM_ID_TYPE_SIGN_AUTH = 3,
} vm_id_type_t;

cap_id_t
rm_get_rm_addrspace(void);

cap_id_t
rm_get_rm_cspace(void);

cap_id_t
rm_get_rm_partition(void);

cap_id_t
rm_get_rm_vic(void);

cap_id_t
rm_get_device_me(void);

cap_id_t
rm_get_me(void);

vmaddr_t
rm_get_hlos_entry(void);

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

paddr_t
rm_ipa_to_pa(uintptr_t ipa);

#if defined(QEMU) && QEMU
vmaddr_t
rm_get_hlos_dt_base(void);

cap_id_t
rm_get_uart_me(void);

vmaddr_t
rm_get_device_me_base(void);
#endif
