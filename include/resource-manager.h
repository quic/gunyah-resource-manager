// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

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

vmaddr_t
rm_get_device_me_base(void);

vmaddr_t
rm_get_hlos_entry(void);

vmaddr_t
rm_get_hlos_dt_base(void);

cap_id_t
rm_get_restricted_hwirq(virq_t irq, vmid_t vmid);
