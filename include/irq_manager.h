// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define VIRQ_LAST_VALID ((virq_t)1019U)

#define VIRQ_INVALID (~(virq_t)0U)

struct vm_irq_manager;
typedef struct vm_irq_manager vm_irq_manager_t;

rm_error_t
irq_manager_init(void);

vm_irq_manager_t *
irq_manager_create(cap_id_t vic, count_t num_hwirqs, const cap_id_t *hwirqs);

bool
irq_manager_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			void *buf, size_t len);

rm_error_t
irq_manager_static_share(vmid_t source_vmid, virq_t source_virq,
			 vmid_t dest_vmid, virq_t dest_virq);

rm_error_t
irq_manager_reserve_virq(vmid_t vmid, virq_t virq, bool is_virt);

typedef struct {
	rm_error_t err;

	virq_t virq;
} irq_manager_get_free_virt_virq_ret_t;

irq_manager_get_free_virt_virq_ret_t
irq_manager_get_free_virt_virq(vmid_t vmid);

error_t
irq_manager_return_virq(vmid_t vmid, virq_t virq);
