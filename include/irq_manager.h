// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

struct vm_irq_manager;
typedef struct vm_irq_manager vm_irq_manager_t;

static const virq_t VIRQ_NUM_INVALID = ~(virq_t)0U;
#define VIRQ_INVALID ((interrupt_data_t){ .irq = VIRQ_NUM_INVALID })

rm_error_t
irq_manager_init(void);

rm_error_t
irq_manager_deinit(void);

vm_irq_manager_t *
irq_manager_create(cap_id_t vic, count_t num_hwirqs, const cap_id_t *hwirqs);

bool
irq_manager_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			void *buf, size_t len);

rm_error_t
irq_manager_static_share(vmid_t source_vmid, virq_t source_virq,
			 vmid_t dest_vmid, virq_t dest_virq);

rm_error_t
irq_manager_reserve_virq(vmid_t vmid, interrupt_data_t virq, bool is_virt);

typedef struct {
	rm_error_t err;

	interrupt_data_t virq;
} irq_manager_get_free_virt_virq_ret_t;

irq_manager_get_free_virt_virq_ret_t
irq_manager_get_free_virt_virq(vmid_t vmid, bool cpu_local);

error_t
irq_manager_return_virq(vmid_t vmid, interrupt_data_t virq);

virq_t
irq_manager_virq_for_hypercall(interrupt_data_t virq);

virq_t
irq_manager_get_max_virq(void);

bool
vm_reset_handle_release_irqs(vmid_t vmid);
