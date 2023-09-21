// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define VM_IRQ_ACCEPT  0x56000050
#define VM_IRQ_LEND    0x56000051
#define VM_IRQ_RELEASE 0x56000052
#define VM_IRQ_RECLAIM 0x56000053
#define VM_IRQ_NOTIFY  0x56000054
#define VM_IRQ_UNMAP   0x56000055

#define NOTIFY_VM_IRQ_LENT     0x56100011
#define NOTIFY_VM_IRQ_RELEASED 0x56100012
#define NOTIFY_VM_IRQ_ACCEPTED 0x56100013

typedef uint16_t cpu_idx_t;
typedef uint32_t virq_handle_t; // remove
typedef uint32_t irq_handle_t;
typedef uint32_t label_t;
typedef uint32_t virq_notify_flag_t;
typedef uint32_t msg_id_t;

#define VIRQ_NOTIFY_FLAG_LENT	  1U
#define VIRQ_NOTIFY_FLAG_RELEASED 2U
#define VIRQ_NOTIFY_FLAG_ACCEPTED 4U

typedef struct {
	virq_handle_t handle;
	virq_t	      virq_num;
} rm_irq_accept_req_t;

typedef struct {
	virq_t virq_num;
} rm_irq_accept_reply_t;

typedef struct {
	vmid_t	borrower;
	char	_pad[2];
	virq_t	virq_num;
	label_t label;
} rm_irq_lend_req_t;

typedef struct {
	virq_handle_t handle;
} rm_irq_lend_reply_t;

typedef struct {
	virq_handle_t handle;
} rm_irq_release_req_t;

typedef struct {
	virq_handle_t handle;
} rm_irq_reclaim_req_t;

typedef struct {
	vmid_t vmid;
	char   _pad[2];
} rm_irq_notify_vmid_t;

typedef struct {
	virq_handle_t	   handle;
	virq_notify_flag_t flags;
} rm_irq_notify_req_t;

typedef struct {
	rm_irq_notify_req_t  req;
	uint16_t	     notify_vmid_entries;
	char		     _pad[2];
	rm_irq_notify_vmid_t notify_vmids[];
} rm_irq_notify_lent_req_t;

typedef struct {
	size_t virq_entry_cnt;
	virq_t virq_nums[];
} rm_irq_unmap_req_t;

typedef struct {
	vmid_t	      owner;
	char	      _pad[2];
	virq_handle_t virq_handle;
	label_t	      virq_label;
} rm_irq_lent_notify_t;

typedef struct {
	virq_handle_t virq_handle;
} rm_irq_owner_notify_t;
