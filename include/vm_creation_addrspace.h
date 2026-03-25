// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_VM_CREATION_ADDRSPACE_H_
#define INCLUDE_VM_CREATION_ADDRSPACE_H_

// Public API for VM address space info area
// -- DO NOT MODIFY --
//
// Any changes need to be co-ordinated and backwards compatible, either by
// appending items to increase the size of a struct, which a VM can detect, or
// by adding new IDs.

// IDs for OWNER ROOTVM namespace
#define ADDRSPACE_INFO_AREA_ROOTVM_ADDRSPACE_CAP (uint16_t)0
#define ADDRSPACE_INFO_AREA_ROOTVM_TRACE_INFO	 (uint16_t)1
#define ADDRSPACE_INFO_AREA_SYSTEM_POWER_CAP	 (uint16_t)2
// IDs for OWNER RM namespace
#define ADDRSPACE_INFO_AREA_RM_RMRPC (uint16_t)0

struct addrspace_info_area_interrupt_s {
	uint32_t type;
	uint32_t irq;
	uint32_t flags;
	uint32_t res0;
};

static_assert(sizeof(struct addrspace_info_area_interrupt_s) == 16U,
	      "struct size");

struct addrspace_info_area_doorbell_s {
	cap_id_t			       capid;
	struct addrspace_info_area_interrupt_s irq;
};

static_assert(sizeof(struct addrspace_info_area_doorbell_s) == 24U,
	      "struct size");

RM_PADDED(typedef struct addrspace_info_area_interrupt_result {
	struct addrspace_info_area_interrupt_s r;
	error_t alignas(register_t)	       e;
} addrspace_info_area_interrupt_result_t)

addrspace_info_area_interrupt_result_t
vm_creation_addrspace_info_area_interrupt(interrupt_data_t virq);

// VM's own address space capability
typedef struct addrspace_info_area_rootvm_addrspace_cap_s {
	cap_id_t	       addrspace_cap;
	cap_rights_addrspace_t rights;
	uint32_t	       res0;
} addrspace_info_area_rootvm_addrspace_cap_t;

static_assert(sizeof(struct addrspace_info_area_rootvm_addrspace_cap_s) == 16U,
	      "struct size");

struct addrspace_info_area_rootvm_trace_info_s {
	vmaddr_t			       trace_ipa;
	uint64_t			       trace_size;
	struct addrspace_info_area_interrupt_s trace_dbl_irq;
};

static_assert(sizeof(struct addrspace_info_area_rootvm_trace_info_s) == 32U,
	      "struct size");

struct addrspace_info_area_rootvm_system_power_cap_s {
	cap_id_t	   power_cap;
	cap_rights_power_t power_cap_rights;
	uint32_t	   res0;
};

static_assert(sizeof(struct addrspace_info_area_rootvm_system_power_cap_s) ==
		      16U,
	      "struct size");

// info data struct versions based on info_area entry type & size
struct addrspace_info_area_rm_rpc_info_s {
	cap_id_t tx_msgq_cap;
	cap_id_t rx_msgq_cap;
	virq_t	 tx_msgq_virq;
	virq_t	 rx_msgq_virq;
	count_t	 tx_msgq_queue_depth;
	count_t	 tx_msgq_max_msg_size;
	count_t	 rx_msgq_queue_depth;
	count_t	 rx_msgq_max_msg_size;
};

static_assert(sizeof(struct addrspace_info_area_rm_rpc_info_s) == 40U,
	      "struct size");

#else

#error multiple include of vm_creation_addrspace.h

#endif
