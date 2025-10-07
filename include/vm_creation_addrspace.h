// © 2024 Qualcomm Innovation Center, Inc. All rights reserved.
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
// IDs for OWNER RM namespace
#define ADDRSPACE_INFO_AREA_RM_RMRPC (uint16_t)0

// VM's own address space capability
struct addrspace_info_area_rootvm_addrspace_cap_s {
	cap_id_t	       addrspace_cap;
	cap_rights_addrspace_t rights;
	uint32_t	       res0;
};

static_assert(sizeof(struct addrspace_info_area_rootvm_addrspace_cap_s) == 16U,
	      "struct size");

struct addrspace_info_area_rootvm_trace_info_s {
	cap_id_t trace_dbl_cap;
	cap_id_t trace_me_cap;
	uint64_t trace_size;
};

static_assert(sizeof(struct addrspace_info_area_rootvm_trace_info_s) == 24U,
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
