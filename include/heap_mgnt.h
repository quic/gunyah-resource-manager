// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_HEAP_MGNT_H_
#define INCLUDE_HEAP_MGNT_H_

#define HEAP_CREATE	   0x51000030U
#define HEAP_DELETE	   0x51000031U
#define HEAP_ADD_MEMORY	   0x51000032U
#define HEAP_REMOVE_MEMORY 0x51000033U
#define HEAP_QUERY	   0x51000034U

#define HEAP_QUERY_TYPE_IS_FREE 0x1U
#define HEAP_QUERY_TYPE_STATS	0x2U

typedef struct {
	uint32_t heap_handle;
	uint8_t	 res0[4];
	uint32_t mp_handle;
} heap_memory_req_t;

typedef struct {
	uint32_t heap_handle;
	uint8_t	 type;
	uint8_t	 res0[3];
} heap_query_req_t;

typedef struct {
	uint32_t total_low;
	uint32_t total_high;
	uint32_t allocated_low;
	uint32_t allocated_high;
	uint32_t reserved_low;
	uint32_t reserved_high;
	uint32_t largest_free_low;
	uint32_t largest_free_high;
} heap_stats_resp_t;

bool
heap_mgnt_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
		      void *buf, size_t len);

rm_error_t
heap_mgnt_get_resource_descs(vmid_t self, vmid_t vmid, vector_t *descs);

typedef struct {
	error_t	 err;
	uint8_t	 pad_to_me_cap[4];
	cap_id_t me_cap;
	size_t	 offset;
	paddr_t	 phys;
} heap_lookup_me_ret_t;

// Find the memextent cap associated with a RM heap address.
heap_lookup_me_ret_t
heap_mgnt_lookup_rm_me(uintptr_t addr);

#else

#error multiple include of heap_mgnt.h

#endif
