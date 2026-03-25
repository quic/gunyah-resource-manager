// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#define MEM_MAGIC 0x4DU

#define IOCTL_ADD_HEAP	     _IOW(MEM_MAGIC, 0U, mem_range_t)
#define IOCTL_REMOVE_HEAP    _IOW(MEM_MAGIC, 1U, mem_range_t)
#define IOCTL_HEAP_IS_FREE   _IOW(MEM_MAGIC, 2U, mem_range_t)
#define IOCTL_HEAP_GET_STATS _IOR(MEM_MAGIC, 3U, allocator_stats_t)

struct mem_range {
	uintptr_t base;
	size_t	  size;
};

typedef struct mem_range mem_range_t;
