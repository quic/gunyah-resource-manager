// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef ARCH_ARMv8_FFA_H_
#define ARCH_ARMv8_FFA_H_

#define RM_FFA_VERSION 0x00010002

#define FFA_TZ_PARTITION_ID 0x8001

#define FFA_RET_SUCCESS	      0x00000000
#define FFA_RET_NOT_SUPPORTED 0xFFFFFFFF

#define FFA_INVALID_HANDLE 0xFFFFFFFFFFFFFFFF

#define FFA_FUNCTION_FFA_ERROR	    0x84000060
#define FFA_FUNCTION_FFA_SUCCESS    0x84000061
#define FFA_FUNCTION_FFA_VERSION    0x84000063
#define FFA_FUNCTION_FFA_FEATURES   0x84000064
#define FFA_FUNCTION_FFA_RXTX_MAP   0x84000066
#define FFA_FUNCTION_FFA_RXTX_UNMAP 0x84000067
#define FFA_FUNCTION_FFA_ID_GET	    0x84000069
#define FFA_FUNCTION_FFA_MEM_SHARE  0x84000073
#define FFA_FUNCTION_MEM_RECLAIM    0x84000077

#define FFA_RXTX_NUM_PAGES 1U

rm_error_t
ffa_init(void);

void
ffa_mem_reclaim(uint64_t handle);

uint64_t
ffa_mem_share(void *addr, size_t size);

#else

#error arch/armv8/include/ffa/ffa.h multiple include

#endif
