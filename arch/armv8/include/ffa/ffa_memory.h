// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef ARCH_ARMv8_FFA_MEMORY_H_
#define ARCH_ARMv8_FFA_MEMORY_H_

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

/*
 * This structure is used to describe the memory access permission descriptor.
 */
typedef struct {
	// 15:0	receiver
	uint16_t receiver;
	// 23:20 unknown
	// 19:18 instr_access
	// 17:16 data_access
	uint8_t acc;
	// 31:24 flags
	uint8_t flags;
} ffa_memory_access_permission_desc_t;

/*
 * This structure is used to describe the memory transcation descriptor.
 */
typedef struct {
	uint16_t sender;
	uint16_t attributes;
	uint32_t flags;
	uint64_t handle;
	uint64_t tag;
	// Size of each endpoint memory access descriptor in the array.
	uint32_t mad_size;
	// Count of endpoint memory access descriptors.
	uint32_t mad_count;
	// Offset from the base address of this descriptor to the
	// first element of the endpoint memory access descriptor array.
	uint32_t mad_array_offset;
	uint32_t reserved[3];
} ffa_memory_transaction_desc_t;

/*
 * This structure is used to describe the memory access descriptor.
 */
typedef struct {
	ffa_memory_access_permission_desc_t permission;
	uint32_t			    composite_mrd_offset;
	uint64_t			    impl_def[2];
	uint64_t			    reserved;
} ffa_memory_access_desc_t;

/*
 * This structure is used to describe the composite memory region descriptor.
 */
typedef struct {
	uint32_t total_page_count;
	uint32_t range_count;
	uint64_t reserved;
} ffa_composite_memory_region_desc_t;

/*
 * This structure is used to describe the comstituent memory region descriptor.
 */
typedef struct {
	uint64_t base_address;
	uint32_t page_count;
	uint32_t reserved;
} ffa_constituent_memory_region_desc_t;

static_assert(sizeof(ffa_memory_transaction_desc_t) == 48U,
	      "FF-A memory transaction descriptor size is not 48 bytes");

static_assert(sizeof(ffa_memory_access_desc_t) == 32U,
	      "FF-A memory access descriptor size is not 32 bytes");

static_assert(sizeof(ffa_composite_memory_region_desc_t) == 16U,
	      "FF-A composite memory region descriptor size is not 16 bytes");

static_assert(sizeof(ffa_constituent_memory_region_desc_t) == 16U,
	      "FF-A constituent memory region descriptor size is not 16 bytes");
#else
#error arch/armv8/include/ffa/ffa_memory.h multiple include
#endif
