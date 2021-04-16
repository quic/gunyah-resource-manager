// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define NULL_ADDRESS	    (0UL)
#define INVALID_ADDRESS	    (~0UL)
#define ADDRESS_SPACE_LIMIT (1UL << 36)
#define ALIGNMENT_IGNORED   (0UL)

struct address_range_allocator;
typedef struct address_range_allocator address_range_allocator_t;

// Address range allocator can only support the range whose size is up to
// ADDRESS_SPACE_LIMIT.
address_range_allocator_t *
address_range_allocator_init(vmaddr_t base_address, size_t size);

typedef struct {
	vmaddr_t base_address;
	size_t	 size;
	error_t	 err;
	uint8_t	 err_padding[4];
} address_range_allocator_alloc_ret_t;

// Allocate an address range
// The start_address can be set as INVALID_ADDRESS, so allocator would choose
// any address which fits the size, and alignment. Or else, it will allocate the
// specified range (start_address++size) if it's possible.
// The alignment parameter must be a power of two.
address_range_allocator_alloc_ret_t
address_range_allocator_alloc(address_range_allocator_t *allocator,
			      vmaddr_t start_address, size_t size,
			      size_t alignment);

error_t
address_range_allocator_free(address_range_allocator_t *allocator,
			     vmaddr_t start_address, size_t size);

// TODO - add alloc_guarded and free_guarded

void
address_range_allocator_deinit(address_range_allocator_t *allocator);

#ifndef NDEBUG
void
address_range_allocator_dump(address_range_allocator_t *allocator);
#endif
