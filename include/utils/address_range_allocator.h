// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// A generic address range allocator that supports free range allocation and
// explicit tagged range allocations.
//
// Tagged regions must be allocated from explicitly, and will not be allocated
// from when requesting any free range.

#define ADDRESS_RANGE_LIMIT	   (1UL << 52)
#define ADDRESS_RANGE_NO_ALIGNMENT 0UL

struct address_range_allocator;
typedef struct address_range_allocator address_range_allocator_t;

typedef uint32_t address_range_tag_t;
#define ADDRESS_RANGE_NO_TAG (address_range_tag_t)0UL

typedef struct {
	uint64_t base_address;
	size_t	 size;
	// Tagged range tag information (for allocation within a tagged range)
	address_range_tag_t tag;

	error_t err;
} address_range_allocator_ret_t;

// Initialize an Address Range Allocator
//
// base_address and size must be PAGE_SIZE aligned.
// base_address + size may not exceed ADDRESS_RANGE_LIMIT.
address_range_allocator_t *
address_range_allocator_init(uint64_t base_address, size_t size);

// Allocate a range from the Address Range Allocator
//
// Either an explicit range or any free range may be requested.
// If base_address is INVALID_ADDRESS then any free range with sufficient size
// will be allocated, but NOT within a tagged range. Otherwise we allocate the
// specified range (base_address++size) if it's possible.
//
// When base_address is INVALID_ADDRESS, the alignment parameter requests an
// aligned base to be allocated, and alignment must be a power of two.
//
// A requested range may not partially overlap a tagged allocator range.
address_range_allocator_ret_t
address_range_allocator_alloc(address_range_allocator_t *allocator,
			      uint64_t base_address, size_t size,
			      size_t alignment);

// Tag a region of the Address Range Allocator
//
// base_address, size must specify an unallocated tagged range in the
// allocator.
//
// Once the region is tagged, it can only be allocated explicitly by requesting
// a range within it.
error_t
address_range_allocator_tag(address_range_allocator_t *allocator,
			    uint64_t base_address, size_t size,
			    address_range_tag_t tag);

// Tag a region of the Address Range Allocator
//
// Once the region is tagged, it can only be allocated explicitly by requesting
// a range within it.
//
// constrain_base, constrain_size: specify an optional constraint on the address
// range of the allocator to search for a free range. If constrain_base is set
// to INVALID_ADDRESS, the constrain_size is ignored, the full free range of the
// allocator may be used.
address_range_allocator_ret_t
address_range_allocator_tag_region(address_range_allocator_t *allocator,
				   uint64_t		      constrain_base,
				   size_t constrain_size, size_t size,
				   size_t alignment, address_range_tag_t tag);

// Return a range to the allocator.
error_t
address_range_allocator_free(address_range_allocator_t *allocator,
			     uint64_t base_address, size_t size);

// Return a tagged range to the allocator.
//
// The tagged range must be unallocated.
error_t
address_range_allocator_untag(address_range_allocator_t *allocator,
			      uint64_t base_address, size_t size,
			      address_range_tag_t tag);

// Destroy a range allocator.
void
address_range_allocator_deinit(address_range_allocator_t *allocator);

#ifndef NDEBUG
void
address_range_allocator_dump(address_range_allocator_t *allocator);
#endif
