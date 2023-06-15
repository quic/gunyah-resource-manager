// © 2022 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define INVALID_DATA (0UL)

struct range_s;
typedef struct range_s range_t;

struct range_list_s;
typedef struct range_list_s range_list_t;

typedef struct {
	uint64_t base_address;
	size_t	 size;

	error_t err;
	uint8_t err_padding[4];
} range_list_remove_ret_t;

uint64_t
range_list_get_base_address(range_list_t *list);

size_t
range_list_get_size(range_list_t *list);

uintptr_t
range_list_get_range_data(range_t *range);

bool
range_list_is_empty(range_list_t *list);

// Init range list
//
// Specify [base_address, base_address + size) range to manage. as_empty
// indicates that the list is initialized as empty, no range can be removed
// from this list initially.
//
// Returns a list or NULL if failed.
range_list_t *
range_list_init(uint64_t base_address, size_t size, bool as_empty);

// Remove a range from range list
//
// Remove [base_address, base_address + size) from the list.
// base_address can be as INVALID_ADDRESS, range list will choose a range by
// size/alignment to remove.
// Only range with the same data can be removed.
//
// Returns the removed range as [base_address, base_address + size) if
// success, or err when failed.
range_list_remove_ret_t
range_list_remove(range_list_t *list, uint64_t base_address, size_t size,
		  size_t alignment, uintptr_t data);

// Add a range into range list
//
// Add [base_address, base_address + size) to the list. The added range
// is marked with data.
//
// Returns error if there's any, or OK when success.
error_t
range_list_insert(range_list_t *list, uint64_t base_address, size_t size,
		  uintptr_t data);

// Update a range with data
//
// Update data for the range [base_address, base_address + size) in
// selected_range. The specified range must inside the selected_range.
//
// Returns error if there's any, or OK when success.
error_t
range_list_update(range_list_t *list, uint64_t base_address, size_t size,
		  range_t *selected_range, uintptr_t data);

// Destroy the range list
//
// It will free all internal resource allocated.
void
range_list_deinit(range_list_t *list);

typedef struct {
	vmaddr_t base_address;
	range_t *selected_range;

	error_t err;
	uint8_t err_padding[4];
} range_list_find_ret_t;

// Find a proper range under region/alignment/data constrains.
//
// [region_base, region_base + region_size)/alignment constrains the base
// address. With range_size, it can return a proper range which has the
// same data.
//
// Returns the based address of the range, and the range node contains such
// range. Or err if failed.
range_list_find_ret_t
range_list_find_range_by_region(range_list_t *allocator, uint64_t region_base,
				size_t region_size, size_t range_size,
				size_t alignment, uintptr_t data);

// Find range which is not assigned with any data.
//
// [base_address, base_address + size)/alignment specify the range
// it would like. base_address can be INVALID_ADDRESS, then it can select
// the range based on size/alignment.
//
// Returns the based address of the range, and the range node contains such
// range. Or err if failed.
range_list_find_ret_t
range_list_find_range(range_list_t *allocator, uint64_t base_address,
		      size_t size, size_t alignment);

// Check if there're ranges in the list which has the data.
//
// Returns true if there's.
bool
range_list_has_data(range_list_t *list, uintptr_t data);

#ifndef NDEBUG
void
range_list_dump(range_list_t *list, const char *prefix);
#endif
