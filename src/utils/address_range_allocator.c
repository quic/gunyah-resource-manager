// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Implements a simple range-list-based address space allocator.

#include <guest_types.h>

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <util.h>
#include <utils/address_range_allocator.h>
#include <utils/list.h>

typedef struct range {
	struct range *range_prev;
	struct range *range_next;

	vmaddr_t base_address;
	size_t	 size;
} range_t;

struct address_range_allocator {
	range_t *range_list;

#ifndef NDEBUG
	// memory footprint measurement, can be done by memory allocator
	size_t range_node_cnt;
#endif

	vmaddr_t start_address;
	size_t	 size;
};

static range_t *
find_range(address_range_allocator_t *allocator, vmaddr_t start_address,
	   size_t size, size_t alignment);

typedef struct {
	range_t *left;
	range_t *right;
} find_neighbor_range_ret_t;

static find_neighbor_range_ret_t
find_neighbor_range(address_range_allocator_t *allocator, vmaddr_t address);

address_range_allocator_t *
address_range_allocator_init(vmaddr_t base_address, size_t size)
{
	if (util_add_overflows(base_address, size)) {
		goto err;
	}

	if (!util_is_baligned(base_address, PAGE_SIZE) ||
	    !util_is_baligned(size, PAGE_SIZE)) {
		goto err;
	}

	if ((base_address + size) > ADDRESS_SPACE_LIMIT) {
		goto err;
	}

	address_range_allocator_t *allocator = calloc(1, sizeof(*allocator));
	if (allocator == NULL) {
		goto err;
	}

	range_t *root_range = calloc(1, sizeof(*root_range));
	if (root_range == NULL) {
		goto err1;
	}

	root_range->base_address = base_address;
	root_range->size	 = size;

	list_append(range_t, &allocator->range_list, root_range, range_);
#ifndef NDEBUG
	allocator->range_node_cnt++;
#endif

	allocator->start_address = base_address;
	allocator->size		 = size;

	return allocator;
err1:
	free(allocator);
err:
	return NULL;
}

address_range_allocator_alloc_ret_t
address_range_allocator_alloc(address_range_allocator_t *allocator,
			      vmaddr_t start_address, size_t size,
			      size_t alignment)
{
	assert(allocator != NULL);

	address_range_allocator_alloc_ret_t ret = {
		.err = OK,
	};

	if ((start_address != INVALID_ADDRESS) &&
	    !util_is_baligned(start_address, PAGE_SIZE)) {
		ret.err = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (!util_is_baligned(size, PAGE_SIZE)) {
		ret.err = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	// ignore alignment if specified start_address
	if ((start_address != INVALID_ADDRESS) &&
	    (util_add_overflows(start_address, size) ||
	     (start_address < allocator->start_address) ||
	     ((start_address + size) >
	      (allocator->start_address + allocator->size)))) {
		ret.err = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	range_t *parent_range = NULL;

	// find the first fit node it start_address is NULL, set
	// start_address find the node contains start_address, if
	// doesn't fit size, return error
	parent_range = find_range(allocator, start_address, size, alignment);
	if (parent_range == NULL) {
		ret.err = ERROR_ALLOCATOR_MEM_INUSE;
		goto out;
	}

	vmaddr_t alloc_address;
	if (start_address == INVALID_ADDRESS) {
		alloc_address =
			util_balign_up(parent_range->base_address, alignment);
	} else {
		alloc_address = start_address;
	}

	assert(!util_add_overflows(alloc_address, size));

	size_t head_remaining_size = alloc_address - parent_range->base_address;
	size_t tail_remaining_size =
		parent_range->size - size - head_remaining_size;
	// it's more obvious than check relation of address and size
	if ((head_remaining_size == 0UL) && (tail_remaining_size == 0UL)) {
		// use all parent range
		list_remove(range_t, &allocator->range_list, parent_range,
			    range_);
		free(parent_range);
#ifndef NDEBUG
		allocator->range_node_cnt--;
#endif
	} else if (head_remaining_size == 0UL) {
		// took the head of parent range
		parent_range->base_address = alloc_address + size;
		parent_range->size -= size;
	} else if (tail_remaining_size == 0UL) {
		// took the tail of parent range
		parent_range->size -= size;
	} else {
		// if start address in the mid, allocate additional
		// node, insert, modify current node, maintain order
		range_t *tail_range = calloc(1, sizeof(*tail_range));
		if (tail_range == NULL) {
			ret.err = ERROR_NOMEM;
			goto out;
		}

		parent_range->size = head_remaining_size;

		tail_range->base_address = alloc_address + size;
		tail_range->size	 = tail_remaining_size;

		// append tailing part to parent range
		list_insert_after(range_t, &allocator->range_list, parent_range,
				  tail_range, range_);

#ifndef NDEBUG
		allocator->range_node_cnt++;
#endif
	}

	ret.base_address = alloc_address;
	ret.size	 = size;

out:
	return ret;
}

error_t
address_range_allocator_free(address_range_allocator_t *allocator,
			     vmaddr_t start_address, size_t size)
{
	error_t ret = OK;

	if ((start_address == INVALID_ADDRESS) ||
	    !util_is_baligned(start_address, PAGE_SIZE)) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (!util_is_baligned(size, PAGE_SIZE)) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if ((util_add_overflows(start_address, size) ||
	     (start_address < allocator->start_address) ||
	     ((start_address + size) >
	      (allocator->start_address + allocator->size)))) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	// find the node which is start_address left neighbor
	find_neighbor_range_ret_t neighbor_ret =
		find_neighbor_range(allocator, start_address);

	// the allocated range should be outside of neighbors
	range_t *left  = neighbor_ret.left;
	range_t *right = neighbor_ret.right;
	if ((left == NULL) && (right == NULL)) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	// check if can merge to left
	bool merge_left = false;
	if (left != NULL) {
		assert(start_address > left->base_address - 1 + left->size);

		assert(!util_add_overflows(left->base_address, left->size));

		merge_left =
			((left->base_address + left->size) == start_address);
	}

	// check if can merge to right
	bool merge_right = false;
	if (right != NULL) {
		// printf("start address %lx, size %lx\n", start_address, size);
		assert(start_address - 1 + size < right->base_address);

		// shouldn't have overflow
		assert(!util_add_overflows(start_address, size));
		merge_right = ((start_address + size) == right->base_address);
	}

	if (merge_left && merge_right) {
		// if merge to both neighbors, delete right neighbor and merge
		// into the left
		assert(!util_add_overflows(left->size, size));
		left->size += size;

		assert(!util_add_overflows(left->size, right->size));
		left->size += right->size;

		list_remove(range_t, &allocator->range_list, right, range_);
		free(right);
#ifndef NDEBUG
		allocator->range_node_cnt--;
#endif
	} else if (merge_left) {
		// if just merge to left, update left neighbor
		assert(!util_add_overflows(left->size, size));
		left->size += size;
	} else if (merge_right) {
		// if just merge to right, just update right neighbor
		right->base_address = start_address;
		assert(!util_add_overflows(right->size, size));
		right->size += size;
	} else {
		// create a new node in the unallocated range
		range_t *new_range = calloc(1, sizeof(*new_range));
		if (new_range == NULL) {
			ret = ERROR_NOMEM;
			goto out;
		}

		new_range->base_address = start_address;
		new_range->size		= size;

		if (left != NULL) {
			list_insert_after(range_t, &allocator->range_list, left,
					  new_range, range_);
		} else {
			list_insert_head(range_t, &allocator->range_list,
					 new_range, range_);
		}
#ifndef NDEBUG
		allocator->range_node_cnt++;
#endif
	}

out:
	return ret;
}

void
address_range_allocator_deinit(address_range_allocator_t *allocator)
{
	range_t *cur, *next;
	loop_list_safe(cur, next, &allocator->range_list, range_)
	{
		free(cur);
#ifndef NDEBUG
		allocator->range_node_cnt--;
#endif
	}

#ifndef NDEBUG
	assert(allocator->range_node_cnt == 0UL);
#endif

	free(allocator);
}

range_t *
find_range(address_range_allocator_t *allocator, vmaddr_t start_address,
	   size_t size, size_t alignment)
{
	range_t *cur = NULL, *ret = NULL;

	// FIXME: might be able to find the just fit free range to avoid
	// fragment
	loop_list(cur, &allocator->range_list, range_)
	{
		if (start_address == INVALID_ADDRESS) {
			size_t remaining_size =
				cur->size -
				(util_balign_up(cur->base_address, alignment) -
				 cur->base_address);
			if (size <= remaining_size) {
				ret = cur;
				break;
			}
		} else {
			assert(!util_add_overflows(start_address, size));

			if ((cur->base_address <= start_address) &&
			    ((cur->base_address + cur->size) >=
			     (start_address + size))) {
				ret = cur;
				break;
			} else if (cur->base_address > start_address) {
				// assume it's ascending order, return early
				break;
			}
		}
	}

	return ret;
}

find_neighbor_range_ret_t
find_neighbor_range(address_range_allocator_t *allocator, vmaddr_t address)
{
	find_neighbor_range_ret_t ret = { .left = NULL, .right = NULL };

	range_t *cur = NULL, *next = NULL;

	// assert address is in initial range
	assert(address >= allocator->start_address);
	assert(address <= (allocator->start_address + allocator->size - 1));

	loop_list_safe(cur, next, &allocator->range_list, range_)
	{
		if (is_first(cur, &allocator->range_list, range_) &&
		    (address < cur->base_address)) {
			ret.left  = NULL;
			ret.right = cur;
			break;
		} else if (is_last(cur, range_) &&
			   (address >= (cur->base_address + cur->size))) {
			ret.left  = cur;
			ret.right = NULL;
			break;
		} else if ((address >= (cur->base_address + cur->size)) &&
			   (next != NULL) && (address < next->base_address)) {
			ret.left  = cur;
			ret.right = next;
			break;
		}
	}

	return ret;
}

#ifndef NDEBUG
void
address_range_allocator_dump(address_range_allocator_t *allocator)
{
	printf("range dump for [0x%lx, 0x%lx):\n", allocator->start_address,
	       allocator->start_address + allocator->size);

	range_t *cur;

	loop_list(cur, &allocator->range_list, range_)
	{
		printf("[0x%lx, 0x%lx), ", cur->base_address,
		       cur->base_address + cur->size);
	}
	printf("\n");
}
#endif
