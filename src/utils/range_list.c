// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Implements a simple range-list-based address space list.

#include <guest_types.h>

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rm_types.h>
#include <util.h>
#include <utils/list.h>
#include <utils/range_list.h>

#include <resource-manager.h>
#include <rm-rpc.h>

struct range_s {
	struct range_s *range_prev;
	struct range_s *range_next;

	uint64_t base_address;
	size_t	 size;

	uintptr_t data;
};

struct range_list_s {
	range_t *range_list;

#ifndef NDEBUG
	// memory footprint measurement, can be done by memory list
	size_t range_node_cnt;
#endif

	uint64_t base_address;
	size_t	 size;
};

static void
find_neighbor_ranges(range_list_t *list, uint64_t address, range_t **left,
		     range_t **right);

static error_t
insert_range(range_list_t *list, range_t *left, range_t *new_range,
	     range_t *right);
static error_t
remove_range(range_list_t *list, range_t *from, uint64_t address, size_t size,
	     range_t **out_left, range_t **out_right);

uint64_t
range_list_get_base_address(range_list_t *list)
{
	assert(list != NULL);
	return list->base_address;
}

size_t
range_list_get_size(range_list_t *list)
{
	assert(list != NULL);
	return list->size;
}

bool
range_list_is_empty(range_list_t *list)
{
	assert(list != NULL);
	return is_empty(list->range_list);
}

static void
insert_after_left_node(range_list_t *list, range_t *left, range_t *insert_range)
{
	if (left != NULL) {
		list_insert_after(range_t, &list->range_list, left,
				  insert_range, range_);
	} else {
		list_insert_head(range_t, &list->range_list, insert_range,
				 range_);
	}

#ifndef NDEBUG
	list->range_node_cnt++;
#endif
}

range_list_t *
range_list_init(uint64_t base_address, size_t size, bool as_empty)
{
	range_list_t *list = NULL;

	if (util_add_overflows(base_address, size)) {
		goto out;
	}

	if (!util_is_baligned(base_address, PAGE_SIZE) ||
	    !util_is_baligned(size, PAGE_SIZE)) {
		goto out;
	}

	list = calloc(1, sizeof(*list));
	if (list == NULL) {
		goto out;
	}

	if (!as_empty) {
		range_t *root_range = calloc(1, sizeof(*root_range));
		if (root_range == NULL) {
			goto err_root_range_alloc;
		}

		root_range->base_address = base_address;
		root_range->size	 = size;

		list_append(range_t, &list->range_list, root_range, range_);
#ifndef NDEBUG
		list->range_node_cnt++;
#endif
	}

	list->base_address = base_address;
	list->size	   = size;

	goto out;

err_root_range_alloc:
	free(list);
	list = NULL;
out:
	return list;
}

static error_t
remove_range(range_list_t *list, range_t *from, uint64_t address, size_t size,
	     range_t **out_left, range_t **out_right)
{
	error_t ret = OK;

	range_t *left  = from;
	range_t *right = from->range_next;

	assert(!util_add_overflows(address, size));

	size_t head_remaining_size = address - from->base_address;
	size_t tail_remaining_size = from->size - size - head_remaining_size;
	// it's more obvious than check relation of address and size
	if ((head_remaining_size == 0UL) && (tail_remaining_size == 0UL)) {
		left = list_prev(from, list->range_list, range_);

		// use all parent range
		list_remove(range_t, &list->range_list, from, range_);
		free(from);
#ifndef NDEBUG
		list->range_node_cnt--;
#endif
	} else if (head_remaining_size == 0UL) {
		left = list_prev(from, list->range_list, range_);

		// took the head of parent range
		from->base_address = address + size;
		from->size -= size;

		right = from;
	} else if (tail_remaining_size == 0UL) {
		left = from;
		// took the tail of parent range
		from->size -= size;

		right = from->range_next;
	} else {
		left = from;

		// if base address in the mid, allocate additional
		// node, insert, modify current node, maintain order
		range_t *tail_range = calloc(1, sizeof(*tail_range));
		if (tail_range == NULL) {
			ret = ERROR_NOMEM;
			goto out;
		}

		from->size = head_remaining_size;

		tail_range->base_address = address + size;
		tail_range->size	 = tail_remaining_size;
		tail_range->data	 = from->data;

		// append tailing part to parent range
		list_insert_after(range_t, &list->range_list, from, tail_range,
				  range_);

		right = tail_range;

#ifndef NDEBUG
		list->range_node_cnt++;
#endif
	}

out:
	if (out_left != NULL) {
		*out_left = left;
	}

	if (out_right != NULL) {
		*out_right = right;
	}

	return ret;
}

range_list_remove_ret_t
range_list_remove(range_list_t *list, uint64_t base_address, size_t size,
		  size_t alignment, uintptr_t data)
{
	assert(list != NULL);

	range_list_remove_ret_t ret = {
		.err	      = OK,
		.base_address = 0UL,
		.size	      = 0UL,
	};

	if ((base_address != INVALID_ADDRESS) &&
	    !util_is_baligned(base_address, PAGE_SIZE)) {
		ret.err = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (!util_is_baligned(size, PAGE_SIZE)) {
		ret.err = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	// ignore alignment if specified base address
	if ((base_address != INVALID_ADDRESS) &&
	    (util_add_overflows(base_address, size) ||
	     (base_address < list->base_address) ||
	     ((base_address + size) > (list->base_address + list->size)))) {
		ret.err = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	// find the first fit node in master list if base address is
	// INVALID_ADDRESS, only with the specified base address, we can
	// allocate in sub level
	range_list_find_ret_t find_range_ret =
		range_list_find_range(list, base_address, size, alignment);
	if (find_range_ret.err != OK) {
		ret.err = find_range_ret.err;
		goto out;
	}

	if (find_range_ret.selected_range->data != data) {
		ret.err = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	range_t *selected_range = find_range_ret.selected_range;

	// the remove of tagged range might effect the data, need to use update
	// to clear the data first for this region first, and make sure this
	// operation will not effect data
	assert(selected_range->data == INVALID_DATA);

	// now try to remove it
	ret.err = remove_range(list, selected_range,
			       find_range_ret.base_address, size, NULL, NULL);

	ret.err		 = OK;
	ret.base_address = find_range_ret.base_address;
	ret.size	 = size;
out:
	return ret;
}

static void
can_merge(range_t *left, range_t *cur_range, uintptr_t range_data,
	  range_t *right, bool *out_merge_left, bool *out_merge_right)
{
	assert(cur_range != NULL);

	if (left != NULL) {
		assert(cur_range->base_address >
		       left->base_address - 1 + left->size);

		assert(!util_add_overflows(left->base_address, left->size));

		*out_merge_left = ((left->base_address + left->size) ==
				   cur_range->base_address) &&
				  (left->data == range_data);
	} else {
		*out_merge_left = false;
	}

	// check if can merge to right
	if (right != NULL) {
		assert(cur_range->base_address - 1 + cur_range->size <
		       right->base_address);

		// shouldn't have overflow
		assert(!util_add_overflows(cur_range->base_address,
					   cur_range->size));

		*out_merge_right = ((cur_range->base_address +
				     cur_range->size) == right->base_address) &&
				   (right->data == range_data);
	} else {
		*out_merge_right = false;
	}
}

static error_t
insert_range(range_list_t *list, range_t *left, range_t *new_range,
	     range_t *right)
{
	error_t ret = OK;

	uint64_t address = new_range->base_address;
	size_t	 size	 = new_range->size;

	// check if can merge to left
	bool merge_left	 = false;
	bool merge_right = false;
	can_merge(left, new_range, new_range->data, right, &merge_left,
		  &merge_right);

	if (merge_left && merge_right) {
		// if merge to both neighbors, delete right neighbor and merge
		// into the left
		assert(!util_add_overflows(left->size, size));
		left->size += size;

		assert(!util_add_overflows(left->size, right->size));
		left->size += right->size;

		list_remove(range_t, &list->range_list, right, range_);
		free(right);
#ifndef NDEBUG
		list->range_node_cnt--;
#endif
	} else if (merge_left) {
		// if just merge to left, update left neighbor
		assert(!util_add_overflows(left->size, size));
		left->size += size;
	} else if (merge_right) {
		// if just merge to right, just update right neighbor
		right->base_address = address;
		assert(!util_add_overflows(right->size, size));
		right->size += size;
	} else {
		range_t *insert_range = calloc(1, sizeof(*new_range));
		if (insert_range == NULL) {
			ret = ERROR_NOMEM;
			goto out;
		}

		*insert_range = *new_range;

		insert_after_left_node(list, left, insert_range);
	}

out:
	return ret;
}

error_t
range_list_insert(range_list_t *list, uint64_t base_address, size_t size,
		  uintptr_t data)
{
	error_t ret = OK;

	if ((base_address == INVALID_ADDRESS) ||
	    !util_is_baligned(base_address, PAGE_SIZE)) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (!util_is_baligned(size, PAGE_SIZE)) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if ((util_add_overflows(base_address, size) ||
	     (base_address < list->base_address) ||
	     ((base_address + size) > (list->base_address + list->size)))) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	// find the node which is base address left neighbor
	range_t *left = NULL, *right = NULL;
	find_neighbor_ranges(list, base_address, &left, &right);

	// create a new node in the unallocated range
	range_t new_range = { .base_address = base_address,
			      .size	    = size,
			      .data	    = data };

	ret = insert_range(list, left, &new_range, right);
out:
	return ret;
}

void
range_list_deinit(range_list_t *list)
{
	if (list == NULL) {
		goto out;
	}

	range_t *cur, *next;
	loop_list_safe(cur, next, &list->range_list, range_)
	{
		free(cur);
#ifndef NDEBUG
		list->range_node_cnt--;
#endif
	}

#ifndef NDEBUG
	assert(list->range_node_cnt == 0UL);
#endif

	free(list);

out:
	return;
}

range_list_find_ret_t
range_list_find_range_by_region(range_list_t *list, uint64_t region_base,
				size_t region_size, size_t range_size,
				size_t alignment, uintptr_t data)
{
	range_list_find_ret_t ret = {
		.err = ERROR_NORESOURCES,
	};

	if (!util_is_baligned(region_base, PAGE_SIZE) ||
	    !util_is_baligned(region_size, PAGE_SIZE) ||
	    !util_is_baligned(alignment, PAGE_SIZE) ||
	    !util_is_baligned(range_size, PAGE_SIZE)) {
		ret.err = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	range_t *cur = NULL;

	loop_list(cur, &list->range_list, range_)
	{
		if (data != cur->data) {
			continue;
		}

		// if the current free region doesn't overlaps with the address
		// region
		if ((cur->base_address + cur->size <= region_base) ||
		    ((region_base + region_size) <= cur->base_address)) {
			continue;
		}

		uint64_t intersection_start_address =
			util_max(cur->base_address, region_base);
		uint64_t intersection_end_address =
			util_min(cur->base_address + (cur->size - 1),
				 region_base + (region_size - 1));

		uint64_t base_address =
			util_balign_up(intersection_start_address, alignment);

		if (intersection_end_address < base_address) {
			continue;
		}

		size_t remaining_size =
			cur->base_address + (cur->size - 1) >= base_address
				? cur->base_address + (cur->size - 1) -
					  base_address + 1
				: 0;

		if (remaining_size >= range_size) {
			ret.err		 = OK;
			ret.base_address = base_address;

			ret.selected_range = cur;
			break;
		}
	}

out:
	return ret;
}

range_list_find_ret_t
range_list_find_range(range_list_t *allocator, uint64_t base_address,
		      size_t size, size_t alignment)
{
	range_list_find_ret_t ret = {
		.err = ERROR_NORESOURCES,
	};

	if ((base_address != INVALID_ADDRESS) &&
	    !util_is_baligned(base_address, alignment)) {
		ret.err = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	range_t *cur = NULL;

	// FIXME: might be able to find the just fit free range to avoid
	// fragment
	loop_list(cur, &allocator->range_list, range_)
	{
		if (base_address == INVALID_ADDRESS) {
			uint64_t ret_address =
				util_balign_up(cur->base_address, alignment);
			size_t remaining_size =
				cur->size >= (ret_address - cur->base_address)
					? cur->size - (ret_address -
						       cur->base_address)
					: 0UL;
			if (size <= remaining_size) {
				ret.err		   = OK;
				ret.base_address   = ret_address;
				ret.selected_range = cur;
				break;
			}
		} else {
			assert(!util_add_overflows(base_address, size));

			if ((cur->base_address <= base_address) &&
			    ((cur->base_address + cur->size) >=
			     (base_address + size))) {
				ret.err		   = OK;
				ret.base_address   = base_address;
				ret.selected_range = cur;
				break;
			} else if (cur->base_address > base_address) {
				// assume it's ascending order, return early
				break;
			} else {
				// does not cover the range
			}
		}
	}
out:
	return ret;
}

static void
find_neighbor_ranges(range_list_t *list, uint64_t address, range_t **left,
		     range_t **right)
{
	assert(left != NULL);
	assert(right != NULL);

	range_t *cur = NULL, *next = NULL;

	// assert address is in initial range
	assert(address >= list->base_address);
	assert(address <= (list->base_address + list->size - 1));

	loop_list_safe(cur, next, &list->range_list, range_)
	{
		if (is_first(cur, list->range_list, range_) &&
		    (address < cur->base_address)) {
			*left  = NULL;
			*right = cur;
			break;
		} else if (is_last(cur, range_) &&
			   (address >= (cur->base_address + cur->size))) {
			*left  = cur;
			*right = NULL;
			break;
		} else if ((next != NULL) && (address < next->base_address)) {
			// since the ranges are maintained in order
			*left  = cur;
			*right = next;
			break;
		} else {
			// new range needed
		}
	}

	return;
}

error_t
range_list_update(range_list_t *list, uint64_t base_address, size_t size,
		  range_t *selected_range, uintptr_t data)
{
	error_t ret = OK;

	assert(base_address != INVALID_ADDRESS);
	assert(size != 0UL);
	assert(selected_range != NULL);
	assert(!util_add_overflows(base_address, size - 1));

	if (selected_range->data == data) {
		ret = OK;
		goto out;
	}

	// make sure selected range covers the whole range requested to update
	if (((selected_range->base_address != 0) &&
	     (base_address + (size - 1) < (selected_range->base_address - 1))) ||
	    (base_address >
	     (selected_range->base_address + (selected_range->size - 1)))) {
		ret = ERROR_NORESOURCES;
		goto out;
	}

	range_t *range_left =
		list_prev(selected_range, list->range_list, range_);
	range_t *range_right = selected_range->range_next;

	bool merge_left	 = false;
	bool merge_right = false;
	can_merge(range_left, selected_range, data, range_right, &merge_left,
		  &merge_right);

	// fast path only applies to change the current range and will not merge
	// to neighours
	if ((selected_range->base_address == base_address) &&
	    (selected_range->size == size) && !merge_right && !merge_left) {
		selected_range->data = data;

		ret = OK;
		goto out;
	} else {
		range_t *left = NULL, *right = NULL;

		ret = remove_range(list, selected_range, base_address, size,
				   &left, &right);
		if (ret != OK) {
			goto out;
		}

		range_t new_range = { .base_address = base_address,
				      .size	    = size,
				      .data	    = data };

		ret = insert_range(list, left, &new_range, right);

		// shouldn't faile since we just remove the same range
		assert(ret == OK);
	}
out:
	return ret;
}

uintptr_t
range_list_get_range_data(range_t *range)
{
	uintptr_t ret = INVALID_DATA;
	if (range != NULL) {
		ret = range->data;
	}

	return ret;
}

bool
range_list_has_data(range_list_t *list, uintptr_t data)
{
	bool ret = false;

	range_t *cur = NULL;
	loop_list(cur, &list->range_list, range_)
	{
		if (cur->data == data) {
			ret = true;
			break;
		}
	}

	return ret;
}

#ifndef NDEBUG
void
range_list_dump(range_list_t *list, const char *prefix)
{
	range_t *cur;

	if (is_empty(list->range_list)) {
		printf("%sEmpty list ", prefix);
#ifndef NDEBUG
		printf("%snode count(%zu)\n", prefix, list->range_node_cnt);
#else
		printf("\n");
#endif
	} else {
		printf("%sRange list ", prefix);
#ifndef NDEBUG
		printf("%snode count(%zu)\n", prefix, list->range_node_cnt);
#else
		printf("\n");
#endif
		loop_list(cur, &list->range_list, range_)
		{
			if (cur->data != INVALID_DATA) {
				printf("%s\ttagged(%lx) [0x%lx, 0x%lx), ",
				       prefix, cur->data, cur->base_address,
				       cur->base_address + cur->size);
			} else {
				printf("%s\t[0x%lx, 0x%lx), ", prefix,
				       cur->base_address,
				       cur->base_address + cur->size);
			}
		}
		printf("\n");
	}
}
#endif
