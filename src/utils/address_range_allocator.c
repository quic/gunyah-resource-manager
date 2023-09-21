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

#include <rm_types.h>
#include <util.h>
#include <utils/address_range_allocator.h>
#include <utils/list.h>
#include <utils/range_list.h>
#include <utils/vector.h>

#include <log.h>
#include <resource-manager.h>
#include <rm-rpc.h>

struct address_range_allocator {
	range_list_t *ralloc;

	vector_t *sub_allocators;

	uint64_t base_address;
	size_t	 size;
};

typedef struct {
	range_list_t *ralloc;

	address_range_tag_t tag;
	uint8_t		    tag_padding[4];
} sub_allocator_t;

static sub_allocator_t *
find_sub_allocator(address_range_allocator_t *allocator,
		   address_range_tag_t	      tag);

static void
remove_sub_allocator(address_range_allocator_t *allocator,
		     sub_allocator_t	       *sub_allocator);

static sub_allocator_t *
find_sub_allocator(address_range_allocator_t *allocator,
		   address_range_tag_t	      tag)
{
	sub_allocator_t *ret = NULL, *cur = NULL;

	index_t idx = 0U;

	foreach_vector(sub_allocator_t *, allocator->sub_allocators, idx, cur)
	{
		if ((cur != NULL) && (cur->tag == tag)) {
			ret = cur;
			break;
		}
	}

	return ret;
}

static void
remove_sub_allocator(address_range_allocator_t *allocator,
		     sub_allocator_t	       *sub_allocator)
{
	sub_allocator_t *cur = NULL;

	index_t idx   = 0U;
	bool	found = false;

	foreach_vector(sub_allocator_t *, allocator->sub_allocators, idx, cur)
	{
		if (cur == sub_allocator) {
			found = true;
			break;
		}
	}

	// since it's called only by untag, the sub allocator must be found
	assert(found);

	if (found) {
		vector_delete(allocator->sub_allocators, idx);
		free(sub_allocator);
	}

	return;
}

address_range_allocator_t *
address_range_allocator_init(uint64_t base_address, size_t size)
{
	address_range_allocator_t *allocator = NULL;

	if (util_add_overflows(base_address, size) ||
	    ((base_address + size) > ADDRESS_RANGE_LIMIT) ||
	    !util_is_baligned(base_address, PAGE_SIZE) || (size < PAGE_SIZE) ||
	    !util_is_baligned(size, PAGE_SIZE)) {
		LOG_LOC("invalid arg");
		goto out;
	}

	allocator = calloc(1, sizeof(*allocator));
	if (allocator == NULL) {
		LOG_LOC("nomem");
		goto out;
	}

	allocator->ralloc = range_list_init(base_address, size, false);
	if (allocator->ralloc == NULL) {
		LOG_LOC("master list init");
		goto err_free_allocator_alloc;
	}

	allocator->sub_allocators = vector_init(sub_allocator_t *, 2, 2);
	if (allocator->sub_allocators == NULL) {
		LOG_LOC("vector");
		goto err_sub_allocator_vector_init;
	}

	allocator->base_address = base_address;
	allocator->size		= size;

	goto out;

err_sub_allocator_vector_init:
	range_list_deinit(allocator->ralloc);
err_free_allocator_alloc:
	free(allocator);
	allocator = NULL;
out:
	return allocator;
}

typedef struct {
	sub_allocator_t allocator;
	uintptr_t	data;
} target_allocator_t;

static target_allocator_t
get_address_allocator(address_range_allocator_t *allocator,
		      uint64_t base_address, size_t size, size_t alignment)
{
	// check if it's in tagged range
	target_allocator_t ret = { .allocator.ralloc = NULL,
				   .allocator.tag    = ADDRESS_RANGE_NO_TAG,
				   .data	     = INVALID_DATA };

	// only support alloc from top level with INVALID_ADDRESS
	if (base_address == INVALID_ADDRESS) {
		ret.allocator.ralloc = allocator->ralloc;
		ret.allocator.tag    = ADDRESS_RANGE_NO_TAG;
		ret.data	     = INVALID_DATA;

		goto out;
	}

	range_list_find_ret_t check_tagged_ret = range_list_find_range(
		allocator->ralloc, base_address, size, alignment);
	if (check_tagged_ret.err != OK) {
		ret.allocator.ralloc = allocator->ralloc;
		ret.allocator.tag    = ADDRESS_RANGE_NO_TAG;
		ret.data	     = INVALID_DATA;
	} else {
		uintptr_t data = range_list_get_range_data(
			check_tagged_ret.selected_range);
		if (data == INVALID_DATA) {
			ret.allocator.ralloc = allocator->ralloc;
			ret.allocator.tag    = ADDRESS_RANGE_NO_TAG;
			ret.data	     = INVALID_DATA;
		} else {
			assert(check_tagged_ret.selected_range != NULL);
			sub_allocator_t *sub_allocator =
				(sub_allocator_t *)(range_list_get_range_data(
					check_tagged_ret.selected_range));
			assert(sub_allocator != NULL);

			ret.allocator.ralloc = sub_allocator->ralloc;
			ret.allocator.tag    = sub_allocator->tag;
			ret.data	     = (uintptr_t)sub_allocator;
		}
	}

out:
	return ret;
}

address_range_allocator_ret_t
address_range_allocator_alloc(address_range_allocator_t *allocator,
			      uint64_t base_address, size_t size,
			      size_t alignment)
{
	assert(allocator != NULL);

	address_range_allocator_ret_t ret = { 0 };

	if (((base_address != INVALID_ADDRESS) &&
	     (util_add_overflows(base_address, size) ||
	      !util_is_baligned(base_address, PAGE_SIZE) ||
	      (base_address < allocator->base_address) ||
	      ((base_address + size) >
	       (allocator->base_address + allocator->size)))) ||
	    (size < PAGE_SIZE) || !util_is_baligned(size, PAGE_SIZE)) {
		ret.err = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (alignment == 0U) {
		alignment = PAGE_SIZE;
	}

	target_allocator_t get_ret =
		get_address_allocator(allocator, base_address, size, alignment);

	range_list_t *target_allocator = get_ret.allocator.ralloc;

	range_list_remove_ret_t remove_ret = range_list_remove(
		target_allocator, base_address, size, alignment, INVALID_DATA);
	if (remove_ret.err == OK) {
		ret.err		 = OK;
		ret.base_address = remove_ret.base_address;
		ret.size	 = remove_ret.size;
		ret.tag		 = get_ret.allocator.tag;
	} else {
		ret.err = remove_ret.err;
	}

out:
	if (ret.err != OK) {
		LOG_ERR(ret.err);
	}
	return ret;
}

error_t
address_range_allocator_free(address_range_allocator_t *allocator,
			     uint64_t base_address, size_t size)
{
	error_t ret;

	if ((base_address == INVALID_ADDRESS) ||
	    util_add_overflows(base_address, size) ||
	    !util_is_baligned(base_address, PAGE_SIZE) || (size < PAGE_SIZE) ||
	    !util_is_baligned(size, PAGE_SIZE) ||
	    (base_address < allocator->base_address) ||
	    ((base_address + size) >
	     (allocator->base_address + allocator->size))) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	target_allocator_t get_ret =
		get_address_allocator(allocator, base_address, size, PAGE_SIZE);

	range_list_t *target_allocator = get_ret.allocator.ralloc;

	ret = range_list_insert(target_allocator, base_address, size,
				INVALID_DATA);

out:
	if (ret != OK) {
		LOG_ERR(ret);
	}
	return ret;
}

void
address_range_allocator_deinit(address_range_allocator_t *allocator)
{
	index_t		 idx	       = 0U;
	sub_allocator_t *cur_allocator = NULL;

	foreach_vector(sub_allocator_t *, allocator->sub_allocators, idx,
		       cur_allocator)
	{
		if (cur_allocator != NULL) {
			range_list_deinit(cur_allocator->ralloc);
			free(cur_allocator);
		}
	}

	vector_deinit(allocator->sub_allocators);

	range_list_deinit(allocator->ralloc);

	free(allocator);
}

address_range_allocator_ret_t
address_range_allocator_tag_region(address_range_allocator_t *allocator,
				   uint64_t		      constrain_base,
				   size_t constrain_size, size_t size,
				   size_t alignment, address_range_tag_t tag)
{
	address_range_allocator_ret_t ret = { 0 };

	if ((tag == ADDRESS_RANGE_NO_TAG) || (size < (size_t)PAGE_SIZE) ||
	    !util_is_baligned(size, PAGE_SIZE) ||
	    (alignment < (size_t)PAGE_SIZE) || !util_is_p2(alignment)) {
		LOG_LOC("bad arg");
		ret.err = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if ((constrain_base != INVALID_ADDRESS) &&
	    (util_add_overflows(constrain_base, constrain_size) ||
	     !util_is_baligned(constrain_base, PAGE_SIZE) ||
	     (constrain_base < allocator->base_address) ||
	     ((constrain_base + constrain_size) >
	      (allocator->base_address + allocator->size)) ||
	     (constrain_size < (size_t)PAGE_SIZE) ||
	     !util_is_baligned(constrain_size, PAGE_SIZE))) {
		LOG_LOC("constrain");
		ret.err = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (constrain_base == INVALID_ADDRESS) {
		constrain_base = allocator->base_address;
		constrain_size = allocator->size;
	}

	range_list_find_ret_t select_ret = range_list_find_range_by_region(
		allocator->ralloc, constrain_base, constrain_size, size,
		alignment, INVALID_DATA);
	if (select_ret.err != OK) {
		LOG_LOC("used");
		ret.err = select_ret.err;
		goto out;
	}

	sub_allocator_t *sub_allocator = find_sub_allocator(allocator, tag);
	if (sub_allocator == NULL) {
		range_list_t *sub_list = range_list_init(
			allocator->base_address, allocator->size, true);
		if (sub_list == NULL) {
			LOG_LOC("alloc");
			ret.err = ERROR_NOMEM;
			goto out;
		} else {
			sub_allocator = calloc(1U, sizeof(*sub_allocator));
			if (sub_allocator == NULL) {
				LOG_LOC("alloc");
				ret.err = ERROR_NOMEM;
				goto out;
			}

			sub_allocator->ralloc = sub_list;
			sub_allocator->tag    = tag;

			ret.err = vector_push_back(allocator->sub_allocators,
						   sub_allocator);
			if (ret.err != OK) {
				LOG_LOC("vector");
				range_list_deinit(sub_list);
				goto out;
			}
		}
	}

	ret.err = range_list_update(allocator->ralloc, select_ret.base_address,
				    size, select_ret.selected_range,
				    (uintptr_t)sub_allocator);
	if (ret.err != OK) {
		LOG_LOC("update");
		goto out;
	}

	error_t sub_list_insert_ret = range_list_insert(sub_allocator->ralloc,
							select_ret.base_address,
							size, INVALID_DATA);
	if (sub_list_insert_ret != OK) {
		(void)range_list_update(allocator->ralloc,
					select_ret.base_address, size,
					select_ret.selected_range,
					INVALID_DATA);

		ret.err = sub_list_insert_ret;
		LOG_LOC("insert");
		goto out;
	}

	ret = (address_range_allocator_ret_t){ .base_address =
						       select_ret.base_address,
					       .size = size,
					       .tag  = tag,
					       .err  = OK };

out:
	return ret;
}

error_t
address_range_allocator_tag(address_range_allocator_t *allocator,
			    uint64_t base_address, size_t size,
			    address_range_tag_t tag)
{
	address_range_allocator_ret_t ret;

	ret = address_range_allocator_tag_region(
		allocator, base_address, PAGE_SIZE, size, PAGE_SIZE, tag);
	if (ret.err != OK) {
		LOG_ERR(ret.err);
	}

	return ret.err;
}

error_t
address_range_allocator_untag(address_range_allocator_t *allocator,
			      uint64_t base_address, size_t size,
			      address_range_tag_t tag)
{
	error_t ret = OK;

	if ((base_address == INVALID_ADDRESS) ||
	    !util_is_baligned(base_address, PAGE_SIZE) || (size < PAGE_SIZE) ||
	    !util_is_baligned(size, PAGE_SIZE) ||
	    util_add_overflows(base_address, size) ||
	    (base_address < allocator->base_address) ||
	    ((base_address + size) >
	     (allocator->base_address + allocator->size))) {
		LOG_LOC("bad arg");
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	range_list_find_ret_t select_ret = range_list_find_range(
		allocator->ralloc, base_address, size, PAGE_SIZE);
	if (select_ret.err != OK) {
		LOG_LOC("address is not tagged");
		ret = select_ret.err;
		goto out;
	}

	assert(base_address == select_ret.base_address);

	sub_allocator_t *sub_allocator = find_sub_allocator(allocator, tag);
	if (sub_allocator == NULL) {
		LOG_LOC("wrong tag");
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (range_list_get_range_data(select_ret.selected_range) !=
	    (uintptr_t)sub_allocator) {
		LOG_LOC("wrong range");
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	range_list_remove_ret_t sub_list_remove_ret =
		range_list_remove(sub_allocator->ralloc, base_address, size,
				  PAGE_SIZE, INVALID_DATA);
	if (sub_list_remove_ret.err != OK) {
		ret = sub_list_remove_ret.err;
		LOG_LOC("remove");
		goto out;
	}

	ret = range_list_update(allocator->ralloc, base_address, size,
				select_ret.selected_range, INVALID_DATA);
	if (ret != OK) {
		assert(range_list_insert(sub_allocator->ralloc, base_address,
					 size, INVALID_DATA) == OK);
		LOG_ERR(ret);
		goto out;
	}

	if ((ret == OK) &&
	    !range_list_has_data(allocator->ralloc, (uintptr_t)sub_allocator)) {
		range_list_deinit(sub_allocator->ralloc);
		remove_sub_allocator(allocator, sub_allocator);
	}
out:
	return ret;
}

#ifndef NDEBUG
void
address_range_allocator_dump(address_range_allocator_t *allocator)
{
	(void)printf("Dump allocator: list range [0x%lx, 0x%lx):\n",
		     allocator->base_address,
		     allocator->base_address + allocator->size);

	range_list_dump(allocator->ralloc, "");

	index_t		 idx	       = 0U;
	sub_allocator_t *cur_allocator = NULL;

	(void)printf("Sub allocators:\n");
	foreach_vector(sub_allocator_t *, allocator->sub_allocators, idx,
		       cur_allocator)
	{
		if (cur_allocator != NULL) {
			range_list_t *a	   = cur_allocator->ralloc;
			uint64_t      base = range_list_get_base_address(a);
			uint64_t      size = range_list_get_size(a);
			(void)printf(
				"\ttagged: list range [0x%lx, 0x%lx) tag(%lx) data(%p):\n",
				base, base + size, (uint64_t)cur_allocator->tag,
				(void *)cur_allocator);
			range_list_dump(a, "\t");
		}
	}
}
#endif
