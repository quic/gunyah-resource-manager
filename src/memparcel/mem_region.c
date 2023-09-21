// © 2022 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include <rm_types.h>
#include <util.h>
#include <utils/vector.h>

#include <memparcel.h>
#include <rm-rpc.h>

#include "mem_region.h"

#define MAX_L1_BITS 14U

#define L2_TABLE_BITS 6U
#define L2_TABLE_SIZE util_bit(L2_TABLE_BITS)

struct region_list_s {
	mem_region_t **regions;
	count_t	       total_len;
	uint8_t	       l1_bits;
	bool	       finalized;
	uint8_t	       pad_to_end[2];
};

mem_region_t
mem_region_init(paddr_t phys, size_t size, vmaddr_t owner_ipa)
{
	return (mem_region_t){
		.phys_pn	       = (uint32_t)(phys >> PAGE_BITS),
		.size_pn	       = (uint32_t)(size >> PAGE_BITS),
		.ipa_pn		       = (uint32_t)(owner_ipa >> PAGE_BITS),
		.mpd_sanitise_refcount = 0,
	};
}

paddr_t
mem_region_get_phys(mem_region_t region)
{
	return (paddr_t)region.phys_pn << PAGE_BITS;
}

size_t
mem_region_get_size(mem_region_t region)
{
	return (size_t)region.size_pn << PAGE_BITS;
}

vmaddr_t
mem_region_get_owner_ipa(mem_region_t region)
{
	return (vmaddr_t)region.ipa_pn << PAGE_BITS;
}

ipa_region_t
ipa_region_init(vmaddr_t ipa)
{
	return (ipa_region_t){
		.ipa_pn = (uint32_t)(ipa >> PAGE_BITS),
	};
}

vmaddr_t
ipa_region_get_ipa(ipa_region_t region)
{
	return (vmaddr_t)region.ipa_pn << PAGE_BITS;
}

uint32_t
mem_region_get_mpd_sanitise_refcount(const mem_region_t *region)
{
	assert(region != NULL);
	return region->mpd_sanitise_refcount;
}

// The refcount functions below should be moved to a platform-specific file for
// memparcel extensions during RM clean-up.
// FIXME:
void
mem_region_increment_mpd_sanitise_refcount(mem_region_t *region)
{
	assert(region != NULL);
	// Since the number of allowed minidump regions is orders of magnitude
	// smaller than the maximum refcount value (uint32), no need to worry
	// about overflows.
	region->mpd_sanitise_refcount++;
}

void
mem_region_decrement_mpd_sanitise_refcount(mem_region_t *region)
{
	assert(region != NULL);
	assert(region->mpd_sanitise_refcount != 0);

	region->mpd_sanitise_refcount--;
}

static index_t
get_l1_idx(index_t i)
{
	return i >> L2_TABLE_BITS;
}

static index_t
get_l2_idx(index_t i)
{
	return i & util_mask(L2_TABLE_BITS);
}

static count_t
get_l1_alloc_count(region_list_t *list)
{
	return (count_t)util_bit(list->l1_bits);
}

static count_t
get_l1_used_count(region_list_t *list)
{
	index_t l1_idx = get_l1_idx(list->total_len);
	index_t l2_idx = get_l2_idx(list->total_len);

	// If the l2 idx is non-zero, we have allocated a l2 table at the
	// current l1 idx. We must account for this in the final count.
	return (l2_idx != 0U) ? l1_idx + 1U : l1_idx;
}

region_list_t *
region_list_init(void)
{
	region_list_t *list = calloc(1U, sizeof(*list));
	if (list == NULL) {
		goto out;
	}

	list->regions = calloc(1U, sizeof(*list->regions));
	if (list->regions == NULL) {
		free(list);
		list = NULL;
		goto out;
	}

out:
	return list;
}

void
region_list_destroy(region_list_t *list)
{
	assert(list != NULL);

	count_t l1_count = get_l1_used_count(list);

	for (index_t i = 0U; i < l1_count; i++) {
		free(list->regions[i]);
	}

	free(list->regions);
	free(list);
}

count_t
region_list_get_len(region_list_t *list)
{
	assert(list != NULL);

	return list->total_len;
}

static rm_error_t
expand_l1(region_list_t *list)
{
	rm_error_t err = RM_OK;

	uint8_t new_bits = list->l1_bits + 1U;
	if (new_bits > MAX_L1_BITS) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	size_t new_size = sizeof(mem_region_t *) << new_bits;

	mem_region_t **new_l1 = realloc(list->regions, new_size);
	if (new_l1 == NULL) {
		err = RM_ERROR_NOMEM;
		goto out;
	}

	list->regions = new_l1;
	list->l1_bits = new_bits;

out:
	return err;
}

static rm_error_t
alloc_l2(region_list_t *list, index_t l1_idx)
{
	rm_error_t err = RM_OK;

	mem_region_t *new_l2 = calloc(L2_TABLE_SIZE, sizeof(*new_l2));
	if (new_l2 == NULL) {
		err = RM_ERROR_NOMEM;
		goto out;
	}

	list->regions[l1_idx] = new_l2;

out:
	return err;
}

rm_error_t
region_list_push_back(region_list_t *list, mem_region_t region)
{
	rm_error_t err = RM_OK;

	assert(list != NULL);

	if (list->finalized) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	assert(list->l1_bits <= MAX_L1_BITS);

	index_t l1_idx = get_l1_idx(list->total_len);
	index_t l2_idx = get_l2_idx(list->total_len);

	count_t l1_alloc_count = get_l1_alloc_count(list);

	if (l1_idx == l1_alloc_count) {
		err = expand_l1(list);
		if (err != RM_OK) {
			goto out;
		}
	}

	if (l2_idx == 0U) {
		err = alloc_l2(list, l1_idx);
		if (err != RM_OK) {
			goto out;
		}
	}

	list->regions[l1_idx][l2_idx] = region;
	list->total_len++;

out:
	return err;
}

mem_region_t
region_list_pop_back(region_list_t *list)
{
	mem_region_t region = { 0 };

	assert(list != NULL);

	if (list->total_len == 0U) {
		goto out;
	}

	list->total_len--;

	index_t l1_idx = get_l1_idx(list->total_len);
	index_t l2_idx = get_l2_idx(list->total_len);

	region = list->regions[l1_idx][l2_idx];

	if (l2_idx == 0U) {
		free(list->regions[l1_idx]);
		list->regions[l1_idx] = NULL;
	}

out:
	return region;
}

rm_error_t
region_list_finalize(region_list_t *list)
{
	rm_error_t err = RM_OK;

	assert(list != NULL);

	if (list->finalized) {
		goto out;
	}

	list->finalized = true;

	index_t l1_idx = get_l1_idx(list->total_len);
	index_t l2_idx = get_l2_idx(list->total_len);

	count_t l1_alloc_count = get_l1_alloc_count(list);
	count_t l1_used_count  = get_l1_used_count(list);

	if (l1_used_count < l1_alloc_count) {
		// We can reduce the size of the l1 table.
		size_t new_l1_size = sizeof(mem_region_t *) * l1_used_count;

		mem_region_t **new_l1 = realloc(list->regions, new_l1_size);
		if ((new_l1 == NULL) && (l1_used_count != 0U)) {
			err = RM_ERROR_NOMEM;
			goto out;
		}

		list->regions = new_l1;
	}

	if (l2_idx != 0U) {
		// We can reduce the size of the last l2 table.
		size_t new_l2_size = sizeof(mem_region_t) * l2_idx;

		assert(list->regions != NULL);

		mem_region_t *new_l2 =
			realloc(list->regions[l1_idx], new_l2_size);
		if (new_l2 == NULL) {
			err = RM_ERROR_NOMEM;
			goto out;
		}

		list->regions[l1_idx] = new_l2;
	}

out:
	return err;
}

mem_region_t
region_list_at(region_list_t *list, index_t i)
{
	mem_region_t region = { 0 };

	if (i >= list->total_len) {
		goto out;
	}

	index_t l1_idx = get_l1_idx(i);
	index_t l2_idx = get_l2_idx(i);

	region = list->regions[l1_idx][l2_idx];

out:
	return region;
}

mem_region_t *
region_list_at_ptr(region_list_t *list, index_t i)
{
	mem_region_t *region = NULL;

	if (i >= list->total_len) {
		goto out;
	}

	index_t l1_idx = get_l1_idx(i);
	index_t l2_idx = get_l2_idx(i);

	region = &list->regions[l1_idx][l2_idx];

out:
	return region;
}
