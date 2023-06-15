// © 2022 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

typedef struct mem_region {
	uint32_t phys_pn;
	uint32_t size_pn;
	uint32_t ipa_pn;
	uint32_t mpd_sanitise_refcount;
} mem_region_t;

mem_region_t
mem_region_init(paddr_t phys, size_t size, vmaddr_t owner_ipa);

paddr_t
mem_region_get_phys(mem_region_t region);

size_t
mem_region_get_size(mem_region_t region);

vmaddr_t
mem_region_get_owner_ipa(mem_region_t region);

uint32_t
mem_region_get_mpd_sanitise_refcount(mem_region_t *region);

void
mem_region_increment_mpd_sanitise_refcount(mem_region_t *region);

void
mem_region_decrement_mpd_sanitise_refcount(mem_region_t *region);

typedef struct ipa_region {
	uint32_t ipa_pn;
} ipa_region_t;

ipa_region_t
ipa_region_init(vmaddr_t ipa);

vmaddr_t
ipa_region_get_ipa(ipa_region_t region);

typedef struct region_list region_list_t;

region_list_t *
region_list_init(void);

void
region_list_destroy(region_list_t *list);

count_t
region_list_get_len(region_list_t *list);

rm_error_t
region_list_push_back(region_list_t *list, mem_region_t region);

mem_region_t
region_list_pop_back(region_list_t *list);

rm_error_t
region_list_finalize(region_list_t *list);

mem_region_t
region_list_at(region_list_t *list, index_t i);

mem_region_t *
region_list_at_ptr(region_list_t *list, index_t i);

#define region_list_loop_range(list, region, i, start_idx, end_idx)            \
	for (i = start_idx, region = region_list_at(list, i); i < end_idx;     \
	     i++, region	   = region_list_at(list, i))

#define region_list_loop(list, region, i)                                      \
	region_list_loop_range(list, region, i, 0U, region_list_get_len(list))
