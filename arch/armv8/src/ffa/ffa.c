// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <asm/arm_smccc.h>

#include <rm_types.h>
#include <util.h>
#include <utils/vector.h>

#include <event.h>
#include <ffa/ffa.h>
#include <ffa/ffa_memory.h>
#include <platform.h>
#include <vm_mgnt.h>

#if defined(PLATFORM_FFA_SUPPORTED) && PLATFORM_FFA_SUPPORTED
// Shared memory between Hypervisor and RM which is used to store
// the memory transaction descriptor for memory management.
static char *tx_buf = NULL;
static char *rx_buf = NULL;

static uint16_t partition_id = 0UL;

// Check if the rm version is compatible with the hyp version.
static bool
version_compatible(uint64_t rm_version, uint64_t hyp_version)
{
	bool ret;

	if (((rm_version & util_bit(31)) != 0) ||
	    ((hyp_version & util_bit(31)) != 0)) {
		ret = false;
		goto out;
	}

	uint32_t rm_major = (rm_version >> 16) & util_mask(16);
	uint32_t rm_minor = rm_version & util_mask(16);

	uint32_t hyp_major = (hyp_version >> 16) & util_mask(16);
	uint32_t hyp_minor = hyp_version & util_mask(16);

	if (rm_major != hyp_major) {
		ret = false;
		goto out;
	}

	if (rm_minor > hyp_minor) {
		ret = false;
		goto out;
	}

	ret = true;
out:
	return ret;
}

// Check if the version is compatible.
static bool
is_hyp_compatible(uint64_t rm_version)
{
	bool ret;

	uint64_t func	     = FFA_FUNCTION_FFA_VERSION;
	uint64_t params[17]  = { 0 };
	uint64_t results[18] = { 0 };

	params[0] = rm_version;

	// Result is either NOT_SUPPORT or version
	(void)arm_smccc12_call(func, &params, &results);
	if ((results[0] & util_mask(32)) != FFA_RET_NOT_SUPPORTED) {
		uint64_t hyp_version = results[0];
		ret = version_compatible(rm_version, hyp_version);
	} else {
		ret = false;
	}

	return ret;
}

static bool
ffa_partion_id(void)
{
	bool ret;

	uint64_t func	     = FFA_FUNCTION_FFA_ID_GET;
	uint64_t params[17]  = { 0 };
	uint64_t results[18] = { 0 };

	(void)arm_smccc12_call(func, &params, &results);
	if ((results[0] & util_mask(32)) == FFA_FUNCTION_FFA_SUCCESS) {
		partition_id = (uint16_t)(results[2] & util_mask(16));
		ret	     = true;
	} else {
		ret = false;
	}

	return ret;
}

// Check if the feature is supported.
static bool
ffa_features_function(uint64_t queried_func_id)
{
	bool ret;

	// It is interpreted as the Function ID of the FF-A interface.
	assert((queried_func_id & util_bit(31U)) != 0U);

	uint64_t func	     = FFA_FUNCTION_FFA_FEATURES;
	uint64_t params[17]  = { 0 };
	uint64_t results[18] = { 0 };

	params[0] = queried_func_id;

	(void)arm_smccc12_call(func, &params, &results);
	ret = (results[0] & util_mask(32)) == FFA_FUNCTION_FFA_SUCCESS;

	return ret;
}

// Create one page RXTX buffer between RM and HYP.
static bool
ffa_rxtx_map(void)
{
	bool ret;

	uint64_t func	   = FFA_FUNCTION_FFA_RXTX_MAP;
	count_t	 num_pages = FFA_RXTX_NUM_PAGES;

	uint64_t params[17]  = { 0 };
	uint64_t results[18] = { 0 };

	// RXTX buffer should be initialized only once
	assert(tx_buf == NULL);
	assert(rx_buf == NULL);

	tx_buf = util_alloc_pages(PAGE_SIZE);
	if (tx_buf == NULL) {
		printf("Failed to allocate FF-A tx_buf\n");
		ret = false;
		goto out_free;
	}

	rx_buf = util_alloc_pages(PAGE_SIZE);
	if (rx_buf == NULL) {
		printf("Failed to allocate FF-A rx_buf\n");
		ret = false;
		goto out_free;
	}

	params[0] = (uint64_t)tx_buf;
	params[1] = (uint64_t)rx_buf;
	params[2] = num_pages;

	(void)arm_smccc12_call(func, &params, &results);
	if ((results[0] & util_mask(32)) == FFA_FUNCTION_FFA_SUCCESS) {
		ret = true;
		goto out;
	} else {
		ret = false;
	}

out_free:
	if (tx_buf != NULL) {
		util_free_pages(tx_buf, PAGE_SIZE);
		tx_buf = NULL;
	}
	if (rx_buf != NULL) {
		util_free_pages(rx_buf, PAGE_SIZE);
		rx_buf = NULL;
	}
out:
	return ret;
}

static void
fill_memory_transaction_desc(ffa_memory_transaction_desc_t *desc)
{
	assert(partition_id != 0U);

	desc->sender = partition_id;
	// NS-bit reserved, Normal memory, Write-back and Inner shareable
	desc->attributes = 0x2FU;
	// zero memory flag 0, operation time slicing flag 0
	desc->flags	       = 0U;
	desc->handle	       = 0UL;
	desc->tag	       = 0UL;
	desc->mad_size	       = sizeof(ffa_memory_access_desc_t);
	desc->mad_count	       = 1U;
	desc->mad_array_offset = sizeof(ffa_memory_transaction_desc_t);
	desc->reserved[0]      = 0U;
	desc->reserved[1]      = 0U;
	desc->reserved[2]      = 0U;
}

static void
fill_memory_access_desc(ffa_memory_access_desc_t *desc)
{
	desc->permission.receiver = FFA_TZ_PARTITION_ID;
	// RW bits[1:0] = b'10
	desc->permission.acc	   = 0x02U;
	desc->permission.flags	   = 0U;
	desc->composite_mrd_offset = sizeof(ffa_memory_transaction_desc_t) +
				     sizeof(ffa_memory_access_desc_t);
	desc->impl_def[0] = 0UL;
	desc->impl_def[1] = 0UL;
	desc->reserved	  = 0UL;
}

static void
fill_composite_memory_region_desc(ffa_composite_memory_region_desc_t *desc,
				  count_t			      count)
{
	// Restrict to a single address rage.
	desc->total_page_count = count;
	desc->range_count      = 1U;
	desc->reserved	       = 0UL;
}

static void
fill_constituent_memory_region_desc(ffa_constituent_memory_region_desc_t *desc,
				    uint64_t addr, count_t count)
{
	desc->base_address = addr;
	desc->page_count   = count;
	desc->reserved	   = 0U;
}

static void
fill_transaction_buf(uint64_t buf, uint64_t addr, uint64_t size)
{
	assert(buf != 0UL);

	assert(util_is_baligned(buf, 8));

	ffa_memory_transaction_desc_t *memory_transaction_desc =
		(ffa_memory_transaction_desc_t *)buf;

	size_t offset_access = sizeof(ffa_memory_transaction_desc_t);
	ffa_memory_access_desc_t *memory_access_desc =
		(ffa_memory_access_desc_t *)(buf + offset_access);

	size_t offset_composite = sizeof(ffa_memory_access_desc_t);
	ffa_composite_memory_region_desc_t *composite_memory_region_desc =
		(ffa_composite_memory_region_desc_t *)(buf + offset_access +
						       offset_composite);

	size_t offset_constituent = sizeof(ffa_composite_memory_region_desc_t);
	ffa_constituent_memory_region_desc_t *constituent_memory_region_desc =
		(ffa_constituent_memory_region_desc_t *)(buf + offset_access +
							 offset_composite +
							 offset_constituent);

	fill_memory_transaction_desc(memory_transaction_desc);

	assert(size != 0U);
	assert(addr != 0U);
	assert(util_is_baligned(size, PAGE_SIZE));
	assert(util_is_baligned(addr, PAGE_SIZE));

	assert((size / PAGE_SIZE) < (util_bit(32)));
	count_t count = (count_t)(size / PAGE_SIZE);

	fill_memory_access_desc(memory_access_desc);
	fill_composite_memory_region_desc(composite_memory_region_desc, count);
	fill_constituent_memory_region_desc(constituent_memory_region_desc,
					    addr, count);
}

/**
 * Shares a memory region using the FFA_MEM_SHARE.
 *
 * @param addr The address of the memory region to be shared.
 * @param size The size of the memory region to be shared.
 *
 * @return A handle to the shared memory region, or invalid handle if the
 * operation fails.
 */
uint64_t
ffa_mem_share(void *addr, size_t size)
{
	uint64_t handle;

	uint64_t func	     = FFA_FUNCTION_FFA_MEM_SHARE;
	uint64_t params[17]  = { 0 };
	uint64_t results[18] = { 0 };

	uint32_t total_len = sizeof(ffa_memory_transaction_desc_t) +
			     sizeof(ffa_memory_access_desc_t) +
			     sizeof(ffa_composite_memory_region_desc_t) +
			     sizeof(ffa_constituent_memory_region_desc_t);
	uint32_t frag_len = total_len;

	params[0] = (uint64_t)total_len;
	params[1] = (uint64_t)frag_len;
	// Use the TX buffer
	params[2] = 0UL;
	params[3] = 0UL;

	fill_transaction_buf((uint64_t)tx_buf, (uint64_t)addr, size);

	(void)arm_smccc12_call(func, &params, &results);
	if ((results[0] & util_mask(32)) == FFA_FUNCTION_FFA_SUCCESS) {
		uint64_t handle_lo = results[2] & util_mask(32);
		uint64_t handle_hi = results[3] << 32;
		handle		   = handle_hi | handle_lo;
		assert(handle != FFA_INVALID_HANDLE);
	} else {
		handle = FFA_INVALID_HANDLE;
	}

	return handle;
}

/**
 * Reclaims memory using the FFA_MEM_RECLAIM.
 *
 * @param handle The handle of the memory to be reclaimed.
 */
void
ffa_mem_reclaim(uint64_t handle)
{
	uint64_t flags = 0UL;

	uint64_t func	     = FFA_FUNCTION_MEM_RECLAIM;
	uint64_t params[17]  = { 0 };
	uint64_t results[18] = { 0 };

	params[0] = handle & util_mask(32);
	params[1] = (handle >> 32) & util_mask(32);
	params[2] = flags;

	(void)arm_smccc12_call(func, &params, &results);
	assert((results[0] & util_mask(32)) == FFA_FUNCTION_FFA_SUCCESS);

	return;
}

/**
 * Initializes the FF-A.
 *
 * This function checks the compatibility of the FF-A version, retrieves the
 * partition ID, verifies the support for required FF-A features, and maps the
 * RXTX buffer.
 *
 * @return rm_error_t indicating the result of the initialization process.
 */
rm_error_t
ffa_init(void)
{
	rm_error_t err;

	bool is_compatible;
	bool is_supported;
	bool rxtx_created;

	is_compatible = is_hyp_compatible(RM_FFA_VERSION);

	if (!is_compatible) {
		(void)printf("FF-A version is not compatible\n");
		err = RM_ERROR_DENIED;
		goto out;
	}

	if (!ffa_partion_id()) {
		(void)printf("FF-A get partition id failed\n");
		err = RM_ERROR_DENIED;
		goto out;
	}

	is_supported = ffa_features_function(FFA_FUNCTION_FFA_RXTX_MAP) &&
		       ffa_features_function(FFA_FUNCTION_FFA_MEM_SHARE) &&
		       ffa_features_function(FFA_FUNCTION_MEM_RECLAIM);

	if (!is_supported) {
		(void)printf("FF-A features not supported\n");
		err = RM_ERROR_DENIED;
		goto out;
	}

	// At this point, the ACL must be already registered.
	rxtx_created = ffa_rxtx_map();
	if (!rxtx_created) {
		(void)printf("FF-A mapping RXTX failed\n");
		err = RM_ERROR_MAP_FAILED;
		goto out;
	}

	err = RM_OK;
out:
	return err;
}
#endif
