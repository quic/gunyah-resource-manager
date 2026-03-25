// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include <rm_types.h>
#include <util.h>
#include <utils/list.h>
#include <utils/vector.h>

#include <cache.h>
#include <event.h>
#include <fcntl.h>
#include <guest_interface.h>
#include <heap_mgnt.h>
#include <log.h>
#include <mem_region.h>
#include <memextent.h>
#include <memparcel.h>
#include <platform.h>
#include <resource-manager.h>
#include <rm-rpc-fifo.h>
#include <rm-rpc.h>
#include <uapi/mem.h>
#include <unistd.h>
#include <vm_config.h>
#include <vm_memory.h>
#include <vm_mgnt.h>
#include <vm_resource_msg.h>

#define ROOT_HEAP_HANDLE 0U
#define ROOT_HEAP_LABEL	 0U

#define RM_HEAP_HANDLE 1U
#define RM_HEAP_LABEL  1U

#define MIN_HEAP_BLOCK_SIZE (1UL << 20)

typedef struct heap_node_s heap_node_t;

struct heap_node_s {
	heap_node_t *next;
	heap_node_t *prev;
	memparcel_t *mp;
	paddr_t	     phys;
	size_t	     size;
	cap_id_t     rm_me;
	uintptr_t    rm_ipa;
};

static heap_node_t *root_heap_list;
static heap_node_t *rm_heap_list;

static rm_error_t
parse_heap_memory_req(vmid_t client_id, void *buf, size_t len,
		      uint32_t *heap_handle, uint32_t *mp_handle)
{
	rm_error_t err;

	assert(heap_handle != NULL);
	assert(mp_handle != NULL);

	// Heap management is limited to HLOS for now.
	if (client_id != VMID_HLOS) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	if (len != sizeof(heap_memory_req_t)) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	heap_memory_req_t *req = (heap_memory_req_t *)(uintptr_t)buf;

	*heap_handle = req->heap_handle;
	*mp_handle   = req->mp_handle;

	if ((*heap_handle != ROOT_HEAP_HANDLE) &&
	    (*heap_handle != RM_HEAP_HANDLE)) {
		err = RM_ERROR_HANDLE_INVALID;
		goto out;
	}

	err = RM_OK;

out:
	return err;
}

static rm_error_t
donate_mp_heap(const heap_node_t *heap, bool to_heap)
{
	paddr_t phys = heap->phys;
	size_t	size = heap->size;

	cap_id_result_t me_cap = memparcel_get_me_cap(heap->mp);
	assert(me_cap.e == OK);

	cap_id_t partition_cap = rm_get_rm_partition();
	assert(partition_cap != CSPACE_CAP_INVALID);

	allocator_memattr_t memattr = allocator_memattr_default();

	error_t err = to_heap ? vm_memory_add_heap(me_cap.r, partition_cap,
						   phys, size, memattr)
			      : vm_memory_remove_heap(me_cap.r, partition_cap,
						      phys, size, memattr);

	return rm_error_from_hyp(err);
}

static int32_t
open_mem_dev(void)
{
	const char *mem_dev = "/dev/mem";

	return (int32_t)open(mem_dev, O_RDWR);
}

static rm_error_t
add_rm_crt_heap(heap_node_t *heap)
{
	rm_error_t ret;
	error_t	   err;
	int32_t	   crt_err;
	paddr_t	   phys = heap->phys;
	size_t	   size = heap->size;

	// The heap memory type must be equivalent to that of RM's main memory.
	address_range_tag_t mp_tag = memparcel_get_phys_address_tag(heap->mp);
	address_range_tag_t rm_tag = vm_memory_get_rm_address_tag();
	if ((mp_tag & rm_tag) != rm_tag) {
		ret = RM_ERROR_MEM_INVALID;
		LOG_ERR(ret);
		goto out;
	}

	vm_t *rm_vm = vm_lookup(VMID_RM);
	assert(rm_vm != NULL);

	// Align mapping to use large pages where possible.
	paddr_t aligned_phys   = util_balign_down(phys, LARGE_PAGE_SIZE);
	size_t	aligned_offset = phys - aligned_phys;
	size_t	aligned_size   = size + aligned_offset;

	// Allocate an IPA for mapping the heap memory.
	vm_address_range_result_t ar_ret = vm_address_range_alloc(
		rm_vm, VM_MEMUSE_NORMAL, INVALID_ADDRESS, aligned_phys,
		aligned_size, LARGE_PAGE_SIZE);
	if (ar_ret.err != OK) {
		ret = rm_error_from_hyp(ar_ret.err);
		LOG_ERR(ret);
		goto out;
	}

	vmaddr_t ipa = ar_ret.base + aligned_offset;
	assert(ipa != 0U);

	cap_id_result_t me_cap = memparcel_get_me_cap(heap->mp);
	assert(me_cap.e == OK);

	// Map the memparcel extent to RM. We don't use memparcel_map_rm() for
	// this as it doesn't support mapping with the required alignment.
	err = vm_memory_map_partial(rm_vm, VM_MEMUSE_NORMAL, me_cap.r, ipa,
				    phys, size, PGTABLE_ACCESS_RW,
				    PGTABLE_VM_MEMTYPE_NORMAL_WB);
	if (err != OK) {
		ret = rm_error_from_hyp(err);
		LOG_ERR(ret);
		goto out_free_ipa;
	}

	// Use the memory device to add the heap to the runtime.
	int32_t fd = open_mem_dev();
	if (fd < 0) {
		ret = RM_ERROR_DENIED;
		LOG_ERR(ret);
		goto out_unmap_me;
	}

	mem_range_t range = {
		.base = ipa,
		.size = size,
	};

	crt_err = ioctl(fd, (int32_t)IOCTL_ADD_HEAP, &range);
	if (crt_err < 0) {
		ret = RM_ERROR_DENIED;
		LOG_ERR(ret);
		goto out_close_fd;
	}

	heap->rm_me  = me_cap.r;
	heap->rm_ipa = ipa;
	ret	     = RM_OK;

out_close_fd:
	crt_err = close(fd);
	assert(crt_err == 0);
out_unmap_me:
	if (ret != RM_OK) {
		err = vm_memory_unmap_partial(rm_vm, VM_MEMUSE_NORMAL, me_cap.r,
					      ipa, phys, size);
		assert(err == OK);
	}
out_free_ipa:
	if (ret != RM_OK) {
		error_t free_err = vm_address_range_free(
			rm_vm, VM_MEMUSE_NORMAL, ar_ret.base, ar_ret.size);
		assert(free_err == OK);
	}
out:
	return ret;
}

static void
heap_mgnt_handle_add_memory(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			    void *buf, size_t len)
{
	rm_error_t ret, err;
	uint32_t   heap_handle;
	uint32_t   mp_handle;

	err = parse_heap_memory_req(client_id, buf, len, &heap_handle,
				    &mp_handle);
	if (err != RM_OK) {
		ret = err;
		LOG_ERR(ret);
		goto out;
	}

	memparcel_t *mp = memparcel_lookup_by_target_vmid(VMID_RM, mp_handle);
	if (mp == NULL) {
		ret = RM_ERROR_HANDLE_INVALID;
		LOG_ERR(ret);
		goto out;
	}

	vm_t *rm_vm = vm_lookup(VMID_RM);
	assert(rm_vm != NULL);

	// The memparcel must be owned by the calling VM; it must also be normal
	// memory that has been exclusively lent to RM with full rights.
	if ((memparcel_get_owner(mp) != client_id) ||
	    !memparcel_is_private(mp, rm_vm)) {
		ret = RM_ERROR_DENIED;
		LOG_ERR(ret);
		goto out;
	}

	// The memparcel's refcount must be zero, otherwise it is already being
	// used as a heap region or for some other purpose.
	if (memparcel_get_refcount(mp) != 0U) {
		ret = RM_ERROR_BUSY;
		LOG_ERR(ret);
		goto out;
	}

	// The memparcel must consist of a single contiguous region.
	if (memparcel_get_num_regions(mp) != 1U) {
		ret = RM_ERROR_MEM_INVALID;
		LOG_ERR(ret);
		goto out;
	}

	// To reduce complexity and overhead of managing many small heap
	// regions, we require a minimum size for each heap region.
	size_result_t size_ret = memparcel_get_region_size(mp, 0U);
	assert(size_ret.e == OK);

	if (size_ret.r < MIN_HEAP_BLOCK_SIZE) {
		ret = RM_ERROR_MEM_INVALID;
		LOG_ERR(ret);
		goto out;
	}

	paddr_result_t phys_ret = memparcel_get_phys(mp, 0U);
	assert(phys_ret.e == OK);

	heap_node_t *heap_node = calloc(1U, sizeof(*heap_node));
	if (heap_node == NULL) {
		ret = RM_ERROR_NOMEM;
		LOG_ERR(ret);
		goto out;
	}

	heap_node->mp	 = mp;
	heap_node->phys	 = phys_ret.r;
	heap_node->size	 = size_ret.r;
	heap_node->rm_me = CSPACE_CAP_INVALID;

	if (heap_handle == ROOT_HEAP_HANDLE) {
		// Donate the memparcel's memory to the root partition heap.
		err = donate_mp_heap(heap_node, true);
		if (err != RM_OK) {
			ret = err;
			LOG_ERR(ret);
			goto out_free_heap;
		}

		list_append(heap_node_t, &root_heap_list, heap_node, );
	} else {
		assert(heap_handle == RM_HEAP_HANDLE);

		// Add the memory to the C runtime's heap.
		err = add_rm_crt_heap(heap_node);
		if (err != RM_OK) {
			ret = err;
			goto out_free_heap;
		}

		list_append(heap_node_t, &rm_heap_list, heap_node, );
	}

	memparcel_increase_refcount(mp);
	ret = RM_OK;
	goto out;

out_free_heap:
	free(heap_node);
out:
	rm_standard_reply(client_id, msg_id, seq_num, ret);
}

static rm_error_t
remove_rm_crt_heap(heap_node_t *heap)
{
	rm_error_t ret;
	int32_t	   crt_err;
	vmaddr_t   ipa	= heap->rm_ipa;
	size_t	   size = heap->size;

	vm_t *rm_vm = vm_lookup(VMID_RM);
	assert(rm_vm != NULL);

	// Use memory device to remove the heap from the runtime.
	int32_t fd = open_mem_dev();
	if (fd < 0) {
		ret = RM_ERROR_DENIED;
		LOG_ERR(ret);
		goto out;
	}

	mem_range_t range = {
		.base = ipa,
		.size = size,
	};

	crt_err = ioctl(fd, (int32_t)IOCTL_REMOVE_HEAP, &range);
	if (crt_err < 0) {
		ret = RM_ERROR_BUSY;
		LOG_ERR(ret);
		goto out_close_fd;
	}

	// Sanitize the memory before unmapping from RM.
	(void)memset((void *)ipa, 0, size);
	cache_clean_by_va((void *)ipa, size);

	// Unmap the memparcel extent from RM.
	error_t unmap_err = vm_memory_unmap_partial(
		rm_vm, VM_MEMUSE_NORMAL, heap->rm_me, ipa, heap->phys, size);
	assert(unmap_err == OK);

	// The IPA allocation was aligned to the large page size; re-calculate
	// the allocated address range and free it.
	vmaddr_t aligned_ipa  = util_balign_down(ipa, LARGE_PAGE_SIZE);
	size_t	 aligned_size = ipa + size - aligned_ipa;

	error_t free_err = vm_address_range_free(rm_vm, VM_MEMUSE_NORMAL,
						 aligned_ipa, aligned_size);
	assert(free_err == OK);

	heap->rm_me  = CSPACE_CAP_INVALID;
	heap->rm_ipa = 0U;
	ret	     = RM_OK;

out_close_fd:
	crt_err = close(fd);
	assert(crt_err == 0);
out:
	return ret;
}

static void
heap_mgnt_handle_remove_memory(vmid_t client_id, uint32_t msg_id,
			       uint16_t seq_num, void *buf, size_t len)
{
	rm_error_t ret, err;
	uint32_t   heap_handle;
	uint32_t   mp_handle;

	err = parse_heap_memory_req(client_id, buf, len, &heap_handle,
				    &mp_handle);
	if (err != RM_OK) {
		ret = err;
		LOG_ERR(ret);
		goto out;
	}

	heap_node_t **heap_list = (heap_handle == ROOT_HEAP_HANDLE)
					  ? &root_heap_list
					  : &rm_heap_list;

	heap_node_t *heap_node = NULL;
	loop_list(heap_node, heap_list, )
	{
		if (memparcel_get_handle(heap_node->mp) == mp_handle) {
			break;
		}
	}

	if (heap_node == NULL) {
		ret = RM_ERROR_NORESOURCE;
		LOG_ERR(ret);
		goto out;
	}

	if (heap_handle == ROOT_HEAP_HANDLE) {
		// Attempt to remove the memparcel's memory from the partition
		// heap. This will fail if the memory is still in use by the
		// hypervisor.
		err = donate_mp_heap(heap_node, false);
		if (err != RM_OK) {
			ret = err;
			LOG_ERR(ret);
			goto out;
		}
	} else {
		assert(heap_handle == RM_HEAP_HANDLE);

		err = remove_rm_crt_heap(heap_node);
		if (err != RM_OK) {
			ret = err;
			goto out;
		}
	}

	list_remove(heap_node_t, heap_list, heap_node, );
	memparcel_decrease_refcount(heap_node->mp);
	free(heap_node);
	ret = RM_OK;

out:
	rm_standard_reply(client_id, msg_id, seq_num, ret);
}

static bool
hyp_heap_is_free(const heap_node_t *heap)
{
	cap_id_t partition_cap = rm_get_rm_partition();
	assert(partition_cap != CSPACE_CAP_INVALID);

	partition_query_flags_t flags = partition_query_flags_default();
	partition_query_flags_set_type(&flags,
				       PARTITION_QUERY_TYPE_HEAP_IS_FREE);

	return gunyah_hyp_partition_query(partition_cap, flags, heap->phys,
					  heap->size, 0U) == OK;
}

static bool
crt_heap_is_free(const heap_node_t *heap)
{
	bool ret = false;

	int32_t fd = open_mem_dev();
	if (fd < 0) {
		goto out;
	}

	mem_range_t range = {
		.base = heap->rm_ipa,
		.size = heap->size,
	};

	if (ioctl(fd, (int32_t)IOCTL_HEAP_IS_FREE, &range) == 0) {
		ret = true;
	}

	int32_t err = close(fd);
	assert(err == 0);

out:
	return ret;
}

static rm_error_t
heap_query_is_free(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
		   uint32_t heap_handle)
{
	rm_error_t ret;

	vector_t *mp_vector = vector_init(uint32_t, 8U, 8U);
	if (mp_vector == NULL) {
		ret = RM_ERROR_NOMEM;
		LOG_ERR(ret);
		goto out;
	}

	heap_node_t **heap_list;
	if (heap_handle == ROOT_HEAP_HANDLE) {
		heap_list = &root_heap_list;
	} else if (heap_handle == RM_HEAP_HANDLE) {
		heap_list = &rm_heap_list;
	} else {
		ret = RM_ERROR_HANDLE_INVALID;
		LOG_ERR(ret);
		goto out_deinit;
	}

	heap_node_t *heap_node = NULL;
	loop_list(heap_node, heap_list, )
	{
		bool is_free = (heap_handle == ROOT_HEAP_HANDLE)
				       ? hyp_heap_is_free(heap_node)
				       : crt_heap_is_free(heap_node);
		if (!is_free) {
			continue;
		}

		uint32_t mp_handle = memparcel_get_handle(heap_node->mp);
		error_t	 vec_err   = vector_push_back(mp_vector, mp_handle);
		if (vec_err != OK) {
			ret = rm_error_from_hyp(vec_err);
			goto out_deinit;
		}
	}

	uint32_t num_mps   = (uint32_t)vector_size(mp_vector);
	size_t	 resp_size = ((size_t)num_mps + 2U) * sizeof(uint32_t);

	uint8_t *resp_buf = calloc(1U, resp_size);
	if (resp_buf == NULL) {
		ret = RM_ERROR_NOMEM;
		goto out_deinit;
	}

	ret = RM_OK;

	(void)memscpy(resp_buf, resp_size, &ret, sizeof(ret));
	(void)memscpy(resp_buf + sizeof(uint32_t), resp_size - sizeof(uint32_t),
		      &num_mps, sizeof(num_mps));
	(void)memscpy(resp_buf + (2U * sizeof(uint32_t)),
		      resp_size - (2U * sizeof(uint32_t)),
		      vector_raw_data(mp_vector), num_mps * sizeof(uint32_t));

	rm_error_t rpc_err = rm_rpc_fifo_reply(client_id, msg_id, seq_num,
					       resp_buf, resp_size);
	if (rpc_err != RM_OK) {
		// We cannot recover from errors here
		(void)printf("heap_query: err(%d)\n", rpc_err);
		exit(1);
	}

out_deinit:
	if (mp_vector != NULL) {
		vector_deinit(mp_vector);
	}
out:
	return ret;
}

static rm_error_t
heap_query_stats(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
		 uint32_t heap_handle)
{
	rm_error_t	  ret;
	allocator_stats_t stats = { 0 };

	if (heap_handle == ROOT_HEAP_HANDLE) {
		cap_id_t partition_cap = rm_get_rm_partition();
		assert(partition_cap != CSPACE_CAP_INVALID);

		partition_query_flags_t flags = partition_query_flags_default();
		partition_query_flags_set_type(&flags,
					       PARTITION_QUERY_TYPE_HEAP_STATS);
		allocator_memattr_t attr = allocator_memattr_default();

		error_t hyp_err = gunyah_hyp_partition_query(
			partition_cap, flags, (uintptr_t)&stats, sizeof(stats),
			allocator_memattr_raw(attr));
		if (hyp_err != OK) {
			ret = rm_error_from_hyp(hyp_err);
			LOG_ERR(ret);
			goto out;
		}
	} else if (heap_handle == RM_HEAP_HANDLE) {
		int32_t fd = open_mem_dev();
		if (fd < 0) {
			ret = RM_ERROR_DENIED;
			goto out;
		}

		int32_t crt_err =
			ioctl(fd, (int32_t)IOCTL_HEAP_GET_STATS, &stats);
		assert(crt_err == 0);

		crt_err = close(fd);
		assert(crt_err == 0);
	} else {
		ret = RM_ERROR_HANDLE_INVALID;
		LOG_ERR(ret);
		goto out;
	}

	heap_stats_resp_t resp = { 0 };

	resp.total_low	       = (uint32_t)(stats.total & 0xffffffffU);
	resp.total_high	       = (uint32_t)(stats.total >> 32U);
	resp.allocated_low     = (uint32_t)(stats.allocated & 0xffffffffU);
	resp.allocated_high    = (uint32_t)(stats.allocated >> 32U);
	resp.reserved_low      = (uint32_t)(stats.reserved & 0xffffffffU);
	resp.reserved_high     = (uint32_t)(stats.reserved >> 32U);
	resp.largest_free_low  = (uint32_t)(stats.largest_free & 0xffffffffU);
	resp.largest_free_high = (uint32_t)(stats.largest_free >> 32U);

	rm_reply(client_id, msg_id, seq_num, &resp, sizeof(resp));

	ret = RM_OK;

out:
	return ret;
}

static void
heap_mgnt_handle_query(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
		       void *buf, size_t len)
{
	rm_error_t ret;
	uint32_t   heap_handle;
	uint8_t	   type;

	if (client_id != VMID_HLOS) {
		ret = RM_ERROR_DENIED;
		LOG_ERR(ret);
		goto out;
	}

	if (len != sizeof(heap_query_req_t)) {
		ret = RM_ERROR_MSG_INVALID;
		LOG_ERR(ret);
		goto out;
	}

	heap_query_req_t *req = (heap_query_req_t *)(uintptr_t)buf;
	heap_handle	      = req->heap_handle;
	type		      = req->type;

	switch (type) {
	case HEAP_QUERY_TYPE_IS_FREE:
		ret = heap_query_is_free(client_id, msg_id, seq_num,
					 heap_handle);
		break;
	case HEAP_QUERY_TYPE_STATS:
		ret = heap_query_stats(client_id, msg_id, seq_num, heap_handle);
		break;
	default:
		ret = RM_ERROR_ARGUMENT_INVALID;
		break;
	}

out:
	if (ret != RM_OK) {
		rm_standard_reply(client_id, msg_id, seq_num, ret);
	}
}

bool
heap_mgnt_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
		      void *buf, size_t len)
{
	bool handled = true;

	switch (msg_id) {
	case HEAP_ADD_MEMORY:
		heap_mgnt_handle_add_memory(client_id, msg_id, seq_num, buf,
					    len);
		break;
	case HEAP_REMOVE_MEMORY:
		heap_mgnt_handle_remove_memory(client_id, msg_id, seq_num, buf,
					       len);
		break;
	case HEAP_QUERY:
		heap_mgnt_handle_query(client_id, msg_id, seq_num, buf, len);
		break;
	case HEAP_CREATE:
	case HEAP_DELETE:
	default:
		handled = false;
		break;
	}

	return handled;
}

rm_error_t
heap_mgnt_get_resource_descs(vmid_t self, vmid_t vmid, vector_t *descs)
{
	rm_error_t ret;
	error_t	   err;

	assert(descs != NULL);

	if ((self != VMID_HLOS) || (vmid != VMID_RM)) {
		ret = RM_OK;
		goto out;
	}

	rm_hyp_resource_resp_t item = { 0 };

	item.resource_type   = (uint8_t)RSC_HEAP;
	item.resource_handle = ROOT_HEAP_HANDLE;
	item.resource_label  = ROOT_HEAP_LABEL;

	err = vector_push_back(descs, item);
	if (err != OK) {
		ret = rm_error_from_hyp(err);
		goto out;
	}

	item.resource_handle = RM_HEAP_HANDLE;
	item.resource_label  = RM_HEAP_LABEL;

	err = vector_push_back(descs, item);
	if (err != OK) {
		ret = rm_error_from_hyp(err);
		goto out;
	}

	ret = RM_OK;

out:
	return ret;
}

heap_lookup_me_ret_t
heap_mgnt_lookup_rm_me(uintptr_t addr)
{
	heap_lookup_me_ret_t ret = { .err = ERROR_ADDR_INVALID };

	// Check if the address lies within the base RM extent.
	vmaddr_t rm_ipa	 = rm_get_me_ipa_base();
	size_t	 rm_size = rm_get_me_size();

	if ((addr >= rm_ipa) && (addr < (rm_ipa + rm_size))) {
		ret.me_cap = rm_get_me();
		ret.offset = addr - rm_ipa;
		ret.phys   = rm_ipa_to_pa(addr);
		ret.err	   = OK;
		goto out;
	}

	// Check if the address lies in any additional heap nodes.
	heap_node_t *heap_node = NULL;
	loop_list(heap_node, &rm_heap_list, )
	{
		vmaddr_t heap_ipa  = heap_node->rm_ipa;
		size_t	 heap_size = heap_node->size;
		if ((addr >= heap_ipa) && (addr < (heap_ipa + heap_size))) {
			ret.me_cap = heap_node->rm_me;
			ret.phys   = addr - heap_ipa + heap_node->phys;
			ret.offset = ret.phys;
			ret.err	   = OK;
			break;
		}
	}

out:
	return ret;
}
