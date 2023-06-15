// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rm_types.h>
#include <util.h>
#include <utils/address_range_allocator.h>
#include <utils/list.h>
#include <utils/vector.h>

#include <cache.h>
#include <dt_overlay.h>
#include <event.h>
#include <guest_interface.h>
#include <log.h>
#include <memextent.h>
#include <memparcel.h>
#include <memparcel_msg.h>
#include <platform.h>
#include <platform_vm_config.h>
#include <resource-manager.h>
#include <rm-rpc-fifo.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_creation.h>
#include <vm_memory.h>
#include <vm_mgnt.h>

#include "mem_region.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

typedef struct {
	vmid_t	      vmid;
	uint32_t      attr;
	ipa_region_t *ipa_list;
	count_t	      ipa_alloc_count;
	uint32_t      phandle;
	uint8_t	      rights;
	bool	      phandle_is_external;
	bool	      shared;
	bool	      mapped;
	bool	      contiguous;
} vm_meminfo_t;

typedef enum {
	MEMPARCEL_STATE_INIT,
	MEMPARCEL_STATE_SHARING,
	MEMPARCEL_STATE_SHARED,
} memparcel_state_t;

typedef struct memparcel memparcel_t;

struct memparcel {
	memparcel_t	 *next;
	memparcel_t	 *prev;
	mem_handle_t	  handle;
	cap_id_t	  me_cap;
	size_t		  total_size;
	label_t		  label;
	bool		  label_valid;
	bool		  mem_info_tag_set;
	label_t		  mem_info_tag;
	vmid_t		  owner_vmid;
	memparcel_state_t state;
	uint32_t	  share_count;
	uint8_t		  mem_type;
	uint8_t		  trans_type;
	bool		  sanitize_create;
	bool		  sanitize_reclaim;
	bool		  locked;
	uint16_t	  num_vms;
	uint16_t	  num_attrs;
	vm_meminfo_t	 *vm_list;
	attr_entry_t	 *attr_list;
	region_list_t	 *region_list;
	vm_acl_info_t	 *acl_info;
	size_t		  rm_map_offset;
	size_t		  rm_map_size;
	uintptr_t	  rm_as_range_base;
	size_t		  rm_as_range_size;
};

#pragma clang diagnostic pop

static memparcel_t *mp_list_head;
static mem_handle_t mp_handles;

#define SIZE_2M (2UL * 1024 * 1024)

#define MAX_MEMPARCEL_PER_VM 64U

#define MEMPARCEL_VERBOSE_DEBUG 0

static rm_error_t
memparcel_notify_owner(memparcel_t *mp, vmid_t vmid, bool accepted);

static rm_error_t
memparcel_read_lists(uint8_t *buf, size_t len, uint16_t *acl_entries,
		     uint16_t *sgl_entries, uint16_t *attr_entries,
		     acl_entry_t **acl, sgl_entry_t **sgl,
		     attr_entry_t **attr_list)
{
	rm_error_t err = RM_OK;

	uintptr_t list_address = 0UL;
	uint8_t	 *next_buf = buf, *prev_buf = buf;
	uint16_t  entries = 0U;

	if (acl != NULL) {
		err = rm_rpc_read_list(next_buf, len, &entries,
				       MAX_LIST_ENTRIES, &list_address,
				       sizeof(acl_entry_t), &next_buf);
		if (err != RM_OK) {
			goto out;
		} else {
			*acl = (acl_entry_t *)list_address;

			if (acl_entries != NULL) {
				*acl_entries = entries;
			}

			list_address = 0UL;
		}

		assert(len >= (size_t)(next_buf - prev_buf));
		len -= (size_t)(next_buf - prev_buf);
		prev_buf = next_buf;
	}

	if (sgl != NULL) {
		err = rm_rpc_read_list(next_buf, len, &entries,
				       MAX_LIST_ENTRIES, &list_address,
				       sizeof(sgl_entry_t), &next_buf);
		if (err != RM_OK) {
			goto out;
		} else {
			*sgl = (sgl_entry_t *)list_address;

			if (sgl_entries != NULL) {
				*sgl_entries = (uint16_t)entries;
			}

			list_address = 0UL;
		}

		assert(len >= (size_t)(next_buf - prev_buf));
		len -= (size_t)(next_buf - prev_buf);
		prev_buf = next_buf;
	}

	if (attr_list != NULL) {
		err = rm_rpc_read_list(next_buf, len, &entries,
				       MAX_LIST_ENTRIES, &list_address,
				       sizeof(attr_entry_t), &next_buf);
		if (err != RM_OK) {
			goto out;
		} else {
			*attr_list = (attr_entry_t *)list_address;

			if (attr_entries != NULL) {
				*attr_entries = (uint16_t)entries;
			}

			list_address = 0UL;
		}
	}

	if (len != (size_t)(next_buf - prev_buf)) {
		err = RM_ERROR_MSG_INVALID;
	}

out:
	return err;
}

static bool
vmid_valid(vmid_t vmid)
{
	return (vmid == VMID_HLOS) || (vmid == VMID_RM) ||
	       vm_is_secondary_vm(vmid) || vm_is_peripheral_vm(vmid) ||
	       vm_is_dynamic_vm(vmid);
}

static bool
mem_rights_valid(uint8_t mem_rights)
{
	bool ret;

	switch (mem_rights) {
	case MEM_RIGHTS_R:
	case MEM_RIGHTS_RX:
	case MEM_RIGHTS_RW:
	case MEM_RIGHTS_RWX:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

static bool
addr_valid(uint64_t addr)
{
	return (addr < ADDR_LIMIT) && util_is_baligned(addr, PAGE_SIZE);
}

static pgtable_access_t
mem_rights_to_pgtable_access(uint8_t mem_rights)
{
	pgtable_access_t ret;
	switch (mem_rights) {
	case MEM_RIGHTS_R:
		ret = PGTABLE_ACCESS_R;
		break;
	case MEM_RIGHTS_RX:
		ret = PGTABLE_ACCESS_RX;
		break;
	case MEM_RIGHTS_RW:
		ret = PGTABLE_ACCESS_RW;
		break;
	case MEM_RIGHTS_RWX:
		ret = PGTABLE_ACCESS_RWX;
		break;
	default:
		ret = PGTABLE_ACCESS_NONE;
		break;
	}

	return ret;
}

static bool
mem_attr_valid(uint32_t mem_attr)
{
	bool ret;

	switch (mem_attr) {
	case MEM_ATTR_NORMAL:
	case MEM_ATTR_DEVICE:
	case MEM_ATTR_UNCACHED:
	case MEM_ATTR_CACHED:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

static pgtable_vm_memtype_t
mem_attr_to_map_memtype(uint32_t mem_attr)
{
	pgtable_vm_memtype_t ret;
	switch (mem_attr) {
	case MEM_ATTR_DEVICE:
		ret = PGTABLE_VM_MEMTYPE_DEVICE_NGNRE;
		break;
	case MEM_ATTR_UNCACHED:
		ret = PGTABLE_VM_MEMTYPE_NORMAL_NC;
		break;
	case MEM_ATTR_CACHED:
	case MEM_ATTR_NORMAL:
	default:
		ret = PGTABLE_VM_MEMTYPE_NORMAL_WB;
		break;
	}

	return ret;
}

static memparcel_t *
lookup_memparcel(mem_handle_t handle)
{
	memparcel_t *curr = NULL;

	loop_list(curr, &mp_list_head, )
	{
		if (curr->handle == handle) {
			break;
		}
	}

	return curr;
}

static vm_meminfo_t *
lookup_vm_info(const memparcel_t *mp, vmid_t vmid)
{
	vm_meminfo_t *vm_info = NULL;

	for (uint32_t i = 0U; i < mp->num_vms; i++) {
		if (mp->vm_list[i].vmid == vmid) {
			vm_info = &mp->vm_list[i];
			break;
		}
	}

	return vm_info;
}

static mem_handle_t
allocate_handle(void)
{
	mem_handle_t handle;
	memparcel_t *mp = NULL;

	do {
		handle = mp_handles;
		mp_handles++;
		mp = lookup_memparcel(handle);
	} while (mp != NULL);

	return handle;
}

static void
sanitise_region(cap_id_t me_cap, uint8_t mem_type, paddr_t phys, size_t size)
{
	size_t offset = phys - vm_memory_get_extent_base(mem_type);
	assert(mem_type != MEM_TYPE_IO);

	error_t err = memextent_zero_range(me_cap, offset, size);
	assert(err == OK);
}

static error_t
map_memory_region(vm_t *vm, vm_meminfo_t *vm_info, cap_id_t me_cap,
		  uint8_t mem_type, vmaddr_t ipa, paddr_t phys, size_t size)
{
	vm_memuse_t	 memuse = (mem_type == MEM_TYPE_IO) ? VM_MEMUSE_DEVICE
							    : VM_MEMUSE_NORMAL;
	size_t		 offset = phys - vm_memory_get_extent_base(mem_type);
	pgtable_access_t access = mem_rights_to_pgtable_access(vm_info->rights);
	pgtable_vm_memtype_t map_memtype =
		mem_attr_to_map_memtype(vm_info->attr);

	return vm_memory_map_partial(vm, memuse, me_cap, ipa, offset, size,
				     access, map_memtype);
}

static error_t
unmap_memory_region(vm_t *vm, cap_id_t me_cap, uint8_t mem_type, vmaddr_t ipa,
		    paddr_t phys, size_t size)
{
	vm_memuse_t memuse = (mem_type == MEM_TYPE_IO) ? VM_MEMUSE_DEVICE
						       : VM_MEMUSE_NORMAL;
	size_t	    offset = phys - vm_memory_get_extent_base(mem_type);

	return vm_memory_unmap_partial(vm, memuse, me_cap, ipa, offset, size);
}

static void
region_list_cleanup_regions(vm_t *vm, cap_id_t me_cap, uint8_t mem_type,
			    vm_acl_info_t *acl_info, bool sanitize,
			    region_list_t *region_list)
{
	assert(vm != NULL);
	assert(region_list != NULL);

	index_t	     i;
	mem_region_t region;

	vm_memory_batch_start();

	region_list_loop(region_list, region, i)
	{
		paddr_t phys = mem_region_get_phys(region);
		size_t	size = mem_region_get_size(region);

		if (sanitize) {
			sanitise_region(me_cap, mem_type, phys, size);
		}

		error_t err = vm_memory_donate_extent(
			vm, mem_type, acl_info, me_cap, phys, size, false);
		assert(err == OK);
	}

	vm_memory_batch_end();
}

static void
delete_memparcel(vm_t *vm, memparcel_t *mp)
{
	list_remove(memparcel_t, &mp_list_head, mp, );

	if (mp->me_cap != CSPACE_CAP_INVALID) {
		memextent_delete(mp->me_cap);
	}

	vm_memory_free_acl_info(mp->acl_info);
	region_list_destroy(mp->region_list);
	free(mp->attr_list);
	free(mp->vm_list);
	free(mp);

	vm->mp_count--;
}

static rm_error_t
add_sgl_to_mp(vm_t *vm, memparcel_t *mp, vm_meminfo_t *owner_info,
	      uint16_t sgl_entries, sgl_entry_t *sgl, bool done)
{
	rm_error_t err = RM_OK;

	cap_id_t       me_cap	  = mp->me_cap;
	uint8_t	       mem_type	  = mp->mem_type;
	uint8_t	       trans_type = mp->trans_type;
	vm_acl_info_t *acl_info	  = mp->acl_info;

	vm_memuse_t memuse  = (mem_type == MEM_TYPE_IO) ? VM_MEMUSE_DEVICE
							: VM_MEMUSE_NORMAL;
	count_t	    old_len = region_list_get_len(mp->region_list);

	vm_memory_batch_start();

	uint16_t sgl_idx = 0U;
	size_t	 offset	 = 0U;
	error_t	 hyp_err;
	while (sgl_idx < sgl_entries) {
		vmaddr_t vaddr = sgl[sgl_idx].ipa + offset;
		size_t	 vsize = sgl[sgl_idx].size - offset;
		if (!addr_valid(vaddr) || !addr_valid(vsize)) {
			err = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}

		vm_memory_result_t lookup_ret =
			vm_memory_lookup(vm, memuse, vaddr, vsize);
		if (lookup_ret.err != OK) {
			printf("memparcel: Failed lookup of VM memory %d  %lX  %lX\n",
			       lookup_ret.err, vaddr, vsize);
			err = RM_ERROR_MEM_INVALID;
			goto out;
		}

		paddr_t paddr = lookup_ret.phys;
		size_t	psize = lookup_ret.size;
		assert(addr_valid(paddr) && addr_valid(psize));

#if MEMPARCEL_VERBOSE_DEBUG
		printf("sgl[%d]: vaddr: %lx vsize: %lx paddr: %lx psize: %lx\n",
		       sgl_idx, vaddr, vsize, paddr, psize);
#endif

		if (trans_type == TRANS_TYPE_SHARE) {
			assert(owner_info != NULL);
			// Add owner's mapping to the memparcel extent. The
			// mapping will be applied after donation.
			hyp_err = map_memory_region(vm, owner_info, me_cap,
						    mem_type, vaddr, paddr,
						    psize);
			if (hyp_err != OK) {
				printf("memparcel: Map in owner failed %d\n",
				       hyp_err);
				err = RM_ERROR_MAP_FAILED;
				goto out;
			}
		} else {
			// The memory will be unmapped when it is donated to the
			// memparcel's extent, nothing to do.
		}

		hyp_err = vm_memory_donate_extent(vm, mem_type, acl_info,
						  me_cap, paddr, psize, true);
		if (hyp_err != OK) {
			printf("memparcel: donate to mp extent failed %d\n",
			       hyp_err);
			err = RM_ERROR_MEM_INVALID;
			goto out;
		}

		mem_region_t region = mem_region_init(paddr, psize, vaddr);

		err = region_list_push_back(mp->region_list, region);
		if (err != RM_OK) {
			printf("memparcel: failed to push back region\n");
			// Revert the earlier donation.
			hyp_err = vm_memory_donate_extent(vm, mem_type,
							  acl_info, me_cap,
							  paddr, psize, false);
			assert(hyp_err == OK);
			goto out;
		}

		if (mp->sanitize_create) {
			sanitise_region(me_cap, mem_type, paddr, psize);
		}

		mp->total_size += psize;
		offset += psize;
		if (offset == sgl[sgl_idx].size) {
			sgl_idx++;
			offset = 0U;
		}
	}

	if (done) {
		err = region_list_finalize(mp->region_list);
		if (err != RM_OK) {
			goto out;
		}

		mp->state = MEMPARCEL_STATE_SHARING;
	}

out:
	if (err != RM_OK) {
		while (region_list_get_len(mp->region_list) > old_len) {
			mem_region_t region =
				region_list_pop_back(mp->region_list);

			paddr_t phys = mem_region_get_phys(region);
			size_t	size = mem_region_get_size(region);

			hyp_err = vm_memory_donate_extent(vm, mem_type,
							  acl_info, me_cap,
							  phys, size, false);
			assert(hyp_err == OK);
		}
	}

	vm_memory_batch_end();

	return err;
}

memparcel_construct_ret_t
memparcel_construct(vmid_t owner_vmid, uint16_t acl_entries,
		    uint16_t sgl_entries, uint16_t attr_entries,
		    acl_entry_t *acl, sgl_entry_t *sgl, attr_entry_t *attr_list,
		    uint32_t label, bool label_valid, uint8_t mem_type,
		    uint8_t trans_type, bool vm_init, uint8_t flags)
{
	rm_error_t     err	      = RM_OK;
	memparcel_t   *mp	      = NULL;
	cap_id_t       me_cap	      = CSPACE_CAP_INVALID;
	region_list_t *region_list    = NULL;
	vm_meminfo_t  *vm_list	      = NULL;
	attr_entry_t  *attr_list_copy = NULL;
	vm_meminfo_t  *owner_info     = NULL;
	vm_acl_info_t *acl_info	      = NULL;

	vm_t *vm = vm_lookup(owner_vmid);
	assert(vm != NULL);
	assert(vm->vm_config != NULL);

	if ((acl_entries == 0U) || (sgl_entries == 0U) || (acl == NULL) ||
	    (sgl == NULL)) {
		err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if ((trans_type == TRANS_TYPE_DONATE) && (acl_entries > 1U)) {
		// Memory can only be donated to a single VM.
		err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (vm->mp_count == MAX_MEMPARCEL_PER_VM) {
		printf("Reached memparcel limit for VM %d\n", owner_vmid);
		err = RM_ERROR_DENIED;
		goto out;
	}

	if (acl_entries > MAX_LIST_ENTRIES || sgl_entries > MAX_LIST_ENTRIES ||
	    attr_entries > MAX_LIST_ENTRIES) {
		err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	bool sanitize = false;
	if ((flags & MEM_CREATE_FLAG_SANITIZE) != 0U) {
		if (mem_type == MEM_TYPE_IO) {
			err = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}
		sanitize = true;
	}

	bool append = (flags & MEM_CREATE_FLAG_APPEND) != 0U;

	mp = calloc(1U, sizeof(*mp));
	if (mp == NULL) {
		err = RM_ERROR_NOMEM;
		goto out;
	}

	cap_id_result_t cap_ret = vm_memory_create_extent(mem_type);
	if (cap_ret.e != OK) {
		err = RM_ERROR_NOMEM;
		goto out;
	}

	me_cap = cap_ret.r;

	region_list = region_list_init();
	if (region_list == NULL) {
		err = RM_ERROR_NOMEM;
		goto out;
	}

	vm_list = calloc(acl_entries, sizeof(*vm_list));
	if (vm_list == NULL) {
		err = RM_ERROR_NOMEM;
		goto out;
	}

	if (attr_entries > 0U) {
		attr_list_copy = calloc(attr_entries, sizeof(*attr_list_copy));
		if (attr_list_copy == NULL) {
			err = RM_ERROR_NOMEM;
			goto out;
		}
	}

	mp->next	     = NULL;
	mp->prev	     = NULL;
	mp->handle	     = allocate_handle();
	mp->me_cap	     = me_cap;
	mp->total_size	     = 0U;
	mp->label	     = label;
	mp->label_valid	     = label_valid;
	mp->owner_vmid	     = owner_vmid;
	mp->trans_type	     = trans_type;
	mp->state	     = MEMPARCEL_STATE_INIT;
	mp->share_count	     = 0U;
	mp->mem_type	     = mem_type;
	mp->sanitize_create  = sanitize;
	mp->sanitize_reclaim = false;
	mp->locked	     = false;
	mp->num_vms	     = acl_entries;
	mp->num_attrs	     = attr_entries;
	mp->vm_list	     = vm_list;
	mp->region_list	     = region_list;
	mp->attr_list	     = attr_list_copy;
	mp->acl_info	     = NULL;

#if MEMPARCEL_VERBOSE_DEBUG
	printf("memparcel: create 0x%x, label 0x%x\n", (unsigned int)mp->handle,
	       (unsigned int)(label_valid ? mp->label : -1U));
#endif

	uint8_t	 max_rights    = (mem_type == MEM_TYPE_IO) ? MEM_RIGHTS_RW
							   : MEM_RIGHTS_RWX;
	uint32_t default_attrs = (mem_type == MEM_TYPE_IO) ? MEM_ATTR_DEVICE
							   : MEM_ATTR_NORMAL;
	for (uint32_t i = 0U; i < acl_entries; i++) {
		for (uint32_t j = 0U; j < i; j++) {
			if (acl[i].vmid == acl[j].vmid) {
				printf("memparcel: acl[%i] duplicate vmid",
				       (int)i);
				err = RM_ERROR_ARGUMENT_INVALID;
				goto out;
			}
		}

		if (!vmid_valid(acl[i].vmid) ||
		    !mem_rights_valid(acl[i].rights)) {
			printf("memparcel: acl[%d]: invalid vmid or rights\n",
			       (int)i);
			err = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}

		if ((mem_type == MEM_TYPE_IO) &&
		    ((acl[i].rights & MEM_RIGHTS_X) != 0U)) {
			printf("memparcel: acl[%d]: invalid IO rights\n",
			       (int)i);
			err = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}

		// If donating, we must give the other VM full rights.
		if ((trans_type == TRANS_TYPE_DONATE) &&
		    (acl[i].rights != max_rights)) {
			err = RM_ERROR_DENIED;
			goto out;
		}

		vm_list[i].vmid	   = acl[i].vmid;
		vm_list[i].rights  = acl[i].rights;
		vm_list[i].attr	   = default_attrs;
		vm_list[i].shared  = false;
		vm_list[i].phandle = DTO_PHANDLE_UNSET;

		if (owner_vmid == acl[i].vmid) {
			owner_info = &vm_list[i];
		}
	}

	// The owner VM should only be included in the ACL for MEM_SHARE
	if (((trans_type == TRANS_TYPE_SHARE) && (owner_info == NULL)) ||
	    ((trans_type != TRANS_TYPE_SHARE) && (owner_info != NULL))) {
		printf("memparcel: invalid share request\n");
		err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	vm_acl_info_result_t acl_ret = vm_memory_get_acl_info(
		vm, mem_type, trans_type, acl, acl_entries, vm_init);
	if (acl_ret.err != OK) {
		printf("memparcel: Failed to get VM ACL info %d\n",
		       acl_ret.err);
		err = RM_ERROR_DENIED;
		goto out;
	}

	acl_info     = acl_ret.info;
	mp->acl_info = acl_info;

	for (uint16_t i = 0U; i < attr_entries; i++) {
		for (uint16_t j = 0U; j < i; j++) {
			if (attr_list[i].vmid == attr_list[j].vmid) {
				printf("memparcel: attr_list[%i] duplicate vmid",
				       (int)i);
				err = RM_ERROR_ARGUMENT_INVALID;
				goto out;
			}
		}

		if (!mem_attr_valid(attr_list[i].attr)) {
			printf("memparcel: invalid attr[%d]", (int)i);
			err = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}

		// Only device attrs can be used for IO memory.
		if ((mem_type == MEM_TYPE_IO) !=
		    (attr_list[i].attr == MEM_ATTR_DEVICE)) {
			err = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}

		// If donating, we only support the default attributes.
		if ((trans_type == TRANS_TYPE_DONATE) &&
		    (attr_list[i].attr != default_attrs)) {
			err = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}

		vm_meminfo_t *vm_info = lookup_vm_info(mp, attr_list[i].vmid);
		if (vm_info != NULL) {
			vm_info->attr = attr_list[i].attr;
		} else {
			err = RM_ERROR_VMID_INVALID;
			goto out;
		}

		mp->attr_list[i].attr = attr_list[i].attr;
		mp->attr_list[i].vmid = attr_list[i].vmid;
	}

	err = add_sgl_to_mp(vm, mp, owner_info, sgl_entries, sgl, !append);
	if (err != RM_OK) {
		goto out;
	}

	list_append(memparcel_t, &mp_list_head, mp, );

	vm->mp_count++;

	err = RM_OK;
out:
	if ((err != RM_OK) && (mp != NULL)) {
		printf("memparcel_construct 0x%x label 0x%x ret %d\n",
		       (uint32_t)mp->handle,
		       (label_valid ? mp->label : (uint32_t)-1), err);
	}

	memparcel_construct_ret_t ret;

	if (err != RM_OK) {
		free(mp);
		free(vm_list);
		free(attr_list_copy);
		if (region_list != NULL) {
			region_list_destroy(region_list);
		}
		if (me_cap != CSPACE_CAP_INVALID) {
			memextent_delete(cap_ret.r);
		}
		vm_memory_free_acl_info(acl_info);
		ret.err	   = err;
		ret.handle = 0U;
	} else {
		ret.err	   = RM_OK;
		ret.handle = mp->handle;
	}

	return ret;
}

static void
memparcel_create(vmid_t vmid, uint32_t msg_id, uint16_t seq_num, uint8_t *buf,
		 size_t len)
{
	rm_error_t err;
	uint8_t	   mem_type, trans_type, flags;
	uint32_t   handle = MEMPARCEL_INVALID_HANDLE;
	uint32_t   label;

	char *type_str;
	if (msg_id == MEM_LEND) {
		trans_type = TRANS_TYPE_LEND;
		type_str   = "LEND";
	} else if (msg_id == MEM_SHARE) {
		trans_type = TRANS_TYPE_SHARE;
		type_str   = "SHARE";
	} else if (msg_id == MEM_DONATE) {
		trans_type = TRANS_TYPE_DONATE;
		type_str   = "DONATE";
	} else {
		type_str = " unknown create";
		err	 = RM_ERROR_UNIMPLEMENTED;
		goto out;
	}

	if (len < sizeof(memparcel_create_req_t)) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	memparcel_create_req_t *req = (memparcel_create_req_t *)(uintptr_t)buf;

	mem_type = req->mem_type;
	flags	 = req->flags;
	label	 = req->label;

	uint16_t      acl_entries  = 0U;
	uint16_t      sgl_entries  = 0U;
	uint16_t      attr_entries = 0U;
	acl_entry_t  *acl	   = NULL;
	sgl_entry_t  *sgl	   = NULL;
	attr_entry_t *attr_list	   = NULL;

	size_t list_offset = offsetof(memparcel_create_req_t, acl_entries);
	err = memparcel_read_lists(buf + list_offset, len - list_offset,
				   &acl_entries, &sgl_entries, &attr_entries,
				   &acl, &sgl, &attr_list);
	if (err != RM_OK) {
		goto out;
	}

	memparcel_construct_ret_t mp_r = memparcel_construct(
		vmid, acl_entries, sgl_entries, attr_entries, acl, sgl,
		attr_list, label, true, mem_type, trans_type, false, flags);
	err = mp_r.err;

	if (err == RM_OK) {
		handle = mp_r.handle;
	}

out:
	if (err == RM_OK) {
		memparcel_handle_resp_t resp = {
			.handle = handle,
		};

		rm_reply(vmid, msg_id, seq_num, &resp, sizeof(resp));
	} else {
		printf("MEM_%s VM %d ret %d\n", type_str, vmid, err);
		rm_standard_reply(vmid, msg_id, seq_num, err);
	}
}

static rm_error_t
memparcel_do_append(vmid_t vmid, mem_handle_t handle, uint8_t flags,
		    uint16_t sgl_entries, sgl_entry_t *sgl)
{
	rm_error_t err = RM_OK;

	if ((sgl_entries == 0U) || (sgl == NULL)) {
		err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	memparcel_t *mp = lookup_memparcel(handle);
	if (mp == NULL) {
		err = RM_ERROR_HANDLE_INVALID;
		goto out;
	}

	if (vmid != mp->owner_vmid) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	if (mp->state != MEMPARCEL_STATE_INIT) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	vm_t *vm = vm_lookup(vmid);
	if (vm == NULL) {
		err = RM_ERROR_VMID_INVALID;
		goto out;
	}

	vm_meminfo_t *owner_info = lookup_vm_info(mp, vmid);
	assert((mp->trans_type != TRANS_TYPE_SHARE) || (owner_info != NULL));

	bool done = (flags & MEM_APPEND_FLAG_DONE) != 0U;

	err = add_sgl_to_mp(vm, mp, owner_info, sgl_entries, sgl, done);
	if (err != RM_OK) {
		goto out;
	}

out:
	return err;
}

static void
memparcel_append(vmid_t vmid, uint16_t seq_num, uint8_t *buf, size_t len)
{
	rm_error_t   err    = RM_OK;
	mem_handle_t handle = MEMPARCEL_INVALID_HANDLE;

	if (len < sizeof(memparcel_append_req_t)) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	memparcel_append_req_t *req = (memparcel_append_req_t *)(uintptr_t)buf;

	handle			 = req->handle;
	uint8_t	     flags	 = req->flags;
	uint16_t     sgl_entries = 0U;
	sgl_entry_t *sgl	 = NULL;

	size_t list_offset = offsetof(memparcel_append_req_t, sgl_entries);
	err = memparcel_read_lists(buf + list_offset, len - list_offset, NULL,
				   &sgl_entries, NULL, NULL, &sgl, NULL);
	if (err != RM_OK) {
		goto out;
	}

	err = memparcel_do_append(vmid, handle, flags, sgl_entries, sgl);

out:
	printf("MEM_APPEND VM %d H %d ret %d\n", vmid, (int)handle, err);

	rm_standard_reply(vmid, MEM_APPEND, seq_num, err);
}

static rm_error_t
memparcel_do_accept(vmid_t vmid, uint16_t acl_entries, uint16_t sgl_entries,
		    uint16_t attr_entries, const acl_entry_t *acl,
		    const sgl_entry_t *sgl, const attr_entry_t *attr_list,
		    vmid_t map_vmid, mem_handle_t handle, uint32_t label,
		    uint8_t mem_type, uint8_t trans_type, uint8_t flags,
		    count_t *resp_entries,
		    sgl_entry_t (*resp_sgl)[MAX_LIST_ENTRIES],
		    uint8_t *resp_flags);

static void
memparcel_handle_accept(vmid_t vmid, uint16_t seq_num, uint8_t *buf, size_t len)
{
	rm_error_t		     err	 = RM_OK;
	memparcel_accept_sgl_resp_t *resp	 = NULL;
	size_t			     resp_size	 = 0U;
	uint16_t		     sgl_entries = 0U;
	mem_handle_t		     handle	 = MEMPARCEL_INVALID_HANDLE;

	sgl_entry_t(*resp_sgl)[MAX_LIST_ENTRIES] = NULL;
	uint8_t *resp_flags			 = NULL;
	count_t	 resp_entries			 = 0U;

	if (len < sizeof(memparcel_accept_req_t)) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	memparcel_accept_req_t *req = (memparcel_accept_req_t *)(uintptr_t)buf;

	handle			   = req->handle;
	uint8_t	      mem_type	   = req->mem_type;
	uint8_t	      trans_type   = req->trans_type;
	uint8_t	      flags	   = req->flags;
	uint32_t      label	   = req->label;
	uint16_t      acl_entries  = 0U;
	uint16_t      attr_entries = 0U;
	acl_entry_t  *acl	   = NULL;
	sgl_entry_t  *sgl	   = NULL;
	attr_entry_t *attr_list	   = NULL;

	size_t list_offset = offsetof(memparcel_accept_req_t, acl_entries);
	err = memparcel_read_lists(buf + list_offset, len - list_offset,
				   &acl_entries, &sgl_entries, &attr_entries,
				   &acl, &sgl, &attr_list);
	if (err != RM_OK) {
		goto out;
	}

	const size_t map_vmid_offset =
		offsetof(memparcel_accept_req_t, map_vmid) +
		(acl_entries * sizeof(acl_entry_t));
	vmid_t map_vmid = *(uint16_t *)((uintptr_t)buf + map_vmid_offset);

	if (sgl_entries == 0U) {
		resp_size = sizeof(memparcel_accept_sgl_resp_t) +
			    (sizeof(sgl_entry_t) * MAX_LIST_ENTRIES);
		char *resp_ptr = calloc(1U, resp_size);
		if (resp_ptr == NULL) {
			err = RM_ERROR_NOMEM;
			goto out;
		}
		uintptr_t resp_buffer = (uintptr_t)resp_ptr;
		resp	   = (memparcel_accept_sgl_resp_t *)resp_buffer;
		resp_sgl   = (sgl_entry_t(*)[MAX_LIST_ENTRIES])(resp_buffer +
								sizeof(*resp));
		resp_flags = &resp->flags;
	}

	err = memparcel_do_accept(vmid, acl_entries, sgl_entries, attr_entries,
				  acl, sgl, attr_list, map_vmid, handle, label,
				  mem_type, trans_type, flags, &resp_entries,
				  resp_sgl, resp_flags);

out:
	printf("MEM_ACCEPT VM %d H %d ret %d\n", vmid, (int)handle, err);

	if ((err == RM_OK) && (resp != NULL)) {
		assert(resp_entries <= MAX_LIST_ENTRIES);

		resp->err	  = RM_OK;
		resp->sgl_entries = (uint16_t)resp_entries;
		resp_size	  = sizeof(memparcel_accept_sgl_resp_t) +
			    (sizeof(sgl_entry_t) * resp_entries);

		err = rm_rpc_fifo_reply(vmid, MEM_ACCEPT, seq_num, resp,
					resp_size);
		if (err != RM_OK) {
			free(resp);
			printf("memparcel_accept: error sending reply %d", err);
			exit(1);
		}
	} else {
		rm_standard_reply(vmid, MEM_ACCEPT, seq_num, err);
		if (resp != NULL) {
			free(resp);
		}
	}
}

rm_error_t
memparcel_accept(vmid_t vmid, uint16_t acl_entries, uint16_t sgl_entries,
		 uint16_t attr_entries, const acl_entry_t *acl,
		 const sgl_entry_t *sgl, const attr_entry_t *attr_list,
		 vmid_t map_vmid, mem_handle_t handle, uint32_t label,
		 uint8_t mem_type, uint8_t trans_type, uint8_t flags)
{
	return memparcel_do_accept(vmid, acl_entries, sgl_entries, attr_entries,
				   acl, sgl, attr_list, map_vmid, handle, label,
				   mem_type, trans_type, flags, NULL, NULL,
				   NULL);
}

memparcel_accept_rm_donation_ret_t
memparcel_accept_rm_donation(mem_handle_t handle, uint8_t rights,
			     uint8_t mem_type)
{
	memparcel_accept_rm_donation_ret_t ret = { 0 };

	acl_entry_t acl_accept[1U] = { { .vmid = VMID_RM, .rights = rights } };
	uint8_t	    accept_flags   = MEM_ACCEPT_FLAG_DONE |
			       MEM_ACCEPT_FLAG_MAP_CONTIGUOUS |
			       MEM_ACCEPT_FLAG_VALIDATE_ACL_ATTR;

	sgl_entry_t(*resp_sgl)[MAX_LIST_ENTRIES] =
		calloc(MAX_LIST_ENTRIES, sizeof(sgl_entry_t));
	if (resp_sgl == NULL) {
		ret.err = RM_ERROR_NOMEM;
		goto out;
	}

	rm_error_t err = memparcel_do_accept(
		VMID_RM, util_array_size(acl_accept), 0U, 0U, acl_accept, NULL,
		NULL, 0U, handle, 0U, mem_type, TRANS_TYPE_DONATE, accept_flags,
		NULL, resp_sgl, NULL);
	if (err != RM_OK) {
		ret.err = err;
		goto out;
	}

	ret.ptr	 = (void *)(*resp_sgl)[0].ipa;
	ret.size = (*resp_sgl)[0].size;
	ret.err	 = RM_OK;

out:
	if (resp_sgl != NULL) {
		free(resp_sgl);
	}

	return ret;
}

static vm_address_range_result_t
alloc_as_range(vm_t *vm, uint8_t mem_type, vmaddr_t ipa, paddr_t phys,
	       size_t size)
{
	vm_memuse_t memuse    = (mem_type == MEM_TYPE_IO) ? VM_MEMUSE_DEVICE
							  : VM_MEMUSE_NORMAL;
	size_t	    alignment = (size >= SIZE_2M) ? SIZE_2M : PAGE_SIZE;

	return vm_address_range_alloc(vm, memuse, ipa, phys, size, alignment);
}

static rm_error_t
validate_as_tag(paddr_t phys, size_t size, address_range_tag_t ipa_tag)
{
	address_range_tag_t phys_tag =
		vm_memory_get_phys_address_tag(phys, size);

	return ((ipa_tag & phys_tag) == ipa_tag) ? RM_OK : RM_ERROR_MEM_INVALID;
}

static void
free_as_range(vm_t *vm, uint8_t mem_type, vmaddr_t ipa, size_t size)
{
	vm_memuse_t memuse = (mem_type == MEM_TYPE_IO) ? VM_MEMUSE_DEVICE
						       : VM_MEMUSE_NORMAL;

	error_t err = vm_address_range_free(vm, memuse, ipa, size);
	assert(err == OK);
}

static void
free_allocated_ipas(vm_t *vm, memparcel_t *mp, vm_meminfo_t *vm_info,
		    index_t start_idx, count_t alloc_count)
{
	if (vm_info->contiguous) {
		assert((start_idx == 0U) && (alloc_count == 1U));
		vmaddr_t ipa = ipa_region_get_ipa(vm_info->ipa_list[0]);
		free_as_range(vm, mp->mem_type, ipa, mp->total_size);
	} else {
		assert((start_idx + alloc_count) <=
		       region_list_get_len(mp->region_list));
		index_t	     i;
		mem_region_t region;
		region_list_loop_range(mp->region_list, region, i, start_idx,
				       start_idx + alloc_count)
		{
			vmaddr_t ipa = ipa_region_get_ipa(vm_info->ipa_list[i]);
			size_t	 size = mem_region_get_size(region);
			free_as_range(vm, mp->mem_type, ipa, size);
		}
	}
}

static vmaddr_t
vm_info_get_ipa(vm_meminfo_t *vm_info, index_t i, size_t offset)
{
	vmaddr_t ipa;

	assert(vm_info != NULL);

	if (vm_info->contiguous) {
		ipa = ipa_region_get_ipa(vm_info->ipa_list[0]) + offset;
	} else {
		ipa = ipa_region_get_ipa(vm_info->ipa_list[i]);
	}

	return ipa;
}

static void
add_to_accepted_list(vm_t *vm, memparcel_t *mp)
{
	assert(vm != NULL);
	assert(vm->vm_config != NULL);
	assert(mp != NULL);

	error_t e = vector_push_back(vm->vm_config->accepted_memparcels, mp);
	assert(e == OK);
}

static void
remove_from_accepted_list(vm_t *vm, memparcel_t *mp)
{
	assert(vm != NULL);
	assert(vm->vm_config != NULL);
	assert(mp != NULL);

	vector_t *mp_vector = vm->vm_config->accepted_memparcels;
	for (index_t i = 0U; i < vector_size(mp_vector); i++) {
		memparcel_t *mp_search = vector_at(memparcel_t *, mp_vector, i);
		if (mp_search == mp) {
			vector_delete(mp_vector, i);
			break;
		}
	}
}

static rm_error_t
memparcel_do_accept(vmid_t vmid, uint16_t acl_entries, uint16_t sgl_entries,
		    uint16_t attr_entries, const acl_entry_t *acl,
		    const sgl_entry_t *sgl, const attr_entry_t *attr_list,
		    vmid_t map_vmid, mem_handle_t handle, uint32_t label,
		    uint8_t mem_type, uint8_t trans_type, uint8_t flags,
		    count_t *resp_entries,
		    sgl_entry_t (*resp_sgl)[MAX_LIST_ENTRIES],
		    uint8_t *resp_flags)
{
	assert((acl_entries == 0U) || (acl != NULL));
	assert((sgl_entries == 0U) || (sgl != NULL));
	assert((attr_entries == 0U) || (attr_list != NULL));

	rm_error_t    err = RM_OK;
	error_t	      hyp_err;
	vm_meminfo_t *vm_info	    = NULL;
	ipa_region_t *ipa_list	    = NULL;
	bool	      accept_done   = (flags & MEM_ACCEPT_FLAG_DONE) != 0U;
	bool	      batch_started = false;

	memparcel_t *mp = lookup_memparcel(handle);
	if (mp == NULL) {
		err = RM_ERROR_HANDLE_INVALID;
		goto out;
	}

	if ((mem_type != mp->mem_type) || (trans_type != mp->trans_type)) {
		err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (((flags & MEM_ACCEPT_FLAG_VALIDATE_SANITIZED) != 0U) &&
	    !mp->sanitize_create) {
		err = RM_ERROR_VALIDATE_FAILED;
		goto out;
	}

	if ((flags & MEM_ACCEPT_FLAG_VALIDATE_LABEL) != 0U) {
		if (label != mp->label) {
			err = RM_ERROR_VALIDATE_FAILED;
			goto out;
		}
	}

	if ((flags & MEM_ACCEPT_FLAG_VALIDATE_ACL_ATTR) != 0U) {
		if ((acl_entries != mp->num_vms) ||
		    (attr_entries != mp->num_attrs)) {
			err = RM_ERROR_VALIDATE_FAILED;
			goto out;
		}

		if (acl == NULL) {
			err = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}

		for (uint32_t i = 0U; i < acl_entries; i++) {
			if ((acl[i].vmid != mp->vm_list[i].vmid) ||
			    (acl[i].rights != mp->vm_list[i].rights)) {
				err = RM_ERROR_VALIDATE_FAILED;
				goto out;
			}
		}

		for (uint16_t i = 0U; i < attr_entries; i++) {
			if ((attr_list[i].attr != mp->attr_list[i].attr) ||
			    (attr_list[i].vmid != mp->attr_list[i].vmid)) {
				err = RM_ERROR_VALIDATE_FAILED;
				goto out;
			}
		}
	}

	// Only map to self currently supported
	if ((flags & MEM_ACCEPT_FLAG_MAP_OTHER) == 0U) {
		if (map_vmid != 0U) {
			err = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}
		map_vmid = vmid;
	} else {
		err = RM_ERROR_DENIED;
		goto out;
	}

	vm_t *vm = vm_lookup(map_vmid);
	if (vm == NULL) {
		err = RM_ERROR_VMID_INVALID;
		goto out;
	}

	vm_info = lookup_vm_info(mp, map_vmid);
	if (vm_info == NULL) {
		err = RM_ERROR_VMID_INVALID;
		goto out;
	}

	if ((vm_info->vmid == mp->owner_vmid) || vm_info->mapped) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	bool contiguous = false;
	if ((flags & MEM_ACCEPT_FLAG_MAP_CONTIGUOUS) != 0U) {
		if (mem_type != MEM_TYPE_NORMAL) {
			err = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}

		if ((vm_info->ipa_list != NULL) && !vm_info->contiguous) {
			err = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}

		contiguous = true;
	}

	vm_meminfo_t *map_vm = lookup_vm_info(mp, map_vmid);
	if (map_vm == NULL) {
		err = RM_ERROR_VMID_INVALID;
		goto out;
	}

	if ((flags & MEM_ACCEPT_FLAG_SANITIZE) != 0U) {
		if (mp->mem_type == MEM_TYPE_IO) {
			err = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}

		// VM must have write access to sanitize
		if ((vm_info->rights & MEM_RIGHTS_W) == 0U) {
			err = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}

		mp->sanitize_reclaim = true;
	}

	count_t num_mappings =
		contiguous ? 1U : region_list_get_len(mp->region_list);
	assert(vm_info->ipa_alloc_count <= num_mappings);

	count_t num_ipa_alloc = util_min(
		num_mappings - vm_info->ipa_alloc_count, MAX_LIST_ENTRIES);

	if (sgl_entries == 0U) {
		if ((resp_flags != NULL) && ((vm_info->ipa_alloc_count +
					      num_ipa_alloc) < num_mappings)) {
			*resp_flags |= MEM_ACCEPT_RESP_FLAG_INCOMPLETE;
		}
		if (resp_entries != NULL) {
			*resp_entries = num_ipa_alloc;
		}
	} else if (sgl_entries <= num_ipa_alloc) {
		num_ipa_alloc = sgl_entries;
	} else {
		err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (vm_info->ipa_list == NULL) {
		assert(vm_info->ipa_alloc_count == 0U);

		ipa_list = calloc(num_mappings, sizeof(*ipa_list));
		if (ipa_list == NULL) {
			err = RM_ERROR_NOMEM;
			goto out;
		}

		vm_info->ipa_list   = ipa_list;
		vm_info->contiguous = contiguous;
	}

	cap_id_t map_me_cap = (trans_type == TRANS_TYPE_DONATE)
				      ? vm_memory_get_owned_extent(vm, mem_type)
				      : mp->me_cap;

	index_t	     i;
	mem_region_t region;
	count_t	     alloc_count   = 0U;
	count_t	     donated_count = 0U;
	count_t	     map_count	   = 0U;
	size_t	     offset	   = 0U;

	if (num_ipa_alloc == 0U) {
		goto do_mapping;
	}

	if (contiguous) {
		vmaddr_t alloc_ipa = INVALID_ADDRESS;
		if (sgl_entries == 1U) {
			if (sgl == NULL) {
				err = RM_ERROR_ARGUMENT_INVALID;
				goto out;
			}

			if (!addr_valid(sgl[0].ipa) ||
			    (sgl[0].size != mp->total_size)) {
				err = RM_ERROR_ARGUMENT_INVALID;
				goto err_alloc;
			}
			alloc_ipa = sgl[0].ipa;
		}

		vm_address_range_result_t ar_ret =
			alloc_as_range(vm, mp->mem_type, alloc_ipa,
				       INVALID_ADDRESS, mp->total_size);
		if (ar_ret.err != OK) {
			printf("memparcel: Failed to alloc contig range %d\n",
			       ar_ret.err);
			err = RM_ERROR_NORESOURCE;
			goto err_alloc;
		}

		if (ar_ret.tag != ADDRESS_RANGE_NO_TAG) {
			region_list_loop(mp->region_list, region, i)
			{
				paddr_t phys = mem_region_get_phys(region);
				size_t	size = mem_region_get_size(region);

				err = validate_as_tag(phys, size, ar_ret.tag);
				if (err != RM_OK) {
					goto err_alloc;
				}
			}
		}

		if (resp_sgl != NULL) {
			(*resp_sgl)[0].ipa  = ar_ret.base;
			(*resp_sgl)[0].size = mp->total_size;
		}

		vm_info->ipa_list[0] = ipa_region_init(ar_ret.base);
		alloc_count	     = 1U;
	} else {
		for (index_t j = 0U; j < num_ipa_alloc; j++) {
			i      = vm_info->ipa_alloc_count + j;
			region = region_list_at(mp->region_list, i);

			paddr_t phys = mem_region_get_phys(region);
			size_t	size = mem_region_get_size(region);

			vmaddr_t alloc_ipa = INVALID_ADDRESS;
			if (sgl_entries != 0U) {
				if (sgl == NULL) {
					err = RM_ERROR_ARGUMENT_INVALID;
					goto out;
				}

				if (!addr_valid(sgl[j].ipa) ||
				    (sgl[j].size != size)) {
					err = RM_ERROR_ARGUMENT_INVALID;
					goto err_alloc;
				}
				alloc_ipa = sgl[j].ipa;
			}

			vm_address_range_result_t ar_ret = alloc_as_range(
				vm, mp->mem_type, alloc_ipa, phys, size);
			if (ar_ret.err != OK) {
				printf("memparcel: Failed to alloc as range %d\n",
				       ar_ret.err);
				err = RM_ERROR_NORESOURCE;
				goto err_alloc;
			}

			if (ar_ret.tag != ADDRESS_RANGE_NO_TAG) {
				err = validate_as_tag(phys, size, ar_ret.tag);
				if (err != RM_OK) {
					goto err_alloc;
				}
			}

			if (resp_sgl != NULL) {
				(*resp_sgl)[j].ipa  = ar_ret.base;
				(*resp_sgl)[j].size = size;
			}

			vm_info->ipa_list[i] = ipa_region_init(ar_ret.base);
			alloc_count++;
		}
	}

do_mapping:
	if (!accept_done) {
		goto finish_accept;
	}

	if ((vm_info->ipa_alloc_count + alloc_count) != num_mappings) {
		// All IPAs must be allocated before mapping.
		err = RM_ERROR_ARGUMENT_INVALID;
		goto err_alloc;
	}

	vm_memory_batch_start();
	batch_started = true;

	if (trans_type == TRANS_TYPE_DONATE) {
		// Donate to the new owner's extent before mapping.
		region_list_loop(mp->region_list, region, i)
		{
			paddr_t phys = mem_region_get_phys(region);
			size_t	size = mem_region_get_size(region);

			hyp_err = vm_memory_donate_extent(vm, mp->mem_type,
							  mp->acl_info,
							  mp->me_cap, phys,
							  size, false);
			if (hyp_err != OK) {
				printf("memparcel: Donate to new owner failed %d\n",
				       hyp_err);
				err = RM_ERROR_MEM_INVALID;
				goto err_donate;
			}

			donated_count++;
		}
	}

	region_list_loop(mp->region_list, region, i)
	{
		paddr_t	 phys = mem_region_get_phys(region);
		size_t	 size = mem_region_get_size(region);
		vmaddr_t ipa  = vm_info_get_ipa(vm_info, i, offset);

		hyp_err = map_memory_region(vm, vm_info, map_me_cap,
					    mp->mem_type, ipa, phys, size);
		if (hyp_err != OK) {
			printf("memparcel: Map region failed %d\n", hyp_err);
			err = RM_ERROR_MAP_FAILED;
			goto err_map;
		}

		offset += size;
		map_count++;
	}

	vm_info->mapped = true;

	if (trans_type == TRANS_TYPE_DONATE) {
		// Free the allocated IPA ranges from the previous owner,
		// and unmap them from the previous owner's extent.
		vm_t *prev_vm = vm_lookup(mp->owner_vmid);
		assert(prev_vm != NULL);

		cap_id_t prev_owner_me =
			vm_memory_get_owned_extent(prev_vm, mem_type);
		region_list_loop(mp->region_list, region, i)
		{
			vmaddr_t ipa  = mem_region_get_owner_ipa(region);
			paddr_t	 phys = mem_region_get_phys(region);
			size_t	 size = mem_region_get_size(region);

			free_as_range(prev_vm, mp->mem_type, ipa, size);

			hyp_err = unmap_memory_region(prev_vm, prev_owner_me,
						      mem_type, ipa, phys,
						      size);
			assert(hyp_err == OK);
		}

		// Complete the donation by deleting the memparcel.
		free(vm_info->ipa_list);
		remove_from_accepted_list(vm, mp);
		delete_memparcel(prev_vm, mp);
		goto out;
	} else {
		err = platform_memparcel_accept(mp, vm);
		if (err != RM_OK) {
			goto err_map;
		}
	}

finish_accept:
	vm_info->ipa_alloc_count += alloc_count;

	if (!vm_info->shared) {
		vm_info->shared = true;
		mp->share_count++;
		mp->state = MEMPARCEL_STATE_SHARED;
		add_to_accepted_list(vm, mp);
	}
err_map:
	if (err != RM_OK) {
		offset = 0U;
		region_list_loop_range(mp->region_list, region, i, 0U,
				       map_count)
		{
			paddr_t	 phys = mem_region_get_phys(region);
			size_t	 size = mem_region_get_size(region);
			vmaddr_t ipa  = vm_info_get_ipa(vm_info, i, offset);

			hyp_err = unmap_memory_region(
				vm, map_me_cap, mp->mem_type, ipa, phys, size);
			assert(hyp_err == OK);
			offset += size;
		}
		vm_info->mapped = false;
	}
err_donate:
	if (err != RM_OK) {
		region_list_loop_range(mp->region_list, region, i, 0U,
				       donated_count)
		{
			paddr_t phys = mem_region_get_phys(region);
			size_t	size = mem_region_get_size(region);

			hyp_err = vm_memory_donate_extent(vm, mp->mem_type,
							  mp->acl_info,
							  mp->me_cap, phys,
							  size, true);
			assert(hyp_err == OK);
		}
	}
err_alloc:
	if ((err != RM_OK) && (alloc_count > 0U)) {
		assert(vm_info != NULL);
		free_allocated_ipas(vm, mp, vm_info, vm_info->ipa_alloc_count,
				    alloc_count);
	}
out:
	if (err != RM_OK) {
		if (ipa_list != NULL) {
			assert(vm_info != NULL);
			vm_info->ipa_list = NULL;
			free(ipa_list);
		}
	}

	if (batch_started) {
		vm_memory_batch_end();
	}

	return err;
}

static rm_error_t
memparcel_do_release(vmid_t vmid, mem_handle_t handle, uint8_t flags)
{
	rm_error_t   err = RM_OK;
	index_t	     i;
	mem_region_t region;

	memparcel_t *mp = lookup_memparcel(handle);
	if (mp == NULL) {
		err = RM_ERROR_HANDLE_INVALID;
		goto out;
	}

	if (mp->locked) {
		printf("MEM_RELEASE: memparcel %d is locked\n", (int)handle);
		err = RM_ERROR_DENIED;
		goto out;
	}

	vm_t *vm = vm_lookup(vmid);
	if (vm == NULL) {
		err = RM_ERROR_VMID_INVALID;
		goto out;
	}

	vm_meminfo_t *vm_info = lookup_vm_info(mp, vmid);
	if (vm_info == NULL) {
		err = RM_ERROR_HANDLE_INVALID;
		goto out;
	}

	if (vm_info->vmid == mp->owner_vmid) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	if (!vm_info->shared) {
		err = RM_ERROR_MEM_RELEASED;
		goto out;
	}

	if ((flags & MEM_RELEASE_FLAG_SANITIZE) != 0U) {
		if (mp->mem_type == MEM_TYPE_IO) {
			err = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}

		// VM must have write access to sanitize
		if ((vm_info->rights & MEM_RIGHTS_W) == 0U) {
			err = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}

		mp->sanitize_reclaim = true;
	}

	if (!vm_info->mapped) {
		goto finish_release;
	}

	err = platform_memparcel_release(mp, vm);
	if (err != RM_OK) {
		goto out;
	}

	vm_memory_batch_start();

	error_t hyp_err;
	count_t unmap_count = 0U;
	size_t	offset	    = 0U;
	region_list_loop(mp->region_list, region, i)
	{
		paddr_t	 phys = mem_region_get_phys(region);
		size_t	 size = mem_region_get_size(region);
		vmaddr_t ipa  = vm_info_get_ipa(vm_info, i, offset);

		hyp_err = unmap_memory_region(vm, mp->me_cap, mp->mem_type, ipa,
					      phys, size);
		if (hyp_err != OK) {
			printf("memparcel: unmap region failed %d\n", hyp_err);
			err = RM_ERROR_MAP_FAILED;
			break;
		}

		offset += size;
		unmap_count++;
	}

	if (err != RM_OK) {
		offset = 0U;
		region_list_loop_range(mp->region_list, region, i, 0U,
				       unmap_count)
		{
			paddr_t	 phys = mem_region_get_phys(region);
			size_t	 size = mem_region_get_size(region);
			vmaddr_t ipa  = vm_info_get_ipa(vm_info, i, offset);

			hyp_err = map_memory_region(vm, vm_info, mp->me_cap,
						    mp->mem_type, ipa, phys,
						    size);
			assert(hyp_err == OK);
			offset += size;
		}
	}

	vm_memory_batch_end();

	if (err != RM_OK) {
		goto out;
	}

finish_release:
	free_allocated_ipas(vm, mp, vm_info, 0U, vm_info->ipa_alloc_count);

	free(vm_info->ipa_list);

	vm_info->ipa_list	 = NULL;
	vm_info->ipa_alloc_count = 0U;
	vm_info->contiguous	 = false;
	vm_info->shared		 = false;
	vm_info->mapped		 = false;

	mp->share_count--;
	if (mp->share_count == 0U) {
		mp->state = MEMPARCEL_STATE_SHARING;
	}

	remove_from_accepted_list(vm, mp);

out:
	printf("MEM_RELEASE VM %d H %d ret %d\n", vmid, (int)handle, err);
	return err;
}

static void
memparcel_release(vmid_t vmid, uint16_t seq_num, uint8_t *buf, size_t len)
{
	rm_error_t err = RM_OK;

	if (len < sizeof(memparcel_release_req_t)) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	memparcel_release_req_t *req =
		(memparcel_release_req_t *)(uintptr_t)buf;

	mem_handle_t handle = req->handle;
	uint8_t	     flags  = req->flags;

	err = memparcel_do_release(vmid, handle, flags);

out:
	rm_standard_reply(vmid, MEM_RELEASE, seq_num, err);
}

rm_error_t
memparcel_do_reclaim(vmid_t vmid, mem_handle_t handle, uint8_t flags)
{
	rm_error_t err = RM_OK;

	memparcel_t *mp = lookup_memparcel(handle);
	if (mp == NULL) {
		err = RM_ERROR_HANDLE_INVALID;
		goto out;
	}

	if (vmid != mp->owner_vmid) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	if (mp->state == MEMPARCEL_STATE_SHARED) {
		err = RM_ERROR_MEM_INUSE;
		goto out;
	}

	if (mp->locked) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	assert(mp->share_count == 0U);

	if ((flags & MEM_RECLAIM_FLAG_SANITIZE) != 0U) {
		if (mp->mem_type == MEM_TYPE_IO) {
			err = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}

		mp->sanitize_reclaim = true;
	}

	vm_t *vm = vm_lookup(vmid);
	if (vm == NULL) {
		err = RM_ERROR_VMID_INVALID;
		goto out;
	}

	region_list_cleanup_regions(vm, mp->me_cap, mp->mem_type, mp->acl_info,
				    mp->sanitize_reclaim, mp->region_list);
	delete_memparcel(vm, mp);

out:
	return err;
}

static void
memparcel_reclaim(vmid_t vmid, uint16_t seq_num, uint8_t *buf, size_t len)
{
	rm_error_t   err    = RM_OK;
	mem_handle_t handle = MEMPARCEL_INVALID_HANDLE;

	if (len < sizeof(memparcel_reclaim_req_t)) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	memparcel_reclaim_req_t *req =
		(memparcel_reclaim_req_t *)(uintptr_t)buf;

	handle	      = req->handle;
	uint8_t flags = req->flags;

	err = memparcel_do_reclaim(vmid, handle, flags);

out:
	printf("MEM_RECLAIM VM %d H %d ret %d\n", vmid, (int)handle, err);
	rm_standard_reply(vmid, MEM_RECLAIM, seq_num, err);
}

static rm_error_t
get_vmid_list(memparcel_t *mp, memparcel_notify_req_t *req, size_t len,
	      uint16_t *vmid_entries_ret, vmid_entry_t **vmid_list_ret)
{
	rm_error_t err = RM_OK;

	assert(vmid_entries_ret != NULL);
	assert(vmid_list_ret != NULL);

	size_t vmid_list_offset = sizeof(memparcel_notify_req_t) + 4U;
	if (len < vmid_list_offset) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	uint16_t vmid_entries = *(uint16_t *)(req + 1U);
	if (vmid_entries == 0U) {
		err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (len < (vmid_list_offset + (sizeof(vmid_entry_t) * vmid_entries))) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	if (vmid_entries > mp->num_vms) {
		err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	vmid_entry_t *vmid_list =
		(vmid_entry_t *)((uintptr_t)req + vmid_list_offset);
	for (uint16_t i = 0U; i < vmid_entries; i++) {
		vmid_t target_vmid = vmid_list[i].vmid;
		vm_t  *target_vm   = vm_lookup(target_vmid);
		if (target_vm == NULL) {
			err = RM_ERROR_VMID_INVALID;
			goto out;
		}

		vm_meminfo_t *vm_info = lookup_vm_info(mp, target_vmid);
		if (vm_info == NULL) {
			err = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}
	}

	*vmid_entries_ret = vmid_entries;
	*vmid_list_ret	  = vmid_list;

out:
	return err;
}

static rm_error_t
memparcel_notify_shared(memparcel_t *mp, vmid_t src_vmid,
			memparcel_notify_req_t *req, size_t len)
{
	rm_error_t    err	   = RM_OK;
	uint16_t      vmid_entries = 0U;
	vmid_entry_t *vmid_list	   = NULL;

	if (src_vmid != mp->owner_vmid) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	err = get_vmid_list(mp, req, len, &vmid_entries, &vmid_list);
	if (err != RM_OK) {
		goto out;
	}

	if (!mp->mem_info_tag_set) {
		memparcel_set_mem_info_tag(mp, req->mem_info_tag);
	}

	// Truncate the SG list if it is too large to send over RM RPC.
	count_t num_regions = util_min(region_list_get_len(mp->region_list),
				       MAX_LIST_ENTRIES);

	size_t notif_size = sizeof(memparcel_shared_notif_t) +
			    (mp->num_vms * sizeof(acl_entry_t)) +
			    (num_regions * sizeof(uint64_t)) +
			    (mp->num_attrs * sizeof(attr_entry_t));

	uint8_t *notif_buf = calloc(notif_size, 1U);
	if (notif_buf == NULL) {
		err = RM_ERROR_NOMEM;
		goto out;
	}

	uintptr_t		  curr	= (uintptr_t)notif_buf;
	memparcel_shared_notif_t *notif = (memparcel_shared_notif_t *)curr;

	notif->handle	    = mp->handle;
	notif->mem_type	    = mp->mem_type;
	notif->trans_type   = mp->trans_type;
	notif->flags	    = mp->sanitize_create ? 1U : 0U;
	notif->owner_vmid   = mp->owner_vmid;
	notif->label	    = mp->label;
	notif->mem_info_tag = mp->mem_info_tag;
	notif->acl_entries  = mp->num_vms;

	curr += offsetof(memparcel_shared_notif_t, acl_entries) + 4U;

	acl_entry_t *acl = (acl_entry_t *)(uintptr_t)curr;
	for (uint32_t i = 0U; i < mp->num_vms; i++) {
		acl[i].vmid   = mp->vm_list[i].vmid;
		acl[i].rights = mp->vm_list[i].rights;
		curr += sizeof(acl_entry_t);
	}

	*(uint16_t *)curr = (uint16_t)num_regions;
	curr += 4U;

	index_t	     idx;
	mem_region_t region;
	uint64_t    *size_list = (uint64_t *)curr;
	region_list_loop(mp->region_list, region, idx)
	{
		size_list[idx] = mem_region_get_size(region);
		curr += sizeof(uint64_t);
	}

	*(uint16_t *)curr = mp->num_attrs;
	curr += 4U;

	attr_entry_t *attr_list = (attr_entry_t *)curr;
	for (uint16_t i = 0U; i < mp->num_attrs; i++) {
		attr_list[i].attr = mp->attr_list[i].attr;
		attr_list[i].vmid = mp->attr_list[i].vmid;
	}

	for (uint16_t i = 0U; i < vmid_entries; i++) {
		vmid_t target_vmid = vmid_list[i].vmid;
		vm_t  *target_vm   = vm_lookup(target_vmid);

		assert(target_vm != NULL);
		if (target_vm->vm_state == VM_STATE_READY) {
			error_t e =
				vm_creation_process_memparcel(target_vm, mp);
			if (e != OK) {
				err = memparcel_notify_owner(mp, target_vmid,
							     false);
			} else {
				err = memparcel_notify_owner(mp, target_vmid,
							     true);
			}
		} else {
			rm_notify(target_vmid, MEM_SHARED, notif_buf,
				  notif_size);
		}
	}

	free(notif_buf);
out:
	return err;
}

static rm_error_t
memparcel_notify_owner(memparcel_t *mp, vmid_t vmid, bool accepted)
{
	rm_error_t err;

	vm_meminfo_t *vm_info = lookup_vm_info(mp, vmid);
	if (vm_info == NULL) {
		err = RM_ERROR_HANDLE_INVALID;
		goto out;
	}

	if (accepted != vm_info->shared) {
		err = vm_info->shared ? RM_ERROR_MEM_INUSE
				      : RM_ERROR_MEM_RELEASED;
		goto out;
	}

	uint32_t notif_id = (accepted) ? MEM_ACCEPTED : MEM_RELEASED;

	memparcel_owner_notif_t notif = { 0 };

	notif.handle	   = mp->handle;
	notif.vmid	   = vmid;
	notif.mem_info_tag = mp->mem_info_tag;

	rm_notify(mp->owner_vmid, notif_id, &notif, sizeof(notif));
	err = RM_OK;
out:
	return err;
}

static rm_error_t
memparcel_notify_recall(memparcel_t *mp, vmid_t src_vmid,
			memparcel_notify_req_t *req, size_t len)
{
	rm_error_t    err	   = RM_OK;
	uint16_t      vmid_entries = 0U;
	vmid_entry_t *vmid_list	   = NULL;

	if (src_vmid != mp->owner_vmid) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	err = get_vmid_list(mp, req, len, &vmid_entries, &vmid_list);
	if (err != RM_OK) {
		goto out;
	}

	memparcel_recall_notif_t notif = {
		.handle	      = mp->handle,
		.mem_info_tag = mp->mem_info_tag,
	};

	for (uint16_t i = 0U; i < vmid_entries; i++) {
		rm_notify(vmid_list[i].vmid, MEM_RECALL, &notif, sizeof(notif));
	}

out:
	return err;
}

static void
memparcel_notify(vmid_t vmid, uint16_t seq_num, uint8_t *buf, size_t len)
{
	rm_error_t   err;
	mem_handle_t handle = MEMPARCEL_INVALID_HANDLE;

	if (len < sizeof(memparcel_notify_req_t)) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	memparcel_notify_req_t *req = (memparcel_notify_req_t *)(uintptr_t)buf;

	handle	      = req->handle;
	uint8_t flags = req->flags;

	memparcel_t *mp = lookup_memparcel(handle);
	if (mp == NULL) {
		err = RM_ERROR_HANDLE_INVALID;
		goto out;
	}

	if (mp->mem_info_tag_set && (mp->mem_info_tag != req->mem_info_tag)) {
		printf("memparcel_notify: mem-info-tag (%x) and request tag "
		       "(%x) mismatch, flags(%x)\n",
		       mp->mem_info_tag, req->mem_info_tag, flags);
		err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (flags == MEM_NOTIFY_FLAG_SHARED) {
		err = memparcel_notify_shared(mp, vmid, req, len);
	} else if (flags == MEM_NOTIFY_FLAG_RELEASED) {
		err = memparcel_notify_owner(mp, vmid, false);
	} else if (flags == MEM_NOTIFY_FLAG_ACCEPTED) {
		err = memparcel_notify_owner(mp, vmid, true);
	} else if (flags == MEM_NOTIFY_FLAG_RECALL) {
		err = memparcel_notify_recall(mp, vmid, req, len);
	} else {
		err = RM_ERROR_ARGUMENT_INVALID;
	}

out:
	printf("MEM_NOTIFY VM %d H %d ret %d\n", vmid, (int)handle, err);
	rm_standard_reply(vmid, MEM_NOTIFY, seq_num, err);
}

mem_handle_t
memparcel_sgl_do_lookup(vmid_t vmid, uint16_t acl_entries, uint16_t sgl_entries,
			uint16_t attr_entries, acl_entry_t *acl,
			sgl_entry_t *sgl, attr_entry_t *attr_list,
			uint32_t label, uint8_t mem_type, bool hyp_unassign)
{
	mem_handle_t handle = ~(uint32_t)0U;

	memparcel_t *mp = NULL;
	loop_list(mp, &mp_list_head, )
	{
		if ((mp->owner_vmid != vmid) ||
		    (mp->state != MEMPARCEL_STATE_SHARING)) {
			continue;
		}

		count_t num_regions = region_list_get_len(mp->region_list);

		if ((mem_type != mp->mem_type) ||
		    (acl_entries != mp->num_vms) ||
		    (sgl_entries != num_regions) ||
		    (attr_entries != mp->num_attrs)) {
			continue;
		}

		bool match = true;

		if (acl == NULL) {
			match = false;
		}

		for (uint32_t i = 0U; match && (i < acl_entries); i++) {
			if (mp->vm_list[i].vmid != acl[i].vmid) {
				match = false;
			}
			// ACL rights can't be checked for hyp
			// unassign, as the source VM list only
			// contains VMIDs.
			if (!hyp_unassign &&
			    (mp->vm_list[i].rights != acl[i].rights)) {
				match = false;
			}
		}

		if (sgl == NULL) {
			match = false;
		}

		for (uint16_t i = 0U; match && (i < sgl_entries); i++) {
			mem_region_t region =
				region_list_at(mp->region_list, i);
			vmaddr_t ipa  = mem_region_get_owner_ipa(region);
			size_t	 size = mem_region_get_size(region);

			if ((ipa != sgl[i].ipa) || (size != sgl[i].size)) {
				match = false;
			}
		}

		for (uint16_t i = 0U; match && (i < attr_entries); i++) {
			if ((mp->attr_list[i].attr != attr_list[i].attr) ||
			    (mp->attr_list[i].vmid != attr_list[i].vmid)) {
				match = false;
			}
		}

		if (match) {
			handle = mp->handle;
			if ((!hyp_unassign) && (!mp->label_valid)) {
				mp->label	= label;
				mp->label_valid = true;
			}
			break;
		}
	}

	return handle;
}

static void
memparcel_lookup_sgl(vmid_t vmid, uint16_t seq_num, uint8_t *buf, size_t len)
{
	rm_error_t   err;
	mem_handle_t handle = MEMPARCEL_INVALID_HANDLE;

	if (len < sizeof(memparcel_lookup_req_t)) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	memparcel_lookup_req_t *req = (memparcel_lookup_req_t *)(uintptr_t)buf;
	uint16_t		acl_entries  = 0U;
	uint16_t		sgl_entries  = 0U;
	uint16_t		attr_entries = 0U;
	acl_entry_t	       *acl	     = NULL;
	sgl_entry_t	       *sgl	     = NULL;
	attr_entry_t	       *attr_list    = NULL;

	size_t list_offset = offsetof(memparcel_lookup_req_t, acl_entries);
	err = memparcel_read_lists(buf + list_offset, len - list_offset,
				   &acl_entries, &sgl_entries, &attr_entries,
				   &acl, &sgl, &attr_list);
	if (err != RM_OK) {
		goto out;
	}

	handle = memparcel_sgl_do_lookup(vmid, acl_entries, sgl_entries,
					 attr_entries, acl, sgl, attr_list,
					 req->label, req->mem_type, false);
	if (handle == MEMPARCEL_INVALID_HANDLE) {
		err = RM_ERROR_LOOKUP_FAILED;
	}

out:
	LOG("MEM_QCOM_LOOKUP_SGL: from:%d handle:%d ret=%d\n", vmid,
	    (int)handle, err);
	if (err == RM_OK) {
		memparcel_handle_resp_t resp = {
			.handle = handle,
		};

		rm_reply(vmid, MEM_QCOM_LOOKUP_SGL, seq_num, &resp,
			 sizeof(resp));
	} else {
		rm_standard_reply(vmid, MEM_QCOM_LOOKUP_SGL, seq_num, err);
	}
}

bool
memparcel_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
		      void *buf, size_t len)
{
	bool handled = true;

	switch (msg_id) {
	case MEM_DONATE:
	case MEM_LEND:
	case MEM_SHARE:
		memparcel_create(client_id, msg_id, seq_num, buf, len);
		break;
	case MEM_ACCEPT:
		memparcel_handle_accept(client_id, seq_num, buf, len);
		break;
	case MEM_RELEASE:
		memparcel_release(client_id, seq_num, buf, len);
		break;
	case MEM_RECLAIM:
		memparcel_reclaim(client_id, seq_num, buf, len);
		break;
	case MEM_NOTIFY:
		memparcel_notify(client_id, seq_num, buf, len);
		break;
	case MEM_APPEND:
		memparcel_append(client_id, seq_num, buf, len);
		break;
	case MEM_QCOM_LOOKUP_SGL:
		memparcel_lookup_sgl(client_id, seq_num, buf, len);
		break;
	default:
		handled = false;
		break;
	}

	return handled;
}

uintptr_result_t
memparcel_map_rm(uint32_t handle, size_t offset, size_t size)
{
	memparcel_t	*mp = lookup_memparcel(handle);
	uintptr_result_t ret;

	if (mp == NULL) {
		ret = uintptr_result_error(ERROR_ARGUMENT_INVALID);
		goto out;
	}

	// First, ensure that no region in this memparcel is already mapped.
	if (mp->rm_map_size != 0U) {
		ret = uintptr_result_error(ERROR_BUSY);
		goto out;
	}

	// RM shouldn't be mapping IO devices.
	if (mp->mem_type != MEM_TYPE_NORMAL) {
		ret = uintptr_result_error(ERROR_DENIED);
		goto out;
	}

	vm_t *rm_vm = vm_lookup(VMID_RM);
	assert(rm_vm != NULL);

	assert(mp->rm_as_range_size == 0U);
	vm_address_range_result_t addr_r = alloc_as_range(
		rm_vm, MEM_TYPE_NORMAL, INVALID_ADDRESS, INVALID_ADDRESS, size);
	if (addr_r.err != OK) {
		ret = uintptr_result_error(addr_r.err);
		goto out;
	}
	mp->rm_as_range_base = addr_r.base;
	mp->rm_as_range_size = addr_r.size;

	mp->rm_map_offset = offset;
	mp->rm_map_size	  = 0U;

	size_t next_offset = offset;
	size_t next_addr   = addr_r.base;
	size_t next_size   = size;

	count_t len = region_list_get_len(mp->region_list);
	error_t err = OK;
	for (index_t i = 0U; (next_size != 0U) && (i < len); i++) {
		mem_region_t region = region_list_at(mp->region_list, i);

		paddr_t region_phys = mem_region_get_phys(region);
		size_t	region_size = mem_region_get_size(region);

		if (next_offset >= region_size) {
			// Offset is completely outside this region; skip it.
			next_offset -= region_size;
			continue;
		}

		paddr_t map_phys = region_phys + next_offset;
		size_t	map_size =
			util_min(region_size - next_offset, next_size);

		err = memextent_map_partial(mp->me_cap, rm_get_rm_addrspace(),
					    next_addr, map_phys, map_size,
					    PGTABLE_ACCESS_RW,
					    PGTABLE_VM_MEMTYPE_NORMAL_WB);
		if (err != OK) {
			break;
		}

		next_offset = 0U;
		next_size -= map_size;
		next_addr += map_size;
		mp->rm_map_size += map_size;
	}

	if ((err == OK) && (next_size != 0U)) {
		// The requested mapping extended past the last region
		err = ERROR_ARGUMENT_SIZE;
	}

	if (err != OK) {
		error_t unmap_err = memparcel_unmap_rm(handle);
		assert(unmap_err == OK);
		ret = uintptr_result_error(err);
	} else {
		ret = uintptr_result_ok(addr_r.base);
	}

out:
	return ret;
}

error_t
memparcel_unmap_rm(uint32_t handle)
{
	memparcel_t *mp	 = lookup_memparcel(handle);
	error_t	     err = OK;

	if (mp == NULL) {
		err = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	size_t next_addr   = mp->rm_as_range_base;
	size_t next_offset = mp->rm_map_offset;
	size_t next_size   = mp->rm_map_size;

	count_t len = region_list_get_len(mp->region_list);
	for (index_t i = 0U; (next_size != 0U) && (i < len); i++) {
		mem_region_t region = region_list_at(mp->region_list, i);

		paddr_t region_phys = mem_region_get_phys(region);
		size_t	region_size = mem_region_get_size(region);

		if (next_offset >= region_size) {
			next_offset -= region_size;
			continue;
		}

		paddr_t unmap_phys = region_phys + next_offset;
		size_t	unmap_size =
			util_min(region_size - next_offset, next_size);

		err = memextent_unmap_partial(mp->me_cap, rm_get_rm_addrspace(),
					      next_addr, unmap_phys,
					      unmap_size);
		assert(err == OK);

		next_offset = 0U;
		next_size -= unmap_size;
		next_addr += unmap_size;
	}

	mp->rm_map_offset = 0U;
	mp->rm_map_size	  = 0U;

	vm_t *rm_vm = vm_lookup(VMID_RM);
	assert(rm_vm != NULL);
	free_as_range(rm_vm, MEM_TYPE_NORMAL, mp->rm_as_range_base,
		      mp->rm_as_range_size);
	mp->rm_as_range_base = INVALID_ADDRESS;
	mp->rm_as_range_size = 0U;

out:
	return err;
}

mem_handle_t
memparcel_get_handle(const memparcel_t *mp)
{
	return mp->handle;
}

vmid_t
memparcel_get_owner(const memparcel_t *mp)
{
	return mp->owner_vmid;
}

label_t
memparcel_get_label(const memparcel_t *mp)
{
	return mp->label;
}

uint8_t
memparcel_get_mem_type(const memparcel_t *mp)
{
	return mp->mem_type;
}

uint8_t
memparcel_get_trans_type(const memparcel_t *mp)
{
	return mp->trans_type;
}

count_t
memparcel_get_num_regions(const memparcel_t *mp)
{
	return region_list_get_len(mp->region_list);
}

region_list_t *
memparcel_get_regions_list(const memparcel_t *mp)
{
	return mp->region_list;
}

count_result_t
memparcel_get_num_mappings(const memparcel_t *mp, vmid_t vmid)
{
	count_result_t ret = count_result_error(ERROR_ARGUMENT_INVALID);

	vm_meminfo_t *vm_info = lookup_vm_info(mp, vmid);
	if (vm_info == NULL) {
		goto out;
	}

	if (!vm_info->shared) {
		goto out;
	}

	count_t num_mappings =
		vm_info->contiguous ? 1U : region_list_get_len(mp->region_list);

	ret = count_result_ok(num_mappings);

out:
	return ret;
}

bool
memparcel_get_sanitize_reclaim(const memparcel_t *mp)
{
	assert(mp != NULL);
	return mp->sanitize_reclaim;
}

void
memparcel_set_lock(memparcel_t *mp, bool lock)
{
	assert(mp != NULL);
	mp->locked = lock;
}

bool
memparcel_is_locked(const memparcel_t *mp)
{
	assert(mp != NULL);
	return mp->locked;
}

// The refcount functions below should be moved to a platform-specific file for
// memparcel extensions during RM clean-up.
// FIXME:
uint32_t
memparcel_get_mpd_sanitise_refcount(const memparcel_t *mp, index_t region_idx)
{
	assert(mp != NULL);
	assert(region_idx < region_list_get_len(mp->region_list));

	mem_region_t *region = region_list_at_ptr(mp->region_list, region_idx);
	return mem_region_get_mpd_sanitise_refcount(region);
}

void
memparcel_increment_mpd_sanitise_refcount(const memparcel_t *mp,
					  index_t	     region_idx)
{
	assert(mp != NULL);
	assert(region_idx < region_list_get_len(mp->region_list));

	mem_region_t *region = region_list_at_ptr(mp->region_list, region_idx);
	mem_region_increment_mpd_sanitise_refcount(region);
}

void
memparcel_decrement_mpd_sanitise_refcount(const memparcel_t *mp,
					  index_t	     region_idx)
{
	assert(mp != NULL);
	assert(region_idx < region_list_get_len(mp->region_list));

	mem_region_t *region = region_list_at_ptr(mp->region_list, region_idx);
	mem_region_decrement_mpd_sanitise_refcount(region);
}

paddr_result_t
memparcel_get_phys(const memparcel_t *mp, index_t region_idx)
{
	paddr_result_t ret;

	if (region_idx < region_list_get_len(mp->region_list)) {
		mem_region_t region =
			region_list_at(mp->region_list, region_idx);
		ret = paddr_result_ok(mem_region_get_phys(region));
	} else {
		ret = paddr_result_error(ERROR_ARGUMENT_INVALID);
	}

	return ret;
}

vmaddr_result_t
memparcel_get_mapped_ipa(const memparcel_t *mp, vmid_t vmid,
			 index_t mapping_idx)
{
	vmaddr_result_t ret = vmaddr_result_error(ERROR_ARGUMENT_INVALID);

	vm_meminfo_t *vm_info = lookup_vm_info(mp, vmid);
	if (vm_info == NULL) {
		goto out;
	}

	if (!vm_info->shared) {
		goto out;
	}

	count_t num_mappings =
		vm_info->contiguous ? 1U : region_list_get_len(mp->region_list);

	if (mapping_idx >= num_mappings) {
		goto out;
	}

	vmaddr_t ipa = ipa_region_get_ipa(vm_info->ipa_list[mapping_idx]);

	ret = vmaddr_result_ok(ipa);

out:
	return ret;
}

size_t
memparcel_get_size(const memparcel_t *mp)
{
	return mp->total_size;
}

size_result_t
memparcel_get_region_size(const memparcel_t *mp, index_t region_idx)
{
	size_result_t ret;

	if (region_idx < region_list_get_len(mp->region_list)) {
		mem_region_t region =
			region_list_at(mp->region_list, region_idx);
		ret = size_result_ok(mem_region_get_size(region));
	} else {
		ret = size_result_error(ERROR_ARGUMENT_INVALID);
	}

	return ret;
}

size_result_t
memparcel_get_mapped_size(const memparcel_t *mp, vmid_t vmid,
			  index_t mapping_idx)
{
	size_result_t ret = size_result_error(ERROR_ARGUMENT_INVALID);

	vm_meminfo_t *vm_info = lookup_vm_info(mp, vmid);
	if (vm_info == NULL) {
		goto out;
	}

	if (!vm_info->shared) {
		goto out;
	}

	count_t num_mappings =
		vm_info->contiguous ? 1U : region_list_get_len(mp->region_list);

	if (mapping_idx >= num_mappings) {
		goto out;
	}

	if (vm_info->contiguous) {
		ret = size_result_ok(memparcel_get_size(mp));
	} else {
		ret = memparcel_get_region_size(mp, mapping_idx);
	}

out:
	return ret;
}

cap_id_result_t
memparcel_get_me_cap(const memparcel_t *mp)
{
	return cap_id_result_ok(mp->me_cap);
}

memparcel_t *
memparcel_iter_by_target_vmid(memparcel_t *after, vmid_t vmid)
{
	memparcel_t *mp = (after == NULL) ? mp_list_head : after->next;

	for (; mp != NULL; mp = mp->next) {
		for (count_t i = 0; i < mp->num_vms; i++) {
			if (mp->vm_list[i].vmid == vmid) {
				return mp;
			}
		}
	}

	return NULL;
}

error_t
memparcel_get_shared_vmids(const memparcel_t *mp, vector_t *vmids)
{
	error_t ret = OK;

	if (mp->trans_type == TRANS_TYPE_SHARE) {
		ret = vector_push_back(vmids, mp->owner_vmid);
		if (ret != OK) {
			return ret;
		}
	}

	for (count_t i = 0; i < mp->num_vms; i++) {
		ret = vector_push_back(vmids, mp->vm_list[i].vmid);
		if (ret != OK) {
			return ret;
		}
	}

	return ret;
}

void
memparcel_set_phandle(memparcel_t *mp, vmid_t vmid, uint32_t phandle,
		      bool is_external)
{
	for (count_t i = 0; i < mp->num_vms; i++) {
		if (mp->vm_list[i].vmid == vmid) {
			mp->vm_list[i].phandle		   = phandle;
			mp->vm_list[i].phandle_is_external = is_external;
		}
	}
}

uint32_t
memparcel_get_phandle(memparcel_t *mp, vmid_t vmid, bool *is_external)
{
	uint32_t ret = 0U;
	for (count_t i = 0; i < mp->num_vms; i++) {
		if (mp->vm_list[i].vmid == vmid) {
			ret = mp->vm_list[i].phandle;
			if (is_external != NULL) {
				*is_external =
					mp->vm_list[i].phandle_is_external;
			}
			break;
		}
	}

	return ret;
}

bool
memparcel_is_shared(const memparcel_t *mp, vmid_t vmid)
{
	bool ret = false;

	for (count_t i = 0; i < mp->num_vms; i++) {
		if (mp->vm_list[i].vmid == vmid) {
			ret = mp->vm_list[i].shared;
		}
	}

	return ret;
}

bool
memparcel_is_exclusive(const memparcel_t *mp, vmid_t vmid)
{
	return (mp->num_vms == 1U) && (mp->vm_list[0U].vmid == vmid);
}

uint8_result_t
memparcel_get_vm_rights(const memparcel_t *mp, vmid_t vmid)
{
	uint8_result_t ret;

	ret.r = 0U;
	ret.e = ERROR_FAILURE;

	for (count_t i = 0; i < mp->num_vms; i++) {
		if (mp->vm_list[i].vmid == vmid) {
			ret.r = mp->vm_list[i].rights;
			ret.e = OK;
			break;
		}
	}

	return ret;
}

uint16_result_t
memparcel_get_vm_attrs(memparcel_t *mp, vmid_t vmid)
{
	uint16_result_t ret;

	ret.r = 0U;
	ret.e = ERROR_FAILURE;

	for (count_t i = 0; i < mp->num_attrs; i++) {
		if (mp->attr_list[i].vmid == vmid) {
			ret.r = mp->attr_list[i].attr;
			ret.e = OK;
			break;
		}
	}

	return ret;
}

void
memparcel_set_mem_info_tag(memparcel_t *mp, label_t tag)
{
	mp->mem_info_tag_set = true;
	mp->mem_info_tag     = tag;
}

// Release last memparcel accepted by VM.
// Return bool to indicate whether there are any accepted memparcels pending to
// release
bool
vm_reset_handle_release_memparcels(vmid_t vmid)
{
	bool ret = false;

	vm_t *vm = vm_lookup(vmid);
	assert((vm != NULL) && (vm->vm_config != NULL));

	vector_t *mp_vector = vm->vm_config->accepted_memparcels;
	if (mp_vector == NULL) {
		ret = true;
		goto out;
	}

	if (vector_is_empty(mp_vector)) {
		ret = true;
		goto out;
	}

	memparcel_t **mp = vector_pop_back(memparcel_t *, mp_vector);

	if ((mp != NULL) && ((*mp) != NULL)) {
		memparcel_do_release(vmid, memparcel_get_handle(*mp), 0);
		rm_error_t err = memparcel_notify_owner(*mp, vmid, false);
		assert(err == RM_OK);
	}

	ret = vector_is_empty(mp_vector);

out:
	return ret;
}
