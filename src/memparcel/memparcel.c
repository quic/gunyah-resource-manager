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

#include <rm-rpc.h>

#include <resource-manager.h>

#include <event.h>
#include <guest_interface.h>
#include <log.h>
#include <memextent.h>
#include <memparcel.h>
#include <memparcel_msg.h>
#include <platform_vm_config.h>
#include <rm-rpc-fifo.h>
#include <time.h>
#include <util.h>
#include <utils/address_range_allocator.h>
#include <utils/vector.h>
#include <vendor_hyp_call.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_creation.h>
#include <vm_mgnt.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

typedef struct mem_region {
	cap_id_t  memextent_cap;
	paddr_t	  phys;
	size_t	  size;
	vmaddr_t  owner_ipa;
	cap_id_t  rm_map_memextent;
	uintptr_t rm_map_addr;
} mem_region_t;

typedef struct {
	vmid_t	  vmid;
	uint32_t  attr;
	vmaddr_t *ipa_list;
	uint32_t  phandle;
	uint8_t	  rights;
	bool	  phandle_is_external;
	bool	  shared;
} vm_meminfo_t;

typedef enum {
	MEMPARCEL_STATE_SHARING,
	MEMPARCEL_STATE_SHARED,
} memparcel_state_t;

typedef struct memparcel memparcel_t;

struct memparcel {
	memparcel_t	    *next;
	memparcel_t	    *prev;
	mem_handle_t	  handle;
	label_t		  label;
	bool		  label_valid;
	bool		  mem_info_tag_set;
	label_t		  mem_info_tag;
	vmid_t		  owner_vmid;
	memparcel_state_t state;
	uint32_t	  share_count;
	uint8_t		  mem_type;
	uint8_t		  trans_type;
	bool		  hyp_assign;
	bool		  sanitize_create;
	bool		  sanitize_reclaim;
	uint32_t	  num_vms;
	uint16_t	  num_regions;
	uint16_t	  num_attrs;
	vm_meminfo_t     *vm_list;
	mem_region_t     *region_list;
	attr_entry_t     *attr_list;
	uint64_t	  hyp_assign_vmids;
};

#pragma clang diagnostic pop

static memparcel_t *memparcel_list_head;
static memparcel_t *memparcel_list_tail;
static uint32_t	    mp_handles;

#define DCACHE_LINE_SIZE 64U

#define SIZE_2M (2UL * 1024 * 1024)

static rm_error_t
memparcel_notify_owner(memparcel_t *mp, vmid_t vmid, bool accepted);

static void
cache_clean_by_va(vmaddr_t va, size_t size)
{
	vmaddr_t aligned_va = util_balign_down(va, DCACHE_LINE_SIZE);

	for (vmaddr_t addr = aligned_va; addr < (va + size);
	     addr += DCACHE_LINE_SIZE) {
		__asm__ volatile("dc  cvac, %0\n" : : "r"(addr) : "memory");
	}

	__asm__ volatile("dmb ish" ::: "memory");
}

static rm_error_t
memparcel_read_lists(uint8_t *buf, size_t len, uint32_t *acl_entries,
		     uint16_t *sgl_entries, uint16_t *attr_entries,
		     acl_entry_t **acl, sgl_entry_t **sgl,
		     attr_entry_t **attr_list, bool attr_required)
{
	rm_error_t err;

	assert(buf != NULL);
	assert(!util_add_overflows((uintptr_t)buf, len));

	uintptr_t curr	     = (uintptr_t)buf;
	uintptr_t start	     = curr;
	size_t	  array_size = 0;
	size_t	  buffer_end = start + len;

	if (util_add_overflows((uintptr_t)curr, sizeof(uint32_t))) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	if (buffer_end < (curr + sizeof(uint32_t))) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	*acl_entries = *(uint32_t *)curr;
	curr += sizeof(uint32_t);

	if (*acl_entries > MAX_LIST_ENTRIES) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	array_size = (*acl_entries * sizeof(acl_entry_t));

	if (util_add_overflows((uintptr_t)curr, array_size)) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	if (buffer_end < (curr + array_size)) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	*acl = (acl_entry_t *)curr;
	curr += array_size;

	if (util_add_overflows((uintptr_t)curr, sizeof(uint32_t))) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	if (buffer_end < (curr + sizeof(uint32_t))) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	*sgl_entries = *(uint16_t *)curr;
	curr += sizeof(uint32_t);

	if (*sgl_entries > MAX_LIST_ENTRIES) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	array_size = (*sgl_entries * sizeof(sgl_entry_t));

	if (util_add_overflows((uintptr_t)curr, array_size)) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	if (buffer_end < (curr + array_size)) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	*sgl = (sgl_entry_t *)curr;
	curr += array_size;

	if (!attr_required && (curr == buffer_end)) {
		*attr_entries = 0U;
		*attr_list    = NULL;
		err	      = RM_OK;
		goto out;
	}

	if (util_add_overflows((uintptr_t)curr, sizeof(uint32_t))) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	if (buffer_end < (curr + sizeof(uint32_t))) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	*attr_entries = *(uint16_t *)curr;
	curr += sizeof(uint32_t);

	if (*attr_entries > MAX_LIST_ENTRIES) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	array_size = (*attr_entries * sizeof(attr_entry_t));

	if (util_add_overflows((uintptr_t)curr, array_size)) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	if (buffer_end < (curr + array_size)) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	*attr_list = (attr_entry_t *)curr;
	curr += array_size;

	err = (curr == buffer_end) ? RM_OK : RM_ERROR_MSG_INVALID;
out:
	return err;
}

static bool
vmid_valid(vmid_t vmid)
{
	return (vmid == VMID_HLOS) || vm_is_secondary_vm(vmid) ||
	       vm_is_peripheral_vm(vmid);
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
	memparcel_t *curr = memparcel_list_head;

	for (; curr != NULL; curr = curr->next) {
		if (curr->handle == handle) {
			break;
		}
	}

	return curr;
}

static vm_meminfo_t *
lookup_vm_info(memparcel_t *mp, vmid_t vmid)
{
	vm_meminfo_t *vm_info = NULL;

	for (uint32_t i = 0U; i < mp->num_vms; i++) {
		if (mp->vm_list[i].vmid == vmid) {
			vm_info = &mp->vm_list[i];
		}
	}

	return vm_info;
}

static rm_error_t
sanitise_region(cap_id_t me_cap, vmaddr_t addr, size_t size)
{
	rm_error_t err = RM_OK;

	// FIXME: sanitize in hypervisor with memextent derive
	// arguments when issue #87 is fixed.
	error_t ret = memextent_map(me_cap, rm_get_rm_addrspace(), addr,
				    PGTABLE_ACCESS_RW,
				    PGTABLE_VM_MEMTYPE_NORMAL_WB);
	if (ret != OK) {
		err = RM_ERROR_MAP_FAILED;
		goto out;
	}

	memset((void *)addr, 0, size);
	cache_clean_by_va(addr, size);

	ret = gunyah_hyp_addrspace_unmap(rm_get_rm_addrspace(), me_cap, addr);
	assert(ret == OK);

out:
	return err;
}

static void
region_list_cleanup_memextents(vmid_t owner_vmid, uint8_t trans_type,
			       mem_region_t *region_list, uint16_t entries)
{
	vm_t *vm = vm_lookup(owner_vmid);

	assert(vm != NULL);
	assert(region_list != NULL);

	bool svm_donate = (owner_vmid != VMID_HLOS) &&
			  (trans_type == TRANS_TYPE_DONATE);

	for (uint16_t i = 0U; i < entries; i++) {
		mem_region_t *region = &region_list[i];

		if (region->rm_map_memextent != CSPACE_CAP_INVALID) {
			error_t err = gunyah_hyp_cspace_delete_cap_from(
				rm_get_rm_cspace(), region->rm_map_memextent);
			assert(err == OK);
			region->rm_map_memextent = CSPACE_CAP_INVALID;
		}

		if (region->memextent_cap != CSPACE_CAP_INVALID) {
			if (svm_donate) {
			} else {
				error_t err = gunyah_hyp_cspace_delete_cap_from(
					rm_get_rm_cspace(),
					region->memextent_cap);
				assert(err == OK);
			}
			region->memextent_cap = CSPACE_CAP_INVALID;
		}
	}
}

static void
delete_memparcel(vmid_t vmid, memparcel_t *mp)
{
	region_list_cleanup_memextents(vmid, mp->trans_type, mp->region_list,
				       mp->num_regions);

	if (memparcel_list_head == mp) {
		memparcel_list_head = mp->next;
	}

	if (memparcel_list_tail == mp) {
		memparcel_list_tail = mp->prev;
	}

	if (mp->prev != NULL) {
		mp->prev->next = mp->next;
	}

	if (mp->next != NULL) {
		mp->next->prev = mp->prev;
	}

	free(mp->attr_list);
	free(mp->vm_list[0].ipa_list);
	free(mp->vm_list);
	free(mp->region_list);
	free(mp);
}

memparcel_construct_ret_t
memparcel_construct(vmid_t owner_vmid, uint32_t acl_entries,
		    uint16_t sgl_entries, uint16_t attr_entries,
		    acl_entry_t *acl, sgl_entry_t *sgl, attr_entry_t *attr_list,
		    uint32_t label, bool label_valid, uint8_t mem_type,
		    uint8_t trans_type, bool hyp_assign, bool sanitize)
{
	rm_error_t    err;
	memparcel_t  *mp	     = NULL;
	mem_region_t *region_list    = NULL;
	vm_meminfo_t *vm_list	     = NULL;
	uint64_t	 *ipa_lists	     = NULL;
	attr_entry_t *attr_list_copy = NULL;
	vm_meminfo_t *owner_info     = NULL;

	bool hlos_iomem = !hyp_assign && (owner_vmid == VMID_HLOS) &&
			  (mem_type == MEM_TYPE_IO);
	bool svm_donate = (owner_vmid != VMID_HLOS) &&
			  (trans_type == TRANS_TYPE_DONATE);
	assert(!hlos_iomem || !svm_donate);

	if ((acl_entries == 0U) || (sgl_entries == 0U)) {
		err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (trans_type == TRANS_TYPE_DONATE) {
		// Memory can only be donated to a single VM.
		if (acl_entries > 1U) {
			err = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}

		// We currently only support donating a single range of normal
		// memory.
		if ((sgl_entries > 1U) || (mem_type != MEM_TYPE_NORMAL)) {
			err = RM_ERROR_DENIED;
			goto out;
		}
	}

	vm_t *vm = vm_lookup(owner_vmid);

	if (acl_entries > MAX_LIST_ENTRIES || sgl_entries > MAX_LIST_ENTRIES ||
	    attr_entries > MAX_LIST_ENTRIES) {
		err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	mp = calloc(1U, sizeof(memparcel_t));
	if (mp == NULL) {
		err = RM_ERROR_NOMEM;
		goto out;
	}

	region_list = calloc(sgl_entries, sizeof(mem_region_t));
	if (region_list == NULL) {
		err = RM_ERROR_NOMEM;
		goto out;
	}

	for (uint16_t i = 0U; i < sgl_entries; i++) {
		region_list[i].memextent_cap	= CSPACE_CAP_INVALID;
		region_list[i].rm_map_memextent = CSPACE_CAP_INVALID;
	}

	vm_list = calloc(acl_entries, sizeof(vm_meminfo_t));
	if (vm_list == NULL) {
		err = RM_ERROR_NOMEM;
		goto out;
	}

	ipa_lists = calloc(sgl_entries * acl_entries, sizeof(uint64_t));
	if (ipa_lists == NULL) {
		err = RM_ERROR_NOMEM;
		goto out;
	}

	if (attr_entries > 0U) {
		attr_list_copy = calloc(attr_entries, sizeof(attr_entry_t));
		if (attr_list_copy == NULL) {
			err = RM_ERROR_NOMEM;
			goto out;
		}
	}

	mp->next	     = NULL;
	mp->prev	     = NULL;
	mp->handle	     = mp_handles++;
	mp->label	     = label;
	mp->label_valid	     = label_valid;
	mp->owner_vmid	     = owner_vmid;
	mp->trans_type	     = trans_type;
	mp->state	     = MEMPARCEL_STATE_SHARING;
	mp->share_count	     = 0U;
	mp->mem_type	     = mem_type;
	mp->hyp_assign	     = hyp_assign;
	mp->sanitize_create  = sanitize;
	mp->sanitize_reclaim = false;
	mp->num_vms	     = acl_entries;
	mp->num_regions	     = sgl_entries;
	mp->num_attrs	     = attr_entries;
	mp->vm_list	     = vm_list;
	mp->region_list	     = region_list;
	mp->attr_list	     = attr_list_copy;

	printf("memparcel: create 0x%x, label 0x%x\n", (unsigned int)mp->handle,
	       (unsigned int)(label_valid ? mp->label : -1U));

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

		if (trans_type == TRANS_TYPE_DONATE) {
			// Only donations from or to HLOS are currently
			// supported.
			if ((owner_vmid != VMID_HLOS) &&
			    (acl[i].vmid != VMID_HLOS)) {
				err = RM_ERROR_DENIED;
				goto out;
			}
			// If donating, we must give the other VM full rights.
			if (acl[i].rights != MEM_RIGHTS_RWX) {
				err = RM_ERROR_DENIED;
				goto out;
			}
		} else {
		}

		vm_list[i].vmid	  = acl[i].vmid;
		vm_list[i].rights = acl[i].rights;
		vm_list[i].attr	  = (mem_type == MEM_TYPE_IO) ? MEM_ATTR_DEVICE
							      : MEM_ATTR_NORMAL;
		vm_list[i].shared = false;
		vm_list[i].ipa_list = ipa_lists + (i * sgl_entries);

		if (owner_vmid == acl[i].vmid) {
			owner_info = &vm_list[i];
		}
	}

	if (hyp_assign) {
	}

	// The owner VM should only be included in the ACL for MEM_SHARE
	if (((trans_type == TRANS_TYPE_SHARE) && (owner_info == NULL)) ||
	    ((trans_type != TRANS_TYPE_SHARE) && (owner_info != NULL))) {
		printf("memparcel: invalid share request\n");
		err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

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

		// If donating, we only support normal attribute.
		if ((trans_type == TRANS_TYPE_DONATE) &&
		    (attr_list[i].attr != MEM_ATTR_NORMAL)) {
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

	for (uint16_t i = 0U; i < sgl_entries; i++) {
		cap_id_t me_cap;
		paddr_t	 phys, offset;
		vmaddr_t ipa	 = sgl[i].ipa;
		size_t	 size	 = sgl[i].size;
		error_t	 hyp_err = OK;

		if (hlos_iomem) {
			// Confirm IO memory is mapped in HLOS
			hlos_memory_result_t mem_ret =
				hlos_memory_is_mapped(ipa, size, true);
			hyp_err = mem_ret.err;
			if (hyp_err != OK) {
				goto err_remap;
			}
		}

		// Create memextent. For IO memory, this will derive from the
		// device memextent provided in the boot env data.
		memextent_memtype_t me_memtype =
			(mem_type == MEM_TYPE_IO) ? MEMEXTENT_MEMTYPE_DEVICE
						  : MEMEXTENT_MEMTYPE_ANY;
		pgtable_access_t access = (mem_type == MEM_TYPE_IO)
						  ? PGTABLE_ACCESS_RW
						  : PGTABLE_ACCESS_RWX;

		cap_id_t parent;

		if (owner_vmid == VMID_RM) {
			parent = CSPACE_CAP_INVALID;
			phys   = (paddr_t)ipa;
			offset = phys;
		} else if (owner_vmid != VMID_HLOS) {
			err = RM_ERROR_MEM_INVALID;
			goto out;
		} else if (mem_type == MEM_TYPE_IO) {
			parent = rm_get_device_me();
			phys   = (paddr_t)ipa;
			offset = phys;
		} else {
			parent = CSPACE_CAP_INVALID;
			phys   = (paddr_t)ipa;
			offset = phys;
		}

		if (svm_donate) {
			err = RM_ERROR_MEM_INVALID;
			goto out;
		} else {
			cap_id_result_t cap_ret = memextent_create(
				offset, size, access, me_memtype, parent);
			if (cap_ret.e != OK) {
				printf("memparcel: Failed to create memextent %d\n",
				       cap_ret.e);
				err = RM_ERROR_MEM_INUSE;
				goto out;
			}
			me_cap = cap_ret.r;
		}

		region_list[i].memextent_cap = me_cap;
		region_list[i].owner_ipa     = ipa;
		region_list[i].phys	     = phys;
		region_list[i].size	     = size;

		printf("[%d]: me:%lx phys:%lx size:%lx ipa:%lx offset:%lx\n", i,
		       me_cap, phys, size, ipa, offset);

		if (owner_vmid == VMID_RM) {
		} else if (hlos_iomem) {
			if (trans_type != TRANS_TYPE_SHARE) {
				hyp_err = hlos_unmap_io_memory(ipa, size, false,
							       me_cap);
				if (hyp_err != OK) {
					printf("memparcel: unmap hlos IO failed\n");
					goto err_remap;
				}
			} else {
				assert(owner_info != NULL);
				if (owner_info->rights != MEM_RIGHTS_RW) {
					printf("memparcel: IO bad owner rights\n");
					hyp_err = ERROR_ARGUMENT_INVALID;
					goto err_remap;
				}
			}
		} else if (hyp_assign) {
		} else if (owner_vmid != VMID_HLOS) {
			cap_id_t addrspace = vm->vm_config->addrspace;

			if (trans_type == TRANS_TYPE_SHARE) {
				assert(owner_info != NULL);
				// Update access rights for owner VM
				pgtable_access_t owner_access =
					mem_rights_to_pgtable_access(
						owner_info->rights);
				hyp_err = memextent_update_access(
					me_cap, addrspace, ipa, owner_access);
				if (hyp_err != OK) {
					printf("memparcel: failed to remap %d\n",
					       hyp_err);
					goto err_remap;
				}
			} else {
				// Unmap from owner VM
				hyp_err = gunyah_hyp_addrspace_unmap(
					addrspace, me_cap, ipa);
				if (hyp_err != OK) {
					printf("memparcel: failed to unmap %d\n",
					       hyp_err);
					goto err_remap;
				}
			}
		}

		if (sanitize) {
			assert(mem_type != MEM_TYPE_IO);
			err = sanitise_region(me_cap, (vmaddr_t)phys, size);
			if (err != RM_OK) {
				printf("memparcel: Failed to sanitize %lx (%lx)\n",
				       ipa, size);
				goto out;
			}
		}

	err_remap:
		if (hlos_iomem && (hyp_err != OK)) {
			if (trans_type != TRANS_TYPE_SHARE) {
				// Restore IO memory that was unmapped
				for (uint16_t j = 0U; j < i; j++) {
					(void)hlos_map_io_memory(
						region_list[j].owner_ipa,
						region_list[j].phys,
						region_list[j].size,
						region_list[i].memextent_cap);
				}
			}
			err = RM_ERROR_MEM_INVALID;
			goto out;
		}
		if ((owner_vmid != VMID_HLOS) && (hyp_err != OK)) {
			cap_id_t addrspace = vm->vm_config->addrspace;
			// Restore SVM memory that was unmapped
			assert(mem_type == MEM_TYPE_NORMAL);
			for (uint16_t j = 0U; j < i; j++) {
				mem_region_t *region = &region_list[i];
				if (trans_type == TRANS_TYPE_SHARE) {
					(void)memextent_update_access(
						region->memextent_cap,
						addrspace, region->owner_ipa,
						PGTABLE_ACCESS_RWX);
				} else {
					(void)memextent_map(
						region->memextent_cap,
						addrspace, region->owner_ipa,
						PGTABLE_ACCESS_RWX,
						PGTABLE_VM_MEMTYPE_NORMAL_WB);
				}
			}
			err = RM_ERROR_MEM_INVALID;
			goto out;
		}
	}

	if (memparcel_list_head != NULL) {
		memparcel_list_tail->next = mp;
		mp->prev		  = memparcel_list_tail;
	} else {
		memparcel_list_head = mp;
		mp->prev	    = NULL;
	}

	memparcel_list_tail = mp;
	mp->next	    = NULL;

	err = RM_OK;
out:
	if (err != RM_OK) {
		printf("memparcel_construct ret=%d\n", err);
	}

	memparcel_construct_ret_t ret;

	if (err != RM_OK) {
		free(mp);
		free(vm_list);
		free(ipa_lists);
		free(attr_list_copy);
		if (region_list != NULL) {
			region_list_cleanup_memextents(owner_vmid, trans_type,
						       region_list,
						       sgl_entries);
			free(region_list);
		}
		ret.err	   = err;
		ret.handle = 0U;
	} else {
		ret.err	   = RM_OK;
		ret.handle = mp->handle;
	}

	return ret;
}

void
memparcel_create(vmid_t vmid, uint32_t msg_id, uint16_t seq_num, uint8_t *buf,
		 size_t len)
{
	rm_error_t err;
	uint8_t	   mem_type, trans_type, flags;
	uint32_t   handle = MEMPARCEL_INVALID_HANDLE;
	uint32_t   label;
	bool	   sanitize   = false;
	bool	   hyp_assign = false;

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

	printf("MEM_%s: from:%d\n", type_str, vmid);

	if (len < sizeof(memparcel_create_req_t)) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	memparcel_create_req_t *req = (memparcel_create_req_t *)(uintptr_t)buf;

	mem_type = req->mem_type;
	flags	 = req->flags;
	label	 = req->label;

	if ((flags & MEM_CREATE_FLAG_SANITIZE) != 0U) {
		if (mem_type == MEM_TYPE_IO) {
			err = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}
		sanitize = true;
	}

	if ((vmid == VMID_HLOS) && (mem_type == MEM_TYPE_NORMAL)) {
		hyp_assign = true;
	}

	uint32_t      acl_entries  = 0U;
	uint16_t      sgl_entries  = 0U;
	uint16_t      attr_entries = 0U;
	acl_entry_t  *acl	   = NULL;
	sgl_entry_t  *sgl	   = NULL;
	attr_entry_t *attr_list	   = NULL;

	size_t list_offset = offsetof(memparcel_create_req_t, acl_entries);
	err = memparcel_read_lists(buf + list_offset, len - list_offset,
				   &acl_entries, &sgl_entries, &attr_entries,
				   &acl, &sgl, &attr_list, true);
	if (err != RM_OK) {
		goto out;
	}

	memparcel_construct_ret_t mp_r = memparcel_construct(
		vmid, acl_entries, sgl_entries, attr_entries, acl, sgl,
		attr_list, label, true, mem_type, trans_type, hyp_assign,
		sanitize);
	err = mp_r.err;

	if (err == RM_OK) {
		handle = mp_r.handle;
	}

out:
	printf("MEM_%s: ret=%d\n", type_str, err);

	if (err == RM_OK) {
		assert(memparcel_list_tail != NULL);

		memparcel_handle_resp_t resp = {
			.handle = handle,
		};

		rm_reply(vmid, msg_id, seq_num, &resp, sizeof(resp));
	} else {
		rm_standard_reply(vmid, msg_id, seq_num, err);
	}
}

void
memparcel_accept(vmid_t vmid, uint16_t seq_num, uint8_t *buf, size_t len)
{
	rm_error_t		     err	 = RM_OK;
	memparcel_accept_sgl_resp_t *resp	 = NULL;
	size_t			     resp_size	 = 0U;
	uint16_t		     sgl_entries = 0U;

	if (len < sizeof(memparcel_accept_req_t)) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	memparcel_accept_req_t *req = (memparcel_accept_req_t *)(uintptr_t)buf;

	mem_handle_t  handle	   = req->handle;
	uint8_t	      mem_type	   = req->mem_type;
	uint8_t	      trans_type   = req->trans_type;
	uint8_t	      flags	   = req->flags;
	uint32_t      label	   = req->label;
	uint32_t      acl_entries  = 0U;
	uint16_t      attr_entries = 0U;
	acl_entry_t  *acl	   = NULL;
	sgl_entry_t  *sgl	   = NULL;
	attr_entry_t *attr_list	   = NULL;

	printf("MEM_ACCEPT: from:%d handle:%d\n", vmid, (int)handle);

	size_t list_offset = offsetof(memparcel_accept_req_t, acl_entries);
	err = memparcel_read_lists(buf + list_offset, len - list_offset,
				   &acl_entries, &sgl_entries, &attr_entries,
				   &acl, &sgl, &attr_list, true);
	if (err != RM_OK) {
		goto out;
	}

	const size_t map_vmid_offset =
		offsetof(memparcel_accept_req_t, map_vmid) +
		(acl_entries * sizeof(acl_entry_t));
	vmid_t map_vmid = *(uint16_t *)((uintptr_t)buf + map_vmid_offset);

	err = memparcel_do_accept(vmid, acl_entries, sgl_entries, attr_entries,
				  acl, sgl, attr_list, map_vmid, handle, label,
				  mem_type, trans_type, flags, &resp,
				  &resp_size);

out:
	printf("MEM_ACCEPT: ret=%d\n", err);

	if ((err == RM_OK) && (sgl_entries == 0U)) {
		assert(resp != NULL);
		err = rm_rpc_fifo_reply(vmid, MEM_ACCEPT, seq_num, resp,
					resp_size, resp_size);
		if (err != RM_OK) {
			free(resp);
			printf("memparcel_accept: error sending reply %d", err);
			exit(1);
		}
	} else {
		assert(resp == NULL);
		rm_standard_reply(vmid, MEM_ACCEPT, seq_num, err);
	}
}

static rm_error_t
memparcel_tag_regions(memparcel_t *mp, vmid_t map_vmid, bool register_region)
{
	rm_error_t ret = RM_OK;

	(void)map_vmid;
	(void)register_region;

	if (mp->mem_type != MEM_TYPE_NORMAL) {
		ret = RM_ERROR_DENIED;
	}

	return ret;
}

rm_error_t
memparcel_do_accept(vmid_t vmid, uint32_t acl_entries, uint16_t sgl_entries,
		    uint16_t attr_entries, acl_entry_t *acl, sgl_entry_t *sgl,
		    attr_entry_t *attr_list, vmid_t map_vmid,
		    mem_handle_t handle, uint32_t label, uint8_t mem_type,
		    uint8_t trans_type, uint8_t flags,
		    memparcel_accept_sgl_resp_t **resp, size_t *resp_size)
{
	assert(resp != NULL);
	assert(resp_size != NULL);

	rm_error_t   err = RM_OK;
	memparcel_t *mp	 = lookup_memparcel(handle);
	if (mp == NULL) {
		err = RM_ERROR_HANDLE_INVALID;
		goto out;
	}

	if ((mem_type != mp->mem_type) || (trans_type != mp->trans_type)) {
		err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if ((flags & MEM_ACCEPT_FLAG_DONE) == 0U) {
		err = RM_ERROR_DENIED;
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

	bool contiguous = false;
	if ((flags & MEM_ACCEPT_FLAG_MAP_CONTIGUOUS) != 0U) {
		if (mem_type != MEM_TYPE_NORMAL) {
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
		if ((map_vm->rights & MEM_RIGHTS_W) == 0U) {
			err = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}

		mp->sanitize_reclaim = true;
	}

	vm_t *vm = vm_lookup(map_vmid);
	if (vm == NULL) {
		err = RM_ERROR_VMID_INVALID;
		goto out;
	}
	cap_id_t addrspace = vm->vm_config->addrspace;

	if (map_vm->vmid == mp->owner_vmid) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	pgtable_vm_memtype_t memtype_map =
		mem_attr_to_map_memtype(map_vm->attr);
	pgtable_access_t access = mem_rights_to_pgtable_access(map_vm->rights);

	if (contiguous) {
		size_t contiguous_size = 0U;
		for (uint16_t i = 0U; i < mp->num_regions; i++) {
			contiguous_size += mp->region_list[i].size;
		}

		address_range_allocator_alloc_ret_t as_ret;
		if (sgl_entries == 0U) {
			*resp_size = sizeof(memparcel_accept_sgl_resp_t) +
				     sizeof(sgl_entry_t);
			*resp = calloc(*resp_size, 1U);
			if (*resp == NULL) {
				err = RM_ERROR_NOMEM;
				goto out;
			}

			size_t alignment = (contiguous_size >= SIZE_2M)
						   ? SIZE_2M
						   : PAGE_SIZE;

			as_ret = address_range_allocator_alloc(vm->as_allocator,
							       INVALID_ADDRESS,
							       contiguous_size,
							       alignment);
		} else if (sgl_entries == 1U) {
			if (sgl[0].size != contiguous_size) {
				err = RM_ERROR_ARGUMENT_INVALID;
				goto out;
			}

			as_ret = address_range_allocator_alloc(
				vm->as_allocator, sgl[0].ipa, sgl[0].size,
				ALIGNMENT_IGNORED);
		} else {
			err = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}

		if (as_ret.err != OK) {
			err = RM_ERROR_NORESOURCE;
			goto out;
		}

		vmaddr_t base = as_ret.base_address;
		vmaddr_t curr = base;
		uint16_t i;
		error_t	 hyp_err;
		for (i = 0U; i < mp->num_regions; i++) {
			hyp_err = memextent_map(
				mp->region_list[i].memextent_cap, addrspace,
				curr, access, memtype_map);
			if (hyp_err != OK) {
				err = RM_ERROR_MAP_FAILED;
				break;
			}

			map_vm->ipa_list[i] = curr;
			curr += mp->region_list[i].size;
		}

		if (err != RM_OK) {
			// rollback mappings
			curr = base;
			for (uint16_t j = 0U; j < i; j++) {
				hyp_err = gunyah_hyp_addrspace_unmap(
					addrspace,
					mp->region_list[j].memextent_cap, curr);
				assert(hyp_err == OK);
				curr += mp->region_list[j].size;
			}

			hyp_err = address_range_allocator_free(
				vm->as_allocator, base, contiguous_size);
			assert(hyp_err == OK);

			goto out;
		}

		if (sgl_entries == 0U) {
			(*resp)->err	     = RM_OK;
			(*resp)->sgl_entries = 1U;

			sgl_entry_t *resp_sgl =
				(sgl_entry_t *)(uintptr_t)(*resp + 1U);

			resp_sgl[0].ipa	 = base;
			resp_sgl[0].size = contiguous_size;
		}
	} else if (sgl_entries == mp->num_regions) {
		error_t	 error;
		uint16_t i;

		for (i = 0U; i < sgl_entries; i++) {
			if (sgl[i].size != mp->region_list[i].size) {
				err = RM_ERROR_ARGUMENT_INVALID;
				break;
			}

			if (mem_type == MEM_TYPE_IO) {
				// FIXME: Enforce 1:1 mapping
				if (sgl[i].ipa != mp->region_list[i].phys) {
					err = RM_ERROR_ARGUMENT_INVALID;
					break;
				}
			} else {
				address_range_allocator_alloc_ret_t as_ret;

				as_ret = address_range_allocator_alloc(
					vm->as_allocator, sgl[i].ipa,
					sgl[i].size, ALIGNMENT_IGNORED);
				if (as_ret.err != OK) {
					err = RM_ERROR_NORESOURCE;
					break;
				}
			}

			map_vm->ipa_list[i] = sgl[i].ipa;

			error = memextent_map(mp->region_list[i].memextent_cap,
					      addrspace, map_vm->ipa_list[i],
					      access, memtype_map);
			if (error != OK) {
				err = RM_ERROR_MAP_FAILED;
				if (mem_type != MEM_TYPE_IO) {
					error = address_range_allocator_free(
						vm->as_allocator, sgl[i].ipa,
						sgl[i].size);
					assert(error == OK);
				}
				break;
			}
		}
		if (err != RM_OK) {
			// rollback mappings
			for (uint16_t j = 0U; j < i; j++) {
				error = gunyah_hyp_addrspace_unmap(
					addrspace,
					mp->region_list[j].memextent_cap,
					map_vm->ipa_list[j]);
				assert(error == OK);

				if (mem_type != MEM_TYPE_IO) {
					error = address_range_allocator_free(
						vm->as_allocator, sgl[j].ipa,
						sgl[j].size);
					assert(error == OK);
				}
			}

			goto out;
		}

	} else if (sgl_entries == 0U) {
		error_t	 error;
		uint16_t i;

		*resp_size = sizeof(memparcel_accept_sgl_resp_t) +
			     (sizeof(sgl_entry_t) * mp->num_regions);
		*resp = calloc(*resp_size, 1U);

		if (*resp == NULL) {
			err = RM_ERROR_NOMEM;
			goto out;
		}

		sgl_entry_t *resp_sgl = (sgl_entry_t *)(uintptr_t)(*resp + 1U);
		for (i = 0U; i < mp->num_regions; i++) {
			if (mem_type == MEM_TYPE_IO) {
				// IO memory must be mapped 1:1. The region is
				// already reserved in the address range
				// allocator.
				map_vm->ipa_list[i] = mp->region_list[i].phys;
			} else {
				address_range_allocator_alloc_ret_t as_ret;

				size_t alignment = mp->region_list[i].size >=
								   SIZE_2M
							   ? SIZE_2M
							   : PAGE_SIZE;

				as_ret = address_range_allocator_alloc(
					vm->as_allocator, INVALID_ADDRESS,
					mp->region_list[i].size, alignment);
				if (as_ret.err != OK) {
					err = RM_ERROR_NORESOURCE;
					break;
				}

				map_vm->ipa_list[i] = as_ret.base_address;
			}

			resp_sgl[i].ipa	 = map_vm->ipa_list[i];
			resp_sgl[i].size = mp->region_list[i].size;

			error = memextent_map(mp->region_list[i].memextent_cap,
					      addrspace, map_vm->ipa_list[i],
					      access, memtype_map);
			if (error != OK) {
				err = RM_ERROR_MAP_FAILED;

				if (mem_type != MEM_TYPE_IO) {
					error = address_range_allocator_free(
						vm->as_allocator,
						resp_sgl[i].ipa,
						resp_sgl[i].size);
					assert(error == OK);
				}
				break;
			}
		}
		if (err != RM_OK) {
			// rollback mappings
			for (uint16_t j = 0U; j < i; j++) {
				error = gunyah_hyp_addrspace_unmap(
					addrspace,
					mp->region_list[j].memextent_cap,
					resp_sgl[j].ipa);
				assert(error == OK);

				if (mem_type != MEM_TYPE_IO) {
					error = address_range_allocator_free(
						vm->as_allocator,
						resp_sgl[j].ipa,
						resp_sgl[j].size);
					assert(error == OK);
				}
			}

			goto out;
		}

		(*resp)->err	     = RM_OK;
		(*resp)->sgl_entries = mp->num_regions;
	} else {
		err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (trans_type == TRANS_TYPE_DONATE) {
		assert(mp->num_regions == 1U);

		mem_region_t *region = &mp->region_list[0];
		if (map_vmid != VMID_HLOS) {
		} else {
			// We are accepting a donation back to HLOS.
			assert(mp->owner_vmid != VMID_HLOS);

			vm_t *owner_vm = vm_lookup(mp->owner_vmid);
			assert(owner_vm != NULL);

			// Free the region's allocated address range.
			error_t hyp_err = address_range_allocator_free(
				owner_vm->as_allocator, region->owner_ipa,
				region->size);
			assert(hyp_err == OK);
		}

		// Complete the donation by deleting the memparcel.
		delete_memparcel(map_vmid, mp);
	} else {
		map_vm->shared = true;
		mp->share_count++;
		mp->state = MEMPARCEL_STATE_SHARED;
	}

	// tag memparcel
	if (mp->sanitize_reclaim && vm->sensitive) {
		err = memparcel_tag_regions(mp, map_vmid, true);
	}

out:
	if ((err != OK) && (*resp != NULL)) {
		free(*resp);
		*resp = NULL;
	}

	return err;
}

void
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

	printf("MEM_RELEASE: from:%d handle:%d\n", vmid, (int)handle);

	memparcel_t *mp = lookup_memparcel(handle);
	if (mp == NULL) {
		err = RM_ERROR_HANDLE_INVALID;
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

	vm_t *vm = vm_lookup(vmid);
	assert(vm != NULL);

	for (uint16_t i = 0U; i < mp->num_regions; i++) {
		cap_id_t addrspace = vm->vm_config->addrspace;
		error_t	 error	   = gunyah_hyp_addrspace_unmap(
			     addrspace, mp->region_list[i].memextent_cap,
			     vm_info->ipa_list[i]);
		if (error != OK) {
			err = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}

		if (mp->mem_type != MEM_TYPE_IO) {
			error = address_range_allocator_free(
				vm->as_allocator, vm_info->ipa_list[i],
				mp->region_list[i].size);
			assert(error == OK);
		}

		vm_info->ipa_list[i] = 0U;
	}

	vm_info->shared = false;
	mp->share_count--;

	if (mp->share_count == 0U) {
		mp->state = MEMPARCEL_STATE_SHARING;
	}

	// untag memparcel
	if (mp->sanitize_reclaim && vm->sensitive) {
		err = memparcel_tag_regions(mp, vmid, false);
	}

out:
	printf("MEM_RELEASE: ret=%d\n", err);
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

	if (mp->state != MEMPARCEL_STATE_SHARING) {
		err = RM_ERROR_MEM_INUSE;
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

	vm_meminfo_t *owner_info = NULL;
	for (uint32_t i = 0U; i < mp->num_vms; i++) {
		if (mp->vm_list[i].vmid == vmid) {
			owner_info = &mp->vm_list[i];
			break;
		}
	}

	vm_t *vm = vm_lookup(vmid);
	if (vm == NULL) {
		err = RM_ERROR_VMID_INVALID;
		goto out;
	}
	cap_id_t addrspace = vm->vm_config->addrspace;

	for (uint16_t i = 0U; i < mp->num_regions; i++) {
		cap_id_t me_cap = mp->region_list[i].memextent_cap;
		vmaddr_t ipa	= mp->region_list[i].owner_ipa;
		paddr_t	 phys	= mp->region_list[i].phys;
		size_t	 size	= mp->region_list[i].size;

		if (mp->sanitize_reclaim) {
			// map into rm, memset zero, unmap
			assert(mp->mem_type != MEM_TYPE_IO);
			err = sanitise_region(me_cap, (vmaddr_t)phys, size);
			if (err != RM_OK) {
				goto out;
			}
		}

		if (!mp->hyp_assign && (vmid == VMID_HLOS) &&
		    (mp->mem_type == MEM_TYPE_IO)) {
			// remap IO memory in HLOS
			error_t hyp_err = OK;
			if (mp->trans_type != TRANS_TYPE_SHARE) {
				hyp_err = hlos_map_io_memory(ipa, phys, size,
							     me_cap);
			}
			if (hyp_err != OK) {
				for (uint16_t j = 0U; j < i; j++) {
					(void)hlos_unmap_io_memory(
						ipa, size, false, me_cap);
				}

				err = RM_ERROR_MAP_FAILED;
				goto out;
			}
		} else if (mp->hyp_assign) {
		} else if (vmid != VMID_HLOS) {
			// Remap memory in SVM
			assert(mp->mem_type == MEM_TYPE_NORMAL);

			error_t hyp_err;
			if (mp->trans_type == TRANS_TYPE_SHARE) {
				hyp_err = memextent_update_access(
					me_cap, addrspace, ipa,
					PGTABLE_ACCESS_RWX);
			} else {
				hyp_err = memextent_map(
					me_cap, addrspace, ipa,
					PGTABLE_ACCESS_RWX,
					PGTABLE_VM_MEMTYPE_NORMAL_WB);
			}

			if (hyp_err != OK) {
				for (uint16_t j = 0U; j < i; j++) {
					mem_region_t *region =
						&mp->region_list[j];
					if (mp->trans_type ==
					    TRANS_TYPE_SHARE) {
						assert(owner_info != NULL);
						pgtable_access_t access =
							mem_rights_to_pgtable_access(
								owner_info
									->rights);
						(void)memextent_update_access(
							region->memextent_cap,
							addrspace,
							region->owner_ipa,
							access);
					} else {
						(void)gunyah_hyp_addrspace_unmap(
							addrspace,
							region->memextent_cap,
							region->owner_ipa);
					}
				}
				goto out;
			}
		}
	}

	delete_memparcel(vmid, mp);

out:
	return err;
}

void
memparcel_reclaim(vmid_t vmid, uint16_t seq_num, uint8_t *buf, size_t len)
{
	rm_error_t err = RM_OK;

	if (len < sizeof(memparcel_reclaim_req_t)) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	memparcel_reclaim_req_t *req =
		(memparcel_reclaim_req_t *)(uintptr_t)buf;

	mem_handle_t handle = req->handle;
	uint8_t	     flags  = req->flags;

	printf("MEM_RECLAIM: from:%d handle:%d\n", vmid, (int)handle);

	err = memparcel_do_reclaim(vmid, handle, flags);

out:
	printf("MEM_RECLAIM: res=%d\n", err);
	rm_standard_reply(vmid, MEM_RECLAIM, seq_num, err);
}

static rm_error_t
memparcel_notify_shared(memparcel_t *mp, vmid_t src_vmid, uint8_t *buf,
			size_t len)
{
	rm_error_t err = RM_OK;

	if (src_vmid != mp->owner_vmid) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	size_t vmid_list_offset = sizeof(memparcel_notify_req_t) + 4U;
	if (len < vmid_list_offset) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	uint16_t vmid_entries =
		*(uint16_t *)((uintptr_t)buf + sizeof(memparcel_notify_req_t));
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
		(vmid_entry_t *)((uintptr_t)buf + vmid_list_offset);
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

	size_t notif_size = sizeof(memparcel_shared_notif_t) +
			    (mp->num_vms * sizeof(acl_entry_t)) +
			    (mp->num_regions * sizeof(uint64_t));
	if (!mp->hyp_assign) {
		notif_size += 4U + (mp->num_attrs * sizeof(attr_entry_t));
	}

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

	*(uint16_t *)curr = mp->num_regions;
	curr += 4U;

	uint64_t *size_list = (uint64_t *)curr;
	for (uint16_t i = 0U; i < mp->num_regions; i++) {
		size_list[i] = mp->region_list[i].size;
		curr += sizeof(uint64_t);
	}

	if (!mp->hyp_assign) {
		*(uint16_t *)curr = mp->num_attrs;
		curr += 4U;

		attr_entry_t *attr_list = (attr_entry_t *)curr;
		for (uint16_t i = 0U; i < mp->num_attrs; i++) {
			attr_list[i].attr = mp->attr_list[i].attr;
			attr_list[i].vmid = mp->attr_list[i].vmid;
		}
	}

	for (uint16_t i = 0U; i < vmid_entries; i++) {
		vmid_t target_vmid = vmid_list[i].vmid;
		vm_t  *target_vm   = vm_lookup(target_vmid);

		assert(target_vm != NULL);
		if (target_vm->vm_state == VM_STATE_READY) {
			error_t e =
				vm_creation_process_memparcel(target_vmid, mp);
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

rm_error_t
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

void
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
		       mp->mem_info_tag_set, req->mem_info_tag, flags);
		err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (!mp->mem_info_tag_set && (flags == MEM_NOTIFY_FLAG_SHARED)) {
		memparcel_set_mem_info_tag(mp, req->mem_info_tag);
	}

	if (flags == MEM_NOTIFY_FLAG_SHARED) {
		err = memparcel_notify_shared(mp, vmid, buf, len);
	} else if (flags == MEM_NOTIFY_FLAG_RELEASED) {
		err = memparcel_notify_owner(mp, vmid, false);
	} else if (flags == MEM_NOTIFY_FLAG_ACCEPTED) {
		err = memparcel_notify_owner(mp, vmid, true);
	} else {
		err = RM_ERROR_ARGUMENT_INVALID;
	}

out:
	printf("MEM_NOTIFY: from:%d handle:%d ret=%d\n", vmid, (int)handle,
	       err);
	rm_standard_reply(vmid, MEM_NOTIFY, seq_num, err);
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
		memparcel_accept(client_id, seq_num, buf, len);
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
	default:
		handled = false;
		break;
	}

	return handled;
}

error_t
memparcel_map_rm(uint32_t handle, size_t offset, uintptr_t addr, size_t size)
{
	memparcel_t *mp	 = lookup_memparcel(handle);
	error_t	     err = OK;

	if (mp == NULL) {
		err = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	size_t next_offset = offset;
	size_t next_addr   = addr;
	size_t next_size   = size;

	// First, ensure that no region in this memparcel is already mapped.
	for (count_t i = 0U; i < (count_t)mp->num_regions; i++) {
		if (mp->region_list[i].rm_map_memextent != CSPACE_CAP_INVALID) {
			err = ERROR_BUSY;
			goto out;
		}
	}

	for (count_t i = 0U;
	     (next_size != 0U) && (i < (count_t)mp->num_regions); i++) {
		if (next_offset >= mp->region_list[i].size) {
			// offset is completely outside this region; skip it
			next_offset -= mp->region_list[i].size;
			continue;
		}

		size_t this_size = mp->region_list[i].size - next_offset;
		if (this_size > next_size) {
			this_size = next_size;
		}

		pgtable_vm_memtype_t memtype_map =
			(mp->mem_type == MEM_TYPE_IO)
				? PGTABLE_VM_MEMTYPE_DEVICE_NGNRE
				: PGTABLE_VM_MEMTYPE_NORMAL_WB;
		cap_id_result_t cap_ret = memextent_create_and_map(
			rm_get_rm_addrspace(), next_offset, next_addr,
			this_size, PGTABLE_ACCESS_RW, mp->mem_type, memtype_map,
			mp->region_list[i].memextent_cap);
		if (cap_ret.e != OK) {
			err = cap_ret.e;
			break;
		}
		mp->region_list[i].rm_map_memextent = cap_ret.r;
		mp->region_list[i].rm_map_addr	    = next_addr;

		next_addr += this_size;
	}

	if (err != OK) {
		error_t unmap_err = memparcel_unmap_rm(handle);
		assert(unmap_err == OK);
	}
out:
	return err;
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

	for (count_t i = 0U; i < (count_t)mp->num_regions; i++) {
		if (mp->region_list[i].rm_map_memextent != CSPACE_CAP_INVALID) {
			err = gunyah_hyp_addrspace_unmap(
				rm_get_rm_addrspace(),
				mp->region_list[i].rm_map_memextent,
				mp->region_list[i].rm_map_addr);
			if (err != OK) {
				break;
			}

			err = gunyah_hyp_cspace_delete_cap_from(
				rm_get_rm_cspace(),
				mp->region_list[i].rm_map_memextent);
			if (err != OK) {
				break;
			}

			mp->region_list[i].rm_map_memextent =
				CSPACE_CAP_INVALID;
		}
	}

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
	return mp->num_regions;
}

paddr_result_t
memparcel_get_phys(const memparcel_t *mp, count_t region_index)
{
	if (region_index >= mp->num_regions) {
		return paddr_result_error(ERROR_ARGUMENT_INVALID);
	}
	return paddr_result_ok(mp->region_list[region_index].phys);
}

vmaddr_result_t
memparcel_get_mapped_ipa(const memparcel_t *mp, vmid_t vmid,
			 count_t region_index)
{
	if (region_index >= mp->num_regions) {
		return vmaddr_result_error(ERROR_ARGUMENT_INVALID);
	}
	for (count_t i = 0; i < mp->num_vms; i++) {
		if (mp->vm_list[i].vmid == vmid) {
			return vmaddr_result_ok(
				mp->vm_list[i].ipa_list[region_index]);
		}
	}
	return vmaddr_result_error(ERROR_ARGUMENT_INVALID);
}

size_t
memparcel_get_size(const memparcel_t *mp)
{
	size_t size = 0U;

	for (index_t i = 0U; i < mp->num_regions; i++) {
		size += mp->region_list[i].size;
	}

	return size;
}

size_result_t
memparcel_get_region_size(const memparcel_t *mp, count_t region_index)
{
	if (region_index >= mp->num_regions) {
		return size_result_error(ERROR_ARGUMENT_INVALID);
	}
	return size_result_ok(mp->region_list[region_index].size);
}

memparcel_t *
memparcel_iter_by_target_vmid(memparcel_t *after, vmid_t vmid)
{
	memparcel_t *mp = (after == NULL) ? memparcel_list_head : after->next;

	while (mp != NULL) {
		for (count_t i = 0; i < mp->num_vms; i++) {
			if (mp->vm_list[i].vmid == vmid) {
				return mp;
			}
		}
		mp = mp->next;
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
