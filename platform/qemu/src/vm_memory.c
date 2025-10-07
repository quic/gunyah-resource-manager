// © 2022 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// This file contains code which is not platform-specifc; these generic
// components should be moved so they can be used across platforms.
// FIXME:

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <rm_types.h>
#include <util.h>
#include <utils/address_range_allocator.h>
#include <utils/vector.h>

#include <event.h>
#include <guest_interface.h>
#include <irq_manager.h>
#include <mem_region.h>
#include <memextent.h>
#include <memparcel.h>
#include <memparcel_msg.h>
#include <platform.h>
#include <platform_vm_config.h>
#include <platform_vm_memory.h>
#include <resource-manager.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_creation.h>
#include <vm_ipa_message.h>
#include <vm_memory.h>
#include <vm_mgnt.h>

// FIXME: hyp API should allow this to be configured and/or queried
#define SVM_ADDRESS_SPACE_BITS 36

// Address range tag bits. All valid tags must have the valid bit set.
#define ADDRESS_RANGE_TAG_VALID	 1U
#define ADDRESS_RANGE_TAG_ECC	 2U
#define ADDRESS_RANGE_TAG_MEMTAG 4U
#define ADDRESS_RANGE_TAG_NORMAL 8U

#define ADDRESS_RANGE_TAG_MASK ~(address_range_tag_t)0U

struct vm_acl_info {
	cap_id_t hyp_assign_me_cap;
};

static cap_id_t parent_ddr_me = CSPACE_CAP_INVALID;

static paddr_t device_addr_limit = 0U;

static cap_id_t batch_me_cap  = CSPACE_CAP_INVALID;
static bool	batch_me_sync = false;

static void
maybe_sync(cap_id_t memextent_cap)
{
	if (memextent_cap == CSPACE_CAP_INVALID) {
		// Given extent is not valid; this is only possible after
		// donation from a partition, so there is no need to sync.
	} else if (memextent_cap == batch_me_cap) {
		// We are in a batch job for the given extent; trigger a sync at
		// the end of the job.
		batch_me_sync = true;
	} else if (batch_me_cap != CSPACE_CAP_INVALID) {
		// We are in a batch job for a different extent; sync and start
		// a new batch job.
		memextent_sync_all(batch_me_cap);
		batch_me_cap = memextent_cap;
	} else {
		// No batch job in progress; sync immediately.
		memextent_sync_all(memextent_cap);
	}
}

static bool
is_mapped_direct(vm_t *vm, vm_memuse_t memuse)
{
	bool ret = false;

	assert(vm != NULL);
	assert(vm->vm_config != NULL);

	switch (memuse) {
	case VM_MEMUSE_IO:
		ret = true;
		break;
	case VM_MEMUSE_NORMAL:
	case VM_MEMUSE_BOOTINFO:
		ret = (vm->vmid == VMID_HLOS) || vm->vm_config->mem_map_direct;
		break;
	case VM_MEMUSE_PROTECTED:
	case VM_MEMUSE_VDEVICE:
	case VM_MEMUSE_PLATFORM_VDEVICE:
	default:
		break;
	}

	return ret;
}

static bool
is_device_mapping(vm_memuse_t memuse, vmaddr_t ipa, size_t size)
{
	// Platform vdevices are based on real devices, so allow them to overlap
	// with device extent IPAs. It is the VM's responsibility to ensure
	// these vdevices don't conflict with other device mappings.
	bool ret = false;

	if ((memuse != VM_MEMUSE_PLATFORM_VDEVICE) ||
	    (ipa == INVALID_ADDRESS)) {
		goto out;
	}

	paddr_t dev_base;
	size_t	dev_size;

	count_t device_ranges_count = rm_get_device_ranges_count();
	for (index_t i = 0U; i < device_ranges_count; i++) {
		rm_get_device_ranges(i, &dev_base, &dev_size);
		if (ipa >= dev_base &&
		    ((ipa + size) <= (dev_base + dev_size))) {
			ret = true;
			break;
		}
	}
out:
	return ret;
}

static cap_id_result_t
create_ddr_me(cap_id_t parent)
{
	return memextent_create(0U, ADDR_LIMIT, MEMEXTENT_TYPE_SPARSE,
				PGTABLE_ACCESS_RWX, MEMEXTENT_MEMTYPE_ANY,
				parent);
}

static cap_id_result_t
create_device_me(void)
{
	cap_id_result_t ret = memextent_create(
		0U, device_addr_limit, MEMEXTENT_TYPE_SPARSE, PGTABLE_ACCESS_RW,
		MEMEXTENT_MEMTYPE_DEVICE, rm_get_device_me_cap());
	if (ret.e != OK) {
		goto out;
	}

	// The derived extent has mappings in HLOS; we need to unmap them.
	error_t err = memextent_unmap_all(ret.r);
	if (err != OK) {
		memextent_delete(ret.r);
		ret = cap_id_result_error(err);
		goto out;
	}

out:
	return ret;
}

error_t
vm_memory_init(void)
{
	cap_id_result_t ret = create_ddr_me(CSPACE_CAP_INVALID);

	if (ret.e == OK) {
		parent_ddr_me = ret.r;
	}

	// Get the device address limit
	paddr_t addr_limit_tmp	    = 0U;
	count_t device_ranges_count = rm_get_device_ranges_count();
	for (index_t i = 0U; i < device_ranges_count; i++) {
		paddr_t dev_base;
		size_t	dev_size;
		paddr_t dev_addr_limit;

		rm_get_device_ranges(i, &dev_base, &dev_size);
		dev_addr_limit = dev_base + dev_size;

		if (dev_addr_limit > addr_limit_tmp) {
			addr_limit_tmp = dev_addr_limit;
		}
	}

	device_addr_limit = addr_limit_tmp;

	return ret.e;
}

error_t
vm_memory_setup(vm_t *vm)
{
	error_t err = OK;

	assert(vm != NULL);

	vm->private_paged_ddr_me = CSPACE_CAP_INVALID;
	vm->shared_paged_ddr_me	 = CSPACE_CAP_INVALID;

	vm->owned_ddr_me    = CSPACE_CAP_INVALID;
	vm->owned_device_me = CSPACE_CAP_INVALID;

	cap_id_result_t cap_ret = create_ddr_me(parent_ddr_me);
	if (cap_ret.e != OK) {
		err = cap_ret.e;
		goto out;
	}

	vm->owned_ddr_me = cap_ret.r;

	cap_ret = create_device_me();
	if (cap_ret.e != OK) {
		err = cap_ret.e;
		goto out;
	}

	vm->owned_device_me = cap_ret.r;

out:
	if (err != OK) {
		vm_memory_teardown(vm);
	}

	return err;
}

error_t
vm_memory_vm_start(vm_t *vm)
{
	error_t err;
	if (vm->sensitive) {
		err = memextent_set_sanitise_on_reset(vm->owned_ddr_me);
	} else {
		err = OK;
	}
	return err;
}

void
vm_memory_sanitise(const vm_t *vm)
{
	bool has_protected = vm->vm_config->mem_demand_paging &&
			     vm->mem_private;

	if (vm->vm_config->addrspace == CSPACE_CAP_INVALID) {
		// nothing to sanitise
	} else if (has_protected) {
		addrspace_modify_pages_flags_t flags =
			addrspace_modify_pages_flags_default();
		addrspace_modify_pages_flags_set_unlock(&flags, true);
		addrspace_modify_pages_flags_set_sanitise(&flags, true);
		gunyah_hyp_addrspace_modify_pages_result_t ret =
			gunyah_hyp_addrspace_modify_pages(
				vm->vm_config->addrspace, 0U,
				util_bit(SVM_ADDRESS_SPACE_BITS), flags);
		assert((ret.error == OK) && (ret.size_remaining == 0U));
	} else {
		// Not protected or not demand-paged; any required sanitisation
		// will be done during memparcel reclaim.
	}
}

void
vm_memory_teardown(vm_t *vm)
{
	if (vm->owned_ddr_me != CSPACE_CAP_INVALID) {
		memextent_delete(vm->owned_ddr_me);
	}

	if (vm->owned_device_me != CSPACE_CAP_INVALID) {
		memextent_delete(vm->owned_device_me);
	}

	if (vm->private_paged_ddr_me != CSPACE_CAP_INVALID) {
		memextent_delete(vm->private_paged_ddr_me);
	}

	if (vm->shared_paged_ddr_me != CSPACE_CAP_INVALID) {
		memextent_delete(vm->shared_paged_ddr_me);
	}
}

error_t
vm_memory_map(vm_t *vm, vm_memuse_t memuse, cap_id_t me_cap, vmaddr_t ipa,
	      pgtable_access_t access, pgtable_vm_memtype_t map_memtype)
{
	error_t err = OK;

	(void)memuse;

	assert(vm != NULL);
	assert(vm->vm_config != NULL);

	cap_id_t addrspace = vm->vm_config->addrspace;

	err = memextent_map(me_cap, addrspace, ipa, access, map_memtype,
			    memuse == VM_MEMUSE_PROTECTED);
	if (err == OK) {
		maybe_sync(me_cap);
	}

	return err;
}

error_t
vm_memory_map_partial(vm_t *vm, vm_memuse_t memuse, cap_id_t me_cap,
		      vmaddr_t ipa, size_t offset, size_t size,
		      pgtable_access_t access, pgtable_vm_memtype_t map_memtype)
{
	error_t err = OK;

	(void)memuse;

	assert(vm != NULL);
	assert(vm->vm_config != NULL);

	cap_id_t addrspace = vm->vm_config->addrspace;

	err = memextent_map_partial(me_cap, addrspace, ipa, offset, size,
				    access, map_memtype,
				    memuse == VM_MEMUSE_PROTECTED);
	if (err == OK) {
		maybe_sync(me_cap);
	}

	return err;
}

error_t
vm_memory_unmap(vm_t *vm, vm_memuse_t memuse, cap_id_t me_cap, vmaddr_t ipa)
{
	error_t err = OK;

	(void)memuse;

	assert(vm != NULL);
	assert(vm->vm_config != NULL);

	cap_id_t addrspace = vm->vm_config->addrspace;

	err = memextent_unmap(me_cap, addrspace, ipa);
	if (err == OK) {
		maybe_sync(me_cap);
	}

	return err;
}

error_t
vm_memory_unmap_partial(vm_t *vm, vm_memuse_t memuse, cap_id_t me_cap,
			vmaddr_t ipa, size_t offset, size_t size)
{
	error_t err = OK;

	(void)memuse;

	assert(vm != NULL);
	assert(vm->vm_config != NULL);

	cap_id_t addrspace = vm->vm_config->addrspace;

	err = memextent_unmap_partial(me_cap, addrspace, ipa, offset, size);
	if (err == OK) {
		maybe_sync(me_cap);
	}

	return err;
}

error_t
vm_memory_remap(vm_t *vm, vm_memuse_t memuse, cap_id_t me_cap, vmaddr_t ipa,
		pgtable_access_t old_access, pgtable_access_t new_access,
		pgtable_vm_memtype_t old_memtype,
		pgtable_vm_memtype_t new_memtype)
{
	error_t err = OK;

	(void)memuse;

	assert(vm != NULL);
	assert(vm->vm_config != NULL);

	if (old_memtype != new_memtype) {
		err = ERROR_DENIED;
		goto out;
	}

	if (old_access == new_access) {
		goto out;
	}

	cap_id_t addrspace = vm->vm_config->addrspace;

	err = memextent_update_access(me_cap, addrspace, ipa, new_access);
	if (err == OK) {
		maybe_sync(me_cap);
	}

out:
	return err;
}

error_t
vm_memory_remap_partial(vm_t *vm, vm_memuse_t memuse, cap_id_t me_cap,
			vmaddr_t ipa, size_t offset, size_t size,
			pgtable_access_t     old_access,
			pgtable_access_t     new_access,
			pgtable_vm_memtype_t old_memtype,
			pgtable_vm_memtype_t new_memtype)
{
	error_t err = OK;

	(void)memuse;

	assert(vm != NULL);
	assert(vm->vm_config != NULL);

	if (old_memtype != new_memtype) {
		err = ERROR_DENIED;
		goto out;
	}

	if (old_access == new_access) {
		goto out;
	}

	cap_id_t addrspace = vm->vm_config->addrspace;

	err = memextent_update_access_partial(me_cap, addrspace, ipa, offset,
					      size, new_access);
	if (err == OK) {
		maybe_sync(me_cap);
	}

out:
	return err;
}

cap_id_result_t
vm_memory_create_and_map(vm_t *vm, vm_memuse_t memuse, cap_id_t parent_me,
			 size_t offset, size_t size, vmaddr_t ipa,
			 memextent_memtype_t  me_memtype,
			 pgtable_access_t     access,
			 pgtable_vm_memtype_t map_memtype)
{
	cap_id_result_t ret;

	(void)memuse;

	assert(vm != NULL);
	assert(vm->vm_config != NULL);

	cap_id_t addrspace = vm->vm_config->addrspace;

	ret = memextent_create_and_map(addrspace, offset, ipa, size, access,
				       me_memtype, map_memtype, parent_me);
	if (ret.e == OK) {
		maybe_sync(parent_me);
	}

	return ret;
}

void
vm_memory_batch_start(cap_id_t me_cap)
{
	assert(batch_me_cap == CSPACE_CAP_INVALID);
	assert(!batch_me_sync);

	batch_me_cap = me_cap;
}

void
vm_memory_batch_end(void)
{
	if (batch_me_sync) {
		memextent_sync_all(batch_me_cap);
		batch_me_sync = false;
	}

	batch_me_cap = CSPACE_CAP_INVALID;
}

vm_memory_result_t
vm_memory_lookup(vm_t *vm, vm_memuse_t memuse, vmaddr_t ipa, size_t size)
{
	vm_memory_result_t ret = { .err = OK };

	assert(vm != NULL);

	uint8_t mem_type;
	if (memuse == VM_MEMUSE_NORMAL) {
		mem_type = MEM_TYPE_NORMAL;
	} else if (memuse == VM_MEMUSE_IO) {
		mem_type = MEM_TYPE_IO;
	} else {
		// Lookup not supported.
		ret.err = ERROR_DENIED;
		goto out;
	}

	cap_id_t me_cap	   = vm_memory_get_owned_extent(vm, mem_type);
	cap_id_t addrspace = vm->vm_config->addrspace;

	gunyah_hyp_addrspace_lookup_result_t lookup_ret =
		gunyah_hyp_addrspace_lookup(addrspace, me_cap, ipa, size);
	if (lookup_ret.error != OK) {
		ret.err = lookup_ret.error;
		goto out;
	}

	ret.phys   = lookup_ret.offset;
	ret.size   = lookup_ret.size;
	ret.access = memextent_mapping_attrs_get_kernel_access(
		&lookup_ret.map_attrs);
	ret.map_memtype =
		memextent_mapping_attrs_get_memtype(&lookup_ret.map_attrs);

out:
	return ret;
}

size_result_t
vm_address_range_init(vm_t *vm)
{
	size_result_t ret;
	vmaddr_t      base;
	size_t	      size;

	assert(vm != NULL);

	if (vm->vmid == VMID_HLOS) {
		// We only need to allocate ranges for virtio.
		base = PLATFORM_HLOS_VIRTIO_FREE_IPA_BASE;
		size = PLATFORM_HLOS_VIRTIO_FREE_IPA_SIZE;
	} else {
		base = 0U;
		size = util_bit(SVM_ADDRESS_SPACE_BITS);
	}

	vm->as_allocator = address_range_allocator_init(base, size);
	if (vm->as_allocator == NULL) {
		ret = size_result_error(ERROR_NOMEM);
		goto out;
	}

	if (vm->vmid != VMID_HLOS) {
		// Reserve the device memory range.
		address_range_allocator_ret_t as_ret;

		paddr_t dev_base;
		size_t	dev_size;

		count_t device_ranges_count = rm_get_device_ranges_count();
		for (index_t i = 0U; i < device_ranges_count; i++) {
			rm_get_device_ranges(i, &dev_base, &dev_size);

			as_ret = address_range_allocator_alloc(
				vm->as_allocator, dev_base, dev_size,
				ADDRESS_RANGE_NO_ALIGNMENT);
			if (as_ret.err != OK) {
				break;
			}
		}

		if (as_ret.err != OK) {
			address_range_allocator_deinit(vm->as_allocator);
			ret = size_result_error(as_ret.err);
			goto out;
		}
	}

	ret = size_result_ok(size);

out:
	return ret;
}

void
vm_address_range_destroy(vm_t *vm)
{
	assert(vm != NULL);

	address_range_allocator_deinit(vm->as_allocator);
}

vm_address_range_result_t
vm_address_range_alloc(vm_t *vm, vm_memuse_t memuse, vmaddr_t start_addr,
		       paddr_t phys, size_t size, size_t alignment)
{
	vm_address_range_result_t ret = { .err = OK };

	assert(vm != NULL);

	if (is_mapped_direct(vm, memuse)) {
		if ((phys != INVALID_ADDRESS) &&
		    ((start_addr == phys) || (start_addr == INVALID_ADDRESS))) {
			ret.base = phys;
			ret.size = size;
			ret.tag	 = ADDRESS_RANGE_NO_TAG;
		} else {
			ret.err = ERROR_DENIED;
		}

		goto out;
	}

	if (is_device_mapping(memuse, start_addr, size)) {
		ret.base = start_addr;
		ret.size = size;
		ret.tag	 = ADDRESS_RANGE_NO_TAG;
		goto out;
	}

	address_range_allocator_ret_t alloc_ret = address_range_allocator_alloc(
		vm->as_allocator, start_addr, size, alignment);
	if (alloc_ret.err == OK) {
		ret.base = alloc_ret.base_address;
		ret.size = alloc_ret.size;
		ret.tag	 = alloc_ret.tag;
	} else {
		ret.err = alloc_ret.err;
	}

out:
	return ret;
}

error_t
vm_address_range_free(vm_t *vm, vm_memuse_t memuse, vmaddr_t base, size_t size)
{
	error_t err;

	assert(vm != NULL);

	if (is_mapped_direct(vm, memuse) ||
	    is_device_mapping(memuse, base, size)) {
		err = OK;
		goto out;
	}

	err = address_range_allocator_free(vm->as_allocator, base, size);

out:
	return err;
}

error_t
vm_address_range_tag(vm_t *vm, vmaddr_t base, size_t size,
		     address_range_tag_t tag)
{
	error_t err;

	assert(vm != NULL);

	if (vm->vmid == VMID_HLOS) {
		// HLOS does not support address space tagging.
		err = ERROR_DENIED;
		goto out;
	}

	err = address_range_allocator_tag(vm->as_allocator, base, size, tag);

out:
	return err;
}

vm_address_range_result_t
vm_address_range_tag_any(vm_t *vm, vmaddr_t start_addr, size_t addr_limit,
			 size_t size, size_t alignment, address_range_tag_t tag)
{
	vm_address_range_result_t ret = { .err = OK };

	assert(vm != NULL);

	if (vm->vmid == VMID_HLOS) {
		// HLOS does not support address space tagging.
		ret.err = ERROR_DENIED;
		goto out;
	}

	address_range_allocator_ret_t tag_ret =
		address_range_allocator_tag_region(vm->as_allocator, start_addr,
						   addr_limit, size, alignment,
						   tag);
	if (tag_ret.err == OK) {
		ret.base = tag_ret.base_address;
		ret.size = tag_ret.size;
		ret.tag	 = tag_ret.tag;
	} else {
		ret.err = tag_ret.err;
	}

out:
	return ret;
}

error_t
vm_address_range_untag(vm_t *vm, vmaddr_t base, size_t size,
		       address_range_tag_t tag)
{
	error_t err;

	assert(vm != NULL);

	if (vm->vmid == VMID_HLOS) {
		// HLOS does not support address space tagging.
		err = ERROR_DENIED;
		goto out;
	}

	err = address_range_allocator_untag(vm->as_allocator, base, size, tag);

out:
	return err;
}

vm_acl_info_result_t
vm_memory_get_acl_info(vm_t *vm, uint8_t mem_type, cap_id_t mp_me_cap,
		       uint8_t trans_type, acl_entry_t *acl,
		       uint32_t acl_entries, bool vm_init)
{
	(void)mem_type;
	(void)mp_me_cap;
	(void)trans_type;
	(void)acl;
	(void)acl_entries;
	(void)vm_init;
	(void)vm;

	return (vm_acl_info_result_t){ .err = OK };
}

void
vm_memory_free_acl_info(vm_acl_info_t *info)
{
	if (info != NULL) {
		free(info);
	}
}

cap_id_result_t
vm_memory_create_extent(uint8_t mem_type)
{
	return (mem_type == MEM_TYPE_IO) ? create_device_me()
					 : create_ddr_me(parent_ddr_me);
}

cap_id_t
vm_memory_get_owned_extent(const vm_t *vm, uint8_t mem_type)
{
	cap_id_t me_cap;

	assert(vm != NULL);

	me_cap = (mem_type == MEM_TYPE_IO) ? vm->owned_device_me
					   : vm->owned_ddr_me;
	return me_cap;
}

error_t
vm_memory_setup_paged_extents(vm_t *vm)
{
	error_t ret;

	if ((vm->shared_paged_ddr_me != CSPACE_CAP_INVALID) ||
	    (vm->private_paged_ddr_me != CSPACE_CAP_INVALID)) {
		ret = ERROR_BUSY;
		goto out;
	}

	vm_t *owner_vm = vm_lookup(vm->owner);
	assert(owner_vm != NULL);

	acl_entry_t acl_unprotected[] = {
		{ .vmid = vm->owner, .rights = MEM_RIGHTS_RWX },
		{ .vmid = vm->vmid, .rights = MEM_RIGHTS_RWX },
	};
	cap_id_t unprotected_host_extent = vm_memory_get_source_extent(
		owner_vm, MEM_TYPE_NORMAL, acl_unprotected,
		util_array_size(acl_unprotected));

	cap_id_result_t shared_me = create_ddr_me(unprotected_host_extent);
	if (shared_me.e != OK) {
		ret = shared_me.e;
		goto out;
	}
	vm->shared_paged_ddr_me = shared_me.r;

	if (vm->mem_private) {
		acl_entry_t acl_protected[] = {
			{ .vmid = vm->vmid, .rights = MEM_RIGHTS_RWX },
		};
		cap_id_t protected_host_extent = vm_memory_get_source_extent(
			owner_vm, MEM_TYPE_NORMAL, acl_protected,
			util_array_size(acl_protected));

		cap_id_result_t private_me =
			create_ddr_me(protected_host_extent);
		if (private_me.e != OK) {
			ret = private_me.e;
			goto out;
		}

		ret = memextent_unmap_all(private_me.r);
		if (ret != OK) {
			goto out;
		}

		vm->private_paged_ddr_me = private_me.r;
	}

	ret = OK;

out:
	return ret;
}

cap_id_t
vm_memory_get_paged_extent(const vm_t *vm, bool is_private)
{
	assert(vm != NULL);

	return is_private ? vm->private_paged_ddr_me : vm->shared_paged_ddr_me;
}

cap_id_t
vm_memory_get_source_extent(const vm_t *vm, uint8_t mem_type, acl_entry_t *acl,
			    uint32_t acl_entries)
{
	(void)acl;
	(void)acl_entries;
	return vm_memory_get_owned_extent(vm, mem_type);
}

error_t
vm_memory_donate_extent(vm_t *vm, uint8_t mem_type, vm_acl_info_t *acl_info,
			cap_id_t mp_me_cap, paddr_t phys, size_t size,
			bool to_mp)
{
	error_t	 err;
	cap_id_t owner_me_cap;
	size_t	 offset = phys;

	assert(vm != NULL);
	(void)acl_info;

	owner_me_cap = vm_memory_get_owned_extent(vm, mem_type);

	if (to_mp) {
		err = memextent_donate_sibling(owner_me_cap, mp_me_cap, offset,
					       size);
	} else {
		err = memextent_donate_sibling(mp_me_cap, owner_me_cap, offset,
					       size);
	}
	if (err == OK) {
		maybe_sync(to_mp ? owner_me_cap : mp_me_cap);
	}

	return err;
}

error_t
vm_memory_add_to_paged_extent(const vm_t *vm, cap_id_t mp_me_cap, paddr_t phys,
			      size_t size, bool is_private, bool reclaim)
{
	error_t err;
	size_t	offset = phys;

	cap_id_t paged_ddr_me = is_private ? vm->private_paged_ddr_me
					   : vm->shared_paged_ddr_me;

	if (is_private && !vm->mem_private) {
		// The VM is unpratected and does not have distinct private and
		// shared DDR MEs. It is not possible to add private memory.
		err = ERROR_DENIED;
	} else if (reclaim) {
		err = memextent_donate_sibling(paged_ddr_me, mp_me_cap, offset,
					       size);
	} else {
		err = memextent_donate_sibling(mp_me_cap, paged_ddr_me, offset,
					       size);
	}

	return err;
}

error_t
platform_vm_memory_donate_ddr(cap_id_t me_cap, paddr_t phys, size_t size,
			      bool to_cap)
{
	error_t	 err;
	cap_id_t rm_partition = rm_get_rm_partition();

	if (to_cap) {
		err = memextent_donate_child(rm_partition, parent_ddr_me, phys,
					     size);
		if (err != OK) {
			goto out;
		}

		err = memextent_donate_child(parent_ddr_me, me_cap, phys, size);
		if (err != OK) {
			(void)memextent_donate_parent(
				rm_partition, parent_ddr_me, phys, size);
		}
	} else {
		err = memextent_donate_parent(parent_ddr_me, me_cap, phys,
					      size);
		if (err != OK) {
			goto out;
		}

		err = memextent_donate_parent(rm_partition, parent_ddr_me, phys,
					      size);
		if (err != OK) {
			(void)memextent_donate_child(parent_ddr_me, me_cap,
						     phys, size);
		}
	}

out:
	return err;
}

address_range_tag_t
vm_memory_constraints_to_tag(vm_t *vm, uint32_t generic_constraints,
			     uint32_t platform_constraints)
{
	address_range_tag_t tag = ADDRESS_RANGE_NO_TAG;

	assert(vm != NULL);

	if ((generic_constraints == IPA_GENERIC_CONSTRAINT_NONE) &&
	    (platform_constraints == IPA_PLATFORM_CONSTRAINT_NONE)) {
		// No constraints, just set the valid tag bit.
		tag = ADDRESS_RANGE_TAG_VALID;
		goto out;
	}

	if ((generic_constraints ==
	     IPA_GENERIC_CONSTRAINT_BASE_MEMORY_COMPATIBLE) &&
	    (platform_constraints == IPA_PLATFORM_CONSTRAINT_NONE)) {
		tag = vm->mem_base_tag;
		goto out;
	}

	// We only support a limited set of generic constraints.
	const uint32_t generic_mask = IPA_GENERIC_CONSTRAINT_ECC |
				      IPA_GENERIC_CONSTRAINT_TAGGED |
				      IPA_GENERIC_CONSTRAINT_NORMAL;
	if ((generic_constraints & ~generic_mask) != 0U) {
		goto out;
	}

	// The normal memory constraint must always be set.
	if ((generic_constraints & IPA_GENERIC_CONSTRAINT_NORMAL) == 0U) {
		goto out;
	}

	tag = ADDRESS_RANGE_TAG_VALID | ADDRESS_RANGE_TAG_NORMAL;

	if ((generic_constraints & IPA_GENERIC_CONSTRAINT_ECC) != 0U) {
		tag |= ADDRESS_RANGE_TAG_ECC;
	}

	if ((generic_constraints & IPA_GENERIC_CONSTRAINT_TAGGED) != 0U) {
		tag |= ADDRESS_RANGE_TAG_MEMTAG;
	}

	switch (platform_constraints) {
	case IPA_PLATFORM_CONSTRAINT_NONE:
		break;
	default:
		// Invalid platform constraints.
		tag = ADDRESS_RANGE_NO_TAG;
		break;
	}

out:
	return tag;
}

address_range_tag_t
vm_memory_get_phys_address_tag(paddr_t phys, size_t size)
{
	address_range_tag_t tag = ADDRESS_RANGE_TAG_MASK;

	(void)phys;
	(void)size;

	if (tag == ADDRESS_RANGE_TAG_MASK) {
		// By default treat the range as valid normal memory.
		tag = ADDRESS_RANGE_TAG_VALID | ADDRESS_RANGE_TAG_NORMAL;
	}

	return tag;
}
