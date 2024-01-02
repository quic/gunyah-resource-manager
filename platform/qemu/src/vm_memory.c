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

#include <event.h>
#include <guest_interface.h>
#include <irq_manager.h>
#include <memextent.h>
#include <memparcel.h>
#include <memparcel_msg.h>
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

static bool batch_me_ops  = false;
static bool batch_me_sync = false;

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
	paddr_t dev_base = rm_get_device_me_base();
	paddr_t dev_size = rm_get_device_me_size();

	// Platform vdevices are based on real devices, so allow them to overlap
	// with device extent IPAs. It is the VM's responsibility to ensure
	// these vdevices don't conflict with other device mappings.
	return (memuse == VM_MEMUSE_PLATFORM_VDEVICE) &&
	       (ipa != INVALID_ADDRESS) && (ipa >= dev_base) &&
	       ((ipa + size) <= (dev_base + dev_size));
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
	cap_id_result_t ret = memextent_create(0U, rm_get_device_me_size(),
					       MEMEXTENT_TYPE_SPARSE,
					       PGTABLE_ACCESS_RW,
					       MEMEXTENT_MEMTYPE_DEVICE,
					       rm_get_device_me_cap());
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

	return ret.e;
}

error_t
vm_memory_setup(vm_t *vm)
{
	error_t err = OK;

	assert(vm != NULL);

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

void
vm_memory_teardown(vm_t *vm)
{
	if (vm->owned_ddr_me != CSPACE_CAP_INVALID) {
		memextent_delete(vm->owned_ddr_me);
	}

	if (vm->owned_device_me != CSPACE_CAP_INVALID) {
		memextent_delete(vm->owned_device_me);
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

	err = memextent_map(me_cap, addrspace, ipa, access, map_memtype);

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
				    access, map_memtype);

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

	return ret;
}

void
vm_memory_batch_start(void)
{
	assert(!batch_me_ops);
	assert(!batch_me_sync);

	batch_me_ops = true;
}

void
vm_memory_batch_end(void)
{
	assert(batch_me_ops);

	if (batch_me_sync) {
		memextent_sync_all(parent_ddr_me);
		batch_me_sync = false;
	}

	batch_me_ops = false;
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

	ret.phys   = vm_memory_get_extent_base(mem_type) + lookup_ret.offset;
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
		as_ret = address_range_allocator_alloc(
			vm->as_allocator, rm_get_device_me_base(),
			rm_get_device_me_size(), ADDRESS_RANGE_NO_ALIGNMENT);
		if (as_ret.err != OK) {
			vm_address_range_destroy(vm);
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

	if (vm->as_allocator != NULL) {
		address_range_allocator_deinit(vm->as_allocator);
		vm->as_allocator = NULL;
	}
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
vm_memory_get_acl_info(vm_t *vm, uint8_t mem_type, uint8_t trans_type,
		       acl_entry_t *acl, uint32_t acl_entries, bool vm_init)
{
	vm_acl_info_result_t ret = { .err = OK };

	(void)mem_type;
	(void)trans_type;
	(void)acl;
	(void)acl_entries;
	(void)vm_init;
	(void)vm;

	ret.info = NULL;

	return ret;
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
vm_memory_get_owned_extent(vm_t *vm, uint8_t mem_type)
{
	cap_id_t me_cap;

	assert(vm != NULL);

	me_cap = (mem_type == MEM_TYPE_IO) ? vm->owned_device_me
					   : vm->owned_ddr_me;
	return me_cap;
}

paddr_t
vm_memory_get_extent_base(uint8_t mem_type)
{
	return (mem_type == MEM_TYPE_IO) ? rm_get_device_me_base() : 0U;
}

error_t
vm_memory_donate_extent(vm_t *vm, uint8_t mem_type, vm_acl_info_t *acl_info,
			cap_id_t mp_me_cap, paddr_t phys, size_t size,
			bool to_mp)
{
	error_t	 err;
	cap_id_t owner_me_cap;
	size_t	 offset = phys - vm_memory_get_extent_base(mem_type);

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
