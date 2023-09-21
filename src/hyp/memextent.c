// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>

#include <rm_types.h>

#include <guest_interface.h>
#include <memextent.h>
#include <resource-manager.h>
#include <rm-rpc.h>

cap_id_result_t
memextent_create(paddr_t phy_base, size_t size, memextent_type_t type,
		 pgtable_access_t access, memextent_memtype_t memtype,
		 cap_id_t parent)
{
	error_t		ret = OK;
	cap_id_result_t cap_ret;

	gunyah_hyp_partition_create_memextent_result_t me_ret;
	me_ret = gunyah_hyp_partition_create_memextent(rm_get_rm_partition(),
						       rm_get_rm_cspace());
	if (me_ret.error != OK) {
		cap_ret = cap_id_result_error(me_ret.error);
		goto out;
	}

	memextent_attrs_t mem_attrs = memextent_attrs_default();
	memextent_attrs_set_access(&mem_attrs, access);
	memextent_attrs_set_memtype(&mem_attrs, memtype);
	memextent_attrs_set_type(&mem_attrs, type);

	if (parent != CSPACE_CAP_INVALID) {
		// To configure derive extents, the phys_base must be the offset
		ret = gunyah_hyp_memextent_configure_derive(
			me_ret.new_cap, parent, phy_base, size, mem_attrs);
	} else {
		ret = gunyah_hyp_memextent_configure(me_ret.new_cap, phy_base,
						     size, mem_attrs);
	}

	if (ret != OK) {
		cap_ret = cap_id_result_error(ret);
		goto out;
	}

	ret = gunyah_hyp_object_activate(me_ret.new_cap);
	if (ret != OK) {
		cap_ret = cap_id_result_error(ret);
		goto out;
	}

	cap_ret = cap_id_result_ok(me_ret.new_cap);
out:
	return cap_ret;
}

error_t
memextent_donate_child(cap_id_t parent, cap_id_t child, size_t offset,
		       size_t size)
{
	memextent_donate_options_t options = memextent_donate_options_default();
	memextent_donate_options_set_type(&options,
					  MEMEXTENT_DONATE_TYPE_TO_CHILD);
	memextent_donate_options_set_no_sync(&options, true);

	cap_id_t from = (parent == CSPACE_CAP_INVALID) ? rm_get_rm_partition()
						       : parent;
	cap_id_t to   = child;

	return gunyah_hyp_memextent_donate(options, from, to, offset, size);
}

error_t
memextent_donate_parent(cap_id_t parent, cap_id_t child, size_t offset,
			size_t size)
{
	memextent_donate_options_t options = memextent_donate_options_default();
	memextent_donate_options_set_type(&options,
					  MEMEXTENT_DONATE_TYPE_TO_PARENT);
	memextent_donate_options_set_no_sync(&options, true);

	cap_id_t from = child;
	cap_id_t to   = (parent == CSPACE_CAP_INVALID) ? rm_get_rm_partition()
						       : parent;

	return gunyah_hyp_memextent_donate(options, from, to, offset, size);
}

error_t
memextent_donate_sibling(cap_id_t from, cap_id_t to, size_t offset, size_t size)
{
	memextent_donate_options_t options = memextent_donate_options_default();
	memextent_donate_options_set_type(&options,
					  MEMEXTENT_DONATE_TYPE_TO_SIBLING);
	memextent_donate_options_set_no_sync(&options, true);

	return gunyah_hyp_memextent_donate(options, from, to, offset, size);
}

static error_t
memextent_map_internal(cap_id_t me_cap, cap_id_t addrspace_cap, vmaddr_t vbase,
		       size_t offset, size_t size, pgtable_access_t access,
		       pgtable_vm_memtype_t memtype_map, bool partial)
{
	memextent_mapping_attrs_t map_attrs = memextent_mapping_attrs_default();
	memextent_mapping_attrs_set_user_access(&map_attrs, access);
	memextent_mapping_attrs_set_kernel_access(&map_attrs, access);
	memextent_mapping_attrs_set_memtype(&map_attrs, memtype_map);

	addrspace_map_flags_t map_flags = addrspace_map_flags_default();
	addrspace_map_flags_set_partial(&map_flags, partial);
	addrspace_map_flags_set_no_sync(&map_flags, true);

	return gunyah_hyp_addrspace_map(addrspace_cap, me_cap, vbase, map_attrs,
					map_flags, offset, size);
}

error_t
memextent_map(cap_id_t me_cap, cap_id_t addrspace_cap, vmaddr_t vbase,
	      pgtable_access_t access, pgtable_vm_memtype_t memtype_map)
{
	return memextent_map_internal(me_cap, addrspace_cap, vbase, 0U, 0U,
				      access, memtype_map, false);
}

error_t
memextent_map_partial(cap_id_t me_cap, cap_id_t addrspace_cap, vmaddr_t vbase,
		      size_t offset, size_t size, pgtable_access_t access,
		      pgtable_vm_memtype_t memtype_map)
{
	return memextent_map_internal(me_cap, addrspace_cap, vbase, offset,
				      size, access, memtype_map, true);
}

static error_t
memextent_unmap_internal(cap_id_t me_cap, cap_id_t addrspace_cap,
			 vmaddr_t vbase, size_t offset, size_t size,
			 bool partial)
{
	addrspace_map_flags_t map_flags = addrspace_map_flags_default();
	addrspace_map_flags_set_partial(&map_flags, partial);
	addrspace_map_flags_set_no_sync(&map_flags, true);

	return gunyah_hyp_addrspace_unmap(addrspace_cap, me_cap, vbase,
					  map_flags, offset, size);
}

error_t
memextent_unmap(cap_id_t me_cap, cap_id_t addrspace_cap, vmaddr_t vbase)
{
	return memextent_unmap_internal(me_cap, addrspace_cap, vbase, 0U, 0U,
					false);
}

error_t
memextent_unmap_partial(cap_id_t me_cap, cap_id_t addrspace_cap, vmaddr_t vbase,
			size_t offset, size_t size)
{
	return memextent_unmap_internal(me_cap, addrspace_cap, vbase, offset,
					size, true);
}

static error_t
memextent_update_access_internal(cap_id_t me_cap, cap_id_t addrspace_cap,
				 vmaddr_t vbase, size_t offset, size_t size,
				 pgtable_access_t access, bool partial)
{
	memextent_access_attrs_t access_attrs =
		memextent_access_attrs_default();
	memextent_access_attrs_set_user_access(&access_attrs, access);
	memextent_access_attrs_set_kernel_access(&access_attrs, access);

	addrspace_map_flags_t map_flags = addrspace_map_flags_default();
	addrspace_map_flags_set_partial(&map_flags, partial);
	addrspace_map_flags_set_no_sync(&map_flags, true);

	return gunyah_hyp_addrspace_update_access(addrspace_cap, me_cap, vbase,
						  access_attrs, map_flags,
						  offset, size);
}

error_t
memextent_update_access(cap_id_t me_cap, cap_id_t addrspace_cap, vmaddr_t vbase,
			pgtable_access_t access)
{
	return memextent_update_access_internal(me_cap, addrspace_cap, vbase,
						0U, 0U, access, false);
}

error_t
memextent_update_access_partial(cap_id_t me_cap, cap_id_t addrspace_cap,
				vmaddr_t vbase, size_t offset, size_t size,
				pgtable_access_t access)
{
	return memextent_update_access_internal(me_cap, addrspace_cap, vbase,
						offset, size, access, true);
}

cap_id_result_t
memextent_create_and_map(cap_id_t addrspace_cap, paddr_t phy_base,
			 vmaddr_t vbase, size_t size, pgtable_access_t access,
			 memextent_memtype_t  memtype,
			 pgtable_vm_memtype_t memtype_map, cap_id_t parent)
{
	// Do not use the given access for memextent creation, as it will reduce
	// the access of the parent's mappings (if deriving).
	pgtable_access_t me_access = (memtype == MEMEXTENT_MEMTYPE_DEVICE)
					     ? PGTABLE_ACCESS_RW
					     : PGTABLE_ACCESS_RWX;

	cap_id_result_t cap_ret = memextent_create(phy_base, size,
						   MEMEXTENT_TYPE_BASIC,
						   me_access, memtype, parent);
	if (cap_ret.e != OK) {
		goto out;
	}

	error_t ret = memextent_map(cap_ret.r, addrspace_cap, vbase, access,
				    memtype_map);
	if (ret != OK) {
		cap_ret = cap_id_result_error(ret);
	}

out:
	return cap_ret;
}

void
memextent_delete(cap_id_t me)
{
	error_t err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(), me);
	assert(err == OK);
}

error_t
memextent_unmap_all(cap_id_t me)
{
	memextent_modify_flags_t flags = memextent_modify_flags_default();
	memextent_modify_flags_set_op(&flags, MEMEXTENT_MODIFY_OP_UNMAP_ALL);
	memextent_modify_flags_set_no_sync(&flags, true);

	return gunyah_hyp_memextent_modify(me, flags, 0U, 0U);
}

error_t
memextent_zero_range(cap_id_t me, size_t offset, size_t size)
{
	memextent_modify_flags_t flags = memextent_modify_flags_default();
	memextent_modify_flags_set_op(&flags, MEMEXTENT_MODIFY_OP_ZERO_RANGE);
	memextent_modify_flags_set_no_sync(&flags, true);

	return gunyah_hyp_memextent_modify(me, flags, offset, size);
}

error_t
memextent_cache_clean_range(cap_id_t me, size_t offset, size_t size)
{
	memextent_modify_flags_t flags = memextent_modify_flags_default();
	memextent_modify_flags_set_op(&flags,
				      MEMEXTENT_MODIFY_OP_CACHE_CLEAN_RANGE);
	memextent_modify_flags_set_no_sync(&flags, true);

	return gunyah_hyp_memextent_modify(me, flags, offset, size);
}

error_t
memextent_cache_flush_range(cap_id_t me, size_t offset, size_t size)
{
	memextent_modify_flags_t flags = memextent_modify_flags_default();
	memextent_modify_flags_set_op(&flags,
				      MEMEXTENT_MODIFY_OP_CACHE_FLUSH_RANGE);
	memextent_modify_flags_set_no_sync(&flags, true);

	return gunyah_hyp_memextent_modify(me, flags, offset, size);
}

void
memextent_sync_all(cap_id_t me)
{
	memextent_modify_flags_t flags = memextent_modify_flags_default();
	memextent_modify_flags_set_op(&flags, MEMEXTENT_MODIFY_OP_SYNC_ALL);

	error_t err = gunyah_hyp_memextent_modify(me, flags, 0U, 0U);
	assert(err == OK);
}
