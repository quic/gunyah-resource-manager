// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <resource-manager.h>

#include <guest_interface.h>
#include <memextent.h>

cap_id_result_t
memextent_create(paddr_t phy_base, size_t size, pgtable_access_t access,
		 memextent_memtype_t memtype, cap_id_t parent)
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
memextent_map(cap_id_t me_cap, cap_id_t addrspace_cap, vmaddr_t vbase,
	      pgtable_access_t access, pgtable_vm_memtype_t memtype_map)
{
	memextent_mapping_attrs_t map_attrs = memextent_mapping_attrs_default();

	memextent_mapping_attrs_set_user_access(&map_attrs, access);
	memextent_mapping_attrs_set_kernel_access(&map_attrs, access);
	memextent_mapping_attrs_set_memtype(&map_attrs, memtype_map);

	return gunyah_hyp_addrspace_map(addrspace_cap, me_cap, vbase,
					map_attrs);
}

error_t
memextent_update_access(cap_id_t me_cap, cap_id_t addrspace_cap, vmaddr_t vbase,
			pgtable_access_t access)
{
	memextent_access_attrs_t access_attrs =
		memextent_access_attrs_default();

	memextent_access_attrs_set_user_access(&access_attrs, access);
	memextent_access_attrs_set_kernel_access(&access_attrs, access);

	return gunyah_hyp_addrspace_update_access(addrspace_cap, me_cap, vbase,
						  access_attrs);
}

cap_id_result_t
memextent_create_and_map(cap_id_t addrspace_cap, paddr_t phy_base,
			 vmaddr_t vbase, size_t size, pgtable_access_t access,
			 memextent_memtype_t  memtype,
			 pgtable_vm_memtype_t memtype_map, cap_id_t parent)
{
	cap_id_result_t cap_ret =
		memextent_create(phy_base, size, access, memtype, parent);
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
