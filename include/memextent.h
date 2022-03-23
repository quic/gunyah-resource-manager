// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// When creating an extent from a parent, the phys_base should really be the
// offset of the (base address to be used - base address of parent extent)
cap_id_result_t
memextent_create(paddr_t phy_base, size_t size, pgtable_access_t access,
		 memextent_memtype_t memtype, cap_id_t parent);

error_t
memextent_map(cap_id_t me_cap, cap_id_t addrspace_cap, vmaddr_t vbase,
	      pgtable_access_t access, pgtable_vm_memtype_t memtype_map);

error_t
memextent_update_access(cap_id_t me_cap, cap_id_t addrspace_cap, vmaddr_t vbase,
			pgtable_access_t access);

// When creating an extent from a parent, the phys_base should really be the
// offset of the (base address to be used - base address of parent extent)
cap_id_result_t
memextent_create_and_map(cap_id_t addrspace_cap, paddr_t phy_base,
			 vmaddr_t vbase, size_t size, pgtable_access_t access,
			 memextent_memtype_t  memtype,
			 pgtable_vm_memtype_t memtype_map, cap_id_t parent);
