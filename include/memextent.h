// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

cap_id_result_t
memextent_create(paddr_t phy_base, size_t size, pgtable_access_t access,
		 memextent_memtype_t memtype, cap_id_t parent);

error_t
memextent_map(cap_id_t me_cap, cap_id_t addrspace_cap, vmaddr_t vbase,
	      pgtable_access_t access, memextent_memtype_t memtype);

cap_id_result_t
memextent_create_and_map(cap_id_t addrspace_cap, paddr_t phy_base,
			 vmaddr_t vbase, size_t size, pgtable_access_t access,
			 memextent_memtype_t memtype, cap_id_t parent);
