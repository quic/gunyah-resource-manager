// © 2022 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Donate memory between the RM partition and a DDR memextent.
error_t
platform_vm_memory_donate_ddr(cap_id_t me_cap, paddr_t phys, size_t size,
			      bool to_cap);
