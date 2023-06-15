// © 2022 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <rm_types.h>
#include <util.h>
#include <utils/address_range_allocator.h>
#include <utils/vector.h>

#include <event.h>
#include <log.h>
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
#include <vm_vcpu.h>

error_t
rm_vm_create(const rm_env_data_t *env_data)
{
	error_t ret = OK;

	vm_t *rm = vm_lookup(VMID_RM);
	assert(rm != NULL);

	cap_id_t rm_partition_cap = rm_get_rm_partition();
	cap_id_t rm_cspace_cap	  = rm_get_rm_cspace();

	// Create the VM config.
	//
	// This is only used to allow RM to receive memory donations, so it only
	// needs the basic three caps for cspace, partition and addrspace.
	vm_config_t *vmcfg =
		vm_config_alloc(rm, rm_cspace_cap, rm_partition_cap);
	if (vmcfg == NULL) {
		ret = ERROR_NOMEM;
		LOG_ERR(ret);
		goto out;
	}
	vmcfg->addrspace = env_data->addrspace_capid;

	ret = vm_config_add_vcpu(vmcfg, env_data->vcpu_capid,
				 env_data->boot_core, true, NULL);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

	ret = vm_memory_setup(rm);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

	ret = vm_address_range_init(rm).e;
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

	// Reserve one page at 0 (if it wasn't already reserved for the root
	// application or device MEs) to ensure that NULL doesn't get allocated
	// as a valid address in the RM address space
	if ((env_data->me_ipa_base != 0U) && (env_data->device_me_base != 0U)) {
		ret = vm_address_range_alloc(rm, VM_MEMUSE_NORMAL, 0U, 0U,
					     PAGE_SIZE, PAGE_SIZE)
			      .err;
		if (ret != OK) {
			LOG_ERR(ret);
			goto out;
		}
	}

	// Reserve the pre-mapped memextent containing the RM code & heap
	ret = vm_address_range_alloc(rm, VM_MEMUSE_NORMAL,
				     env_data->me_ipa_base,
				     env_data->me_ipa_base, env_data->me_size,
				     0U)
		      .err;
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

out:
	return ret;
}
