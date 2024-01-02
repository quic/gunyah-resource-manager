// © 2022 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rm_types.h>
#include <utils/address_range_allocator.h>
#include <utils/vector.h>

#include <event.h>
#include <guest_interface.h>
#include <log.h>
#include <memextent.h>
#include <platform_vm_config.h>
#include <resource-manager.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_creation.h>
#include <vm_memory.h>
#include <vm_mgnt.h>

error_t
vm_creation_config_vm_info_area(vm_config_t *vmcfg)
{
	error_t ret = OK;

	// We need to dynamically allocate some pages for the info area and
	// attach them to a memextent. For this, we have to derive a memextent
	// from the RM's memextent and map this allocated range as read-only to
	// the VM.
	// For now allocate one page. In the future we could have multiple.
	// Warning: Prone to rowhammer attacks.
	// FIXME:
	size_t size = PAGE_SIZE;

	vmcfg->vm->vm_info_area_size   = 0;
	vmcfg->vm->vm_info_area_ipa    = ~0UL;
	vmcfg->vm->vm_info_area_rm_ipa = ~0UL;
	vmcfg->vm_info_area_me_cap     = CSPACE_CAP_INVALID;

	void *rm_ipa = aligned_alloc(PAGE_SIZE, size);
	if (rm_ipa == NULL) {
		ret = ERROR_NOMEM;
		goto out;
	}
	(void)memset(rm_ipa, 0, size);

	size_t offset = (size_t)((vmaddr_t)rm_ipa - rm_get_me_ipa_base());

	cap_id_result_t me_ret = memextent_create(
		offset, size, MEMEXTENT_TYPE_BASIC, PGTABLE_ACCESS_RW,
		MEMEXTENT_MEMTYPE_ANY, rm_get_me());
	if (me_ret.e != OK) {
		ret = me_ret.e;
		goto error_free_rm_ipa;
	}

	// Allocate IPA
	vm_address_range_result_t alloc_ret = vm_address_range_alloc(
		vmcfg->vm, VM_MEMUSE_VDEVICE, INVALID_ADDRESS, INVALID_ADDRESS,
		size, PAGE_SIZE);
	if (alloc_ret.err != OK) {
		ret = alloc_ret.err;
		(void)printf(
			"Failed to allocate IPA for stats area, error %" PRId32
			"\n",
			(int32_t)ret);
		goto error_delete_me_cap;
	}

	vmcfg->vm->vm_info_area_ipa    = alloc_ret.base;
	vmcfg->vm->vm_info_area_rm_ipa = (uintptr_t)rm_ipa;
	vmcfg->vm->vm_info_area_size   = size;
	vmcfg->vm_info_area_me_cap     = me_ret.r;

	goto out;

error_delete_me_cap:
	memextent_delete(me_ret.r);
error_free_rm_ipa:
	free(rm_ipa);
out:
	return ret;
}

error_t
vm_creation_map_vm_info_area(vm_config_t *vmcfg)
{
	error_t err;

	if ((vmcfg->vm->vm_info_area_ipa == ~0UL) ||
	    (vmcfg->vm->vm_info_area_rm_ipa == ~0UL) ||
	    (vmcfg->vm_info_area_me_cap == CSPACE_CAP_INVALID)) {
		err = ERROR_ADDR_INVALID;
		goto out;
	}

	// Map it to the VM read-only
	err = vm_memory_map(vmcfg->vm, VM_MEMUSE_VDEVICE,
			    vmcfg->vm_info_area_me_cap,
			    vmcfg->vm->vm_info_area_ipa, PGTABLE_ACCESS_R,
			    PGTABLE_VM_MEMTYPE_NORMAL_WB);

out:
	return err;
}

void
vm_creation_vm_info_area_teardown(vm_config_t *vmcfg)
{
	if (vmcfg->vm->vm_info_area_size != 0UL) {
		if (vmcfg->vm->vm_info_area_ipa != ~0UL) {
			error_t err = vm_address_range_free(
				vmcfg->vm, VM_MEMUSE_VDEVICE,
				vmcfg->vm->vm_info_area_ipa,
				vmcfg->vm->vm_info_area_size);
			assert(err == OK);
		}

		if (vmcfg->vm_info_area_me_cap != CSPACE_CAP_INVALID) {
			memextent_delete(vmcfg->vm_info_area_me_cap);
		}

		if (vmcfg->vm->vm_info_area_rm_ipa != ~0UL) {
			free((void *)vmcfg->vm->vm_info_area_rm_ipa);
		}
	}
}
