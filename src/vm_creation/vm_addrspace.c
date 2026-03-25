// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rm_types.h>
#include <util.h>

#include <dt_linux.h>
#include <event.h>
#include <guest_interface.h>
#include <heap_mgnt.h>
#include <log.h>
#include <memextent.h>
#include <platform.h>
#include <platform_vm_config.h>
#include <resource-manager.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_creation.h>
#include <vm_creation_addrspace.h>
#include <vm_memory.h>
#include <vm_mgnt.h>

error_t
vm_creation_config_vm_info_area(cap_id_t as_cap, vm_config_t *vmcfg)
{
	error_t ret;

	// We need to dynamically allocate some pages for the info area and
	// attach them to a memextent. For this, we have to derive a memextent
	// from the RM's memextent and map this allocated range as read-only to
	// the VM.
	// For now allocate one page. In the future we could have multiple.
	// Warning: Prone to rowhammer attacks.
	// FIXME: QC RM issue #17
	size_t size = PAGE_SIZE;

	vmcfg->vm->vm_info_area_size   = 0U;
	vmcfg->vm->vm_info_area_ipa    = ~0UL;
	vmcfg->vm->vm_info_area_rm_ipa = ~0UL;
	vmcfg->vm_info_area_me_cap     = CSPACE_CAP_INVALID;

	// We need to update the VM loading API to support getting this memory
	// from the VM owner instead of RM's heap.
	// FIXME: QC RM issue #63
	void *rm_ipa = util_alloc_pages(size);
	if (rm_ipa == NULL) {
		ret = ERROR_NOMEM;
		goto out;
	}
	(void)memset(rm_ipa, 0, size);

	heap_lookup_me_ret_t lookup_ret =
		heap_mgnt_lookup_rm_me((uintptr_t)rm_ipa);
	assert(lookup_ret.err == OK);

	size_t	 offset = lookup_ret.offset;
	cap_id_t rm_me	= lookup_ret.me_cap;

	cap_id_result_t me_ret = memextent_create(offset, size,
						  MEMEXTENT_TYPE_BASIC,
						  PGTABLE_ACCESS_RW,
						  MEMEXTENT_MEMTYPE_ANY, rm_me);
	if (me_ret.e != OK) {
		ret = me_ret.e;
		goto error_free_rm_ipa;
	}

	// The derived extent is still mapped in RM; we unmap to prevent
	// accidental use.
	error_t err = memextent_unmap_all(me_ret.r);
	if (err != OK) {
		memextent_delete(me_ret.r);
		ret = err;
		goto out;
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

	ret = gunyah_hyp_addrspace_configure_info_area(
		as_cap, vmcfg->vm_info_area_me_cap,
		vmcfg->vm->vm_info_area_ipa);
	if (ret != OK) {
		goto out;
	}
	goto out;

error_delete_me_cap:
	memextent_delete(me_ret.r);
error_free_rm_ipa:
	util_free_pages(rm_ipa, size);
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
		assert(vmcfg->vm->vm_info_area_ipa != ~0UL);
		assert(vmcfg->vm->vm_info_area_rm_ipa != ~0UL);
		assert(vmcfg->vm_info_area_me_cap != CSPACE_CAP_INVALID);

		error_t err =
			vm_address_range_free(vmcfg->vm, VM_MEMUSE_VDEVICE,
					      vmcfg->vm->vm_info_area_ipa,
					      vmcfg->vm->vm_info_area_size);
		assert(err == OK);

		heap_lookup_me_ret_t lookup_ret =
			heap_mgnt_lookup_rm_me(vmcfg->vm->vm_info_area_rm_ipa);
		assert(lookup_ret.err == OK);

		memextent_delete(vmcfg->vm_info_area_me_cap);
		memextent_sync_all(lookup_ret.me_cap);

		util_free_pages((void *)vmcfg->vm->vm_info_area_rm_ipa,
				vmcfg->vm->vm_info_area_size);

		vmcfg->vm->vm_info_area_ipa    = ~0UL;
		vmcfg->vm->vm_info_area_rm_ipa = ~0UL;
		vmcfg->vm->vm_info_area_size   = 0U;
		vmcfg->vm_info_area_me_cap     = CSPACE_CAP_INVALID;
	}
}

addrspace_info_area_interrupt_result_t
vm_creation_addrspace_info_area_interrupt(interrupt_data_t virq)
{
	addrspace_info_area_interrupt_result_t ret = { .e = OK };

	if (!virq.is_cpu_local && (virq.irq >= 32U) && (virq.irq < 1020U)) {
		ret.r.type = DT_GIC_SPI;
		ret.r.irq  = virq.irq - 32U;
	} else if (virq.is_cpu_local && (virq.irq >= 16U) && (virq.irq < 32U)) {
		ret.r.type = DT_GIC_PPI;
		ret.r.irq  = virq.irq - 16U;
	} else if (!virq.is_cpu_local && (virq.irq >= 4096U) &&
		   (virq.irq < 5120U)) {
		ret.r.type = DT_GIC_ESPI;
		ret.r.irq  = virq.irq - 4096U;
	} else if (virq.is_cpu_local && (virq.irq >= 1056U) &&
		   (virq.irq < 1120U)) {
		ret.r.type = DT_GIC_EPPI;
		ret.r.irq  = virq.irq - 1056U;
	} else {
		ret.r.irq = VIRQ_INVALID;
		ret.e	  = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	ret.r.flags = virq.is_edge_triggering ? DT_GIC_IRQ_TYPE_EDGE_RISING
					      : DT_GIC_IRQ_TYPE_LEVEL_HIGH;

out:
	return ret;
}
