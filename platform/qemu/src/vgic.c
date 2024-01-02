// © 2022 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>

#include <rm_types.h>

#include <resource-manager.h>
#include <rm-rpc.h>
#include <rm_env_data.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wzero-length-array"
#pragma clang diagnostic ignored "-Wbad-function-cast"
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wdocumentation-unknown-command"
#pragma clang diagnostic ignored "-Wextra-semi"
#include <libfdt.h>
#pragma clang diagnostic pop

#include <util.h>
#include <utils/vector.h>

#include <dt_overlay.h>
#include <dtb_parser.h>
#include <event.h>
#include <guest_interface.h>
#include <irq_manager.h>
#include <log.h>
#include <platform_dt_parser.h>
#include <platform_qemu.h>
#include <platform_vm_config.h>
#include <vgic.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_memory.h>
#include <vm_mgnt.h>
#include <vm_vcpu.h>

#include <platform_vm_config_parser.h>
#include <vm_config_parser.h>

static paddr_t hlos_vgic_gicd_base;
static size_t  hlos_vgic_gicr_stride;
static paddr_t hlos_vgic_gicr_base;
static count_t hlos_vgic_gicr_count;

error_t
vgic_init(const rm_env_data_t *env_data)
{
	hlos_vgic_gicd_base = env_data->platform_env->gicd_base;

	assert(env_data->platform_env->gicr_ranges_count == 1U);
	hlos_vgic_gicr_base   = env_data->platform_env->gicr_ranges[0].base;
	hlos_vgic_gicr_count  = env_data->platform_env->gicr_ranges[0].count;
	hlos_vgic_gicr_stride = env_data->platform_env->gicr_stride;

	return OK;
}

error_t
vgic_vm_config_add(vm_config_t *vmcfg, const vm_config_parser_data_t *data)
{
	error_t err;

	vm_t	     *vm       = vmcfg->vm;
	const count_t gicr_cnt = (count_t)vector_size(vm->vm_config->vcpus);
	if (data == NULL) {
		// This is the primary VM.

		// We need to attach at the platform address range taken from
		// the boot environment.
		assert(gicr_cnt <= hlos_vgic_gicr_count);
		vmcfg->platform.vgic_gicd_base	 = hlos_vgic_gicd_base;
		vmcfg->platform.vgic_gicr_base	 = hlos_vgic_gicr_base;
		vmcfg->platform.vgic_gicr_stride = hlos_vgic_gicr_stride;

		// Patching the DT is not possible.
		vmcfg->platform.vgic_phandle  = ~0U;
		vmcfg->platform.vgic_patch_dt = false;
	} else if (data->platform.vgic_gicr_stride == 0U) {
		// If the stride wasn't initialised in the parser data,
		// we need to allocate addresses and generate a DT node
		// from scratch.
		vmcfg->platform.vgic_gicd_base	 = INVALID_ADDRESS;
		vmcfg->platform.vgic_gicr_base	 = INVALID_ADDRESS;
		vmcfg->platform.vgic_gicr_stride = vgic_gicr_size;
		vmcfg->platform.vgic_phandle	 = ~0U;
		vmcfg->platform.vgic_patch_dt	 = true;
	} else {
		// Copy the parser data. This may or may not trigger
		// generation or patching of the DT node.
		vmcfg->platform.vgic_gicd_base = data->platform.vgic_gicd_base;
		vmcfg->platform.vgic_gicr_base = data->platform.vgic_gicr_base;
		vmcfg->platform.vgic_gicr_stride =
			data->platform.vgic_gicr_stride;
		vmcfg->platform.vgic_phandle  = data->platform.vgic_phandle;
		vmcfg->platform.vgic_patch_dt = data->platform.vgic_patch_dt;
		vmcfg->platform.vgic_addr_cells =
			data->platform.vgic_addr_cells;
		vmcfg->platform.vgic_size_cells =
			data->platform.vgic_size_cells;
	}

	// Allocate and attach the GIC vdevice address ranges

	// GICD: 64K, attachment index 0
	if ((vm->vm_config->platform.vgic_gicd_base != INVALID_ADDRESS) &&
	    util_add_overflows(vm->vm_config->platform.vgic_gicd_base,
			       vgic_gicd_size - 1U)) {
		err = ERROR_ADDR_OVERFLOW;
		LOG_LOC("overflow GICD");
		goto out;
	}
	if ((vm->vm_config->platform.vgic_gicd_base != INVALID_ADDRESS) &&
	    !util_is_baligned(vm->vm_config->platform.vgic_gicd_base,
			      vgic_alignment)) {
		err = ERROR_ADDR_INVALID;
		LOG_LOC("align GICD");
		goto out;
	}

	vm_address_range_result_t alloc_ret = vm_address_range_alloc(
		vm, VM_MEMUSE_PLATFORM_VDEVICE,
		vm->vm_config->platform.vgic_gicd_base, INVALID_ADDRESS,
		vgic_gicd_size, vgic_gicd_size);
	if (alloc_ret.err == OK) {
		vm->vm_config->platform.vgic_gicd_base = alloc_ret.base;
	} else {
		err = alloc_ret.err;
		LOG_LOC("alloc GICD");
		goto out;
	}

	err = gunyah_hyp_addrspace_attach_vdevice(
		vm->vm_config->addrspace, vm->vm_config->vic, 0U,
		vm->vm_config->platform.vgic_gicd_base, vgic_gicd_size,
		(addrspace_attach_vdevice_flags_t){ 0U });
	if (err != OK) {
		LOG_LOC("attach GICD");
		goto out;
	}

	// GICRs: one contiguous region, 128K each (possibly with 256K stride),
	// attachment indices n + 1
	if ((vm->vm_config->platform.vgic_gicr_stride < vgic_gicr_size) ||
	    util_mult_integer_overflows(
		    vm->vm_config->platform.vgic_gicr_stride, gicr_cnt)) {
		err = ERROR_ARGUMENT_SIZE;
		goto out;
	}
	const size_t gicr_total_size =
		vm->vm_config->platform.vgic_gicr_stride * gicr_cnt;
	if ((vm->vm_config->platform.vgic_gicr_base != INVALID_ADDRESS) &&
	    util_add_overflows(vm->vm_config->platform.vgic_gicr_base,
			       gicr_total_size - 1U)) {
		err = ERROR_ADDR_OVERFLOW;
		LOG_LOC("overflow GICR");
		goto out;
	}
	if ((vm->vm_config->platform.vgic_gicr_base != INVALID_ADDRESS) &&
	    !util_is_baligned(vm->vm_config->platform.vgic_gicr_base,
			      vgic_alignment)) {
		err = ERROR_ADDR_INVALID;
		LOG_LOC("align GICR");
		goto out;
	}

	alloc_ret = vm_address_range_alloc(
		vm, VM_MEMUSE_PLATFORM_VDEVICE,
		vm->vm_config->platform.vgic_gicr_base, INVALID_ADDRESS,
		gicr_total_size, vm->vm_config->platform.vgic_gicr_stride);
	if (alloc_ret.err == OK) {
		vm->vm_config->platform.vgic_gicr_base = alloc_ret.base;
	} else {
		err = alloc_ret.err;
		LOG_LOC("alloc GICR");
		goto out;
	}

	cpu_index_t cpu_id = 0;
	for (index_t gicr_slot = 0; gicr_slot < gicr_cnt; gicr_slot++) {
		while (!rm_is_core_usable(cpu_id)) {
			cpu_id++;
			if (cpu_id > rm_get_platform_max_cores()) {
				err = ERROR_NORESOURCES;
				LOG_LOC("GICR core ID range");
				goto out;
			}
		}

		vgic_gicr_attach_flags_t flags =
			vgic_gicr_attach_flags_default();
		vgic_gicr_attach_flags_set_last(&flags,
						gicr_slot == (gicr_cnt - 1U));
		vgic_gicr_attach_flags_set_last_valid(&flags, true);
		err = gunyah_hyp_addrspace_attach_vdevice(
			vm->vm_config->addrspace, vm->vm_config->vic,
			cpu_id + 1U,
			vm->vm_config->platform.vgic_gicr_base +
				(gicr_slot *
				 vm->vm_config->platform.vgic_gicr_stride),
			vgic_gicr_size,
			(addrspace_attach_vdevice_flags_t){ .vgic_gicr =
								    flags });
		if (err != OK) {
			LOG_LOC("attach GICR");
			goto out;
		}
		cpu_id++;
	}

out:
	return err;
}

error_t
vgic_dto_finalise(dto_t *dto, const vm_t *vm)
{
	assert(dto != NULL);
	assert(vm != NULL);

	vm_config_t *vmcfg = vm->vm_config;
	assert(vmcfg != NULL);

	error_t ret;

	if (!vmcfg->platform.vgic_patch_dt) {
		ret = OK;
		goto out;
	}

	if (vmcfg->platform.vgic_phandle == ~0U) {
		// Creating a VGIC node from scratch is not yet implemented
		(void)printf("Invalid or missing VGIC node in DT\n");
		ret = ERROR_UNIMPLEMENTED;
		goto out;
	}

	(void)printf("vgic_dto_finalise: patching node %#x\n",
		     vmcfg->platform.vgic_phandle);
	ret = dto_modify_begin_by_phandle(dto, vmcfg->platform.vgic_phandle);
	if (ret != OK) {
		goto out;
	}

	ret = dto_property_add_string(dto, "compatible", "arm,gic-v3");
	if (ret != OK) {
		goto out;
	}

	ret = dto_property_add_u32(dto, "#redistributor-regions", 1U);
	if (ret != OK) {
		goto out;
	}

	ret = dto_property_add_u64(dto, "redistributor-stride",
				   vmcfg->platform.vgic_gicr_stride);
	if (ret != OK) {
		goto out;
	}

	size_t num_vcpus = vector_size(vmcfg->vcpus);
	if (num_vcpus == 0U) {
		(void)printf("VGIC cannot be generated for 0 VCPUs\n");
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	dto_addrrange_t reg[2] = {
		{ .addr = vmcfg->platform.vgic_gicd_base,
		  .size = vgic_gicd_size },
		{ .addr = vmcfg->platform.vgic_gicr_base,
		  .size = vmcfg->platform.vgic_gicr_stride * num_vcpus },
	};
	ret = dto_property_add_addrrange_array(dto, "reg", reg,
					       util_array_size(reg),
					       vmcfg->platform.vgic_addr_cells,
					       vmcfg->platform.vgic_size_cells);
	if (ret != OK) {
		goto out;
	}

	ret = dto_modify_end_by_phandle(dto, vmcfg->platform.vgic_phandle);

out:
	return ret;
}
