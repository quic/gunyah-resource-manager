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
#include <utils/address_range_allocator.h>
#include <utils/vector.h>

#include <dt_overlay.h>
#include <dtb_parser.h>
#include <event.h>
#include <guest_interface.h>
#include <irq_manager.h>
#include <log.h>
#include <platform_dt_parser.h>
#include <platform_vm_config.h>
#include <vgic.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_mgnt.h>
#include <vm_vcpu.h>

// Must be last
#include <platform_vm_config_parser.h>
#include <vm_config_parser.h>

error_t
vgic_init(const rm_env_data_t *env_data)
{
	(void)env_data;

	return OK;
}

error_t
vgic_vm_config_add(vm_config_t *vmcfg, const vm_config_parser_data_t *data)
{
	error_t err;

	if (data == NULL) {
		// This is the primary VM.

		// For HLOS, the hypervisor has been told to use the physical
		// GIC addresses, and we will never patch the DT. We don't need
		// these to be valid.
		vmcfg->platform.vgic_gicd_base	 = INVALID_ADDRESS;
		vmcfg->platform.vgic_gicr_base	 = INVALID_ADDRESS;
		vmcfg->platform.vgic_gicr_stride = 0U;
		vmcfg->platform.vgic_phandle	 = ~0U;
		vmcfg->platform.vgic_patch_dt	 = false;

		// We don't need to allocate or attach any address ranges.
		err = OK;
		goto out;
	}

	if (data->platform.vgic_gicr_stride == 0U) {
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
	vm_t *vm = vmcfg->vm;

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

	address_range_allocator_ret_t alloc_ret = address_range_allocator_alloc(
		vm->as_allocator, vm->vm_config->platform.vgic_gicd_base,
		vgic_gicd_size, vgic_gicd_size);
	if ((alloc_ret.err != OK) &&
	    (vm->vm_config->platform.vgic_gicd_base == INVALID_ADDRESS)) {
		err = alloc_ret.err;
		LOG_LOC("alloc GICD");
		goto out;
	}
	if (alloc_ret.err == OK) {
		vm->vm_config->platform.vgic_gicd_base = alloc_ret.base_address;
	}

	err = gunyah_hyp_addrspace_attach_vdevice(
		vm->vm_config->addrspace, vm->vm_config->vic, 0U,
		vm->vm_config->platform.vgic_gicd_base, vgic_gicd_size);
	if (err != OK) {
		LOG_LOC("attach GICD");
		goto out;
	}

	// GICRs: one contiguous region, 128K each (possibly with 256K stride),
	// attachment indices n + 1
	const count_t gicr_cnt = (count_t)vector_size(vm->vm_config->vcpus);
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

	alloc_ret = address_range_allocator_alloc(
		vm->as_allocator, vm->vm_config->platform.vgic_gicr_base,
		gicr_total_size, vm->vm_config->platform.vgic_gicr_stride);
	if ((alloc_ret.err != OK) &&
	    (vm->vm_config->platform.vgic_gicr_base == INVALID_ADDRESS)) {
		err = alloc_ret.err;
		LOG_LOC("alloc GICR");
		goto out;
	}
	if (alloc_ret.err == OK) {
		vm->vm_config->platform.vgic_gicr_base = alloc_ret.base_address;
	}

	for (index_t i = 0; i < gicr_cnt; i++) {
		err = gunyah_hyp_addrspace_attach_vdevice(
			vm->vm_config->addrspace, vm->vm_config->vic, i + 1U,
			vm->vm_config->platform.vgic_gicr_base +
				(i * vm->vm_config->platform.vgic_gicr_stride),
			vgic_gicr_size);
		if (err != OK) {
			LOG_LOC("attach GICR");
			goto out;
		}
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
